"""Integration tests for end-to-end MISP sharing flow.

This module tests the complete sharing pipeline with mocked DataTide and PyMISP,
verifying the full orchestrator flow including:
- End-to-end sharing flow with multiple objects
- Version update flow (modify version, verify update called)
- TLP filtering across multiple instances
- Fail-forward behavior (one instance fails, others continue)

**Validates: Requirements 2.2, 4.2, 4.3, 8.5, 8.6**
"""

import sys
import uuid
from dataclasses import asdict
from typing import Dict, List, Tuple
from unittest.mock import MagicMock, patch, call

import git
import pytest

# Add project root to path for imports
sys.path.insert(0, str(git.Repo(".", search_parent_directories=True).working_dir))

from pymisp import MISPEvent, MISPObject

from Engines.modules.sharing import (
    TLPLevel,
    MISPInstanceConfig,
    OrganisationConfig,
    SharingConfig,
    derive_event_uuid,
)
from Engines.sharing.scope import ScopedObject, compute_sharing_scope
from Engines.sharing.events import (
    ExistenceResult,
    check_existence,
    create_event,
    update_event,
    build_opentide_misp_object,
    should_update_event,
)


# ============================================================================
# Test Fixtures and Factories
# ============================================================================

def make_test_uuid() -> str:
    """Generate a random UUID for testing."""
    return str(uuid.uuid4())


def make_organisation_config(enabled: bool = True) -> OrganisationConfig:
    """Create a test OrganisationConfig."""
    return OrganisationConfig(
        enabled=enabled,
        name="Test Organisation",
        uuid=make_test_uuid()
    )


def make_misp_instance_config(
    name: str = "Test MISP",
    url: str = "https://misp.example.org",
    max_allowed_tlp: TLPLevel = TLPLevel.AMBER,
    proxy: bool = False,
    publish_on_change: bool = False,
    verify_ssl: bool = True
) -> MISPInstanceConfig:
    """Create a test MISPInstanceConfig."""
    return MISPInstanceConfig(
        name=name,
        url=url,
        token="test-api-token-12345",
        org_uuid=make_test_uuid(),
        max_allowed_tlp=max_allowed_tlp,
        mode="send",
        proxy=proxy,
        publish_on_change=publish_on_change,
        verify_ssl=verify_ssl
    )


def make_sharing_config(
    enabled: bool = True,
    instances: List[MISPInstanceConfig] = None
) -> SharingConfig:
    """Create a test SharingConfig."""
    if instances is None:
        instances = []
    return SharingConfig(
        organisation=make_organisation_config(enabled),
        instances=instances
    )


def make_opentide_object(
    obj_uuid: str = None,
    name: str = "Test Object",
    tlp: str = "green",
    version: int = 1,
    obj_type: str = "tvm"
) -> dict:
    """Create a test OpenTIDE object dictionary."""
    if obj_uuid is None:
        obj_uuid = make_test_uuid()
    
    obj = {
        "name": name,
        "metadata": {
            "uuid": obj_uuid,
            "tlp": tlp,
            "version": version
        }
    }
    
    # Add type-specific fields
    if obj_type == "tvm":
        obj["threat"] = {"actors": []}
    elif obj_type == "dom":
        obj["objective"] = {"threats": []}
    elif obj_type == "mdr":
        obj["detection_model"] = None
    
    return obj


def make_all_objects(objects: List[Tuple[str, str, dict]]) -> Dict[str, Tuple[str, dict]]:
    """Create an all_objects dictionary for testing.
    
    Args:
        objects: List of (uuid, object_type, object_data) tuples.
        
    Returns:
        Dictionary mapping UUIDs to (object_type, object_data) tuples.
    """
    return {obj_uuid: (obj_type, obj_data) for obj_uuid, obj_type, obj_data in objects}


def make_mock_misp_event(
    event_uuid: str,
    opentide_uuid: str,
    version: int = 1
) -> MISPEvent:
    """Create a mock MISPEvent with an opentide object."""
    event = MISPEvent()
    event.uuid = event_uuid
    event.id = "12345"
    event.timestamp = 1234567890
    
    # Create opentide object
    obj = MISPObject(name="opentide")
    obj.id = "obj-123"
    obj.uuid = make_test_uuid()
    
    # Add attributes to the object (these are MISPAttribute-like objects)
    class MockAttribute:
        def __init__(self, object_relation: str, value: str):
            self.object_relation = object_relation
            self.value = value
    
    obj.Attribute = [
        MockAttribute("uuid", opentide_uuid),
        MockAttribute("version", str(version)),
        MockAttribute("name", "Test Object"),
        MockAttribute("opentide-type", "tvm"),
    ]
    
    event.Object = [obj]
    event.Tag = []
    event.Galaxy = []
    
    return event


# ============================================================================
# Integration Tests: Full End-to-End Flow
# ============================================================================

class TestEndToEndSharingFlow:
    """Test the complete end-to-end sharing flow with mocked components.
    
    **Validates: Requirements 2.2, 4.2, 4.3, 8.5, 8.6**
    """

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_full_flow_creates_new_events_for_all_objects(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test that full flow creates new MISP events for all objects in scope.
        
        This test verifies the complete flow:
        1. Objects are filtered by TLP scope
        2. Existence is checked for each object
        3. New events are created for objects without existing events
        
        **Validates: Requirements 2.2**
        """
        # Setup mocks
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        # Create mock PyMISP client
        mock_client = MagicMock()
        
        # Configure search to return empty (no existing events)
        mock_client.search.return_value = []
        
        # Configure add_event to return success
        def mock_add_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        mock_client.add_event.side_effect = mock_add_event
        mock_client.publish = MagicMock()
        
        # Create test objects
        obj1_uuid = make_test_uuid()
        obj2_uuid = make_test_uuid()
        obj3_uuid = make_test_uuid()
        
        objects = [
            (obj1_uuid, "tvm", make_opentide_object(obj1_uuid, "TVM Object 1", "green", 1, "tvm")),
            (obj2_uuid, "dom", make_opentide_object(obj2_uuid, "DOM Object 1", "green", 1, "dom")),
            (obj3_uuid, "mdr", make_opentide_object(obj3_uuid, "MDR Object 1", "green", 1, "mdr")),
        ]
        all_objects = make_all_objects(objects)
        
        # Create instance config
        instance_config = make_misp_instance_config(max_allowed_tlp=TLPLevel.AMBER)
        
        # Get scope
        scope = compute_sharing_scope(instance_config, all_objects)
        
        # Process each object - simulate orchestrator flow
        created_count = 0
        for scoped_obj in scope:
            # Check existence
            mock_client.search.return_value = []  # No existing event
            existence = check_existence(mock_client, instance_config.org_uuid, scoped_obj.uuid)
            
            assert not existence.found, "Should not find existing event"
            
            # Create new event
            success = create_event(
                client=mock_client,
                instance_config=instance_config,
                object_uuid=scoped_obj.uuid,
                object_type=scoped_obj.object_type,
                object_data=scoped_obj.data,
                object_name=scoped_obj.name,
                tlp=scoped_obj.tlp
            )
            
            assert success, f"Should successfully create event for {scoped_obj.name}"
            created_count += 1
        
        assert created_count == 3, "Should create events for all 3 objects"
        assert mock_client.add_event.call_count == 3, "Should call add_event 3 times"

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_full_flow_with_mixed_create_and_update(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test flow that mixes creating new events and updating existing ones.
        
        **Validates: Requirements 4.2, 4.3**
        """
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        mock_client = MagicMock()
        
        # Create test objects
        obj1_uuid = make_test_uuid()  # Will be new
        obj2_uuid = make_test_uuid()  # Will exist with older version
        obj3_uuid = make_test_uuid()  # Will exist with current version
        
        objects = [
            (obj1_uuid, "tvm", make_opentide_object(obj1_uuid, "New Object", "green", 1, "tvm")),
            (obj2_uuid, "tvm", make_opentide_object(obj2_uuid, "Update Object", "green", 5, "tvm")),
            (obj3_uuid, "tvm", make_opentide_object(obj3_uuid, "Skip Object", "green", 3, "tvm")),
        ]
        all_objects = make_all_objects(objects)
        
        instance_config = make_misp_instance_config()
        scope = compute_sharing_scope(instance_config, all_objects)
        
        # Setup search results for different objects
        search_results = {
            obj1_uuid: [],  # No existing event
            obj2_uuid: [make_mock_misp_event(derive_event_uuid(obj2_uuid), obj2_uuid, version=3)],  # Older version
            obj3_uuid: [make_mock_misp_event(derive_event_uuid(obj3_uuid), obj3_uuid, version=3)],  # Same version
        }
        
        def mock_search(*args, **kwargs):
            value = kwargs.get('value')
            return search_results.get(value, [])
        
        mock_client.search.side_effect = mock_search
        
        # Mock add_event and update_event
        def mock_add_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        def mock_update_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = str(event.id) if hasattr(event, 'id') else "12345"
            return result
        
        mock_client.add_event.side_effect = mock_add_event
        mock_client.update_event.side_effect = mock_update_event
        mock_client.delete_object = MagicMock()
        
        # Track operations
        operations = {"created": 0, "updated": 0, "skipped": 0}
        
        for scoped_obj in scope:
            existence = check_existence(mock_client, instance_config.org_uuid, scoped_obj.uuid)
            local_version = scoped_obj.data["metadata"]["version"]
            
            if not existence.found:
                success = create_event(
                    client=mock_client,
                    instance_config=instance_config,
                    object_uuid=scoped_obj.uuid,
                    object_type=scoped_obj.object_type,
                    object_data=scoped_obj.data,
                    object_name=scoped_obj.name,
                    tlp=scoped_obj.tlp
                )
                if success:
                    operations["created"] += 1
            else:
                should_update, _ = should_update_event(local_version, existence.remote_version)
                
                if should_update:
                    success = update_event(
                        client=mock_client,
                        instance_config=instance_config,
                        existing_event=existence.event,
                        object_uuid=scoped_obj.uuid,
                        object_type=scoped_obj.object_type,
                        object_data=scoped_obj.data,
                        object_name=scoped_obj.name,
                        tlp=scoped_obj.tlp
                    )
                    if success:
                        operations["updated"] += 1
                else:
                    operations["skipped"] += 1
        
        assert operations["created"] == 1, "Should create 1 new event"
        assert operations["updated"] == 1, "Should update 1 existing event"
        assert operations["skipped"] == 1, "Should skip 1 event with current version"


# ============================================================================
# Integration Tests: Version Update Flow
# ============================================================================

class TestVersionUpdateFlow:
    """Test version comparison and update flow.
    
    **Validates: Requirements 4.2, 4.3**
    """

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_version_update_triggers_event_update(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test that a higher local version triggers an event update.
        
        **Validates: Requirements 4.2**
        - WHEN local version > remote version, THE Sharing_Engine SHALL update
        """
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        mock_client = MagicMock()
        
        obj_uuid = make_test_uuid()
        local_version = 10
        remote_version = 5
        
        # Create existing event with older version
        existing_event = make_mock_misp_event(
            derive_event_uuid(obj_uuid), 
            obj_uuid, 
            version=remote_version
        )
        
        mock_client.search.return_value = [existing_event]
        mock_client.delete_object = MagicMock()
        
        def mock_update_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        mock_client.update_event.side_effect = mock_update_event
        
        instance_config = make_misp_instance_config()
        obj_data = make_opentide_object(obj_uuid, "Test Object", "green", local_version, "tvm")
        
        # Check existence
        existence = check_existence(mock_client, instance_config.org_uuid, obj_uuid)
        
        assert existence.found, "Should find existing event"
        assert existence.remote_version == remote_version
        
        # Verify update should happen
        should_update, _ = should_update_event(local_version, existence.remote_version)
        assert should_update, "Should update when local > remote version"
        
        # Perform update
        success = update_event(
            client=mock_client,
            instance_config=instance_config,
            existing_event=existence.event,
            object_uuid=obj_uuid,
            object_type="tvm",
            object_data=obj_data,
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        assert success, "Update should succeed"
        mock_client.update_event.assert_called_once()

    def test_version_equal_or_lower_skips_update(self):
        """Test that equal or lower local version skips update.
        
        **Validates: Requirements 4.3**
        - WHEN local version <= remote version, THE Sharing_Engine SHALL skip
        """
        # Equal version
        should_update, reason = should_update_event(5, 5)
        assert not should_update, "Should skip when versions are equal"
        assert reason == "skip"
        
        # Lower version
        should_update, reason = should_update_event(3, 5)
        assert not should_update, "Should skip when local < remote"
        assert reason == "skip"

    def test_missing_remote_version_treated_as_zero(self):
        """Test that missing remote version is treated as 0.
        
        **Validates: Requirements 4.5**
        """
        # Local version 1 > remote version 0 (missing)
        should_update, reason = should_update_event(1, 0)
        assert should_update, "Should update when remote version is 0 (missing)"

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_publish_on_change_triggers_publish(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test that publish_on_change=True triggers event publish after update.
        
        **Validates: Requirements 1.8**
        """
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        mock_client = MagicMock()
        
        obj_uuid = make_test_uuid()
        existing_event = make_mock_misp_event(derive_event_uuid(obj_uuid), obj_uuid, version=1)
        
        mock_client.delete_object = MagicMock()
        
        def mock_update_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        mock_client.update_event.side_effect = mock_update_event
        mock_client.publish = MagicMock()
        
        # Instance with publish_on_change=True
        instance_config = make_misp_instance_config(publish_on_change=True)
        obj_data = make_opentide_object(obj_uuid, "Test Object", "green", 2, "tvm")
        
        success = update_event(
            client=mock_client,
            instance_config=instance_config,
            existing_event=existing_event,
            object_uuid=obj_uuid,
            object_type="tvm",
            object_data=obj_data,
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        assert success
        mock_client.publish.assert_called_once()
        # Verify alert=False
        call_kwargs = mock_client.publish.call_args[1]
        assert call_kwargs.get('alert') is False


# ============================================================================
# Integration Tests: TLP Filtering Across Multiple Instances
# ============================================================================

class TestTLPFilteringAcrossInstances:
    """Test TLP-based filtering across multiple MISP instances.
    
    **Validates: Requirements 2.2**
    """

    def test_same_objects_filtered_differently_per_instance_tlp(self):
        """Test that the same objects are filtered differently based on instance TLP.
        
        **Validates: Requirements 2.2, 2.4**
        - Objects are included iff TLP <= instance max_allowed_tlp
        - TLP filtering is evaluated independently per instance
        """
        # Create objects with different TLP levels
        obj_clear = make_test_uuid()
        obj_green = make_test_uuid()
        obj_amber = make_test_uuid()
        obj_red = make_test_uuid()
        
        objects = [
            (obj_clear, "tvm", make_opentide_object(obj_clear, "Clear Object", "clear", 1, "tvm")),
            (obj_green, "tvm", make_opentide_object(obj_green, "Green Object", "green", 1, "tvm")),
            (obj_amber, "tvm", make_opentide_object(obj_amber, "Amber Object", "amber", 1, "tvm")),
            (obj_red, "tvm", make_opentide_object(obj_red, "Red Object", "red", 1, "tvm")),
        ]
        all_objects = make_all_objects(objects)
        
        # Create instances with different max_allowed_tlp
        instance_green = make_misp_instance_config(name="Green MISP", max_allowed_tlp=TLPLevel.GREEN)
        instance_amber = make_misp_instance_config(name="Amber MISP", max_allowed_tlp=TLPLevel.AMBER)
        instance_red = make_misp_instance_config(name="Red MISP", max_allowed_tlp=TLPLevel.RED)
        
        # Compute scopes for each instance
        scope_green = compute_sharing_scope(instance_green, all_objects)
        scope_amber = compute_sharing_scope(instance_amber, all_objects)
        scope_red = compute_sharing_scope(instance_red, all_objects)
        
        # Verify scope sizes
        assert len(scope_green) == 2, "Green instance should get clear + green objects"
        assert len(scope_amber) == 3, "Amber instance should get clear + green + amber objects"
        assert len(scope_red) == 4, "Red instance should get all objects"
        
        # Verify specific objects in each scope
        green_uuids = {obj.uuid for obj in scope_green}
        amber_uuids = {obj.uuid for obj in scope_amber}
        red_uuids = {obj.uuid for obj in scope_red}
        
        assert obj_clear in green_uuids and obj_green in green_uuids
        assert obj_red not in green_uuids and obj_amber not in green_uuids
        
        assert obj_clear in amber_uuids and obj_green in amber_uuids and obj_amber in amber_uuids
        assert obj_red not in amber_uuids
        
        assert all(u in red_uuids for u in [obj_clear, obj_green, obj_amber, obj_red])

    def test_white_and_clear_are_equivalent(self):
        """Test that 'white' and 'clear' TLP are treated equivalently.
        
        **Validates: Requirements 2.1, 2.6**
        """
        obj_white = make_test_uuid()
        obj_clear = make_test_uuid()
        
        objects = [
            (obj_white, "tvm", make_opentide_object(obj_white, "White Object", "white", 1, "tvm")),
            (obj_clear, "tvm", make_opentide_object(obj_clear, "Clear Object", "clear", 1, "tvm")),
        ]
        all_objects = make_all_objects(objects)
        
        # Instance with CLEAR TLP
        instance = make_misp_instance_config(max_allowed_tlp=TLPLevel.CLEAR)
        scope = compute_sharing_scope(instance, all_objects)
        
        # Both should be in scope
        assert len(scope) == 2, "Both white and clear objects should be in scope"
        scope_uuids = {obj.uuid for obj in scope}
        assert obj_white in scope_uuids and obj_clear in scope_uuids

    def test_objects_without_tlp_excluded_from_all_instances(self):
        """Test that objects without TLP are excluded from all sharing scopes.
        
        **Validates: Requirements 2.3**
        """
        obj_no_tlp = make_test_uuid()
        obj_data = {
            "name": "No TLP Object",
            "metadata": {
                "uuid": obj_no_tlp,
                "version": 1
                # No tlp field!
            }
        }
        
        objects = [(obj_no_tlp, "tvm", obj_data)]
        all_objects = make_all_objects(objects)
        
        # Test across multiple instances
        instance_green = make_misp_instance_config(max_allowed_tlp=TLPLevel.GREEN)
        instance_red = make_misp_instance_config(max_allowed_tlp=TLPLevel.RED)
        
        scope_green = compute_sharing_scope(instance_green, all_objects)
        scope_red = compute_sharing_scope(instance_red, all_objects)
        
        assert len(scope_green) == 0, "Object without TLP should be excluded from green instance"
        assert len(scope_red) == 0, "Object without TLP should be excluded even from red instance"


# ============================================================================
# Integration Tests: Fail-Forward Behavior
# ============================================================================

class TestFailForwardBehavior:
    """Test fail-forward behavior where failures don't halt the pipeline.
    
    **Validates: Requirements 8.5, 8.6**
    """

    @patch("Engines.sharing.connector.PyMISP")
    @patch("Engines.sharing.connector.log")
    def test_connection_failure_to_one_instance_allows_others(
        self,
        mock_log,
        mock_pymisp_class
    ):
        """Test that connection failure to one instance doesn't stop processing of others.
        
        **Validates: Requirements 8.6**
        - IF a MISP_Instance is unreachable, THE Sharing_Engine SHALL log FATAL
          and proceed to the next configured instance
        """
        from Engines.sharing.connector import create_misp_client
        
        # First instance fails, second succeeds
        instance1_config = make_misp_instance_config(name="Failing MISP", url="https://bad.misp.org")
        instance2_config = make_misp_instance_config(name="Working MISP", url="https://good.misp.org")
        
        call_count = [0]
        
        def mock_pymisp_init(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionRefusedError("Connection refused")
            mock_client = MagicMock()
            mock_client.misp_instance_version = {"version": "2.4.180"}
            return mock_client
        
        mock_pymisp_class.side_effect = mock_pymisp_init
        
        # First instance should fail
        client1 = create_misp_client(instance1_config)
        assert client1 is None, "First instance should fail to connect"
        
        # Second instance should succeed
        client2 = create_misp_client(instance2_config)
        assert client2 is not None, "Second instance should connect successfully"
        
        # Verify FATAL was logged for the failure
        fatal_calls = [c for c in mock_log.call_args_list if c[0][0] == "FATAL"]
        assert len(fatal_calls) >= 1, "Should log FATAL for connection failure"

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_api_error_on_one_object_continues_processing_others(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test that API error on one object doesn't halt processing of other objects.
        
        **Validates: Requirements 8.5**
        - WHEN PyMISP raises an exception, THE Sharing_Engine SHALL log FAILURE
          and continue processing remaining objects
        """
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        mock_client = MagicMock()
        
        # Create objects
        obj1_uuid = make_test_uuid()  # Will fail
        obj2_uuid = make_test_uuid()  # Will succeed
        obj3_uuid = make_test_uuid()  # Will succeed
        
        objects = [
            (obj1_uuid, "tvm", make_opentide_object(obj1_uuid, "Failing Object", "green", 1, "tvm")),
            (obj2_uuid, "tvm", make_opentide_object(obj2_uuid, "Success Object 1", "green", 1, "tvm")),
            (obj3_uuid, "tvm", make_opentide_object(obj3_uuid, "Success Object 2", "green", 1, "tvm")),
        ]
        all_objects = make_all_objects(objects)
        
        mock_client.search.return_value = []  # No existing events
        
        # First add_event fails, others succeed
        call_count = [0]
        
        def mock_add_event(event, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("API Error: Server error 500")
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        mock_client.add_event.side_effect = mock_add_event
        
        instance_config = make_misp_instance_config()
        scope = compute_sharing_scope(instance_config, all_objects)
        
        # Track results
        results = {"success": 0, "failed": 0}
        
        for scoped_obj in scope:
            success = create_event(
                client=mock_client,
                instance_config=instance_config,
                object_uuid=scoped_obj.uuid,
                object_type=scoped_obj.object_type,
                object_data=scoped_obj.data,
                object_name=scoped_obj.name,
                tlp=scoped_obj.tlp
            )
            
            if success:
                results["success"] += 1
            else:
                results["failed"] += 1
        
        assert results["failed"] == 1, "One object should fail"
        assert results["success"] == 2, "Two objects should succeed"
        assert mock_client.add_event.call_count == 3, "Should attempt all 3 objects"

    def test_existence_check_api_error_skips_object(self):
        """Test that API error during existence check skips the object gracefully.
        
        **Validates: Requirements 3.4, 8.5**
        """
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("Network timeout")
        
        obj_uuid = make_test_uuid()
        org_uuid = make_test_uuid()
        
        # Should not raise, should return found=False
        result = check_existence(mock_client, org_uuid, obj_uuid)
        
        assert not result.found, "Should return found=False on API error"

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_full_pipeline_with_mixed_failures(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test full pipeline with multiple instances and mixed object failures.
        
        This is a comprehensive integration test that verifies:
        - Multiple MISP instances are processed
        - Failures on one instance don't affect others
        - Individual object failures don't halt instance processing
        
        **Validates: Requirements 8.5, 8.6**
        """
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        # Create two mock clients
        client1 = MagicMock()
        client2 = MagicMock()
        
        # Create objects
        obj1_uuid = make_test_uuid()
        obj2_uuid = make_test_uuid()
        
        objects = [
            (obj1_uuid, "tvm", make_opentide_object(obj1_uuid, "Object 1", "green", 1, "tvm")),
            (obj2_uuid, "tvm", make_opentide_object(obj2_uuid, "Object 2", "green", 1, "tvm")),
        ]
        all_objects = make_all_objects(objects)
        
        # Configure client1: first object fails, second succeeds
        client1.search.return_value = []
        client1_call_count = [0]
        
        def client1_add_event(event, **kwargs):
            client1_call_count[0] += 1
            if client1_call_count[0] == 1:
                raise Exception("Instance 1 API Error")
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        client1.add_event.side_effect = client1_add_event
        
        # Configure client2: all succeed
        client2.search.return_value = []
        
        def client2_add_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "67890"
            return result
        
        client2.add_event.side_effect = client2_add_event
        
        # Create instance configs
        instance1 = make_misp_instance_config(name="Instance 1")
        instance2 = make_misp_instance_config(name="Instance 2")
        
        # Simulate processing both instances
        instances_results = {}
        
        for instance_config, client in [(instance1, client1), (instance2, client2)]:
            scope = compute_sharing_scope(instance_config, all_objects)
            counters = {"shared": 0, "failed": 0}
            
            for scoped_obj in scope:
                success = create_event(
                    client=client,
                    instance_config=instance_config,
                    object_uuid=scoped_obj.uuid,
                    object_type=scoped_obj.object_type,
                    object_data=scoped_obj.data,
                    object_name=scoped_obj.name,
                    tlp=scoped_obj.tlp
                )
                
                if success:
                    counters["shared"] += 1
                else:
                    counters["failed"] += 1
            
            instances_results[instance_config.name] = counters
        
        # Verify Instance 1: 1 failed, 1 succeeded
        assert instances_results["Instance 1"]["failed"] == 1
        assert instances_results["Instance 1"]["shared"] == 1
        
        # Verify Instance 2: all succeeded
        assert instances_results["Instance 2"]["failed"] == 0
        assert instances_results["Instance 2"]["shared"] == 2


# ============================================================================
# Integration Tests: Duplicate Event Handling
# ============================================================================

class TestDuplicateEventHandling:
    """Test handling of duplicate MISP events.
    
    **Validates: Requirements 3.3**
    """

    def test_multiple_existing_events_uses_most_recent(self):
        """Test that when multiple matching events exist, the most recent is used.
        
        **Validates: Requirements 3.3**
        - IF the existence query returns more than one matching MISP_Event,
          THEN THE Sharing_Engine SHALL use the most recently modified event
        """
        mock_client = MagicMock()
        
        obj_uuid = make_test_uuid()
        org_uuid = make_test_uuid()
        
        # Create two events with different timestamps
        event1 = make_mock_misp_event(derive_event_uuid(obj_uuid), obj_uuid, version=2)
        event1.timestamp = 1000000000  # Older
        
        event2 = make_mock_misp_event(derive_event_uuid(obj_uuid), obj_uuid, version=3)
        event2.timestamp = 2000000000  # Newer
        
        # Return both events
        mock_client.search.return_value = [event1, event2]
        
        result = check_existence(mock_client, org_uuid, obj_uuid)
        
        assert result.found, "Should find existing event"
        assert result.remote_version == 3, "Should use version from most recent event"
        assert result.event.timestamp == 2000000000, "Should select the most recent event"


# ============================================================================
# Integration Tests: Object Type Handling
# ============================================================================

class TestObjectTypeHandling:
    """Test handling of different object types (TVM, DOM, MDR)."""

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_all_object_types_processed_correctly(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test that TVM, DOM, and MDR objects are all processed correctly."""
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        mock_client = MagicMock()
        mock_client.search.return_value = []
        
        def mock_add_event(event, **kwargs):
            result = MISPEvent()
            result.uuid = event.uuid
            result.id = "12345"
            return result
        
        mock_client.add_event.side_effect = mock_add_event
        
        instance_config = make_misp_instance_config()
        
        # Test each object type
        for obj_type in ["tvm", "dom", "mdr"]:
            obj_uuid = make_test_uuid()
            obj_data = make_opentide_object(obj_uuid, f"Test {obj_type.upper()}", "green", 1, obj_type)
            
            success = create_event(
                client=mock_client,
                instance_config=instance_config,
                object_uuid=obj_uuid,
                object_type=obj_type,
                object_data=obj_data,
                object_name=f"Test {obj_type.upper()}",
                tlp=TLPLevel.GREEN
            )
            
            assert success, f"Should successfully create event for {obj_type}"
        
        assert mock_client.add_event.call_count == 3, "Should create events for all 3 object types"


# ============================================================================
# Integration Tests: Deterministic Event UUID
# ============================================================================

class TestDeterministicEventUUID:
    """Test that event UUIDs are derived deterministically.
    
    **Validates: Requirements 5.9**
    """

    @patch("Engines.sharing.events.resolve_relations")
    @patch("Engines.sharing.events.build_attack_tags")
    @patch("Engines.sharing.events.build_actor_galaxies")
    def test_same_object_gets_same_event_uuid_across_instances(
        self,
        mock_actor_galaxies,
        mock_attack_tags,
        mock_resolve_relations
    ):
        """Test that the same object gets the same event UUID regardless of instance.
        
        **Validates: Requirements 5.9**
        """
        mock_resolve_relations.return_value = []
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        obj_uuid = make_test_uuid()
        obj_data = make_opentide_object(obj_uuid, "Test Object", "green", 1, "tvm")
        
        created_event_uuids = []
        
        # Create events on two different instances
        for instance_name in ["Instance 1", "Instance 2"]:
            mock_client = MagicMock()
            mock_client.search.return_value = []
            
            def mock_add_event(event, **kwargs):
                created_event_uuids.append(event.uuid)
                result = MISPEvent()
                result.uuid = event.uuid
                result.id = "12345"
                return result
            
            mock_client.add_event.side_effect = mock_add_event
            
            instance_config = make_misp_instance_config(name=instance_name)
            
            create_event(
                client=mock_client,
                instance_config=instance_config,
                object_uuid=obj_uuid,
                object_type="tvm",
                object_data=obj_data,
                object_name="Test Object",
                tlp=TLPLevel.GREEN
            )
        
        assert len(created_event_uuids) == 2, "Should create events on both instances"
        assert created_event_uuids[0] == created_event_uuids[1], \
            "Event UUIDs should be identical across instances"
        assert created_event_uuids[0] == derive_event_uuid(obj_uuid), \
            "Event UUID should match the deterministic derivation"
