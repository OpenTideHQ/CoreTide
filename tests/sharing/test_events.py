"""Tests for Engines/sharing/events.py — MISP event lifecycle tests.

This module tests the event lifecycle functions in the sharing pipeline:
- build_opentide_misp_object(): MISP object construction
- check_existence(): Existence check querying MISP for existing events
- create_event(): Creating new MISP events
- update_event(): Updating existing MISP events
- should_update_event(): Version comparison logic

Requirements tested:
- 3.1: Query by org_uuid and opentide uuid attribute
- 3.2: Filter to events owned by org_uuid
- 3.3: Handle multiple matches - use most recently modified
- 3.4: Handle API errors gracefully
- 4.1: Compare versions using integer numeric comparison
- 4.2: Update when local > remote
- 4.3: Skip when local <= remote
- 4.4: Create new event when no matching event found
- 4.5: Handle missing/unparseable version as 0
- 5.3: Required attributes: name, opentide-object, opentide-type, uuid, version
- 5.4: opentide-relation with UUIDs according to object type rules
- 5.8: Omit opentide-relation if no resolvable relations
- 1.8: Publish without email when publish_on_change is True
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))


# ============================================================================
# Mock Setup - must be done BEFORE any imports that trigger DataTide
# ============================================================================

class MockHelperTide:
    """Mock HelperTide for tests."""
    
    @staticmethod
    def is_debug():
        return True
    
    @staticmethod
    def fetch_config_envvar(config_secrets: dict) -> dict:
        """Mock environment variable resolution."""
        return dict(config_secrets)


# Mock the tide module before importing events to avoid DataTide initialization
mock_tide = MagicMock()
mock_tide.HelperTide = MockHelperTide
mock_tide.DataTide = MagicMock()
mock_tide.DataTide.Models = MagicMock()
mock_tide.DataTide.Models.chaining = {}
sys.modules['Engines.modules.tide'] = mock_tide

# Mock the logs module
mock_logs = MagicMock()
mock_logs.log = MagicMock()
sys.modules['Engines.modules.logs'] = mock_logs

import pytest
import yaml

# Remove cached modules if present to ensure fresh import with mocks
modules_to_clear = [
    'Engines.modules.sharing',
    'Engines.sharing.events',
    'Engines.sharing.relations',
    'Engines.sharing.tagging',
]
for mod in modules_to_clear:
    if mod in sys.modules:
        del sys.modules[mod]

from pymisp import MISPObject, MISPEvent, MISPAttribute

from Engines.modules.sharing import MISPInstanceConfig, TLPLevel
from Engines.sharing.events import (
    build_opentide_misp_object,
    OPENTIDE_TEMPLATE_UUID,
    ExistenceResult,
    should_update_event,
    log_skip_version_current,
    check_existence,
    create_event,
    update_event,
    _event_has_matching_opentide,
    _extract_opentide_version,
    API_TIMEOUT,
)


def _create_instance_config(
    name: str = "Test MISP",
    url: str = "https://misp.test.org",
    token: str = "test-api-token",
    org_uuid: str = "11111111-2222-3333-4444-555555555555",
    max_allowed_tlp: TLPLevel = TLPLevel.AMBER,
    mode: str = "send",
    proxy: bool = False,
    publish_on_change: bool = True,
    verify_ssl: bool = True
) -> MISPInstanceConfig:
    """Helper function to create MISPInstanceConfig for tests."""
    return MISPInstanceConfig(
        name=name,
        url=url,
        token=token,
        org_uuid=org_uuid,
        max_allowed_tlp=max_allowed_tlp,
        mode=mode,
        proxy=proxy,
        publish_on_change=publish_on_change,
        verify_ssl=verify_ssl
    )


def _create_mock_misp_event(
    event_uuid: str = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
    timestamp: int = 1700000000,
    opentide_uuid: str = None,
    opentide_version: str = "1",
    has_opentide_object: bool = True
) -> MISPEvent:
    """Helper function to create a mock MISPEvent for tests."""
    event = MagicMock(spec=MISPEvent)
    event.uuid = event_uuid
    event.timestamp = timestamp
    event.Tag = []
    event.Galaxy = []
    
    if has_opentide_object and opentide_uuid:
        # Create a mock opentide object with attributes
        mock_opentide_obj = MagicMock()
        mock_opentide_obj.name = "opentide"
        
        # Create mock attributes
        uuid_attr = MagicMock()
        uuid_attr.object_relation = "uuid"
        uuid_attr.value = opentide_uuid
        
        version_attr = MagicMock()
        version_attr.object_relation = "version"
        version_attr.value = opentide_version
        
        mock_opentide_obj.Attribute = [uuid_attr, version_attr]
        event.Object = [mock_opentide_obj]
    else:
        event.Object = []
    
    return event


class TestBuildOpentideMispObject:
    """Tests for the build_opentide_misp_object() function."""

    def test_template_uuid_is_correct(self):
        """Verify the template UUID constant is set correctly."""
        assert OPENTIDE_TEMPLATE_UUID == "892fd46a-f69e-455c-8c4f-843a4b8f4295"

    def test_creates_misp_object_with_correct_name(self):
        """Test that the MISPObject has name='opentide'."""
        object_data = {
            "metadata": {
                "uuid": "11111111-1111-1111-1111-111111111111",
                "version": 1,
            },
            "name": "Test Object",
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid="11111111-1111-1111-1111-111111111111",
                object_type="tvm",
                object_data=object_data,
                object_name="Test Object"
            )
        
        assert isinstance(result, MISPObject)
        assert result.name == "opentide"

    def test_required_attributes_present(self):
        """Test that all required attributes are present in the MISP object.
        
        Requirements 5.3: Required attributes: name, opentide-object, 
        opentide-type, uuid, version
        """
        object_uuid = "22222222-2222-2222-2222-222222222222"
        object_data = {
            "metadata": {
                "uuid": object_uuid,
                "version": 5,
            },
            "name": "My Test TVM",
            "description": "A test description",
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="My Test TVM"
            )
        
        # Extract attribute values by object_relation
        attrs = {attr.object_relation: attr.value for attr in result.Attribute}
        
        assert "name" in attrs
        assert "opentide-object" in attrs
        assert "opentide-type" in attrs
        assert "uuid" in attrs
        assert "version" in attrs

    def test_name_attribute_value(self):
        """Test that the name attribute contains the object title."""
        object_data = {
            "metadata": {
                "uuid": "33333333-3333-3333-3333-333333333333",
                "version": 1,
            },
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid="33333333-3333-3333-3333-333333333333",
                object_type="dom",
                object_data=object_data,
                object_name="My Detection Objective"
            )
        
        attrs = {attr.object_relation: attr.value for attr in result.Attribute}
        assert attrs["name"] == "My Detection Objective"

    def test_opentide_object_attribute_is_yaml(self):
        """Test that opentide-object contains YAML serialization of object_data."""
        object_data = {
            "metadata": {
                "uuid": "44444444-4444-4444-4444-444444444444",
                "version": 3,
            },
            "name": "Test",
            "nested": {"key": "value"},
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid="44444444-4444-4444-4444-444444444444",
                object_type="mdr",
                object_data=object_data,
                object_name="Test"
            )
        
        attrs = {attr.object_relation: attr.value for attr in result.Attribute}
        
        # Parse the YAML content and verify it matches original data
        parsed_yaml = yaml.safe_load(attrs["opentide-object"])
        assert parsed_yaml == object_data

    def test_opentide_type_attribute_values(self):
        """Test that opentide-type is set correctly for each object type."""
        object_data = {
            "metadata": {
                "uuid": "55555555-5555-5555-5555-555555555555",
                "version": 1,
            },
        }
        
        for obj_type in ["tvm", "dom", "mdr"]:
            with patch('Engines.sharing.events.resolve_relations', return_value=[]):
                result = build_opentide_misp_object(
                    object_uuid="55555555-5555-5555-5555-555555555555",
                    object_type=obj_type,
                    object_data=object_data,
                    object_name="Test"
                )
            
            attrs = {attr.object_relation: attr.value for attr in result.Attribute}
            assert attrs["opentide-type"] == obj_type

    def test_uuid_attribute_value(self):
        """Test that the uuid attribute contains the OpenTIDE object UUID."""
        object_uuid = "66666666-6666-6666-6666-666666666666"
        object_data = {
            "metadata": {
                "uuid": object_uuid,
                "version": 1,
            },
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test"
            )
        
        attrs = {attr.object_relation: attr.value for attr in result.Attribute}
        assert attrs["uuid"] == object_uuid

    def test_version_attribute_is_string(self):
        """Test that the version attribute is converted to a string."""
        object_data = {
            "metadata": {
                "uuid": "77777777-7777-7777-7777-777777777777",
                "version": 42,
            },
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid="77777777-7777-7777-7777-777777777777",
                object_type="tvm",
                object_data=object_data,
                object_name="Test"
            )
        
        attrs = {attr.object_relation: attr.value for attr in result.Attribute}
        assert attrs["version"] == "42"
        assert isinstance(attrs["version"], str)

    def test_relations_added_as_multi_value(self):
        """Test that opentide-relation is added as multi-value attribute.
        
        Requirements 5.4: opentide-relation with UUIDs according to object type rules
        """
        object_uuid = "88888888-8888-8888-8888-888888888888"
        object_data = {
            "metadata": {
                "uuid": object_uuid,
                "version": 1,
            },
        }
        
        mock_relations = [
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
        ]
        
        with patch('Engines.sharing.events.resolve_relations', return_value=mock_relations):
            result = build_opentide_misp_object(
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test"
            )
        
        # Get all opentide-relation attribute values
        relation_values = [
            attr.value for attr in result.Attribute 
            if attr.object_relation == "opentide-relation"
        ]
        
        assert len(relation_values) == 3
        assert set(relation_values) == set(mock_relations)

    def test_relations_omitted_when_empty(self):
        """Test that opentide-relation is omitted when no relations exist.
        
        Requirements 5.8: Omit opentide-relation if no resolvable relations
        """
        object_uuid = "99999999-9999-9999-9999-999999999999"
        object_data = {
            "metadata": {
                "uuid": object_uuid,
                "version": 1,
            },
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test"
            )
        
        # Check that no opentide-relation attributes exist
        relation_attrs = [
            attr for attr in result.Attribute 
            if attr.object_relation == "opentide-relation"
        ]
        
        assert len(relation_attrs) == 0

    def test_default_version_when_missing(self):
        """Test that version defaults to '0' when metadata.version is missing."""
        object_data = {
            "metadata": {
                "uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                # version is missing
            },
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                object_type="tvm",
                object_data=object_data,
                object_name="Test"
            )
        
        attrs = {attr.object_relation: attr.value for attr in result.Attribute}
        assert attrs["version"] == "0"


class TestExistenceResult:
    """Tests for the ExistenceResult dataclass."""

    def test_default_values(self):
        """Test that ExistenceResult has correct default values."""
        result = ExistenceResult(found=False)
        assert result.found is False
        assert result.event is None
        assert result.remote_version == 0

    def test_with_event(self):
        """Test ExistenceResult with an event."""
        mock_event = MagicMock()
        result = ExistenceResult(found=True, event=mock_event, remote_version=5)
        assert result.found is True
        assert result.event == mock_event
        assert result.remote_version == 5


class TestShouldUpdateEvent:
    """Tests for the should_update_event() function."""

    def test_update_when_local_greater(self):
        """Test that update is indicated when local version > remote version."""
        should_update, reason = should_update_event(local_version=5, remote_version=3)
        assert should_update is True
        assert reason == "update"

    def test_skip_when_versions_equal(self):
        """Test that skip is indicated when versions are equal."""
        should_update, reason = should_update_event(local_version=3, remote_version=3)
        assert should_update is False
        assert reason == "skip"

    def test_skip_when_local_less(self):
        """Test that skip is indicated when local version < remote version."""
        should_update, reason = should_update_event(local_version=2, remote_version=5)
        assert should_update is False
        assert reason == "skip"

    def test_update_when_remote_is_zero(self):
        """Test update when remote version is 0 (missing/unparseable)."""
        should_update, reason = should_update_event(local_version=1, remote_version=0)
        assert should_update is True
        assert reason == "update"


# ============================================================================
# Tests for check_existence() function
# ============================================================================

class TestCheckExistenceZeroResults:
    """Tests for check_existence() when MISP search returns 0 results.
    
    **Validates: Requirements 3.1, 3.2, 3.4**
    """

    @patch('Engines.sharing.events.PyMISP')
    def test_returns_not_found_when_search_returns_empty_list(self, mock_pymisp_class):
        """Test that ExistenceResult.found=False when search returns empty list.
        
        **Validates: Requirements 3.1, 3.2**
        """
        mock_client = MagicMock()
        mock_client.search.return_value = []
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        assert result.found is False
        assert result.event is None
        assert result.remote_version == 0

    @patch('Engines.sharing.events.PyMISP')
    def test_returns_not_found_when_search_returns_none(self, mock_pymisp_class):
        """Test that ExistenceResult.found=False when search returns None.
        
        **Validates: Requirements 3.4**
        """
        mock_client = MagicMock()
        mock_client.search.return_value = None
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        assert result.found is False
        assert result.event is None

    @patch('Engines.sharing.events.PyMISP')
    def test_search_called_with_correct_parameters(self, mock_pymisp_class):
        """Test that PyMISP.search is called with correct parameters.
        
        **Validates: Requirements 3.1, 3.2**
        
        Search should filter by:
        - org_uuid (events owned by our org)
        - object_name='opentide'
        - value matching the OpenTIDE UUID
        """
        mock_client = MagicMock()
        mock_client.search.return_value = []
        
        check_existence(
            client=mock_client,
            org_uuid="org-uuid-12345",
            opentide_uuid="opentide-uuid-67890"
        )
        
        mock_client.search.assert_called_once_with(
            controller='events',
            org="org-uuid-12345",
            object_name='opentide',
            value="opentide-uuid-67890",
            pythonify=True,
            timeout=API_TIMEOUT
        )


class TestCheckExistenceOneResult:
    """Tests for check_existence() when MISP search returns 1 result.
    
    **Validates: Requirements 3.1, 3.2, 4.5**
    """

    @patch('Engines.sharing.events.PyMISP')
    def test_returns_found_with_event_when_single_match(self, mock_pymisp_class):
        """Test that ExistenceResult.found=True with event when single match exists.
        
        **Validates: Requirements 3.1, 3.2**
        """
        mock_client = MagicMock()
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        
        mock_event = _create_mock_misp_event(
            event_uuid="event-uuid-123",
            opentide_uuid=opentide_uuid,
            opentide_version="5"
        )
        mock_client.search.return_value = [mock_event]
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        assert result.event == mock_event

    @patch('Engines.sharing.events.PyMISP')
    def test_extracts_version_from_opentide_object(self, mock_pymisp_class):
        """Test that version is extracted from the opentide object.
        
        **Validates: Requirements 4.5**
        """
        mock_client = MagicMock()
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        
        mock_event = _create_mock_misp_event(
            opentide_uuid=opentide_uuid,
            opentide_version="42"
        )
        mock_client.search.return_value = [mock_event]
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=opentide_uuid
        )
        
        assert result.remote_version == 42

    @patch('Engines.sharing.events.PyMISP')
    def test_version_defaults_to_zero_when_missing(self, mock_pymisp_class):
        """Test that version defaults to 0 when version attribute is missing.
        
        **Validates: Requirements 4.5**
        """
        mock_client = MagicMock()
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        
        # Create event with opentide object but no version attribute
        mock_event = MagicMock(spec=MISPEvent)
        mock_event.uuid = "event-uuid-123"
        mock_event.timestamp = 1700000000
        
        mock_opentide_obj = MagicMock()
        mock_opentide_obj.name = "opentide"
        
        uuid_attr = MagicMock()
        uuid_attr.object_relation = "uuid"
        uuid_attr.value = opentide_uuid
        # No version attribute
        mock_opentide_obj.Attribute = [uuid_attr]
        mock_event.Object = [mock_opentide_obj]
        
        mock_client.search.return_value = [mock_event]
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        assert result.remote_version == 0

    @patch('Engines.sharing.events.PyMISP')
    def test_version_defaults_to_zero_when_unparseable(self, mock_pymisp_class):
        """Test that version defaults to 0 when version attribute is not a valid integer.
        
        **Validates: Requirements 4.5**
        """
        mock_client = MagicMock()
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        
        mock_event = _create_mock_misp_event(
            opentide_uuid=opentide_uuid,
            opentide_version="not-a-number"  # Invalid version
        )
        mock_client.search.return_value = [mock_event]
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        assert result.remote_version == 0


class TestCheckExistenceMultipleResults:
    """Tests for check_existence() when MISP search returns N>1 results.
    
    **Validates: Requirements 3.3, 3.4**
    """

    @patch('Engines.sharing.events.PyMISP')
    def test_uses_most_recently_modified_event(self, mock_pymisp_class):
        """Test that the most recently modified event is used when multiple matches exist.
        
        **Validates: Requirements 3.3**
        """
        mock_client = MagicMock()
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        
        # Create multiple events with different timestamps
        older_event = _create_mock_misp_event(
            event_uuid="older-event",
            timestamp=1600000000,  # Older
            opentide_uuid=opentide_uuid,
            opentide_version="3"
        )
        
        newer_event = _create_mock_misp_event(
            event_uuid="newer-event",
            timestamp=1700000000,  # Newer
            opentide_uuid=opentide_uuid,
            opentide_version="5"
        )
        
        oldest_event = _create_mock_misp_event(
            event_uuid="oldest-event",
            timestamp=1500000000,  # Oldest
            opentide_uuid=opentide_uuid,
            opentide_version="1"
        )
        
        # Return events in random order
        mock_client.search.return_value = [older_event, newer_event, oldest_event]
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        # Should return the event with highest timestamp (most recent)
        assert result.event.uuid == "newer-event"
        assert result.remote_version == 5

    @patch('Engines.sharing.events.PyMISP')
    def test_logs_failure_when_duplicates_found(self, mock_pymisp_class):
        """Test that FAILURE is logged when duplicate events are detected.
        
        **Validates: Requirements 3.3**
        """
        mock_client = MagicMock()
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        mock_logs.log.reset_mock()
        
        event1 = _create_mock_misp_event(
            event_uuid="event-1",
            timestamp=1600000000,
            opentide_uuid=opentide_uuid
        )
        event2 = _create_mock_misp_event(
            event_uuid="event-2",
            timestamp=1700000000,
            opentide_uuid=opentide_uuid
        )
        
        mock_client.search.return_value = [event1, event2]
        
        check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=opentide_uuid
        )
        
        # Verify FAILURE was logged about duplicates
        failure_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "FAILURE"]
        assert len(failure_calls) >= 1
        assert "duplicate" in str(failure_calls[-1]).lower() or "Duplicate" in str(failure_calls[-1])


class TestCheckExistenceApiErrors:
    """Tests for check_existence() error handling.
    
    **Validates: Requirements 3.4**
    """

    @patch('Engines.sharing.events.PyMISP')
    def test_returns_not_found_on_exception(self, mock_pymisp_class):
        """Test that ExistenceResult.found=False when API raises exception.
        
        **Validates: Requirements 3.4**
        """
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("Network error")
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        assert result.found is False
        assert result.event is None

    @patch('Engines.sharing.events.PyMISP')
    def test_logs_failure_on_exception(self, mock_pymisp_class):
        """Test that FAILURE is logged when API raises exception.
        
        **Validates: Requirements 3.4**
        """
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("Connection timeout")
        mock_logs.log.reset_mock()
        
        check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid="test-uuid-123"
        )
        
        # Verify FAILURE was logged
        failure_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "FAILURE"]
        assert len(failure_calls) >= 1
        assert "test-uuid-123" in str(failure_calls[-1])

    @patch('Engines.sharing.events.PyMISP')
    def test_returns_not_found_on_timeout(self, mock_pymisp_class):
        """Test that ExistenceResult.found=False when API times out.
        
        **Validates: Requirements 3.4**
        """
        import socket
        mock_client = MagicMock()
        mock_client.search.side_effect = socket.timeout("timed out")
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        assert result.found is False

    @patch('Engines.sharing.events.PyMISP')
    def test_returns_not_found_on_auth_error(self, mock_pymisp_class):
        """Test that ExistenceResult.found=False on authentication error.
        
        **Validates: Requirements 3.4**
        """
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("Authentication failed")
        
        result = check_existence(
            client=mock_client,
            org_uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        assert result.found is False


# ============================================================================
# Tests for create_event() function
# ============================================================================

class TestCreateEvent:
    """Tests for create_event() function.
    
    **Validates: Requirements 4.4, 1.8**
    """

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_calls_add_event_on_client(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that create_event calls client.add_event.
        
        **Validates: Requirements 4.4**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.add_event.return_value = mock_result_event
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        config = _create_instance_config(publish_on_change=False)
        
        result = create_event(
            client=mock_client,
            instance_config=config,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 1}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.add_event.assert_called_once()
        assert result is True

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_publish_called_when_publish_on_change_true(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that client.publish is called with alert=False when publish_on_change is True.
        
        **Validates: Requirements 1.8**
        
        WHERE boolean publish_on_change is true, THE Sharing_Engine SHALL 
        publish without email the MISP event on that instance.
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.add_event.return_value = mock_result_event
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        config = _create_instance_config(publish_on_change=True)
        
        create_event(
            client=mock_client,
            instance_config=config,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 1}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        assert call_args[1]['alert'] is False

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_publish_not_called_when_publish_on_change_false(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that client.publish is NOT called when publish_on_change is False.
        
        **Validates: Requirements 1.8**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.add_event.return_value = mock_result_event
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        config = _create_instance_config(publish_on_change=False)
        
        create_event(
            client=mock_client,
            instance_config=config,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 1}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.publish.assert_not_called()

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_returns_false_on_api_error(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that create_event returns False when add_event fails.
        
        **Validates: Requirements 4.4**
        """
        mock_client = MagicMock()
        mock_client.add_event.side_effect = Exception("API Error")
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        config = _create_instance_config()
        
        result = create_event(
            client=mock_client,
            instance_config=config,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 1}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        assert result is False

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_logs_success_on_successful_creation(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that SUCCESS is logged when event is created successfully.
        
        **Validates: Requirements 4.4**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.add_event.return_value = mock_result_event
        mock_logs.log.reset_mock()
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        config = _create_instance_config(name="Test Instance", publish_on_change=False)
        
        create_event(
            client=mock_client,
            instance_config=config,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 1}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        success_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "SUCCESS"]
        assert len(success_calls) >= 1
        assert "Test Object" in str(success_calls[-1])

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_logs_failure_on_api_error(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that FAILURE is logged when create_event fails.
        
        **Validates: Requirements 4.4**
        """
        mock_client = MagicMock()
        mock_client.add_event.side_effect = Exception("Connection failed")
        mock_logs.log.reset_mock()
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        config = _create_instance_config(name="Failed Instance")
        
        create_event(
            client=mock_client,
            instance_config=config,
            object_uuid="test-uuid",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 1}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        failure_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "FAILURE"]
        assert len(failure_calls) >= 1


# ============================================================================
# Tests for update_event() function
# ============================================================================

class TestUpdateEvent:
    """Tests for update_event() function.
    
    **Validates: Requirements 4.2, 4.3, 1.8**
    """

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_calls_update_event_on_client(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that update_event calls client.update_event.
        
        **Validates: Requirements 4.2**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.update_event.return_value = mock_result_event
        mock_client.delete_object.return_value = None
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        existing_event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            opentide_version="1"
        )
        
        config = _create_instance_config(publish_on_change=False)
        
        result = update_event(
            client=mock_client,
            instance_config=config,
            existing_event=existing_event,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 2}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.update_event.assert_called_once()
        assert result is True

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_publish_called_when_publish_on_change_true(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that client.publish is called with alert=False when publish_on_change is True.
        
        **Validates: Requirements 1.8**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.update_event.return_value = mock_result_event
        mock_client.delete_object.return_value = None
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        existing_event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            opentide_version="1"
        )
        
        config = _create_instance_config(publish_on_change=True)
        
        update_event(
            client=mock_client,
            instance_config=config,
            existing_event=existing_event,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 2}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        assert call_args[1]['alert'] is False

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_publish_not_called_when_publish_on_change_false(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that client.publish is NOT called when publish_on_change is False.
        
        **Validates: Requirements 1.8**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.update_event.return_value = mock_result_event
        mock_client.delete_object.return_value = None
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        existing_event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            opentide_version="1"
        )
        
        config = _create_instance_config(publish_on_change=False)
        
        update_event(
            client=mock_client,
            instance_config=config,
            existing_event=existing_event,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 2}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.publish.assert_not_called()

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_returns_false_on_api_error(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that update_event returns False when update_event fails.
        
        **Validates: Requirements 4.2**
        """
        mock_client = MagicMock()
        mock_client.update_event.side_effect = Exception("API Error")
        mock_client.delete_object.return_value = None
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        existing_event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        config = _create_instance_config()
        
        result = update_event(
            client=mock_client,
            instance_config=config,
            existing_event=existing_event,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 2}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        assert result is False

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_logs_success_on_successful_update(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that SUCCESS is logged when event is updated successfully.
        
        **Validates: Requirements 4.2**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.update_event.return_value = mock_result_event
        mock_client.delete_object.return_value = None
        mock_logs.log.reset_mock()
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        existing_event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        
        config = _create_instance_config(name="Test Instance", publish_on_change=False)
        
        update_event(
            client=mock_client,
            instance_config=config,
            existing_event=existing_event,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 2}},
            object_name="Updated Object",
            tlp=TLPLevel.GREEN
        )
        
        success_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "SUCCESS"]
        assert len(success_calls) >= 1
        assert "Updated Object" in str(success_calls[-1])

    @patch('Engines.sharing.events.build_actor_galaxies')
    @patch('Engines.sharing.events.build_attack_tags')
    @patch('Engines.sharing.events.build_tlp_tag')
    @patch('Engines.sharing.events.build_opentide_misp_object')
    def test_attempts_to_delete_old_opentide_objects(
        self, mock_build_object, mock_tlp_tag, mock_attack_tags, mock_actor_galaxies
    ):
        """Test that update_event attempts to delete old opentide objects.
        
        **Validates: Requirements 4.2**
        """
        mock_client = MagicMock()
        mock_result_event = MagicMock(spec=MISPEvent)
        mock_result_event.uuid = "result-event-uuid"
        mock_client.update_event.return_value = mock_result_event
        
        mock_build_object.return_value = MagicMock(spec=MISPObject)
        mock_tlp_tag.return_value = "tlp:green"  # Return a valid tag string
        mock_attack_tags.return_value = []
        mock_actor_galaxies.return_value = []
        
        # Create existing event with an opentide object
        existing_event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        # Give the opentide object an ID for deletion
        existing_event.Object[0].id = "old-object-id"
        
        config = _create_instance_config(publish_on_change=False)
        
        update_event(
            client=mock_client,
            instance_config=config,
            existing_event=existing_event,
            object_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            object_type="tvm",
            object_data={"metadata": {"uuid": "test", "version": 2}},
            object_name="Test Object",
            tlp=TLPLevel.GREEN
        )
        
        mock_client.delete_object.assert_called()


class TestLogSkipVersionCurrent:
    """Tests for log_skip_version_current() function.
    
    **Validates: Requirements 4.3**
    """

    def test_logs_skip_message(self):
        """Test that SKIP message is logged with correct information.
        
        **Validates: Requirements 4.3**
        """
        mock_logs.log.reset_mock()
        
        log_skip_version_current(
            object_name="Test Object",
            object_uuid="test-uuid-123",
            local_version=5,
            remote_version=5,
            instance_name="Test MISP"
        )
        
        skip_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "SKIP"]
        assert len(skip_calls) >= 1
        call_str = str(skip_calls[-1])
        assert "Test Object" in call_str
        assert "5" in call_str  # Versions should be in the log


# ============================================================================
# Tests for helper functions
# ============================================================================

class TestEventHasMatchingOpentide:
    """Tests for the _event_has_matching_opentide() helper function."""

    def test_returns_true_when_matching_opentide_found(self):
        """Test returns True when event has matching opentide object."""
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        event = _create_mock_misp_event(
            opentide_uuid=opentide_uuid,
            has_opentide_object=True
        )
        
        result = _event_has_matching_opentide(event, opentide_uuid)
        
        assert result is True

    def test_returns_false_when_no_opentide_object(self):
        """Test returns False when event has no opentide object."""
        event = _create_mock_misp_event(has_opentide_object=False)
        
        result = _event_has_matching_opentide(event, "some-uuid")
        
        assert result is False

    def test_returns_false_when_uuid_does_not_match(self):
        """Test returns False when opentide uuid doesn't match."""
        event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            has_opentide_object=True
        )
        
        result = _event_has_matching_opentide(event, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        
        assert result is False

    def test_returns_false_when_object_list_is_none(self):
        """Test returns False when event.Object is None."""
        event = MagicMock(spec=MISPEvent)
        event.Object = None
        
        result = _event_has_matching_opentide(event, "some-uuid")
        
        assert result is False


class TestExtractOpentideVersion:
    """Tests for the _extract_opentide_version() helper function."""

    def test_returns_version_when_found(self):
        """Test returns version when opentide object has version attribute."""
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        event = _create_mock_misp_event(
            opentide_uuid=opentide_uuid,
            opentide_version="42"
        )
        
        result = _extract_opentide_version(event, opentide_uuid)
        
        assert result == 42

    def test_returns_zero_when_version_missing(self):
        """Test returns 0 when version attribute is missing."""
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        
        # Create event with opentide object but no version attribute
        event = MagicMock(spec=MISPEvent)
        mock_opentide_obj = MagicMock()
        mock_opentide_obj.name = "opentide"
        
        uuid_attr = MagicMock()
        uuid_attr.object_relation = "uuid"
        uuid_attr.value = opentide_uuid
        mock_opentide_obj.Attribute = [uuid_attr]  # No version attribute
        event.Object = [mock_opentide_obj]
        
        result = _extract_opentide_version(event, opentide_uuid)
        
        assert result == 0

    def test_returns_zero_when_version_not_parseable(self):
        """Test returns 0 when version is not a valid integer."""
        opentide_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        event = _create_mock_misp_event(
            opentide_uuid=opentide_uuid,
            opentide_version="invalid"
        )
        
        result = _extract_opentide_version(event, opentide_uuid)
        
        assert result == 0

    def test_returns_zero_when_no_matching_opentide(self):
        """Test returns 0 when no matching opentide object found."""
        event = _create_mock_misp_event(
            opentide_uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            opentide_version="5"
        )
        
        # Search for a different UUID
        result = _extract_opentide_version(event, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        
        assert result == 0


class TestApiTimeout:
    """Tests for API timeout constant."""

    def test_api_timeout_is_30_seconds(self):
        """Test that API_TIMEOUT is set to 30 seconds per requirements."""
        assert API_TIMEOUT == 30
