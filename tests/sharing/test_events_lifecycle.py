"""Tests for Engines/sharing/events.py — Event lifecycle (existence check, create, update).

This module tests the MISP event lifecycle functions:
- check_existence() for querying existing events
- create_event() for creating new MISP events
- update_event() for updating existing MISP events

All tests use mocked PyMISP to validate API interaction logic without
a live MISP instance.

Requirements tested:
- 3.1: Query by org_uuid and opentide uuid attribute
- 3.2: Filter to events owned by org_uuid
- 3.3: Handle multiple matches - use most recently modified
- 3.4: Handle API errors gracefully
- 4.1: Version comparison for update decision
- 4.2: Update when local > remote
- 4.3: Skip when local <= remote
- 4.4: Create when no existing event found
- 1.8: Publish without email when publish_on_change is True
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from dataclasses import dataclass

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

from pymisp import MISPEvent, MISPObject, MISPAttribute

# Now import the module under test
from Engines.sharing.events import (
    check_existence,
    create_event,
    update_event,
    ExistenceResult,
    _event_has_matching_opentide,
    _extract_opentide_version,
)
from Engines.modules.sharing import MISPInstanceConfig, TLPLevel


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def mock_pymisp():
    """Create a mocked PyMISP client."""
    client = MagicMock()
    return client


@pytest.fixture
def sample_instance_config():
    """Create a sample MISP instance configuration."""
    return MISPInstanceConfig(
        name="Test MISP",
        url="https://misp.test.org",
        token="test-token",
        org_uuid="00000000-0000-0000-0000-000000000001",
        max_allowed_tlp=TLPLevel.AMBER,
        mode="send",
        proxy=False,
        publish_on_change=True,
        verify_ssl=True
    )


@pytest.fixture
def sample_instance_config_no_publish():
    """Create a sample MISP instance config with publish_on_change=False."""
    return MISPInstanceConfig(
        name="Test MISP",
        url="https://misp.test.org",
        token="test-token",
        org_uuid="00000000-0000-0000-0000-000000000001",
        max_allowed_tlp=TLPLevel.AMBER,
        mode="send",
        proxy=False,
        publish_on_change=False,
        verify_ssl=True
    )


def create_mock_misp_event(
    uuid: str,
    opentide_uuid: str,
    opentide_version: str = "1",
    timestamp: int = 1000
) -> MISPEvent:
    """Create a mock MISPEvent with an opentide object."""
    event = MISPEvent()
    event.uuid = uuid
    event.timestamp = timestamp
    event.info = "Test Event"
    
    # Create a mock opentide object with attributes
    opentide_obj = MISPObject(name="opentide")
    
    uuid_attr = MISPAttribute()
    uuid_attr.object_relation = "uuid"
    uuid_attr.value = opentide_uuid
    
    version_attr = MISPAttribute()
    version_attr.object_relation = "version"
    version_attr.value = opentide_version
    
    opentide_obj.Attribute = [uuid_attr, version_attr]
    event.Object = [opentide_obj]
    
    return event


# ============================================================================
# Tests for check_existence() - 0, 1, N event results
# ============================================================================

class TestCheckExistence:
    """Tests for the check_existence() function."""

    def test_no_matching_events_returns_not_found(self, mock_pymisp):
        """Test when search returns no matching events.
        
        Requirements 3.1, 3.2: Query by org_uuid and opentide uuid attribute.
        """
        # Search returns empty list
        mock_pymisp.search.return_value = []
        
        result = check_existence(
            client=mock_pymisp,
            org_uuid="00000000-0000-0000-0000-000000000001",
            opentide_uuid="11111111-1111-1111-1111-111111111111"
        )
        
        assert result.found is False
        assert result.event is None
        assert result.remote_version == 0
        
        # Verify search was called with correct parameters
        mock_pymisp.search.assert_called_once()
        call_kwargs = mock_pymisp.search.call_args.kwargs
        assert call_kwargs['controller'] == 'events'
        assert call_kwargs['org'] == "00000000-0000-0000-0000-000000000001"
        assert call_kwargs['object_name'] == 'opentide'
        assert call_kwargs['value'] == "11111111-1111-1111-1111-111111111111"

    def test_one_matching_event_returns_found(self, mock_pymisp):
        """Test when search returns exactly one matching event.
        
        Requirements 3.1, 3.2: Returns the found event with remote version.
        """
        opentide_uuid = "22222222-2222-2222-2222-222222222222"
        mock_event = create_mock_misp_event(
            uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            opentide_uuid=opentide_uuid,
            opentide_version="5",
            timestamp=1234567890
        )
        mock_pymisp.search.return_value = [mock_event]
        
        result = check_existence(
            client=mock_pymisp,
            org_uuid="00000000-0000-0000-0000-000000000001",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        assert result.event is mock_event
        assert result.remote_version == 5

    def test_multiple_matching_events_uses_most_recent(self, mock_pymisp):
        """Test when search returns multiple matching events.
        
        Requirements 3.3: Use most recently modified event.
        """
        opentide_uuid = "33333333-3333-3333-3333-333333333333"
        
        # Create events with different timestamps
        old_event = create_mock_misp_event(
            uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            opentide_uuid=opentide_uuid,
            opentide_version="1",
            timestamp=1000  # Older
        )
        
        newer_event = create_mock_misp_event(
            uuid="cccccccc-cccc-cccc-cccc-cccccccccccc",
            opentide_uuid=opentide_uuid,
            opentide_version="3",
            timestamp=3000  # Newer
        )
        
        middle_event = create_mock_misp_event(
            uuid="dddddddd-dddd-dddd-dddd-dddddddddddd",
            opentide_uuid=opentide_uuid,
            opentide_version="2",
            timestamp=2000  # In between
        )
        
        # Return events in non-chronological order
        mock_pymisp.search.return_value = [old_event, middle_event, newer_event]
        
        with patch('Engines.sharing.events.log') as mock_log:
            result = check_existence(
                client=mock_pymisp,
                org_uuid="00000000-0000-0000-0000-000000000001",
                opentide_uuid=opentide_uuid
            )
            
            # Should return the most recent event
            assert result.found is True
            assert result.event is newer_event
            assert result.remote_version == 3
            
            # Should log FAILURE about duplicates
            mock_log.assert_called()
            log_calls = [str(c) for c in mock_log.call_args_list]
            assert any('FAILURE' in str(c) and 'Duplicate' in str(c) for c in log_calls)

    def test_api_error_returns_not_found(self, mock_pymisp):
        """Test when API call raises an exception.
        
        Requirements 3.4: Handle API errors gracefully.
        """
        mock_pymisp.search.side_effect = Exception("Network timeout")
        
        with patch('Engines.sharing.events.log') as mock_log:
            result = check_existence(
                client=mock_pymisp,
                org_uuid="00000000-0000-0000-0000-000000000001",
                opentide_uuid="44444444-4444-4444-4444-444444444444"
            )
            
            assert result.found is False
            assert result.event is None
            assert result.remote_version == 0
            
            # Should log FAILURE
            mock_log.assert_called()
            assert mock_log.call_args[0][0] == "FAILURE"

    def test_missing_version_attribute_treated_as_zero(self, mock_pymisp):
        """Test when opentide object has no version attribute.
        
        Requirements 4.5: Missing version treated as 0.
        """
        opentide_uuid = "55555555-5555-5555-5555-555555555555"
        
        # Create event with opentide object but no version attribute
        event = MISPEvent()
        event.uuid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        event.timestamp = 1234567890
        
        opentide_obj = MISPObject(name="opentide")
        uuid_attr = MISPAttribute()
        uuid_attr.object_relation = "uuid"
        uuid_attr.value = opentide_uuid
        # No version attribute
        opentide_obj.Attribute = [uuid_attr]
        event.Object = [opentide_obj]
        
        mock_pymisp.search.return_value = [event]
        
        result = check_existence(
            client=mock_pymisp,
            org_uuid="00000000-0000-0000-0000-000000000001",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        assert result.remote_version == 0

    def test_unparseable_version_treated_as_zero(self, mock_pymisp):
        """Test when version attribute cannot be parsed as integer.
        
        Requirements 4.5: Unparseable version treated as 0.
        """
        opentide_uuid = "66666666-6666-6666-6666-666666666666"
        mock_event = create_mock_misp_event(
            uuid="ffffffff-ffff-ffff-ffff-ffffffffffff",
            opentide_uuid=opentide_uuid,
            opentide_version="invalid_version",  # Not a number
            timestamp=1234567890
        )
        mock_pymisp.search.return_value = [mock_event]
        
        result = check_existence(
            client=mock_pymisp,
            org_uuid="00000000-0000-0000-0000-000000000001",
            opentide_uuid=opentide_uuid
        )
        
        assert result.found is True
        assert result.remote_version == 0

    def test_events_without_matching_opentide_are_filtered(self, mock_pymisp):
        """Test that events without the matching opentide UUID are excluded."""
        target_uuid = "77777777-7777-7777-7777-777777777777"
        
        # Event with different opentide uuid
        non_matching_event = create_mock_misp_event(
            uuid="11111111-1111-1111-1111-111111111111",
            opentide_uuid="99999999-9999-9999-9999-999999999999",  # Different!
            opentide_version="5"
        )
        
        mock_pymisp.search.return_value = [non_matching_event]
        
        result = check_existence(
            client=mock_pymisp,
            org_uuid="00000000-0000-0000-0000-000000000001",
            opentide_uuid=target_uuid
        )
        
        # Should not find because the UUID doesn't match
        assert result.found is False

    def test_none_search_result_returns_not_found(self, mock_pymisp):
        """Test when search returns None."""
        mock_pymisp.search.return_value = None
        
        result = check_existence(
            client=mock_pymisp,
            org_uuid="00000000-0000-0000-0000-000000000001",
            opentide_uuid="88888888-8888-8888-8888-888888888888"
        )
        
        assert result.found is False
        assert result.event is None


# ============================================================================
# Tests for create_event()
# ============================================================================

class TestCreateEvent:
    """Tests for the create_event() function."""

    def test_successful_event_creation(self, mock_pymisp, sample_instance_config):
        """Test successful creation of a new MISP event.
        
        Requirements 4.4: Create new event when no existing event found.
        """
        object_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 1},
            "name": "Test TVM",
            "description": "A test threat"
        }
        
        # Mock successful add_event
        mock_result = MISPEvent()
        mock_result.uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        mock_pymisp.add_event.return_value = mock_result
        mock_pymisp.publish.return_value = {"saved": True}
        
        with patch('Engines.sharing.events.log') as mock_log, \
             patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag') as mock_tlp, \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]):
            
            mock_tlp.return_value = MagicMock()
            
            result = create_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is True
            mock_pymisp.add_event.assert_called_once()
            
            # Check SUCCESS was logged
            success_calls = [c for c in mock_log.call_args_list if c[0][0] == "SUCCESS"]
            assert len(success_calls) == 1

    def test_publish_on_change_true_calls_publish(self, mock_pymisp, sample_instance_config):
        """Test that publish is called when publish_on_change is True.
        
        Requirements 1.8: Publish without email when publish_on_change is True.
        """
        object_uuid = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 1},
            "name": "Test TVM"
        }
        
        mock_result = MISPEvent()
        mock_result.uuid = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        mock_pymisp.add_event.return_value = mock_result
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log'):
            
            result = create_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,  # publish_on_change=True
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is True
            # Verify publish was called with alert=False
            mock_pymisp.publish.assert_called_once()
            call_kwargs = mock_pymisp.publish.call_args
            assert call_kwargs.kwargs.get('alert') is False or \
                   (len(call_kwargs.args) > 1 and call_kwargs.args[1] is False) or \
                   call_kwargs[1].get('alert') is False

    def test_publish_on_change_false_skips_publish(
        self, mock_pymisp, sample_instance_config_no_publish
    ):
        """Test that publish is NOT called when publish_on_change is False."""
        object_uuid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 1},
            "name": "Test TVM"
        }
        
        mock_result = MISPEvent()
        mock_result.uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        mock_pymisp.add_event.return_value = mock_result
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log'):
            
            result = create_event(
                client=mock_pymisp,
                instance_config=sample_instance_config_no_publish,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is True
            # Verify publish was NOT called
            mock_pymisp.publish.assert_not_called()

    def test_create_event_api_failure_returns_false(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that API failure during creation returns False.
        
        Requirements 8.5: Log FAILURE on PyMISP exceptions.
        """
        object_uuid = "11111111-2222-3333-4444-555555555555"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 1},
            "name": "Test TVM"
        }
        
        # Return error response (not a MISPEvent with uuid)
        mock_pymisp.add_event.return_value = {"errors": ["Server error"]}
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log') as mock_log:
            
            result = create_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is False
            # Check FAILURE was logged
            failure_calls = [c for c in mock_log.call_args_list if c[0][0] == "FAILURE"]
            assert len(failure_calls) >= 1

    def test_create_event_exception_returns_false(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that exception during creation returns False."""
        object_uuid = "66666666-7777-8888-9999-aaaaaaaaaaaa"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 1},
            "name": "Test TVM"
        }
        
        mock_pymisp.add_event.side_effect = Exception("Connection refused")
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log') as mock_log:
            
            result = create_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is False
            # Check FAILURE was logged with exception info
            failure_calls = [c for c in mock_log.call_args_list if c[0][0] == "FAILURE"]
            assert len(failure_calls) >= 1

    def test_create_event_uses_deterministic_uuid(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that event UUID is derived deterministically from object UUID.
        
        Requirements 5.9: Derive event UUID deterministically.
        """
        object_uuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 1},
            "name": "Test TVM"
        }
        
        mock_result = MISPEvent()
        mock_result.uuid = "result-uuid"
        mock_pymisp.add_event.return_value = mock_result
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log'), \
             patch('Engines.sharing.events.derive_event_uuid') as mock_derive:
            
            mock_derive.return_value = "derived-uuid-12345"
            
            create_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            # Verify derive_event_uuid was called with the object UUID
            mock_derive.assert_called_once_with(object_uuid)


# ============================================================================
# Tests for update_event()
# ============================================================================

class TestUpdateEvent:
    """Tests for the update_event() function."""

    def test_successful_event_update(self, mock_pymisp, sample_instance_config):
        """Test successful update of an existing MISP event.
        
        Requirements 4.2: Update when local > remote.
        """
        object_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 5},
            "name": "Updated TVM",
            "description": "Updated description"
        }
        
        existing_event = create_mock_misp_event(
            uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            opentide_uuid=object_uuid,
            opentide_version="1"
        )
        
        mock_result = MISPEvent()
        mock_result.uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        mock_pymisp.update_event.return_value = mock_result
        mock_pymisp.delete_object.return_value = {"saved": True}
        mock_pymisp.publish.return_value = {"saved": True}
        
        with patch('Engines.sharing.events.log') as mock_log, \
             patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag') as mock_tlp, \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]):
            
            mock_tlp.return_value = MagicMock()
            
            result = update_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                existing_event=existing_event,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Updated TVM",
                tlp=TLPLevel.AMBER
            )
            
            assert result is True
            mock_pymisp.update_event.assert_called_once()
            
            # Check SUCCESS was logged
            success_calls = [c for c in mock_log.call_args_list if c[0][0] == "SUCCESS"]
            assert len(success_calls) == 1

    def test_update_event_publish_on_change_true(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that publish is called after update when publish_on_change is True.
        
        Requirements 1.8: Publish without email when publish_on_change is True.
        """
        object_uuid = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 2},
            "name": "Test TVM"
        }
        
        existing_event = create_mock_misp_event(
            uuid="dddddddd-dddd-dddd-dddd-dddddddddddd",
            opentide_uuid=object_uuid,
            opentide_version="1"
        )
        
        mock_result = MISPEvent()
        mock_result.uuid = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        mock_pymisp.update_event.return_value = mock_result
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log'):
            
            result = update_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,  # publish_on_change=True
                existing_event=existing_event,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is True
            # Verify publish was called with alert=False
            mock_pymisp.publish.assert_called_once()
            call_kwargs = mock_pymisp.publish.call_args
            assert call_kwargs.kwargs.get('alert') is False or \
                   (len(call_kwargs.args) > 1 and call_kwargs.args[1] is False) or \
                   call_kwargs[1].get('alert') is False

    def test_update_event_publish_on_change_false(
        self, mock_pymisp, sample_instance_config_no_publish
    ):
        """Test that publish is NOT called after update when publish_on_change is False."""
        object_uuid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 3},
            "name": "Test TVM"
        }
        
        existing_event = create_mock_misp_event(
            uuid="ffffffff-ffff-ffff-ffff-ffffffffffff",
            opentide_uuid=object_uuid,
            opentide_version="2"
        )
        
        mock_result = MISPEvent()
        mock_result.uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        mock_pymisp.update_event.return_value = mock_result
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log'):
            
            result = update_event(
                client=mock_pymisp,
                instance_config=sample_instance_config_no_publish,
                existing_event=existing_event,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is True
            mock_pymisp.publish.assert_not_called()

    def test_update_event_api_failure_returns_false(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that API failure during update returns False."""
        object_uuid = "11111111-2222-3333-4444-555555555555"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 2},
            "name": "Test TVM"
        }
        
        existing_event = create_mock_misp_event(
            uuid="66666666-7777-8888-9999-aaaaaaaaaaaa",
            opentide_uuid=object_uuid,
            opentide_version="1"
        )
        
        # Return error response
        mock_pymisp.update_event.return_value = {"errors": ["Update failed"]}
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log') as mock_log:
            
            result = update_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                existing_event=existing_event,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is False
            failure_calls = [c for c in mock_log.call_args_list if c[0][0] == "FAILURE"]
            assert len(failure_calls) >= 1

    def test_update_event_exception_returns_false(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that exception during update returns False."""
        object_uuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 2},
            "name": "Test TVM"
        }
        
        existing_event = create_mock_misp_event(
            uuid="11111111-2222-3333-4444-555555555555",
            opentide_uuid=object_uuid,
            opentide_version="1"
        )
        
        mock_pymisp.update_event.side_effect = Exception("Network error")
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log') as mock_log:
            
            result = update_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                existing_event=existing_event,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is False
            failure_calls = [c for c in mock_log.call_args_list if c[0][0] == "FAILURE"]
            assert len(failure_calls) >= 1

    def test_update_event_deletes_old_opentide_objects(
        self, mock_pymisp, sample_instance_config
    ):
        """Test that old opentide objects are deleted before adding new one."""
        object_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        object_data = {
            "metadata": {"uuid": object_uuid, "version": 2},
            "name": "Test TVM"
        }
        
        # Create existing event with an opentide object that has an ID
        existing_event = create_mock_misp_event(
            uuid="ffffffff-1111-2222-3333-444444444444",
            opentide_uuid=object_uuid,
            opentide_version="1"
        )
        # Set object ID so it can be deleted
        existing_event.Object[0].id = "old-object-id-123"
        
        mock_result = MISPEvent()
        mock_result.uuid = "ffffffff-1111-2222-3333-444444444444"
        mock_pymisp.update_event.return_value = mock_result
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]), \
             patch('Engines.sharing.events.build_tlp_tag'), \
             patch('Engines.sharing.events.build_attack_tags', return_value=[]), \
             patch('Engines.sharing.events.build_actor_galaxies', return_value=[]), \
             patch('Engines.sharing.events.log'):
            
            result = update_event(
                client=mock_pymisp,
                instance_config=sample_instance_config,
                existing_event=existing_event,
                object_uuid=object_uuid,
                object_type="tvm",
                object_data=object_data,
                object_name="Test TVM",
                tlp=TLPLevel.GREEN
            )
            
            assert result is True
            # Verify delete_object was called for the old object
            mock_pymisp.delete_object.assert_called_once_with("old-object-id-123")


# ============================================================================
# Tests for helper functions
# ============================================================================

class TestEventHasMatchingOpentide:
    """Tests for the _event_has_matching_opentide() helper function."""

    def test_returns_true_for_matching_uuid(self):
        """Test returns True when opentide object has matching UUID."""
        opentide_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        event = create_mock_misp_event(
            uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            opentide_uuid=opentide_uuid,
            opentide_version="1"
        )
        
        result = _event_has_matching_opentide(event, opentide_uuid)
        assert result is True

    def test_returns_false_for_non_matching_uuid(self):
        """Test returns False when opentide object has different UUID."""
        event = create_mock_misp_event(
            uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            opentide_uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            opentide_version="1"
        )
        
        result = _event_has_matching_opentide(event, "different-uuid")
        assert result is False

    def test_returns_false_for_event_without_objects(self):
        """Test returns False when event has no objects."""
        event = MISPEvent()
        event.uuid = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        event.Object = []
        
        result = _event_has_matching_opentide(event, "any-uuid")
        assert result is False

    def test_returns_false_for_non_opentide_objects(self):
        """Test returns False when event only has non-opentide objects."""
        event = MISPEvent()
        event.uuid = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        
        other_obj = MISPObject(name="file")
        other_obj.Attribute = []
        event.Object = [other_obj]
        
        result = _event_has_matching_opentide(event, "any-uuid")
        assert result is False


class TestExtractOpentideVersion:
    """Tests for the _extract_opentide_version() helper function."""

    def test_extracts_numeric_version(self):
        """Test extraction of numeric version from opentide object."""
        opentide_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        event = create_mock_misp_event(
            uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            opentide_uuid=opentide_uuid,
            opentide_version="42"
        )
        
        result = _extract_opentide_version(event, opentide_uuid)
        assert result == 42

    def test_returns_zero_for_missing_version(self):
        """Test returns 0 when version attribute is missing."""
        opentide_uuid = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        
        event = MISPEvent()
        event.uuid = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        
        opentide_obj = MISPObject(name="opentide")
        uuid_attr = MISPAttribute()
        uuid_attr.object_relation = "uuid"
        uuid_attr.value = opentide_uuid
        # No version attribute
        opentide_obj.Attribute = [uuid_attr]
        event.Object = [opentide_obj]
        
        result = _extract_opentide_version(event, opentide_uuid)
        assert result == 0

    def test_returns_zero_for_unparseable_version(self):
        """Test returns 0 when version cannot be parsed as integer."""
        opentide_uuid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        event = create_mock_misp_event(
            uuid="ffffffff-ffff-ffff-ffff-ffffffffffff",
            opentide_uuid=opentide_uuid,
            opentide_version="not-a-number"
        )
        
        result = _extract_opentide_version(event, opentide_uuid)
        assert result == 0

    def test_returns_zero_for_no_matching_object(self):
        """Test returns 0 when no matching opentide object exists."""
        event = MISPEvent()
        event.uuid = "11111111-1111-1111-1111-111111111111"
        event.Object = []
        
        result = _extract_opentide_version(event, "any-uuid")
        assert result == 0

