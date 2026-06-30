"""Property-based tests for version comparison logic.

**Validates: Requirements 4.1, 4.2, 4.3, 4.5**

Property 6: Version comparison determines correct action
- For any pair of integer versions (local_version, remote_version) where local_version > 0,
  the sharing engine SHALL: update the event when local_version > remote_version,
  skip when local_version <= remote_version.
- When remote_version is missing or unparseable, it SHALL be treated as 0.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))

# Mock the heavy imports before importing from events module
# This prevents DataTide from loading during test collection
sys.modules['Engines.modules.tide'] = MagicMock()
sys.modules['Engines.modules.logs'] = MagicMock()

import pytest
from hypothesis import given, strategies as st, assume, settings


# Import the version comparison function we're testing
from Engines.sharing.events import should_update_event, _extract_opentide_version


# =============================================================================
# Strategies for property-based tests
# =============================================================================

# Strategy for positive version numbers (valid local versions)
positive_version_strategy = st.integers(min_value=1, max_value=1_000_000)

# Strategy for non-negative version numbers (remote versions, 0 = missing)
non_negative_version_strategy = st.integers(min_value=0, max_value=1_000_000)

# Strategy for local versions (must be > 0 per requirement)
local_version_strategy = positive_version_strategy

# Strategy for remote versions (0 represents missing/unparseable)
remote_version_strategy = non_negative_version_strategy


# =============================================================================
# Property 6: Version comparison determines correct action
# =============================================================================

class TestProperty6VersionComparison:
    """Property tests for version comparison (Property 6).
    
    **Validates: Requirements 4.1, 4.2, 4.3, 4.5**
    
    Property 6: Version comparison determines correct action
    - Update when local > remote
    - Skip when local <= remote
    - Missing/unparseable remote version treated as 0
    """

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_update_iff_local_greater_than_remote(
        self, local_version: int, remote_version: int
    ):
        """Test that update is indicated iff local_version > remote_version.
        
        **Validates: Requirements 4.1, 4.2, 4.3**
        
        For any pair of versions:
        - should_update_event returns (True, "update") iff local > remote
        - should_update_event returns (False, "skip") iff local <= remote
        """
        should_update, reason = should_update_event(local_version, remote_version)
        
        expected_update = local_version > remote_version
        
        assert should_update == expected_update, (
            f"Expected should_update={expected_update} for "
            f"local={local_version}, remote={remote_version}, "
            f"but got should_update={should_update}"
        )
        
        if expected_update:
            assert reason == "update", f"Expected reason='update' but got '{reason}'"
        else:
            assert reason == "skip", f"Expected reason='skip' but got '{reason}'"

    @given(local_version=local_version_strategy)
    def test_update_when_remote_is_zero(self, local_version: int):
        """Test that update is always indicated when remote version is 0.
        
        **Validates: Requirements 4.2, 4.5**
        
        A remote version of 0 represents missing/unparseable, and any
        positive local version should trigger an update.
        """
        should_update, reason = should_update_event(local_version, remote_version=0)
        
        # Any positive local version > 0 (remote), so should always update
        assert should_update is True, (
            f"Expected update=True when local={local_version}, remote=0"
        )
        assert reason == "update"

    @given(version=positive_version_strategy)
    def test_skip_when_versions_equal(self, version: int):
        """Test that skip is always indicated when versions are equal.
        
        **Validates: Requirements 4.3**
        
        When local == remote, the sharing engine shall skip the update.
        """
        should_update, reason = should_update_event(
            local_version=version, 
            remote_version=version
        )
        
        assert should_update is False, (
            f"Expected skip when local=remote={version}"
        )
        assert reason == "skip"

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_skip_when_local_less_than_remote(
        self, local_version: int, remote_version: int
    ):
        """Test that skip is indicated when local < remote.
        
        **Validates: Requirements 4.3**
        
        When local < remote, the sharing engine shall skip the update.
        """
        # Filter to cases where local < remote
        assume(local_version < remote_version)
        
        should_update, reason = should_update_event(local_version, remote_version)
        
        assert should_update is False, (
            f"Expected skip when local={local_version} < remote={remote_version}"
        )
        assert reason == "skip"

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_skip_when_local_less_or_equal_remote(
        self, local_version: int, remote_version: int
    ):
        """Test that skip is indicated when local <= remote.
        
        **Validates: Requirements 4.3**
        
        Comprehensive test that skip is returned for all local <= remote cases.
        """
        # Filter to cases where local <= remote
        assume(local_version <= remote_version)
        
        should_update, reason = should_update_event(local_version, remote_version)
        
        assert should_update is False, (
            f"Expected skip when local={local_version} <= remote={remote_version}"
        )
        assert reason == "skip"

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_update_when_local_strictly_greater(
        self, local_version: int, remote_version: int
    ):
        """Test that update is indicated when local > remote.
        
        **Validates: Requirements 4.2**
        
        Comprehensive test that update is returned for all local > remote cases.
        """
        # Filter to cases where local > remote
        assume(local_version > remote_version)
        
        should_update, reason = should_update_event(local_version, remote_version)
        
        assert should_update is True, (
            f"Expected update when local={local_version} > remote={remote_version}"
        )
        assert reason == "update"

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_comparison_uses_integer_numeric_comparison(
        self, local_version: int, remote_version: int
    ):
        """Test that version comparison uses integer numeric comparison.
        
        **Validates: Requirements 4.1**
        
        Versions are compared numerically as integers, not lexicographically.
        """
        should_update, _ = should_update_event(local_version, remote_version)
        
        # The result should match standard integer comparison
        expected = local_version > remote_version
        assert should_update == expected

    @given(
        base_version=st.integers(min_value=1, max_value=100),
        delta=st.integers(min_value=1, max_value=100)
    )
    def test_update_threshold_at_boundary(self, base_version: int, delta: int):
        """Test version comparison at the update/skip boundary.
        
        **Validates: Requirements 4.2, 4.3**
        
        At the boundary:
        - local = remote + delta (where delta > 0): update
        - local = remote: skip
        """
        remote = base_version
        local_update = remote + delta  # Always > remote
        local_skip = remote  # Always == remote
        
        # Should update when local > remote
        should_update, reason = should_update_event(local_update, remote)
        assert should_update is True
        assert reason == "update"
        
        # Should skip when local == remote
        should_skip, reason = should_update_event(local_skip, remote)
        assert should_skip is False
        assert reason == "skip"


class TestVersionComparisonEdgeCases:
    """Edge case tests for version comparison.
    
    **Validates: Requirements 4.1, 4.2, 4.3, 4.5**
    """

    def test_minimum_positive_local_version(self):
        """Test with minimum positive local version (1).
        
        **Validates: Requirements 4.2**
        """
        should_update, reason = should_update_event(local_version=1, remote_version=0)
        assert should_update is True
        assert reason == "update"

    def test_boundary_case_one_greater(self):
        """Test when local is exactly one greater than remote.
        
        **Validates: Requirements 4.2**
        """
        should_update, reason = should_update_event(local_version=6, remote_version=5)
        assert should_update is True
        assert reason == "update"

    def test_boundary_case_one_less(self):
        """Test when local is exactly one less than remote.
        
        **Validates: Requirements 4.3**
        """
        should_update, reason = should_update_event(local_version=4, remote_version=5)
        assert should_update is False
        assert reason == "skip"

    def test_large_version_numbers(self):
        """Test with large version numbers.
        
        **Validates: Requirements 4.1**
        """
        # Large local > large remote: update
        should_update, reason = should_update_event(
            local_version=1_000_000, 
            remote_version=999_999
        )
        assert should_update is True
        assert reason == "update"
        
        # Large local == large remote: skip
        should_update, reason = should_update_event(
            local_version=1_000_000, 
            remote_version=1_000_000
        )
        assert should_update is False
        assert reason == "skip"

    def test_zero_remote_always_triggers_update(self):
        """Test that remote version 0 always triggers update.
        
        **Validates: Requirements 4.5**
        
        Remote version of 0 represents missing/unparseable version,
        and any positive local version should trigger update.
        """
        for local in [1, 2, 5, 10, 100, 1000]:
            should_update, reason = should_update_event(
                local_version=local, 
                remote_version=0
            )
            assert should_update is True, f"Failed for local={local}"
            assert reason == "update"


class TestMissingUnparseableRemoteVersion:
    """Tests for missing/unparseable remote version handling.
    
    **Validates: Requirements 4.5**
    
    When remote version is missing or unparseable, it SHALL be treated as 0.
    """

    def test_remote_zero_treated_as_missing(self):
        """Test that remote version 0 is treated as missing version.
        
        **Validates: Requirements 4.5**
        """
        # Remote = 0 means missing/unparseable, so any positive local should update
        should_update, reason = should_update_event(local_version=1, remote_version=0)
        assert should_update is True
        assert reason == "update"

    @given(local_version=positive_version_strategy)
    def test_any_positive_local_updates_against_zero_remote(
        self, local_version: int
    ):
        """Test that any positive local version updates against zero remote.
        
        **Validates: Requirements 4.5**
        """
        should_update, reason = should_update_event(
            local_version=local_version, 
            remote_version=0
        )
        assert should_update is True
        assert reason == "update"


class TestVersionComparisonReturnValues:
    """Tests for the return value structure of should_update_event.
    
    **Validates: Requirements 4.1, 4.2, 4.3**
    """

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_returns_tuple(self, local_version: int, remote_version: int):
        """Test that should_update_event always returns a tuple."""
        result = should_update_event(local_version, remote_version)
        assert isinstance(result, tuple)
        assert len(result) == 2

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_first_element_is_boolean(self, local_version: int, remote_version: int):
        """Test that the first element is always a boolean."""
        should_update, _ = should_update_event(local_version, remote_version)
        assert isinstance(should_update, bool)

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_second_element_is_valid_reason(
        self, local_version: int, remote_version: int
    ):
        """Test that the second element is a valid reason string."""
        _, reason = should_update_event(local_version, remote_version)
        assert isinstance(reason, str)
        assert reason in ("update", "skip")

    @given(
        local_version=local_version_strategy,
        remote_version=remote_version_strategy
    )
    def test_reason_matches_should_update_flag(
        self, local_version: int, remote_version: int
    ):
        """Test that the reason string is consistent with the boolean flag."""
        should_update, reason = should_update_event(local_version, remote_version)
        
        if should_update:
            assert reason == "update"
        else:
            assert reason == "skip"


class TestExtractOpentideVersionEdgeCases:
    """Tests for _extract_opentide_version handling of edge cases.
    
    **Validates: Requirements 4.5**
    
    Tests that missing/unparseable version is treated as 0.
    """

    def test_missing_version_returns_zero(self):
        """Test that missing version attribute returns 0."""
        from pymisp import MISPEvent, MISPObject
        
        # Create event with opentide object but no version attribute
        event = MISPEvent()
        opentide_obj = MISPObject(name="opentide")
        opentide_obj.add_attribute(object_relation="uuid", value="test-uuid")
        # Note: no version attribute added
        event.Object = [opentide_obj]
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 0

    def test_unparseable_version_returns_zero(self):
        """Test that unparseable version attribute returns 0."""
        from pymisp import MISPEvent, MISPObject
        
        # Create event with opentide object with non-integer version
        event = MISPEvent()
        opentide_obj = MISPObject(name="opentide")
        opentide_obj.add_attribute(object_relation="uuid", value="test-uuid")
        opentide_obj.add_attribute(object_relation="version", value="not-a-number")
        event.Object = [opentide_obj]
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 0

    def test_valid_integer_version_returns_value(self):
        """Test that valid integer version is returned."""
        from pymisp import MISPEvent, MISPObject
        
        event = MISPEvent()
        opentide_obj = MISPObject(name="opentide")
        opentide_obj.add_attribute(object_relation="uuid", value="test-uuid")
        opentide_obj.add_attribute(object_relation="version", value="42")
        event.Object = [opentide_obj]
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 42

    def test_string_integer_version_parsed(self):
        """Test that string representation of integer is parsed correctly."""
        from pymisp import MISPEvent, MISPObject
        
        event = MISPEvent()
        opentide_obj = MISPObject(name="opentide")
        opentide_obj.add_attribute(object_relation="uuid", value="test-uuid")
        opentide_obj.add_attribute(object_relation="version", value="123")
        event.Object = [opentide_obj]
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 123

    def test_no_matching_opentide_object_returns_zero(self):
        """Test that non-matching UUID returns 0."""
        from pymisp import MISPEvent, MISPObject
        
        event = MISPEvent()
        opentide_obj = MISPObject(name="opentide")
        opentide_obj.add_attribute(object_relation="uuid", value="different-uuid")
        opentide_obj.add_attribute(object_relation="version", value="5")
        event.Object = [opentide_obj]
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 0

    def test_empty_event_objects_returns_zero(self):
        """Test that event with no objects returns 0."""
        from pymisp import MISPEvent
        
        event = MISPEvent()
        event.Object = []
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 0

    def test_event_with_none_objects_returns_zero(self):
        """Test that event with None Object attribute returns 0."""
        from pymisp import MISPEvent
        
        event = MISPEvent()
        event.Object = None
        
        result = _extract_opentide_version(event, "test-uuid")
        assert result == 0
