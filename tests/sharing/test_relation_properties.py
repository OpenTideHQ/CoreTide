"""Property-based tests for relation resolution correctness.

This module tests Property 9 (Non-TVM relation resolution correctness)
using Hypothesis.

**Validates: Requirements 5.6, 5.7, 5.8**
"""

import sys
import uuid
from typing import List, Optional

import git
import pytest
from hypothesis import given, settings, assume, note
from hypothesis import strategies as st

# Add project root to path for imports
sys.path.insert(0, str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.sharing.relations import resolve_relations, _resolve_dom_relations, _resolve_mdr_relations


# ============================================================================
# Hypothesis Strategies for generating test data
# ============================================================================

@st.composite
def valid_uuid(draw) -> str:
    """Generate a valid UUIDv4 string."""
    return str(uuid.uuid4())


@st.composite
def uuid_list(draw, min_size: int = 0, max_size: int = 10) -> List[str]:
    """Generate a list of valid UUIDv4 strings."""
    return draw(st.lists(valid_uuid(), min_size=min_size, max_size=max_size))


@st.composite
def dom_object_with_threats(draw, threats: Optional[List[str]] = None) -> dict:
    """Generate a DOM object with a specific threats list.
    
    Args:
        threats: Optional specific threats list. If None, randomly generated.
    """
    if threats is None:
        threats = draw(uuid_list())
    
    obj_uuid = draw(valid_uuid())
    
    # Build the objective section with threats
    objective = {}
    if threats:
        objective["threats"] = threats
    
    obj_data = {
        "uuid": obj_uuid,
        "name": f"Test DOM {obj_uuid[:8]}",
        "metadata": {
            "uuid": obj_uuid,
            "tlp": "green",
            "version": draw(st.integers(min_value=1, max_value=100))
        }
    }
    
    # Only add objective if we have threats to add (or randomly add empty objective)
    if threats or draw(st.booleans()):
        obj_data["objective"] = objective
    
    return obj_data


@st.composite
def dom_object_with_specific_threats(draw, threats: List[str]) -> dict:
    """Generate a DOM object with exactly the specified threats list."""
    obj_uuid = draw(valid_uuid())
    
    obj_data = {
        "uuid": obj_uuid,
        "name": f"Test DOM {obj_uuid[:8]}",
        "metadata": {
            "uuid": obj_uuid,
            "tlp": "green",
            "version": draw(st.integers(min_value=1, max_value=100))
        },
        "objective": {
            "threats": threats
        }
    }
    
    return obj_data


@st.composite
def mdr_object_with_detection_model(draw, detection_model: Optional[str] = None) -> dict:
    """Generate an MDR object with a specific detection_model.
    
    Args:
        detection_model: Optional specific detection_model UUID. If None, randomly generated.
    """
    if detection_model is None:
        # Randomly decide whether to include a detection_model
        include_model = draw(st.booleans())
        detection_model = draw(valid_uuid()) if include_model else None
    
    obj_uuid = draw(valid_uuid())
    
    obj_data = {
        "uuid": obj_uuid,
        "name": f"Test MDR {obj_uuid[:8]}",
        "metadata": {
            "uuid": obj_uuid,
            "tlp": "amber",
            "version": draw(st.integers(min_value=1, max_value=100))
        }
    }
    
    if detection_model is not None:
        obj_data["detection_model"] = detection_model
    
    return obj_data


@st.composite
def mdr_object_with_specific_detection_model(draw, detection_model: str) -> dict:
    """Generate an MDR object with exactly the specified detection_model UUID."""
    obj_uuid = draw(valid_uuid())
    
    return {
        "uuid": obj_uuid,
        "name": f"Test MDR {obj_uuid[:8]}",
        "metadata": {
            "uuid": obj_uuid,
            "tlp": "amber",
            "version": draw(st.integers(min_value=1, max_value=100))
        },
        "detection_model": detection_model
    }


# ============================================================================
# Property 9: Non-TVM relation resolution correctness
# ============================================================================

class TestNonTVMRelationResolutionCorrectness:
    """Property 9: Non-TVM relation resolution correctness.
    
    **Validates: Requirements 5.6, 5.7, 5.8**
    
    Property Statement:
    *For any* DOM object, `resolve_relations()` SHALL return exactly the UUIDs 
    from `objective.threats`. *For any* MDR object, `resolve_relations()` SHALL 
    return a list containing exactly the `detection_model` UUID. When these 
    fields are empty or absent, the function SHALL return an empty list.
    """

    # ========================================================================
    # DOM Tests - Validates Requirement 5.6
    # ========================================================================

    @given(threats=uuid_list(min_size=1, max_size=20))
    @settings(max_examples=100)
    def test_dom_returns_exactly_threats_uuids(self, threats: List[str]):
        """Test that DOM resolve_relations returns exactly the objective.threats UUIDs.
        
        **Validates: Requirements 5.6**
        
        For any DOM object with a non-empty threats list, resolve_relations()
        shall return exactly those UUIDs in the same order.
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM {obj_uuid[:8]}",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": "green",
                "version": 1
            },
            "objective": {
                "threats": threats
            }
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        
        # Result should contain exactly the same UUIDs
        assert len(result) == len(threats), (
            f"Expected {len(threats)} UUIDs but got {len(result)}. "
            f"Expected: {threats}, Got: {result}"
        )
        
        # Verify each UUID is present and in correct order
        for i, expected_uuid in enumerate(threats):
            assert result[i] == str(expected_uuid), (
                f"UUID mismatch at index {i}: expected {expected_uuid}, got {result[i]}"
            )

    @given(threats=uuid_list(min_size=1, max_size=10))
    @settings(max_examples=100)
    def test_dom_returns_all_threats_without_modification(self, threats: List[str]):
        """Test that DOM relations are returned without modification.
        
        **Validates: Requirements 5.6**
        
        The returned list should be exactly equal to the threats list
        (converted to strings).
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1},
            "objective": {"threats": threats}
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        expected = [str(t) for t in threats]
        
        assert result == expected, (
            f"DOM relations mismatch. Expected: {expected}, Got: {result}"
        )

    @given(data=st.data())
    @settings(max_examples=100)
    def test_dom_empty_threats_returns_empty_list(self, data):
        """Test that DOM with empty threats list returns empty list.
        
        **Validates: Requirements 5.8**
        
        When objective.threats is an empty list, resolve_relations()
        shall return an empty list.
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1},
            "objective": {
                "threats": []
            }
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        
        assert result == [], (
            f"Expected empty list for DOM with empty threats, got: {result}"
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_dom_absent_threats_returns_empty_list(self, data):
        """Test that DOM with absent threats field returns empty list.
        
        **Validates: Requirements 5.8**
        
        When objective.threats is absent from the DOM object, 
        resolve_relations() shall return an empty list.
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1},
            "objective": {}  # objective exists but no threats field
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        
        assert result == [], (
            f"Expected empty list for DOM with absent threats, got: {result}"
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_dom_absent_objective_returns_empty_list(self, data):
        """Test that DOM with absent objective section returns empty list.
        
        **Validates: Requirements 5.8**
        
        When the entire objective section is absent from the DOM object,
        resolve_relations() shall return an empty list.
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1}
            # No objective field at all
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        
        assert result == [], (
            f"Expected empty list for DOM with absent objective, got: {result}"
        )

    @given(threats=uuid_list(min_size=1, max_size=5))
    @settings(max_examples=50)
    def test_dom_threats_with_extra_objective_fields(self, threats: List[str]):
        """Test DOM resolution with additional objective fields is not affected.
        
        **Validates: Requirements 5.6**
        
        Extra fields in the objective section should not affect threat resolution.
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1},
            "objective": {
                "threats": threats,
                "description": "Some description",
                "priority": "high",
                "extra_field": ["some", "data"]
            }
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        expected = [str(t) for t in threats]
        
        assert result == expected, (
            f"Extra objective fields affected resolution. Expected: {expected}, Got: {result}"
        )

    # ========================================================================
    # MDR Tests - Validates Requirement 5.7
    # ========================================================================

    @given(detection_model=valid_uuid())
    @settings(max_examples=100)
    def test_mdr_returns_exactly_detection_model_uuid(self, detection_model: str):
        """Test that MDR resolve_relations returns exactly the detection_model UUID.
        
        **Validates: Requirements 5.7**
        
        For any MDR object with a detection_model field, resolve_relations()
        shall return a list containing exactly that single UUID.
        """
        obj_uuid = str(uuid.uuid4())
        
        mdr_data = {
            "uuid": obj_uuid,
            "name": f"Test MDR {obj_uuid[:8]}",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": "amber",
                "version": 1
            },
            "detection_model": detection_model
        }
        
        result = resolve_relations(obj_uuid, "mdr", mdr_data)
        
        # Result should be a single-element list with the detection_model UUID
        assert len(result) == 1, (
            f"Expected 1 UUID for MDR but got {len(result)}. Result: {result}"
        )
        
        assert result[0] == str(detection_model), (
            f"MDR detection_model mismatch: expected {detection_model}, got {result[0]}"
        )

    @given(detection_model=valid_uuid())
    @settings(max_examples=100)
    def test_mdr_returns_single_element_list(self, detection_model: str):
        """Test that MDR always returns a single-element list.
        
        **Validates: Requirements 5.7**
        
        The MDR resolution should always produce a list with exactly one element.
        """
        obj_uuid = str(uuid.uuid4())
        
        mdr_data = {
            "uuid": obj_uuid,
            "name": f"Test MDR",
            "metadata": {"uuid": obj_uuid, "tlp": "red", "version": 1},
            "detection_model": detection_model
        }
        
        result = resolve_relations(obj_uuid, "mdr", mdr_data)
        
        assert isinstance(result, list), (
            f"Expected list type, got {type(result)}"
        )
        assert len(result) == 1, (
            f"Expected exactly 1 element for MDR, got {len(result)}"
        )
        assert result == [str(detection_model)], (
            f"MDR result mismatch. Expected: [{detection_model}], Got: {result}"
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_mdr_absent_detection_model_returns_empty_list(self, data):
        """Test that MDR with absent detection_model returns empty list.
        
        **Validates: Requirements 5.8**
        
        When detection_model is absent from the MDR object,
        resolve_relations() shall return an empty list.
        """
        obj_uuid = str(uuid.uuid4())
        
        mdr_data = {
            "uuid": obj_uuid,
            "name": f"Test MDR",
            "metadata": {"uuid": obj_uuid, "tlp": "amber", "version": 1}
            # No detection_model field
        }
        
        result = resolve_relations(obj_uuid, "mdr", mdr_data)
        
        assert result == [], (
            f"Expected empty list for MDR with absent detection_model, got: {result}"
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_mdr_empty_detection_model_returns_empty_list(self, data):
        """Test that MDR with empty/None detection_model returns empty list.
        
        **Validates: Requirements 5.8**
        
        When detection_model is empty string or None, resolve_relations()
        shall return an empty list.
        """
        obj_uuid = str(uuid.uuid4())
        
        # Test with empty string
        mdr_data_empty = {
            "uuid": obj_uuid,
            "name": f"Test MDR",
            "metadata": {"uuid": obj_uuid, "tlp": "amber", "version": 1},
            "detection_model": ""
        }
        
        result_empty = resolve_relations(obj_uuid, "mdr", mdr_data_empty)
        
        assert result_empty == [], (
            f"Expected empty list for MDR with empty detection_model, got: {result_empty}"
        )
        
        # Test with None value
        mdr_data_none = {
            "uuid": obj_uuid,
            "name": f"Test MDR",
            "metadata": {"uuid": obj_uuid, "tlp": "amber", "version": 1},
            "detection_model": None
        }
        
        result_none = resolve_relations(obj_uuid, "mdr", mdr_data_none)
        
        assert result_none == [], (
            f"Expected empty list for MDR with None detection_model, got: {result_none}"
        )

    @given(detection_model=valid_uuid())
    @settings(max_examples=50)
    def test_mdr_with_extra_fields(self, detection_model: str):
        """Test MDR resolution with additional fields is not affected.
        
        **Validates: Requirements 5.7**
        
        Extra fields in the MDR object should not affect detection_model resolution.
        """
        obj_uuid = str(uuid.uuid4())
        
        mdr_data = {
            "uuid": obj_uuid,
            "name": f"Test MDR",
            "metadata": {"uuid": obj_uuid, "tlp": "amber", "version": 1},
            "detection_model": detection_model,
            "detection_logic": "Some logic",
            "response_actions": ["action1", "action2"],
            "extra_field": {"nested": "data"}
        }
        
        result = resolve_relations(obj_uuid, "mdr", mdr_data)
        
        assert result == [str(detection_model)], (
            f"Extra fields affected MDR resolution. Expected: [{detection_model}], Got: {result}"
        )

    # ========================================================================
    # Combined/Edge Case Tests - Validates Requirements 5.6, 5.7, 5.8
    # ========================================================================

    @given(
        dom_threats=uuid_list(min_size=0, max_size=5),
        mdr_model=st.one_of(valid_uuid(), st.none())
    )
    @settings(max_examples=100)
    def test_type_dispatch_correctness(self, dom_threats: List[str], mdr_model: Optional[str]):
        """Test that resolve_relations correctly dispatches by object type.
        
        **Validates: Requirements 5.6, 5.7**
        
        Verify that the same data processed as DOM vs MDR produces different results
        based on the object_type parameter.
        """
        obj_uuid = str(uuid.uuid4())
        
        # Build DOM data
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test Object",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1},
            "objective": {"threats": dom_threats}
        }
        if mdr_model:
            dom_data["detection_model"] = mdr_model
        
        dom_result = resolve_relations(obj_uuid, "dom", dom_data)
        
        # DOM should return threats, not detection_model
        expected_dom = [str(t) for t in dom_threats]
        assert dom_result == expected_dom, (
            f"DOM returned wrong data. Expected threats: {expected_dom}, Got: {dom_result}"
        )
        
        # Build MDR data
        mdr_data = {
            "uuid": obj_uuid,
            "name": f"Test Object",
            "metadata": {"uuid": obj_uuid, "tlp": "amber", "version": 1}
        }
        if dom_threats:
            mdr_data["objective"] = {"threats": dom_threats}
        if mdr_model:
            mdr_data["detection_model"] = mdr_model
        
        mdr_result = resolve_relations(obj_uuid, "mdr", mdr_data)
        
        # MDR should return detection_model, not threats
        expected_mdr = [str(mdr_model)] if mdr_model else []
        assert mdr_result == expected_mdr, (
            f"MDR returned wrong data. Expected model: {expected_mdr}, Got: {mdr_result}"
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_empty_object_data_returns_empty_list(self, data):
        """Test that empty object data returns empty list for DOM and MDR.
        
        **Validates: Requirements 5.8**
        
        When object_data is completely empty (or near empty), resolve_relations()
        shall return an empty list.
        """
        obj_uuid = str(uuid.uuid4())
        
        empty_data = {}
        
        dom_result = resolve_relations(obj_uuid, "dom", empty_data)
        assert dom_result == [], (
            f"Expected empty list for DOM with empty data, got: {dom_result}"
        )
        
        mdr_result = resolve_relations(obj_uuid, "mdr", empty_data)
        assert mdr_result == [], (
            f"Expected empty list for MDR with empty data, got: {mdr_result}"
        )

    @given(
        threats=uuid_list(min_size=1, max_size=5),
        detection_model=valid_uuid()
    )
    @settings(max_examples=50)
    def test_dom_ignores_detection_model(self, threats: List[str], detection_model: str):
        """Test that DOM resolution ignores detection_model field.
        
        **Validates: Requirements 5.6**
        
        When a DOM object has both threats and detection_model (unusual but possible),
        the DOM resolution should only return the threats.
        """
        obj_uuid = str(uuid.uuid4())
        
        dom_data = {
            "uuid": obj_uuid,
            "name": f"Test DOM",
            "metadata": {"uuid": obj_uuid, "tlp": "green", "version": 1},
            "objective": {"threats": threats},
            "detection_model": detection_model  # Should be ignored for DOM
        }
        
        result = resolve_relations(obj_uuid, "dom", dom_data)
        expected = [str(t) for t in threats]
        
        assert result == expected, (
            f"DOM should ignore detection_model. Expected: {expected}, Got: {result}"
        )
        # Ensure detection_model is NOT in the result
        assert detection_model not in result, (
            f"DOM included detection_model {detection_model} when it should have been ignored"
        )

    @given(
        threats=uuid_list(min_size=1, max_size=5),
        detection_model=valid_uuid()
    )
    @settings(max_examples=50)
    def test_mdr_ignores_objective_threats(self, threats: List[str], detection_model: str):
        """Test that MDR resolution ignores objective.threats field.
        
        **Validates: Requirements 5.7**
        
        When an MDR object has both detection_model and objective.threats,
        the MDR resolution should only return the detection_model.
        """
        obj_uuid = str(uuid.uuid4())
        
        mdr_data = {
            "uuid": obj_uuid,
            "name": f"Test MDR",
            "metadata": {"uuid": obj_uuid, "tlp": "amber", "version": 1},
            "detection_model": detection_model,
            "objective": {"threats": threats}  # Should be ignored for MDR
        }
        
        result = resolve_relations(obj_uuid, "mdr", mdr_data)
        
        assert result == [str(detection_model)], (
            f"MDR should ignore objective.threats. Expected: [{detection_model}], Got: {result}"
        )
        # Ensure threats are NOT in the result
        for threat in threats:
            assert threat not in result, (
                f"MDR included threat {threat} when it should have been ignored"
            )

    @given(data=st.data())
    @settings(max_examples=30)
    def test_return_type_is_always_list(self, data):
        """Test that resolve_relations always returns a list (not None or other types).
        
        **Validates: Requirements 5.6, 5.7, 5.8**
        
        The function should always return a list, even when empty.
        """
        obj_uuid = str(uuid.uuid4())
        
        # Test DOM variants
        dom_cases = [
            {},
            {"objective": {}},
            {"objective": {"threats": []}},
            {"objective": {"threats": [str(uuid.uuid4())]}},
        ]
        
        for dom_data in dom_cases:
            result = resolve_relations(obj_uuid, "dom", dom_data)
            assert isinstance(result, list), (
                f"DOM resolve_relations should return list, got {type(result)}"
            )
        
        # Test MDR variants
        mdr_cases = [
            {},
            {"detection_model": None},
            {"detection_model": ""},
            {"detection_model": str(uuid.uuid4())},
        ]
        
        for mdr_data in mdr_cases:
            result = resolve_relations(obj_uuid, "mdr", mdr_data)
            assert isinstance(result, list), (
                f"MDR resolve_relations should return list, got {type(result)}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
