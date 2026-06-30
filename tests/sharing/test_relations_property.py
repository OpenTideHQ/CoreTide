"""Property-based tests for relation resolution.

**Validates: Requirements 5.5, 5.6, 5.7, 5.8**

This module contains property tests for:
- Property 8: TVM recursive chaining resolution (separate tests)
- Property 9: Non-TVM relation resolution correctness (DOM and MDR)
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))

# Mock the heavy imports before importing from relations module
sys.modules['Engines.modules.tide'] = MagicMock()
sys.modules['Engines.modules.logs'] = MagicMock()

import pytest
from hypothesis import given, strategies as st, assume, settings


# Import the actual relation resolution functions we're testing
from Engines.sharing.relations import (
    resolve_relations,
    _resolve_dom_relations,
    _resolve_mdr_relations,
)


# Strategy for generating valid UUIDs
uuid_strategy = st.uuids().map(str)


# Strategy for generating a list of UUIDs (for DOM objective.threats)
uuid_list_strategy = st.lists(uuid_strategy, min_size=0, max_size=10)


# Strategy for generating a DOM object with objective.threats field
@st.composite
def dom_object_strategy(draw):
    """Generate a DOM object with optional objective.threats field."""
    include_objective = draw(st.booleans())
    include_threats = draw(st.booleans())
    
    obj = {}
    
    if include_objective:
        objective = {}
        if include_threats:
            threats = draw(uuid_list_strategy)
            objective["threats"] = threats
        obj["objective"] = objective
    
    return obj


# Strategy for generating a DOM object that always has threats
@st.composite
def dom_object_with_threats_strategy(draw):
    """Generate a DOM object with a non-empty objective.threats field."""
    threats = draw(st.lists(uuid_strategy, min_size=1, max_size=10))
    return {
        "objective": {
            "threats": threats
        }
    }


# Strategy for generating an MDR object with detection_model field
@st.composite
def mdr_object_strategy(draw):
    """Generate an MDR object with optional detection_model field."""
    include_detection_model = draw(st.booleans())
    
    obj = {}
    
    if include_detection_model:
        detection_model = draw(uuid_strategy)
        obj["detection_model"] = detection_model
    
    return obj


# Strategy for generating an MDR object that always has detection_model
@st.composite
def mdr_object_with_detection_model_strategy(draw):
    """Generate an MDR object with a detection_model field."""
    detection_model = draw(uuid_strategy)
    return {
        "detection_model": detection_model
    }


class TestProperty9NonTVMRelationResolution:
    """Property tests for non-TVM relation resolution (Property 9).
    
    **Validates: Requirements 5.6, 5.7, 5.8**
    
    Property 9: Non-TVM relation resolution correctness
    - For any DOM object, resolve_relations() SHALL return exactly the UUIDs 
      from objective.threats.
    - For any MDR object, resolve_relations() SHALL return a list containing 
      exactly the detection_model UUID.
    - When these fields are empty or absent, the function SHALL return an empty list.
    """

    @given(dom_obj=dom_object_with_threats_strategy())
    def test_dom_returns_exactly_objective_threats_uuids(self, dom_obj: dict):
        """Test that DOM relations return exactly the UUIDs from objective.threats.
        
        **Validates: Requirements 5.6**
        
        For any DOM object with objective.threats field populated,
        resolve_relations() should return exactly those UUIDs.
        """
        expected_uuids = dom_obj["objective"]["threats"]
        
        # Call the resolve_relations function with dom type
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        # The result should contain exactly the expected UUIDs
        assert len(result) == len(expected_uuids)
        assert result == [str(uuid) for uuid in expected_uuids]

    @given(mdr_obj=mdr_object_with_detection_model_strategy())
    def test_mdr_returns_exactly_detection_model_uuid(self, mdr_obj: dict):
        """Test that MDR relations return exactly the detection_model UUID.
        
        **Validates: Requirements 5.7**
        
        For any MDR object with detection_model field populated,
        resolve_relations() should return a single-element list with that UUID.
        """
        expected_uuid = mdr_obj["detection_model"]
        
        # Call the resolve_relations function with mdr type
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        
        # The result should be a list with exactly one element - the detection_model UUID
        assert len(result) == 1
        assert result[0] == str(expected_uuid)

    @given(dom_obj=dom_object_strategy())
    def test_dom_empty_absent_fields_return_empty_list(self, dom_obj: dict):
        """Test that DOM objects with empty/absent fields return empty list.
        
        **Validates: Requirements 5.8**
        
        When objective is absent, objective.threats is absent, or 
        objective.threats is empty, resolve_relations() should return [].
        """
        # Check if the object has threats
        objective = dom_obj.get("objective", {})
        threats = objective.get("threats", []) if objective else []
        
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        # If no threats or empty threats, result should be empty
        if not threats:
            assert result == [], f"Expected empty list but got {result}"
        else:
            # If there are threats, result should match
            assert result == [str(t) for t in threats]

    @given(mdr_obj=mdr_object_strategy())
    def test_mdr_empty_absent_fields_return_empty_list(self, mdr_obj: dict):
        """Test that MDR objects with empty/absent detection_model return empty list.
        
        **Validates: Requirements 5.8**
        
        When detection_model is absent or empty, resolve_relations() should return [].
        """
        detection_model = mdr_obj.get("detection_model")
        
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        
        # If no detection_model, result should be empty
        if not detection_model:
            assert result == [], f"Expected empty list but got {result}"
        else:
            # If detection_model exists, result should be a single-element list
            assert result == [str(detection_model)]

    def test_dom_with_empty_objective(self):
        """Test DOM with empty objective returns empty list.
        
        **Validates: Requirements 5.8**
        """
        dom_obj = {"objective": {}}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        assert result == []

    def test_dom_with_empty_threats_list(self):
        """Test DOM with empty threats list returns empty list.
        
        **Validates: Requirements 5.8**
        """
        dom_obj = {"objective": {"threats": []}}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        assert result == []

    def test_dom_without_objective_key(self):
        """Test DOM without objective key returns empty list.
        
        **Validates: Requirements 5.8**
        """
        dom_obj = {}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        assert result == []

    def test_mdr_without_detection_model_key(self):
        """Test MDR without detection_model key returns empty list.
        
        **Validates: Requirements 5.8**
        """
        mdr_obj = {}
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        assert result == []

    def test_mdr_with_none_detection_model(self):
        """Test MDR with None detection_model returns empty list.
        
        **Validates: Requirements 5.8**
        """
        mdr_obj = {"detection_model": None}
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        assert result == []

    def test_mdr_with_empty_string_detection_model(self):
        """Test MDR with empty string detection_model returns empty list.
        
        **Validates: Requirements 5.8**
        """
        mdr_obj = {"detection_model": ""}
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        assert result == []

    @given(uuid_list=st.lists(uuid_strategy, min_size=1, max_size=20))
    def test_dom_preserves_uuid_order(self, uuid_list: list):
        """Test that DOM relation resolution preserves the order of UUIDs.
        
        **Validates: Requirements 5.6**
        
        The order of UUIDs in objective.threats should be preserved in the result.
        """
        dom_obj = {"objective": {"threats": uuid_list}}
        
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        # Order should be preserved
        assert result == [str(uuid) for uuid in uuid_list]

    @given(uuid_str=uuid_strategy)
    def test_mdr_detection_model_converted_to_string(self, uuid_str: str):
        """Test that MDR detection_model is converted to string in result.
        
        **Validates: Requirements 5.7**
        """
        mdr_obj = {"detection_model": uuid_str}
        
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        
        assert len(result) == 1
        assert isinstance(result[0], str)
        assert result[0] == str(uuid_str)


class TestDirectFunctionCalls:
    """Tests that call the internal _resolve_dom_relations and _resolve_mdr_relations directly.
    
    **Validates: Requirements 5.6, 5.7, 5.8**
    """

    @given(dom_obj=dom_object_with_threats_strategy())
    def test_direct_dom_resolution(self, dom_obj: dict):
        """Test _resolve_dom_relations directly.
        
        **Validates: Requirements 5.6**
        """
        expected_uuids = dom_obj["objective"]["threats"]
        result = _resolve_dom_relations(dom_obj)
        
        assert result == [str(uuid) for uuid in expected_uuids]

    @given(mdr_obj=mdr_object_with_detection_model_strategy())
    def test_direct_mdr_resolution(self, mdr_obj: dict):
        """Test _resolve_mdr_relations directly.
        
        **Validates: Requirements 5.7**
        """
        expected_uuid = mdr_obj["detection_model"]
        result = _resolve_mdr_relations(mdr_obj)
        
        assert len(result) == 1
        assert result[0] == str(expected_uuid)

    def test_direct_dom_resolution_empty_objective(self):
        """Test _resolve_dom_relations with empty objective.
        
        **Validates: Requirements 5.8**
        """
        result = _resolve_dom_relations({"objective": {}})
        assert result == []

    def test_direct_dom_resolution_no_objective(self):
        """Test _resolve_dom_relations with no objective.
        
        **Validates: Requirements 5.8**
        """
        result = _resolve_dom_relations({})
        assert result == []

    def test_direct_mdr_resolution_no_detection_model(self):
        """Test _resolve_mdr_relations with no detection_model.
        
        **Validates: Requirements 5.8**
        """
        result = _resolve_mdr_relations({})
        assert result == []

    def test_direct_mdr_resolution_none_detection_model(self):
        """Test _resolve_mdr_relations with None detection_model.
        
        **Validates: Requirements 5.8**
        """
        result = _resolve_mdr_relations({"detection_model": None})
        assert result == []


class TestEdgeCases:
    """Edge case tests for non-TVM relation resolution.
    
    **Validates: Requirements 5.6, 5.7, 5.8**
    """

    def test_dom_threats_with_none_values_filtered(self):
        """Test that None values in threats list are filtered out.
        
        **Validates: Requirements 5.6**
        """
        dom_obj = {
            "objective": {
                "threats": ["uuid-1", None, "uuid-2", None, "uuid-3"]
            }
        }
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        # None values should be filtered
        assert result == ["uuid-1", "uuid-2", "uuid-3"]

    def test_dom_threats_with_empty_strings_filtered(self):
        """Test that empty strings in threats list are filtered out.
        
        **Validates: Requirements 5.6**
        """
        dom_obj = {
            "objective": {
                "threats": ["uuid-1", "", "uuid-2", "", "uuid-3"]
            }
        }
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        # Empty strings should be filtered (as falsy values)
        assert result == ["uuid-1", "uuid-2", "uuid-3"]

    def test_dom_with_objective_none(self):
        """Test DOM with objective set to None returns empty list.
        
        **Validates: Requirements 5.8**
        """
        dom_obj = {"objective": None}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        assert result == []

    def test_dom_with_threats_none(self):
        """Test DOM with threats set to None returns empty list.
        
        **Validates: Requirements 5.8**
        """
        dom_obj = {"objective": {"threats": None}}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        assert result == []

    def test_unknown_object_type_returns_empty_list(self):
        """Test that unknown object types return empty list.
        
        This tests the dispatcher behavior in resolve_relations().
        """
        result = resolve_relations(
            object_uuid="test-uuid",
            object_type="unknown",
            object_data={"some": "data"}
        )
        assert result == []

    @given(uuid_list=st.lists(uuid_strategy, min_size=0, max_size=5))
    def test_dom_result_is_always_list_of_strings(self, uuid_list: list):
        """Test that DOM resolution always returns a list of strings.
        
        **Validates: Requirements 5.6**
        """
        dom_obj = {"objective": {"threats": uuid_list}}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, str)

    @given(uuid_str=uuid_strategy)
    def test_mdr_result_is_always_list_of_strings(self, uuid_str: str):
        """Test that MDR resolution always returns a list of strings.
        
        **Validates: Requirements 5.7**
        """
        mdr_obj = {"detection_model": uuid_str}
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, str)

    def test_mdr_result_is_empty_list_not_none(self):
        """Test that MDR with no detection_model returns empty list, not None.
        
        **Validates: Requirements 5.8**
        """
        mdr_obj = {}
        result = resolve_relations(
            object_uuid="test-mdr-uuid",
            object_type="mdr",
            object_data=mdr_obj
        )
        
        assert result is not None
        assert result == []
        assert isinstance(result, list)

    def test_dom_result_is_empty_list_not_none(self):
        """Test that DOM with no threats returns empty list, not None.
        
        **Validates: Requirements 5.8**
        """
        dom_obj = {}
        result = resolve_relations(
            object_uuid="test-dom-uuid",
            object_type="dom",
            object_data=dom_obj
        )
        
        assert result is not None
        assert result == []
        assert isinstance(result, list)
