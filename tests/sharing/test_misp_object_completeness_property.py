"""Property tests for MISP object attribute completeness (Property 7).

**Validates: Requirements 5.3**

Property 7: MISP object attribute completeness
*For any* OpenTIDE object (TVM, DOM, or MDR) with valid metadata (uuid, version, name),
the constructed `opentide` MISP object SHALL contain all required attributes:
`name`, `opentide-object` (YAML serialization), `opentide-type`, `uuid`, and `version`.

This module uses Hypothesis property-based testing to verify that the
build_opentide_misp_object() function always produces MISP objects with
all required attributes, regardless of the input object data.
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

import uuid

import pytest
import yaml
from hypothesis import given, strategies as st, assume, settings, HealthCheck
from pymisp import MISPObject

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

from Engines.sharing.events import (
    build_opentide_misp_object,
    OPENTIDE_TEMPLATE_UUID,
)


# =============================================================================
# Strategies for property-based tests
# =============================================================================

# Strategy for generating valid UUIDs
uuid_strategy = st.uuids().map(str)


# Strategy for valid version numbers (positive integers)
version_strategy = st.integers(min_value=0, max_value=1_000_000)


# Strategy for object names (non-empty strings, stripped)
# Note: PyMISP strips whitespace from attribute values, so we generate
# names that are already stripped to match the expected behavior.
name_strategy = st.text(
    alphabet=st.characters(
        whitelist_categories=('L', 'N', 'P', 'Zs'),
        blacklist_categories=('Cc', 'Cs'),
    ),
    min_size=1,
    max_size=256
).map(lambda x: x.strip()).filter(lambda x: len(x) > 0)  # Strip and ensure non-empty


# Strategy for object types
object_type_strategy = st.sampled_from(["tvm", "dom", "mdr"])


@st.composite
def metadata_strategy(draw):
    """Generate valid metadata dictionaries with uuid and version."""
    return {
        "uuid": draw(uuid_strategy),
        "version": draw(version_strategy),
    }


@st.composite
def simple_object_data_strategy(draw):
    """Generate simple valid OpenTIDE object dictionaries.
    
    These contain the minimum required fields: metadata with uuid and version.
    """
    metadata = draw(metadata_strategy())
    name = draw(name_strategy)
    
    return {
        "metadata": metadata,
        "name": name,
    }


@st.composite
def nested_dict_strategy(draw, max_depth=2):
    """Generate nested dictionary structures for testing YAML serialization.
    
    Creates dictionaries that may contain nested structures to verify
    that YAML serialization works correctly for complex object data.
    """
    if max_depth <= 0:
        # Base case: return simple values
        return draw(st.one_of(
            st.text(min_size=0, max_size=50),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.booleans(),
            st.none(),
        ))
    
    # Recursive case: potentially nested structures
    return draw(st.one_of(
        st.text(min_size=0, max_size=50),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.booleans(),
        st.none(),
        st.lists(
            nested_dict_strategy(max_depth=max_depth - 1),
            max_size=5
        ),
        st.dictionaries(
            keys=st.text(min_size=1, max_size=20).filter(lambda x: x.strip()),
            values=nested_dict_strategy(max_depth=max_depth - 1),
            max_size=5
        ),
    ))


@st.composite
def complex_object_data_strategy(draw):
    """Generate complex OpenTIDE object dictionaries with nested data.
    
    These contain the required metadata fields plus additional nested
    structures to verify YAML serialization handles complex data.
    """
    metadata = draw(metadata_strategy())
    name = draw(name_strategy)
    
    # Base object with required fields
    obj = {
        "metadata": metadata,
        "name": name,
    }
    
    # Add some optional nested fields
    num_extra_fields = draw(st.integers(min_value=0, max_value=5))
    for _ in range(num_extra_fields):
        field_name = draw(st.text(min_size=1, max_size=20).filter(
            lambda x: x.strip() and x not in obj
        ))
        if field_name and field_name not in obj:
            obj[field_name] = draw(nested_dict_strategy(max_depth=2))
    
    return obj


# Combined strategy for any valid object data
object_data_strategy = st.one_of(
    simple_object_data_strategy(),
    complex_object_data_strategy(),
)


@st.composite
def opentide_object_inputs_strategy(draw):
    """Generate complete valid inputs for build_opentide_misp_object().
    
    Returns a dictionary with:
    - object_uuid: The UUID from the object's metadata
    - object_type: One of "tvm", "dom", "mdr"
    - object_data: The full object dictionary
    - object_name: The object's display name
    """
    object_data = draw(object_data_strategy)
    object_type = draw(object_type_strategy)
    object_name = draw(name_strategy)
    
    # Use the UUID from metadata
    object_uuid = object_data["metadata"]["uuid"]
    
    return {
        "object_uuid": object_uuid,
        "object_type": object_type,
        "object_data": object_data,
        "object_name": object_name,
    }


# =============================================================================
# Property Tests
# =============================================================================

class TestMISPObjectAttributeCompleteness:
    """Property tests for MISP object attribute completeness.
    
    **Validates: Requirements 5.3**
    
    These tests verify that for any valid OpenTIDE object, the constructed
    MISP object always contains all required attributes.
    """
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_all_required_attributes_present(self, inputs: dict):
        """Test that all required attributes are always present.
        
        **Validates: Requirements 5.3**
        
        For any valid OpenTIDE object, the constructed MISP object SHALL contain:
        - name
        - opentide-object (YAML serialization)
        - opentide-type
        - uuid
        - version
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Get attribute names from the MISP object
        attr_relations = {attr.object_relation for attr in result.Attribute}
        
        required_attributes = {"name", "opentide-object", "opentide-type", "uuid", "version"}
        
        assert required_attributes.issubset(attr_relations), (
            f"Missing required attributes. "
            f"Expected: {required_attributes}, "
            f"Got: {attr_relations}, "
            f"Missing: {required_attributes - attr_relations}"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_name_attribute_matches_input(self, inputs: dict):
        """Test that the name attribute matches the provided object_name.
        
        **Validates: Requirements 5.3**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract the name attribute value
        name_attrs = [attr for attr in result.Attribute if attr.object_relation == "name"]
        
        assert len(name_attrs) == 1, f"Expected exactly one 'name' attribute, got {len(name_attrs)}"
        assert name_attrs[0].value == inputs["object_name"], (
            f"Name mismatch: expected '{inputs['object_name']}', "
            f"got '{name_attrs[0].value}'"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_uuid_attribute_matches_input(self, inputs: dict):
        """Test that the uuid attribute matches the provided object_uuid.
        
        **Validates: Requirements 5.3**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract the uuid attribute value
        uuid_attrs = [attr for attr in result.Attribute if attr.object_relation == "uuid"]
        
        assert len(uuid_attrs) == 1, f"Expected exactly one 'uuid' attribute, got {len(uuid_attrs)}"
        assert uuid_attrs[0].value == inputs["object_uuid"], (
            f"UUID mismatch: expected '{inputs['object_uuid']}', "
            f"got '{uuid_attrs[0].value}'"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_opentide_type_matches_input(self, inputs: dict):
        """Test that the opentide-type attribute matches the provided object_type.
        
        **Validates: Requirements 5.3**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract the opentide-type attribute value
        type_attrs = [attr for attr in result.Attribute if attr.object_relation == "opentide-type"]
        
        assert len(type_attrs) == 1, f"Expected exactly one 'opentide-type' attribute, got {len(type_attrs)}"
        assert type_attrs[0].value == inputs["object_type"], (
            f"Type mismatch: expected '{inputs['object_type']}', "
            f"got '{type_attrs[0].value}'"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_version_attribute_is_string(self, inputs: dict):
        """Test that the version attribute is always a string.
        
        **Validates: Requirements 5.3**
        
        The version must be converted to a string for MISP compatibility.
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract the version attribute value
        version_attrs = [attr for attr in result.Attribute if attr.object_relation == "version"]
        
        assert len(version_attrs) == 1, f"Expected exactly one 'version' attribute, got {len(version_attrs)}"
        assert isinstance(version_attrs[0].value, str), (
            f"Version should be string, got {type(version_attrs[0].value).__name__}"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_version_matches_metadata_as_string(self, inputs: dict):
        """Test that the version attribute matches metadata.version as string.
        
        **Validates: Requirements 5.3**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract the version attribute value
        version_attrs = [attr for attr in result.Attribute if attr.object_relation == "version"]
        
        expected_version = str(inputs["object_data"]["metadata"]["version"])
        assert version_attrs[0].value == expected_version, (
            f"Version mismatch: expected '{expected_version}', "
            f"got '{version_attrs[0].value}'"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_opentide_object_is_valid_yaml(self, inputs: dict):
        """Test that the opentide-object attribute contains valid YAML.
        
        **Validates: Requirements 5.3**
        
        The opentide-object attribute must be a valid YAML serialization
        of the object data.
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract the opentide-object attribute value
        obj_attrs = [attr for attr in result.Attribute if attr.object_relation == "opentide-object"]
        
        assert len(obj_attrs) == 1, f"Expected exactly one 'opentide-object' attribute, got {len(obj_attrs)}"
        
        # Verify it's valid YAML that can be parsed back
        yaml_content = obj_attrs[0].value
        try:
            parsed = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            pytest.fail(f"opentide-object contains invalid YAML: {e}")
        
        # The parsed content should match the original object data
        assert parsed == inputs["object_data"], (
            f"YAML content doesn't match input object_data. "
            f"Expected: {inputs['object_data']}, Parsed: {parsed}"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_result_is_misp_object(self, inputs: dict):
        """Test that the result is always a MISPObject instance.
        
        **Validates: Requirements 5.3**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        assert isinstance(result, MISPObject), (
            f"Expected MISPObject, got {type(result).__name__}"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_misp_object_name_is_opentide(self, inputs: dict):
        """Test that the MISP object name is always 'opentide'.
        
        **Validates: Requirements 5.3**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        assert result.name == "opentide", (
            f"MISP object name should be 'opentide', got '{result.name}'"
        )


class TestMISPObjectRelationsHandling:
    """Property tests for opentide-relation attribute handling.
    
    **Validates: Requirements 5.3, 5.4, 5.8**
    
    These tests verify that relations are correctly added when present
    and omitted when absent.
    """
    
    @given(
        inputs=opentide_object_inputs_strategy(),
        relations=st.lists(uuid_strategy, min_size=1, max_size=10)
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_relations_added_when_present(self, inputs: dict, relations: list):
        """Test that opentide-relation attributes are added when relations exist.
        
        **Validates: Requirements 5.4**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=relations):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract all opentide-relation attribute values
        relation_attrs = [
            attr.value for attr in result.Attribute 
            if attr.object_relation == "opentide-relation"
        ]
        
        assert len(relation_attrs) == len(relations), (
            f"Expected {len(relations)} relation attributes, got {len(relation_attrs)}"
        )
        assert set(relation_attrs) == set(relations), (
            f"Relation values mismatch. Expected: {set(relations)}, Got: {set(relation_attrs)}"
        )
    
    @given(inputs=opentide_object_inputs_strategy())
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_no_relations_when_empty(self, inputs: dict):
        """Test that no opentide-relation attributes exist when relations are empty.
        
        **Validates: Requirements 5.8**
        """
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=inputs["object_uuid"],
                object_type=inputs["object_type"],
                object_data=inputs["object_data"],
                object_name=inputs["object_name"]
            )
        
        # Extract all opentide-relation attribute values
        relation_attrs = [
            attr for attr in result.Attribute 
            if attr.object_relation == "opentide-relation"
        ]
        
        assert len(relation_attrs) == 0, (
            f"Expected no relation attributes when relations are empty, "
            f"got {len(relation_attrs)}"
        )


class TestMISPObjectWithMissingVersion:
    """Property tests for handling objects with missing version.
    
    **Validates: Requirements 5.3**
    
    These tests verify that the function handles missing metadata.version
    gracefully by defaulting to '0'.
    """
    
    @given(
        object_uuid=uuid_strategy,
        object_type=object_type_strategy,
        object_name=name_strategy
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_missing_version_defaults_to_zero(
        self, 
        object_uuid: str, 
        object_type: str, 
        object_name: str
    ):
        """Test that missing metadata.version defaults to '0'.
        
        **Validates: Requirements 5.3**
        """
        object_data = {
            "metadata": {
                "uuid": object_uuid,
                # version is intentionally missing
            },
            "name": object_name,
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=object_uuid,
                object_type=object_type,
                object_data=object_data,
                object_name=object_name
            )
        
        # Extract the version attribute value
        version_attrs = [attr for attr in result.Attribute if attr.object_relation == "version"]
        
        assert len(version_attrs) == 1, f"Expected exactly one 'version' attribute"
        assert version_attrs[0].value == "0", (
            f"Version should default to '0' when missing, got '{version_attrs[0].value}'"
        )
    
    @given(
        object_uuid=uuid_strategy,
        object_type=object_type_strategy,
        object_name=name_strategy
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_required_attributes_present_even_with_missing_version(
        self, 
        object_uuid: str, 
        object_type: str, 
        object_name: str
    ):
        """Test that all required attributes are present even when version is missing.
        
        **Validates: Requirements 5.3**
        """
        object_data = {
            "metadata": {
                "uuid": object_uuid,
                # version is intentionally missing
            },
            "name": object_name,
        }
        
        with patch('Engines.sharing.events.resolve_relations', return_value=[]):
            result = build_opentide_misp_object(
                object_uuid=object_uuid,
                object_type=object_type,
                object_data=object_data,
                object_name=object_name
            )
        
        # Get attribute names from the MISP object
        attr_relations = {attr.object_relation for attr in result.Attribute}
        
        required_attributes = {"name", "opentide-object", "opentide-type", "uuid", "version"}
        
        assert required_attributes.issubset(attr_relations), (
            f"Missing required attributes with missing version. "
            f"Expected: {required_attributes}, "
            f"Got: {attr_relations}, "
            f"Missing: {required_attributes - attr_relations}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
