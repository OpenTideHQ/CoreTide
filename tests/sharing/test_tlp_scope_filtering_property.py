"""Property-based tests for TLP scope filtering correctness.

**Validates: Requirements 2.2, 2.4**

Property 5: TLP scope filtering correctness
- For any OpenTIDE object with a valid TLP value and for any MISP instance
  configuration with a valid max_allowed_tlp, the object SHALL be included
  in the sharing scope if and only if the object's TLP level is less than
  or equal to the instance's max_allowed_tlp level according to the TLP hierarchy.
"""

import sys
from pathlib import Path
from typing import Dict, List, Literal, Tuple
from unittest.mock import MagicMock

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))

# Mock the heavy imports before importing from sharing module
sys.modules['Engines.modules.tide'] = MagicMock()
sys.modules['Engines.modules.logs'] = MagicMock()

import pytest
from hypothesis import given, strategies as st, assume, settings

# Import the actual function we're testing
from Engines.sharing.scope import compute_sharing_scope, ScopedObject

# Import TLPLevel from sharing module for consistency
from Engines.modules.sharing import TLPLevel, MISPInstanceConfig


# Define the TLP hierarchy ordering for reference
TLP_ORDERED_LEVELS = [
    TLPLevel.CLEAR,
    TLPLevel.GREEN,
    TLPLevel.AMBER,
    TLPLevel.AMBER_STRICT,
    TLPLevel.RED,
]

# TLP string values mapped to TLPLevel
TLP_STRING_TO_LEVEL = {
    "clear": TLPLevel.CLEAR,
    "white": TLPLevel.CLEAR,
    "green": TLPLevel.GREEN,
    "amber": TLPLevel.AMBER,
    "amber+strict": TLPLevel.AMBER_STRICT,
    "red": TLPLevel.RED,
}

# Valid TLP string values
VALID_TLP_STRINGS = ["clear", "white", "green", "amber", "amber+strict", "red"]

# Object types
ObjectType = Literal["tvm", "dom", "mdr"]
OBJECT_TYPES: List[ObjectType] = ["tvm", "dom", "mdr"]


# Strategy for generating valid TLP levels
tlp_level_strategy = st.sampled_from(TLP_ORDERED_LEVELS)


# Strategy for generating valid TLP strings
tlp_string_strategy = st.sampled_from(VALID_TLP_STRINGS)


# Strategy for generating object type
object_type_strategy = st.sampled_from(OBJECT_TYPES)


# Strategy for generating a valid UUID string
uuid_strategy = st.uuids().map(str)


# Strategy for generating a MISP instance config with a specific max_allowed_tlp
@st.composite
def misp_instance_config_strategy(draw, max_tlp: TLPLevel = None):
    """Generate a valid MISPInstanceConfig with optional fixed max_allowed_tlp."""
    if max_tlp is None:
        max_tlp = draw(tlp_level_strategy)
    
    return MISPInstanceConfig(
        name=draw(st.text(min_size=1, max_size=50, alphabet=st.characters(
            whitelist_categories=('L', 'N'),
            whitelist_characters=' -_'
        )).filter(lambda s: len(s.strip()) > 0)),
        url="https://misp.example.org",
        token="test-token-12345",
        org_uuid=draw(uuid_strategy),
        max_allowed_tlp=max_tlp,
        mode="send",
        proxy=False,
        publish_on_change=False,
        verify_ssl=True,
    )


# Strategy for generating an OpenTIDE object with a specific TLP
@st.composite
def opentide_object_strategy(draw, tlp_str: str = None, object_type: ObjectType = None):
    """Generate an OpenTIDE object dictionary with optional fixed TLP and type."""
    if tlp_str is None:
        tlp_str = draw(tlp_string_strategy)
    
    if object_type is None:
        object_type = draw(object_type_strategy)
    
    obj_uuid = draw(uuid_strategy)
    obj_name = f"Test Object {obj_uuid[:8]}"
    
    return {
        "uuid": obj_uuid,
        "type": object_type,
        "data": {
            "name": obj_name,
            "metadata": {
                "uuid": obj_uuid,
                "tlp": tlp_str,
                "version": 1,
            }
        }
    }


# Strategy for generating a collection of objects with various TLPs
@st.composite
def all_objects_strategy(draw, min_objects: int = 1, max_objects: int = 20):
    """Generate a dictionary of objects suitable for compute_sharing_scope."""
    num_objects = draw(st.integers(min_value=min_objects, max_value=max_objects))
    
    all_objects: Dict[str, Tuple[ObjectType, dict]] = {}
    
    for _ in range(num_objects):
        obj = draw(opentide_object_strategy())
        obj_uuid = obj["uuid"]
        obj_type = obj["type"]
        obj_data = obj["data"]
        all_objects[obj_uuid] = (obj_type, obj_data)
    
    return all_objects


class TestProperty5TLPScopeFilteringCorrectness:
    """Property tests for TLP scope filtering correctness (Property 5).
    
    **Validates: Requirements 2.2, 2.4**
    
    Property 5: TLP scope filtering correctness
    - For any OpenTIDE object with a valid TLP value and for any MISP instance
      configuration with a valid max_allowed_tlp, the object SHALL be included
      in the sharing scope if and only if the object's TLP level is less than
      or equal to the instance's max_allowed_tlp level according to the TLP hierarchy.
    """

    @given(
        object_tlp=tlp_level_strategy,
        instance_max_tlp=tlp_level_strategy,
        object_type=object_type_strategy
    )
    def test_object_included_iff_tlp_lte_max_allowed(
        self,
        object_tlp: TLPLevel,
        instance_max_tlp: TLPLevel,
        object_type: ObjectType
    ):
        """Test that an object is included iff its TLP <= instance max_allowed_tlp.
        
        **Validates: Requirements 2.2, 2.4**
        
        This is the core property test. For any valid combination of object TLP
        and instance max_allowed_tlp, the object should be in the scope if and
        only if object_tlp <= instance_max_tlp.
        """
        # Create a MISP instance config with the specified max_allowed_tlp
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=instance_max_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Get the TLP string for the object
        # Map TLPLevel back to string for object data
        tlp_level_to_string = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red",
        }
        tlp_str = tlp_level_to_string[object_tlp]
        
        # Create a single object with the specified TLP
        obj_uuid = "test-object-uuid-12345678"
        obj_name = "Test Object"
        obj_data = {
            "name": obj_name,
            "metadata": {
                "uuid": obj_uuid,
                "tlp": tlp_str,
                "version": 1,
            }
        }
        
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            obj_uuid: (object_type, obj_data)
        }
        
        # Compute the sharing scope
        scope = compute_sharing_scope(instance_config, all_objects)
        
        # Expected: object is in scope iff object_tlp <= instance_max_tlp
        should_be_included = object_tlp <= instance_max_tlp
        
        # Check the result
        scope_uuids = {obj.uuid for obj in scope}
        is_included = obj_uuid in scope_uuids
        
        assert is_included == should_be_included, (
            f"Object with TLP {object_tlp.name} (level {object_tlp.value}) "
            f"{'should' if should_be_included else 'should NOT'} be in scope "
            f"for instance with max_allowed_tlp {instance_max_tlp.name} "
            f"(level {instance_max_tlp.value}), but was "
            f"{'included' if is_included else 'excluded'}"
        )

    @given(instance_max_tlp=tlp_level_strategy)
    def test_all_objects_at_or_below_max_tlp_are_included(
        self,
        instance_max_tlp: TLPLevel
    ):
        """Test that all objects with TLP <= max_allowed_tlp are included.
        
        **Validates: Requirements 2.2, 2.4**
        
        Create objects at each TLP level and verify that exactly those at or
        below the max_allowed_tlp are included in the scope.
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=instance_max_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Map TLPLevel to string
        tlp_level_to_string = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red",
        }
        
        # Create one object at each TLP level
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {}
        expected_in_scope: set = set()
        
        for tlp_level in TLP_ORDERED_LEVELS:
            obj_uuid = f"object-{tlp_level.name.lower()}-uuid"
            tlp_str = tlp_level_to_string[tlp_level]
            
            all_objects[obj_uuid] = ("tvm", {
                "name": f"Object at {tlp_level.name}",
                "metadata": {
                    "uuid": obj_uuid,
                    "tlp": tlp_str,
                    "version": 1,
                }
            })
            
            # Object should be in scope if its TLP <= max_allowed_tlp
            if tlp_level <= instance_max_tlp:
                expected_in_scope.add(obj_uuid)
        
        # Compute the sharing scope
        scope = compute_sharing_scope(instance_config, all_objects)
        actual_in_scope = {obj.uuid for obj in scope}
        
        assert actual_in_scope == expected_in_scope, (
            f"With max_allowed_tlp={instance_max_tlp.name}, "
            f"expected objects {expected_in_scope} in scope, "
            f"but got {actual_in_scope}"
        )

    @given(object_tlp=tlp_level_strategy)
    def test_object_excluded_from_instances_with_lower_max_tlp(
        self,
        object_tlp: TLPLevel
    ):
        """Test that an object is excluded from instances with lower max_allowed_tlp.
        
        **Validates: Requirements 2.2, 2.4**
        
        For any object with a given TLP, it should be excluded from all instances
        whose max_allowed_tlp is lower than the object's TLP.
        """
        # Map TLPLevel to string
        tlp_level_to_string = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red",
        }
        
        # Create an object at the specified TLP level
        obj_uuid = "test-object-uuid"
        obj_data = {
            "name": "Test Object",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": tlp_level_to_string[object_tlp],
                "version": 1,
            }
        }
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            obj_uuid: ("tvm", obj_data)
        }
        
        # Test against all possible max_allowed_tlp values
        for instance_max_tlp in TLP_ORDERED_LEVELS:
            instance_config = MISPInstanceConfig(
                name=f"Instance with max TLP {instance_max_tlp.name}",
                url="https://misp.example.org",
                token="test-token",
                org_uuid="11111111-2222-3333-4444-555555555555",
                max_allowed_tlp=instance_max_tlp,
                mode="send",
                proxy=False,
                publish_on_change=False,
                verify_ssl=True,
            )
            
            scope = compute_sharing_scope(instance_config, all_objects)
            scope_uuids = {obj.uuid for obj in scope}
            
            should_be_included = object_tlp <= instance_max_tlp
            is_included = obj_uuid in scope_uuids
            
            assert is_included == should_be_included, (
                f"Object with TLP {object_tlp.name} "
                f"{'should' if should_be_included else 'should NOT'} be included "
                f"for instance with max_allowed_tlp {instance_max_tlp.name}"
            )

    @given(
        tlp_str=st.sampled_from(["clear", "white", "green", "amber", "amber+strict", "red"]),
        data=st.data()
    )
    def test_tlp_string_case_variations_handled(self, tlp_str: str, data):
        """Test that TLP string parsing handles case variations correctly.
        
        **Validates: Requirements 2.2, 2.4** (indirectly via case-insensitive parsing)
        
        The compute_sharing_scope function should handle TLP strings in any case.
        """
        # Generate case variation
        casing = data.draw(st.sampled_from(["lower", "upper", "title", "mixed"]))
        if casing == "lower":
            case_varied = tlp_str.lower()
        elif casing == "upper":
            case_varied = tlp_str.upper()
        elif casing == "title":
            case_varied = tlp_str.title()
        else:  # mixed
            case_varied = "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(tlp_str)
            )
        
        # Get expected TLP level
        expected_tlp = TLP_STRING_TO_LEVEL[tlp_str.lower()]
        
        # Create instance with max_allowed_tlp = expected_tlp (should include object)
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=expected_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Create object with case-varied TLP string
        obj_uuid = "test-object-uuid"
        obj_data = {
            "name": "Test Object",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": case_varied,
                "version": 1,
            }
        }
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            obj_uuid: ("tvm", obj_data)
        }
        
        # Compute scope - object should be included since TLP equals max_allowed_tlp
        scope = compute_sharing_scope(instance_config, all_objects)
        scope_uuids = {obj.uuid for obj in scope}
        
        assert obj_uuid in scope_uuids, (
            f"Object with TLP '{case_varied}' should be included in scope "
            f"with max_allowed_tlp={expected_tlp.name}"
        )

    @given(data=st.data())
    def test_white_equals_clear_for_scope_filtering(self, data):
        """Test that 'white' TLP is treated equivalently to 'clear' in filtering.
        
        **Validates: Requirements 2.2** (TLP hierarchy where white=clear)
        
        Objects with TLP 'white' and 'clear' should have identical filtering behavior.
        """
        # Get a max_allowed_tlp value
        instance_max_tlp = data.draw(tlp_level_strategy)
        
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=instance_max_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Create two objects: one with 'white', one with 'clear'
        white_uuid = "object-white-uuid"
        clear_uuid = "object-clear-uuid"
        
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            white_uuid: ("tvm", {
                "name": "Object with TLP white",
                "metadata": {"uuid": white_uuid, "tlp": "white", "version": 1}
            }),
            clear_uuid: ("tvm", {
                "name": "Object with TLP clear",
                "metadata": {"uuid": clear_uuid, "tlp": "clear", "version": 1}
            }),
        }
        
        scope = compute_sharing_scope(instance_config, all_objects)
        scope_uuids = {obj.uuid for obj in scope}
        
        # Both should have the same inclusion status
        white_included = white_uuid in scope_uuids
        clear_included = clear_uuid in scope_uuids
        
        assert white_included == clear_included, (
            f"'white' and 'clear' should have same inclusion status, "
            f"but white={white_included}, clear={clear_included}"
        )

    @given(all_objects=all_objects_strategy(min_objects=1, max_objects=50))
    @settings(max_examples=50)
    def test_scope_filtering_with_multiple_objects(
        self,
        all_objects: Dict[str, Tuple[ObjectType, dict]]
    ):
        """Test scope filtering with multiple objects at various TLP levels.
        
        **Validates: Requirements 2.2, 2.4**
        
        For a collection of objects with various TLP levels, verify that
        exactly the correct subset is included based on the instance's max_allowed_tlp.
        """
        # Choose a random max_allowed_tlp for the instance
        instance_max_tlp = TLP_ORDERED_LEVELS[len(TLP_ORDERED_LEVELS) // 2]  # AMBER
        
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=instance_max_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Calculate expected objects in scope
        expected_in_scope: set = set()
        for obj_uuid, (obj_type, obj_data) in all_objects.items():
            tlp_str = obj_data.get("metadata", {}).get("tlp")
            if tlp_str:
                try:
                    obj_tlp = TLPLevel.from_string(str(tlp_str))
                    if obj_tlp <= instance_max_tlp:
                        expected_in_scope.add(obj_uuid)
                except ValueError:
                    pass  # Invalid TLP string - object will be excluded
        
        # Compute the sharing scope
        scope = compute_sharing_scope(instance_config, all_objects)
        actual_in_scope = {obj.uuid for obj in scope}
        
        assert actual_in_scope == expected_in_scope, (
            f"Expected {len(expected_in_scope)} objects in scope, "
            f"got {len(actual_in_scope)}. "
            f"Missing: {expected_in_scope - actual_in_scope}, "
            f"Extra: {actual_in_scope - expected_in_scope}"
        )


class TestScopeFilteringEdgeCases:
    """Edge case tests for TLP scope filtering.
    
    **Validates: Requirements 2.2, 2.4**
    """

    def test_empty_objects_returns_empty_scope(self):
        """Test that empty objects dictionary returns empty scope.
        
        **Validates: Requirements 2.2**
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.RED,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        scope = compute_sharing_scope(instance_config, {})
        
        assert scope == []
        assert isinstance(scope, list)

    def test_max_tlp_clear_only_includes_clear_white(self):
        """Test that max_allowed_tlp=CLEAR only includes CLEAR/WHITE objects.
        
        **Validates: Requirements 2.2, 2.4**
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.CLEAR,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Create objects at each TLP level
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            "obj-clear": ("tvm", {"name": "Clear", "metadata": {"uuid": "obj-clear", "tlp": "clear", "version": 1}}),
            "obj-white": ("tvm", {"name": "White", "metadata": {"uuid": "obj-white", "tlp": "white", "version": 1}}),
            "obj-green": ("tvm", {"name": "Green", "metadata": {"uuid": "obj-green", "tlp": "green", "version": 1}}),
            "obj-amber": ("tvm", {"name": "Amber", "metadata": {"uuid": "obj-amber", "tlp": "amber", "version": 1}}),
            "obj-amber-strict": ("tvm", {"name": "Amber+Strict", "metadata": {"uuid": "obj-amber-strict", "tlp": "amber+strict", "version": 1}}),
            "obj-red": ("tvm", {"name": "Red", "metadata": {"uuid": "obj-red", "tlp": "red", "version": 1}}),
        }
        
        scope = compute_sharing_scope(instance_config, all_objects)
        scope_uuids = {obj.uuid for obj in scope}
        
        # Only clear and white should be included
        assert scope_uuids == {"obj-clear", "obj-white"}

    def test_max_tlp_red_includes_all_objects(self):
        """Test that max_allowed_tlp=RED includes all TLP levels.
        
        **Validates: Requirements 2.2, 2.4**
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.RED,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            "obj-clear": ("tvm", {"name": "Clear", "metadata": {"uuid": "obj-clear", "tlp": "clear", "version": 1}}),
            "obj-green": ("dom", {"name": "Green", "metadata": {"uuid": "obj-green", "tlp": "green", "version": 1}}),
            "obj-amber": ("mdr", {"name": "Amber", "metadata": {"uuid": "obj-amber", "tlp": "amber", "version": 1}}),
            "obj-amber-strict": ("tvm", {"name": "Amber+Strict", "metadata": {"uuid": "obj-amber-strict", "tlp": "amber+strict", "version": 1}}),
            "obj-red": ("dom", {"name": "Red", "metadata": {"uuid": "obj-red", "tlp": "red", "version": 1}}),
        }
        
        scope = compute_sharing_scope(instance_config, all_objects)
        scope_uuids = {obj.uuid for obj in scope}
        
        # All objects should be included
        assert scope_uuids == {"obj-clear", "obj-green", "obj-amber", "obj-amber-strict", "obj-red"}

    def test_scope_includes_correct_object_metadata(self):
        """Test that ScopedObject contains correct metadata from the source object.
        
        **Validates: Requirements 2.2**
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.AMBER,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        obj_uuid = "test-object-12345"
        obj_name = "My Test Object"
        obj_data = {
            "name": obj_name,
            "metadata": {
                "uuid": obj_uuid,
                "tlp": "green",
                "version": 5,
            },
            "extra_field": "extra_value"
        }
        
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            obj_uuid: ("dom", obj_data)
        }
        
        scope = compute_sharing_scope(instance_config, all_objects)
        
        assert len(scope) == 1
        scoped_obj = scope[0]
        
        assert scoped_obj.uuid == obj_uuid
        assert scoped_obj.name == obj_name
        assert scoped_obj.object_type == "dom"
        assert scoped_obj.tlp == TLPLevel.GREEN
        assert scoped_obj.data == obj_data

    def test_object_missing_tlp_is_excluded(self):
        """Test that objects missing metadata.tlp are excluded from scope.
        
        **Validates: Requirement 2.3** (Objects without TLP are excluded)
        
        Note: This is related to 2.2 and 2.4 as it affects scope filtering.
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.RED,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            "obj-with-tlp": ("tvm", {"name": "With TLP", "metadata": {"uuid": "obj-with-tlp", "tlp": "green", "version": 1}}),
            "obj-without-tlp": ("tvm", {"name": "Without TLP", "metadata": {"uuid": "obj-without-tlp", "version": 1}}),
            "obj-empty-metadata": ("dom", {"name": "Empty Metadata", "metadata": {}}),
            "obj-no-metadata": ("mdr", {"name": "No Metadata"}),
        }
        
        scope = compute_sharing_scope(instance_config, all_objects)
        scope_uuids = {obj.uuid for obj in scope}
        
        # Only object with valid TLP should be included
        assert scope_uuids == {"obj-with-tlp"}

    @given(
        object_type=object_type_strategy,
        tlp_level=tlp_level_strategy
    )
    def test_scope_preserves_object_type(
        self,
        object_type: ObjectType,
        tlp_level: TLPLevel
    ):
        """Test that ScopedObject correctly preserves the object type.
        
        **Validates: Requirements 2.2, 2.4**
        """
        instance_config = MISPInstanceConfig(
            name="Test Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.RED,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        tlp_level_to_string = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red",
        }
        
        obj_uuid = "test-object-uuid"
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            obj_uuid: (object_type, {
                "name": "Test Object",
                "metadata": {
                    "uuid": obj_uuid,
                    "tlp": tlp_level_to_string[tlp_level],
                    "version": 1
                }
            })
        }
        
        scope = compute_sharing_scope(instance_config, all_objects)
        
        assert len(scope) == 1
        assert scope[0].object_type == object_type


class TestScopeFilteringIndependencePerInstance:
    """Test that TLP filtering is evaluated independently per MISP instance.
    
    **Validates: Requirements 2.4**
    """

    def test_different_instances_have_different_scopes(self):
        """Test that different instances with different max_allowed_tlp have different scopes.
        
        **Validates: Requirements 2.4**
        
        THE Sharing_Engine SHALL evaluate TLP filtering independently for each
        configured MISP_Instance.
        """
        # Create instances with different max_allowed_tlp
        instance_green = MISPInstanceConfig(
            name="Green Instance",
            url="https://green.misp.org",
            token="green-token",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=TLPLevel.GREEN,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        instance_amber = MISPInstanceConfig(
            name="Amber Instance",
            url="https://amber.misp.org",
            token="amber-token",
            org_uuid="22222222-3333-4444-5555-666666666666",
            max_allowed_tlp=TLPLevel.AMBER,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Create objects at different TLP levels
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            "obj-clear": ("tvm", {"name": "Clear", "metadata": {"uuid": "obj-clear", "tlp": "clear", "version": 1}}),
            "obj-green": ("dom", {"name": "Green", "metadata": {"uuid": "obj-green", "tlp": "green", "version": 1}}),
            "obj-amber": ("mdr", {"name": "Amber", "metadata": {"uuid": "obj-amber", "tlp": "amber", "version": 1}}),
            "obj-red": ("tvm", {"name": "Red", "metadata": {"uuid": "obj-red", "tlp": "red", "version": 1}}),
        }
        
        # Compute scopes for each instance independently
        scope_green = compute_sharing_scope(instance_green, all_objects)
        scope_amber = compute_sharing_scope(instance_amber, all_objects)
        
        green_uuids = {obj.uuid for obj in scope_green}
        amber_uuids = {obj.uuid for obj in scope_amber}
        
        # Green instance should only have clear and green
        assert green_uuids == {"obj-clear", "obj-green"}
        
        # Amber instance should have clear, green, and amber
        assert amber_uuids == {"obj-clear", "obj-green", "obj-amber"}
        
        # Verify they are different
        assert green_uuids != amber_uuids

    @given(
        max_tlp_1=tlp_level_strategy,
        max_tlp_2=tlp_level_strategy
    )
    def test_two_instances_scope_relationship(
        self,
        max_tlp_1: TLPLevel,
        max_tlp_2: TLPLevel
    ):
        """Test the relationship between scopes of two instances.
        
        **Validates: Requirements 2.4**
        
        If instance A has max_allowed_tlp <= instance B's max_allowed_tlp,
        then A's scope should be a subset of (or equal to) B's scope.
        """
        instance_1 = MISPInstanceConfig(
            name="Instance 1",
            url="https://misp1.org",
            token="token1",
            org_uuid="11111111-2222-3333-4444-555555555555",
            max_allowed_tlp=max_tlp_1,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        instance_2 = MISPInstanceConfig(
            name="Instance 2",
            url="https://misp2.org",
            token="token2",
            org_uuid="22222222-3333-4444-5555-666666666666",
            max_allowed_tlp=max_tlp_2,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True,
        )
        
        # Create objects at all TLP levels
        all_objects: Dict[str, Tuple[ObjectType, dict]] = {
            "obj-clear": ("tvm", {"name": "Clear", "metadata": {"uuid": "obj-clear", "tlp": "clear", "version": 1}}),
            "obj-green": ("dom", {"name": "Green", "metadata": {"uuid": "obj-green", "tlp": "green", "version": 1}}),
            "obj-amber": ("mdr", {"name": "Amber", "metadata": {"uuid": "obj-amber", "tlp": "amber", "version": 1}}),
            "obj-amber-strict": ("tvm", {"name": "Amber+Strict", "metadata": {"uuid": "obj-amber-strict", "tlp": "amber+strict", "version": 1}}),
            "obj-red": ("dom", {"name": "Red", "metadata": {"uuid": "obj-red", "tlp": "red", "version": 1}}),
        }
        
        scope_1 = compute_sharing_scope(instance_1, all_objects)
        scope_2 = compute_sharing_scope(instance_2, all_objects)
        
        uuids_1 = {obj.uuid for obj in scope_1}
        uuids_2 = {obj.uuid for obj in scope_2}
        
        # If max_tlp_1 <= max_tlp_2, then scope_1 should be subset of scope_2
        if max_tlp_1 <= max_tlp_2:
            assert uuids_1.issubset(uuids_2), (
                f"With max_tlp_1={max_tlp_1.name} <= max_tlp_2={max_tlp_2.name}, "
                f"scope_1 ({uuids_1}) should be subset of scope_2 ({uuids_2})"
            )
        else:
            # max_tlp_1 > max_tlp_2, so scope_2 should be subset of scope_1
            assert uuids_2.issubset(uuids_1), (
                f"With max_tlp_2={max_tlp_2.name} <= max_tlp_1={max_tlp_1.name}, "
                f"scope_2 ({uuids_2}) should be subset of scope_1 ({uuids_1})"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
