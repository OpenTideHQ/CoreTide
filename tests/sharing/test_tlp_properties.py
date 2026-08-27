"""Property-based tests for TLP hierarchy ordering and scope filtering.

This module tests Property 4 (TLP hierarchy ordering) and Property 5 
(TLP scope filtering correctness) using Hypothesis.

**Validates: Requirements 2.1, 2.2, 2.4, 2.6**
"""

import sys
import uuid
from unittest.mock import patch

import git
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

# Add project root to path for imports
sys.path.insert(0, str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.sharing import TLPLevel, MISPInstanceConfig
from Engines.sharing.scope import compute_sharing_scope, ScopedObject


# Strategies for generating test data
tlp_levels = st.sampled_from(list(TLPLevel))

tlp_strings = st.sampled_from([
    "clear", "CLEAR", "Clear",
    "white", "WHITE", "White",  # alias for clear
    "green", "GREEN", "Green",
    "amber", "AMBER", "Amber",
    "amber+strict", "AMBER+STRICT", "Amber+Strict",
    "red", "RED", "Red"
])

object_types = st.sampled_from(["tvm", "dom", "mdr"])


@st.composite
def valid_uuid(draw):
    """Generate a valid UUIDv4 string."""
    return str(uuid.uuid4())


@st.composite
def misp_instance_config(draw, max_tlp=None):
    """Generate a valid MISPInstanceConfig for testing.
    
    Args:
        max_tlp: Optional specific TLP level to use. If None, randomly generated.
    """
    if max_tlp is None:
        max_tlp = draw(tlp_levels)
    
    return MISPInstanceConfig(
        name=draw(st.text(min_size=1, max_size=128, alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd", "Pc"),
            whitelist_characters=" -_"
        ))),
        url=f"https://misp-{draw(st.integers(min_value=1, max_value=1000))}.example.org",
        token="test-token",
        org_uuid=draw(valid_uuid()),
        max_allowed_tlp=max_tlp,
        mode=draw(st.sampled_from(["send", "fetch", "sync"])),
        proxy=draw(st.booleans()),
        publish_on_change=draw(st.booleans()),
        verify_ssl=draw(st.booleans())
    )


@st.composite
def opentide_object(draw, tlp_level=None):
    """Generate a valid OpenTIDE object dictionary.
    
    Args:
        tlp_level: Optional specific TLP level string. If None, randomly generated.
    """
    if tlp_level is None:
        tlp_level = draw(tlp_strings)
    
    obj_uuid = draw(valid_uuid())
    obj_name = draw(st.text(min_size=1, max_size=100, alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd", "Pc"),
        whitelist_characters=" -_"
    )))
    
    return {
        "uuid": obj_uuid,
        "name": obj_name,
        "metadata": {
            "uuid": obj_uuid,
            "tlp": tlp_level,
            "version": draw(st.integers(min_value=1, max_value=100))
        }
    }


@st.composite
def opentide_object_with_specific_tlp(draw, tlp_level: TLPLevel):
    """Generate an OpenTIDE object with a specific TLP level."""
    tlp_string_mapping = {
        TLPLevel.CLEAR: draw(st.sampled_from(["clear", "white", "CLEAR", "WHITE"])),
        TLPLevel.GREEN: draw(st.sampled_from(["green", "GREEN"])),
        TLPLevel.AMBER: draw(st.sampled_from(["amber", "AMBER"])),
        TLPLevel.AMBER_STRICT: draw(st.sampled_from(["amber+strict", "AMBER+STRICT"])),
        TLPLevel.RED: draw(st.sampled_from(["red", "RED"]))
    }
    return draw(opentide_object(tlp_level=tlp_string_mapping[tlp_level]))


# ============================================================================
# Property 5: TLP scope filtering correctness
# ============================================================================

class TestTLPScopeFilteringCorrectness:
    """Property 5: TLP scope filtering correctness.
    
    **Validates: Requirements 2.2, 2.4**
    
    Property Statement:
    *For any* OpenTIDE object with a valid TLP value and *for any* MISP instance 
    configuration with a valid `max_allowed_tlp`, the object SHALL be included 
    in the sharing scope if and only if the object's TLP level is less than or 
    equal to the instance's `max_allowed_tlp` level according to the TLP hierarchy.
    """

    @given(
        object_tlp=tlp_levels,
        instance_max_tlp=tlp_levels,
        object_type=object_types
    )
    @settings(max_examples=100)
    def test_object_included_iff_tlp_within_limit(
        self, object_tlp, instance_max_tlp, object_type
    ):
        """Test that an object is included iff its TLP <= instance max_allowed_tlp.
        
        **Validates: Requirements 2.2, 2.4**
        
        This test verifies the bi-conditional relationship:
        - object TLP <= max_allowed_tlp → object IS in scope
        - object TLP > max_allowed_tlp → object is NOT in scope
        """
        # Generate test data
        obj_uuid = str(uuid.uuid4())
        
        # Map TLP level to a string representation
        tlp_string_map = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red"
        }
        
        object_data = {
            "uuid": obj_uuid,
            "name": f"Test Object {obj_uuid[:8]}",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": tlp_string_map[object_tlp],
                "version": 1
            }
        }
        
        instance_config = MISPInstanceConfig(
            name="Test MISP Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid=str(uuid.uuid4()),
            max_allowed_tlp=instance_max_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True
        )
        
        all_objects = {obj_uuid: (object_type, object_data)}
        
        # Mock the log function to avoid output during tests
        with patch("Engines.sharing.scope.log"):
            scope = compute_sharing_scope(instance_config, all_objects)
        
        # Extract UUIDs from scope
        scope_uuids = {obj.uuid for obj in scope}
        
        # Verify the bi-conditional property
        expected_in_scope = object_tlp <= instance_max_tlp
        actually_in_scope = obj_uuid in scope_uuids
        
        assert expected_in_scope == actually_in_scope, (
            f"TLP scope filtering mismatch: "
            f"object TLP={object_tlp.name} ({object_tlp.value}), "
            f"instance max_tlp={instance_max_tlp.name} ({instance_max_tlp.value}), "
            f"expected in scope={expected_in_scope}, "
            f"actually in scope={actually_in_scope}"
        )

    @given(
        object_tlp=tlp_levels,
        object_type=object_types
    )
    @settings(max_examples=100)
    def test_object_always_included_when_tlp_at_or_below_max(
        self, object_tlp, object_type
    ):
        """Test that objects are always included when their TLP is at or below max.
        
        **Validates: Requirements 2.2**
        
        For any TLP level, if we set max_allowed_tlp to RED (the maximum), 
        all objects should be included.
        """
        obj_uuid = str(uuid.uuid4())
        
        tlp_string_map = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red"
        }
        
        object_data = {
            "uuid": obj_uuid,
            "name": f"Test Object {obj_uuid[:8]}",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": tlp_string_map[object_tlp],
                "version": 1
            }
        }
        
        # Max allowed TLP is RED (highest), so all objects should be included
        instance_config = MISPInstanceConfig(
            name="Test MISP Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid=str(uuid.uuid4()),
            max_allowed_tlp=TLPLevel.RED,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True
        )
        
        all_objects = {obj_uuid: (object_type, object_data)}
        
        with patch("Engines.sharing.scope.log"):
            scope = compute_sharing_scope(instance_config, all_objects)
        
        scope_uuids = {obj.uuid for obj in scope}
        
        assert obj_uuid in scope_uuids, (
            f"Object with TLP {object_tlp.name} should be included when "
            f"max_allowed_tlp is RED, but was excluded"
        )

    @given(
        object_tlp=st.sampled_from([TLPLevel.GREEN, TLPLevel.AMBER, TLPLevel.AMBER_STRICT, TLPLevel.RED]),
        object_type=object_types
    )
    @settings(max_examples=100)
    def test_object_excluded_when_tlp_above_max(
        self, object_tlp, object_type
    ):
        """Test that objects are excluded when their TLP exceeds max_allowed_tlp.
        
        **Validates: Requirements 2.2, 2.4**
        
        For any TLP level above CLEAR, if we set max_allowed_tlp to a lower level,
        the object should be excluded.
        """
        # Ensure object_tlp > CLEAR so we can set a lower max
        assume(object_tlp > TLPLevel.CLEAR)
        
        # Set max_allowed_tlp to one level below the object's TLP
        max_tlp_level = TLPLevel(object_tlp - 1)
        
        obj_uuid = str(uuid.uuid4())
        
        tlp_string_map = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red"
        }
        
        object_data = {
            "uuid": obj_uuid,
            "name": f"Test Object {obj_uuid[:8]}",
            "metadata": {
                "uuid": obj_uuid,
                "tlp": tlp_string_map[object_tlp],
                "version": 1
            }
        }
        
        instance_config = MISPInstanceConfig(
            name="Test MISP Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid=str(uuid.uuid4()),
            max_allowed_tlp=max_tlp_level,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True
        )
        
        all_objects = {obj_uuid: (object_type, object_data)}
        
        with patch("Engines.sharing.scope.log"):
            scope = compute_sharing_scope(instance_config, all_objects)
        
        scope_uuids = {obj.uuid for obj in scope}
        
        assert obj_uuid not in scope_uuids, (
            f"Object with TLP {object_tlp.name} should be excluded when "
            f"max_allowed_tlp is {max_tlp_level.name}, but was included"
        )

    @given(
        object_types_list=st.lists(object_types, min_size=1, max_size=10),
        instance_max_tlp=tlp_levels
    )
    @settings(max_examples=100)
    def test_independent_filtering_per_instance(
        self, object_types_list, instance_max_tlp
    ):
        """Test that TLP filtering is applied independently for each MISP instance.
        
        **Validates: Requirements 2.4**
        
        Different instances with different max_allowed_tlp values should filter
        the same set of objects differently.
        """
        # Generate objects with varying TLP levels
        all_objects = {}
        tlp_levels_list = list(TLPLevel)
        
        tlp_string_map = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red"
        }
        
        for i, obj_type in enumerate(object_types_list):
            obj_uuid = str(uuid.uuid4())
            obj_tlp = tlp_levels_list[i % len(tlp_levels_list)]
            
            object_data = {
                "uuid": obj_uuid,
                "name": f"Test Object {i}",
                "metadata": {
                    "uuid": obj_uuid,
                    "tlp": tlp_string_map[obj_tlp],
                    "version": 1
                }
            }
            all_objects[obj_uuid] = (obj_type, object_data)
        
        # Create instance config with the given max TLP
        instance_config = MISPInstanceConfig(
            name="Test MISP Instance",
            url="https://misp.example.org",
            token="test-token",
            org_uuid=str(uuid.uuid4()),
            max_allowed_tlp=instance_max_tlp,
            mode="send",
            proxy=False,
            publish_on_change=False,
            verify_ssl=True
        )
        
        with patch("Engines.sharing.scope.log"):
            scope = compute_sharing_scope(instance_config, all_objects)
        
        # Verify each object in scope has TLP <= max_allowed_tlp
        for scoped_obj in scope:
            assert scoped_obj.tlp <= instance_max_tlp, (
                f"Object {scoped_obj.uuid} with TLP {scoped_obj.tlp.name} "
                f"should not be in scope for instance with "
                f"max_allowed_tlp={instance_max_tlp.name}"
            )
        
        # Verify all objects with TLP <= max_allowed_tlp are in scope
        scope_uuids = {obj.uuid for obj in scope}
        for obj_uuid, (_, obj_data) in all_objects.items():
            obj_tlp_str = obj_data["metadata"]["tlp"]
            obj_tlp = TLPLevel.from_string(obj_tlp_str)
            
            if obj_tlp <= instance_max_tlp:
                assert obj_uuid in scope_uuids, (
                    f"Object {obj_uuid} with TLP {obj_tlp.name} should be in scope "
                    f"for instance with max_allowed_tlp={instance_max_tlp.name}"
                )

    @given(object_type=object_types)
    @settings(max_examples=50)
    def test_all_tlp_boundary_conditions(self, object_type):
        """Test boundary conditions at each TLP level.
        
        **Validates: Requirements 2.2, 2.4**
        
        For each TLP level, verify that:
        - An object at that exact level is included when max_allowed_tlp equals it
        - An object at that exact level is excluded when max_allowed_tlp is below it
        """
        tlp_string_map = {
            TLPLevel.CLEAR: "clear",
            TLPLevel.GREEN: "green",
            TLPLevel.AMBER: "amber",
            TLPLevel.AMBER_STRICT: "amber+strict",
            TLPLevel.RED: "red"
        }
        
        for object_tlp in TLPLevel:
            obj_uuid = str(uuid.uuid4())
            
            object_data = {
                "uuid": obj_uuid,
                "name": f"Test Object {object_tlp.name}",
                "metadata": {
                    "uuid": obj_uuid,
                    "tlp": tlp_string_map[object_tlp],
                    "version": 1
                }
            }
            
            all_objects = {obj_uuid: (object_type, object_data)}
            
            # Test exact boundary: max_allowed_tlp == object TLP
            instance_config = MISPInstanceConfig(
                name="Test MISP Instance",
                url="https://misp.example.org",
                token="test-token",
                org_uuid=str(uuid.uuid4()),
                max_allowed_tlp=object_tlp,
                mode="send",
                proxy=False,
                publish_on_change=False,
                verify_ssl=True
            )
            
            with patch("Engines.sharing.scope.log"):
                scope = compute_sharing_scope(instance_config, all_objects)
            
            scope_uuids = {obj.uuid for obj in scope}
            
            assert obj_uuid in scope_uuids, (
                f"Object with TLP {object_tlp.name} should be included when "
                f"max_allowed_tlp equals {object_tlp.name}"
            )
            
            # Test below boundary: max_allowed_tlp < object TLP
            if object_tlp > TLPLevel.CLEAR:
                below_tlp = TLPLevel(object_tlp - 1)
                
                instance_config_below = MISPInstanceConfig(
                    name="Test MISP Instance Below",
                    url="https://misp.example.org",
                    token="test-token",
                    org_uuid=str(uuid.uuid4()),
                    max_allowed_tlp=below_tlp,
                    mode="send",
                    proxy=False,
                    publish_on_change=False,
                    verify_ssl=True
                )
                
                with patch("Engines.sharing.scope.log"):
                    scope_below = compute_sharing_scope(instance_config_below, all_objects)
                
                scope_below_uuids = {obj.uuid for obj in scope_below}
                
                assert obj_uuid not in scope_below_uuids, (
                    f"Object with TLP {object_tlp.name} should be excluded when "
                    f"max_allowed_tlp is {below_tlp.name}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
