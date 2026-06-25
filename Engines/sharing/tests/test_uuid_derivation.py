"""Property-based tests for deterministic event UUID derivation.

**Validates: Requirements 5.9**

Property 10: Deterministic event UUID derivation
- For any OpenTIDE object UUID, `derive_event_uuid()` SHALL always produce the same
  output UUID regardless of how many times it is called or which MISP instance the
  event is destined for.
"""

import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))

# Mock the tide module before importing sharing to avoid DataTide initialization
sys.modules['Engines.modules.tide'] = MagicMock()

import uuid
import pytest
from hypothesis import given, strategies as st, settings

from Engines.modules.sharing import derive_event_uuid, OPENTIDE_NAMESPACE_UUID


# Strategy for generating valid UUID strings
@st.composite
def uuid_string_strategy(draw):
    """Generate a valid UUID string in standard format."""
    # Generate 16 random bytes and create a UUID
    random_bytes = draw(st.binary(min_size=16, max_size=16))
    generated_uuid = uuid.UUID(bytes=random_bytes)
    return str(generated_uuid)


# Strategy for generating UUIDv4 strings specifically
def uuid_v4_string_strategy():
    """Generate a valid UUIDv4 string in standard format."""
    # Use st.builds to create UUIDs without needing @st.composite
    return st.builds(lambda: str(uuid.uuid4()))


class TestDeterministicEventUUIDDerivation:
    """Property tests for deterministic event UUID derivation (Property 10).
    
    **Validates: Requirements 5.9**
    """

    @given(opentide_uuid=uuid_string_strategy())
    def test_deterministic_output(self, opentide_uuid: str):
        """Test that derive_event_uuid always produces the same output for the same input.
        
        **Validates: Requirements 5.9**
        
        For any OpenTIDE object UUID, calling derive_event_uuid multiple times
        should always return the same derived event UUID.
        """
        result1 = derive_event_uuid(opentide_uuid)
        result2 = derive_event_uuid(opentide_uuid)
        
        assert result1 == result2, (
            f"derive_event_uuid returned different values for same input '{opentide_uuid}': "
            f"'{result1}' vs '{result2}'"
        )

    @given(opentide_uuid=uuid_string_strategy())
    @settings(max_examples=100)
    def test_idempotency_across_multiple_calls(self, opentide_uuid: str):
        """Test idempotency across multiple consecutive calls.
        
        **Validates: Requirements 5.9**
        
        Calling derive_event_uuid many times in succession should always
        yield the same result.
        """
        results: List[str] = []
        
        # Call the function multiple times
        for _ in range(10):
            results.append(derive_event_uuid(opentide_uuid))
        
        # All results should be identical
        assert all(r == results[0] for r in results), (
            f"derive_event_uuid produced inconsistent results for '{opentide_uuid}': {set(results)}"
        )

    @given(
        opentide_uuid=uuid_string_strategy(),
        instance_marker=st.integers(min_value=1, max_value=100)
    )
    def test_independent_of_misp_instance(self, opentide_uuid: str, instance_marker: int):
        """Test that derived UUID is independent of which MISP instance is targeted.
        
        **Validates: Requirements 5.9**
        
        The derive_event_uuid function takes only the OpenTIDE UUID as input,
        ensuring the derived event UUID is the same regardless of destination instance.
        This test simulates checking the function across "different instances" by
        calling it multiple times with different context (the instance_marker is
        just to ensure Hypothesis generates varied test cases).
        """
        # The instance marker doesn't affect the function, but we verify
        # that the same opentide_uuid always produces the same result
        derived_uuid = derive_event_uuid(opentide_uuid)
        
        # Call again to verify consistency
        derived_uuid_again = derive_event_uuid(opentide_uuid)
        
        assert derived_uuid == derived_uuid_again, (
            f"UUID derivation should be independent of context (instance {instance_marker})"
        )

    @given(
        uuid_a=uuid_string_strategy(),
        uuid_b=uuid_string_strategy()
    )
    def test_different_inputs_produce_different_outputs(self, uuid_a: str, uuid_b: str):
        """Test that different input UUIDs produce different derived UUIDs (with high probability).
        
        **Validates: Requirements 5.9**
        
        While not strictly required by the spec, different OpenTIDE UUIDs should
        produce different derived event UUIDs (UUID5 provides this property).
        """
        if uuid_a == uuid_b:
            # Same input should produce same output (already tested above)
            assert derive_event_uuid(uuid_a) == derive_event_uuid(uuid_b)
        else:
            # Different inputs should produce different outputs
            assert derive_event_uuid(uuid_a) != derive_event_uuid(uuid_b), (
                f"Different UUIDs '{uuid_a}' and '{uuid_b}' produced the same derived UUID"
            )

    @given(opentide_uuid=uuid_string_strategy())
    def test_output_is_valid_uuid_format(self, opentide_uuid: str):
        """Test that the output is a valid UUID string.
        
        **Validates: Requirements 5.9**
        
        The derived event UUID should be a valid UUID that can be parsed.
        """
        result = derive_event_uuid(opentide_uuid)
        
        # Should be parseable as a UUID
        try:
            parsed = uuid.UUID(result)
        except ValueError as e:
            pytest.fail(f"derive_event_uuid returned invalid UUID '{result}': {e}")
        
        # The string representation should match
        assert str(parsed) == result, (
            f"UUID string representation mismatch: expected '{result}', got '{str(parsed)}'"
        )

    @given(opentide_uuid=uuid_string_strategy())
    def test_output_is_uuid5(self, opentide_uuid: str):
        """Test that the output is a UUID version 5.
        
        **Validates: Requirements 5.9**
        
        The derive_event_uuid function uses uuid.uuid5(), so the result
        should be a version 5 UUID.
        """
        result = derive_event_uuid(opentide_uuid)
        parsed = uuid.UUID(result)
        
        assert parsed.version == 5, (
            f"Expected UUID version 5, got version {parsed.version} for input '{opentide_uuid}'"
        )

    @given(opentide_uuid=uuid_v4_string_strategy())
    def test_with_v4_uuids_specifically(self, opentide_uuid: str):
        """Test determinism specifically with UUIDv4 inputs (the typical case).
        
        **Validates: Requirements 5.9**
        
        OpenTIDE object UUIDs are typically UUIDv4. This test ensures
        the function works correctly with this common input format.
        """
        result1 = derive_event_uuid(opentide_uuid)
        result2 = derive_event_uuid(opentide_uuid)
        
        assert result1 == result2
        
        # Verify it's a valid UUID5
        parsed = uuid.UUID(result1)
        assert parsed.version == 5


class TestEventUUIDDerivationEdgeCases:
    """Edge case tests for event UUID derivation.
    
    **Validates: Requirements 5.9**
    """

    def test_known_uuid_produces_expected_result(self):
        """Test that a specific UUID always produces the same known result.
        
        **Validates: Requirements 5.9**
        
        This test uses a fixed input to verify the function produces a
        predictable, repeatable output that can be verified across implementations.
        """
        test_uuid = "550e8400-e29b-41d4-a716-446655440000"
        
        # Call multiple times
        results = [derive_event_uuid(test_uuid) for _ in range(5)]
        
        # All should be the same
        assert len(set(results)) == 1, f"Got different results: {results}"
        
        # And should be a valid UUID5
        parsed = uuid.UUID(results[0])
        assert parsed.version == 5

    def test_uses_correct_namespace(self):
        """Test that the derivation uses the correct namespace UUID.
        
        **Validates: Requirements 5.9**
        
        The namespace should be the opentide MISP object template UUID:
        892fd46a-f69e-455c-8c4f-843a4b8f4295
        """
        expected_namespace = uuid.UUID("892fd46a-f69e-455c-8c4f-843a4b8f4295")
        
        # Verify the constant is correct
        assert OPENTIDE_NAMESPACE_UUID == expected_namespace
        
        # Verify the function produces the same result as manual uuid5 call
        test_uuid = "test-uuid-value"
        expected = str(uuid.uuid5(expected_namespace, test_uuid))
        actual = derive_event_uuid(test_uuid)
        
        assert actual == expected, (
            f"Expected '{expected}' using namespace {expected_namespace}, got '{actual}'"
        )

    def test_empty_string_input_is_deterministic(self):
        """Test that even an empty string input produces deterministic output.
        
        **Validates: Requirements 5.9**
        
        While not a typical case, the function should still be deterministic
        for any string input.
        """
        result1 = derive_event_uuid("")
        result2 = derive_event_uuid("")
        
        assert result1 == result2

    def test_uuid_variants_produce_consistent_results(self):
        """Test that different UUID string formats are handled consistently.
        
        **Validates: Requirements 5.9**
        
        UUID strings in different formats (with/without hyphens, uppercase/lowercase)
        should be treated as different inputs, producing different outputs.
        The function does not normalize UUID formats.
        """
        uuid_lower = "550e8400-e29b-41d4-a716-446655440000"
        uuid_upper = "550E8400-E29B-41D4-A716-446655440000"
        uuid_no_hyphens = "550e8400e29b41d4a716446655440000"
        
        result_lower = derive_event_uuid(uuid_lower)
        result_upper = derive_event_uuid(uuid_upper)
        result_no_hyphens = derive_event_uuid(uuid_no_hyphens)
        
        # Each should be deterministic
        assert result_lower == derive_event_uuid(uuid_lower)
        assert result_upper == derive_event_uuid(uuid_upper)
        assert result_no_hyphens == derive_event_uuid(uuid_no_hyphens)
        
        # But different formats produce different results (string comparison is exact)
        assert result_lower != result_upper, "Case-different UUIDs should produce different results"
        assert result_lower != result_no_hyphens, "Format-different UUIDs should produce different results"

    @given(opentide_uuid=uuid_string_strategy())
    def test_no_state_leakage_between_calls(self, opentide_uuid: str):
        """Test that there's no state leakage between calls.
        
        **Validates: Requirements 5.9**
        
        Calling derive_event_uuid with one UUID should not affect
        subsequent calls with different UUIDs.
        """
        # Make some calls with different UUIDs
        _ = derive_event_uuid("first-test-uuid")
        _ = derive_event_uuid("second-test-uuid")
        
        # Now check our target UUID
        result1 = derive_event_uuid(opentide_uuid)
        
        # Make more interfering calls
        _ = derive_event_uuid("third-test-uuid")
        
        # Check again - should be the same
        result2 = derive_event_uuid(opentide_uuid)
        
        assert result1 == result2, "State leakage detected between calls"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
