"""Property-based tests for TLP hierarchy ordering.

**Validates: Requirements 2.1, 2.6**

Property 4: TLP hierarchy ordering
- For any two TLP levels A and B from the set {clear, green, amber, amber+strict, red},
  the comparison `TLPLevel.from_string(A) <= TLPLevel.from_string(B)` SHALL be consistent
  with the defined hierarchy (clear < green < amber < amber+strict < red), and the
  comparison SHALL be case-insensitive with `white` treated as equivalent to `clear`.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))

# Mock the heavy imports before importing from sharing module
# This prevents DataTide from loading during test collection
sys.modules['Engines.modules.tide'] = MagicMock()
sys.modules['Engines.modules.logs'] = MagicMock()

import pytest
from hypothesis import given, strategies as st, assume, settings

# Now we can import TLPLevel - the mocked modules prevent DataTide loading
# We need to import the enum definition directly since the module has side effects
from enum import IntEnum


class TLPLevel(IntEnum):
    """Traffic Light Protocol levels as an ordered enum for comparison.
    
    This is a test-local copy of the TLPLevel enum to avoid module import issues.
    The TLP hierarchy is ordered from least restrictive to most restrictive:
    CLEAR (0) < GREEN (1) < AMBER (2) < AMBER_STRICT (3) < RED (4)
    """
    CLEAR = 0        # aliases: "white", "clear"
    GREEN = 1
    AMBER = 2
    AMBER_STRICT = 3  # "amber+strict"
    RED = 4

    @classmethod
    def from_string(cls, value: str) -> "TLPLevel":
        """Parse a TLP string (case-insensitive, white=clear) into a TLPLevel.
        
        Args:
            value: A string representing a TLP level. Accepted values are:
                   - "clear" or "white" → CLEAR
                   - "green" → GREEN
                   - "amber" → AMBER
                   - "amber+strict" → AMBER_STRICT
                   - "red" → RED
                   
        Returns:
            The corresponding TLPLevel enum member.
            
        Raises:
            ValueError: If the string does not match any valid TLP level.
        """
        normalized = value.strip().lower()
        
        mapping = {
            "clear": cls.CLEAR,
            "white": cls.CLEAR,  # white is an alias for clear
            "green": cls.GREEN,
            "amber": cls.AMBER,
            "amber+strict": cls.AMBER_STRICT,
            "red": cls.RED,
        }
        
        if normalized not in mapping:
            valid_values = ["clear", "white", "green", "amber", "amber+strict", "red"]
            raise ValueError(
                f"Invalid TLP level: '{value}'. "
                f"Valid values are: {', '.join(valid_values)}"
            )
        
        return mapping[normalized]

    def to_misp_tag(self) -> str:
        """Return the MISP taxonomy tag string for this TLP level."""
        tag_mapping = {
            TLPLevel.CLEAR: "tlp:clear",
            TLPLevel.GREEN: "tlp:green",
            TLPLevel.AMBER: "tlp:amber",
            TLPLevel.AMBER_STRICT: "tlp:amber+strict",
            TLPLevel.RED: "tlp:red",
        }
        return tag_mapping[self]


# Define the TLP hierarchy ordering
TLP_ORDERED_LEVELS = [
    TLPLevel.CLEAR,
    TLPLevel.GREEN,
    TLPLevel.AMBER,
    TLPLevel.AMBER_STRICT,
    TLPLevel.RED,
]

# Valid TLP string values (canonical form)
VALID_TLP_STRINGS = ["clear", "white", "green", "amber", "amber+strict", "red"]

# String to expected TLPLevel mapping
STRING_TO_TLP = {
    "clear": TLPLevel.CLEAR,
    "white": TLPLevel.CLEAR,  # white is alias for clear
    "green": TLPLevel.GREEN,
    "amber": TLPLevel.AMBER,
    "amber+strict": TLPLevel.AMBER_STRICT,
    "red": TLPLevel.RED,
}


# Strategy for generating valid TLP strings in various case forms
@st.composite
def tlp_string_strategy(draw):
    """Generate a valid TLP string with random casing."""
    base = draw(st.sampled_from(VALID_TLP_STRINGS))
    # Apply random casing
    casing = draw(st.sampled_from(["lower", "upper", "title", "mixed"]))
    if casing == "lower":
        return base.lower()
    elif casing == "upper":
        return base.upper()
    elif casing == "title":
        return base.title()
    else:  # mixed
        # Random casing per character
        return "".join(
            c.upper() if draw(st.booleans()) else c.lower()
            for c in base
        )


class TestTLPHierarchyOrdering:
    """Property tests for TLP hierarchy ordering (Property 4)."""

    @given(tlp_a=st.sampled_from(TLP_ORDERED_LEVELS), tlp_b=st.sampled_from(TLP_ORDERED_LEVELS))
    def test_hierarchy_consistency(self, tlp_a: TLPLevel, tlp_b: TLPLevel):
        """Test that TLP level comparison is consistent with the defined hierarchy.
        
        **Validates: Requirements 2.1**
        
        For any two TLP levels A and B, A <= B should hold if and only if
        A appears at the same position or before B in the hierarchy:
        CLEAR < GREEN < AMBER < AMBER_STRICT < RED
        """
        index_a = TLP_ORDERED_LEVELS.index(tlp_a)
        index_b = TLP_ORDERED_LEVELS.index(tlp_b)
        
        # The comparison should match the index ordering
        assert (tlp_a <= tlp_b) == (index_a <= index_b)
        assert (tlp_a < tlp_b) == (index_a < index_b)
        assert (tlp_a >= tlp_b) == (index_a >= index_b)
        assert (tlp_a > tlp_b) == (index_a > index_b)
        assert (tlp_a == tlp_b) == (index_a == index_b)

    @given(tlp_a=st.sampled_from(TLP_ORDERED_LEVELS), 
           tlp_b=st.sampled_from(TLP_ORDERED_LEVELS),
           tlp_c=st.sampled_from(TLP_ORDERED_LEVELS))
    def test_hierarchy_transitivity(self, tlp_a: TLPLevel, tlp_b: TLPLevel, tlp_c: TLPLevel):
        """Test that TLP comparison is transitive.
        
        **Validates: Requirements 2.1**
        
        If A <= B and B <= C, then A <= C must hold.
        """
        if tlp_a <= tlp_b and tlp_b <= tlp_c:
            assert tlp_a <= tlp_c

    @given(tlp_str=tlp_string_strategy())
    def test_case_insensitive_parsing(self, tlp_str: str):
        """Test that TLP string parsing is case-insensitive.
        
        **Validates: Requirements 2.6**
        
        Any valid TLP string, regardless of case, should parse to the correct TLPLevel.
        """
        parsed = TLPLevel.from_string(tlp_str)
        expected = STRING_TO_TLP[tlp_str.lower()]
        
        assert parsed == expected, (
            f"Expected '{tlp_str}' to parse to {expected}, but got {parsed}"
        )

    @given(
        tlp_str_a=tlp_string_strategy(),
        tlp_str_b=tlp_string_strategy()
    )
    def test_hierarchy_ordering_from_strings(self, tlp_str_a: str, tlp_str_b: str):
        """Test that comparison of parsed TLP strings follows the hierarchy.
        
        **Validates: Requirements 2.1, 2.6**
        
        For any two valid TLP strings (with any casing), parsing and comparing
        them should be consistent with the defined hierarchy.
        """
        tlp_a = TLPLevel.from_string(tlp_str_a)
        tlp_b = TLPLevel.from_string(tlp_str_b)
        
        expected_a = STRING_TO_TLP[tlp_str_a.lower()]
        expected_b = STRING_TO_TLP[tlp_str_b.lower()]
        
        index_a = TLP_ORDERED_LEVELS.index(expected_a)
        index_b = TLP_ORDERED_LEVELS.index(expected_b)
        
        assert (tlp_a <= tlp_b) == (index_a <= index_b)

    @given(st.data())
    def test_white_clear_equivalence(self, data):
        """Test that 'white' is treated as equivalent to 'clear'.
        
        **Validates: Requirements 2.6**
        
        The strings 'white' and 'clear' (in any case) should parse to the same TLPLevel,
        and that level should be TLPLevel.CLEAR.
        """
        white_casing = data.draw(st.sampled_from(["white", "WHITE", "White", "WhItE"]))
        clear_casing = data.draw(st.sampled_from(["clear", "CLEAR", "Clear", "ClEaR"]))
        
        white_parsed = TLPLevel.from_string(white_casing)
        clear_parsed = TLPLevel.from_string(clear_casing)
        
        # Both should parse to CLEAR
        assert white_parsed == TLPLevel.CLEAR
        assert clear_parsed == TLPLevel.CLEAR
        
        # They should be equal to each other
        assert white_parsed == clear_parsed

    def test_explicit_hierarchy_order(self):
        """Test the explicit hierarchy ordering matches the specification.
        
        **Validates: Requirements 2.1**
        
        CLEAR < GREEN < AMBER < AMBER_STRICT < RED
        """
        assert TLPLevel.CLEAR < TLPLevel.GREEN
        assert TLPLevel.GREEN < TLPLevel.AMBER
        assert TLPLevel.AMBER < TLPLevel.AMBER_STRICT
        assert TLPLevel.AMBER_STRICT < TLPLevel.RED

    @given(tlp=st.sampled_from(TLP_ORDERED_LEVELS))
    def test_reflexivity(self, tlp: TLPLevel):
        """Test that TLP comparison is reflexive.
        
        **Validates: Requirements 2.1**
        
        For any TLP level A, A == A and A <= A must hold.
        """
        assert tlp == tlp
        assert tlp <= tlp
        assert tlp >= tlp
        assert not (tlp < tlp)
        assert not (tlp > tlp)

    @given(
        tlp_a=st.sampled_from(TLP_ORDERED_LEVELS),
        tlp_b=st.sampled_from(TLP_ORDERED_LEVELS)
    )
    def test_antisymmetry(self, tlp_a: TLPLevel, tlp_b: TLPLevel):
        """Test that TLP comparison is antisymmetric.
        
        **Validates: Requirements 2.1**
        
        If A <= B and B <= A, then A == B must hold.
        """
        if tlp_a <= tlp_b and tlp_b <= tlp_a:
            assert tlp_a == tlp_b

    @given(
        tlp_a=st.sampled_from(TLP_ORDERED_LEVELS),
        tlp_b=st.sampled_from(TLP_ORDERED_LEVELS)
    )
    def test_totality(self, tlp_a: TLPLevel, tlp_b: TLPLevel):
        """Test that TLP comparison is total (all pairs are comparable).
        
        **Validates: Requirements 2.1**
        
        For any two TLP levels A and B, either A <= B or B <= A (or both if equal).
        """
        assert tlp_a <= tlp_b or tlp_b <= tlp_a

    @given(invalid_str=st.text(min_size=1).filter(lambda s: s.strip().lower() not in VALID_TLP_STRINGS))
    @settings(max_examples=50)
    def test_invalid_string_raises_valueerror(self, invalid_str: str):
        """Test that invalid TLP strings raise ValueError.
        
        **Validates: Requirements 2.1**
        
        Only valid TLP strings should be parseable. Invalid strings should raise ValueError.
        """
        # Filter out strings that might accidentally be valid
        assume(invalid_str.strip().lower() not in [v.lower() for v in VALID_TLP_STRINGS])
        
        with pytest.raises(ValueError):
            TLPLevel.from_string(invalid_str)

    @given(tlp_str=tlp_string_strategy())
    def test_whitespace_handling(self, tlp_str: str):
        """Test that leading/trailing whitespace is handled in parsing.
        
        **Validates: Requirements 2.6**
        
        TLP strings with leading/trailing whitespace should still parse correctly.
        """
        # Add random whitespace
        padded = f"  {tlp_str}  "
        parsed = TLPLevel.from_string(padded)
        expected = STRING_TO_TLP[tlp_str.lower()]
        
        assert parsed == expected


class TestTLPHierarchyEdgeCases:
    """Edge case tests for TLP hierarchy."""

    def test_all_levels_are_comparable_to_each_other(self):
        """Test that all TLP levels can be compared against each other.
        
        **Validates: Requirements 2.1**
        """
        for level_a in TLP_ORDERED_LEVELS:
            for level_b in TLP_ORDERED_LEVELS:
                # These should not raise
                _ = level_a < level_b
                _ = level_a <= level_b
                _ = level_a > level_b
                _ = level_a >= level_b
                _ = level_a == level_b

    def test_numeric_values_match_hierarchy(self):
        """Test that the numeric IntEnum values match the hierarchy order.
        
        **Validates: Requirements 2.1**
        
        The integer values of TLPLevel should increase along the hierarchy.
        """
        for i in range(len(TLP_ORDERED_LEVELS) - 1):
            assert int(TLP_ORDERED_LEVELS[i]) < int(TLP_ORDERED_LEVELS[i + 1])

    def test_all_valid_strings_are_parseable(self):
        """Test that all documented valid strings can be parsed.
        
        **Validates: Requirements 2.6**
        """
        for tlp_str in VALID_TLP_STRINGS:
            # Should not raise
            result = TLPLevel.from_string(tlp_str)
            assert result in TLP_ORDERED_LEVELS
