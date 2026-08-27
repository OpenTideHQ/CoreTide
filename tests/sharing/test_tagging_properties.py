"""Property-based tests for MISP event tagging.

This module tests:
- Property 11 (TLP tag format correctness)
- Property 12 (ATT&CK technique tag completeness)
- Property 13 (Threat actor galaxy attachment priority)

**Validates: Requirements 6.1, 6.2, 6.3, 6.4**
"""

import re
import sys
import uuid
from unittest.mock import patch, MagicMock

import git
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

# Add project root to path for imports
sys.path.insert(0, str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.sharing import TLPLevel
from Engines.sharing.tagging import build_tlp_tag, build_attack_tags, build_actor_galaxies


# Strategies for generating test data
tlp_levels = st.sampled_from(list(TLPLevel))

# Strategy for generating valid ATT&CK technique identifiers
# ATT&CK technique IDs follow the pattern: TXXXX or TXXXX.YYY
attack_technique_id = st.from_regex(r'^T[0-9]{4}(\.[0-9]{3})?$', fullmatch=True)

# Strategy for generating lists of technique identifiers (including duplicates)
attack_technique_list = st.lists(attack_technique_id, min_size=0, max_size=20)

# Strategy for generating valid UUIDs
valid_uuid = st.uuids().map(str)


# ============================================================================
# Property 11: TLP tag format correctness
# ============================================================================

class TestTLPTagFormatCorrectness:
    """Property 11: TLP tag format correctness.
    
    **Validates: Requirements 6.1**
    
    Property Statement:
    *For any* valid TLP level, the MISP tag returned by build_tlp_tag() SHALL 
    match the pattern `tlp:<level>` where <level> is the lowercase TLP level 
    identifier (clear, green, amber, amber+strict, red).
    """

    # Expected tag mapping for verification
    EXPECTED_TAGS = {
        TLPLevel.CLEAR: "tlp:clear",
        TLPLevel.GREEN: "tlp:green",
        TLPLevel.AMBER: "tlp:amber",
        TLPLevel.AMBER_STRICT: "tlp:amber+strict",
        TLPLevel.RED: "tlp:red",
    }

    @given(tlp_level=tlp_levels)
    @settings(max_examples=100)
    def test_tag_matches_tlp_prefix_pattern(self, tlp_level):
        """Test that all TLP tags start with 'tlp:' prefix.
        
        **Validates: Requirements 6.1**
        
        This test verifies that for any valid TLP level, the resulting tag
        follows the MISP taxonomy format starting with 'tlp:'.
        """
        tag = build_tlp_tag(tlp_level)
        
        # Verify tag has the expected name attribute
        assert hasattr(tag, 'name'), (
            f"MISPTag should have a 'name' attribute, got: {type(tag)}"
        )
        
        # Verify tag name starts with 'tlp:'
        assert tag.name.startswith("tlp:"), (
            f"TLP tag for {tlp_level.name} should start with 'tlp:', "
            f"got: '{tag.name}'"
        )

    @given(tlp_level=tlp_levels)
    @settings(max_examples=100)
    def test_tag_matches_exact_format(self, tlp_level):
        """Test that TLP tags match the exact expected format.
        
        **Validates: Requirements 6.1**
        
        This test verifies that for any valid TLP level, the resulting tag
        matches the exact expected MISP taxonomy format.
        """
        tag = build_tlp_tag(tlp_level)
        expected_tag = self.EXPECTED_TAGS[tlp_level]
        
        assert tag.name == expected_tag, (
            f"TLP tag for {tlp_level.name} should be '{expected_tag}', "
            f"got: '{tag.name}'"
        )

    @given(tlp_level=tlp_levels)
    @settings(max_examples=100)
    def test_tag_follows_misp_taxonomy_pattern(self, tlp_level):
        r"""Test that TLP tags follow the MISP taxonomy pattern.
        
        **Validates: Requirements 6.1**
        
        This test verifies that the tag name matches the regex pattern
        for valid MISP TLP taxonomy tags: tlp:(clear|green|amber|amber\+strict|red)
        """
        tag = build_tlp_tag(tlp_level)
        
        # MISP TLP taxonomy pattern
        tlp_pattern = r'^tlp:(clear|green|amber|amber\+strict|red)$'
        
        assert re.match(tlp_pattern, tag.name), (
            f"TLP tag '{tag.name}' for {tlp_level.name} does not match "
            f"the expected MISP taxonomy pattern '{tlp_pattern}'"
        )

    @given(tlp_level=tlp_levels)
    @settings(max_examples=100)
    def test_tag_is_lowercase(self, tlp_level):
        """Test that TLP tags are in lowercase format.
        
        **Validates: Requirements 6.1**
        
        This test verifies that the tag name is entirely lowercase,
        as required by the MISP taxonomy format.
        """
        tag = build_tlp_tag(tlp_level)
        
        # The tag name should be lowercase (except for the + in amber+strict)
        assert tag.name == tag.name.lower(), (
            f"TLP tag for {tlp_level.name} should be lowercase, "
            f"got: '{tag.name}'"
        )

    @given(tlp_level=tlp_levels)
    @settings(max_examples=100)
    def test_tag_consistency_across_calls(self, tlp_level):
        """Test that build_tlp_tag produces consistent results.
        
        **Validates: Requirements 6.1**
        
        This test verifies that calling build_tlp_tag multiple times
        with the same TLP level always produces the same tag name.
        """
        tag1 = build_tlp_tag(tlp_level)
        tag2 = build_tlp_tag(tlp_level)
        tag3 = build_tlp_tag(tlp_level)
        
        assert tag1.name == tag2.name == tag3.name, (
            f"build_tlp_tag should produce consistent results for {tlp_level.name}, "
            f"got: '{tag1.name}', '{tag2.name}', '{tag3.name}'"
        )

    def test_all_tlp_levels_produce_valid_tags(self):
        """Test that all TLP levels produce valid tags.
        
        **Validates: Requirements 6.1**
        
        This test exhaustively verifies that every TLP level enum member
        produces a valid MISP taxonomy tag.
        """
        for tlp_level in TLPLevel:
            tag = build_tlp_tag(tlp_level)
            expected_tag = self.EXPECTED_TAGS[tlp_level]
            
            assert tag.name == expected_tag, (
                f"TLP tag for {tlp_level.name} should be '{expected_tag}', "
                f"got: '{tag.name}'"
            )

    def test_to_misp_tag_method_consistency(self):
        """Test that build_tlp_tag uses TLPLevel.to_misp_tag() correctly.
        
        **Validates: Requirements 6.1**
        
        This test verifies that build_tlp_tag produces the same result
        as directly calling TLPLevel.to_misp_tag().
        """
        for tlp_level in TLPLevel:
            tag = build_tlp_tag(tlp_level)
            direct_tag = tlp_level.to_misp_tag()
            
            assert tag.name == direct_tag, (
                f"build_tlp_tag result should match TLPLevel.to_misp_tag() "
                f"for {tlp_level.name}: '{tag.name}' != '{direct_tag}'"
            )


# ============================================================================
# Property 12: ATT&CK technique tag completeness
# ============================================================================

class TestATTACKTechniqueTagCompleteness:
    """Property 12: ATT&CK technique tag completeness.
    
    **Validates: Requirements 6.2**
    
    Property Statement:
    *For any* set of resolved ATT&CK technique identifiers returned by 
    techniques_resolver(), build_attack_tags() SHALL produce exactly one 
    MISP tag per unique resolved technique identifier.
    """

    @given(techniques=attack_technique_list, object_uuid=valid_uuid)
    @settings(max_examples=100)
    def test_one_tag_per_unique_technique(self, techniques, object_uuid):
        """Test that exactly one tag is created per unique technique.
        
        **Validates: Requirements 6.2**
        
        This test verifies that for any list of resolved techniques 
        (which may contain duplicates), the number of tags produced
        equals the number of unique techniques.
        """
        unique_techniques = set(techniques)
        
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags(object_uuid)
        
        assert len(tags) == len(unique_techniques), (
            f"Expected {len(unique_techniques)} tags for {len(unique_techniques)} "
            f"unique techniques from input {techniques}, got {len(tags)} tags"
        )

    @given(techniques=attack_technique_list, object_uuid=valid_uuid)
    @settings(max_examples=100)
    def test_all_unique_techniques_represented(self, techniques, object_uuid):
        """Test that all unique techniques are represented in the tags.
        
        **Validates: Requirements 6.2**
        
        This test verifies that every unique technique identifier in the 
        resolved list has a corresponding tag in the output.
        """
        unique_techniques = set(techniques)
        
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags(object_uuid)
        
        # Extract technique IDs from tags
        tag_technique_ids = set()
        for tag in tags:
            # Tag format: misp-galaxy:mitre-attack-pattern="TXXXX"
            match = re.search(r'"(T[0-9]{4}(?:\.[0-9]{3})?)"', tag.name)
            if match:
                tag_technique_ids.add(match.group(1))
        
        assert tag_technique_ids == unique_techniques, (
            f"Tags should represent all unique techniques. "
            f"Expected: {unique_techniques}, Got: {tag_technique_ids}"
        )

    @given(techniques=attack_technique_list, object_uuid=valid_uuid)
    @settings(max_examples=100)
    def test_no_duplicate_tags(self, techniques, object_uuid):
        """Test that no duplicate tags are produced.
        
        **Validates: Requirements 6.2**
        
        This test verifies that even when the input contains duplicate
        technique identifiers, the output contains no duplicate tags.
        """
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags(object_uuid)
        
        tag_names = [tag.name for tag in tags]
        unique_tag_names = set(tag_names)
        
        assert len(tag_names) == len(unique_tag_names), (
            f"Tags should not contain duplicates. "
            f"Got {len(tag_names)} tags but only {len(unique_tag_names)} unique: "
            f"{tag_names}"
        )

    @given(techniques=attack_technique_list, object_uuid=valid_uuid)
    @settings(max_examples=100)
    def test_tags_follow_misp_galaxy_format(self, techniques, object_uuid):
        """Test that ATT&CK tags follow the MISP galaxy format.
        
        **Validates: Requirements 6.2**
        
        This test verifies that all produced tags follow the expected
        MISP galaxy format: misp-galaxy:mitre-attack-pattern="<technique>"
        """
        # Skip if no techniques (empty list is valid per Requirement 6.6)
        assume(len(techniques) > 0)
        
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags(object_uuid)
        
        # MISP galaxy ATT&CK pattern format
        galaxy_pattern = r'^misp-galaxy:mitre-attack-pattern="T[0-9]{4}(?:\.[0-9]{3})?"$'
        
        for tag in tags:
            assert re.match(galaxy_pattern, tag.name), (
                f"Tag '{tag.name}' does not match expected MISP galaxy format "
                f"'{galaxy_pattern}'"
            )

    @given(object_uuid=valid_uuid)
    @settings(max_examples=50)
    def test_empty_techniques_returns_empty_tags(self, object_uuid):
        """Test that empty technique list produces empty tag list.
        
        **Validates: Requirements 6.2, 6.6**
        
        This test verifies that when techniques_resolver returns an empty
        list, build_attack_tags also returns an empty list (not an error).
        """
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=[]
        ):
            tags = build_attack_tags(object_uuid)
        
        assert tags == [], (
            f"Empty technique list should produce empty tag list, got: {tags}"
        )

    @given(
        techniques=st.lists(attack_technique_id, min_size=1, max_size=10),
        object_uuid=valid_uuid
    )
    @settings(max_examples=100)
    def test_tag_technique_id_matches_input(self, techniques, object_uuid):
        """Test that tag technique IDs exactly match the unique input techniques.
        
        **Validates: Requirements 6.2**
        
        This test verifies that the technique IDs embedded in the tags
        exactly match the unique input technique identifiers.
        """
        unique_techniques = set(techniques)
        
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags(object_uuid)
        
        # Extract all technique IDs from tags
        extracted_ids = set()
        for tag in tags:
            # Extract the technique ID from the tag name
            # Format: misp-galaxy:mitre-attack-pattern="TXXXX"
            start = tag.name.find('"') + 1
            end = tag.name.rfind('"')
            if start > 0 and end > start:
                extracted_ids.add(tag.name[start:end])
        
        assert extracted_ids == unique_techniques, (
            f"Extracted technique IDs should match unique input. "
            f"Input: {unique_techniques}, Extracted: {extracted_ids}"
        )

    @given(
        techniques=st.lists(attack_technique_id, min_size=1, max_size=5),
        object_uuid=valid_uuid
    )
    @settings(max_examples=50)
    def test_consistency_across_calls(self, techniques, object_uuid):
        """Test that build_attack_tags produces consistent results.
        
        **Validates: Requirements 6.2**
        
        This test verifies that calling build_attack_tags multiple times
        with the same input always produces the same tags (idempotency).
        """
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags1 = build_attack_tags(object_uuid)
            tags2 = build_attack_tags(object_uuid)
            tags3 = build_attack_tags(object_uuid)
        
        names1 = sorted([t.name for t in tags1])
        names2 = sorted([t.name for t in tags2])
        names3 = sorted([t.name for t in tags3])
        
        assert names1 == names2 == names3, (
            f"build_attack_tags should produce consistent results. "
            f"Got: {names1}, {names2}, {names3}"
        )

    def test_techniques_with_subtechniques(self):
        """Test handling of both technique and sub-technique IDs.
        
        **Validates: Requirements 6.2**
        
        This test verifies that both main techniques (TXXXX) and 
        sub-techniques (TXXXX.YYY) are handled correctly.
        """
        techniques = ["T1003", "T1003.001", "T1003.002", "T1059", "T1059.001"]
        
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags("test-uuid")
        
        # Should have one tag per unique technique (5 in this case)
        assert len(tags) == 5, (
            f"Expected 5 tags for 5 unique techniques, got {len(tags)}"
        )
        
        # Verify all IDs are represented
        tag_names = [t.name for t in tags]
        for tech_id in techniques:
            expected_pattern = f'misp-galaxy:mitre-attack-pattern="{tech_id}"'
            assert expected_pattern in tag_names, (
                f"Missing tag for technique {tech_id}"
            )

    def test_duplicate_input_produces_deduplicated_output(self):
        """Test that duplicate input techniques are deduplicated.
        
        **Validates: Requirements 6.2**
        
        This test verifies explicit deduplication behavior - input
        with duplicates should produce deduplicated output.
        """
        techniques = ["T1003", "T1003", "T1059", "T1003", "T1059"]  # 2 unique
        
        with patch(
            "Engines.sharing.tagging.techniques_resolver",
            return_value=techniques
        ):
            tags = build_attack_tags("test-uuid")
        
        assert len(tags) == 2, (
            f"Expected 2 tags for 2 unique techniques (with duplicates in input), "
            f"got {len(tags)}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ============================================================================
# Property 13: Threat actor galaxy attachment priority
# ============================================================================

# Strategies for generating actor data
actor_uuid = st.uuids().map(str)
actor_name = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters=' -_'),
    min_size=1,
    max_size=50
).map(str.strip).filter(lambda x: len(x) > 0)
attack_group_id = st.from_regex(r'^G[0-9]{4}$', fullmatch=True)


def make_misp_actor(uuid_str: str, name: str) -> dict:
    """Helper to create a MISP-stage actor dictionary."""
    return {
        "uuid": uuid_str,
        "name": name,
        "tide": {
            "vocab": {
                "stages": "misp"
            }
        }
    }


def make_attack_actor(name: str, attack_id: str = None) -> dict:
    """Helper to create an ATT&CK-stage actor dictionary."""
    actor = {
        "name": name,
        "tide": {
            "vocab": {
                "stages": "att&ck"
            }
        }
    }
    if attack_id:
        actor["id"] = attack_id
    return actor


def make_other_actor(name: str) -> dict:
    """Helper to create an actor with neither misp nor att&ck stage."""
    return {
        "name": name,
        "tide": {
            "vocab": {
                "stages": "other"
            }
        }
    }


# Strategy for generating MISP-stage actor lists
misp_actor_list = st.lists(
    st.tuples(actor_uuid, actor_name).map(lambda t: make_misp_actor(t[0], t[1])),
    min_size=0,
    max_size=5
)

# Strategy for generating ATT&CK-stage actor lists
attack_actor_list = st.lists(
    st.tuples(actor_name, attack_group_id).map(lambda t: make_attack_actor(t[0], t[1])),
    min_size=0,
    max_size=5
)


class TestThreatActorGalaxyPriority:
    """Property 13: Threat actor galaxy attachment priority.
    
    **Validates: Requirements 6.3, 6.4**
    
    Property Statement:
    *For any* TVM object with a threat.actors list:
    1. If actors with tide.vocab.stages == "misp" exist, only misp-stage actors 
       SHALL be used for galaxy resolution (Req 6.3)
    2. If NO misp-stage actors exist but att&ck-stage actors do, only att&ck-stage 
       actors SHALL be used for galaxy resolution as fallback (Req 6.4)
    3. Actor galaxies only apply to TVM objects; DOM/MDR return empty (Design spec)
    """

    @given(
        misp_actors=st.lists(
            st.tuples(actor_uuid, actor_name).map(lambda t: make_misp_actor(t[0], t[1])),
            min_size=1,
            max_size=5
        ),
        attack_actors=st.lists(
            st.tuples(actor_name, attack_group_id).map(lambda t: make_attack_actor(t[0], t[1])),
            min_size=1,
            max_size=5
        )
    )
    @settings(max_examples=100)
    def test_misp_actors_take_priority(self, misp_actors, attack_actors):
        """Test that misp-stage actors take priority over att&ck-stage actors.
        
        **Validates: Requirements 6.3, 6.4**
        
        When both misp-stage and att&ck-stage actors are present, only
        misp-stage actors should be processed (att&ck actors are ignored).
        """
        # Build object data with both types of actors
        object_data = {
            "name": "Test TVM Object",
            "threat": {
                "actors": misp_actors + attack_actors
            }
        }
        
        # Mock the MISP client with functions that track which actors are looked up
        resolved_misp_uuids = []
        resolved_attack_ids = []
        
        def mock_search_galaxy_clusters(galaxy=None, uuid=None, searchall=None, pythonify=False):
            if uuid:
                resolved_misp_uuids.append(uuid)
                # Return a mock cluster to indicate success
                return [{
                    "GalaxyCluster": {
                        "uuid": uuid,
                        "type": "threat-actor",
                        "value": f"Actor {uuid[:8]}",
                        "tag_name": f"misp-galaxy:threat-actor=\"Actor {uuid[:8]}\"",
                        "galaxy_id": "123",
                        "collection_uuid": "abc"
                    }
                }]
            if searchall:
                resolved_attack_ids.append(searchall)
                return [{
                    "GalaxyCluster": {
                        "uuid": "attack-uuid",
                        "type": "mitre-intrusion-set",
                        "value": f"Group {searchall}",
                        "tag_name": f"misp-galaxy:mitre-intrusion-set=\"{searchall}\"",
                        "galaxy_id": "456",
                        "collection_uuid": "def"
                    }
                }]
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        # Verify that only misp-stage actors were looked up (by UUID)
        expected_misp_uuids = [a["uuid"] for a in misp_actors]
        assert set(resolved_misp_uuids) == set(expected_misp_uuids), (
            f"Only misp-stage actor UUIDs should be looked up. "
            f"Expected: {expected_misp_uuids}, Got: {resolved_misp_uuids}"
        )
        
        # Verify that NO att&ck-stage actors were looked up
        assert len(resolved_attack_ids) == 0, (
            f"ATT&CK-stage actors should NOT be looked up when misp-stage actors exist. "
            f"But these were looked up: {resolved_attack_ids}"
        )
        
        # Verify we got results (one per misp actor)
        assert len(result) == len(misp_actors), (
            f"Expected {len(misp_actors)} galaxy clusters, got {len(result)}"
        )

    @given(
        attack_actors=st.lists(
            st.tuples(actor_name, attack_group_id).map(lambda t: make_attack_actor(t[0], t[1])),
            min_size=1,
            max_size=5
        )
    )
    @settings(max_examples=100)
    def test_fallback_to_attack_when_no_misp(self, attack_actors):
        """Test fallback to att&ck when no misp-stage actors present.
        
        **Validates: Requirements 6.3, 6.4**
        
        When no misp-stage actors exist but att&ck-stage actors do,
        the att&ck-stage actors should be used as fallback.
        """
        # Build object data with only att&ck actors
        object_data = {
            "name": "Test TVM Object",
            "threat": {
                "actors": attack_actors
            }
        }
        
        # Track which lookups are performed
        resolved_misp_uuids = []
        resolved_attack_ids = []
        
        def mock_search_galaxy_clusters(galaxy=None, uuid=None, searchall=None, pythonify=False):
            if uuid:
                resolved_misp_uuids.append(uuid)
                return []  # No results for UUID lookup
            if searchall:
                resolved_attack_ids.append(searchall)
                return [{
                    "GalaxyCluster": {
                        "uuid": "attack-uuid",
                        "type": "mitre-intrusion-set",
                        "value": f"Group {searchall}",
                        "tag_name": f"misp-galaxy:mitre-intrusion-set=\"{searchall}\"",
                        "galaxy_id": "456",
                        "collection_uuid": "def"
                    }
                }]
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        # Verify that NO misp-stage lookups occurred (no UUID lookups)
        assert len(resolved_misp_uuids) == 0, (
            f"No MISP UUID lookups should occur when there are no misp-stage actors. "
            f"But these were looked up: {resolved_misp_uuids}"
        )
        
        # Verify that att&ck-stage actors were looked up
        expected_attack_ids = [a.get("id") for a in attack_actors if a.get("id")]
        assert set(resolved_attack_ids) == set(expected_attack_ids), (
            f"ATT&CK-stage actor IDs should be looked up as fallback. "
            f"Expected: {expected_attack_ids}, Got: {resolved_attack_ids}"
        )
        
        # Verify we got results (one per attack actor with ID)
        assert len(result) == len([a for a in attack_actors if a.get("id")]), (
            f"Expected one galaxy cluster per ATT&CK actor with ID, "
            f"got {len(result)}"
        )

    @given(object_uuid=valid_uuid)
    @settings(max_examples=50)
    def test_dom_returns_empty(self, object_uuid):
        """Test that DOM objects return empty actor galaxies.
        
        **Validates: Requirements 6.3, 6.4**
        
        Actor galaxies only apply to TVM objects; DOM should return empty.
        """
        # Build a DOM object data with actors (should be ignored)
        object_data = {
            "name": "Test DOM Object",
            "metadata": {"uuid": object_uuid},
            "threat": {
                "actors": [
                    make_misp_actor("test-uuid", "Test Actor"),
                    make_attack_actor("Attack Actor", "G0001")
                ]
            }
        }
        
        # The MISP client should never be called for DOM
        lookup_called = []
        
        def mock_search_galaxy_clusters(**kwargs):
            lookup_called.append(kwargs)
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("dom", object_data, mock_client)
        
        # Verify empty result for DOM
        assert result == [], (
            f"DOM objects should return empty actor galaxies, got: {result}"
        )
        
        # Verify no MISP lookups occurred
        assert len(lookup_called) == 0, (
            f"No MISP lookups should occur for DOM objects, but got: {lookup_called}"
        )

    @given(object_uuid=valid_uuid)
    @settings(max_examples=50)
    def test_mdr_returns_empty(self, object_uuid):
        """Test that MDR objects return empty actor galaxies.
        
        **Validates: Requirements 6.3, 6.4**
        
        Actor galaxies only apply to TVM objects; MDR should return empty.
        """
        # Build an MDR object data with actors (should be ignored)
        object_data = {
            "name": "Test MDR Object",
            "metadata": {"uuid": object_uuid},
            "threat": {
                "actors": [
                    make_misp_actor("test-uuid", "Test Actor"),
                    make_attack_actor("Attack Actor", "G0001")
                ]
            }
        }
        
        lookup_called = []
        
        def mock_search_galaxy_clusters(**kwargs):
            lookup_called.append(kwargs)
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("mdr", object_data, mock_client)
        
        # Verify empty result for MDR
        assert result == [], (
            f"MDR objects should return empty actor galaxies, got: {result}"
        )
        
        # Verify no MISP lookups occurred
        assert len(lookup_called) == 0, (
            f"No MISP lookups should occur for MDR objects, but got: {lookup_called}"
        )

    @given(
        misp_actors=st.lists(
            st.tuples(actor_uuid, actor_name).map(lambda t: make_misp_actor(t[0], t[1])),
            min_size=0,
            max_size=3
        ),
        attack_actors=st.lists(
            st.tuples(actor_name, attack_group_id).map(lambda t: make_attack_actor(t[0], t[1])),
            min_size=0,
            max_size=3
        ),
        other_actors=st.lists(
            actor_name.map(make_other_actor),
            min_size=0,
            max_size=3
        )
    )
    @settings(max_examples=100)
    def test_priority_with_mixed_stages(self, misp_actors, attack_actors, other_actors):
        """Test priority logic with mixed actor stages.
        
        **Validates: Requirements 6.3, 6.4**
        
        Verifies the priority:
        1. If any misp-stage actors exist, use only them
        2. Else if any att&ck-stage actors exist, use only them
        3. Else return empty (other stages are ignored)
        """
        # Build object data with all types of actors
        all_actors = misp_actors + attack_actors + other_actors
        object_data = {
            "name": "Test TVM Object",
            "threat": {
                "actors": all_actors
            }
        }
        
        # Track lookups
        uuid_lookups = []
        searchall_lookups = []
        
        def mock_search_galaxy_clusters(galaxy=None, uuid=None, searchall=None, pythonify=False):
            if uuid:
                uuid_lookups.append(uuid)
                return [{
                    "GalaxyCluster": {
                        "uuid": uuid,
                        "type": "threat-actor",
                        "value": f"Actor {uuid[:8]}",
                        "tag_name": f"misp-galaxy:threat-actor=\"Actor\"",
                        "galaxy_id": "123",
                        "collection_uuid": "abc"
                    }
                }]
            if searchall:
                searchall_lookups.append(searchall)
                return [{
                    "GalaxyCluster": {
                        "uuid": "attack-uuid",
                        "type": "mitre-intrusion-set",
                        "value": f"Group {searchall}",
                        "tag_name": f"misp-galaxy:mitre-intrusion-set=\"{searchall}\"",
                        "galaxy_id": "456",
                        "collection_uuid": "def"
                    }
                }]
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        # Determine expected behavior based on priority
        if len(misp_actors) > 0:
            # Priority 1: misp-stage actors exist - use only them
            expected_uuids = [a["uuid"] for a in misp_actors]
            assert set(uuid_lookups) == set(expected_uuids), (
                f"When misp-stage actors exist, only they should be looked up. "
                f"Expected UUIDs: {expected_uuids}, Got: {uuid_lookups}"
            )
            assert len(searchall_lookups) == 0, (
                f"ATT&CK lookups should not occur when misp-stage actors exist. "
                f"Got: {searchall_lookups}"
            )
            assert len(result) == len(misp_actors)
        elif len(attack_actors) > 0:
            # Priority 2: no misp-stage, but att&ck-stage exist - use them
            expected_ids = [a.get("id") for a in attack_actors if a.get("id")]
            assert len(uuid_lookups) == 0, (
                f"UUID lookups should not occur when using att&ck fallback. "
                f"Got: {uuid_lookups}"
            )
            assert set(searchall_lookups) == set(expected_ids), (
                f"When falling back to att&ck actors, their IDs should be looked up. "
                f"Expected: {expected_ids}, Got: {searchall_lookups}"
            )
            # Result count matches attack actors with IDs
            assert len(result) == len([a for a in attack_actors if a.get("id")])
        else:
            # Priority 3: no misp or att&ck actors - return empty
            assert len(uuid_lookups) == 0
            assert len(searchall_lookups) == 0
            assert result == [], (
                f"With no misp or att&ck actors, result should be empty. "
                f"Got: {result}"
            )

    @given(object_uuid=valid_uuid)
    @settings(max_examples=50)
    def test_empty_actors_returns_empty(self, object_uuid):
        """Test that empty actor list returns empty result.
        
        **Validates: Requirements 6.3, 6.4**
        """
        object_data = {
            "name": "Test TVM Object",
            "metadata": {"uuid": object_uuid},
            "threat": {
                "actors": []
            }
        }
        
        lookup_called = []
        
        def mock_search_galaxy_clusters(**kwargs):
            lookup_called.append(kwargs)
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        assert result == [], f"Empty actors list should return empty, got: {result}"
        assert len(lookup_called) == 0, "No lookups should occur for empty actors"

    @given(object_uuid=valid_uuid)
    @settings(max_examples=50)
    def test_missing_threat_section_returns_empty(self, object_uuid):
        """Test that missing threat section returns empty result.
        
        **Validates: Requirements 6.3, 6.4**
        """
        object_data = {
            "name": "Test TVM Object",
            "metadata": {"uuid": object_uuid}
            # No threat section
        }
        
        lookup_called = []
        
        def mock_search_galaxy_clusters(**kwargs):
            lookup_called.append(kwargs)
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        assert result == [], f"Missing threat section should return empty, got: {result}"
        assert len(lookup_called) == 0

    @given(object_uuid=valid_uuid)
    @settings(max_examples=50)
    def test_missing_actors_key_returns_empty(self, object_uuid):
        """Test that missing actors key returns empty result.
        
        **Validates: Requirements 6.3, 6.4**
        """
        object_data = {
            "name": "Test TVM Object",
            "metadata": {"uuid": object_uuid},
            "threat": {
                # No actors key
            }
        }
        
        lookup_called = []
        
        def mock_search_galaxy_clusters(**kwargs):
            lookup_called.append(kwargs)
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        assert result == [], f"Missing actors key should return empty, got: {result}"
        assert len(lookup_called) == 0

    @given(
        misp_actors=st.lists(
            st.tuples(actor_uuid, actor_name).map(lambda t: make_misp_actor(t[0], t[1])),
            min_size=2,
            max_size=5
        )
    )
    @settings(max_examples=50)
    def test_multiple_misp_actors_all_resolved(self, misp_actors):
        """Test that all misp-stage actors are resolved when present.
        
        **Validates: Requirements 6.3**
        """
        object_data = {
            "name": "Test TVM Object",
            "threat": {
                "actors": misp_actors
            }
        }
        
        resolved_uuids = []
        
        def mock_search_galaxy_clusters(galaxy=None, uuid=None, searchall=None, pythonify=False):
            if uuid:
                resolved_uuids.append(uuid)
                return [{
                    "GalaxyCluster": {
                        "uuid": uuid,
                        "type": "threat-actor",
                        "value": f"Actor {uuid[:8]}",
                        "tag_name": f"misp-galaxy:threat-actor=\"Actor\"",
                        "galaxy_id": "123",
                        "collection_uuid": "abc"
                    }
                }]
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        expected_uuids = [a["uuid"] for a in misp_actors]
        
        # Verify all misp actors were looked up
        assert set(resolved_uuids) == set(expected_uuids), (
            f"All misp-stage actor UUIDs should be looked up. "
            f"Expected: {expected_uuids}, Got: {resolved_uuids}"
        )
        
        # Verify result count matches
        assert len(result) == len(misp_actors), (
            f"Expected {len(misp_actors)} resolved clusters, got {len(result)}"
        )

    @given(
        attack_actors=st.lists(
            st.tuples(actor_name, attack_group_id).map(lambda t: make_attack_actor(t[0], t[1])),
            min_size=2,
            max_size=5
        )
    )
    @settings(max_examples=50)
    def test_multiple_attack_actors_all_resolved_as_fallback(self, attack_actors):
        """Test that all att&ck-stage actors are resolved when no misp actors.
        
        **Validates: Requirements 6.4**
        """
        object_data = {
            "name": "Test TVM Object",
            "threat": {
                "actors": attack_actors
            }
        }
        
        resolved_ids = []
        
        def mock_search_galaxy_clusters(galaxy=None, uuid=None, searchall=None, pythonify=False):
            if searchall:
                resolved_ids.append(searchall)
                return [{
                    "GalaxyCluster": {
                        "uuid": "attack-uuid",
                        "type": "mitre-intrusion-set",
                        "value": f"Group {searchall}",
                        "tag_name": f"misp-galaxy:mitre-intrusion-set=\"{searchall}\"",
                        "galaxy_id": "456",
                        "collection_uuid": "def"
                    }
                }]
            return []
        
        mock_client = MagicMock()
        mock_client.search_galaxy_clusters = mock_search_galaxy_clusters
        
        result = build_actor_galaxies("tvm", object_data, mock_client)
        
        expected_ids = [a.get("id") for a in attack_actors if a.get("id")]
        
        # Verify all attack actors were looked up
        assert set(resolved_ids) == set(expected_ids), (
            f"All att&ck-stage actor IDs should be looked up as fallback. "
            f"Expected: {expected_ids}, Got: {resolved_ids}"
        )
        
        # Verify result count matches actors with IDs
        assert len(result) == len([a for a in attack_actors if a.get("id")]), (
            f"Expected {len([a for a in attack_actors if a.get('id')])} resolved clusters, "
            f"got {len(result)}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
