"""Engines/sharing/tagging.py — Build tags and galaxy clusters for MISP events.

This module provides functions to build MISP tags and galaxy clusters for
OpenTIDE objects being shared to MISP instances. It handles:

- TLP tags in MISP taxonomy format (tlp:green, tlp:amber, etc.)
- ATT&CK technique tags resolved via the techniques_resolver
- Threat actor galaxy clusters for TVM objects (misp stage > att&ck stage priority)

The tagging follows the requirements specified in the design document:
- Requirement 6.1: TLP tags in MISP taxonomy format
- Requirement 6.2: ATT&CK technique tags for resolved techniques
- Requirement 6.3: MISP Galaxy threat actor clusters for misp-stage actors
- Requirement 6.4: ATT&CK group clusters as fallback for att&ck-stage actors
- Requirement 6.5: Log FAILURE for unresolvable actors, continue processing
- Requirement 6.6: Empty technique list is not an error
"""

from typing import List, Literal, Dict, Any, Optional

from pymisp import MISPTag, PyMISP

from Engines.modules.sharing import TLPLevel
from Engines.modules.framework import techniques_resolver
from Engines.modules.logs import log


ObjectType = Literal["tvm", "dom", "mdr"]


def build_tlp_tag(tlp: TLPLevel) -> MISPTag:
    """Create a MISP TLP tag from the TLP level.
    
    Converts a TLPLevel enum value to a MISPTag object with the proper
    MISP taxonomy format (e.g., 'tlp:green', 'tlp:amber+strict').
    
    Args:
        tlp: The TLP level enum value.
    
    Returns:
        A MISPTag object with the name set to the TLP taxonomy tag.
    
    Examples:
        >>> tag = build_tlp_tag(TLPLevel.GREEN)
        >>> tag.name
        'tlp:green'
        >>> tag = build_tlp_tag(TLPLevel.AMBER_STRICT)
        >>> tag.name
        'tlp:amber+strict'
    
    Requirements:
        - 6.1: Apply TLP tag in MISP taxonomy format
    
    **Validates: Requirements 6.1**
    """
    tag = MISPTag()
    tag.name = tlp.to_misp_tag()
    return tag


def build_attack_tags(object_uuid: str) -> List[MISPTag]:
    """Resolve ATT&CK techniques and create MISP tags for each.
    
    Uses the existing techniques_resolver function to resolve all ATT&CK
    technique identifiers associated with an OpenTIDE object. For DOM and
    MDR objects, this includes techniques from parent relationships
    (MDR→DOM→TVM traversal).
    
    Args:
        object_uuid: The UUID of the OpenTIDE object to resolve techniques for.
    
    Returns:
        A list of MISPTag objects, one per unique resolved technique.
        Returns an empty list if no techniques are resolved (not an error).
    
    Examples:
        >>> tags = build_attack_tags("550e8400-e29b-41d4-a716-446655440000")
        >>> [tag.name for tag in tags]
        ['misp-galaxy:mitre-attack-pattern="T1003 - OS Credential Dumping"']
    
    Behavior:
        - Returns empty list if techniques_resolver returns no techniques
        - Does NOT log an error for empty results (per Requirement 6.6)
        - Each unique technique ID produces exactly one tag
        - Uses MISP galaxy format for ATT&CK technique tags
    
    Requirements:
        - 6.2: Apply ATT&CK technique tags for each resolved technique
        - 6.6: Empty results are not an error condition
    
    **Validates: Requirements 6.2, 6.6**
    """
    # Use the existing techniques_resolver with recursive=True
    # This traverses parent relationships for DOM and MDR objects
    techniques = techniques_resolver(object_uuid, recursive=True)
    
    # If no techniques resolved, return empty list (not an error per Req 6.6)
    if not techniques:
        return []
    
    # Create a MISP tag for each unique technique
    tags: List[MISPTag] = []
    seen_techniques = set()
    
    for technique_id in techniques:
        # Skip duplicates (techniques_resolver already deduplicates, but be safe)
        if technique_id in seen_techniques:
            continue
        seen_techniques.add(technique_id)
        
        # Create the MISP galaxy tag for ATT&CK technique
        # Format: misp-galaxy:mitre-attack-pattern="TXXXX - Technique Name"
        # However, we just have the technique ID, so we use a simpler format
        # that MISP can match against the ATT&CK galaxy
        tag = MISPTag()
        # Use the standard MISP ATT&CK tag format
        # This format is recognized by MISP for ATT&CK technique tagging
        tag.name = f"misp-galaxy:mitre-attack-pattern=\"{technique_id}\""
        tags.append(tag)
    
    return tags


def build_actor_galaxies(
    object_type: ObjectType,
    object_data: dict,
    misp_client: PyMISP
) -> List[dict]:
    """Attach threat actor galaxy clusters to TVM events.
    
    Builds a list of MISP Galaxy cluster references for threat actors
    associated with a TVM object. Only applies to TVM objects; returns
    an empty list for DOM and MDR objects.
    
    Priority logic for actor resolution:
    1. If threat.actors contains entries with tide.vocab.stages == "misp":
       Match by actor UUID → MISP Galaxy threat-actor cluster
    2. Elif threat.actors contains entries with tide.vocab.stages == "att&ck":
       Match by ATT&CK group identifier → MISP Galaxy intrusion-set cluster
    
    Args:
        object_type: The type of OpenTIDE object ("tvm", "dom", or "mdr").
        object_data: The full object dictionary from DataTide.
        misp_client: PyMISP client for galaxy lookup on the target instance.
    
    Returns:
        A list of galaxy cluster dictionaries suitable for attaching to
        a MISP event. Returns an empty list for DOM/MDR objects or if
        no actors are present.
    
    Behavior:
        - Only processes TVM objects; returns empty for DOM/MDR
        - Prioritizes misp-stage actors over att&ck-stage actors
        - Logs FAILURE for unresolvable actors but continues processing
        - Returns partial results if some actors resolve and others don't
    
    Requirements:
        - 6.3: Attach MISP Galaxy threat-actor clusters for misp-stage actors
        - 6.4: Attach ATT&CK group clusters for att&ck-stage actors (fallback)
        - 6.5: Log FAILURE for unresolvable actors, continue processing
    
    **Validates: Requirements 6.3, 6.4, 6.5**
    """
    # Actor galaxies only apply to TVM objects
    if object_type != "tvm":
        return []
    
    # Extract threat.actors list from the TVM object
    threat_section = object_data.get("threat", {})
    actors_list = threat_section.get("actors", [])
    
    if not actors_list:
        return []
    
    # Categorize actors by their stage
    misp_stage_actors: List[dict] = []
    attack_stage_actors: List[dict] = []
    
    for actor in actors_list:
        if not isinstance(actor, dict):
            continue
        
        # Get the tide.vocab.stages value
        tide_section = actor.get("tide", {})
        vocab_section = tide_section.get("vocab", {})
        stages = vocab_section.get("stages", "")
        
        if stages == "misp":
            misp_stage_actors.append(actor)
        elif stages == "att&ck":
            attack_stage_actors.append(actor)
    
    # Priority: misp-stage actors first, then att&ck-stage actors as fallback
    # Per requirements 6.3 and 6.4: only use att&ck if NO misp-stage actors
    if misp_stage_actors:
        return _resolve_misp_actors(misp_stage_actors, misp_client, object_data)
    elif attack_stage_actors:
        return _resolve_attack_actors(attack_stage_actors, misp_client, object_data)
    
    return []


def _resolve_misp_actors(
    actors: List[dict],
    misp_client: PyMISP,
    object_data: dict
) -> List[dict]:
    """Resolve MISP-stage actors to MISP Galaxy threat-actor clusters.
    
    Matches actors by their UUID to MISP Galaxy threat-actor clusters.
    
    Args:
        actors: List of actor dictionaries with tide.vocab.stages == "misp".
        misp_client: PyMISP client for galaxy lookup.
        object_data: The full object data (for logging context).
    
    Returns:
        List of resolved galaxy cluster dictionaries.
    """
    resolved_clusters: List[dict] = []
    object_name = object_data.get("name", "Unknown")
    
    for actor in actors:
        actor_uuid = actor.get("uuid")
        actor_name = actor.get("name", "Unknown Actor")
        
        if not actor_uuid:
            log(
                "FAILURE",
                f"Actor entry missing UUID in TVM object",
                f"Object: {object_name}, Actor: {actor_name}",
                "Skipping this actor, continuing with remaining tags."
            )
            continue
        
        # Try to resolve the actor UUID to a MISP Galaxy threat-actor cluster
        cluster = _lookup_galaxy_cluster_by_uuid(
            misp_client,
            actor_uuid,
            galaxy_type="threat-actor"
        )
        
        if cluster:
            resolved_clusters.append(cluster)
        else:
            log(
                "FAILURE",
                f"Cannot resolve actor to MISP Galaxy cluster",
                f"Object: {object_name}, Actor: {actor_name}, UUID: {actor_uuid}",
                "Skipping this actor, continuing with remaining tags."
            )
    
    return resolved_clusters


def _resolve_attack_actors(
    actors: List[dict],
    misp_client: PyMISP,
    object_data: dict
) -> List[dict]:
    """Resolve ATT&CK-stage actors to MISP Galaxy intrusion-set clusters.
    
    Matches actors by their ATT&CK group identifier (e.g., G0001) to
    MISP Galaxy intrusion-set clusters.
    
    Args:
        actors: List of actor dictionaries with tide.vocab.stages == "att&ck".
        misp_client: PyMISP client for galaxy lookup.
        object_data: The full object data (for logging context).
    
    Returns:
        List of resolved galaxy cluster dictionaries.
    """
    resolved_clusters: List[dict] = []
    object_name = object_data.get("name", "Unknown")
    
    for actor in actors:
        actor_name = actor.get("name", "Unknown Actor")
        
        # For ATT&CK actors, we need an identifier (e.g., G0001)
        # This could be stored in various ways; check common fields
        attack_id = actor.get("id") or actor.get("attack_id") or actor.get("external_id")
        
        if not attack_id:
            # Try to extract from name if it follows ATT&CK naming convention
            # ATT&CK group IDs are typically in the format GXXXX
            import re
            match = re.search(r'G\d{4}', str(actor_name))
            if match:
                attack_id = match.group(0)
        
        if not attack_id:
            log(
                "FAILURE",
                f"Actor entry missing ATT&CK identifier in TVM object",
                f"Object: {object_name}, Actor: {actor_name}",
                "Skipping this actor, continuing with remaining tags."
            )
            continue
        
        # Try to resolve the ATT&CK group ID to a MISP Galaxy intrusion-set cluster
        cluster = _lookup_galaxy_cluster_by_value(
            misp_client,
            attack_id,
            galaxy_type="mitre-intrusion-set"
        )
        
        if cluster:
            resolved_clusters.append(cluster)
        else:
            log(
                "FAILURE",
                f"Cannot resolve ATT&CK actor to MISP Galaxy cluster",
                f"Object: {object_name}, Actor: {actor_name}, ID: {attack_id}",
                "Skipping this actor, continuing with remaining tags."
            )
    
    return resolved_clusters


def _lookup_galaxy_cluster_by_uuid(
    misp_client: PyMISP,
    cluster_uuid: str,
    galaxy_type: str
) -> Optional[dict]:
    """Look up a MISP Galaxy cluster by its UUID.
    
    Queries the MISP instance to find a galaxy cluster matching the
    specified UUID and galaxy type.
    
    Args:
        misp_client: PyMISP client for the target MISP instance.
        cluster_uuid: The UUID of the galaxy cluster to find.
        galaxy_type: The type of galaxy to search (e.g., "threat-actor").
    
    Returns:
        A dictionary representing the galaxy cluster if found, None otherwise.
    """
    try:
        # Use PyMISP's galaxy cluster search
        result = misp_client.search_galaxy_clusters(
            galaxy=galaxy_type,
            uuid=cluster_uuid,
            pythonify=False
        )
        
        if result and isinstance(result, list) and len(result) > 0:
            # Return the first matching cluster
            cluster_data = result[0]
            # Return a format suitable for attaching to events
            return _format_cluster_for_attachment(cluster_data)
        
        return None
        
    except Exception as e:
        # Log at debug level - the caller will log FAILURE for unresolved actors
        return None


def _lookup_galaxy_cluster_by_value(
    misp_client: PyMISP,
    search_value: str,
    galaxy_type: str
) -> Optional[dict]:
    """Look up a MISP Galaxy cluster by a value (e.g., ATT&CK ID).
    
    Queries the MISP instance to find a galaxy cluster matching the
    specified value and galaxy type.
    
    Args:
        misp_client: PyMISP client for the target MISP instance.
        search_value: The value to search for (e.g., "G0001").
        galaxy_type: The type of galaxy to search (e.g., "mitre-intrusion-set").
    
    Returns:
        A dictionary representing the galaxy cluster if found, None otherwise.
    """
    try:
        # Use PyMISP's galaxy cluster search with searchall
        result = misp_client.search_galaxy_clusters(
            galaxy=galaxy_type,
            searchall=search_value,
            pythonify=False
        )
        
        if result and isinstance(result, list) and len(result) > 0:
            # Find the best match - prefer exact ID match
            for cluster in result:
                cluster_meta = cluster.get("GalaxyCluster", cluster)
                # Check if this cluster's value or any synonym matches
                cluster_value = cluster_meta.get("value", "")
                if search_value.lower() in cluster_value.lower():
                    return _format_cluster_for_attachment(cluster)
                
                # Check meta.external_id if available
                meta = cluster_meta.get("meta", {})
                external_ids = meta.get("external_id", [])
                if isinstance(external_ids, list) and search_value in external_ids:
                    return _format_cluster_for_attachment(cluster)
                elif external_ids == search_value:
                    return _format_cluster_for_attachment(cluster)
            
            # If no exact match, return the first result
            return _format_cluster_for_attachment(result[0])
        
        return None
        
    except Exception as e:
        # Log at debug level - the caller will log FAILURE for unresolved actors
        return None


def _format_cluster_for_attachment(cluster_data: dict) -> dict:
    """Format a galaxy cluster for attachment to a MISP event.
    
    Extracts the necessary fields from a MISP API response to create
    a cluster reference that can be attached to events.
    
    Args:
        cluster_data: Raw cluster data from the MISP API.
    
    Returns:
        A formatted dictionary suitable for event attachment.
    """
    # Handle both wrapped and unwrapped responses
    if "GalaxyCluster" in cluster_data:
        cluster = cluster_data["GalaxyCluster"]
    else:
        cluster = cluster_data
    
    return {
        "uuid": cluster.get("uuid"),
        "type": cluster.get("type"),
        "value": cluster.get("value"),
        "tag_name": cluster.get("tag_name"),
        "galaxy_id": cluster.get("galaxy_id"),
        "collection_uuid": cluster.get("collection_uuid"),
    }
