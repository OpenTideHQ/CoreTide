"""Engines/sharing/relations.py — Resolve opentide-relation attribute values.

This module handles the resolution of related object UUIDs for the
opentide-relation MISP object attribute. Each object type (TVM, DOM, MDR)
has specific rules for determining its relations:

- TVM: Recursively traverse DataTide.Models.chaining to collect all
  transitively linked TVM UUIDs (cycle-safe via visited set).
- DOM: Return UUIDs from the objective.threats field.
- MDR: Return the single UUID from the detection_model field.
"""

from typing import List, Literal, Set, Optional

ObjectType = Literal["tvm", "dom", "mdr"]


def resolve_relations(
    object_uuid: str,
    object_type: ObjectType,
    object_data: dict,
    chaining_index: Optional[dict] = None
) -> List[str]:
    """Resolve the opentide-relation UUIDs for an OpenTIDE object.

    Dispatches to type-specific resolution logic based on the object_type:
    - TVM: Recursively traverse chaining index for linked TVM UUIDs
    - DOM: Extract UUIDs from objective.threats field
    - MDR: Extract UUID from detection_model field

    Args:
        object_uuid: The UUID of the object being processed.
        object_type: The type of object ("tvm", "dom", or "mdr").
        object_data: The full object dictionary from DataTide.
        chaining_index: Optional chaining index dictionary. If None,
            will be loaded from DataTide.Models.chaining.

    Returns:
        List of related UUIDs. Empty list if no relations resolvable.
        Returns empty list (not None) when relations are absent.
    """
    if object_type == "tvm":
        return _resolve_tvm_relations(object_uuid, chaining_index)
    elif object_type == "dom":
        return _resolve_dom_relations(object_data)
    elif object_type == "mdr":
        return _resolve_mdr_relations(object_data)
    else:
        # Unknown object type, return empty list
        return []


def _resolve_tvm_relations(
    tvm_uuid: str,
    chaining_index: Optional[dict] = None
) -> List[str]:
    """Resolve all TVM chain relations for a given TVM.

    Loads the chaining index from DataTide if not provided and
    recursively resolves all transitively linked TVM UUIDs.

    Args:
        tvm_uuid: The TVM UUID to resolve chains for.
        chaining_index: Optional pre-loaded chaining index.

    Returns:
        List of all transitively reachable TVM UUIDs (deduplicated).
    """
    if chaining_index is None:
        # Lazy import to avoid circular dependencies
        from Engines.modules.tide import DataTide
        chaining_index = DataTide.Models.chaining

    return _resolve_tvm_chains(tvm_uuid, chaining_index)


def _resolve_tvm_chains(
    tvm_uuid: str,
    chaining_index: dict,
    visited: Optional[Set[str]] = None
) -> List[str]:
    """Recursively resolve all chained TVM UUIDs from the chaining index.

    Traverses all relations for the given TVM, collecting vector UUIDs.
    For each collected UUID that itself has chaining entries, recurse.
    Uses a visited set to prevent infinite loops in cyclic chains.

    The chaining_index structure is:
    {
        tvm_uuid: {
            relation_name: [vector_uuid, ...],
            ...
        },
        ...
    }

    Args:
        tvm_uuid: The TVM to resolve chains for.
        chaining_index: DataTide.Models.chaining dictionary.
        visited: Set of already-visited UUIDs (cycle protection).

    Returns:
        Flat list of all transitively reachable TVM UUIDs (deduplicated).
    """
    if visited is None:
        visited = set()

    # Protect against cycles by checking if we've already visited this UUID
    if tvm_uuid in visited:
        return []

    # Mark this TVM as visited
    visited.add(tvm_uuid)

    # Collect all directly linked UUIDs from this TVM
    direct_relations: List[str] = []

    if tvm_uuid in chaining_index:
        tvm_chains = chaining_index[tvm_uuid]
        # Iterate over all relation types (e.g., "succeeds", "precedes", etc.)
        for relation_name, vector_list in tvm_chains.items():
            for vector_uuid in vector_list:
                # Skip self-references, already-visited UUIDs, and duplicates
                # This ensures we don't include nodes we've already processed
                # (cycle protection) or the current node itself
                if (vector_uuid != tvm_uuid and 
                    vector_uuid not in visited and
                    vector_uuid not in direct_relations):
                    direct_relations.append(vector_uuid)

    # Recursively resolve chains for each directly linked TVM
    all_relations: List[str] = list(direct_relations)
    for related_uuid in direct_relations:
        if related_uuid not in visited:
            # Recurse into the related TVM's chains
            nested_relations = _resolve_tvm_chains(
                related_uuid, chaining_index, visited
            )
            # Add any new UUIDs not already in our list
            for uuid in nested_relations:
                if uuid not in all_relations:
                    all_relations.append(uuid)

    return all_relations


def _resolve_dom_relations(object_data: dict) -> List[str]:
    """Resolve DOM relations from the objective.threats field.

    DOM objects reference TVMs through their objective.threats field,
    which contains a list of TVM UUIDs.

    Args:
        object_data: The DOM object dictionary from DataTide.

    Returns:
        List of TVM UUIDs from objective.threats, or empty list if absent.
    """
    objective = object_data.get("objective", {})
    if not objective:
        return []

    threats = objective.get("threats", [])
    if not threats:
        return []

    # Ensure we return a list of strings (UUIDs)
    if isinstance(threats, list):
        return [str(threat) for threat in threats if threat]
    else:
        # Single value case (shouldn't happen, but handle gracefully)
        return [str(threats)] if threats else []


def _resolve_mdr_relations(object_data: dict) -> List[str]:
    """Resolve MDR relations from the detection_model field.

    MDR objects reference a single DOM through their detection_model field,
    which contains the UUID of the referred DOM signal.

    Args:
        object_data: The MDR object dictionary from DataTide.

    Returns:
        List containing the detection_model UUID, or empty list if absent.
    """
    detection_model = object_data.get("detection_model")
    if not detection_model:
        return []

    # Return as a single-element list
    return [str(detection_model)]
