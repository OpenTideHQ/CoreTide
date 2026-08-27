"""Engines/sharing/scope.py — TLP-based sharing scope computation.

This module provides functions to compute the sharing scope for each MISP
instance based on TLP filtering. Objects are included in a scope only if
their TLP level is equal to or less restrictive than the instance's
max_allowed_tlp configuration.
"""

from dataclasses import dataclass
from typing import Dict, List, Literal, Tuple

from Engines.modules.logs import log
from Engines.modules.sharing import MISPInstanceConfig, TLPLevel


ObjectType = Literal["tvm", "dom", "mdr"]


@dataclass
class ScopedObject:
    """Represents an OpenTIDE object that is eligible for sharing.
    
    This dataclass encapsulates all the information needed to process
    an object for sharing with a specific MISP instance.
    
    Attributes:
        uuid: The unique identifier of the object (metadata.uuid).
        name: The human-readable name of the object.
        object_type: The type of OpenTIDE object ('tvm', 'dom', or 'mdr').
        tlp: The TLP level of the object parsed from metadata.tlp.
        data: The raw object dictionary from DataTide containing all fields.
    """
    uuid: str
    name: str
    object_type: ObjectType
    tlp: TLPLevel
    data: dict


def compute_sharing_scope(
    instance_config: MISPInstanceConfig,
    all_objects: Dict[str, Tuple[ObjectType, dict]]
) -> List[ScopedObject]:
    """Filter objects eligible for sharing with a specific MISP instance.
    
    This function evaluates each object against the instance's max_allowed_tlp
    setting and returns only those objects that are permitted to be shared.
    
    For each object:
        - Extract metadata.tlp (case-insensitive, white=clear normalization)
        - If TLP is missing: log FAILURE, exclude from scope
        - If TLP is invalid: log FAILURE, exclude from scope
        - If object TLP <= instance max_allowed_tlp: include in scope
        - If object TLP > instance max_allowed_tlp: log SKIP, exclude
    
    Args:
        instance_config: Configuration for the target MISP instance,
                        including max_allowed_tlp setting.
        all_objects: Dictionary mapping object UUIDs to tuples of
                    (object_type, object_data) where object_data is the
                    full dictionary representation from DataTide.
    
    Returns:
        List of ScopedObject instances eligible for sharing with this
        MISP instance.
        
    Note:
        If instance_config.max_allowed_tlp is somehow invalid, this function
        will log FATAL and return an empty list (skip the entire instance).
    """
    # Validate instance configuration
    if not isinstance(instance_config.max_allowed_tlp, TLPLevel):
        log(
            "FATAL",
            f"Invalid max_allowed_tlp for MISP instance",
            highlight=f"Instance: {instance_config.name}, "
                      f"Value: {instance_config.max_allowed_tlp}",
            advice="Check the sharing.toml configuration for valid TLP values: "
                   "clear, white, green, amber, amber+strict, red"
        )
        return []
    
    scope: List[ScopedObject] = []
    max_tlp = instance_config.max_allowed_tlp
    
    for obj_uuid, (object_type, object_data) in all_objects.items():
        # Extract object name for logging
        object_name = object_data.get("name", obj_uuid)
        
        # Extract TLP from metadata
        metadata = object_data.get("metadata", {})
        tlp_value = metadata.get("tlp")
        
        # Handle missing TLP
        if tlp_value is None:
            log(
                "FAILURE",
                f"Object missing metadata.tlp field, excluding from all sharing scopes",
                highlight=f"Object: {object_name} ({obj_uuid}), Type: {object_type}"
            )
            continue
        
        # Parse TLP value
        try:
            object_tlp = TLPLevel.from_string(str(tlp_value))
        except ValueError as e:
            log(
                "FAILURE",
                f"Object has invalid TLP value, excluding from all sharing scopes",
                highlight=f"Object: {object_name} ({obj_uuid}), TLP value: {tlp_value}",
                advice=str(e)
            )
            continue
        
        # Compare TLP levels
        if object_tlp <= max_tlp:
            # Object is within TLP scope for this instance
            scope.append(ScopedObject(
                uuid=obj_uuid,
                name=object_name,
                object_type=object_type,
                tlp=object_tlp,
                data=object_data
            ))
        else:
            # Object exceeds TLP scope for this instance
            log(
                "SKIP",
                f"Object excluded due to TLP restrictions",
                highlight=f"Object: {object_name}, TLP: {object_tlp.to_misp_tag()}, "
                          f"Instance: {instance_config.name}, "
                          f"Max allowed: {max_tlp.to_misp_tag()}"
            )
    
    return scope
