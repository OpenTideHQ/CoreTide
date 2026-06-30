"""Engines/sharing/events.py — MISP event existence check, creation, and update.

This module handles the MISP event lifecycle operations:
- Checking for existing events matching an OpenTIDE object
- Creating new MISP events for OpenTIDE objects
- Updating existing MISP events when object versions change

Each OpenTIDE object maps to exactly one MISP event containing a single
opentide MISP object. Event UUIDs are derived deterministically from
the OpenTIDE object UUID for consistent identity across instances.
"""

from dataclasses import dataclass
from typing import List, Optional, Literal, Tuple

import yaml
from pymisp import PyMISP, MISPEvent, MISPObject, MISPTag

from Engines.modules.logs import log
from Engines.modules.sharing import MISPInstanceConfig, TLPLevel, derive_event_uuid
from Engines.sharing.relations import resolve_relations

# Import tagging functions if available (Task 7.1)
# These will be replaced with actual imports once tagging.py is created
try:
    from Engines.sharing.tagging import build_tlp_tag, build_attack_tags, build_actor_galaxies
    _TAGGING_AVAILABLE = True
except ImportError:
    _TAGGING_AVAILABLE = False
    
    def build_tlp_tag(tlp: TLPLevel) -> MISPTag:
        """Placeholder for TLP tag builder. Creates a basic MISPTag."""
        tag = MISPTag()
        tag.name = tlp.to_misp_tag()
        return tag
    
    def build_attack_tags(object_uuid: str) -> List[MISPTag]:
        """Placeholder for ATT&CK tag builder. Returns empty list."""
        return []
    
    def build_actor_galaxies(
        object_type: str,
        object_data: dict,
        misp_client: PyMISP
    ) -> List[dict]:
        """Placeholder for actor galaxy builder. Returns empty list."""
        return []


# API timeout in seconds for MISP operations
API_TIMEOUT = 30

ObjectType = Literal["tvm", "dom", "mdr"]


@dataclass
class ExistenceResult:
    """Result of checking for an existing MISP event.
    
    Encapsulates the result of querying MISP for an existing event that
    matches an OpenTIDE object by org_uuid and opentide uuid attribute.
    
    Attributes:
        found: Whether a matching event was found.
        event: The matching MISPEvent if found, None otherwise.
        remote_version: The version attribute from the opentide object
            in the existing event. Defaults to 0 if missing/unparseable.
    """
    found: bool
    event: Optional[MISPEvent] = None
    remote_version: int = 0


def check_existence(
    client: PyMISP,
    org_uuid: str,
    opentide_uuid: str
) -> ExistenceResult:
    """Query MISP for existing events matching the OpenTIDE object.
    
    Searches the target MISP instance for events that:
    - Are owned by the specified organisation (org_uuid)
    - Contain an opentide object with a uuid attribute matching opentide_uuid
    
    Args:
        client: Configured PyMISP client for the target instance.
        org_uuid: UUID of the organisation under which events are created.
        opentide_uuid: UUID of the OpenTIDE object to search for.
    
    Returns:
        ExistenceResult with:
        - found=True and event populated if a matching event exists
        - found=False if no match or on API error
        - remote_version extracted from the opentide object's version attribute
          (defaults to 0 if missing or unparseable)
    
    Behavior:
        - If multiple matches: uses most recently modified, logs FAILURE about duplicates
        - If API error: logs FAILURE, returns ExistenceResult(found=False)
        - If version attribute missing/unparseable: treats remote_version as 0
        - Timeout: 30 seconds per API call
    
    Requirements:
        - 3.1: Query by org_uuid and opentide uuid attribute
        - 3.2: Filter to events owned by org_uuid
        - 3.3: Handle multiple matches - use most recently modified
        - 3.4: Handle API errors gracefully
        - 4.5: Handle missing/unparseable version as 0
    """
    try:
        # Search for events containing an opentide object with matching uuid
        # We search by:
        # 1. Organisation UUID (events created by our org)
        # 2. Object type "opentide"
        # 3. Attribute value matching the OpenTIDE UUID
        #
        # PyMISP search_index allows us to search for events by various criteria.
        # We use returnFormat='json' to get full event details.
        search_result = client.search(
            controller='events',
            org=org_uuid,
            object_name='opentide',
            value=opentide_uuid,
            pythonify=True,
            timeout=API_TIMEOUT
        )
        
        # Handle empty or error responses
        if not search_result:
            return ExistenceResult(found=False)
        
        # Filter to events that actually contain an opentide object with matching uuid
        matching_events = []
        for event in search_result:
            if isinstance(event, MISPEvent):
                # Verify the event contains an opentide object with the right uuid
                if _event_has_matching_opentide(event, opentide_uuid):
                    matching_events.append(event)
        
        if not matching_events:
            return ExistenceResult(found=False)
        
        # Handle multiple matches: use most recently modified, log FAILURE about duplicates
        if len(matching_events) > 1:
            log(
                "FAILURE",
                f"Duplicate MISP events found for OpenTIDE object",
                f"UUID: {opentide_uuid}, Found {len(matching_events)} events",
                "Using the most recently modified event. Consider cleaning up duplicates."
            )
            # Sort by timestamp descending (most recent first)
            # MISPEvent.timestamp is the modification timestamp
            matching_events.sort(
                key=lambda e: int(getattr(e, 'timestamp', 0) or 0),
                reverse=True
            )
        
        # Use the most recently modified (or only) event
        selected_event = matching_events[0]
        
        # Extract the version from the opentide object
        remote_version = _extract_opentide_version(selected_event, opentide_uuid)
        
        return ExistenceResult(
            found=True,
            event=selected_event,
            remote_version=remote_version
        )
        
    except Exception as e:
        log(
            "FAILURE",
            f"API error during existence check for OpenTIDE object",
            f"UUID: {opentide_uuid}, Error: {type(e).__name__}: {str(e)}",
            "Skipping this object for the current MISP instance."
        )
        return ExistenceResult(found=False)


def _event_has_matching_opentide(event: MISPEvent, opentide_uuid: str) -> bool:
    """Check if a MISP event contains an opentide object with the given UUID.
    
    Iterates through all objects in the event looking for an opentide object
    that has a uuid attribute matching the provided opentide_uuid.
    
    Args:
        event: The MISPEvent to check.
        opentide_uuid: The OpenTIDE UUID to search for.
    
    Returns:
        True if a matching opentide object is found, False otherwise.
    """
    # Get objects from the event
    objects = getattr(event, 'Object', []) or []
    
    for obj in objects:
        # Check if this is an opentide object
        obj_name = getattr(obj, 'name', None)
        if obj_name != 'opentide':
            continue
        
        # Check if it has a uuid attribute matching our target
        attributes = getattr(obj, 'Attribute', []) or []
        for attr in attributes:
            attr_type = getattr(attr, 'object_relation', None)
            attr_value = getattr(attr, 'value', None)
            
            # The uuid attribute in opentide object stores the OpenTIDE object UUID
            if attr_type == 'uuid' and attr_value == opentide_uuid:
                return True
    
    return False


def _extract_opentide_version(event: MISPEvent, opentide_uuid: str) -> int:
    """Extract the version attribute from the matching opentide object.
    
    Searches for the opentide object with the given UUID and extracts
    its version attribute value.
    
    Args:
        event: The MISPEvent containing the opentide object.
        opentide_uuid: The OpenTIDE UUID to identify the correct object.
    
    Returns:
        The version as an integer, or 0 if missing/unparseable.
        
    Requirements:
        - 4.5: Treat missing/unparseable version as 0
    """
    objects = getattr(event, 'Object', []) or []
    
    for obj in objects:
        # Check if this is an opentide object
        obj_name = getattr(obj, 'name', None)
        if obj_name != 'opentide':
            continue
        
        attributes = getattr(obj, 'Attribute', []) or []
        
        # First verify this is the right opentide object
        is_matching_object = False
        version_value = None
        
        for attr in attributes:
            attr_type = getattr(attr, 'object_relation', None)
            attr_value = getattr(attr, 'value', None)
            
            if attr_type == 'uuid' and attr_value == opentide_uuid:
                is_matching_object = True
            elif attr_type == 'version':
                version_value = attr_value
        
        # If this is our object, return its version
        if is_matching_object:
            if version_value is None:
                return 0
            
            # Try to parse as integer
            try:
                return int(version_value)
            except (ValueError, TypeError):
                # Version attribute present but not parseable as integer
                return 0
    
    # No matching opentide object found (shouldn't happen if event passed filtering)
    return 0


# Template UUID for the opentide MISP object
OPENTIDE_TEMPLATE_UUID = "892fd46a-f69e-455c-8c4f-843a4b8f4295"


def build_opentide_misp_object(
    object_uuid: str,
    object_type: ObjectType,
    object_data: dict,
    object_name: str
) -> MISPObject:
    """Build the opentide MISP object with required attributes.
    
    Creates a MISPObject using the opentide template and populates it with
    the required attributes from the OpenTIDE object data.
    
    Args:
        object_uuid: The UUID of the OpenTIDE object (metadata.uuid).
        object_type: The type of object ("tvm", "dom", or "mdr").
        object_data: The full object dictionary from DataTide.
        object_name: The display name/title of the object.
    
    Returns:
        A MISPObject with the following attributes:
        - name: Object title (object_name)
        - opentide-object: Full object content serialized as YAML
        - opentide-type: "tvm", "dom", or "mdr"
        - uuid: The OpenTIDE object UUID
        - version: The object version as a string
        - opentide-relation: UUIDs of related objects (multi-value, omitted if empty)
    
    Requirements:
        - 5.1: One MISP event per OpenTIDE object (1:1 mapping)
        - 5.3: Required attributes: name, opentide-object, opentide-type, uuid, version
        - 5.4: opentide-relation with UUIDs according to object type rules
        - 5.5, 5.6, 5.7: Type-specific relation resolution
        - 5.8: Omit opentide-relation if no resolvable relations
    """
    # Create the MISP object with the opentide template UUID
    misp_object = MISPObject(
        name="opentide",
        template_uuid=OPENTIDE_TEMPLATE_UUID,
        standalone=False
    )
    
    # Extract metadata for version
    metadata = object_data.get("metadata", {})
    version = metadata.get("version", 0)
    
    # Add required attributes
    # name: Object title
    misp_object.add_attribute(
        object_relation="name",
        value=object_name
    )
    
    # opentide-object: Full object content serialized as YAML
    yaml_content = yaml.dump(
        object_data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False
    )
    misp_object.add_attribute(
        object_relation="opentide-object",
        value=yaml_content
    )
    
    # opentide-type: "tvm", "dom", or "mdr"
    misp_object.add_attribute(
        object_relation="opentide-type",
        value=object_type
    )
    
    # uuid: The OpenTIDE object UUID
    misp_object.add_attribute(
        object_relation="uuid",
        value=object_uuid
    )
    
    # version: The object version as a string
    misp_object.add_attribute(
        object_relation="version",
        value=str(version)
    )
    
    # Resolve relations and add opentide-relation if non-empty
    relations = resolve_relations(
        object_uuid=object_uuid,
        object_type=object_type,
        object_data=object_data
    )
    
    # Only add opentide-relation if there are relations to add
    # Each UUID is a separate value of the multi-value attribute
    if relations:
        for relation_uuid in relations:
            misp_object.add_attribute(
                object_relation="opentide-relation",
                value=relation_uuid
            )
    
    return misp_object



def create_event(
    client: PyMISP,
    instance_config: MISPInstanceConfig,
    object_uuid: str,
    object_type: ObjectType,
    object_data: dict,
    object_name: str,
    tlp: TLPLevel
) -> bool:
    """Create a new MISP event for an OpenTIDE object.
    
    Creates a MISP event with a deterministically-derived UUID, attaches the
    opentide MISP object containing the full object data, and applies
    appropriate tags and galaxy clusters.
    
    Args:
        client: Configured PyMISP client for the target instance.
        instance_config: Configuration for the target MISP instance.
        object_uuid: The UUID of the OpenTIDE object (metadata.uuid).
        object_type: The type of object ("tvm", "dom", or "mdr").
        object_data: The full object dictionary from DataTide.
        object_name: The display name/title of the object.
        tlp: The TLP level of the object for tagging.
    
    Returns:
        True on successful creation, False on failure.
    
    Behavior:
        - Derives event UUID deterministically from object UUID
        - Sets event org to instance_config.org_uuid
        - Attaches opentide MISP object with all required attributes
        - Applies TLP tag, ATT&CK tags, and actor galaxy clusters
        - If publish_on_change: calls client.publish(event, alert=False)
        - Logs SUCCESS on successful creation
        - Logs FAILURE and returns False on any error
    
    Requirements:
        - 4.4: Create new event when no matching event found
        - 5.1: One MISP event per OpenTIDE object (1:1 mapping)
        - 5.9: Derive event UUID deterministically
        - 1.8: Publish without email when publish_on_change is True
        - 6.1, 6.2, 6.3, 6.4: Apply appropriate tags and galaxies
    """
    try:
        # Create a new MISP event
        event = MISPEvent()
        
        # Derive event UUID deterministically from OpenTIDE object UUID
        event.uuid = derive_event_uuid(object_uuid)
        
        # Set event info with object name
        event.info = f"OpenTIDE {object_type.upper()}: {object_name}"
        
        # Set the organisation UUID for this event
        event.orgc_uuid = instance_config.org_uuid
        
        # Build and attach the opentide MISP object
        opentide_object = build_opentide_misp_object(
            object_uuid=object_uuid,
            object_type=object_type,
            object_data=object_data,
            object_name=object_name
        )
        event.add_object(opentide_object)
        
        # Apply TLP tag
        tlp_tag = build_tlp_tag(tlp)
        event.add_tag(tlp_tag)
        
        # Apply ATT&CK technique tags
        attack_tags = build_attack_tags(object_uuid)
        for tag in attack_tags:
            event.add_tag(tag)
        
        # Apply threat actor galaxy clusters (TVM only)
        actor_galaxies = build_actor_galaxies(object_type, object_data, client)
        for galaxy in actor_galaxies:
            # Galaxy clusters are added via the Galaxy attribute
            if hasattr(event, 'Galaxy') and event.Galaxy is not None:
                event.Galaxy.append(galaxy)
            else:
                event.Galaxy = [galaxy]
        
        # Add the event to MISP
        result = client.add_event(event, pythonify=True, timeout=API_TIMEOUT)
        
        # Check if the event was created successfully
        if isinstance(result, MISPEvent) and result.uuid:
            # Publish the event if configured to do so
            if instance_config.publish_on_change:
                client.publish(result, alert=False)
            
            log(
                "SUCCESS",
                f"Created MISP event for OpenTIDE object",
                f"Object: {object_name} ({object_uuid})",
                f"Instance: {instance_config.name}, Event UUID: {result.uuid}"
            )
            return True
        else:
            # Handle error response from MISP
            error_msg = str(result) if result else "Unknown error"
            log(
                "FAILURE",
                f"Failed to create MISP event for OpenTIDE object",
                f"Object: {object_name} ({object_uuid})",
                f"Instance: {instance_config.name}, Error: {error_msg}"
            )
            return False
            
    except Exception as e:
        log(
            "FAILURE",
            f"Exception creating MISP event for OpenTIDE object",
            f"Object: {object_name} ({object_uuid})",
            f"Instance: {instance_config.name}, Error: {type(e).__name__}: {str(e)}"
        )
        return False


def update_event(
    client: PyMISP,
    instance_config: MISPInstanceConfig,
    existing_event: MISPEvent,
    object_uuid: str,
    object_type: ObjectType,
    object_data: dict,
    object_name: str,
    tlp: TLPLevel
) -> bool:
    """Update an existing MISP event with current object state.
    
    Replaces the opentide MISP object in an existing event with a new one
    containing the current object data, and updates all tags and galaxy clusters.
    
    Args:
        client: Configured PyMISP client for the target instance.
        instance_config: Configuration for the target MISP instance.
        existing_event: The existing MISP event to update.
        object_uuid: The UUID of the OpenTIDE object (metadata.uuid).
        object_type: The type of object ("tvm", "dom", or "mdr").
        object_data: The full object dictionary from DataTide.
        object_name: The display name/title of the object.
        tlp: The TLP level of the object for tagging.
    
    Returns:
        True on successful update, False on failure.
    
    Behavior:
        - Replaces the opentide MISP object (removes old, adds new)
        - Replaces all tags with current state (TLP, ATT&CK)
        - Replaces galaxy clusters with current state
        - If publish_on_change: calls client.publish(event, alert=False)
        - Logs SUCCESS on successful update
        - Logs FAILURE and returns False on any error
    
    Requirements:
        - 4.2: Update existing event when local version > remote version
        - 5.3, 5.4: Update opentide object with current attributes
        - 1.8: Publish without email when publish_on_change is True
        - 6.1, 6.2, 6.3, 6.4: Update tags and galaxies
    """
    try:
        # Remove existing opentide objects from the event
        objects_to_remove = []
        existing_objects = getattr(existing_event, 'Object', []) or []
        for obj in existing_objects:
            obj_name = getattr(obj, 'name', None)
            if obj_name == 'opentide':
                objects_to_remove.append(obj)
        
        # Delete old opentide objects from MISP
        for old_obj in objects_to_remove:
            obj_id = getattr(old_obj, 'id', None) or getattr(old_obj, 'uuid', None)
            if obj_id:
                try:
                    client.delete_object(obj_id)
                except Exception as e:
                    # Log but continue - we'll add the new object anyway
                    log(
                        "FAILURE",
                        f"Could not delete old opentide object",
                        f"Object ID: {obj_id}, Error: {str(e)}",
                        "Continuing with update..."
                    )
        
        # Build new opentide MISP object
        new_opentide_object = build_opentide_misp_object(
            object_uuid=object_uuid,
            object_type=object_type,
            object_data=object_data,
            object_name=object_name
        )
        
        # Add the new object to the event
        existing_event.add_object(new_opentide_object)
        
        # Clear existing tags and add new ones
        # We need to remove old tags and add current ones
        existing_event.Tag = []
        
        # Apply TLP tag
        tlp_tag = build_tlp_tag(tlp)
        existing_event.add_tag(tlp_tag)
        
        # Apply ATT&CK technique tags
        attack_tags = build_attack_tags(object_uuid)
        for tag in attack_tags:
            existing_event.add_tag(tag)
        
        # Clear existing galaxies and add new ones
        existing_event.Galaxy = []
        
        # Apply threat actor galaxy clusters (TVM only)
        actor_galaxies = build_actor_galaxies(object_type, object_data, client)
        for galaxy in actor_galaxies:
            existing_event.Galaxy.append(galaxy)
        
        # Update event info
        existing_event.info = f"OpenTIDE {object_type.upper()}: {object_name}"
        
        # Update the event in MISP
        result = client.update_event(existing_event, pythonify=True, timeout=API_TIMEOUT)
        
        # Check if the event was updated successfully
        if isinstance(result, MISPEvent) and result.uuid:
            # Publish the event if configured to do so
            if instance_config.publish_on_change:
                client.publish(result, alert=False)
            
            log(
                "SUCCESS",
                f"Updated MISP event for OpenTIDE object",
                f"Object: {object_name} ({object_uuid})",
                f"Instance: {instance_config.name}, Event UUID: {result.uuid}"
            )
            return True
        else:
            # Handle error response from MISP
            error_msg = str(result) if result else "Unknown error"
            log(
                "FAILURE",
                f"Failed to update MISP event for OpenTIDE object",
                f"Object: {object_name} ({object_uuid})",
                f"Instance: {instance_config.name}, Error: {error_msg}"
            )
            return False
            
    except Exception as e:
        log(
            "FAILURE",
            f"Exception updating MISP event for OpenTIDE object",
            f"Object: {object_name} ({object_uuid})",
            f"Instance: {instance_config.name}, Error: {type(e).__name__}: {str(e)}"
        )
        return False


def should_update_event(local_version: int, remote_version: int) -> Tuple[bool, str]:
    """Determine if an event should be updated based on version comparison.
    
    Implements the version comparison logic for the sharing pipeline.
    
    Args:
        local_version: The version of the local OpenTIDE object.
        remote_version: The version from the existing MISP event's opentide object.
                       Should be 0 if missing or unparseable.
    
    Returns:
        A tuple of (should_update, reason):
        - (True, "update") if local version > remote version
        - (False, "skip") if local version <= remote version
    
    Requirements:
        - 4.1: Compare versions using integer numeric comparison
        - 4.2: Update when local > remote
        - 4.3: Skip when local <= remote
        - 4.5: Missing/unparseable remote version treated as 0
    """
    if local_version > remote_version:
        return (True, "update")
    else:
        return (False, "skip")


def log_skip_version_current(
    object_name: str,
    object_uuid: str,
    local_version: int,
    remote_version: int,
    instance_name: str
) -> None:
    """Log a SKIP message when an object's version is current.
    
    Helper function to log when an object is skipped because its local
    version is not greater than the remote version.
    
    Args:
        object_name: The display name of the OpenTIDE object.
        object_uuid: The UUID of the OpenTIDE object.
        local_version: The local object version.
        remote_version: The remote event's opentide object version.
        instance_name: The name of the MISP instance.
    
    Requirements:
        - 4.3: Log SKIP when local version <= remote version
    """
    log(
        "SKIP",
        f"OpenTIDE object version is current, no update needed",
        f"Object: {object_name} ({object_uuid})",
        f"Local version: {local_version}, Remote version: {remote_version}",
        f"Instance: {instance_name}"
    )
