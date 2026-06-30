"""Engines/modules/sharing.py — Sharing configuration and helpers.

This module provides configuration dataclasses, TLP handling, and utility functions
for the MISP sharing pipeline. It follows the CoreTIDE module patterns established
in other Engines/modules/ files.
"""

import re
import uuid
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from Engines.modules.logs import log
from Engines.modules.tide import HelperTide


class TLPLevel(IntEnum):
    """Traffic Light Protocol levels as an ordered enum for comparison.
    
    The TLP hierarchy is ordered from least restrictive to most restrictive:
    CLEAR (0) < GREEN (1) < AMBER (2) < AMBER_STRICT (3) < RED (4)
    
    This allows direct comparison using standard operators:
        TLPLevel.GREEN < TLPLevel.AMBER  # True
        TLPLevel.CLEAR <= TLPLevel.GREEN  # True
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
            
        Examples:
            >>> TLPLevel.from_string("green")
            <TLPLevel.GREEN: 1>
            >>> TLPLevel.from_string("WHITE")
            <TLPLevel.CLEAR: 0>
            >>> TLPLevel.from_string("AMBER+STRICT")
            <TLPLevel.AMBER_STRICT: 3>
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
        """Return the MISP taxonomy tag string for this TLP level.
        
        Returns:
            A string in the format 'tlp:<level>' suitable for use as a MISP tag.
            
        Examples:
            >>> TLPLevel.GREEN.to_misp_tag()
            'tlp:green'
            >>> TLPLevel.AMBER_STRICT.to_misp_tag()
            'tlp:amber+strict'
            >>> TLPLevel.CLEAR.to_misp_tag()
            'tlp:clear'
        """
        tag_mapping = {
            TLPLevel.CLEAR: "tlp:clear",
            TLPLevel.GREEN: "tlp:green",
            TLPLevel.AMBER: "tlp:amber",
            TLPLevel.AMBER_STRICT: "tlp:amber+strict",
            TLPLevel.RED: "tlp:red",
        }
        return tag_mapping[self]


@dataclass
class MISPInstanceConfig:
    """Configuration for a single MISP instance connection.
    
    Represents the configuration for connecting to and sharing objects with
    a specific MISP server instance.
    
    Attributes:
        name: Human-readable name for this instance (1-128 characters).
        url: Base URL of the MISP instance (HTTP/HTTPS).
        token: API token for authentication. If prefixed with '$', the value
               is resolved from the corresponding environment variable.
        org_uuid: UUID of the organisation under which events are created.
        max_allowed_tlp: Maximum TLP level allowed for sharing to this instance.
                         Objects with higher TLP are excluded from sharing.
        mode: Operation mode - 'send' (push only), 'fetch' (pull only), 
              or 'sync' (bidirectional).
        proxy: Whether to route connections through the configured proxy.
        publish_on_change: Whether to auto-publish events after creation/update.
        verify_ssl: Whether to validate TLS certificates for this instance.
    """
    name: str                    # 1-128 chars
    url: str                     # valid HTTP/HTTPS URL
    token: str                   # resolved from env var if $-prefixed
    org_uuid: str                # UUIDv4
    max_allowed_tlp: TLPLevel
    mode: Literal["send", "fetch", "sync"]
    proxy: bool
    publish_on_change: bool
    verify_ssl: bool


@dataclass
class OrganisationConfig:
    """Configuration for the sharing organisation identity.
    
    Represents the organisation that owns and shares OpenTIDE objects
    to configured MISP instances.
    
    Attributes:
        enabled: Whether sharing is enabled for this organisation.
                 If False, all sharing operations are skipped.
        name: Human-readable name of the organisation (1-256 characters).
        uuid: UUID of the organisation in UUIDv4 format.
    """
    enabled: bool
    name: str                    # 1-256 chars
    uuid: str                    # UUIDv4


@dataclass
class SharingConfig:
    """Top-level sharing configuration container.
    
    Aggregates the organisation configuration and list of MISP instance
    configurations for the sharing pipeline.
    
    Attributes:
        organisation: Configuration for the sharing organisation identity.
        instances: List of MISP instance configurations to share objects with.
    """
    organisation: OrganisationConfig
    instances: List[MISPInstanceConfig] = field(default_factory=list)


# Fixed namespace UUID for deterministic event UUID derivation
# This is the opentide MISP object template UUID
OPENTIDE_NAMESPACE_UUID = uuid.UUID("892fd46a-f69e-455c-8c4f-843a4b8f4295")


def derive_event_uuid(opentide_uuid: str) -> str:
    """Deterministically derive a MISP event UUID from an OpenTIDE object UUID.
    
    Uses UUID5 with a fixed namespace (the opentide MISP object template UUID)
    to ensure consistent event identity across all MISP instances. This means
    the same OpenTIDE object will always map to the same MISP event UUID,
    regardless of which instance it's pushed to or how many times the
    derivation is performed.
    
    Args:
        opentide_uuid: The UUID of the OpenTIDE object (metadata.uuid).
        
    Returns:
        A string representation of the derived UUID5.
        
    Examples:
        >>> derive_event_uuid("550e8400-e29b-41d4-a716-446655440000")
        '...'  # Always returns the same value for the same input
        >>> derive_event_uuid("550e8400-e29b-41d4-a716-446655440000") == \\
        ...     derive_event_uuid("550e8400-e29b-41d4-a716-446655440000")
        True
    """
    return str(uuid.uuid5(OPENTIDE_NAMESPACE_UUID, opentide_uuid))


# UUID validation regex pattern
_UUID_V4_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE
)

# Valid modes for MISP instance configuration
_VALID_MODES = {"send", "fetch", "sync"}


def _is_valid_uuid_v4(value: str) -> bool:
    """Check if a string is a valid UUIDv4 format.
    
    Args:
        value: String to validate.
        
    Returns:
        True if the string matches UUIDv4 format, False otherwise.
    """
    return bool(_UUID_V4_PATTERN.match(value))


def _is_valid_url(value: str) -> bool:
    """Check if a string is a valid HTTP or HTTPS URL.
    
    Args:
        value: String to validate.
        
    Returns:
        True if the string is a valid HTTP/HTTPS URL, False otherwise.
    """
    try:
        result = urlparse(value)
        return result.scheme in ('http', 'https') and bool(result.netloc)
    except Exception:
        return False


def _resolve_env_token(value: str, field_name: str, context: str) -> str:
    """Resolve a $-prefixed environment variable token.
    
    If the value starts with '$', it will be resolved via HelperTide.fetch_config_envvar().
    Otherwise, the value is returned unchanged.
    
    Args:
        value: The value to potentially resolve.
        field_name: Name of the field being resolved (for error reporting).
        context: Context description for error messages (e.g., "MISP instance 'Internal'").
        
    Returns:
        The resolved value.
        
    Raises:
        ValueError: If the environment variable is not found.
    """
    if not isinstance(value, str) or not value.startswith('$'):
        return value
    
    # Use HelperTide.fetch_config_envvar which handles the env var resolution
    # Create a temporary dict to leverage the existing method
    temp_config = {field_name: value}
    resolved = HelperTide.fetch_config_envvar(temp_config)
    
    # If the value wasn't resolved (still starts with $), it means env var was not found
    if resolved[field_name].startswith('$'):
        env_var_name = value[1:]  # Remove the $ prefix
        log("FATAL", f"Missing environment variable '{env_var_name}' for {field_name} in {context}")
        raise ValueError(f"Missing environment variable '{env_var_name}' for {field_name} in {context}")
    
    return resolved[field_name]


def load_sharing_config(sharing_toml: dict, deployment_toml: dict) -> SharingConfig:
    """Parse and validate sharing.toml content alongside deployment.toml proxy settings.
    
    Parses the sharing configuration from TOML dictionaries and validates all fields
    against their type constraints. Environment variable tokens (prefixed with '$')
    are resolved via HelperTide.fetch_config_envvar().
    
    Args:
        sharing_toml: Dictionary containing the parsed sharing.toml content.
                      Expected structure:
                      - [organisation] section with enabled, name, uuid
                      - [[misp]] array with instance configurations
        deployment_toml: Dictionary containing the parsed deployment.toml content.
                        Used to validate proxy consistency ([debug].proxy_enabled).
    
    Returns:
        A validated SharingConfig dataclass containing the organisation config
        and list of MISP instance configurations.
        
    Raises:
        ValueError: If any field fails validation (invalid type, length, format)
                   or if required environment variables are missing.
                   
    Requirements:
        - 1.1: Parse [organisation] section with enabled, name, uuid fields
        - 1.2: Parse [[misp]] array entries with all required fields
        - 1.3: Resolve $-prefixed tokens via HelperTide.fetch_config_envvar()
        - 1.4: Log FATAL and raise on missing environment variables
        - 1.6: Validate proxy consistency
        - 1.7: Validate mode values (send, fetch, sync)
        - 1.11: Validate field types and constraints
        - 1.12: Validate proxy=true requires proxy_enabled=true
    """
    errors: List[str] = []
    
    # Validate organisation section exists
    org_section = sharing_toml.get("organisation")
    if not org_section:
        log("FATAL", "Missing [organisation] section in sharing.toml")
        raise ValueError("Missing [organisation] section in sharing.toml")
    
    # Parse and validate organisation fields
    org_enabled = org_section.get("enabled")
    org_name = org_section.get("name", "")
    org_uuid = org_section.get("uuid", "")
    
    # Validate enabled is boolean
    if not isinstance(org_enabled, bool):
        errors.append(f"organisation.enabled must be a boolean, got {type(org_enabled).__name__}")
    
    # Validate name is string with 1-256 chars
    if not isinstance(org_name, str):
        errors.append(f"organisation.name must be a string, got {type(org_name).__name__}")
    elif org_enabled and (len(org_name) < 1 or len(org_name) > 256):
        errors.append(f"organisation.name must be 1-256 characters, got {len(org_name)}")
    
    # Validate uuid is valid UUIDv4 format (only if enabled)
    if not isinstance(org_uuid, str):
        errors.append(f"organisation.uuid must be a string, got {type(org_uuid).__name__}")
    elif org_enabled and org_uuid and not _is_valid_uuid_v4(org_uuid):
        errors.append(f"organisation.uuid must be a valid UUIDv4 format, got '{org_uuid}'")
    
    # Check for fatal organisation errors before proceeding
    if errors:
        for error in errors:
            log("FATAL", error)
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    # Create OrganisationConfig
    organisation = OrganisationConfig(
        enabled=org_enabled,
        name=org_name,
        uuid=org_uuid
    )
    
    # Get proxy_enabled from deployment.toml [debug] section
    debug_section = deployment_toml.get("debug", {})
    proxy_enabled_globally = debug_section.get("proxy_enabled", False)
    
    # Parse MISP instances
    misp_instances: List[MISPInstanceConfig] = []
    misp_entries = sharing_toml.get("misp", [])
    
    # Handle the case where misp is not a list (single entry without array syntax)
    if isinstance(misp_entries, dict):
        misp_entries = [misp_entries]
    
    for idx, misp_entry in enumerate(misp_entries):
        instance_errors: List[str] = []
        instance_name = misp_entry.get("name", f"instance_{idx}")
        context = f"MISP instance '{instance_name}' (index {idx})"
        
        # Validate name (1-128 chars)
        name = misp_entry.get("name")
        if not isinstance(name, str):
            instance_errors.append(f"name must be a string, got {type(name).__name__}")
        elif len(name) < 1 or len(name) > 128:
            instance_errors.append(f"name must be 1-128 characters, got {len(name)}")
        
        # Validate url (valid HTTP/HTTPS URL)
        url = misp_entry.get("url")
        if not isinstance(url, str):
            instance_errors.append(f"url must be a string, got {type(url).__name__}")
        elif not _is_valid_url(url):
            instance_errors.append(f"url must be a valid HTTP/HTTPS URL, got '{url}'")
        
        # Validate and resolve token
        token = misp_entry.get("token")
        if not isinstance(token, str):
            instance_errors.append(f"token must be a string, got {type(token).__name__}")
        else:
            try:
                token = _resolve_env_token(token, "token", context)
            except ValueError as e:
                instance_errors.append(str(e))
        
        # Validate org_uuid (UUIDv4)
        inst_org_uuid = misp_entry.get("org_uuid")
        if not isinstance(inst_org_uuid, str):
            instance_errors.append(f"org_uuid must be a string, got {type(inst_org_uuid).__name__}")
        elif not _is_valid_uuid_v4(inst_org_uuid):
            instance_errors.append(f"org_uuid must be a valid UUIDv4 format, got '{inst_org_uuid}'")
        
        # Validate max_allowed_tlp
        max_tlp_str = misp_entry.get("max_allowed_tlp")
        max_allowed_tlp = None
        if not isinstance(max_tlp_str, str):
            instance_errors.append(f"max_allowed_tlp must be a string, got {type(max_tlp_str).__name__}")
        else:
            try:
                max_allowed_tlp = TLPLevel.from_string(max_tlp_str)
            except ValueError as e:
                instance_errors.append(f"max_allowed_tlp: {e}")
        
        # Validate mode (send, fetch, sync)
        mode = misp_entry.get("mode")
        if not isinstance(mode, str):
            instance_errors.append(f"mode must be a string, got {type(mode).__name__}")
        elif mode not in _VALID_MODES:
            instance_errors.append(f"mode must be one of {_VALID_MODES}, got '{mode}'")
        
        # Validate proxy (boolean)
        proxy = misp_entry.get("proxy")
        if not isinstance(proxy, bool):
            instance_errors.append(f"proxy must be a boolean, got {type(proxy).__name__}")
        
        # Validate proxy consistency: proxy=true requires proxy_enabled=true in deployment.toml
        if isinstance(proxy, bool) and proxy and not proxy_enabled_globally:
            instance_errors.append(
                f"proxy is set to true but proxy_enabled is false in deployment.toml [debug] section. "
                "Enable proxy globally in deployment.toml or set proxy to false for this instance."
            )
        
        # Validate publish_on_change (boolean)
        publish_on_change = misp_entry.get("publish_on_change")
        if not isinstance(publish_on_change, bool):
            instance_errors.append(f"publish_on_change must be a boolean, got {type(publish_on_change).__name__}")
        
        # Validate verify_ssl (boolean)
        verify_ssl = misp_entry.get("verify_ssl")
        if not isinstance(verify_ssl, bool):
            instance_errors.append(f"verify_ssl must be a boolean, got {type(verify_ssl).__name__}")
        
        # If there are errors for this instance, log and collect them
        if instance_errors:
            for error in instance_errors:
                log("FATAL", f"{context}: {error}")
            errors.extend([f"{context}: {e}" for e in instance_errors])
            continue
        
        # Create MISPInstanceConfig if all validations pass
        misp_instances.append(MISPInstanceConfig(
            name=name,
            url=url,
            token=token,
            org_uuid=inst_org_uuid,
            max_allowed_tlp=max_allowed_tlp,  # type: ignore
            mode=mode,  # type: ignore
            proxy=proxy,
            publish_on_change=publish_on_change,
            verify_ssl=verify_ssl
        ))
    
    # If there were any errors during instance parsing, raise
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return SharingConfig(
        organisation=organisation,
        instances=misp_instances
    )
