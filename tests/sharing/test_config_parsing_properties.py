"""Property-based tests for configuration parsing.

This module tests Properties 1, 2, and 3 from the MISP Sharing Pipeline design document:
- Property 1: Configuration round-trip integrity
- Property 2: Invalid configuration rejection
- Property 3: Environment variable resolution

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.7, 1.11**
"""

import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import git
import pytest
from hypothesis import given, settings, assume, example
from hypothesis import strategies as st

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))


# ============================================================================
# Mock Setup
# ============================================================================

class MockHelperTide:
    """Mock HelperTide for tests that need environment variable resolution."""
    
    @staticmethod
    def is_debug():
        return True
    
    @staticmethod
    def fetch_config_envvar(config_secrets: dict) -> dict:
        """Resolve $-prefixed environment variables from os.environ.
        
        This mock mirrors the real HelperTide.fetch_config_envvar behavior:
        - Values starting with $ are resolved from os.environ
        - If the env var exists, the value is replaced
        - If the env var doesn't exist, the value remains unchanged (with $ prefix)
        """
        result = dict(config_secrets)
        for key in list(result.keys()):
            if isinstance(result[key], str) and result[key].startswith('$'):
                env_var_name = result[key][1:]
                if env_var_name in os.environ:
                    result[key] = os.environ[env_var_name]
        return result


# Mock the tide module before importing sharing to avoid DataTide initialization
mock_tide = MagicMock()
mock_tide.HelperTide = MockHelperTide
mock_tide.DataTide = MagicMock()
sys.modules['Engines.modules.tide'] = mock_tide

# Mock the logs module
mock_logs = MagicMock()
mock_logs.log = MagicMock()
sys.modules['Engines.modules.logs'] = mock_logs


# ============================================================================
# Import sharing module after mocking dependencies
# ============================================================================

# Import the sharing module - use importlib to ensure fresh import
import importlib

# If the module was already imported, reload it with the mocks in place
if 'Engines.modules.sharing' in sys.modules:
    # Remove and reimport
    del sys.modules['Engines.modules.sharing']

from Engines.modules.sharing import (
    TLPLevel,
    MISPInstanceConfig,
    OrganisationConfig,
    SharingConfig,
    load_sharing_config,
)


# ============================================================================
# Test Data Strategies
# ============================================================================

# Valid TLP strings (case-insensitive in implementation)
VALID_TLP_STRINGS = ["clear", "white", "green", "amber", "amber+strict", "red"]
VALID_MODES = ["send", "fetch", "sync"]


@st.composite
def valid_uuid_v4(draw) -> str:
    """Generate a valid UUIDv4 string."""
    return str(uuid.uuid4())


@st.composite
def valid_org_name(draw) -> str:
    """Generate a valid organisation name (1-256 chars)."""
    return draw(st.text(
        min_size=1,
        max_size=256,
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd", "Pc"),
            whitelist_characters=" -_."
        )
    ))


@st.composite
def valid_instance_name(draw) -> str:
    """Generate a valid MISP instance name (1-128 chars)."""
    return draw(st.text(
        min_size=1,
        max_size=128,
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd", "Pc"),
            whitelist_characters=" -_."
        )
    ))


@st.composite
def valid_url(draw) -> str:
    """Generate a valid HTTP/HTTPS URL."""
    protocol = draw(st.sampled_from(["http", "https"]))
    domain = draw(st.text(
        min_size=1,
        max_size=50,
        alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="-")
    ))
    tld = draw(st.sampled_from(["org", "com", "net", "io"]))
    return f"{protocol}://{domain}.{tld}"


@st.composite
def valid_organisation_config(draw) -> Dict[str, Any]:
    """Generate a valid [organisation] section dictionary."""
    return {
        "enabled": draw(st.booleans()),
        "name": draw(valid_org_name()),
        "uuid": draw(valid_uuid_v4())
    }


@st.composite
def valid_misp_instance_dict(draw, use_env_token: bool = False) -> Dict[str, Any]:
    """Generate a valid [[misp]] entry dictionary.
    
    Args:
        use_env_token: If True, token will be $ENV_VAR format instead of literal.
    """
    if use_env_token:
        token = "$" + draw(st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("Lu", "Nd"), whitelist_characters="_")
        ))
    else:
        token = draw(st.text(min_size=1, max_size=100, alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd")
        )))
    
    return {
        "name": draw(valid_instance_name()),
        "url": draw(valid_url()),
        "token": token,
        "org_uuid": draw(valid_uuid_v4()),
        "max_allowed_tlp": draw(st.sampled_from(VALID_TLP_STRINGS)),
        "mode": draw(st.sampled_from(VALID_MODES)),
        "proxy": draw(st.booleans()),
        "publish_on_change": draw(st.booleans()),
        "verify_ssl": draw(st.booleans())
    }


@st.composite
def valid_sharing_toml(draw, num_instances: int = None) -> Dict[str, Any]:
    """Generate a complete valid sharing.toml content dictionary.
    
    Args:
        num_instances: Specific number of MISP instances to generate.
                      If None, a random number (0-5) is generated.
    """
    if num_instances is None:
        num_instances = draw(st.integers(min_value=0, max_value=5))
    
    org_config = draw(valid_organisation_config())
    
    # Ensure organisation has valid name and uuid when enabled
    if org_config["enabled"]:
        # Force valid values for enabled organisation
        if not org_config["name"]:
            org_config["name"] = "Default Organisation"
    
    instances = [draw(valid_misp_instance_dict()) for _ in range(num_instances)]
    
    # Ensure proxy consistency - if any instance has proxy=true, 
    # we need to account for this in tests
    
    return {
        "organisation": org_config,
        "misp": instances
    }


@st.composite
def valid_deployment_toml(draw, proxy_enabled: bool = None) -> Dict[str, Any]:
    """Generate a deployment.toml content dictionary.
    
    Args:
        proxy_enabled: Specific value for proxy_enabled. 
                      If None, randomly generated.
    """
    if proxy_enabled is None:
        proxy_enabled = draw(st.booleans())
    
    return {
        "debug": {
            "proxy_enabled": proxy_enabled
        }
    }


# ============================================================================
# Property 1: Configuration round-trip integrity
# ============================================================================

class TestConfigurationRoundTripIntegrity:
    """Property 1: Configuration round-trip integrity.
    
    **Validates: Requirements 1.1, 1.2**
    
    Property Statement:
    *For any* valid `sharing.toml` content containing a well-formed `[organisation]`
    section and zero or more valid `[[misp]]` entries, parsing via `load_sharing_config()`
    SHALL produce a `SharingConfig` dataclass whose fields, when serialized back to a
    dictionary, are equivalent to the original input (after env var resolution and
    TLP normalization).
    """

    @given(st.data())
    @settings(max_examples=100)
    def test_valid_config_parses_to_equivalent_dataclass(self, data):
        """Test that valid configs parse successfully and preserve field values.
        
        **Validates: Requirements 1.1, 1.2**
        """
        # Generate valid sharing.toml with instances that don't require proxy
        sharing_toml = data.draw(valid_sharing_toml())
        
        # To avoid proxy consistency errors, either:
        # 1. Disable proxy on all instances, OR
        # 2. Enable proxy_enabled globally
        proxy_enabled = any(
            inst.get("proxy", False) 
            for inst in sharing_toml.get("misp", [])
        )
        deployment_toml = data.draw(valid_deployment_toml(proxy_enabled=proxy_enabled))
        
        # Parse the configuration
        config = load_sharing_config(sharing_toml, deployment_toml)
        
        # Verify organisation fields match
        org = config.organisation
        assert org.enabled == sharing_toml["organisation"]["enabled"]
        assert org.name == sharing_toml["organisation"]["name"]
        assert org.uuid == sharing_toml["organisation"]["uuid"]
        
        # Verify number of instances matches
        assert len(config.instances) == len(sharing_toml.get("misp", []))
        
        # Verify each instance's fields match (accounting for TLP normalization)
        for i, instance in enumerate(config.instances):
            orig = sharing_toml["misp"][i]
            
            assert instance.name == orig["name"]
            assert instance.url == orig["url"]
            # Token may be resolved from env var, so we check it was preserved or resolved
            if not orig["token"].startswith("$"):
                assert instance.token == orig["token"]
            assert instance.org_uuid == orig["org_uuid"]
            # TLP is normalized to TLPLevel enum
            expected_tlp = TLPLevel.from_string(orig["max_allowed_tlp"])
            assert instance.max_allowed_tlp == expected_tlp
            assert instance.mode == orig["mode"]
            assert instance.proxy == orig["proxy"]
            assert instance.publish_on_change == orig["publish_on_change"]
            assert instance.verify_ssl == orig["verify_ssl"]

    @given(
        enabled=st.booleans(),
        name=valid_org_name(),
        org_uuid=valid_uuid_v4()
    )
    @settings(max_examples=50)
    def test_organisation_section_fields_preserved(self, enabled, name, org_uuid):
        """Test that organisation section fields are correctly preserved.
        
        **Validates: Requirements 1.1**
        """
        sharing_toml = {
            "organisation": {
                "enabled": enabled,
                "name": name,
                "uuid": org_uuid
            },
            "misp": []
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        config = load_sharing_config(sharing_toml, deployment_toml)
        
        assert config.organisation.enabled == enabled
        assert config.organisation.name == name
        assert config.organisation.uuid == org_uuid

    @given(instance_data=valid_misp_instance_dict(use_env_token=False))
    @settings(max_examples=50)
    def test_misp_instance_fields_preserved(self, instance_data):
        """Test that MISP instance fields are correctly preserved.
        
        **Validates: Requirements 1.2**
        """
        # Ensure proxy consistency
        proxy_enabled = instance_data.get("proxy", False)
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [instance_data]
        }
        deployment_toml = {"debug": {"proxy_enabled": proxy_enabled}}
        
        config = load_sharing_config(sharing_toml, deployment_toml)
        
        assert len(config.instances) == 1
        instance = config.instances[0]
        
        assert instance.name == instance_data["name"]
        assert instance.url == instance_data["url"]
        assert instance.token == instance_data["token"]
        assert instance.org_uuid == instance_data["org_uuid"]
        assert instance.max_allowed_tlp == TLPLevel.from_string(instance_data["max_allowed_tlp"])
        assert instance.mode == instance_data["mode"]
        assert instance.proxy == instance_data["proxy"]
        assert instance.publish_on_change == instance_data["publish_on_change"]
        assert instance.verify_ssl == instance_data["verify_ssl"]

    @given(num_instances=st.integers(min_value=0, max_value=10))
    @settings(max_examples=30)
    def test_multiple_instances_all_parsed(self, num_instances):
        """Test that all MISP instances are parsed correctly.
        
        **Validates: Requirements 1.2**
        """
        instances = []
        for i in range(num_instances):
            instances.append({
                "name": f"Instance {i}",
                "url": f"https://misp{i}.example.org",
                "token": f"token{i}",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": "send",
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            })
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": instances
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        config = load_sharing_config(sharing_toml, deployment_toml)
        
        assert len(config.instances) == num_instances
        for i, instance in enumerate(config.instances):
            assert instance.name == f"Instance {i}"


# ============================================================================
# Property 2: Invalid configuration rejection
# ============================================================================

class TestInvalidConfigurationRejection:
    """Property 2: Invalid configuration rejection.
    
    **Validates: Requirements 1.7, 1.11**
    
    Property Statement:
    *For any* `sharing.toml` content containing at least one field that violates
    its type constraint (non-boolean where boolean expected, string exceeding length
    limit, invalid UUID format, invalid URL, mode not in {send, fetch, sync}),
    `load_sharing_config()` SHALL raise an error and the resulting SharingConfig
    SHALL NOT be successfully constructed.
    """

    @given(invalid_enabled=st.one_of(
        st.integers(),
        st.text(min_size=1),
        st.floats(),
        st.none()
    ))
    @settings(max_examples=50)
    def test_non_boolean_enabled_rejected(self, invalid_enabled):
        """Test that non-boolean organisation.enabled is rejected.
        
        **Validates: Requirements 1.11**
        """
        sharing_toml = {
            "organisation": {
                "enabled": invalid_enabled,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": []
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(name_length=st.integers(min_value=257, max_value=500))
    @settings(max_examples=30)
    def test_org_name_exceeding_256_chars_rejected(self, name_length):
        """Test that organisation.name exceeding 256 characters is rejected.
        
        **Validates: Requirements 1.1, 1.11**
        """
        long_name = "x" * name_length
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": long_name,
                "uuid": str(uuid.uuid4())
            },
            "misp": []
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(invalid_uuid=st.text(min_size=1, max_size=50).filter(
        lambda s: not _is_valid_uuid_v4_format(s)
    ))
    @settings(max_examples=50)
    def test_invalid_org_uuid_format_rejected(self, invalid_uuid):
        """Test that invalid organisation.uuid format is rejected.
        
        **Validates: Requirements 1.1, 1.11**
        """
        assume(invalid_uuid.strip())  # Ensure non-empty
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": invalid_uuid
            },
            "misp": []
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(name_length=st.integers(min_value=129, max_value=300))
    @settings(max_examples=30)
    def test_instance_name_exceeding_128_chars_rejected(self, name_length):
        """Test that MISP instance name exceeding 128 characters is rejected.
        
        **Validates: Requirements 1.2, 1.11**
        """
        long_name = "x" * name_length
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": long_name,
                "url": "https://misp.example.org",
                "token": "test-token",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": "send",
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(invalid_url=st.one_of(
        st.just("not-a-url"),
        st.just("ftp://invalid-protocol.org"),
        st.just("missing-protocol.org"),
        st.just(""),
        st.text(min_size=1, max_size=20).filter(lambda s: not s.startswith("http"))
    ))
    @settings(max_examples=50)
    def test_invalid_url_rejected(self, invalid_url):
        """Test that invalid MISP instance URL is rejected.
        
        **Validates: Requirements 1.2, 1.11**
        """
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": "Test Instance",
                "url": invalid_url,
                "token": "test-token",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": "send",
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(invalid_mode=st.text(min_size=1, max_size=20).filter(
        lambda s: s.lower() not in VALID_MODES
    ))
    @settings(max_examples=50)
    def test_invalid_mode_rejected(self, invalid_mode):
        """Test that invalid MISP instance mode is rejected.
        
        **Validates: Requirements 1.7, 1.11**
        """
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": "Test Instance",
                "url": "https://misp.example.org",
                "token": "test-token",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": invalid_mode,
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(invalid_tlp=st.text(min_size=1, max_size=30).filter(
        lambda s: s.lower().strip() not in [t.lower() for t in VALID_TLP_STRINGS]
    ))
    @settings(max_examples=50)
    def test_invalid_max_allowed_tlp_rejected(self, invalid_tlp):
        """Test that invalid max_allowed_tlp value is rejected.
        
        **Validates: Requirements 1.11**
        """
        assume(invalid_tlp.strip())  # Ensure non-empty
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": "Test Instance",
                "url": "https://misp.example.org",
                "token": "test-token",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": invalid_tlp,
                "mode": "send",
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    @given(invalid_boolean_field=st.sampled_from(["proxy", "publish_on_change", "verify_ssl"]))
    @settings(max_examples=30)
    def test_non_boolean_instance_fields_rejected(self, invalid_boolean_field):
        """Test that non-boolean values for boolean fields are rejected.
        
        **Validates: Requirements 1.2, 1.11**
        """
        instance_data = {
            "name": "Test Instance",
            "url": "https://misp.example.org",
            "token": "test-token",
            "org_uuid": str(uuid.uuid4()),
            "max_allowed_tlp": "green",
            "mode": "send",
            "proxy": False,
            "publish_on_change": True,
            "verify_ssl": True
        }
        
        # Set the target field to an invalid non-boolean value
        instance_data[invalid_boolean_field] = "not-a-boolean"
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [instance_data]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    def test_proxy_without_global_proxy_enabled_rejected(self):
        """Test that proxy=true without global proxy_enabled=true is rejected.
        
        **Validates: Requirements 1.11** (proxy consistency)
        """
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": "Test Instance",
                "url": "https://misp.example.org",
                "token": "test-token",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": "send",
                "proxy": True,  # Requires proxy_enabled=true globally
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        # proxy_enabled is False, so this should fail
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)

    def test_missing_organisation_section_rejected(self):
        """Test that missing [organisation] section is rejected.
        
        **Validates: Requirements 1.1**
        """
        sharing_toml = {
            "misp": []
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError):
            load_sharing_config(sharing_toml, deployment_toml)


# ============================================================================
# Property 3: Environment variable resolution
# ============================================================================

class TestEnvironmentVariableResolution:
    """Property 3: Environment variable resolution.
    
    **Validates: Requirements 1.3, 1.4**
    
    Property Statement:
    *For any* token string starting with `$` where the referenced environment variable
    exists, `load_sharing_config()` SHALL replace the token with the environment
    variable value. *For any* token string starting with `$` where the referenced
    environment variable does NOT exist, the function SHALL signal a fatal error.
    """

    @given(
        env_var_name=st.text(
            min_size=1, 
            max_size=30,
            alphabet=st.characters(whitelist_categories=("Lu", "Nd"), whitelist_characters="_")
        ).filter(lambda s: s and s[0].isalpha()),
        env_var_value=st.text(min_size=1, max_size=100, alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd")
        ))
    )
    @settings(max_examples=50)
    def test_existing_env_var_resolved(self, env_var_name, env_var_value):
        """Test that $-prefixed tokens resolve from existing environment variables.
        
        **Validates: Requirements 1.3**
        """
        # Set the environment variable
        original_value = os.environ.get(env_var_name)
        os.environ[env_var_name] = env_var_value
        
        try:
            sharing_toml = {
                "organisation": {
                    "enabled": True,
                    "name": "Test Org",
                    "uuid": str(uuid.uuid4())
                },
                "misp": [{
                    "name": "Test Instance",
                    "url": "https://misp.example.org",
                    "token": f"${env_var_name}",
                    "org_uuid": str(uuid.uuid4()),
                    "max_allowed_tlp": "green",
                    "mode": "send",
                    "proxy": False,
                    "publish_on_change": True,
                    "verify_ssl": True
                }]
            }
            deployment_toml = {"debug": {"proxy_enabled": False}}
            
            config = load_sharing_config(sharing_toml, deployment_toml)
            
            # The token should be resolved to the environment variable value
            assert config.instances[0].token == env_var_value
        finally:
            # Restore original environment
            if original_value is None:
                os.environ.pop(env_var_name, None)
            else:
                os.environ[env_var_name] = original_value

    @given(
        env_var_name=st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("Lu", "Nd"), whitelist_characters="_")
        ).filter(lambda s: s and s[0].isalpha())
    )
    @settings(max_examples=50)
    def test_missing_env_var_raises_error(self, env_var_name):
        """Test that $-prefixed tokens with missing env vars raise an error.
        
        **Validates: Requirements 1.4**
        """
        # Ensure the environment variable does NOT exist
        assume(env_var_name not in os.environ)
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": "Test Instance",
                "url": "https://misp.example.org",
                "token": f"${env_var_name}",
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": "send",
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        with pytest.raises(ValueError) as exc_info:
            load_sharing_config(sharing_toml, deployment_toml)
        
        # Verify the error message mentions the missing variable
        assert env_var_name in str(exc_info.value)

    def test_non_prefixed_token_preserved(self):
        """Test that tokens NOT starting with $ are preserved as-is.
        
        **Validates: Requirements 1.3** (inverse case)
        """
        literal_token = "my-api-token-12345"
        
        sharing_toml = {
            "organisation": {
                "enabled": True,
                "name": "Test Org",
                "uuid": str(uuid.uuid4())
            },
            "misp": [{
                "name": "Test Instance",
                "url": "https://misp.example.org",
                "token": literal_token,
                "org_uuid": str(uuid.uuid4()),
                "max_allowed_tlp": "green",
                "mode": "send",
                "proxy": False,
                "publish_on_change": True,
                "verify_ssl": True
            }]
        }
        deployment_toml = {"debug": {"proxy_enabled": False}}
        
        config = load_sharing_config(sharing_toml, deployment_toml)
        
        # The literal token should be preserved exactly
        assert config.instances[0].token == literal_token

    @given(
        env_var_names=st.lists(
            st.text(
                min_size=1,
                max_size=20,
                alphabet=st.characters(whitelist_categories=("Lu", "Nd"), whitelist_characters="_")
            ).filter(lambda s: s and s[0].isalpha()),
            min_size=1,
            max_size=5,
            unique=True
        )
    )
    @settings(max_examples=30)
    def test_multiple_instances_with_env_vars(self, env_var_names):
        """Test that multiple instances with different env vars are resolved correctly.
        
        **Validates: Requirements 1.3**
        """
        # Set environment variables
        original_values = {}
        for name in env_var_names:
            original_values[name] = os.environ.get(name)
            os.environ[name] = f"value_for_{name}"
        
        try:
            instances = []
            for i, var_name in enumerate(env_var_names):
                instances.append({
                    "name": f"Instance {i}",
                    "url": f"https://misp{i}.example.org",
                    "token": f"${var_name}",
                    "org_uuid": str(uuid.uuid4()),
                    "max_allowed_tlp": "green",
                    "mode": "send",
                    "proxy": False,
                    "publish_on_change": True,
                    "verify_ssl": True
                })
            
            sharing_toml = {
                "organisation": {
                    "enabled": True,
                    "name": "Test Org",
                    "uuid": str(uuid.uuid4())
                },
                "misp": instances
            }
            deployment_toml = {"debug": {"proxy_enabled": False}}
            
            config = load_sharing_config(sharing_toml, deployment_toml)
            
            # Verify each instance's token was resolved correctly
            for i, var_name in enumerate(env_var_names):
                assert config.instances[i].token == f"value_for_{var_name}"
        finally:
            # Restore original environment
            for name in env_var_names:
                if original_values[name] is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = original_values[name]


# ============================================================================
# Helper Functions
# ============================================================================

def _is_valid_uuid_v4_format(value: str) -> bool:
    """Check if a string is a valid UUIDv4 format."""
    import re
    pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(pattern.match(value))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
