"""Unit tests for the MISP connector module.

**Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6**

This module contains unit tests for:
- PyMISP initialization with correct parameters
- SSL verification enabled/disabled
- Proxy configuration with and without credentials
- Connection failure handling and FATAL logging
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
import socket
import ssl

import git

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))


# ============================================================================
# Mock Setup - must be done BEFORE any imports that trigger DataTide
# ============================================================================

class MockHelperTide:
    """Mock HelperTide for tests."""
    
    @staticmethod
    def is_debug():
        return True
    
    @staticmethod
    def fetch_config_envvar(config_secrets: dict) -> dict:
        """Mock environment variable resolution."""
        return dict(config_secrets)


# Mock the tide module before importing sharing to avoid DataTide initialization
mock_tide = MagicMock()
mock_tide.HelperTide = MockHelperTide
mock_tide.DataTide = MagicMock()
sys.modules['Engines.modules.tide'] = mock_tide

# Mock the logs module
mock_logs = MagicMock()
mock_logs.log = MagicMock()
sys.modules['Engines.modules.logs'] = mock_logs

import pytest

# Remove cached module if present to ensure fresh import with mocks
if 'Engines.modules.sharing' in sys.modules:
    del sys.modules['Engines.modules.sharing']
if 'Engines.sharing.connector' in sys.modules:
    del sys.modules['Engines.sharing.connector']

from Engines.modules.sharing import MISPInstanceConfig, TLPLevel
from Engines.sharing.connector import (
    create_misp_client,
    _build_proxy_dict,
    CONNECTION_TIMEOUT,
)


def _create_instance_config(
    name: str = "Test MISP",
    url: str = "https://misp.test.org",
    token: str = "test-api-token",
    org_uuid: str = "11111111-2222-3333-4444-555555555555",
    max_allowed_tlp: TLPLevel = TLPLevel.AMBER,
    mode: str = "send",
    proxy: bool = False,
    publish_on_change: bool = True,
    verify_ssl: bool = True
) -> MISPInstanceConfig:
    """Helper function to create MISPInstanceConfig for tests."""
    return MISPInstanceConfig(
        name=name,
        url=url,
        token=token,
        org_uuid=org_uuid,
        max_allowed_tlp=max_allowed_tlp,
        mode=mode,
        proxy=proxy,
        publish_on_change=publish_on_change,
        verify_ssl=verify_ssl
    )


class TestPyMISPInitialization:
    """Tests for PyMISP initialization with correct parameters.
    
    **Validates: Requirements 9.1, 9.2**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_pymisp_initialized_with_correct_url(self, mock_pymisp_class):
        """Test that PyMISP is initialized with the configured URL.
        
        **Validates: Requirements 9.1, 9.2**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(url="https://misp.example.org")
        
        result = create_misp_client(config)
        
        mock_pymisp_class.assert_called_once()
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['url'] == "https://misp.example.org"
        assert result is mock_client

    @patch('Engines.sharing.connector.PyMISP')
    def test_pymisp_initialized_with_correct_token(self, mock_pymisp_class):
        """Test that PyMISP is initialized with the configured API token.
        
        **Validates: Requirements 9.1, 9.2**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(token="my-secret-api-key-12345")
        
        create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['key'] == "my-secret-api-key-12345"

    @patch('Engines.sharing.connector.PyMISP')
    def test_pymisp_initialized_with_timeout(self, mock_pymisp_class):
        """Test that PyMISP is initialized with the correct timeout value.
        
        **Validates: Requirements 9.1, 9.2**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config()
        
        create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['timeout'] == CONNECTION_TIMEOUT
        assert call_kwargs['timeout'] == 30  # Per requirements


class TestSSLVerification:
    """Tests for SSL verification enabled/disabled.
    
    **Validates: Requirements 9.1, 9.2**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_ssl_verification_enabled_when_verify_ssl_true(self, mock_pymisp_class):
        """Test that SSL verification is enabled when verify_ssl is True.
        
        **Validates: Requirements 9.1**
        
        WHEN verify_ssl is set to true for a MISP_Instance, THE Sharing_Engine 
        SHALL validate the server TLS certificate during API communication.
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(verify_ssl=True)
        
        create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['ssl'] is True

    @patch('Engines.sharing.connector.PyMISP')
    def test_ssl_verification_disabled_when_verify_ssl_false(self, mock_pymisp_class):
        """Test that SSL verification is disabled when verify_ssl is False.
        
        **Validates: Requirements 9.2**
        
        WHEN verify_ssl is set to false for a MISP_Instance, THE Sharing_Engine 
        SHALL skip TLS certificate validation for that instance.
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(verify_ssl=False)
        
        create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['ssl'] is False


class TestProxyConfiguration:
    """Tests for proxy configuration with and without credentials.
    
    **Validates: Requirements 9.3, 9.4**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_no_proxy_when_proxy_disabled(self, mock_pymisp_class):
        """Test that no proxy is configured when proxy is disabled.
        
        **Validates: Requirements 9.3**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=False)
        
        create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['proxies'] is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_proxy_configured_when_enabled(self, mock_pymisp_class):
        """Test that proxy is configured when enabled.
        
        **Validates: Requirements 9.3**
        
        WHERE proxy configuration is enabled for a MISP_Instance, THE Sharing_Engine 
        SHALL configure the PyMISP connection to route through the proxy host and port 
        defined in the [proxy] section of deployment.toml.
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080"
        }
        
        create_misp_client(config, proxy_config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['proxies'] is not None
        assert 'http' in call_kwargs['proxies']
        assert 'https' in call_kwargs['proxies']
        assert "proxy.example.org:8080" in call_kwargs['proxies']['http']
        assert "proxy.example.org:8080" in call_kwargs['proxies']['https']

    @patch('Engines.sharing.connector.PyMISP')
    def test_proxy_without_auth_credentials(self, mock_pymisp_class):
        """Test proxy configuration without authentication credentials.
        
        **Validates: Requirements 9.3**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "3128"
        }
        
        create_misp_client(config, proxy_config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        expected_proxy_url = "http://proxy.example.org:3128"
        assert call_kwargs['proxies']['http'] == expected_proxy_url
        assert call_kwargs['proxies']['https'] == expected_proxy_url

    @patch('Engines.sharing.connector.PyMISP')
    def test_proxy_with_auth_credentials(self, mock_pymisp_class):
        """Test proxy configuration with authentication credentials.
        
        **Validates: Requirements 9.4**
        
        WHERE proxy configuration is enabled and both proxy_user and proxy_password 
        in the [proxy] section resolve to non-empty values after environment variable 
        substitution, THE Sharing_Engine SHALL include the proxy username and password 
        in the proxy configuration.
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_user": "proxyuser",
            "proxy_password": "proxypass123"
        }
        
        create_misp_client(config, proxy_config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        expected_proxy_url = "http://proxyuser:proxypass123@proxy.example.org:8080"
        assert call_kwargs['proxies']['http'] == expected_proxy_url
        assert call_kwargs['proxies']['https'] == expected_proxy_url

    @patch('Engines.sharing.connector.PyMISP')
    def test_proxy_with_empty_credentials_not_included(self, mock_pymisp_class):
        """Test that empty credentials are not included in proxy URL.
        
        **Validates: Requirements 9.4**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_user": "",
            "proxy_password": ""
        }
        
        create_misp_client(config, proxy_config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        # Should not include credentials when empty
        expected_proxy_url = "http://proxy.example.org:8080"
        assert call_kwargs['proxies']['http'] == expected_proxy_url
        assert "@" not in call_kwargs['proxies']['http']

    @patch('Engines.sharing.connector.PyMISP')
    def test_proxy_with_only_user_not_included(self, mock_pymisp_class):
        """Test that credentials are only included when both user and password are present.
        
        **Validates: Requirements 9.4**
        """
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_user": "proxyuser",
            "proxy_password": ""  # Empty password
        }
        
        create_misp_client(config, proxy_config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        # Should not include credentials when password is empty
        expected_proxy_url = "http://proxy.example.org:8080"
        assert call_kwargs['proxies']['http'] == expected_proxy_url
        assert "@" not in call_kwargs['proxies']['http']


class TestBuildProxyDict:
    """Tests for the _build_proxy_dict helper function.
    
    **Validates: Requirements 9.3, 9.4**
    """

    def test_returns_none_when_proxy_host_missing(self):
        """Test that None is returned when proxy_host is missing."""
        proxy_config = {"proxy_port": "8080"}
        
        result = _build_proxy_dict(proxy_config, "Test Instance")
        
        assert result is None

    def test_returns_none_when_proxy_port_missing(self):
        """Test that None is returned when proxy_port is missing."""
        proxy_config = {"proxy_host": "proxy.example.org"}
        
        result = _build_proxy_dict(proxy_config, "Test Instance")
        
        assert result is None

    def test_returns_proxy_dict_with_valid_config(self):
        """Test that proxy dict is returned with valid configuration."""
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080"
        }
        
        result = _build_proxy_dict(proxy_config, "Test Instance")
        
        assert result is not None
        assert 'http' in result
        assert 'https' in result
        assert result['http'] == "http://proxy.example.org:8080"
        assert result['https'] == "http://proxy.example.org:8080"

    def test_includes_auth_when_both_user_and_password_present(self):
        """Test that auth is included when both user and password are present."""
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_user": "user",
            "proxy_password": "pass"
        }
        
        result = _build_proxy_dict(proxy_config, "Test Instance")
        
        assert result['http'] == "http://user:pass@proxy.example.org:8080"
        assert result['https'] == "http://user:pass@proxy.example.org:8080"

    def test_excludes_auth_when_user_missing(self):
        """Test that auth is excluded when user is missing."""
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_password": "pass"
        }
        
        result = _build_proxy_dict(proxy_config, "Test Instance")
        
        assert result['http'] == "http://proxy.example.org:8080"
        assert "@" not in result['http']

    def test_excludes_auth_when_password_missing(self):
        """Test that auth is excluded when password is missing."""
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_user": "user"
        }
        
        result = _build_proxy_dict(proxy_config, "Test Instance")
        
        assert result['http'] == "http://proxy.example.org:8080"
        assert "@" not in result['http']


class TestConnectionFailureHandling:
    """Tests for connection failure handling and FATAL logging.
    
    **Validates: Requirements 9.5, 9.6**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_on_ssl_error(self, mock_pymisp_class):
        """Test that None is returned on SSL certificate validation failure.
        
        **Validates: Requirements 9.5**
        
        IF TLS certificate validation fails when verify_ssl is true, THEN 
        THE Sharing_Engine SHALL log a FATAL message identifying the instance 
        name and the certificate error, and skip all object sharing for that instance.
        """
        mock_pymisp_class.side_effect = ssl.SSLError("certificate verify failed")
        
        config = _create_instance_config(name="SSL Test MISP", verify_ssl=True)
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_on_ssl_error(self, mock_pymisp_class):
        """Test that FATAL is logged on SSL certificate validation failure.
        
        **Validates: Requirements 9.5**
        """
        mock_pymisp_class.side_effect = ssl.SSLError("certificate verify failed")
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="SSL Test MISP", verify_ssl=True)
        
        create_misp_client(config)
        
        # Verify FATAL was logged with the instance name
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "SSL Test MISP" in str(call_args)
        assert "SSL" in str(call_args) or "certificate" in str(call_args).lower()

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_on_timeout(self, mock_pymisp_class):
        """Test that None is returned on connection timeout.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = socket.timeout("timed out")
        
        config = _create_instance_config(name="Timeout MISP")
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_on_timeout(self, mock_pymisp_class):
        """Test that FATAL is logged on connection timeout.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = socket.timeout("timed out")
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Timeout MISP")
        
        create_misp_client(config)
        
        # Verify FATAL was logged with instance name and timeout info
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Timeout MISP" in str(call_args)
        assert "timeout" in str(call_args).lower()

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_on_dns_failure(self, mock_pymisp_class):
        """Test that None is returned on DNS resolution failure.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = socket.gaierror(11001, "getaddrinfo failed")
        
        config = _create_instance_config(name="DNS Fail MISP")
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_on_dns_failure(self, mock_pymisp_class):
        """Test that FATAL is logged on DNS resolution failure.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = socket.gaierror(11001, "getaddrinfo failed")
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="DNS Fail MISP")
        
        create_misp_client(config)
        
        # Verify FATAL was logged with instance name and DNS error
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "DNS Fail MISP" in str(call_args)
        assert "DNS" in str(call_args) or "resolve" in str(call_args).lower()

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_on_connection_refused(self, mock_pymisp_class):
        """Test that None is returned when connection is refused.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = ConnectionRefusedError("Connection refused")
        
        config = _create_instance_config(name="Refused MISP")
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_on_connection_refused(self, mock_pymisp_class):
        """Test that FATAL is logged when connection is refused.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = ConnectionRefusedError("Connection refused")
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Refused MISP")
        
        create_misp_client(config)
        
        # Verify FATAL was logged
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Refused MISP" in str(call_args)
        assert "refused" in str(call_args).lower()

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_on_generic_connection_error(self, mock_pymisp_class):
        """Test that None is returned on generic connection error.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = ConnectionError("Connection failed")
        
        config = _create_instance_config(name="Error MISP")
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_on_unexpected_exception(self, mock_pymisp_class):
        """Test that None is returned on unexpected exceptions.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = Exception("Unexpected error")
        
        config = _create_instance_config(name="Exception MISP")
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_on_unexpected_exception(self, mock_pymisp_class):
        """Test that FATAL is logged on unexpected exceptions.
        
        **Validates: Requirements 9.6**
        """
        mock_pymisp_class.side_effect = Exception("Unexpected error message")
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Exception MISP")
        
        create_misp_client(config)
        
        # Verify FATAL was logged with instance name and error
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Exception MISP" in str(call_args)

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_when_proxy_config_incomplete(self, mock_pymisp_class):
        """Test behavior when proxy config is incomplete (missing required fields).
        
        **Validates: Requirements 9.6**
        
        When proxy is enabled and proxy_config is provided but incomplete (has dict
        but missing proxy_host/proxy_port), the function should return None and log FATAL.
        """
        mock_logs.log.reset_mock()
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(name="Incomplete Proxy MISP", proxy=True)
        # Provide a non-empty proxy_config that's missing required fields
        proxy_config = {"some_other_key": "value"}
        
        result = create_misp_client(config, proxy_config)
        
        assert result is None
        # PyMISP should not be called since proxy config is incomplete
        mock_pymisp_class.assert_not_called()
        # FATAL should be logged about incomplete proxy config
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Incomplete Proxy MISP" in str(call_args)


class TestConnectionValidation:
    """Tests for connection validation after PyMISP initialization.
    
    **Validates: Requirements 9.1, 9.2**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_verifies_connection_by_fetching_version(self, mock_pymisp_class):
        """Test that connection is verified by fetching MISP version."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config()
        
        result = create_misp_client(config)
        
        assert result is mock_client

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_when_version_response_has_errors(self, mock_pymisp_class):
        """Test that None is returned when version response contains errors."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'errors': 'Authentication failed'}
        mock_pymisp_class.return_value = mock_client
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Auth Fail MISP")
        
        result = create_misp_client(config)
        
        assert result is None
        # Verify FATAL was logged
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Auth Fail MISP" in str(call_args)

    @patch('Engines.sharing.connector.PyMISP')
    def test_returns_none_when_version_response_is_none(self, mock_pymisp_class):
        """Test that None is returned when version response is None."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = None
        mock_pymisp_class.return_value = mock_client
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="No Response MISP")
        
        result = create_misp_client(config)
        
        assert result is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_success_on_successful_connection(self, mock_pymisp_class):
        """Test that SUCCESS is logged on successful connection."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Success MISP")
        
        create_misp_client(config)
        
        # Find the SUCCESS log call
        success_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "SUCCESS"]
        assert len(success_calls) >= 1
        assert "Success MISP" in str(success_calls[-1])


class TestProxyFailureBehavior:
    """Tests for proxy-related failure behavior.
    
    **Validates: Requirements 9.6**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_when_proxy_config_missing_host(self, mock_pymisp_class):
        """Test that FATAL is logged when proxy host is missing."""
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Missing Host MISP", proxy=True)
        proxy_config = {"proxy_port": "8080"}  # Missing proxy_host
        
        result = create_misp_client(config, proxy_config)
        
        assert result is None
        # Verify FATAL was logged about incomplete proxy config
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Missing Host MISP" in str(call_args)
        assert "proxy" in str(call_args).lower()

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_fatal_when_proxy_config_missing_port(self, mock_pymisp_class):
        """Test that FATAL is logged when proxy port is missing."""
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Missing Port MISP", proxy=True)
        proxy_config = {"proxy_host": "proxy.example.org"}  # Missing proxy_port
        
        result = create_misp_client(config, proxy_config)
        
        assert result is None
        # Verify FATAL was logged about incomplete proxy config
        mock_logs.log.assert_called()
        call_args = mock_logs.log.call_args_list[-1]
        assert call_args[0][0] == "FATAL"
        assert "Missing Port MISP" in str(call_args)

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_info_for_authenticated_proxy(self, mock_pymisp_class):
        """Test that INFO is logged when using authenticated proxy."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Auth Proxy MISP", proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080",
            "proxy_user": "user",
            "proxy_password": "pass"
        }
        
        create_misp_client(config, proxy_config)
        
        # Verify INFO was logged about proxy usage
        info_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "INFO"]
        assert len(info_calls) >= 1
        assert "Auth Proxy MISP" in str(info_calls[0])
        assert "authentication" in str(info_calls[0]).lower() or "authenticated" in str(info_calls[0]).lower()

    @patch('Engines.sharing.connector.PyMISP')
    def test_logs_info_for_unauthenticated_proxy(self, mock_pymisp_class):
        """Test that INFO is logged when using unauthenticated proxy."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="Unauth Proxy MISP", proxy=True)
        proxy_config = {
            "proxy_host": "proxy.example.org",
            "proxy_port": "8080"
        }
        
        create_misp_client(config, proxy_config)
        
        # Verify INFO was logged about proxy usage
        info_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "INFO"]
        assert len(info_calls) >= 1
        assert "Unauth Proxy MISP" in str(info_calls[0])


class TestEdgeCases:
    """Edge case tests for the connector module.
    
    **Validates: Requirements 9.1, 9.2, 9.3, 9.4**
    """

    @patch('Engines.sharing.connector.PyMISP')
    def test_proxy_enabled_but_no_proxy_config_provided(self, mock_pymisp_class):
        """Test behavior when proxy is enabled but no config is provided."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(proxy=True)
        # No proxy_config provided (None)
        
        result = create_misp_client(config, proxy_config=None)
        
        # Should proceed without proxy since proxy_config is None
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['proxies'] is None

    @patch('Engines.sharing.connector.PyMISP')
    def test_http_url_accepted(self, mock_pymisp_class):
        """Test that HTTP URLs are accepted (for internal instances)."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(url="http://misp.internal.local")
        
        result = create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['url'] == "http://misp.internal.local"
        assert result is mock_client

    @patch('Engines.sharing.connector.PyMISP')
    def test_https_url_accepted(self, mock_pymisp_class):
        """Test that HTTPS URLs are accepted."""
        mock_client = MagicMock()
        mock_client.misp_instance_version = {'version': '2.4.170'}
        mock_pymisp_class.return_value = mock_client
        
        config = _create_instance_config(url="https://misp.secure.org")
        
        result = create_misp_client(config)
        
        call_kwargs = mock_pymisp_class.call_args[1]
        assert call_kwargs['url'] == "https://misp.secure.org"
        assert result is mock_client

    @patch('Engines.sharing.connector.PyMISP')
    def test_version_as_string_handled(self, mock_pymisp_class):
        """Test that non-dict version response is handled gracefully."""
        mock_client = MagicMock()
        # Version as a string instead of dict
        mock_client.misp_instance_version = "2.4.170"
        mock_pymisp_class.return_value = mock_client
        mock_logs.log.reset_mock()
        
        config = _create_instance_config(name="String Version MISP")
        
        result = create_misp_client(config)
        
        # Should log SUCCESS with 'unknown' version
        success_calls = [c for c in mock_logs.log.call_args_list if c[0][0] == "SUCCESS"]
        assert len(success_calls) >= 1
        assert result is mock_client
