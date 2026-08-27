"""Engines/sharing/connector.py — MISP connection factory.

This module provides the PyMISP client factory for connecting to MISP instances
with configurable SSL verification, proxy settings, and error handling.
"""

import socket
import ssl
from typing import Optional

from pymisp import PyMISP

from Engines.modules.sharing import MISPInstanceConfig
from Engines.modules.logs import log


# Connection timeout in seconds for MISP API operations
CONNECTION_TIMEOUT = 30


def create_misp_client(
    instance_config: MISPInstanceConfig,
    proxy_config: Optional[dict] = None
) -> Optional[PyMISP]:
    """Create a PyMISP client for the given instance configuration.
    
    Creates and configures a PyMISP instance for connecting to a MISP server.
    Handles SSL verification settings, proxy configuration with optional
    authentication, and connection failure scenarios.
    
    Args:
        instance_config: Validated MISP instance configuration containing:
            - url: Base URL of the MISP instance
            - token: API authentication token
            - verify_ssl: Whether to validate TLS certificates
            - proxy: Whether to route through configured proxy
        proxy_config: Optional proxy settings from deployment.toml [proxy] section.
            Expected keys when provided:
            - proxy_host: Proxy server hostname
            - proxy_port: Proxy server port
            - proxy_user: Optional proxy username for authentication
            - proxy_password: Optional proxy password for authentication
    
    Returns:
        A configured PyMISP instance ready for API operations, or None if
        connection fails. When None is returned, a FATAL log has been emitted
        and the caller should proceed to the next instance.
    
    Behavior:
        - Sets ssl=instance_config.verify_ssl on PyMISP initialization
        - If instance_config.proxy is True and proxy_config is provided,
          configures HTTP/HTTPS proxy from proxy_config
        - If proxy auth credentials (proxy_user and proxy_password) are
          non-empty, includes them in the proxy URL
        - Logs FATAL on connection failure (timeout 30s, DNS failure, SSL error)
        - Returns None on failure so caller can proceed to next instance
    
    Requirements:
        - 1.5: Direct connection when proxy is False
        - 1.6: Proxy routing when proxy is True and proxy_enabled is True
        - 1.13: Skip TLS verification when verify_ssl is False
        - 9.1: Validate TLS certificate when verify_ssl is True
        - 9.2: Skip TLS validation when verify_ssl is False
        - 9.3: Configure proxy from deployment.toml [proxy] section
        - 9.4: Include proxy auth credentials when non-empty
        - 9.5: Log FATAL on TLS certificate validation failure
        - 9.6: Log FATAL on proxy connection failure
    """
    try:
        # Build proxy URL if proxy is enabled
        proxies = None
        if instance_config.proxy and proxy_config:
            proxies = _build_proxy_dict(proxy_config, instance_config.name)
            if proxies is None:
                # Proxy configuration failed, FATAL already logged
                return None
        
        # Create PyMISP client with configured settings
        # PyMISP accepts ssl parameter for certificate verification
        # and proxies dict for HTTP/HTTPS proxy configuration
        client = PyMISP(
            url=instance_config.url,
            key=instance_config.token,
            ssl=instance_config.verify_ssl,
            timeout=CONNECTION_TIMEOUT,
            proxies=proxies
        )
        
        # Verify connectivity by fetching MISP version
        # This validates the connection, authentication, and SSL settings
        version_response = client.misp_instance_version
        
        if not version_response or isinstance(version_response, dict) and 'errors' in version_response:
            error_msg = version_response.get('errors', 'Unknown error') if isinstance(version_response, dict) else 'No response'
            log(
                "FATAL",
                f"Failed to connect to MISP instance '{instance_config.name}'",
                f"URL: {instance_config.url}",
                f"Error: {error_msg}"
            )
            return None
        
        log(
            "SUCCESS",
            f"Connected to MISP instance '{instance_config.name}'",
            f"MISP version: {version_response.get('version', 'unknown') if isinstance(version_response, dict) else 'unknown'}"
        )
        
        return client
        
    except ssl.SSLError as e:
        log(
            "FATAL",
            f"SSL certificate validation failed for MISP instance '{instance_config.name}'",
            f"URL: {instance_config.url}",
            f"SSL Error: {str(e)}. If the server uses a self-signed certificate, set verify_ssl=false in sharing.toml"
        )
        return None
        
    except socket.timeout:
        log(
            "FATAL",
            f"Connection timeout for MISP instance '{instance_config.name}'",
            f"URL: {instance_config.url}",
            f"The connection timed out after {CONNECTION_TIMEOUT} seconds. Check network connectivity and firewall rules."
        )
        return None
        
    except socket.gaierror as e:
        log(
            "FATAL",
            f"DNS resolution failed for MISP instance '{instance_config.name}'",
            f"URL: {instance_config.url}",
            f"Could not resolve hostname: {str(e)}"
        )
        return None
        
    except ConnectionRefusedError:
        log(
            "FATAL",
            f"Connection refused by MISP instance '{instance_config.name}'",
            f"URL: {instance_config.url}",
            "The server actively refused the connection. Verify the URL and port are correct."
        )
        return None
        
    except ConnectionError as e:
        log(
            "FATAL",
            f"Connection error for MISP instance '{instance_config.name}'",
            f"URL: {instance_config.url}",
            f"Connection error: {str(e)}"
        )
        return None
        
    except Exception as e:
        log(
            "FATAL",
            f"Unexpected error connecting to MISP instance '{instance_config.name}'",
            f"URL: {instance_config.url}",
            f"Error: {type(e).__name__}: {str(e)}"
        )
        return None


def _build_proxy_dict(
    proxy_config: dict,
    instance_name: str
) -> Optional[dict]:
    """Build a proxy dictionary for PyMISP from deployment.toml proxy config.
    
    Constructs the proxy URLs for HTTP and HTTPS connections based on the
    provided proxy configuration. Supports both authenticated and
    unauthenticated proxy connections.
    
    Args:
        proxy_config: Dictionary containing proxy configuration with keys:
            - proxy_host: Proxy server hostname (required)
            - proxy_port: Proxy server port (required)
            - proxy_user: Optional username for proxy authentication
            - proxy_password: Optional password for proxy authentication
        instance_name: Name of the MISP instance for logging purposes.
    
    Returns:
        A dictionary with 'http' and 'https' keys mapping to proxy URLs,
        or None if required proxy configuration is missing.
    """
    proxy_host = proxy_config.get("proxy_host")
    proxy_port = proxy_config.get("proxy_port")
    
    if not proxy_host or not proxy_port:
        log(
            "FATAL",
            f"Proxy enabled for MISP instance '{instance_name}' but proxy configuration is incomplete",
            f"Missing proxy_host or proxy_port in deployment.toml [proxy] section",
            "Ensure both proxy_host and proxy_port are configured in deployment.toml"
        )
        return None
    
    # Build proxy URL with optional authentication
    proxy_user = proxy_config.get("proxy_user")
    proxy_password = proxy_config.get("proxy_password")
    
    # Include credentials only when both user and password are non-empty
    if proxy_user and proxy_password:
        proxy_url = f"http://{proxy_user}:{proxy_password}@{proxy_host}:{proxy_port}"
        log(
            "INFO",
            f"Using authenticated proxy for MISP instance '{instance_name}'",
            f"Proxy: {proxy_host}:{proxy_port} (with authentication)"
        )
    else:
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        log(
            "INFO",
            f"Using unauthenticated proxy for MISP instance '{instance_name}'",
            f"Proxy: {proxy_host}:{proxy_port}"
        )
    
    return {
        "http": proxy_url,
        "https": proxy_url
    }
