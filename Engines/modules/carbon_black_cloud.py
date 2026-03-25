import os
import sys 
import git
from abc import ABC

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, HelperTide
from Engines.modules.deployment import Proxy


class CarbonBlackCloudEngineInit(ABC):
    """
    Utility class used to initialise all constants relevant to operations with Carbon Black Cloud.
    Supports both MDRv4 typed format (tenants) and legacy format (setup/secrets).
    """

    def __init__(self):

        self.DEBUG = DebugEnvironment.ENABLED

        self.DEPLOYER_IDENTIFIER = "carbon_black_cloud"

        CBC_CONFIG = DataTide.Configurations.Systems.CarbonBlackCloud

        self.SEVERITY_MAPPING = {
            "Informational": 1,
            "Low": 3,
            "Medium": 6,
            "High": 8,
            "Critical": 10,
        }

        # MDRv4 typed format — tenants configured via [platform]/[[tenants]]
        if CBC_CONFIG.tenants:
            self._init_from_tenants(CBC_CONFIG)
        else:
            # TODO: DEPRECATED [carbon-black-cloud-mdrv4] — Legacy format
            self._init_from_legacy(CBC_CONFIG)

        if self.DEBUG:
            self.SSL_ENABLED = DebugEnvironment.SSL_ENABLED

        log("INFO", "SSL has been set to",
        str(self.SSL_ENABLED),
        "This can be adjusted in carbon_black_cloud.toml with the setup.ssl keyword")

    def _init_from_tenants(self, cbc_config):
        """Initialise from MDRv4 typed tenant configuration."""
        first_tenant = cbc_config.tenants[0]
        self.DEFAULT_WATCHLIST = first_tenant.setup.watchlist or ""
        self.CBC_URL = first_tenant.setup.url
        self.SSL_ENABLED = first_tenant.setup.ssl
        self.PROXY_ENABLED = first_tenant.setup.proxy

        secrets = {}
        organizations = []
        for tenant in cbc_config.tenants:
            org_name = tenant.name
            organizations.append(org_name)
            secrets[org_name] = {
                "org_key": tenant.setup.org_key,
                "token": tenant.setup.token,
            }

        self.CBC_SECRETS = secrets
        self.ORGANIZATIONS = first_tenant.setup.organizations if first_tenant.setup.organizations else organizations
        self.VALIDATION_ORGANIZATION = organizations[0] if organizations else ""

    def _init_from_legacy(self, cbc_config):
        """Initialise from legacy setup/secrets configuration."""
        CBC_SETUP = HelperTide.fetch_config_envvar(cbc_config.setup)
        self.DEFAULT_WATCHLIST = CBC_SETUP["watchlist"]
        self.CBC_URL = CBC_SETUP["url"]
        self.SSL_ENABLED = CBC_SETUP["ssl"]
        self.PROXY_ENABLED = CBC_SETUP["proxy"]

        secrets = {}
        cbc_secrets_error_flag = False
        for org in cbc_config.secrets:
            tenant_secrets = HelperTide.fetch_config_envvar(cbc_config.secrets[org])
            if "org_key" not in tenant_secrets:
                log(
                    "FATAL",
                    "Could not fetch Organisation Key for organisation",
                    org,
                    "Double check that there is a namespaced entry for this organisation in the TOML config",
                )
                cbc_secrets_error_flag = True
            if "token" not in tenant_secrets:
                log(
                    "FATAL",
                    "Target organisation is not present in Secrets configuration",
                    org,
                    "Double check that there is a namespaced entry for this organisation in the TOML config",
                )
                cbc_secrets_error_flag = True

            if not cbc_secrets_error_flag:
                secrets[org] = {}
                secrets[org]["org_key"] = tenant_secrets["org_key"]  # type: ignore
                secrets[org]["token"] = tenant_secrets["token"]  # type: ignore

        if cbc_secrets_error_flag:
            log("FATAL",
                "The secrets configuration was not set up correctly",
                "Review the previous errors to understand what attribute was missing")
            raise KeyError

        self.CBC_SECRETS = secrets
        self.ORGANIZATIONS = CBC_SETUP["organizations"]
        self.VALIDATION_ORGANIZATION = cbc_config.validation.get("organization", "")

    def configure_proxy(self):
        """Applies the proxy configuration for this system.
        Called before operational methods (deploy/validate) to avoid
        global proxy state conflicts during plugin loading."""
        if self.PROXY_ENABLED:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
