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
    Utility class used to initialize all constant relevant to operations with Carbon Black Cloud 
    """

    def __init__(self):

        self.DEBUG = DebugEnvironment.ENABLED

        self.DEPLOYER_IDENTIFIER = "carbon_black_cloud"

        CBC_CONFIG = DataTide.Configurations.Systems.CarbonBlackCloud

        CBC_SETUP = HelperTide.fetch_config_envvar(CBC_CONFIG.setup)
        self.DEFAULT_WATCHLIST = CBC_SETUP["watchlist"]
        self.CBC_URL = CBC_SETUP["url"]
        self.SSL_ENABLED = CBC_SETUP["ssl"]

        if self.DEBUG:
            self.SSL_ENABLED = DebugEnvironment.SSL_ENABLED

        log("INFO", "SSL has been set to",
        str(self.SSL_ENABLED),
        "This can be adjusted in carbon_black_cloud.toml with the setup.ssl keyword")

        secrets = {}
        
        #Allows to print all errors for all tenants at once and raise Exception later
        cbc_secrets_error_flag = False 
        for org in CBC_CONFIG.secrets:
            tenant_secrets = HelperTide.fetch_config_envvar(CBC_CONFIG.secrets[org])
            if "org_key" not in tenant_secrets:
                log(
                    "FATAL",
                    "Could not fetch Organization Key for organization",
                    org,
                    "Double check that there is a namespaced entry for this organization in the TOML config",
                )
                cbc_secrets_error_flag = True
            if "token" not in tenant_secrets:
                log(
                    "FATAL",
                    "Target organization is not present in Secrets configuration",
                    org,
                    "Double check that there is a namespaced entry for this organization in the TOML config",
                )
                cbc_secrets_error_flag = True

            #We can skip in case of error as we raise Exception later
            if not cbc_secrets_error_flag: 
                secrets[org] = {}
                secrets[org]["org_key"] = tenant_secrets["org_key"] #type: ignore
                secrets[org]["token"] = tenant_secrets["token"] #type: ignore

        if cbc_secrets_error_flag:
            log("FATAL",
                "The secrets configuration was not setup correctly",
                "Review the previous errors to understand what attribute was missing")
            raise KeyError
        
        self.CBC_SECRETS = secrets
        self.ORGANIZATIONS = CBC_SETUP["organizations"]
        self.VALIDATION_ORGANIZATION = CBC_CONFIG.validation["organization"]
        self.SEVERITY_MAPPING = {
            "Informational": 1,
            "Low": 3,
            "Medium": 6,
            "High": 8,
            "Critical": 10,
        }

        self.PROXY_ENABLED = CBC_SETUP["proxy"]

    def configure_proxy(self):
        """Applies the proxy configuration for this system.
        Called before operational methods (deploy/validate) to avoid
        global proxy state conflicts during plugin loading."""
        if self.PROXY_ENABLED:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
