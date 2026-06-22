import git
import sys

from cbc_sdk.rest_api import CBCloudAPI

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.models import TideConfigs
from Engines.modules.deployment import Proxy


class CarbonBlackCloudService:
    """Interface to connect to a Carbon Black Cloud tenant.

    Initialised on a single tenant basis, following the same architectural
    pattern as SentinelService, DefenderForEndpointService, etc.
    """

    def __init__(self, tenant_config: TideConfigs.Systems.CarbonBlackCloud.Tenant) -> None:
        self.tenant_config = tenant_config
        self.setup = tenant_config.setup

        if self.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()

        if DebugEnvironment.ENABLED:
            ssl = DebugEnvironment.SSL_ENABLED
        else:
            ssl = self.setup.ssl

        self.service = CBCloudAPI(
            url=self.setup.url,
            token=self.setup.token,
            org_key=self.setup.org_key,
            ssl_verify=ssl,
        )

        log("SUCCESS", "Successfully connected to Carbon Black Cloud on tenant",
            tenant_config.name)
