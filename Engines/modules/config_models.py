import os
import sys
from tokenize import String
import git

from dataclasses import dataclass
from typing import Literal, Never, Optional, List, Sequence, Mapping, Any, Union
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

from Engines.modules.enums import StatusStrategy
from Engines.modules.system_models import SystemConfig
@dataclass
class TideConfigs:

    @dataclass
    class Deployment:
        
        @dataclass
        class Status:
            name: str
            description: str
            strategy: Union[StatusStrategy, str]

            def __post_init__(self):
                if type(self.strategy) is str:
                    self.strategy = StatusStrategy[self.strategy]

        statuses = Sequence[Status]

    @dataclass
    class Systems:

        @dataclass
        class Sentinel(SystemConfig):
            
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    resource_group: str
                    workspace_name: str
                    workspace_id: str
                    azure_tenant_id: str
                    azure_subscription_id: str
                    azure_client_id: str
                    azure_client_secret: str

                setup: Setup
        @dataclass
        class Splunk(SystemConfig):
            ...

        @dataclass
        class CarbonBlackCloud(SystemConfig):
            ...

        @dataclass
        class SentinelOne(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url:str
                    account_id:int
                    api_token:str
                    site_id:Optional[int] = None

                setup:Setup

        @dataclass
        class DefenderForEndpoint(SystemConfig):
            
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Parameters:
                    device_groups: Optional[Sequence[str]] = None

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    tenant_id: str
                    client_id: str
                    client_secret: str

                setup:Setup
                parameters: Optional[Parameters] = None

            tenants: Optional[Sequence[Tenant]]

        @dataclass
        class Crowdstrike(SystemConfig):
            
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    api: str
                    client_id: str
                    client_secret: str
                    customer_id: str

                setup:Setup

            tenants: Optional[Sequence[Tenant]]

        @dataclass
        class HarfangLab(SystemConfig):
            
            @dataclass
            class Platform(SystemConfig.Platform):
                pass

            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    type: str  # "Sigma" or "YARA"
                    url: str
                    api_token: str
                    source_id: str

                setup: Setup

            tenants: Optional[Sequence[Tenant]]

