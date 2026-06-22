import os
import sys
from tokenize import String
import git

from dataclasses import dataclass
from typing import Literal, Never, Optional, List, Sequence, Mapping, Any, Union
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

from Engines.modules.enums import DeploymentStrategy
from Engines.modules.object_models import DetectionRule

@dataclass
class SystemConfig:

    @dataclass
    class Platform:
        enabled: bool
        identifier: str
        name: str
        subschema: str
        description: str
        flags: list[str]

    @dataclass
    class Modifiers:
        @dataclass
        class Conditions:
            status: Optional[Sequence[str]] = None
            flags: Optional[Sequence[Never] | Sequence[str]] = None
            tenants: Optional[Sequence[Never] | Sequence[str]] = None
            default: Optional[bool] = None
        
        conditions: Conditions
        modifications: Mapping[Any, str]
        name: Optional[str] = None
        description: Optional[str] = None

    @dataclass 
    class Tenant:
        @dataclass
        class Setup:
            proxy: bool
            ssl: bool

        @dataclass
        class Parameters:
            ...
        
        name: str
        description: str
        deployment: Union[DeploymentStrategy, str]
        setup: Setup
        parameters: Optional[Parameters] = None

        def __post_init__(self):
            if type(self.deployment) is str:
                self.deployment = DeploymentStrategy[self.deployment]

    platform: Platform
    tenants: Optional[Sequence[Tenant]]
    modifiers: Optional[Sequence[Modifiers]] = None

@dataclass
class DeploymentBatch:
    """
    Base common dataclass used to construct tenant deployment
    per system
    """
    tenant: SystemConfig.Tenant
    rules: Sequence[DetectionRule]


TenantDeploymentModel = DeploymentBatch


from Engines.modules.config_models import TideConfigs


class TenantDeployment:

    @dataclass
    class Splunk(DeploymentBatch):
        tenant: TideConfigs.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Sentinel(DeploymentBatch):
        tenant: TideConfigs.Systems.Sentinel.Tenant

    @dataclass
    class CarbonBlackCloud(DeploymentBatch):
        tenant: TideConfigs.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class SentinelOne(DeploymentBatch):
        tenant: TideConfigs.Systems.SentinelOne.Tenant

    @dataclass
    class DefenderForEndpoint(DeploymentBatch):
        tenant: TideConfigs.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Crowdstrike(DeploymentBatch):
        tenant: TideConfigs.Systems.Crowdstrike.Tenant

    @dataclass
    class HarfangLab(DeploymentBatch):
        tenant: TideConfigs.Systems.HarfangLab.Tenant
