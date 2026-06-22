# Engines/modules/models.py — backward compatibility shim
from Engines.modules.enums import StatusStrategy, DetectionPlatforms, DeploymentStrategy, DetectionSystems
from Engines.modules.system_models import SystemConfig, DeploymentBatch, TenantDeployment
from Engines.modules.config_models import ConfigurationModels, TideConfigs
from Engines.modules.object_models import (
    SharedModels,
    DetectionRule,
    TideDefinitionsModels,
    TideModels,
)

# Legacy aliases
TenantDeploymentModel = DeploymentBatch

__all__ = [
    "StatusStrategy",
    "DetectionPlatforms",
    "DetectionSystems",
    "DeploymentStrategy",
    "SystemConfig",
    "DeploymentBatch",
    "TenantDeploymentModel",
    "TenantDeployment",
    "ConfigurationModels",
    "TideConfigs",
    "SharedModels",
    "DetectionRule",
    "TideDefinitionsModels",
    "TideModels",
]
