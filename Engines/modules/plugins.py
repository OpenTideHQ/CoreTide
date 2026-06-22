# Engines/modules/plugins.py — backward compatibility shim
from Engines.modules.platforms import (
    PlatformEngine,
    RuleDeployer,
    QueryValidator,
    PlatformLoader,
    Platform,
    PlatformsCollection,
    DeployTide,
    PluginTide,
    DeployEngine,
    DeployMDR,
    ValidateQuery,
    PluginEnginesLoader,
)

__all__ = [
    "PlatformEngine",
    "RuleDeployer",
    "QueryValidator",
    "PlatformLoader",
    "Platform",
    "PlatformsCollection",
    "DeployTide",
    "PluginTide",
    "DeployEngine",
    "DeployMDR",
    "ValidateQuery",
    "PluginEnginesLoader",
]
