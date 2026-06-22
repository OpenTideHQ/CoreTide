"""Detection platform registry — deployers, validators, and per-platform configuration."""

import importlib
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterator, Optional

import git

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.deployment_utils import enabled_systems
from Engines.modules.logs import log
from Engines.modules.platform_config import build_system_config, systems_raw_index


class PlatformEngine(ABC):
    pass


class RuleDeployer(PlatformEngine):
    @abstractmethod
    def deploy(self, deployment: list[str]):
        """Deploy detection rules onto the target platform."""


class QueryValidator(PlatformEngine):
    @abstractmethod
    def validate(self, deployment: list[str]):
        """Validate that queries can be executed on the target platform."""


# Legacy aliases
PluginTide = PlatformEngine
DeployEngine = PlatformEngine
DeployMDR = RuleDeployer
ValidateQuery = QueryValidator


@dataclass
class Platform:
    """A detection platform's configuration and operational capabilities."""

    name: str
    enabled: bool = False
    config: Any = None
    deployer: Optional[RuleDeployer] = None
    validator: Optional[QueryValidator] = None

    @property
    def can_deploy(self) -> bool:
        return self.deployer is not None

    @property
    def can_validate(self) -> bool:
        return self.validator is not None


_PLATFORM_ATTR_NAMES = {
    "sentinel": "Sentinel",
    "defender_for_endpoint": "DefenderForEndpoint",
    "splunk": "Splunk",
    "sentinel_one": "SentinelOne",
    "carbon_black_cloud": "CarbonBlackCloud",
    "crowdstrike": "Crowdstrike",
    "harfanglab": "HarfangLab",
}

_VALIDATOR_SYSTEMS = frozenset({
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "carbon_black_cloud",
})


class _DeployTier:
    """Sentinel for deploy-engine loading."""


class _ValidationTier:
    """Sentinel for validation-engine loading."""


class PlatformLoader:
    """Loads platform deployer and validator engines from deployment modules."""

    class PluginInterface:
        @staticmethod
        def declare():
            ...

    @staticmethod
    def import_plugin(plugin: str) -> PluginInterface:
        return importlib.import_module(plugin)  # type: ignore

    def _generic_loader(self, tier: type, identifier: str) -> dict[str, PlatformEngine]:
        log("ONGOING", "Initiating platform engine loading routine")
        available: dict[str, PlatformEngine] = {}
        systems_index = systems_raw_index()
        for system in systems_index:
            plugin_name = system + identifier
            plugin = None
            try:
                if tier is _DeployTier:
                    log("ONGOING", "Loading rule deployers", plugin_name)
                    plugin = self.import_plugin(f"Engines.deployment.{plugin_name}")
                elif tier is _ValidationTier:
                    log("ONGOING", "Loading query validators", plugin_name)
                    plugin = self.import_plugin(f"Engines.validation.{plugin_name}")
                else:
                    log("FATAL", "Platform engine tier is not supported", str(tier))
            except Exception as e:
                log("WARNING", "Failed to import platform engine", repr(e), plugin_name)

            if plugin:
                try:
                    available[system] = plugin.declare()
                except Exception as e:
                    log(
                        "FATAL",
                        "Imported module but could not declare platform engine",
                        plugin_name,
                        "Module must expose declare() returning the engine class",
                    )
                    log("FATAL", repr(e))
                    raise Exception("PLATFORM ENGINE IMPORT ERROR")
                log("SUCCESS", "Found platform engine for", plugin_name)

        return available

    def rule_deployers(self) -> dict[str, RuleDeployer]:
        return self._generic_loader(identifier="", tier=_DeployTier)  # type: ignore[return-value]

    def query_validators(self) -> dict[str, QueryValidator]:
        return self._generic_loader(identifier="_query", tier=_ValidationTier)  # type: ignore[return-value]


# Legacy alias
PluginEnginesLoader = PlatformLoader


def _platform_enabled(raw: dict) -> bool:
    try:
        return raw.get("tide", {}).get("enabled") is True
    except Exception:
        return raw.get("platform", {}).get("enabled") is True


def _load_platform_config(system: str, raw: dict) -> Any:
    return build_system_config(system, raw)


class PlatformsCollection:
    """First-class platform access on OpenTide."""

    def __init__(self) -> None:
        self._loader = PlatformLoader()
        self._deployers = self._loader.rule_deployers()
        self._validators = self._loader.query_validators()
        systems_index = systems_raw_index()
        self._platforms: dict[str, Platform] = {}
        for system, raw in systems_index.items():
            attr = _PLATFORM_ATTR_NAMES.get(system, system)
            self._platforms[system] = Platform(
                name=system,
                enabled=_platform_enabled(raw),
                config=_load_platform_config(system, raw) if system in systems_index else None,
                deployer=self._deployers.get(system),
                validator=self._validators.get(system)
                if system in _VALIDATOR_SYSTEMS
                else None,
            )
            setattr(self, attr, self._platforms[system])

    def __getitem__(self, name: str) -> Platform:
        return self._platforms[name]

    def __contains__(self, name: str) -> bool:
        return name in self._platforms

    def items(self):
        return self._platforms.items()

    def values(self):
        return self._platforms.values()

    def enabled(self) -> Iterator[Platform]:
        for platform in self._platforms.values():
            if platform.enabled:
                yield platform

    @staticmethod
    def register(name: str, deployer_cls: type) -> None:
        """Internal registration hook used by platform declare() routines."""
        log("DEBUG", "Platform registration recorded for", name)


class DeployTide:
    """Legacy deployment interface — prefer OpenTide.Platforms."""

    _collection: PlatformsCollection | None = None

    @classmethod
    def _ensure(cls) -> PlatformsCollection:
        if cls._collection is None:
            cls._collection = PlatformsCollection()
        return cls._collection

    @property
    def mdr(self) -> dict[str, RuleDeployer]:
        collection = self._ensure()
        return {name: p.deployer for name, p in collection.items() if p.deployer}

    @property
    def query_validation(self) -> dict[str, QueryValidator]:
        collection = self._ensure()
        return {name: p.validator for name, p in collection.items() if p.validator}


DeployTide = DeployTide()
