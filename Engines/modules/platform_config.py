"""Per-platform configuration loading — single source for Platform.config."""

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from Engines.modules.enums import DetectionPlatforms
from Engines.modules.loaders.object_loader import ObjectLoader
from Engines.modules.models import ConfigurationModels


def systems_raw_index() -> dict[str, dict]:
    from Engines.modules.index import IndexManager

    return dict(IndexManager.load()["configurations"]["systems"])


def build_system_config(system: str, raw: dict | None = None) -> Any:
    """Build typed platform configuration for a detection system."""
    index = systems_raw_index()
    raw = dict(raw if raw is not None else index[system])

    if system == "splunk":

        @dataclass(frozen=True)
        class SplunkConfig:
            Index = raw
            tide = dict(raw["tide"])
            setup = dict(raw["setup"])
            secrets = dict(raw["secrets"])
            defaults = dict(raw["defaults"])
            modifiers = dict(raw.get("modifiers", {}))

        return SplunkConfig()

    if system == "carbon_black_cloud":

        @dataclass(frozen=True)
        class CarbonBlackCloudConfig:
            Index = raw
            tide = dict(raw["tide"])
            setup = dict(raw["setup"])
            secrets = dict(raw["secrets"])
            validation = dict(raw["validation"])

        return CarbonBlackCloudConfig()

    platform = {
        "sentinel": DetectionPlatforms.SENTINEL,
        "defender_for_endpoint": DetectionPlatforms.DEFENDER_FOR_ENDPOINT,
        "sentinel_one": DetectionPlatforms.SENTINEL_ONE,
        "crowdstrike": DetectionPlatforms.CROWDSTRIKE,
        "harfanglab": DetectionPlatforms.HARFANGLAB,
    }[system]

    raw_config = dict(raw)
    return SimpleNamespace(
        raw=raw_config,
        platform=ObjectLoader.load_platform_config(
            dict(raw_config["platform"]), platform
        ),
        modifiers=(
            ObjectLoader.load_modifiers_config(raw_config["modifiers"])
            if raw_config.get("modifiers")
            else None
        ),
        tenants=(
            ObjectLoader.load_tenants_config(raw_config["tenants"], platform)
            if raw_config.get("tenants")
            else None
        ),
    )
