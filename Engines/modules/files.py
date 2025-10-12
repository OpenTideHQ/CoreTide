import sys
import git
import os
import toml
from pathlib import Path
from collections.abc import MutableMapping as Map
from typing import overload, Tuple, Literal


def resolve_configurations() -> dict[str, dict]:
    """
    Interface to provide a single point of truth for all configurations in the
    Tide infrastructure. Custom configurations at the top level are seeked and merged
    into the base configurations using a deep merge algorithm.
    """
    
    def deep_merge(source_dict, merge_dict):
        """
        Recursive dict merge. Mitigation for dict.update() which will not resolve
        two dictionaries with common nested keys and just overwrite from the top level.

        The source_dict is the one that will be overwritten to by the merge_dict
        """
        for key in merge_dict:
            if (
                key in source_dict
                and isinstance(source_dict[key], Map)
                and isinstance(merge_dict[key], Map)
            ):
                deep_merge(source_dict[key], merge_dict[key])
            else:
                source_dict[key] = merge_dict[key]

    def fetch_configs(configuration_path: Path) -> dict[str, dict]:

        config_index = dict()
        for entry in os.listdir(configuration_path):
            # If there are loose top level files, indexes them
            if os.path.isfile(configuration_path / entry):
                try:
                    config_index[entry.removesuffix(".toml")] = toml.load(
                        open(configuration_path / entry, encoding="utf-8")
                    )
                except:
                    raise ValueError(f"Failed to open configuration file {configuration_path}/{entry}")
            # Some configurations, especially for recomposition, are namespaced within folders.
            elif os.path.isdir(configuration_path / entry):
                config_index[entry] = dict()
                for config in os.listdir(configuration_path / entry):
                    configuration = toml.load(
                        open(configuration_path / entry / config, encoding="utf-8")
                    )
                    config = configuration.get("tide", {}).get(
                        "identifier"
                    ) or config.removesuffix(".toml")
                    config_index[entry][config] = configuration

        return config_index

    ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

    # We need to hardcode these paths as they aer static, and must be 
    # used as a final reference point to prevent circular executions 
    CORE_CONFIGURATION_PATH = ROOT / "Configurations"
    CUSTOM_CONFIGURATIONS_PATH = ROOT.parent / "Configurations"
    
    core_configs = fetch_configs(CORE_CONFIGURATION_PATH)
    unified_configs = (
        core_configs.copy()
    )  # Copy since deep merge modifies the dict in place
    custom_configs = fetch_configs(CUSTOM_CONFIGURATIONS_PATH)

    deep_merge(unified_configs, custom_configs)

    return unified_configs

@overload
def resolve_paths(separate:Literal[True]) -> Tuple[dict[str, Path], dict[str, Path]]:
    ...
@overload
def resolve_paths(separate:Literal[False]) -> dict[str, Path]:
    ...
@overload
def resolve_paths() -> dict[str, Path]:
    ...
def resolve_paths(separate:bool=False):
    """
    Interface to provide absolute paths from configurations, after reconciling the
    them. Tide Paths are directed at the top level instance into which Tide
    is injected. Core Paths are internal paths to the Tide repo.

    When `separate=False`, returns a flattened dict of all paths for easier consumption
    """
    
    ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
    # Fetch configs, as paths may have been modified by the custom config
    CONFIGS = resolve_configurations()
    TIDE_CONFIG = CONFIGS["global"]

    TIDE_PATHS = {
        k: (ROOT.parent / path) for k, path in TIDE_CONFIG["paths"]["tide"].items()
    }
    CORE_PATHS = {k: (ROOT / path) for k, path in TIDE_CONFIG["paths"]["core"].items()}

    if separate:
        return TIDE_PATHS, CORE_PATHS
    else:
        return TIDE_PATHS | CORE_PATHS


def safe_file_name(string: str, safe_mode: bool = True) -> str:
    """
    Removes forbidden path character based on automatic OS detection.
    Useful when using human-written names to write a file name without running into
    OS issues.

    safe_mode removes all characters that are problematic across all platforms.
    """

    cleaned_string = str()

    FORBIDDEN_WINDOWS_ASCII = [">", "<", ":", '"', "\\", "/", "|", "?", "*"]
    FORBIDDEN_LINUX_ASCII = ["/"]

    if safe_mode:
        forbidden_characters = FORBIDDEN_WINDOWS_ASCII
        forbidden_characters.extend(FORBIDDEN_LINUX_ASCII)
        for char in string:
            if char not in forbidden_characters:
                cleaned_string += char

    else:
        platform = sys.platform
        if platform.startswith("linux"):
            for char in string:
                if char not in FORBIDDEN_LINUX_ASCII:
                    cleaned_string += char

        elif platform.startswith("win32"):
            for char in string:
                if char not in FORBIDDEN_WINDOWS_ASCII:
                    cleaned_string += char

    return cleaned_string


# DEBUG Check resulting configuration
#with open("config_out.json", "w+") as DEBUG:
#    json.dump(resolve_configurations(), DEBUG, indent=4)
