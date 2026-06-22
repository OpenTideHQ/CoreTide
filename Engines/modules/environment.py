import os
import git
import sys
from pathlib import Path
import json
from typing import (
    Any,
    Dict,
    Literal,
    Mapping,
    Never,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)
from functools import cache
from abc import ABC
from importlib import import_module
from copy import deepcopy

from dataclasses import dataclass, asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.indexing.indexer import indexer
from Engines.modules.logs import log
from Engines.modules.models import (DetectionSystems,
                                    TideModels,
                                    TideDefinitionsModels,
                                    TideConfigs,
                                    SystemConfig)
from Engines.modules.patching import Tide2Patching
from Engines.modules.datamodels.objects import Objects
from Engines.modules.datamodels.configurations import Configurations

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
# Configuration Models. Used to facilitate type hinting
class HelperTide:
    @staticmethod
    def is_debug() -> bool:
        """
        Provides an interface to discover whether the current execution
        context is considered to be in a debugging scenario.
        """
        if (
            os.environ.get("DEBUG") == True
            or os.environ.get("TERM_PROGRAM") == "vscode"
        ):
            return True
        else:
            return False

    @staticmethod
    def fetch_config_envvar(config_secrets: dict[str,str]) -> dict[str, Any]:
        """Resolve and replace environment-variable placeholders in a config mapping.

        Many configuration files in TIDE use strings that begin with ``$`` to indicate
        that the real value should be read from an environment variable. This
        function walks the provided mapping and replaces any such placeholders
        with the corresponding environment value. It also prints debug guidance
        when running in debug mode and logs missing values.

        Args:
            config_secrets: A mapping of configuration keys to values. Values that
                are strings beginning with ``$`` will be treated as environment
                variable references and replaced with the variable's value.

        Returns:
            The same mapping (mutated in place) with placeholders replaced by
            environment values where applicable.

        Notes:
            - If a referenced environment variable is missing and the runtime is
              not in debug mode, a fatal log entry will be emitted and the
              function will mark that an environment variable error occurred.
            - When running in debug mode, a local helper module
              ``Engines.modules.local_secrets`` is imported (if present) to help
              set environment variables for local development.
        """
        #Allows to print all errors at once before raising exception
        missing_envvar_error = False
        
        if HelperTide.is_debug():
            try:
                import_module("Engines.modules.local_secrets")
            except:
                log("FAILURE",
                    "Could not find local python file at `Engines.modules.local_secrets` to set secret environment variables",
                    "Parts of this module may not work properly",
                    "Refer to the relevant TOML conguration file to find which variables may be necessary")


        for sec in config_secrets.copy():
            if not config_secrets[sec]:
                log("SKIP", "Did not found an entry for", sec,
                    "If there are deployment issue, review if it is relevant to configure")
                continue
            if type(config_secrets[sec]) == str:
                if config_secrets[sec].startswith("$"):
                    if config_secrets[sec].removeprefix("$") in os.environ:
                        env_variable = str(config_secrets.pop(sec)).removeprefix("$")
                        config_secrets[sec] = os.environ.get(env_variable, "")
                        log("SUCCESS", "Fetched environment secret", env_variable)
                    else:
                        if HelperTide.is_debug():
                            log("SKIP", 
                                "Could not find expected environment variable",
                                config_secrets[sec],
                                "Debug Mode identified, continuing - remember that this may break some deployments")
                        else:
                            log(
                                "FATAL",
                                "Could not find expected environment variable",
                                config_secrets[sec],
                                "Review configuration file and execution environment",
                            )
                            missing_envvar_error = True

        if missing_envvar_error:
            log("FATAL",
                "Some environment variable specified in configuration files were not found"
                "Review the previous errors to find which ones were missing",
                "Check your CI settings to ensure these environment variables are properly injected",
                "This may not be a critical issue, for example if you didn't enable a particular system")

        return config_secrets

