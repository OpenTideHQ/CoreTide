import os
from importlib import import_module
from typing import Any

from Engines.modules.logs import log


def debug_enabled() -> bool:
    """Return whether the current execution context is a debugging scenario."""
    return (
        os.environ.get("DEBUG") == True
        or os.environ.get("DEBUG_ENABLED") == "True"
        or os.environ.get("TIDE_DEBUG_ENABLED") == "True"
        or os.environ.get("TERM_PROGRAM") == "vscode"
    )


def fetch_config_envvar(config_secrets: dict[str, str]) -> dict[str, Any]:
    """Resolve environment-variable placeholders in a configuration mapping."""
    missing_envvar_error = False

    if debug_enabled():
        try:
            import_module("Engines.modules.local_secrets")
        except Exception:
            log(
                "FAILURE",
                "Could not find local python file at `Engines.modules.local_secrets` to set secret environment variables",
                "Parts of this module may not work properly",
                "Refer to the relevant TOML conguration file to find which variables may be necessary",
            )

    for sec in config_secrets.copy():
        if not config_secrets[sec]:
            log(
                "SKIP",
                "Did not found an entry for",
                sec,
                "If there are deployment issue, review if it is relevant to configure",
            )
            continue
        if type(config_secrets[sec]) == str:
            if config_secrets[sec].startswith("$"):
                if config_secrets[sec].removeprefix("$") in os.environ:
                    env_variable = str(config_secrets.pop(sec)).removeprefix("$")
                    config_secrets[sec] = os.environ.get(env_variable, "")
                    log("SUCCESS", "Fetched environment secret", env_variable)
                else:
                    if debug_enabled():
                        log(
                            "SKIP",
                            "Could not find expected environment variable",
                            config_secrets[sec],
                            "Debug Mode identified, continuing - remember that this may break some deployments",
                        )
                    else:
                        log(
                            "FATAL",
                            "Could not find expected environment variable",
                            config_secrets[sec],
                            "Review configuration file and execution environment",
                        )
                        missing_envvar_error = True

    if missing_envvar_error:
        log(
            "FATAL",
            "Some environment variable specified in configuration files were not found"
            "Review the previous errors to find which ones were missing",
            "Check your CI settings to ensure these environment variables are properly injected",
            "This may not be a critical issue, for example if you didn't enable a particular system",
        )

    return config_secrets


class HelperTide:
    """Legacy helper — prefer OpenTide.debug utilities."""

    is_debug = staticmethod(debug_enabled)
    fetch_config_envvar = staticmethod(fetch_config_envvar)
