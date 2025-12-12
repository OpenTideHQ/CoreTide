import yaml
import os
import git
import sys
import toml
import ast

from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Engines.modules.logs import log
from Engines.modules.files import resolve_configurations, resolve_paths
import re

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

CONFIGURATIONS = resolve_configurations()
PATHS = resolve_paths()

DEPLOYMENT_CONFIG = CONFIGURATIONS["deployment"]

PROMOTION_ENABLED = DEPLOYMENT_CONFIG["promotion"].get("enabled")
PROMOTION_TARGET = DEPLOYMENT_CONFIG["promotion"].get("promotion_target")

if (os.environ.get("DEBUG") == True or os.environ.get("TERM_PROGRAM") == "vscode"):
    DEBUG = True
else:
    DEBUG = False


#TODO Rework Promotion to consume from DataTide
def get_valid_statuses() -> list[str]:
    """
    Retrieve a list of all valid status names from the deployment configuration.
    
    This function parses the deployment status configurations and returns a list
    of all defined status names, regardless of their strategy.
    
    Returns:
        list[str]: A list of all valid status names defined in the configuration.
        
    Raises:
        Exception: If the "statuses" configuration cannot be resolved from the deployment
                  configuration.
        Exception: If a status definition is missing the "name" field.
    
    Note:
        This function depends on a global CONFIGURATIONS dictionary containing deployment
        configuration with a "statuses" key that holds a list of status definitions.
        Each status definition must contain a "name" field.
    """
    statuses_config = CONFIGURATIONS["deployment"].get("statuses")
    if not statuses_config:
        raise Exception("Could not resolve status definitions")
    
    valid_statuses = []
    for status in statuses_config:
        name = status.get("name")
        if not name:
            raise Exception(f"Missing name in status definition: {str(status)}")
        valid_statuses.append(name)
        log("INFO", "Found valid status", name)
    
    return valid_statuses

def get_non_promotable_statuses()->list[str]:
    """
    Retrieve a list of status names that are considered non-promotable based on their strategy.
    This function parses the deployment status configurations and identifies statuses
    that have strategies of type "RELEASE", "DELETION", or "DISABLEMENT". These statuses
    are considered non-promotable and their names are collected into a list.
    Returns:
        list[str]: A list of status names that are non-promotable. Returns an empty list
                   if no non-promotable statuses are found.
    Raises:
        Exception: If the "statuses" configuration cannot be resolved from the deployment
                   configuration.
        Exception: If a status definition is missing the "strategy" field.
        Exception: If a status definition is missing the "name" field.
    Note:
        This function depends on a global CONFIGURATIONS dictionary containing deployment
        configuration with a "statuses" key that holds a list of status definitions.
        Each status definition must contain "name" and "strategy" fields.
    """
    non_editable_statuses = list()

    statuses_config = CONFIGURATIONS["deployment"].get("statuses")
    if not statuses_config:
        raise Exception("Could not resolve status definitions")

    for status in statuses_config:
        strategy = status.get("strategy")
        name = status.get("name")
        if not strategy:
            raise Exception(f"Missing strategy in status definition : ", str(status))
        
        if not name:
            raise Exception(f"Missing name in status definition : ", str(status))

        if strategy in ["RELEASE", "DELETION", "DISABLEMENT"]:
            log("INFO", "Adding status as a non promotable status", name)
            non_editable_statuses.append(name)

    return non_editable_statuses

# Get list of all valid statuses from configuration
VALID_STATUSES = get_valid_statuses()

# Get list of statuses that cannot be promoted
NON_PROMOTABLE_STATUSES = get_non_promotable_statuses()

class PromoteMDR:
    """
    If enabled by config, dynamically re-assigns non-production statuses
    towards new targets
    """
    def edit_mdr_statuses(self, mdr_path:Path, status_to_promote:list):

        # We modify the file as text instead of loading and dumping the yaml
        # as formatting or comments are not always preserved, for small
        # modifications such as this one it's preferable to do in this way.

        with open(mdr_path, "r", encoding="utf-8") as file:
            buffer = []
            crossed = False
            for line in file:

                # Ensure that only data after crossing the configurations point is modified
                # in rare cases where the description contains some mentions of the status,
                # and may introduce confusion if mistakenly modified.
                if "configurations" in line:
                    crossed = True

                if crossed:
                    if re.search(r'status\s*:\s*', line):
                        for word in status_to_promote:
                            if word in line:
                                line = line.replace(word, PROMOTION_TARGET)
                buffer.append(line)

        with open(mdr_path, "w", encoding="utf-8") as file:
            for line in buffer:
                file.write(line)

        log("SUCCESS", f"Successfully promoted MDR to {PROMOTION_TARGET}")


    def promote(self, deployment:list[Path]):
        log("TITLE", "MDR Status Promotion")
        log("INFO", "Promotes the status of modified MDR files according to configuration")

        if PROMOTION_ENABLED:

            if PROMOTION_TARGET not in VALID_STATUSES:
                log(
                    "FAILURE",
                    "The target status defined in the config is not a valid status",
                    PROMOTION_TARGET,
                    f"Valid statuses are in the statuses definitions : {', '.join(VALID_STATUSES)}",
                )
                exit()

            if DEBUG:
                MDR_FOLDER = ROOT / PATHS["mdr"]
                deployment = [MDR_FOLDER / mdr for mdr in sorted(os.listdir(MDR_FOLDER))]

            else:
                # Fetch MDR in the deployment diff calculation
                  # Returns string expression into list object
                if not deployment:
                    log(
                        "SKIP",
                        "Found nothing to deploy in PRE_DEPLOYMENT environment variable",
                    )
                    return

            for mdr in deployment:
                system_promotion = {}
                data = yaml.safe_load(open(mdr, encoding="utf-8"))
                mdr_name = data["name"]

                for system in (conf := data["configurations"]):
                    system_status = conf[system]["status"]

                    if system_status not in NON_PROMOTABLE_STATUSES:
                        system_promotion[system] = system_status

                if not system_promotion:
                    log("SKIP", "Nothing to promote, MDR already in Production status", mdr_name)
                else:
                    log(
                        "INFO",
                        "Detected statuses needing promotion for the following MDR",
                        mdr_name,
                    )
                    log(
                        "ONGOING",
                        "Promoting the following systems statuses",
                        ", ".join(
                            f"{key} : {value}" for key, value in system_promotion.items()
                        ),
                    )
                    statuses_to_replace = [system_promotion[s] for s in system_promotion]
                    self.edit_mdr_statuses(mdr, statuses_to_replace)

        else:
            log(
                "SKIP",
                "MDR Promotion disabled in config",
                advice="You can enable MDR Promotion under config>deployment>status>promotion",
            )

