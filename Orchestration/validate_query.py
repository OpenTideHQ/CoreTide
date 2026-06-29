import traceback
import sys
import git
import os

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.deployment import (
    make_deploy_plan,
    DeploymentStrategy,
    CIEnvironment,
)
from Engines.modules.logs import log, ANSI, coretide_intro
from Engines.modules.plugins import DeployTide
from Engines.modules.tide import DataTide

print(coretide_intro())
print(f"""
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
CoreTide Detection Rules Query Validation
{ANSI.Formatting.STOP}
""")

DEPLOYMENT_PLAN = DeploymentStrategy.load_from_environment()

# Refetches the deployment plan, so it can read the MDR after modification
# and assess the correct latest status
deployment_list = make_deploy_plan(
    DEPLOYMENT_PLAN,
    wide_scope=True,
    keep_deprecated=False
    )  # type: ignore
if len(deployment_list) == 0:  # In case of no deployments possible, fail graciously
    log(
        "WARNING",
        "Nothing could deploy, no MDR can be addressed within this deployment context",
    )
    traceback.print_exc()

for system in deployment_list:
    try:
        system_name = DataTide.Configurations.Systems.Index[system]["tide"]["name"]
    except:
        system_name = DataTide.Configurations.Systems.Index[system]["platform"]["name"]

    log("TITLE", f"Query Validation - {system_name}")
    log("INFO", "Validating the query in the MDR against the system")

    if system in DeployTide.query_validation:
        log("ONGOING", f"Validating the query against {system_name}")
        DeployTide.query_validation[system].validate(
            mdr_deployment=deployment_list[system],
            deployment_plan=DEPLOYMENT_PLAN
        )
    else:
        log(
            "SKIP",
            f"Cannot find a query validation engine for the target system {
                system}",
            "Ensure there is an adequate plugin present in the Tide Instance",
        )

if os.environ.get("VALIDATION_ERROR_RAISED"):
    log(
        "FATAL",
        "Some validation scripts failed.",
        "Review the error logs to discover the problem",
    )
    raise Exception("Validation Failed")

if os.environ.get("VALIDATION_WARNING_RAISED"):
    environment = CIEnvironment().environment
    log(
        "WARNING",
        "Passed validation, but with some warning",
        "Review the warning logs to discover the problem",
    )

    # We only exit with a specific error code for Gitlab CI
    # as it will be caught by the pipeline and will warn the job
    # that it has failed, but not block the pipeline.
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)
else:
    log("SUCCESS", "All content successfully passed validation")
