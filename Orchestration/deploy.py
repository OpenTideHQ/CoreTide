import yaml
import os
import git
import re
import sys
import traceback

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.deployment import (enabled_systems,
                                        modified_mdr_files,
                                        make_deploy_plan,
                                        DeploymentStrategy,
                                        CIEnvironment)
from Engines.modules.logs import log, ANSI, coretide_intro
from Engines.modules.tide import IndexTide
from Engines.mutation.promotion import PromoteMDR


os.environ["INDEX_OUTPUT"] = "cache"

print(coretide_intro())
print(f"""
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
CoreTide Detection Deployment
{ANSI.Formatting.STOP}
""")

DEPLOYMENT_PLAN = DeploymentStrategy.load_from_environment()

# Status promotion, happening before the main deployment loop
if DEPLOYMENT_PLAN is DeploymentStrategy.PRODUCTION:
    pre_deployment = modified_mdr_files(DEPLOYMENT_PLAN)
    log("TITLE", "Pre-deployment Routine")
    PromoteMDR().promote(pre_deployment)


# Refetches the deployment plan, so it can read the MDR after modification
# and assess the correct latest status
deployment_list = make_deploy_plan(DEPLOYMENT_PLAN)  # type: ignore

if len(deployment_list) == 0:  # In case of no deployments possible, fail graciously
    environment = CIEnvironment().environment
    log("FAILURE",
        "Nothing could deploy, no MDR can be addressed within this deployment context",
        "This may not be an issue if you didn't intend a deployment")

    # We only exit with a specific error code for Gitlab CI
    # as it will be caught by the pipeline and will warn the job
    # that it has failed, but not block the pipeline.
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        traceback.print_exc()
        sys.exit(19)
    elif environment is CIEnvironment.CIPlatforms.GitHubActions:
        # GitHub Actions does not support exit codes, so we use a warning
        # to indicate that no deployment was identified.
        print("::warning::No deployment was identified in this context")
        exit(0)
    else:
        exit()

# Need reindexation after MDR promotion is complete.
IndexTide.reload()

# Need to import later so DataTide has been correctly
# Refreshed post-promotion, and thus can correctly set
# global modules variables.
from Engines.modules.plugins import DeployTide

for system in deployment_list:
    log("TITLE", "MDR Deployment")
    log(
        "INFO",
        "Deploy MDR onto the system they target, if allowed at the instance level and deployment context",
    )

    if system in DeployTide.mdr:
        try:
            log("ONGOING",
                "Deploying MDR for target system",
                system,
                "Using MDRv3 standard methods")
            DeployTide.mdr[system].deploy(deployment=deployment_list[system])
        except:
            log("WARNING", "Switching to MDRv4 new methods")
            log("ONGOING",
                "Deploying MDR for target system",
                system,
                "Using MDRv4 new methods")
            DeployTide.mdr[system].deploy(mdr_deployment=deployment_list[system], #type: ignore
                                          deployment_plan=DEPLOYMENT_PLAN) #type: ignore

    else:
        log(
            "FATAL",
            f"Cannot find a deployement engine for the target system {system}",
            "Ensure there is an adequate plugin present in the Tide Instance",
        )
        raise (Exception("DEPLOYMENT ENGINE NOT FOUND"))

if os.environ.get("DEPLOYMENT_ERROR_RAISED"):
    log(
        "FATAL",
        "Some deployment scripts failed.",
        "Review the error logs to discover the problem",
    )
    raise Exception("Deployment Failed")

if os.environ.get("DEPLOYMENT_WARNING_RAISED"):
    environment = CIEnvironment().environment
    log("WARNING", "Passed deployment, but with some warning", 
                "Review the warning logs to discover the problem")

    # We only exit with a specific error code for Gitlab CI
    # as it will be caught by the pipeline and will warn the job
    # that it has failed, but not block the pipeline.
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)

else:
    log("SUCCESS", "All content passed validation")
