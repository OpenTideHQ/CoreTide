import pandas as pd
from git.repo import Repo
from Engines.modules.framework import unroll_dot_dict
from Engines.modules.models import (
    TideDefinitionsModels,
    TideModels,
    SystemConfig,
    DeploymentStrategy,
    StatusStrategy,
    TenantDeployment,
    TenantDeploymentModel,
)
from Engines.modules.tide import DataTide, DetectionSystems, TideLoader, HelperTide
from Engines.modules.errors import TideErrors
from Engines.modules.debug import DebugEnvironment
from Engines.modules.logs import log
import sys
import os
import git
import yaml
import re
from typing import MutableMapping, Sequence
from enum import Enum, auto
from pathlib import Path
from dataclasses import asdict, dataclass

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.ci import CIEnvironment
from Engines.modules.git_repo import TideRepo

SYSTEMS_CONFIGS_INDEX = DataTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

def check_status(status_name:str)->StatusStrategy:
    statuses_definitions = DataTide.Configurations.Deployment.statuses
    for status in statuses_definitions:
        if status.name == status_name:
            if type(status.strategy) is str:
                return StatusStrategy[status.name]
            elif type(status.strategy) is StatusStrategy:
                return status.strategy
            else:
                log("FATAL",
                    "Could not return status strategy",
                    str(status),
                    str(type(status.strategy)))
                raise Exception

    log("FATAL",
        "Could not look up requested status in existing statuses",
        f"Requested status : {status_name}",
        f"Available statuses in deployment.toml : {statuses_definitions}")
    raise Exception


def make_deploy_plan(
    plan: DeploymentStrategy,
    wide_scope=False,
    keep_deprecated=True
) -> dict[str, list[str]]:
    """
    Algorithm which assembles the MDR to deploy, organized per system

    plan: Execution environment used to calculate the acceptable statuses
    wide_scope: If set to true, will return all statuses regardless of the plan.

    plan is still required if wide_scope is set to True as it configures the calculation
    algorithm behaviour. wide_scope is useful to validate all MDR regardless of statuses if
    using the deploy plan to calculate the MDR that were modified.
    """

    SYSTEMS_DEPLOYMENT = enabled_systems()

    log("INFO", "Compiling MDRs to deploy in plan", plan.name)
    if wide_scope:
        log(
            "WARNING",
            "Wide Scope has been enabled for the deployment plan calculation",
            "This will assemble the plan with no consideration for statuses. Use with caution.",
        )

    mdr_files = list()
    deploy_mdr = dict()

    if plan == "FULL":
        MDR_PATH = Path(DataTide.Configurations.Global.Paths.Tide.mdr)
        mdr_files = [MDR_PATH / mdr for mdr in os.listdir(MDR_PATH)]
        log(
            "ONGOING",
            "Redeploying complete MDR library",
            f"[{len(mdr_files)} MDR] are in scope",
        )

    else:
        mdr_files = modified_mdr_files(plan)

    for rule in mdr_files:
        data = yaml.safe_load(open(rule, encoding="utf-8"))
        name = data["name"]
        conf_data = data["configurations"]
        mdr_uuid = data.get("uuid") or data["metadata"]["uuid"]

        for system in conf_data:
            platform_status = conf_data[system]["status"]

            if system in SYSTEMS_DEPLOYMENT:
                if (
                    keep_deprecated is False
                    and check_status(platform_status) in DEPRECATED_STATUSES
                ):
                    log("SKIP",
                        f"Not keeping in deployment plan as {system} is set to a deprecated status",
                        platform_status)
                elif wide_scope:
                    deploy_mdr.setdefault(system, []).append(mdr_uuid)
                else:
                    if plan is DeploymentStrategy.PRODUCTION:
                        if (
                            (check_status(platform_status) is StatusStrategy.RELEASE) or 
                            (check_status(platform_status) is StatusStrategy.UNIVERSAL) or
                            (check_status(platform_status) is StatusStrategy.DISABLEMENT) or  
                            (check_status(platform_status) is StatusStrategy.DELETION)  
                        ):
                            deploy_mdr.setdefault(system, []).append(mdr_uuid)
                            log(
                                "SUCCESS",
                                f"[{system.upper()}][{
                                    platform_status
                                }] Identified MDR to deploy in {plan}",
                                name,
                            )
                        else:
                            log(
                                "WARNING",
                                f"[{system.upper()}][{
                                    platform_status
                                }] Skipping as cannot be deployed in {plan}",
                                name,
                            )

                    elif plan is DeploymentStrategy.STAGING:
                        if (
                            (check_status(platform_status) is StatusStrategy.PREVIEW) or 
                            (check_status(platform_status) is StatusStrategy.UNIVERSAL)
                        ):
                            deploy_mdr.setdefault(system, []).append(mdr_uuid)
                            log(
                                "SUCCESS",
                                f"[{system.upper()}][{
                                    platform_status
                                }] Identified MDR to deploy in {plan}",
                                name,
                            )
                        else:
                            log(
                                "WARNING",
                                f"[{system.upper()}][{
                                    platform_status
                                }] Skipping as cannot be deployed in {plan}",
                                name,
                            )

            else:
                log(
                    "FAILURE",
                    f"[{system.upper()}] is disabled and cannot be deployed to for",
                    name,
                )

    return deploy_mdr


def modified_mdr_files(plan: DeploymentStrategy) -> list[Path]:
    MDR_PATH = Path(DataTide.Configurations.Global.Paths.Tide.mdr)
    MDR_PATH_RAW = DataTide.Configurations.Global.Paths.Tide._raw["mdr"]
    MDR_PATH_RAW = MDR_PATH_RAW.replace(r"/", r"\/")

    mdr_path_regex = rf"^.*{MDR_PATH_RAW}[^\/]+(\.yaml|\.yml)$"
    mdr_files = [
        mdr.split("/")[-1]
        for mdr in diff_calculation(plan)
        if re.match(mdr_path_regex, mdr)
    ]
    # Extracting only the file name so it can be appended to MDR_PATH
    # which is absolute, and thus more reliable

    mdr_files = [(MDR_PATH / Path(f)) for f in mdr_files]
    log("INFO", "Computed modified MDR Files", str(mdr_files))
    return mdr_files


def diff_calculation(plan: DeploymentStrategy) -> list:
    """
    Calculates the files in scope of deployment based on the execution context.

    Limitation: Tied to certain Gitlab CI variables, need more separation
    to work in other environments

    In a Merge Request, the calculation will take in consideration
    the root of the MR and tip of the branch. In a direct commit to main, it will
    instead take the difference between the two last commits.

    stage: used to filter the paths computed

    """
    scope = list()

    TARGET_CI = CIEnvironment().environment

    repo = TideRepo().repository

    match TARGET_CI:
        case CIEnvironment.CIPlatforms.GitHubActions:
            log("INFO", "Identified GitHub Actions as the CI Runtime Platform")
            LATEST_COMMIT = os.getenv("GITHUB_SHA")


            if plan is DeploymentStrategy.PRODUCTION:
                commits = list(repo.iter_commits("HEAD", max_count=2))
                if len(commits) > 1:
                    BASE_COMMIT = commits[1].hexsha
                else:
                    return []

            elif plan is DeploymentStrategy.STAGING:
                repo.remotes.origin.fetch()
                source_branch = os.getenv("GITHUB_HEAD_REF")
                target_branch = os.getenv("GITHUB_BASE_REF")

                if not source_branch or not target_branch:
                    log(
                        "FATAL",
                        "Could not identify source and target branch using predefined Azure Pipeline variables",
                        "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
                        "Ensure this is runnning in a Pull Request pipeline",
                    )
                    raise KeyError

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                log(
                    "INFO",
                    "Identified source and target branch in the pull request",
                    f"source: {source_branch} -> target: {target_branch}",
                )
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    log(
                        "FATAL",
                        "Could not identify the base of the Pull Request",
                        "You may not have a sufficient Checkout Depth configuration",
                        "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR",
                    )
                    raise TideErrors

        case CIEnvironment.CIPlatforms.GitlabCI:
            log("INFO", "Identified Gitlab CI as the CI Runtime Platform")
            LATEST_COMMIT = os.getenv("CI_COMMIT_SHA")

            if plan is DeploymentStrategy.PRODUCTION:
                BASE_COMMIT = os.getenv("CI_COMMIT_BEFORE_SHA")
            elif plan is DeploymentStrategy.STAGING:
                BASE_COMMIT = os.getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
                # Allows the proper base commit calculation for Merged Result pipelines
                if os.getenv("CI_MERGE_REQUEST_EVENT_TYPE") == "merged_result":
                    log(
                        "INFO", "Currently running a diff calculation for merge results"
                    )
                    for commit in repo.iter_commits():
                        if commit.hexsha == os.getenv("CI_COMMIT_BEFORE_SHA"):
                            mr_correct_parent = commit.parents[1]
                            log(
                                "INFO",
                                "Current evaluating commit and found parent",
                                f"{commit.hexsha} | {commit.message}",
                                str(mr_correct_parent),
                            )
                            LATEST_COMMIT = mr_correct_parent
                            break
            else:
                log(
                    "FATAL",
                    f"Illegal Deployment Plan {
                        str(plan)
                    } passed to diff_calculation algorithm",
                )
                raise KeyError

        case CIEnvironment.CIPlatforms.AzurePipeline:
            log("INFO", "Identified Azure Pipeline as the CI Runtime Platform")
            LATEST_COMMIT = os.getenv("BUILD_SOURCEVERSION")

            if plan is DeploymentStrategy.PRODUCTION:
                commits = list(repo.iter_commits("HEAD", max_count=2))
                if len(commits) > 1:
                    BASE_COMMIT = commits[1].hexsha
                else:
                    return []

            elif plan is DeploymentStrategy.STAGING:
                repo.remotes.origin.fetch()
                source_branch = os.getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH")
                target_branch = os.getenv(
                    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME")

                if not source_branch or not target_branch:
                    log(
                        "FATAL",
                        "Could not identify source and target branch using predefined Azure Pipeline variables",
                        "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
                        "Ensure this is runnning in a Pull Request pipeline",
                    )
                    raise KeyError

                source_branch = source_branch.replace("refs/heads/", "")
                source_branch = "origin/" + source_branch
                target_branch = "origin/" + target_branch
                log(
                    "INFO",
                    "Identified source and target branch in the pull request",
                    f"source: {source_branch} -> target: {target_branch}",
                )
                base_commit = repo.merge_base(target_branch, source_branch)

                if base_commit[0]:
                    BASE_COMMIT = base_commit[0].hexsha
                else:
                    log(
                        "FATAL",
                        "Could not identify the base of the Pull Request",
                        "You may not have a sufficient OpenTide.Repo.Checkout.Depth configuration",
                        "If you run very old Pull Requests, this setting may need to be increased, or reopen a PR",
                    )
                    raise TideErrors

            else:
                log(
                    "FATAL",
                    f"Illegal Deployment Plan {
                        str(plan)
                    } passed to diff_calculation algorithm",
                )
                raise KeyError

        case _:
            log("FATAL", "Illegal CI Environment detected", str(TARGET_CI))

            raise Exception

    log(
        "INFO",
        "Setting source and target commit for the diff calculation to",
        f"{BASE_COMMIT} | {LATEST_COMMIT}",
    )

    source_commit = None
    try:
        source_commit = repo.commit(BASE_COMMIT)
    except Exception:
        log(
            "INFO",
            "Could not find source commit in current branch, trying iter_commits method",
        )
        remote_refs = repo.remote().refs

        for refs in remote_refs:
            log("INFO", refs.name)

        for commit in repo.iter_commits("origin/main"):
            log("INFO", "Currently Evaluating", f"{commit.message}")
            if commit.hexsha == BASE_COMMIT:
                source_commit = commit
                log(
                    "SUCCESS",
                    "Found source commit",
                    f"{commit.hexsha} | {commit.message}",
                )
                break

    if not source_commit:
        log("FATAL", "No Source Commit could be identified")
        raise Exception("No Source Commit Found")

    latest_commit = repo.commit(LATEST_COMMIT)
    diff = source_commit.diff(latest_commit)

    log(
        "INFO",
        "Preliminary diff calculation completed, returned with",
        ", ".join([f.b_path for f in diff]),
    )

    # Computing diff for added/renamed paths and modified files.
    # Deleted files are explicitely excluded to avoid attempting to deploy
    # something that is not material anymore.
    added_files = [f.b_path for f in diff.iter_change_type("A")]
    renamed_files = [f.b_path for f in diff.iter_change_type("R")]
    modified_files = [f.b_path for f in diff.iter_change_type("M")]

    scope = added_files + renamed_files + modified_files
    scope = list(
        set(scope)
    )  # De-duplicate - may happen if file modified and renamed, for example
    log("INFO", "Computed diff scope", ", ".join(scope))

    return scope


def enabled_systems() -> list[str]:
    enabled_systems = list()
    for system in SYSTEMS_CONFIGS_INDEX:
        try:
            if SYSTEMS_CONFIGS_INDEX[system]["tide"].get("enabled") is True:
                enabled_systems.append(system)
        except:
            if SYSTEMS_CONFIGS_INDEX[system]["platform"].get("enabled") is True:
                enabled_systems.append(system)

    return enabled_systems


class Proxy:
    """
    Encapsulates proxy setup for environment variables.

    Behavior:
    - Requires proxy_host and proxy_port
    - Uses proxy_user / proxy_password only when both are provided
    - Supports unauthenticated proxy URLs for hosts behind transparent proxies
    """

    @staticmethod
    def set_proxy():
        if DebugEnvironment.ENABLED and not DebugEnvironment.PROXY_ENABLED:
            # Debug mode explicitly has proxy setup disabled
            return

        log("ONGOING", "Setting environment proxy according to CI variables")
        PROXY_CONFIG = DataTide.Configurations.Deployment.proxy
        PROXY_CONFIG = HelperTide.fetch_config_envvar(PROXY_CONFIG)
        proxy_user = PROXY_CONFIG.get("proxy_user")
        proxy_pass = PROXY_CONFIG.get("proxy_password")
        proxy_host = PROXY_CONFIG.get("proxy_host")
        proxy_port = PROXY_CONFIG.get("proxy_port")

        if proxy_host and proxy_port:
            if proxy_user and proxy_pass:
                proxy = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
            else:
                proxy = f"http://{proxy_host}:{proxy_port}"

            os.environ["HTTP_PROXY"] = proxy
            os.environ["HTTPS_PROXY"] = proxy
            log("SUCCESS", "Proxy environment setup successful")
        else:
            log(
                "FAILURE",
                "Could not retrieve mandatory proxy host and port",
                "Control that proxy_host and proxy_port are entered in CI variables",
                "proxy_user and proxy_password are optional",
            )

    @staticmethod
    def unset_proxy():
        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        log("INFO", "Resetting proxy setup")


class ExternalIdHelper:
    """
    Utility class to help processing external rule IDs in MDR Files
    """

    @staticmethod
    def remove_id(rule_id: int | str, tenant_name: str, mdr_uuid: str):
        """
        Removes an existing external ID. Mostly used in rule deletion workflows
        """
        file_path = (
            DataTide.Configurations.Global.Paths.Tide.mdr
            / DataTide.Models.files[mdr_uuid]
        )
        with open(file_path, "r", encoding="utf-8") as mdr_file:
            content = mdr_file.readlines()

        updated_content = list()

        # Remove previous rule ID from file
        for line in content:
            if line.strip() != f"rule_id::{tenant_name}: {rule_id}":
                updated_content.append(line)

        with open(file_path, "w", encoding="utf-8") as mdr_file:
            log("SUCCESS", f"Removed ID in MDR File for tenant {tenant_name}")
            mdr_file.writelines(updated_content)

    @staticmethod
    def insert_id(
        rule_id: int | str, tenant_name: str, mdr_uuid: str, system_name: str
    ):
        """
        Adds a new rule_id::<tenant>::<id> key to store IDs generated by the target system
        """
        file_path = (
            DataTide.Configurations.Global.Paths.Tide.mdr
            / DataTide.Models.files[mdr_uuid]
        )
        with open(file_path, "r", encoding="utf-8") as mdr_file:
            content = mdr_file.readlines()

        updated_content = list()
        for line in content:
            if line.strip().removesuffix(":").strip() == system_name:
                updated_content.append(line)
                updated_content.append(
                    f"    rule_id::{tenant_name}: {rule_id}\n")
            else:
                updated_content.append(line)

        with open(file_path, "w", encoding="utf-8") as mdr_file:
            print(updated_content)
            mdr_file.writelines(updated_content)
            log(
                "SUCCESS",
                f"Updated MDR File with new ID for tenant {tenant_name}",
                str(rule_id),
            )

