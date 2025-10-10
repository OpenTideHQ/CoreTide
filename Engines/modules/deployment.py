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
from Engines.modules.tide import DataTide, DetectionSystems, TideLoader
from Engines.modules.errors import TideErrors
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, HelperTide
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


SYSTEMS_CONFIGS_INDEX = DataTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION,
                        StatusStrategy.DISABLEMENT)


class TideRepo:

    def __init__(self):
        self.repository = self._initialize_repository()
        self.last_commit_details = self._latest_commit_information()
    
    @dataclass
    class LatestCommit:
        message: str
        author: str
        sha: str

    def _initialize_repository(self)->git.Repo:
        TARGET_CI = CIEnvironment().environment
        match TARGET_CI:
            case CIEnvironment.CIPlatforms.GitHubActions:
                log("INFO", "Identified GitHub Actions as the CI Runtime Platform")
                REPO_DIR = os.getenv("GITHUB_WORKSPACE")
            case CIEnvironment.CIPlatforms.GitlabCI:
                log("INFO", "Identified Gitlab CI as the CI Runtime Platform")
                REPO_DIR = os.getenv("CI_PROJECT_DIR")
            case CIEnvironment.CIPlatforms.AzurePipeline:
                log("INFO", "Identified Azure Pipeline as the CI Runtime Platform")
                REPO_DIR = os.getenv("BUILD_SOURCESDIRECTORY")
            case CIEnvironment.CIPlatforms.LocalDebug:
                return None #type: ignore
        log("INFO",
            "Will initialize repository located on",
            str(REPO_DIR))

        return Repo(REPO_DIR)


    def _latest_commit_information(self)->LatestCommit:
        
        if CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug:
            return self.LatestCommit(message = "Sample Commit Message",
                                    author = "Sample Commit Author",
                                    sha = "Sample Commit SHA")
        commit = self.repository.head.commit
        return self.LatestCommit(message = str(commit.message.strip()),
                                 author = str(commit.author.name),
                                 sha = str(commit.hexsha))


class CIEnvironment:
    """
    Returns the CI Environment based on the environment variables
    """

    def __init__(self):
        self.environment = self._check_ci_environment()

    class CIPlatforms(Enum):
        """
        Represents the supported CI options
        """

        AzurePipeline = auto()
        GitlabCI = auto()
        GitHubActions = auto()
        LocalDebug = auto()        

    def _check_ci_environment(self) -> CIPlatforms:
        if os.getenv("TF_BUILD"):
            log("SUCCESS", "Discovered CI Environment to be Azure Pipeline")
            return self.CIPlatforms.AzurePipeline
        elif os.getenv("GITHUB_ACTIONS"):
            log("SUCCESS", "Discovered CI Environment to be GitHub Actions")
            return self.CIPlatforms.GitHubActions
        elif os.getenv("CI"):
            log("SUCCESS", "Discovered CI Environment to be Gitlab CI")
            return self.CIPlatforms.GitlabCI
        elif HelperTide.is_debug():
            log("SUCCESS", "Discover CI Environment to be Local")
            return self.CIPlatforms.LocalDebug
        else:
            log(
                "FATAL",
                "CI Target environment variable is not implemented",
                "Ensure that you have configured a variable OpenTide.TargetCi as part of your pipeline",
                "Current supported values: GitlabCI, AzurePipelines, GitlabActions, LocalDebug",
            )
            raise Exception




def check_status(status_name:str)->StatusStrategy:
    statuses = DataTide.Configurations.Deployment.statuses
    for status in statuses:
        if status.name == status_name:
            if status.strategy is str:
                return StatusStrategy[status.name]
            elif status.strategy is StatusStrategy:
                return status.strategy
            else:
                log("FATAL",
                    "Could not return status strategy",
                    str(status))
                raise Exception

    log("FATAL",
        "Could not look up requested status in existing statuses",
        f"Requested status : {status_name}",
        f"Available statuses in deployment.toml : {statuses}")
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
                        if check_status(platform_status) is StatusStrategy.PRODUCTION:
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
                            check_status(platform_status) not in (StatusStrategy.PRODUCTION, StatusStrategy.INERT) 
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


def enabled_lookup_systems() -> list[str]:
    enabled_lookup_systems = list()
    for system in SYSTEMS_CONFIGS_INDEX:
        if SYSTEMS_CONFIGS_INDEX[system].get("lookups", {}).get("enabled") is True:
            enabled_lookup_systems.append(system)

    return enabled_lookup_systems


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
    Simple class to encapulate configuring the proxy in
    environment variables
    """

    @staticmethod
    def set_proxy():
        if DebugEnvironment.ENABLED and not DebugEnvironment.PROXY_ENABLED:
            pass
        else:
            log("ONGOING", "Setting environment proxy according to CI variables")
            PROXY_CONFIG = DataTide.Configurations.Deployment.proxy
            PROXY_CONFIG = HelperTide.fetch_config_envvar(PROXY_CONFIG)
            proxy_user = PROXY_CONFIG["proxy_user"]
            proxy_pass = PROXY_CONFIG["proxy_password"]
            proxy_host = PROXY_CONFIG["proxy_host"]
            proxy_port = PROXY_CONFIG["proxy_port"]
            if proxy_host and proxy_port and proxy_user and proxy_pass:
                proxy = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
                os.environ["HTTP_PROXY"] = proxy
                os.environ["HTTPS_PROXY"] = proxy
                log("SUCCESS", "Proxy environment setup successful")
            else:
                log(
                    "FAILURE",
                    "Could not retrieve all proxy information",
                    "Control that all proxy infos are entered in CI variables",
                    "Expects proxy_user, proxy_password, proxy_host and proxy_port",
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


class TideDeployment:
    def __init__(self, deployment, system: DetectionSystems, strategy):
        match system:
            case DetectionSystems.SPLUNK:
                self.rule_deployment: Sequence[TenantDeployment.Splunk] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )  
            case DetectionSystems.SENTINEL:
                self.rule_deployment: Sequence[TenantDeployment.Sentinel] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy) 
                )
            case DetectionSystems.CARBON_BLACK_CLOUD:
                self.rule_deployment: Sequence[TenantDeployment.CarbonBlackCloud] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionSystems.DEFENDER_FOR_ENDPOINT:
                self.rule_deployment: Sequence[TenantDeployment.DefenderForEndpoint] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionSystems.SENTINEL_ONE:
                self.rule_deployment: Sequence[TenantDeployment.SentinelOne] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                ) 
            case DetectionSystems.CROWDSTRIKE:
                self.rule_deployment: Sequence[TenantDeployment.Crowdstrike] = (
                    self.deployment_resolver(deployment, system, strategy) # type:ignore
                )
            case _:
                raise NotImplementedError(
                    f"System {system} is not implemented by TideDeployment"
                )

    def system_configuration_resolver(self, system: DetectionSystems):  # type:ignore
        match system:
            # case DetectionSystems.SPLUNK:
            #    return DataTide.Configurations.Systems.Splunk
            # case DetectionSystems.CARBON_BLACK_CLOUD:
            #    return DataTide.Configurations.Systems.CarbonBlackCloud
            case DetectionSystems.SENTINEL:
                return DataTide.Configurations.Systems.Sentinel
            case DetectionSystems.DEFENDER_FOR_ENDPOINT:
                return DataTide.Configurations.Systems.DefenderForEndpoint
            case DetectionSystems.SENTINEL_ONE:
                return DataTide.Configurations.Systems.SentinelOne
            case DetectionSystems.CROWDSTRIKE:
                return DataTide.Configurations.Systems.Crowdstrike
            # case _:
            #    raise NotImplemented

    def mdr_configuration_resolver(
        self, data: TideModels.MDR, system: DetectionSystems
    ) -> TideDefinitionsModels.SystemConfigurationModel:
        match system:
            case DetectionSystems.SENTINEL:
                mdr_config = data.configurations.sentinel
            case DetectionSystems.DEFENDER_FOR_ENDPOINT:
                mdr_config = data.configurations.defender_for_endpoint
            case DetectionSystems.SENTINEL_ONE:
                mdr_config = data.configurations.sentinel_one
            case DetectionSystems.CROWDSTRIKE:
                mdr_config = data.configurations.crowdstrike
            case _:
                log(
                    "FATAL",
                    "Could not resolve mdr configuration for system",
                    str(system),
                )
                raise Exception(NotImplemented)

        if not mdr_config:
            log(
                "FAILURE",
                "Was not able to retrieve MDR configuration for targeted system",
                f"[{data.metadata.uuid}] {data.name} - Available configurations : [{
                    str(data.configurations)
                }]",
            )
            raise Exception(NotImplemented)

        return mdr_config

    def tenants_resolver(
        self,
        data: TideModels.MDR,
        system: DetectionSystems,
        deployment_strategy: DeploymentStrategy,
    ) -> Sequence[SystemConfig.Tenant]:
        """
        Returns a list of all the tenants configurations, if they are allowed to be targeted.
        - If ALWAYS, will be targeted on every deployment
        - If MANUAL, can only be targeted if defined in the MDR
        - If STAGING or PRODUCTION, can only be targeted if the current deployment plan alligns with it
        """
        tenants = self.system_configuration_resolver(
            system).tenants  # type: ignore
        mdr_tenants = self.mdr_configuration_resolver(data, system).tenants
        target_tenants = list()

        log(
            "ONGOING",
            "Currently resolving available tenant deployments for rule",
            data.name,
            data.metadata.uuid,
        )

        if not tenants:
            log(
                "FATAL",
                "Missing tenant configuration for enabled system",
                system.name,
                "Review the system configuration and ensure you have at least one tenant",
            )
            raise Exception

        for tenant in tenants:

            # Resolve tenant deployments when they are specific or not in the MDR spec
            if mdr_tenants:
                log(
                    "INFO",
                    "Found specific tenants targeted by rule",
                    data.name,
                    str(mdr_tenants),
                )

                if tenant.name in mdr_tenants:
                    if (
                        (tenant.deployment is DeploymentStrategy.MANUAL) or
                        (tenant.deployment is DeploymentStrategy.ALWAYS) or
                        (tenant.deployment is deployment_strategy)
                    ):
                        target_tenants.append(tenant)
                        log(
                            "SUCCESS",
                            f"Adding tenant {
                                tenant.name
                            } to the tenant deployment list",
                            f"Compatible with current deployment plan : {
                                deployment_strategy
                            }",
                        )
                    else:
                        log(
                            "SKIP",
                            f"Skipping tenant {
                                tenant.name
                            } as is not compatible with current deployment plan",
                            f"Tenant deployment plan : {
                                tenant.deployment
                            }, current deployment plan : {deployment_strategy.name}",
                        )
                else:
                    log(
                        "SKIP",
                        f"Skipping tenant {
                            tenant.name
                        } as is not defined by MDR tenant list",
                        str(mdr_tenants),
                    )

            else:
                log(
                    "INFO",
                    "Did not find tenants specified in detection rule, will resolve available ones",
                    data.name,
                )

                if tenant.deployment is DeploymentStrategy.MANUAL:
                    log(
                        "SKIP",
                        f"Skipping tenant {
                            tenant.name
                        } as can only be assigned within the MDR defined tenant",
                        "You can define custom target tenants under the tenants keyword",
                    )
                    continue

                elif ( 
                    (tenant.deployment is deployment_strategy) or
                    (tenant.deployment is DeploymentStrategy.ALWAYS)
                ):
                    target_tenants.append(tenant)
                    log(
                        "SUCCESS",
                        f"Adding tenant {
                            tenant.name} to the tenant deployment list",
                        f"Compatible with current deployment plan : {
                            deployment_strategy
                        }",
                    )
                else:
                    log(
                        "SKIP",
                        f"Skipping tenant {
                            tenant.name
                        } as is not compatible with current deployment plan",
                        f"Tenant deployment plan : {
                            tenant.deployment
                        }, current deployment plan : {deployment_strategy.name}",
                    )

        return target_tenants

    def _deep_update(
        self, base_dictionary: MutableMapping, updating_dictionary: MutableMapping
    ) -> MutableMapping:
        """
        Performs a deep nested mapping, so can combine dictionaries
        without overriding them
        """
        for key, value in updating_dictionary.items():
            if isinstance(value, MutableMapping):
                base_dictionary[key] = self._deep_update(
                    base_dictionary.get(key, {}), value
                )
            else:
                base_dictionary[key] = value
        return base_dictionary

    def modifiers_resolver(
        self, data: TideModels.MDR, target_tenant: str, system: DetectionSystems
    ) -> TideModels.MDR:
        """
        Dynamically modifies MDR data based on
        """

        system_configuration = self.system_configuration_resolver(system)
        modifiers = system_configuration.modifiers  # type: ignore
        mdr_config = self.mdr_configuration_resolver(data, system)
        system_identifier = system_configuration.platform.identifier  # type: ignore

        if not mdr_config:
            raise NotImplemented

        raw_data = asdict(data)
        raw_mdr_config = asdict(mdr_config)

        log("ONGOING", "Checking modifiers for system",
            str(system), str(modifiers))

        if modifiers:
            log("INFO", "Found modifiers in configuration for system", str(system))
            for mod in modifiers:
                log(
                    "ONGOING",
                    f"Evaluating modifier {str(mod.name)} {
                        str(mod.description)}",
                    str(mod.conditions),
                )

                match = False

                if mod.conditions.default:
                    if mod.conditions.default is True:
                        match = True

                if mod.conditions.status:
                    if mdr_config.status in mod.conditions.status:
                        match = True
                if mod.conditions.tenants:
                    if target_tenant in mod.conditions.tenants:
                        match = True
                    else:
                        match = False
                if mod.conditions.flags and mdr_config.flags:
                    if [tag for tag in mdr_config.flags if tag in mod.conditions.flags]:
                        match = True
                    else:
                        match = False

                if match is True:
                    log(
                        "INFO",
                        "Condition Matching",
                        str(mod.name or ""),
                        str(mod.description or ""),
                    )
                    flatten_modifications = pd.json_normalize(
                        mod.modifications # type: ignore
                    ).to_dict(orient="records")[0] 
                    for modification in flatten_modifications:
                        new_value = flatten_modifications[modification]
                        new_value = None if new_value in [
                            "NONE", "NULL"] else new_value
                        if new_value:
                            if type(new_value) is not str:
                                pass
                            elif "::" in new_value:
                                raw_mdr_config_flatten = pd.json_normalize(
                                    raw_mdr_config # type: ignore
                                ).to_dict(orient="records")[0]  
                                operator = new_value.split("::")[0]
                                value = new_value.split("::")[1]
                                log(
                                    "DEBUG",
                                    f"Found mod {modification} with operator {
                                        operator
                                    } with value {value}",
                                )
                                log("DEBUG", str(raw_mdr_config_flatten))
                                if modification in raw_mdr_config_flatten:
                                    log(
                                        "DEBUG",
                                        str(raw_mdr_config_flatten[modification]),
                                    )
                                    if operator == "prefix":
                                        new_value = value + (
                                            raw_mdr_config_flatten[modification] or ""
                                        )
                                    elif operator == "suffix":
                                        new_value = (
                                            raw_mdr_config_flatten[modification] or ""
                                        ) + value
                                    log("DEBUG", "Generated new value", new_value)
                                else:
                                    new_value = value

                        updated_config = unroll_dot_dict(
                            {modification: new_value})
                        log(
                            "ONGOING",
                            f"Applying modification {
                                modification} -> {str(new_value)}",
                        )
                        if updated_config:
                            raw_mdr_config = self._deep_update(
                                raw_mdr_config.copy(), updated_config # type: ignore
                            )  

        raw_data["configurations"].update({system_identifier: raw_mdr_config})
        log("INFO", "New recompiled modified deployment", str(raw_data))

        return TideLoader.load_mdr(raw_data)

    def deployment_resolver(
        self,
        mdr_deployment: Sequence[TideModels.MDR],
        system: DetectionSystems,
        deployment_strategy: DeploymentStrategy,
    ) -> Sequence[TenantDeploymentModel]:
        deployment = list()
        tenants_data = dict()
        tenants_mapping = dict()

        for mdr in mdr_deployment:
            if type(mdr) is str:
                mdr = DataTide.Models.MDR[mdr]

            tenants = self.tenants_resolver(mdr, system, deployment_strategy)

            for tenant in tenants:
                tenants_data[tenant.name] = tenant
                tenants_mapping.setdefault(tenant.name, []).append(
                    self.modifiers_resolver(
                        data=mdr, target_tenant=tenant.name, system=system
                    )
                )

        for tenant in tenants_mapping:
            deployment.append(
                TenantDeploymentModel(
                    tenant=tenants_data[tenant], rules=tenants_mapping[tenant]
                )
            )

        return deployment
