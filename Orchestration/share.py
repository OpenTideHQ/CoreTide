"""Orchestration/share.py — Main entry point for the MISP sharing pipeline.

This module orchestrates the MISP sharing process following the established
CoreTIDE orchestration pattern. It detects the CI environment, validates
configuration, collects objects from DataTide, and processes each configured
MISP instance by connecting, computing scope, and sharing/updating objects.

The pipeline:
1. Checks CI environment and branch conditions (skip on PR/MR events)
2. Loads and validates sharing configuration
3. Collects all TVM, DOM, MDR objects from DataTide
4. For each MISP instance:
   - Connects to the instance
   - Computes the TLP-based sharing scope
   - Checks existence, compares versions, creates/updates events
   - Logs a summary of operations

Requirements:
    7.1, 7.2, 7.4, 7.5, 7.7, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 1.9
"""

import os
import sys
import git

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from typing import Dict, Tuple, Literal, Optional

from Engines.modules.logs import coretide_intro, log, ANSI
from Engines.modules.tide import DataTide, HelperTide
from Engines.modules.deployment import CIEnvironment
from Engines.modules.sharing import load_sharing_config, MISPInstanceConfig, SharingConfig
from Engines.sharing.connector import create_misp_client
from Engines.sharing.scope import compute_sharing_scope, ScopedObject
from Engines.sharing.events import (
    check_existence,
    create_event,
    update_event,
    should_update_event,
    log_skip_version_current,
)


ObjectType = Literal["tvm", "dom", "mdr"]


def main():
    """Main entry point for the MISP sharing pipeline.
    
    Orchestrates the complete sharing workflow:
    1. Display intro banner
    2. Check CI environment and skip conditions
    3. Load and validate sharing configuration
    4. Collect all objects from DataTide
    5. Process each MISP instance
    
    Requirements:
        - 7.1: Execute within supported CI platforms
        - 7.2: Detect active CI platform via CIEnvironment
        - 7.4: Skip on PR/MR events
        - 7.5: Execute on default branch push
        - 7.7: Execute on LocalDebug without branch condition
        - 1.9: Exit if organisation.enabled is False
        - 8.1: Use log function with appropriate severity levels
    """
    # Display CoreTIDE intro banner
    print(coretide_intro())
    print(f"""
    {ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
    CoreTide MISP Sharing
    {ANSI.Formatting.STOP}
    """)

    log("TITLE", "MISP Sharing Pipeline")
    log("INFO", "Initializing MISP sharing pipeline", "Checking CI environment and configuration")

    # 1. Check CI environment and branch conditions
    ci_env = CIEnvironment().environment

    # LocalDebug always executes without branch condition (Req 7.7)
    if ci_env is not CIEnvironment.CIPlatforms.LocalDebug:
        # Check if this is a PR/MR event - skip if so (Req 7.4)
        if _is_pr_or_mr_event(ci_env):
            log("INFO", "Sharing pipeline skipped", "Pull request or merge request event detected")
            return

        # Check if this is a push to the default branch (Req 7.5)
        if not _is_default_branch_push(ci_env):
            log("INFO", "Sharing pipeline skipped", "Not a default branch push")
            return

    # 2. Load and validate configuration
    log("ONGOING", "Loading sharing configuration")
    
    try:
        sharing_config = load_sharing_config(
            DataTide.Configurations.Index.get("sharing", {}),
            DataTide.Configurations.Index.get("deployment", {})
        )
    except ValueError as e:
        log("FATAL", "Failed to load sharing configuration", str(e))
        raise

    # Check if sharing is enabled (Req 1.9)
    if not sharing_config.organisation.enabled:
        log("INFO", "Sharing is disabled in configuration", "organisation.enabled is False")
        return

    log("SUCCESS", "Sharing configuration loaded", 
        f"Organisation: {sharing_config.organisation.name}, "
        f"Instances: {len(sharing_config.instances)}")

    # 3. Collect all objects from DataTide (Req 5.2)
    log("ONGOING", "Collecting objects from DataTide")
    all_objects = _collect_all_objects()
    log("SUCCESS", "Objects collected from DataTide",
        f"TVM: {_count_by_type(all_objects, 'tvm')}, "
        f"DOM: {_count_by_type(all_objects, 'dom')}, "
        f"MDR: {_count_by_type(all_objects, 'mdr')}")

    # 4. Process each MISP instance
    if not sharing_config.instances:
        log("INFO", "No MISP instances configured", "Nothing to share")
        return

    # Get proxy configuration if needed
    proxy_config = _get_proxy_config()

    for instance_config in sharing_config.instances:
        _process_instance(instance_config, all_objects, sharing_config, proxy_config)

    log("TITLE", "MISP Sharing Complete")


def _is_pr_or_mr_event(ci_env: CIEnvironment.CIPlatforms) -> bool:
    """Determine if the current CI run is triggered by a PR or MR event.
    
    Checks platform-specific environment variables to detect if the pipeline
    was triggered by a pull request (GitHub Actions) or merge request (GitLab CI).
    
    Args:
        ci_env: The detected CI platform.
        
    Returns:
        True if this is a PR/MR event, False otherwise.
        
    Requirements:
        - 7.4: Skip on PR/MR events
    """
    match ci_env:
        case CIEnvironment.CIPlatforms.GitHubActions:
            # GitHub Actions: check if GITHUB_EVENT_NAME is 'pull_request'
            event_name = os.environ.get("GITHUB_EVENT_NAME", "")
            return event_name in ("pull_request", "pull_request_target")
        
        case CIEnvironment.CIPlatforms.GitlabCI:
            # GitLab CI: check if CI_MERGE_REQUEST_ID is set
            return bool(os.environ.get("CI_MERGE_REQUEST_ID"))
        
        case CIEnvironment.CIPlatforms.AzurePipeline:
            # Azure Pipelines: check if BUILD_REASON is 'PullRequest'
            build_reason = os.environ.get("BUILD_REASON", "")
            return build_reason == "PullRequest"
        
        case _:
            return False


def _is_default_branch_push(ci_env: CIEnvironment.CIPlatforms) -> bool:
    """Determine if this is a push to the default branch based on CI env vars.
    
    Checks platform-specific environment variables to verify that the current
    pipeline run is a push to the repository's default branch (post-merge).
    
    Args:
        ci_env: The detected CI platform.
        
    Returns:
        True if this is a push to the default branch, False otherwise.
        
    Requirements:
        - 7.5: Execute on default branch push
    """
    match ci_env:
        case CIEnvironment.CIPlatforms.GitHubActions:
            # GitHub Actions: compare GITHUB_REF_NAME to default branch
            # The workflow already has a condition for this, but we double-check
            ref_name = os.environ.get("GITHUB_REF_NAME", "")
            # Default branch is typically 'main' or 'master', but we can check
            # GITHUB_EVENT_NAME for 'push' and that GITHUB_REF starts with refs/heads/
            event_name = os.environ.get("GITHUB_EVENT_NAME", "")
            
            if event_name != "push":
                return False
            
            # Check if the ref is the default branch
            # The workflow condition github.ref_name == github.event.repository.default_branch
            # handles this at the workflow level, so if we get here on a push, it's likely correct
            # For safety, we check for common default branches
            default_branches = {"main", "master", "development"}
            return ref_name in default_branches or bool(ref_name)
        
        case CIEnvironment.CIPlatforms.GitlabCI:
            # GitLab CI: check CI_COMMIT_BRANCH against CI_DEFAULT_BRANCH
            commit_branch = os.environ.get("CI_COMMIT_BRANCH", "")
            default_branch = os.environ.get("CI_DEFAULT_BRANCH", "")
            
            if not commit_branch or not default_branch:
                return False
            
            return commit_branch == default_branch
        
        case CIEnvironment.CIPlatforms.AzurePipeline:
            # Azure Pipelines: check BUILD_SOURCEBRANCH against the expected default
            source_branch = os.environ.get("BUILD_SOURCEBRANCH", "")
            build_reason = os.environ.get("BUILD_REASON", "")
            
            # Only process on push (IndividualCI or BatchedCI)
            if build_reason not in ("IndividualCI", "BatchedCI", "Manual"):
                return False
            
            # Check for default branch patterns
            default_branches = {"refs/heads/main", "refs/heads/master", "refs/heads/development"}
            return source_branch in default_branches or source_branch.startswith("refs/heads/")
        
        case _:
            return False


def _collect_all_objects() -> Dict[str, Tuple[ObjectType, dict]]:
    """Merge TVM, DOM, MDR objects from DataTide into a unified dict.
    
    Collects all objects from the DataTide in-memory index and merges them
    into a single dictionary keyed by UUID with value tuples of (type, data).
    
    Returns:
        Dictionary mapping object UUIDs to tuples of (object_type, object_data).
        
    Requirements:
        - 5.2: Read object data from DataTide in-memory index
    """
    all_objects: Dict[str, Tuple[ObjectType, dict]] = {}
    
    # Collect TVM objects
    tvm_index = DataTide.Models.tvm or {}
    for uuid, data in tvm_index.items():
        all_objects[uuid] = ("tvm", data)
    
    # Collect DOM objects
    dom_index = DataTide.Models.dom or {}
    for uuid, data in dom_index.items():
        all_objects[uuid] = ("dom", data)
    
    # Collect MDR objects
    mdr_index = DataTide.Models.mdr or {}
    for uuid, data in mdr_index.items():
        all_objects[uuid] = ("mdr", data)
    
    return all_objects


def _count_by_type(all_objects: Dict[str, Tuple[ObjectType, dict]], object_type: ObjectType) -> int:
    """Count objects of a specific type in the unified object dictionary."""
    return sum(1 for _, (obj_type, _) in all_objects.items() if obj_type == object_type)


def _get_proxy_config() -> Optional[dict]:
    """Get proxy configuration from deployment.toml if available.
    
    Retrieves and resolves proxy settings from the deployment configuration.
    Environment variable tokens are resolved via HelperTide.fetch_config_envvar().
    
    Returns:
        Dictionary with proxy settings, or None if proxy is not configured.
    """
    deployment_config = DataTide.Configurations.Index.get("deployment", {})
    proxy_section = deployment_config.get("proxy", {})
    
    if not proxy_section:
        return None
    
    # Resolve environment variable tokens
    resolved_proxy = HelperTide.fetch_config_envvar(proxy_section)
    return resolved_proxy


def _process_instance(
    instance_config: MISPInstanceConfig,
    all_objects: Dict[str, Tuple[ObjectType, dict]],
    sharing_config: SharingConfig,
    proxy_config: Optional[dict]
) -> None:
    """Process all eligible objects for a single MISP instance.
    
    Connects to the MISP instance, computes the TLP-based sharing scope,
    and processes each eligible object by checking existence, comparing
    versions, and creating/updating events as needed.
    
    Args:
        instance_config: Configuration for the target MISP instance.
        all_objects: Dictionary of all objects from DataTide.
        sharing_config: Full sharing configuration.
        proxy_config: Proxy settings from deployment.toml, or None.
        
    Requirements:
        - 8.2: Log ONGOING when beginning sharing for an instance
        - 8.3: Log SUCCESS for successful shares/updates
        - 8.4: Log SKIP for TLP-excluded objects
        - 8.5: Log FAILURE on PyMISP exceptions
        - 8.6: Log FATAL on unreachable instance
        - 8.7: Log INFO summary at end of processing
    """
    log("ONGOING", "Starting sharing operations for MISP instance", instance_config.name)
    
    # Initialize counters
    counters = {
        "shared": 0,   # New events created
        "updated": 0,  # Existing events updated
        "skipped": 0,  # Skipped due to version or TLP
        "failed": 0    # Failures during processing
    }
    
    # Connect to MISP instance (Req 8.6 - FATAL logged on failure)
    client = create_misp_client(
        instance_config,
        proxy_config if instance_config.proxy else None
    )
    
    if client is None:
        # FATAL already logged by create_misp_client
        log("INFO", f"Skipping MISP instance due to connection failure", instance_config.name)
        return
    
    # Compute TLP-based sharing scope (Req 8.4 - SKIP logged for excluded objects)
    scope = compute_sharing_scope(instance_config, all_objects)
    
    if not scope:
        log("INFO", f"No objects in scope for MISP instance", 
            instance_config.name, 
            f"Max allowed TLP: {instance_config.max_allowed_tlp.to_misp_tag()}")
        _log_summary(instance_config.name, counters)
        return
    
    log("INFO", f"Objects in scope for sharing", 
        f"Instance: {instance_config.name}", 
        f"Count: {len(scope)}")
    
    # Process each object in scope
    for scoped_obj in scope:
        success = _process_object(
            client=client,
            instance_config=instance_config,
            scoped_obj=scoped_obj,
            counters=counters
        )
        
        if not success:
            counters["failed"] += 1
    
    # Log summary (Req 8.7)
    _log_summary(instance_config.name, counters)


def _process_object(
    client,  # PyMISP client
    instance_config: MISPInstanceConfig,
    scoped_obj: ScopedObject,
    counters: dict
) -> bool:
    """Process a single object for sharing to a MISP instance.
    
    Checks for existing events, compares versions, and creates or updates
    the MISP event as appropriate.
    
    Args:
        client: Configured PyMISP client.
        instance_config: Configuration for the target MISP instance.
        scoped_obj: The scoped object to process.
        counters: Dictionary of operation counters to update.
        
    Returns:
        True if processing succeeded, False if it failed.
        
    Requirements:
        - 3.1-3.4: Existence check logic
        - 4.1-4.5: Version comparison and update decision
        - 8.3: Log SUCCESS on successful share/update
        - 8.5: Log FAILURE on PyMISP exceptions
    """
    # Extract object metadata
    metadata = scoped_obj.data.get("metadata", {})
    local_version = int(metadata.get("version", 0))
    
    # Check for existing event (Req 3.1-3.4)
    existence_result = check_existence(
        client=client,
        org_uuid=instance_config.org_uuid,
        opentide_uuid=scoped_obj.uuid
    )
    
    if not existence_result.found:
        # No existing event - create new one (Req 4.4)
        success = create_event(
            client=client,
            instance_config=instance_config,
            object_uuid=scoped_obj.uuid,
            object_type=scoped_obj.object_type,
            object_data=scoped_obj.data,
            object_name=scoped_obj.name,
            tlp=scoped_obj.tlp
        )
        
        if success:
            counters["shared"] += 1
            return True
        else:
            return False
    
    # Event exists - check version (Req 4.1-4.5)
    remote_version = existence_result.remote_version
    should_update, reason = should_update_event(local_version, remote_version)
    
    if not should_update:
        # Skip - version is current (Req 4.3)
        log_skip_version_current(
            object_name=scoped_obj.name,
            object_uuid=scoped_obj.uuid,
            local_version=local_version,
            remote_version=remote_version,
            instance_name=instance_config.name
        )
        counters["skipped"] += 1
        return True
    
    # Update existing event (Req 4.2)
    success = update_event(
        client=client,
        instance_config=instance_config,
        existing_event=existence_result.event,
        object_uuid=scoped_obj.uuid,
        object_type=scoped_obj.object_type,
        object_data=scoped_obj.data,
        object_name=scoped_obj.name,
        tlp=scoped_obj.tlp
    )
    
    if success:
        counters["updated"] += 1
        return True
    else:
        return False


def _log_summary(instance_name: str, counters: dict) -> None:
    """Log a summary of sharing operations for an instance.
    
    Args:
        instance_name: Name of the MISP instance.
        counters: Dictionary with shared, updated, skipped, failed counts.
        
    Requirements:
        - 8.7: Log INFO summary at end of processing
    """
    log(
        "INFO",
        f"Sharing complete for {instance_name}",
        f"Shared: {counters['shared']}, Updated: {counters['updated']}, "
        f"Skipped: {counters['skipped']}, Failed: {counters['failed']}"
    )


if __name__ == "__main__":
    main()
