"""Unit tests for orchestrator CI conditions and flow.

This module tests the MISP sharing pipeline orchestrator's behavior under
different CI environments, including PR/MR event skipping, default branch
push execution, LocalDebug execution, and disabled organisation handling.

**Validates: Requirements 7.1, 7.2, 7.4, 7.5, 7.6, 7.7**
"""

import sys
import uuid
import os
from unittest.mock import patch, MagicMock

import git
import pytest

# Add project root to path for imports
sys.path.insert(0, str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.deployment import CIEnvironment
from Engines.modules.sharing import (
    TLPLevel,
    MISPInstanceConfig,
    OrganisationConfig,
    SharingConfig,
)
from Orchestration.share import (
    _is_pr_or_mr_event,
    _is_default_branch_push,
    _collect_all_objects,
    _count_by_type,
    main,
)


# ============================================================================
# Helper factories
# ============================================================================

def make_sharing_config(
    enabled: bool = True,
    instances: list = None
) -> SharingConfig:
    """Create a SharingConfig for testing."""
    if instances is None:
        instances = []
    return SharingConfig(
        organisation=OrganisationConfig(
            enabled=enabled,
            name="Test Organisation",
            uuid=str(uuid.uuid4())
        ),
        instances=instances
    )


def make_misp_instance_config(name: str = "Test MISP") -> MISPInstanceConfig:
    """Create a MISPInstanceConfig for testing."""
    return MISPInstanceConfig(
        name=name,
        url="https://misp.example.org",
        token="test-token",
        org_uuid=str(uuid.uuid4()),
        max_allowed_tlp=TLPLevel.AMBER,
        mode="send",
        proxy=False,
        publish_on_change=False,
        verify_ssl=True
    )


# ============================================================================
# Tests for _is_pr_or_mr_event
# ============================================================================

class TestPRMREventDetection:
    """Test detection of PR/MR events across CI platforms.
    
    **Validates: Requirements 7.4**
    
    THE Sharing_Engine SHALL skip all sharing operations without error
    if the pipeline is triggered during a pull request or merge request event.
    """

    def test_github_actions_pr_event_detected(self):
        """Test that GitHub Actions PR events are detected.
        
        **Validates: Requirements 7.4**
        """
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "pull_request"
        }, clear=False):
            assert _is_pr_or_mr_event(ci_env) is True

    def test_github_actions_pr_target_event_detected(self):
        """Test that GitHub Actions pull_request_target events are detected.
        
        **Validates: Requirements 7.4**
        """
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "pull_request_target"
        }, clear=False):
            assert _is_pr_or_mr_event(ci_env) is True

    def test_github_actions_push_event_not_pr(self):
        """Test that GitHub Actions push events are not PR events.
        
        **Validates: Requirements 7.4**
        """
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "push"
        }, clear=False):
            assert _is_pr_or_mr_event(ci_env) is False

    def test_github_actions_no_event_name(self):
        """Test that missing GITHUB_EVENT_NAME is not a PR event."""
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        # Remove GITHUB_EVENT_NAME if it exists
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_EVENT_NAME"}
        with patch.dict(os.environ, env, clear=True):
            assert _is_pr_or_mr_event(ci_env) is False

    def test_gitlab_ci_mr_event_detected(self):
        """Test that GitLab CI MR events are detected.
        
        **Validates: Requirements 7.4**
        """
        ci_env = CIEnvironment.CIPlatforms.GitlabCI
        
        with patch.dict(os.environ, {
            "CI_MERGE_REQUEST_ID": "123"
        }, clear=False):
            assert _is_pr_or_mr_event(ci_env) is True

    def test_gitlab_ci_non_mr_event(self):
        """Test that GitLab CI non-MR events are not detected as PR events."""
        ci_env = CIEnvironment.CIPlatforms.GitlabCI
        
        # Remove CI_MERGE_REQUEST_ID if it exists
        env = {k: v for k, v in os.environ.items() if k != "CI_MERGE_REQUEST_ID"}
        with patch.dict(os.environ, env, clear=True):
            assert _is_pr_or_mr_event(ci_env) is False

    def test_azure_pipelines_pr_event_detected(self):
        """Test that Azure Pipelines PR events are detected.
        
        **Validates: Requirements 7.4**
        """
        ci_env = CIEnvironment.CIPlatforms.AzurePipeline
        
        with patch.dict(os.environ, {
            "BUILD_REASON": "PullRequest"
        }, clear=False):
            assert _is_pr_or_mr_event(ci_env) is True

    def test_azure_pipelines_non_pr_event(self):
        """Test that Azure Pipelines non-PR events are not detected as PR events."""
        ci_env = CIEnvironment.CIPlatforms.AzurePipeline
        
        with patch.dict(os.environ, {
            "BUILD_REASON": "IndividualCI"
        }, clear=False):
            assert _is_pr_or_mr_event(ci_env) is False

    def test_local_debug_never_pr_event(self):
        """Test that LocalDebug is never considered a PR event."""
        ci_env = CIEnvironment.CIPlatforms.LocalDebug
        
        assert _is_pr_or_mr_event(ci_env) is False


# ============================================================================
# Tests for _is_default_branch_push
# ============================================================================

class TestDefaultBranchPushDetection:
    """Test detection of default branch pushes across CI platforms.
    
    **Validates: Requirements 7.5**
    
    THE Sharing_Engine SHALL execute the full sharing operation sequence
    when the pipeline is triggered by a push to the repository default branch.
    """

    def test_github_actions_push_to_main(self):
        """Test that push to main branch is detected.
        
        **Validates: Requirements 7.5**
        """
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_NAME": "main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_github_actions_push_to_master(self):
        """Test that push to master branch is detected."""
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_NAME": "master"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_github_actions_push_to_development(self):
        """Test that push to development branch is detected."""
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_NAME": "development"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_github_actions_non_push_event(self):
        """Test that non-push events return False."""
        ci_env = CIEnvironment.CIPlatforms.GitHubActions
        
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF_NAME": "main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is False

    def test_gitlab_ci_push_to_default_branch(self):
        """Test that GitLab CI push to default branch is detected.
        
        **Validates: Requirements 7.5**
        """
        ci_env = CIEnvironment.CIPlatforms.GitlabCI
        
        with patch.dict(os.environ, {
            "CI_COMMIT_BRANCH": "main",
            "CI_DEFAULT_BRANCH": "main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_gitlab_ci_push_to_non_default_branch(self):
        """Test that GitLab CI push to non-default branch returns False."""
        ci_env = CIEnvironment.CIPlatforms.GitlabCI
        
        with patch.dict(os.environ, {
            "CI_COMMIT_BRANCH": "feature-branch",
            "CI_DEFAULT_BRANCH": "main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is False

    def test_gitlab_ci_missing_branch_env_vars(self):
        """Test that missing GitLab CI env vars return False."""
        ci_env = CIEnvironment.CIPlatforms.GitlabCI
        
        # Remove the env vars if they exist
        env = {k: v for k, v in os.environ.items() 
               if k not in ("CI_COMMIT_BRANCH", "CI_DEFAULT_BRANCH")}
        with patch.dict(os.environ, env, clear=True):
            assert _is_default_branch_push(ci_env) is False

    def test_azure_pipelines_push_to_main(self):
        """Test that Azure Pipelines push to main is detected.
        
        **Validates: Requirements 7.5**
        """
        ci_env = CIEnvironment.CIPlatforms.AzurePipeline
        
        with patch.dict(os.environ, {
            "BUILD_REASON": "IndividualCI",
            "BUILD_SOURCEBRANCH": "refs/heads/main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_azure_pipelines_push_to_master(self):
        """Test that Azure Pipelines push to master is detected."""
        ci_env = CIEnvironment.CIPlatforms.AzurePipeline
        
        with patch.dict(os.environ, {
            "BUILD_REASON": "BatchedCI",
            "BUILD_SOURCEBRANCH": "refs/heads/master"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_azure_pipelines_manual_trigger(self):
        """Test that Azure Pipelines manual triggers work."""
        ci_env = CIEnvironment.CIPlatforms.AzurePipeline
        
        with patch.dict(os.environ, {
            "BUILD_REASON": "Manual",
            "BUILD_SOURCEBRANCH": "refs/heads/main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is True

    def test_azure_pipelines_pr_build_reason(self):
        """Test that Azure Pipelines PR builds return False."""
        ci_env = CIEnvironment.CIPlatforms.AzurePipeline
        
        with patch.dict(os.environ, {
            "BUILD_REASON": "PullRequest",
            "BUILD_SOURCEBRANCH": "refs/heads/main"
        }, clear=False):
            assert _is_default_branch_push(ci_env) is False

    def test_local_debug_returns_false(self):
        """Test that LocalDebug always returns False from this function."""
        ci_env = CIEnvironment.CIPlatforms.LocalDebug
        
        assert _is_default_branch_push(ci_env) is False


# ============================================================================
# Tests for LocalDebug execution
# ============================================================================

class TestLocalDebugExecution:
    """Test LocalDebug execution without branch conditions.
    
    **Validates: Requirements 7.7**
    
    WHILE the CIEnvironment is detected as LocalDebug, THE Sharing_Engine SHALL
    execute sharing operations against all configured MISP instances without 
    requiring a CI branch condition.
    """

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_local_debug_executes_without_branch_check(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_ci_env_class
    ):
        """Test that LocalDebug skips branch conditions and executes sharing.
        
        **Validates: Requirements 7.7**
        """
        # Setup mocks
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.LocalDebug
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        # Setup sharing config with instances
        instance_config = make_misp_instance_config()
        sharing_config = make_sharing_config(enabled=True, instances=[instance_config])
        mock_load_config.return_value = sharing_config
        
        # Setup DataTide
        mock_datatide.Configurations.Index.get.return_value = {}
        mock_datatide.Models.tvm = {"uuid1": {"name": "TVM1", "metadata": {"uuid": "uuid1"}}}
        mock_datatide.Models.dom = {}
        mock_datatide.Models.mdr = {}
        
        # Run main
        main()
        
        # Verify that _process_instance was called (sharing executed)
        assert mock_process_instance.called, "LocalDebug should execute sharing without branch condition"

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_local_debug_processes_all_instances(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_ci_env_class
    ):
        """Test that LocalDebug processes all configured MISP instances.
        
        **Validates: Requirements 7.7**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.LocalDebug
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        # Setup sharing config with multiple instances
        instance1 = make_misp_instance_config("MISP Instance 1")
        instance2 = make_misp_instance_config("MISP Instance 2")
        sharing_config = make_sharing_config(enabled=True, instances=[instance1, instance2])
        mock_load_config.return_value = sharing_config
        
        mock_datatide.Configurations.Index.get.return_value = {}
        mock_datatide.Models.tvm = {}
        mock_datatide.Models.dom = {}
        mock_datatide.Models.mdr = {}
        
        main()
        
        # Verify _process_instance was called for each instance
        assert mock_process_instance.call_count == 2, "Should process all MISP instances"


# ============================================================================
# Tests for disabled organisation exit
# ============================================================================

class TestDisabledOrganisationExit:
    """Test that disabled organisation exits gracefully.
    
    **Validates: Requirements 1.9, 7.6**
    
    WHEN `organisation.enabled` is `false`, THE Sharing_Engine SHALL skip
    all sharing operations and log a message at INFO level indicating 
    sharing is disabled.
    """

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_disabled_organisation_skips_sharing(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_ci_env_class
    ):
        """Test that disabled organisation skips all sharing operations.
        
        **Validates: Requirements 1.9**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.LocalDebug
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        # Setup sharing config with disabled organisation
        sharing_config = make_sharing_config(enabled=False, instances=[make_misp_instance_config()])
        mock_load_config.return_value = sharing_config
        
        mock_datatide.Configurations.Index.get.return_value = {}
        
        main()
        
        # Verify that _process_instance was NOT called
        assert not mock_process_instance.called, "Disabled organisation should skip sharing"

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_disabled_organisation_logs_info_message(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_ci_env_class
    ):
        """Test that disabled organisation logs INFO message.
        
        **Validates: Requirements 1.9**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.LocalDebug
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        sharing_config = make_sharing_config(enabled=False)
        mock_load_config.return_value = sharing_config
        
        mock_datatide.Configurations.Index.get.return_value = {}
        
        main()
        
        # Verify INFO log was called with appropriate message
        log_calls = [call for call in mock_log.call_args_list 
                     if call[0][0] == "INFO" and "disabled" in call[0][1].lower()]
        assert len(log_calls) > 0, "Should log INFO message about disabled sharing"

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_disabled_organisation_exits_without_error(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_ci_env_class
    ):
        """Test that disabled organisation exits gracefully without raising.
        
        **Validates: Requirements 1.9**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.LocalDebug
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        sharing_config = make_sharing_config(enabled=False)
        mock_load_config.return_value = sharing_config
        
        mock_datatide.Configurations.Index.get.return_value = {}
        
        # Should not raise any exception
        main()


# ============================================================================
# Tests for PR/MR event skipping
# ============================================================================

class TestPRMREventSkipping:
    """Test that PR/MR events cause the pipeline to skip.
    
    **Validates: Requirements 7.4**
    """

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share._is_pr_or_mr_event")
    @patch("Orchestration.share._is_default_branch_push")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_github_pr_event_skips_sharing(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_is_default_push,
        mock_is_pr_mr,
        mock_ci_env_class
    ):
        """Test that GitHub Actions PR events skip sharing.
        
        **Validates: Requirements 7.4**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.GitHubActions
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        mock_is_pr_mr.return_value = True
        
        main()
        
        # Verify load_sharing_config was NOT called (exited early)
        assert not mock_load_config.called, "PR event should skip sharing before loading config"
        assert not mock_process_instance.called, "PR event should not process instances"

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share._is_pr_or_mr_event")
    @patch("Orchestration.share._is_default_branch_push")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_gitlab_mr_event_skips_sharing(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_is_default_push,
        mock_is_pr_mr,
        mock_ci_env_class
    ):
        """Test that GitLab CI MR events skip sharing.
        
        **Validates: Requirements 7.4**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.GitlabCI
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        mock_is_pr_mr.return_value = True
        
        main()
        
        assert not mock_load_config.called, "MR event should skip sharing before loading config"
        assert not mock_process_instance.called, "MR event should not process instances"

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share._is_pr_or_mr_event")
    @patch("Orchestration.share._is_default_branch_push")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_pr_event_logs_skip_message(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_is_default_push,
        mock_is_pr_mr,
        mock_ci_env_class
    ):
        """Test that PR event logs an INFO skip message.
        
        **Validates: Requirements 7.4**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.GitHubActions
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        mock_is_pr_mr.return_value = True
        
        main()
        
        # Verify INFO log about skipping was called
        # Check all arguments in log calls for PR/MR related keywords
        log_calls = [call for call in mock_log.call_args_list 
                     if call[0][0] == "INFO" and any(
                         "pull request" in str(arg).lower() or "merge request" in str(arg).lower()
                         for arg in call[0]
                     )]
        assert len(log_calls) > 0, "Should log INFO about PR/MR event skip"


# ============================================================================
# Tests for default branch push execution
# ============================================================================

class TestDefaultBranchPushExecution:
    """Test that default branch pushes execute the full sharing sequence.
    
    **Validates: Requirements 7.5**
    """

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share._is_pr_or_mr_event")
    @patch("Orchestration.share._is_default_branch_push")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_default_branch_push_executes_sharing(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_is_default_push,
        mock_is_pr_mr,
        mock_ci_env_class
    ):
        """Test that default branch pushes execute the full sharing sequence.
        
        **Validates: Requirements 7.5**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.GitHubActions
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        mock_is_pr_mr.return_value = False
        mock_is_default_push.return_value = True
        
        instance_config = make_misp_instance_config()
        sharing_config = make_sharing_config(enabled=True, instances=[instance_config])
        mock_load_config.return_value = sharing_config
        
        mock_datatide.Configurations.Index.get.return_value = {}
        mock_datatide.Models.tvm = {}
        mock_datatide.Models.dom = {}
        mock_datatide.Models.mdr = {}
        
        main()
        
        # Verify load_sharing_config was called
        assert mock_load_config.called, "Default branch push should load config"
        # Verify _process_instance was called
        assert mock_process_instance.called, "Default branch push should process instances"

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share._is_pr_or_mr_event")
    @patch("Orchestration.share._is_default_branch_push")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_non_default_branch_push_skips_sharing(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_is_default_push,
        mock_is_pr_mr,
        mock_ci_env_class
    ):
        """Test that non-default branch pushes skip sharing.
        
        **Validates: Requirements 7.5**
        """
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.GitHubActions
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        mock_is_pr_mr.return_value = False
        mock_is_default_push.return_value = False
        
        main()
        
        # Verify load_sharing_config was NOT called
        assert not mock_load_config.called, "Non-default branch push should skip sharing"
        assert not mock_process_instance.called, "Non-default branch push should not process instances"


# ============================================================================
# Tests for CI environment detection
# ============================================================================

class TestCIEnvironmentDetection:
    """Test CI environment detection.
    
    **Validates: Requirements 7.1, 7.2**
    """

    def test_github_actions_detected_via_env_var(self):
        """Test that GitHub Actions is detected via GITHUB_ACTIONS env var.
        
        **Validates: Requirements 7.2**
        """
        with patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true"
        }, clear=False):
            with patch("Engines.modules.deployment.HelperTide.is_debug", return_value=False):
                with patch("Engines.modules.deployment.log"):
                    env = CIEnvironment()
                    assert env.environment == CIEnvironment.CIPlatforms.GitHubActions

    def test_gitlab_ci_detected_via_env_var(self):
        """Test that GitLab CI is detected via CI env var.
        
        **Validates: Requirements 7.2**
        """
        # Clear GITHUB_ACTIONS and TF_BUILD to ensure GitLab CI is detected
        env_vars = {k: v for k, v in os.environ.items() 
                   if k not in ("GITHUB_ACTIONS", "TF_BUILD")}
        env_vars["CI"] = "true"
        
        with patch.dict(os.environ, env_vars, clear=True):
            with patch("Engines.modules.deployment.HelperTide.is_debug", return_value=False):
                with patch("Engines.modules.deployment.log"):
                    env = CIEnvironment()
                    assert env.environment == CIEnvironment.CIPlatforms.GitlabCI

    def test_azure_pipelines_detected_via_env_var(self):
        """Test that Azure Pipelines is detected via TF_BUILD env var.
        
        **Validates: Requirements 7.2**
        """
        # Clear GITHUB_ACTIONS to ensure Azure is detected first
        env_vars = {k: v for k, v in os.environ.items() 
                   if k not in ("GITHUB_ACTIONS",)}
        env_vars["TF_BUILD"] = "True"
        
        with patch.dict(os.environ, env_vars, clear=True):
            with patch("Engines.modules.deployment.HelperTide.is_debug", return_value=False):
                with patch("Engines.modules.deployment.log"):
                    env = CIEnvironment()
                    assert env.environment == CIEnvironment.CIPlatforms.AzurePipeline

    def test_local_debug_detected_when_debug_enabled(self):
        """Test that LocalDebug is detected when debug mode is enabled.
        
        **Validates: Requirements 7.2**
        """
        # Clear all CI-related env vars
        env_vars = {k: v for k, v in os.environ.items() 
                   if k not in ("GITHUB_ACTIONS", "TF_BUILD", "CI")}
        
        with patch.dict(os.environ, env_vars, clear=True):
            with patch("Engines.modules.deployment.HelperTide.is_debug", return_value=True):
                with patch("Engines.modules.deployment.log"):
                    env = CIEnvironment()
                    assert env.environment == CIEnvironment.CIPlatforms.LocalDebug


# ============================================================================
# Tests for object collection
# ============================================================================

class TestObjectCollection:
    """Test object collection from DataTide."""

    @patch("Orchestration.share.DataTide")
    def test_collect_all_objects_merges_tvm_dom_mdr(self, mock_datatide):
        """Test that _collect_all_objects merges TVM, DOM, MDR objects."""
        mock_datatide.Models.tvm = {
            "uuid1": {"name": "TVM1", "metadata": {"uuid": "uuid1"}}
        }
        mock_datatide.Models.dom = {
            "uuid2": {"name": "DOM1", "metadata": {"uuid": "uuid2"}}
        }
        mock_datatide.Models.mdr = {
            "uuid3": {"name": "MDR1", "metadata": {"uuid": "uuid3"}}
        }
        
        result = _collect_all_objects()
        
        assert "uuid1" in result
        assert "uuid2" in result
        assert "uuid3" in result
        assert result["uuid1"][0] == "tvm"
        assert result["uuid2"][0] == "dom"
        assert result["uuid3"][0] == "mdr"

    @patch("Orchestration.share.DataTide")
    def test_collect_all_objects_handles_empty_indices(self, mock_datatide):
        """Test that _collect_all_objects handles empty indices."""
        mock_datatide.Models.tvm = {}
        mock_datatide.Models.dom = {}
        mock_datatide.Models.mdr = {}
        
        result = _collect_all_objects()
        
        assert result == {}

    @patch("Orchestration.share.DataTide")
    def test_collect_all_objects_handles_none_indices(self, mock_datatide):
        """Test that _collect_all_objects handles None indices."""
        mock_datatide.Models.tvm = None
        mock_datatide.Models.dom = None
        mock_datatide.Models.mdr = None
        
        result = _collect_all_objects()
        
        assert result == {}

    def test_count_by_type(self):
        """Test _count_by_type helper function."""
        all_objects = {
            "uuid1": ("tvm", {}),
            "uuid2": ("tvm", {}),
            "uuid3": ("dom", {}),
            "uuid4": ("mdr", {}),
        }
        
        assert _count_by_type(all_objects, "tvm") == 2
        assert _count_by_type(all_objects, "dom") == 1
        assert _count_by_type(all_objects, "mdr") == 1


# ============================================================================
# Tests for no instances configured
# ============================================================================

class TestNoInstancesConfigured:
    """Test handling when no MISP instances are configured."""

    @patch("Orchestration.share.CIEnvironment")
    @patch("Orchestration.share.load_sharing_config")
    @patch("Orchestration.share.DataTide")
    @patch("Orchestration.share._process_instance")
    @patch("Orchestration.share.log")
    @patch("Orchestration.share.print")
    @patch("Orchestration.share.coretide_intro")
    def test_no_instances_logs_info_and_exits(
        self,
        mock_coretide_intro,
        mock_print,
        mock_log,
        mock_process_instance,
        mock_datatide,
        mock_load_config,
        mock_ci_env_class
    ):
        """Test that no instances configured logs INFO and exits gracefully."""
        mock_coretide_intro.return_value = ""
        mock_ci_env_instance = MagicMock()
        mock_ci_env_instance.environment = CIEnvironment.CIPlatforms.LocalDebug
        mock_ci_env_class.return_value = mock_ci_env_instance
        mock_ci_env_class.CIPlatforms = CIEnvironment.CIPlatforms
        
        # No instances
        sharing_config = make_sharing_config(enabled=True, instances=[])
        mock_load_config.return_value = sharing_config
        
        mock_datatide.Configurations.Index.get.return_value = {}
        mock_datatide.Models.tvm = {}
        mock_datatide.Models.dom = {}
        mock_datatide.Models.mdr = {}
        
        main()
        
        # Verify _process_instance was NOT called
        assert not mock_process_instance.called, "No instances should mean no processing"
        
        # Verify INFO log about no instances
        log_calls = [call for call in mock_log.call_args_list 
                     if call[0][0] == "INFO" and "no" in call[0][1].lower() 
                     and "instance" in call[0][1].lower()]
        assert len(log_calls) > 0, "Should log INFO about no instances configured"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
