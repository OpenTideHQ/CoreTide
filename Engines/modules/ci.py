from git.repo import Repo
from Engines.modules.environment import HelperTide
from Engines.modules.errors import TideErrors
from Engines.modules.debug import DebugEnvironment
from Engines.modules.logs import log
import sys
import os
import git
from enum import Enum, auto
from pathlib import Path

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

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


