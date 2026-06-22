import pandas as pd
from git.repo import Repo
from Engines.modules.tide import DataTide, HelperTide
from Engines.modules.errors import TideErrors
from Engines.modules.debug import DebugEnvironment
from Engines.modules.logs import log
import sys
import os
import git
from enum import Enum, auto
from pathlib import Path
from dataclasses import dataclass

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.ci import CIEnvironment

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

