import os
import sys
from tokenize import String
import git

from dataclasses import dataclass
from typing import Literal, Never, Optional, List, Sequence, Mapping, Any, Union
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

class StatusStrategy(Enum):
    INERT = "Does not interact with deployment"
    RELEASE = "Deployment from the default branch (also called trunk, or main branch)"
    PREVIEW = "Deployment from Pull/Merge Requests"
    DISABLEMENT = "Deployment from the default branch, but only to disable an existing rule. If the target system does not have a concept of disabling rules, then defaults to deleting them."
    DELETION = "Deployment from the default branch, but removes the rule from the target system."
    UNIVERSAL = "Deployment from both Pull/Merge Requests, and default branch pipelines."

class DetectionPlatforms(Enum):
    DEFENDER_FOR_ENDPOINT = auto()
    CARBON_BLACK_CLOUD = auto()
    SPLUNK = auto()
    SENTINEL = auto()
    SENTINEL_ONE = auto()
    CROWDSTRIKE = auto()
    HARFANGLAB = auto()


# Legacy alias
DetectionSystems = DetectionPlatforms

class DeploymentStrategy(Enum):
    STAGING = "Deployment allowed during a Pull (or Merge) Request Pipeline"
    PRODUCTION = "Deployment allowed during a Default Branch Pipeline"
    FULL = "Deployment allowed during both Pull (or Merge) Request Pipeline and Default Branch Pipeline"
    ALWAYS = "Deployment allowed during both Pull (or Merge) Request Pipeline and Default Branch Pipeline"
    MANUAL = "Deployment allowed during both Pull (or Merge) Request Pipeline and Default Branch Pipeline, but only when explictely specified under tenants"
    DEBUG = "Deployment used for debugging and testing purposes only"


    @staticmethod
    def load_from_environment():
        """
        Read the DEPLOYMENT_PLAN environment variable and maps it to 
        DeploymentStrategy valid values. In case of an illegal value, 
        or missing environment variable will raise an exception
        """
        SUPPORTED_PLANS = [plan.name for plan in DeploymentStrategy]
        DEPLOYMENT_PLAN = str(os.getenv("DEPLOYMENT_PLAN")) or None
        if not DEPLOYMENT_PLAN:
            log(
                "FATAL",
                "No deployment plan, ensure that the CI variable DEPLOYMENT_PLAN is set correctly",
            )
            raise Exception("NO DEPLOYMENT PLAN")

        try:
            DEPLOYMENT_PLAN = DeploymentStrategy[DEPLOYMENT_PLAN]
        except:

                log(
                    "FATAL",
                    "The following deployment plan is not supported",
                    DEPLOYMENT_PLAN,
                    f"Supported plan : {SUPPORTED_PLANS}",
                )
                raise AttributeError("UNSUPPORTED DEPLOYMENT PLAN")

        return DEPLOYMENT_PLAN

