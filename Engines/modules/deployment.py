# Engines/modules/deployment.py — backward compatibility shim
from Engines.modules.ci import CIEnvironment
from Engines.modules.git_repo import TideRepo
from Engines.modules.deployment_utils import (
    check_status,
    make_deploy_plan,
    modified_mdr_files,
    diff_calculation,
    enabled_systems,
    Proxy,
    ExternalIdHelper,
    SYSTEMS_CONFIGS_INDEX,
    DEPRECATED_STATUSES,
)
from Engines.modules.deployment_planning import TideDeployment

__all__ = [
    "CIEnvironment", "TideRepo",
    "check_status", "make_deploy_plan", "modified_mdr_files", "diff_calculation",
    "enabled_systems", "Proxy", "ExternalIdHelper",
    "SYSTEMS_CONFIGS_INDEX", "DEPRECATED_STATUSES",
    "TideDeployment",
]
