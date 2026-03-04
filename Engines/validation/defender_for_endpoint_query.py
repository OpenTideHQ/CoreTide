import os
import sys
import git

from typing import Sequence, Union

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.plugins import ValidateQuery
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy,) 
from Engines.modules.deployment import TideDeployment
from Engines.modules.systems.defender_for_endpoint import DefenderForEndpointService
from Engines.validation.kql import validate_mde_required_columns


class DefenderForEndpointValidateQuery(ValidateQuery):

    def check_query(self,
                    mdr:TideModels.MDR,
                    service:DefenderForEndpointService):
        
        config = mdr.configurations.defender_for_endpoint
        if not config: 
            raise
        query = config.query
        mdr_name = mdr.name
        mdr_uuid = mdr.metadata.uuid

        # Pre-flight validation: required columns for MDE custom detections
        is_valid, missing_columns = validate_mde_required_columns(query)
        if not is_valid:
            log("FATAL",
                f"MDE custom detection query is missing required columns: {', '.join(missing_columns)}",
                f"{mdr_name} ({mdr_uuid})",
                "Per Microsoft documentation, MDE custom detection queries must include "
                "Timestamp, DeviceId, and ReportId columns in the output. "
                "See: https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules")
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            return

        validation = service.validate_query(query)
        if not validation:
            os.environ["VALIDATION_ERROR_RAISED"] = "True" 


    def validate(self,
                 mdr_deployment: Union[Sequence[TideModels.MDR], Sequence[str]],
                 deployment_plan:DeploymentStrategy):
        
        if type(mdr_deployment[0]) is str:
            mdr_deployment = [DataTide.Models.MDR[uuid] for uuid in mdr_deployment]

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.DEFENDER_FOR_ENDPOINT,
                                    strategy=deployment_plan)
        
        for tenant_deployment in deployment.rule_deployment:
            service = DefenderForEndpointService(tenant_deployment.tenant) #type:ignore

            for mdr in tenant_deployment.rules:
                self.check_query(mdr=mdr,
                                service=service)

def declare():
    return DefenderForEndpointValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    DefenderForEndpointValidateQuery().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)