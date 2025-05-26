import os
import sys
import git

from cbc_sdk.rest_api import CBCloudAPI
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

class DefenderForEndpointValidateQuery(ValidateQuery):

    def check_query(self,
                    mdr:TideModels.MDR,
                    service:DefenderForEndpointService):
        
        config = mdr.configurations.defender_for_endpoint
        if not config: 
            raise
        query = config.query
        
        validation = service.validate_query(query)
        if not validation:
            os.environ["VALIDATION_ERROR_RAISED"] = "True" 


    def validate(self,
                 mdr_deployment: Union[Sequence[TideModels.MDR], Sequence[str]],
                 deployment_plan:DeploymentStrategy):
        
        if type(mdr_deployment[0]) is str:
            mdr_deployment = [DataTide.Objects.MDR[uuid] for uuid in mdr_deployment]

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