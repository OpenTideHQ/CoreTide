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
                                    DeploymentStrategy,
                                    TideConfigs) 
from Engines.modules.deployment import TideDeployment
from Engines.modules.systems.sentinel_one import SentinelOneService

class SentinelOneValidateQuery(ValidateQuery):

    def check_query(self,
                    mdr:TideModels.MDR,
                    service:SentinelOneService):
        
        config = mdr.configurations.sentinel_one
        if not config: 
            raise Exception
        
        if config.condition.type == "Single Event":
            if not config.condition.single_event:
                raise Exception
            
            query = config.condition.single_event.query
            log("ONGOING", "Validating query", query)
            validation = service.validate_query(query)
            
            if not validation:
                os.environ["VALIDATION_ERROR_RAISED"] = "True" 
        
        elif config.condition.type == "Correlation":
            if not config.condition.correlation:
                raise Exception
            
            for sub_query in config.condition.correlation.sub_queries:
                query = sub_query.query
                log("ONGOING", "Validating query", query)
                validation = service.validate_query(query)
                if not validation:
                    os.environ["VALIDATION_ERROR_RAISED"] = "True" 

    def validate(self,
                 mdr_deployment: Union[Sequence[TideModels.MDR], Sequence[str]],
                 deployment_plan:DeploymentStrategy):
        
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Objects.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.SENTINEL_ONE,
                                    strategy=deployment_plan)
        
        for tenant_deployment in deployment.rule_deployment:
            service = SentinelOneService(tenant_deployment.tenant)

            for mdr in tenant_deployment.rules:
                log("INFO",
                    f"Starting query validation on tenant {tenant_deployment.tenant.name}",
                    mdr.name,
                    mdr.metadata.uuid)
                
                self.check_query(mdr=mdr,
                                service=service)

def declare():
    return SentinelOneValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelOneValidateQuery().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)