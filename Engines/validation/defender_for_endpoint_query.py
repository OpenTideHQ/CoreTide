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

# Per Microsoft documentation for MDE custom detection rules:
# https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules
MDE_REQUIRED_COLUMNS = {"Timestamp", "DeviceId", "ReportId"}

class DefenderForEndpointValidateQuery(ValidateQuery):

    def check_query(self,
                    mdr:TideModels.MDR,
                    service:DefenderForEndpointService):
        
        config = mdr.configurations.defender_for_endpoint
        if not config: 
            raise ValueError(f"Missing MDE configuration for {mdr.name}")
        query = config.query
        mdr_name = mdr.name
        mdr_uuid = mdr.metadata.uuid

        # Step 1 — Run the query to validate it can execute
        try:
            response = service.run_hunting_query(query)
        except Exception:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            return

        # Step 2 — Check the returned schema for required columns
        # Graph API returns lowercase keys ("name"), XDR API uses PascalCase ("Name")
        returned_columns = {
            col.get("name") or col.get("Name")
            for col in response.get("schema", response.get("Schema", []))
        }
        returned_columns.discard(None)
        missing = MDE_REQUIRED_COLUMNS - returned_columns
        if missing:
            log("FATAL",
                f"MDE custom detection query is missing required columns: {', '.join(sorted(missing))}",
                f"{mdr_name} ({mdr_uuid})",
                "Per Microsoft documentation, MDE custom detection queries must include "
                "Timestamp, DeviceId, and ReportId columns in the output. "
                "See: https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules")
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