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
from Engines.modules.carbon_black_cloud import CarbonBlackCloudEngineInit
from Engines.modules.deployment import TideDeployment
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy,
                                    TenantDeployment)
from Engines.modules.systems.carbon_black_cloud import CarbonBlackCloudService


class CarbonBlackCloudValidateQuery(CarbonBlackCloudEngineInit, ValidateQuery):

    def check_query(self, mdr: TideModels.MDR, service: CBCloudAPI):
        config = mdr.configurations.carbon_black_cloud
        if not config or not hasattr(config, "query"):
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing CBC configuration in MDR", mdr.name)
            return

        query = config.query
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing query in MDR", f"{mdr.name} ({mdr.metadata.uuid})")
            return

        try:
            result = service.validate_process_query(query)
            if result:
                log("SUCCESS", "The query is a valid CBC search")
            else:
                log("FATAL",
                    f"The CBC query is invalid for : {mdr.name} ({mdr.metadata.uuid})",
                    "Ensure a value is included and slashes, colons, and spaces are manually escaped")
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
        except Exception as error:
            log("FATAL", "Failed to validate the query on the CBC tenant")
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            raise error

    def validate(self,
                 mdr_deployment: Union[Sequence[TideModels.MDR], Sequence[str]],
                 deployment_plan: DeploymentStrategy):

        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Models.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        if not mdr_deployment:
            log("SKIP", "No MDRs to validate for Carbon Black Cloud")
            return

        self.configure_proxy()

        deployment_resolution = TideDeployment(
            deployment=mdr_deployment,
            system=DetectionSystems.CARBON_BLACK_CLOUD,
            strategy=deployment_plan)

        for tenant_deployment in deployment_resolution.rule_deployment:  # type: ignore
            tenant_deployment: TenantDeployment.CarbonBlackCloud
            cbc_service = CarbonBlackCloudService(tenant_deployment.tenant)

            for mdr in tenant_deployment.rules:
                log("ONGOING", "Validating CBC Lucene Query",
                    f"{mdr.name} ({mdr.metadata.uuid})")
                self.check_query(mdr, cbc_service.service)


def declare():
    return CarbonBlackCloudValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudValidateQuery().validate(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
