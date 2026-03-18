import os
import git
import sys
import json
from typing import Literal, Sequence
from datetime import timedelta

import pandas as pd

from azure.identity import ClientSecretCredential, CredentialUnavailableError
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError, ServiceRequestError

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.plugins import ValidateQuery
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from Engines.modules.models import TideModels, TideConfigs, TenantDeployment
from Engines.modules.errors import TideErrors
from Engines.modules.deployment import TideDeployment, DetectionSystems, DeploymentStrategy

class SentinelValidateQuery(ValidateQuery):

    def check_query(self,
                    mdr:TideModels.MDR,
                    tenant_config:TideConfigs.Systems.Sentinel.Tenant,
                    service:LogsQueryClient):
        mdr_uuid = mdr.metadata.uuid
        if not mdr.configurations.sentinel:
            raise TideErrors.TideMDRDataModelErrors("Missing Sentinel")
        
        query:str = mdr.configurations.sentinel.query
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing query in MDR", f"{mdr.name} ({mdr_uuid})")
            return

        query += " | limit 1"

        try:
            service.query_workspace(workspace_id=tenant_config.setup.workspace_id,
                                    query = query,
                                    timespan=timedelta(minutes=1))
            log("SUCCESS", "The query is a valid Sentinel KQL",
                f"{mdr.name} ({mdr_uuid})")

        except CredentialUnavailableError as error:
            log("FATAL",
                f"Azure credential unavailable for : {mdr.name} ({mdr_uuid})",
                str(error),
                "The credential provider could not authenticate. "
                "Check that tenant_id, client_id and client_secret are correctly configured.")
            os.environ["VALIDATION_ERROR_RAISED"] = "True"

        except ClientAuthenticationError as error:
            log("FATAL",
                f"Azure authentication failed for : {mdr.name} ({mdr_uuid})",
                str(error.message),
                "The service principal credentials may be expired or invalid. "
                "Verify the client secret has not expired in Entra ID.")
            os.environ["VALIDATION_ERROR_RAISED"] = "True"

        except ServiceRequestError as error:
            log("FATAL",
                f"Network error reaching Azure Monitor for : {mdr.name} ({mdr_uuid})",
                str(error),
                "Could not connect to the Azure Monitor endpoint. "
                "Check network connectivity, proxy settings and SSL configuration.")
            os.environ["VALIDATION_ERROR_RAISED"] = "True"

        except HttpResponseError as error:
            log("DEBUG", "Full error message", str(error))
            try:
                log("FATAL",
                    f"The KQL query is invalid for : {mdr.name} ({mdr_uuid})",
                    error.error.innererror["innererror"]["message"], #type: ignore
                    f"Review the error and ensure your search can work in the relevant Sentinel workspace ({tenant_config.setup.workspace_name})") 
            except:
                log("FAILURE",
                    "Not able to parse out the error message",
                    "This may mean that there is a more complex problem",
                    "Will print out the full error package now")
                print(error)
            os.environ["VALIDATION_ERROR_RAISED"] = "True"

        except Exception as error:
            log("FATAL",
                f"Unexpected error during query validation for : {mdr.name} ({mdr_uuid})",
                f"{type(error).__name__}: {error}",
                "An unhandled exception occurred. Review the error details above.")
            os.environ["VALIDATION_ERROR_RAISED"] = "True"


    def validate(self, mdr_deployment: Sequence[TideModels.MDR] | list[str], deployment_plan:DeploymentStrategy):
        
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Models.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        
        
        
        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.SENTINEL,
                                    strategy=deployment_plan)


        for tenant_deployment in deployment.rule_deployment: #type: ignore
            tenant_deployment: TenantDeployment.Sentinel # Force assignment here as case switch in TideDeployment doesn't seem to resolve perfectly
            tenant_setup = tenant_deployment.tenant.setup
            log("ONGOING",
                "Acquiring Azure credentials for tenant",
                tenant_deployment.tenant.name)
            credentials = ClientSecretCredential(tenant_setup.azure_tenant_id,
                                                tenant_setup.azure_client_id,
                                                tenant_setup.azure_client_secret)
            log("SUCCESS",
                "Azure credentials prepared for tenant",
                tenant_deployment.tenant.name,
                "Note: credentials are validated lazily on first API call")

            log("ONGOING",
                "Initialising LogsQueryClient for tenant",
                tenant_deployment.tenant.name)
            service = LogsQueryClient(credential=credentials,
                                    connection_verify=tenant_setup.ssl)
            log("SUCCESS",
                "LogsQueryClient ready for tenant",
                tenant_deployment.tenant.name)


            for mdr in tenant_deployment.rules:

                log("ONGOING",
                    "Validating KQL Query",
                    f"{mdr.name} ({mdr.metadata.uuid})")
                log("ONGOING",
                    "Sending query to Azure Monitor workspace",
                    f"{mdr.name} ({mdr.metadata.uuid})")
                self.check_query(mdr=mdr,
                                 service=service,
                                 tenant_config=tenant_deployment.tenant)



def declare():
    return SentinelValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelValidateQuery().validate(["5e791284-684c-4245-9ac7-cf00a1d041d6"], DeploymentStrategy.DEBUG)