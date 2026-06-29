import os
import git
import sys
import json
import traceback
from typing import Sequence, Union

from splunklib import client

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.splunk import connect_splunk, create_query_v4, SplunkEngineInit
from Engines.modules.plugins import ValidateQuery
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.deployment import TideDeployment, Proxy
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy,
                                    TenantDeployment)


class SplunkValidateQuery(SplunkEngineInit, ValidateQuery):

    def check_query(self, mdr: TideModels.MDR, service: client.Service):
        mdr_uuid = mdr.metadata.uuid

        config = mdr.configurations.splunk
        if not config:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing Splunk configuration in MDR",
                f"{mdr.name} ({mdr_uuid})")
            return

        query: str = config.query  # type: ignore
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing query in MDR", f"{mdr.name} ({mdr_uuid})")
            return

        query = create_query_v4(mdr)
        if not query.startswith("| "):
            query = "| search " + query
            log("INFO",
                "Adding implicit `| search` as could not find starting command")

        try:
            response = service.parse(query.strip(),
                                     enable_lookups=True,
                                     output_mode='json',
                                     reload_macros=True)
            status = response["status"]

            if status == 19:

                if reason := response.get("reason"):
                    if reason == "Temporary Redirect":
                        if "Network Error" in str(response["body"].read()):
                            log("FAILURE",
                                "We encountered an unexpected error, which has shown empirically to be related to time-out",
                                "The query is assumed to be valid, be aware that if deployment fails it may be related to the query")
                            os.environ["VALIDATION_WARNING_RAISED"] = "True"
                            return

                parsing = response["body"].read()
                parsing = json.loads(parsing)  # type: ignore
                log("DEBUG", "Parsed Body", parsing)
                for message in parsing["messages"]:
                    log("FATAL",
                        f"The SPL query is invalid for : {mdr.name} ({mdr_uuid})",
                        message.get("text", ""),
                        "Review the error and ensure it can run on the Splunk Search console")
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
                return

            elif status == 200:
                parsing = response["body"].read()
                parsing = json.loads(parsing)  # type: ignore
                log("SUCCESS", "The query is a valid SPL that can be parsed by Splunk")
                return

            else:
                log("FATAL",
                    "Unexpected Error Code",
                    str(response))
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
                return

        except Exception as e:
            log("FATAL",
                "An unknown error was found",
                repr(e))
            traceback.print_exc()
            raise

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
            log("SKIP", "No MDRs to validate for Splunk")
            return

        self.configure_proxy()

        deployment_resolution = TideDeployment(
            deployment=mdr_deployment,
            system=DetectionSystems.SPLUNK,
            strategy=deployment_plan)

        for tenant_deployment in deployment_resolution.rule_deployment:  # type: ignore
            tenant_deployment: TenantDeployment.Splunk
            tenant = tenant_deployment.tenant

            if tenant.setup.proxy:
                Proxy.set_proxy()
            else:
                Proxy.unset_proxy()

            service = connect_splunk(
                host=tenant.setup.url,
                port=tenant.setup.port,
                token=tenant.setup.token,
                app=tenant.setup.app,
                allow_http_errors=True,
                ssl_enabled=tenant.setup.ssl,
            )

            for mdr in tenant_deployment.rules:
                log("ONGOING",
                    "Validating SPL Query",
                    f"{mdr.name} ({mdr.metadata.uuid})")
                self.check_query(mdr, service)


def declare():
    return SplunkValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkValidateQuery().validate(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
