import os
import git
import sys
import json
from typing import Literal
from splunklib import client, results
import traceback

import pandas as pd

from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.core.exceptions import HttpResponseError

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.sentinel import SentinelEngineInit, build_query
from Engines.modules.plugins import ValidateQuery
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from datetime import timedelta


class SentinelValidateQuery(SentinelEngineInit, ValidateQuery):

    def check_query(self, mdr:dict, service:LogsQueryClient):
        mdr_uuid = mdr.get("uuid") or mdr["metadata"]["uuid"]
        query:str = mdr["configurations"][self.DEPLOYER_IDENTIFIER].get("query")
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing query in MDR", f"{mdr.get('name')} ({mdr_uuid})")
            return

        query = build_query(mdr) + " | limit 1"

        try:
            service.query_workspace(workspace_id=self.AZURE_SENTINEL_WORKSPACE_ID,
                                    query = query,
                                    timespan=timedelta(minutes=1))
            log("SUCCESS", "The query is a valid Sentinel KQL")
        
        except HttpResponseError as error:
            log("DEBUG", "Full error message", str(error))
            try:
                log("FATAL",
                    f"The KQL query is invalid for : {mdr['name']} ({mdr_uuid})",
                    error.error.innererror["innererror"]["message"], #type: ignore
                    f"Review the error and ensure your search can work in the relevant Sentinel workspace ({self.AZURE_SENTINEL_WORKSPACE_NAME})") 
            except:
                log("FAILURE",
                    "Not able to parse out the error message",
                    "This may mean that there is a more complex problem",
                    "Will print out the full error package now")
                print(error)
            os.environ["VALIDATION_ERROR_RAISED"] = "True"


    def validate(self, deployment: list[str]):
        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        credentials = ClientSecretCredential(self.AZURE_TENANT_ID,
                                             self.AZURE_CLIENT_ID,
                                            self.AZURE_CLIENT_SECRET)

        service = LogsQueryClient(credential=credentials,
                                  connection_verify=self.SSL_ENABLED)

        # Start deployment routine
        for mdr in deployment:
            mdr_data:dict = DataTide.Objects.mdr[mdr]
            mdr_uuid = mdr_data.get("uuid") or mdr_data["metadata"]["uuid"]

            # Check if modified MDR contains a platform entry (by safety, but should not happen since
            # the orchestrator will filter for the platform)
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"].keys():
                # Connection routine, if not connected yet.
                log("ONGOING",
                    "Validating KQL Query",
                    f"{mdr_data['name']} ({mdr_uuid}")
                self.check_query(mdr_data, service)
            else:
                log(
                    "SKIP",
                    f"🛑 Skipping {mdr_data.get('name')} as does not contain a Sentinel configuration section",
                )



def declare():
    return SentinelValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    print("RUNNING")
    SentinelValidateQuery().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)