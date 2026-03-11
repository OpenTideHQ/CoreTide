import os
import sys
import git

from cbc_sdk.rest_api import CBCloudAPI

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.plugins import ValidateQuery
from Engines.modules.tide import DataTide
from Engines.modules.carbon_black_cloud import CarbonBlackCloudEngineInit

class CarbonBlackCloudValidateQuery(CarbonBlackCloudEngineInit, ValidateQuery):

    def check_query(self, mdr:dict, service:CBCloudAPI):
        query:str = mdr["configurations"]["carbon_black_cloud"].get("query")
        mdr_uuid = mdr.get('uuid') or mdr["metadata"]["uuid"]
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            log("FATAL", "Missing query in MDR", f"{mdr.get('name')} ({mdr_uuid})")
            return

        try:
            result = service.validate_process_query(query)
            if result:
                log("SUCCESS", "The query is a valid CBC search")
            else:
                log("FATAL",
                    f"The CBC query is invalid for : {mdr['name']} ({mdr_uuid})",
                    # Same error message as displayed on the GUI
                    "Ensure a value is included and slashes, colons, and spaces are manually escaped")
        except Exception as error:
            log("FATAL", "Failed to validate the query on the CBC tenant")
            raise error

    def validate(self, deployment: list[str]):
        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        self.configure_proxy()

        ORG_KEY = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]["org_key"]
        TOKEN = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]["token"]

        service = CBCloudAPI(
                    url=self.CBC_URL,
                    token=TOKEN,
                    org_key=ORG_KEY,
                    ssl_verify=self.SSL_ENABLED
                )
        log(
            "SUCCESS",
            "Successfully connected to Carbon Black Cloud on tenant",
            self.VALIDATION_ORGANIZATION,
        )

        # Start deployment routine
        for mdr in deployment:
            mdr_data:dict = DataTide.Models.mdr[mdr]
            mdr_uuid = mdr_data.get('uuid') or mdr_data["metadata"]["uuid"]

            # Check if modified MDR contains a platform entry (by safety, but should not happen since
            # the orchestrator will filter for the platform)
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"].keys():
                # Connection routine, if not connected yet.
                log("ONGOING",
                    "Validating CBC Lucene Query",
                    f"{mdr_data['name']} ({mdr_uuid}")
                self.check_query(mdr_data, service)
            else:
                log(
                    "SKIP",
                    f"🛑 Skipping {mdr_data.get('name')} as does not contain a Splunk configuration section",
                )


def declare():
    return CarbonBlackCloudValidateQuery()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudValidateQuery().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)