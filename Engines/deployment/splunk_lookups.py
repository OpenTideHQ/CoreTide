import os
import git
import yaml
import pandas as pd
import json
from splunklib import client
from io import StringIO
import time
import sys

start_time = time.time()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.splunk import connect_splunk, SplunkEngineInit
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.plugins import DeployLookups


class SplunkLookupsDeploy(SplunkEngineInit, DeployLookups):

    def deploy_lookup(
        self, lookup_name: str, lookup_df: pd.DataFrame, service: client.Service
    ):

        log("DEBUG", "Compiling dataframe to a json-like data structure")
        lookup_records = lookup_df.to_dict("records")

        content = {"body": lookup_records}

        log("DEBUG", "Double json dumping strategy to safely escape all quotes")
        raw = json.dumps(json.dumps(content, default=str)).lstrip('"').rstrip('"')
        query = f"""| makeresults
        | eval _raw="{raw}"
        | spath path=body{{}} output=temp 
        | mvexpand temp 
        | spath input=temp 
        | fields - _raw _time temp
        | outputlookup {lookup_name}.csv
        """

        log("ONGOING", "Overriding existing lookup from splunk", lookup_name)
        service.jobs.oneshot(query)

        return True

    def deploy(self, deployment: list[str]):
        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        self.configure_proxy()

        log("ONGOING", "Splunk Lookup Deployer")
        log(
            "INFO",
            "Overrides existing lookups with the newly modified one from CoreTIDE",
        )
        service = connect_splunk(
            host=self.SPLUNK_URL,
            port=self.SPLUNK_PORT,
            token=self.SPLUNK_TOKEN,
            app=self.SPLUNK_APP,
            ssl_enabled=self.SSL_ENABLED
        )

        # Start deployment routine
        for lookup in deployment:
            #Explicitely remove extension is present
            if lookup.endswith(".csv"):
                lookup.removesuffix(".csv")
            if lookup not in self.LOOKUPS_INDEX:
                log("FAILURE", f"Could not find lookup namein current index", lookup)
                raise (Exception)

            lookup_df = pd.read_csv(StringIO(self.LOOKUPS_INDEX[lookup]))
            log("INFO", "Lookup deployment started", lookup)
            self.deploy_lookup(lookup, lookup_df, service)
            log("SUCCESS", "Lookup deployment successful", lookup)


def declare():
    return SplunkLookupsDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkLookupsDeploy().deploy(DebugEnvironment.LOOKUP_DEPLOYMENT_TEST_FILES)