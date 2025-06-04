import os
import git
from pathlib import Path
import json
import time
import sys
import datetime

start_time = time.time()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.splunk import connect_splunk, SplunkEngineInit
from Engines.modules.framework import techniques_resolver
from Engines.modules.tide import DataTide
from Engines.modules.plugins import DeployMetadata
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment

class SplunkMetadataDeploy(SplunkEngineInit, DeployMetadata):
    def __init__(self):
        """
        Specific attributes to the metadata implementation on top of SplunkEngineInit 
        """
        
        super().__init__()
        MDR_ICON = DataTide.Configurations.Documentation.icons["mdr"]
        self.DEFAULT_RESPONDERS = DataTide.Configurations.Deployment.default_responders
        if os.getenv("TIDE_WIKI_GENERATION") == "GITLAB_WIKI":
            WIKI_URL = f"{os.getenv('CI_SERVER_URL')}/{os.getenv('CI_PROJECT_PATH')}/-/wikis/"
        else:
            WIKI_URL = DataTide.Configurations.Documentation.wiki.get("wiki_link", "")

        self.GITWIKI = WIKI_URL
        self.GITWIKI += str(
            DataTide.Configurations.Documentation.models_docs_folder
        ).replace("../", "").replace("wiki", "")
        self.GITWIKI += "/" + DataTide.Configurations.Documentation.object_names["mdr"]
        self.GITWIKI = self.GITWIKI.replace(" ", "-")
        self.GITWIKI += f"/{MDR_ICON}-"

    def deploy(self, deployment: list[str], lookup_name: str):
        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        if not lookup_name.endswith(".csv"):
            lookup_name += ".csv"

        mdr_to_update = list()

        # Build lookup data
        for mdr in deployment:
            entry = dict()
            # Could load from index, but this is fast enough for lookup update purposes
            body = DataTide.Models.mdr[mdr]
            mdr_uuid = body.get("uuid") or body["metadata"]["uuid"]
            log("ONGOING", "Generating Lookup entry", body["name"])
            
            techniques = techniques_resolver(mdr_uuid)
            if techniques:
                techniques = ", ".join(techniques)
            else:
                techniques = None

            statuses = dict()
            configurations = body.get("configurations")
            for system in configurations:
                entry[f"MDR_status_{system}"] = configurations[system]["status"]
            metadata = body.get("metadata") or body["meta"]
            entry["MDR_UUID"] = mdr_uuid
            entry["MDR_name"] = body.get("name")
            entry["MDR_author"] = metadata.get("author")
            entry["MDR_version"] = metadata.get("version")
            entry["MDR_last_modified"] = str(metadata.get("modified"))

            # Generate current ISO 8601 Date+Time with UTC offset
            current_datetime = datetime.datetime.now(datetime.timezone.utc).astimezone()
            current_datetime = current_datetime.replace(microsecond=0)
            entry["MDR_deployed"] = str(current_datetime.isoformat())

            entry["MDR_detection_model"] = body.get("detection_model")
            entry["MDR_severity"] = body.get("response", {}).get("alert_severity")
            entry["MDR_alert_handling_team"] = (
                body.get("response", {}).get("responders") or self.DEFAULT_RESPONDERS
            )
            procedure = body.get("response", {}).get("procedure", {})
            entry["MDR_response_procedure"] = json.dumps(procedure)
            entry["MDR_attack_technique"] = techniques
            entry["MDR_saw_playbook"] = body.get("response", {}).get("playbook")
            entry["MDR_documentation"] = self.GITWIKI + body.get("name").replace(
                " ", "-"
            ).replace("_", "-")

            entry = {k: v if v is not None else "" for k, v in entry.items()}

            mdr_to_update.append(entry)


        # Splunk magic to build SPL that will update the query
        content = {"body": mdr_to_update}
        raw = json.dumps(json.dumps(content, default=str)).lstrip('"').rstrip('"')
        query = f"""| makeresults
        | eval _raw="{raw}"
        | spath path=body{{}} output=temp 
        | mvexpand temp 
        | spath input=temp 
        | fields - _raw _time temp
        | inputlookup append=true {lookup_name}
        | stats first(*) as * by MDR_UUID
        | outputlookup {lookup_name}
        """

        log("DEBUG", "Compiled lookup creation query", query)

        # Connect to splunk service
        service = connect_splunk(
            host=self.SPLUNK_URL,
            port=self.SPLUNK_PORT,
            token=self.SPLUNK_TOKEN,
            app=self.SPLUNK_APP,
            ssl_enabled=self.SSL_ENABLED
        )

        # Deploy lookup in oneshot (executes immediately) job
        print("🥁 Exporting query to Splunk...")
        service.jobs.oneshot(query)

        time_to_execute = "%.2f" % (time.time() - start_time)
        print(f"\n⏱️ Exported lookup in {time_to_execute} seconds")
        print("✅ Successfully updated lookup to Splunk")


def declare():
    return SplunkMetadataDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkMetadataDeploy().deploy(deployment=DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS,
                                  lookup_name=DebugEnvironment.METADATA_DEPLOYMENT_TEST_FILE)