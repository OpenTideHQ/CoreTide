import os
import git
import sys
import json
from typing import Literal
from pprint import pprint

import pandas as pd

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.splunk import (
    SplunkEngineInit,
    connect_splunk,
    cron_to_timeframe,
    create_query,
    splunk_timerange,
)
from Engines.modules.framework import (
    get_value_metaschema,
    techniques_resolver,
)
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide

from Engines.modules.plugins import DeployMDR


class SplunkDeploy(SplunkEngineInit, DeployMDR):

    def config_mdr(self, mdr):
        """
        Compiled the configuration that will be written to the saved search object.
        """

        config = dict()

        # Before processing MDR data, adding config configuration
        uuid = mdr.get("uuid") or mdr["metadata"]["uuid"]
        name = mdr["name"].strip()
        description = mdr["description"]
        mdr_splunk = mdr["configurations"]["splunk"]
        advanced_config = mdr_splunk.pop(
            "advanced", None
        )  # Remove advanced config and keep it separate
        
        # Normalize all types to string by safety
        if advanced_config:
            advanced_config = {k: str(v) for k,v in advanced_config.items()}
        
        # Exception for risk, as is a particular data structure in Splunk
        risk = mdr_splunk.get("risk")
        if risk:
            risk = mdr_splunk.pop("risk")

        mdr_splunk = pd.json_normalize(mdr_splunk, sep="|").to_dict(orient="records")[0]
        for key in mdr_splunk.copy():  # Avoids dict mutation errors
            new_key = str(key).split("|")[
                -1
            ]  # type:ignore Keep only the string after the last separator
            mdr_splunk[new_key] = mdr_splunk.pop(key)

        for key in mdr_splunk:
            param_name = get_value_metaschema(
                key, self.SPLUNK_SUBSCHEMA, "tide.mdr.parameter"
            )
            data = mdr_splunk[key]

            if key == "lookback":
                data = splunk_timerange(
                    data, skewing=self.SKEWING_VALUE, offset=self.OFFSET
                )

            if key == "duration":
                config["alert.suppress"] = "true"

            if key == "frequency":
                # If there is no cron expression, we assign the parameter of cron on it which will deploy
                if "cron" not in mdr_splunk:
                    custom_time = mdr_splunk.get(
                        "custom_time"
                    )  # Check if there is a custom time the rule should trigger at
                    if custom_time:
                        data = cron_to_timeframe(
                            data, mode="custom", custom_time=custom_time
                        )
                    else:
                        data = cron_to_timeframe(data, mode=self.TIMERANGE_MODE)
                    param_name = get_value_metaschema(
                        "cron", self.SPLUNK_SUBSCHEMA, "tide.mdr.parameter"
                    )

            # Splunk mostly expects comma separated list when multiple values are present
            if type(data) == list:
                data = ", ".join(data)

            if type(data) == str:
                data = data.strip()

            if param_name:
                config[param_name] = data

        # Disabled Check
        status = mdr_splunk["status"]
        if status == "DISABLED":
            config["disabled"] = "true"
            log("INFO", "🔕 Configuring saved search as disabled")

        # Alert Severity Configuration
        config["alert.severity"] = self.ALERT_SEVERITY_MAPPING[
            mdr["response"]["alert_severity"]
        ]

        # Risk action has a specific implementation in Splunk where it fully relies on a
        # single flattened JSON string to represent the entire risk configuration. This is
        # unique in Splunk and is most likely explained by the fact that risk is a list of dictionaries,
        # which can't be represented in the flat key:value structure of savedsearches.conf
        if risk:
            risk_config = []
            risk_param = get_value_metaschema(
                "risk", self.SPLUNK_SUBSCHEMA, "tide.mdr.parameter"
            )
            risk_objects_config = []
            threat_objects_config = []
            risk_message = risk.get("message")
            if ro := risk.get("risk_objects"):
                for risk_object in ro:
                    risk_object_paramed = {}
                    for key in risk_object:
                        risk_object_paramed[
                            get_value_metaschema(
                                key,
                                self.SPLUNK_SUBSCHEMA,
                                "tide.mdr.parameter",
                                scope="risk_objects",
                            )
                        ] = risk_object[key]
                    risk_objects_config.append(risk_object_paramed)

            if to := risk.get("threat_objects"):
                for threat_object in to:
                    threat_object_paramed = {}
                    for key in threat_object:
                        threat_object_paramed[
                            get_value_metaschema(
                                key,
                                self.SPLUNK_SUBSCHEMA,
                                "tide.mdr.parameter",
                                scope="threat_objects",
                            )
                        ] = threat_object[key]
                    threat_objects_config.append(threat_object_paramed)

            risk_config = risk_objects_config + threat_objects_config
            if risk_config:
                config[risk_param] = json.dumps(risk_config)
            if risk_message:
                config[
                    get_value_metaschema(
                        "message",
                        self.SPLUNK_SUBSCHEMA,
                        "tide.mdr.parameter",
                        scope="risk",
                    )
                ] = risk_message

        # If there are advanced configurations, add it to the otherall config
        if advanced_config:
            for adv in advanced_config:
                config[adv] = advanced_config[adv]

        # Add ManagedBy and set to responders
        responders = mdr.get("response", {}).get("responders") or ""
        config["alert.managedBy"] = responders

        # Add correlation search setup
        if self.CORRELATION_SEARCHES:
            config["action.correlationsearch.enabled"] = "true"
            # For compatibility with Splunk Enterprise Security post-processing on
            # correlation searches, append " - Rule" to the MDR name itself
            # and keep original name for correlationsearch label
            config["action.correlationsearch.label"] = name
            config["name"] = name + ' - Rule'
            techniques = techniques_resolver(uuid)
            if techniques:
                config["action.correlationsearch.annotations.mitre_attack"] = ", ".join(
                    techniques
                )

        # Human readable description
        config["description"] = description
        return config

    def deploy_mdr(self, mdr, service):
        """
        Deployment routine, connecting to the platform and combining base and custom configurations
        """

        # Generate saved search configuration
        mdr_config = self.config_mdr(mdr)

        # Fetch name for the saved search
        name: str = mdr_config["name"].strip()
        mdr_splunk: dict = mdr["configurations"]["splunk"]
        status: str = mdr_splunk["status"]
        query = create_query(mdr)

        # By default, status allows all the actions supported by the global config
        status_allowed_actions = self.SPLUNK_ACTIONS

        # Add status specific parameters
        status_modifiers = self.STATUS_MODIFIERS.get(status) or {}

        if status_modifiers:
            if "allowed_actions" in status_modifiers:
                allowed_actions_config = status_modifiers.pop("allowed_actions")
                # If explicitely set to False, we blank the actions allowed
                if allowed_actions_config in [False, None]:
                    log(
                        "INFO",
                        "This MDR will not have any action enabled in Splunk, as actions_enabled is set to False",
                        status,
                    )
                    status_allowed_actions = []
                else:
                    log(
                        "INFO",
                        "The enabled actions for this MDR will be constrained by the status modifier actions_enabled",
                        allowed_actions_config,
                    )
                    status_allowed_actions = allowed_actions_config

            # We pop out allowed_actions, remainder are attributes
            if status_modifiers:
                log(
                    "INFO",
                    f"Applying status modifiers for {status}",
                    str(status_modifiers),
                )
                mdr_config.update(status_modifiers)

        actions_config = {}

        # Add allowed splunk actions once the entire MDR is configured
        if self.SPLUNK_ACTIONS:
            # We enable the action only when a configuration has been set related to this action
            # For example, we may allow action.email, but will only configure it as enabled
            # if some parameter in the config related to it were configured
            triggered_actions = []
            for action in self.SPLUNK_ACTIONS:
                for param in mdr_config:
                    if "action." + action in param:
                        if action in status_allowed_actions:
                            triggered_actions.append(action)
                            actions_config["action." + action] = (
                                1  # Turning on the action
                            )
                            break

            if not triggered_actions:
                # Allowing default actions if they are not denied at status config level
                triggered_actions = [
                    action
                    for action in self.SPLUNK_DEFAULT_ACTIONS
                    if action in status_allowed_actions
                ]

            if triggered_actions:
                actions_config["actions"] = ", ".join(triggered_actions)

                # Actions modifiers which automate certain attributes bound to the action being allocated
                if "notable" in triggered_actions:
                    # Assign default notable title if not specified in mdr config
                    if "action.notable.param.rule_title" not in mdr_config:
                        actions_config["action.notable.param.rule_title"] = name
                        actions_config["action.notable.param.rule_description"] = (
                            mdr.get("description") or ""
                        )
                        actions_config["action.notable.param.severity"] = mdr[
                            "response"
                        ]["alert_severity"].lower()
                if "risk" in triggered_actions:
                    # Explicitely set _risk_score to 0 since it is set to 1 by the platform
                    # as a way to show a default GUI, but interferes with automation.
                    # All risk configuration are carried by action.notable.param._risk in a JSON bundle
                    actions_config["action.risk.param._risk_score"] = 0

            else:
                actions_config["actions"] = ""

        deploy_config = self.DEFAULT_CONFIG.copy()
        deploy_config.update(mdr_config)
        deploy_config.update(actions_config)
        deploy_config["search"] = query

        if self.DEBUG:
            log("DEBUG", "The following configuration was compiled")
            print(json.dumps(deploy_config, indent=1, sort_keys=True))

        # In Splunk, some configurations are coupled with others. The update()
        # method of saved_searches objects does not resolve this, and depending on the
        # order of the attrributes in the kwargs passed may hit blocks.
        #
        # This workaround lifts some of those identified blockers and will roll them out
        # after their dependencies, which are deployed first.

        second_stage_attributes = [
            "alert.suppress",  # needs alert.suppress.period to be set first
            "is_scheduled",  # needs alert_comparator to be set first
            "actions",  # requires other action namespace item to be set first
            "search",  # empirical testing show that the search don't update properly if not last
        ]
        second_stage = dict()

        for attribute in second_stage_attributes:
            if attribute in deploy_config:
                second_stage[attribute] = deploy_config.pop(attribute)

        pprint(deploy_config)

        # Check if saved search already exists or create a new one
        try:
            selected_search = service.saved_searches[name]
            log("INFO", "Found existing saved search", name)
        except:
            # Special case for removed rules, do not bother with recreating
            if status == "REMOVED":
                log(
                    "SKIP",
                    f"Saved search was already non existent, no action required",
                    name
                )
                return None

            # For all other rules, create a new saved search
            else:
                log("ONGOING", "Will create a new saved search", name)
                selected_search = service.saved_searches.create(name, search=query)

        # Steps to handle REMOVED rules
        if status == "REMOVED":
            service.saved_searches.delete(name)
            log("WARNING", f"Deleted splunk alert", name)
            return None

        # Debugging output; sets attribute one by one
        if self.DEBUG_STEP:
            for k, v in deploy_config.items():
                log("ONGOING", f"Updating value {k} with {v}")
                selected_search.update(**{k: v})

            if second_stage:
                for k, v in second_stage.items():
                    log("ONGOING", f"Updating value {k} with {v}")
                    selected_search.update(**{k: v})

        else:
            selected_search.update(**deploy_config)

            # Rolling out attributes with dependencies that will block the deployment if out of order.
            if second_stage:
                selected_search.update(**second_stage)
        log("SUCCESS", "Deployed on Splunk", name)

        return True

    def deploy(self, deployment: list[str]):

        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        service = connect_splunk(
            host=self.SPLUNK_URL,
            port=self.SPLUNK_PORT,
            token=self.SPLUNK_TOKEN,
            app=self.SPLUNK_APP,
            ssl_enabled=self.SSL_ENABLED
        )

        # Start deployment routine
        for mdr in deployment:
            mdr_data = DataTide.Models.mdr[mdr]

            # Check if modified MDR contains a platform entry (by safety, but should not happen since
            # the orchestrator will filter for the platform)
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"].keys():
                # Connection routine, if not connected yet.
                log("ONGOING", f"🔥 Currently deploying MDR {mdr_data['name']}...")
                self.deploy_mdr(mdr_data, service)
            else:
                log(
                    "SKIP",
                    f"🛑 Skipping {mdr_data.get('name')} as does not contain a Splunk rule",
                )

def declare():
    return SplunkDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
