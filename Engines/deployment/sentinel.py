import os
import git
import os
import sys
import yaml
from pprint import pprint
from pathlib import Path

import pandas as pd

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.sentinel import (
    SentinelEngineInit,
    connect_sentinel,
    build_query,
    build_description,
    iso_duration_timedelta,
)
from Engines.modules.framework import get_vocab_entry, techniques_resolver
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
#from Engines.modules.plugins import DeployMDR

from azure.mgmt.securityinsight import SecurityInsights


class SentinelDeploy(SentinelEngineInit):

    def config_mdr(self, data, client: SecurityInsights):

        mdr_uuid = data.get("uuid") or data["metadata"]["uuid"]
        rule = client.alert_rules.models.ScheduledAlertRule()
        rule.name = data["name"]
        mdr_sentinel_raw = data["configurations"]["sentinel"]
        status = mdr_sentinel_raw["status"]

        status_parameters = get_vocab_entry("status", status, "attributes_override")
        if status_parameters is dict:
            status_parameters = status_parameters.get(self.DEPLOYER_IDENTIFIER)
        else:
            status_parameters = {}

        default_config = pd.json_normalize(self.DEFAULT_CONFIG, sep=".").to_dict(
            orient="records"
        )[0]
        mdr_config = pd.json_normalize(mdr_sentinel_raw, sep=".").to_dict(
            orient="records"
        )[0]

        mdr_sentinel = {}
        mdr_sentinel.update(default_config)
        mdr_sentinel.update(mdr_config)
        if status_parameters:
            mdr_sentinel.update(
                pd.json_normalize(status_parameters, sep=".").to_dict(orient="records")[
                    0
                ]
            )

        if self.DEBUG:
            with open("sentinel_config.toml", "w+") as out:
                pprint(mdr_sentinel)

        status = mdr_sentinel["status"]
        rule.enabled = True
        if status in ["DISABLED"]:
            rule.enabled = False

        suppression = mdr_sentinel.get("alert.suppression")

        # Handle suppression setting
        if suppression:
            rule.suppression_enabled = True
            rule.suppression_duration = iso_duration_timedelta(mdr_sentinel["alert.suppression"])
        # Handle disables suppression
        elif suppression is False:
            rule.suppression_enabled = False
            rule.suppression_duration = iso_duration_timedelta("1h") #Requires a default value, even if disabled
        # Handle defaults
        else:
            rule.suppression_enabled = mdr_sentinel.get("alert.suppression_enabled")
            rule.suppression_duration = iso_duration_timedelta(mdr_sentinel["alert.suppression"])

        if mdr_sentinel.get("scheduling.nrt") == True:
            rule.kind = "NRT"
        else:
            rule.query_frequency = iso_duration_timedelta(
                mdr_sentinel["scheduling.frequency"]
            )
            rule.query_period = iso_duration_timedelta(
                mdr_sentinel["scheduling.lookback"]
            )
            rule.trigger_threshold = mdr_sentinel.get("threshold")
            rule.trigger_operator = mdr_sentinel.get("trigger")

        details_overrides = client.alert_rules.models.AlertDetailsOverride()
        details_overrides.alert_display_name_format = mdr_sentinel.get("alert.title")
        if alert_description:=mdr_sentinel.get("alert.description"):
            details_overrides.alert_description_format = build_description(data, alert_description)
        dynamic_properties = mdr_sentinel.get("alert.dynamic_properties")
        if dynamic_properties:
            alert_dynamic_properties = []
            alert_dynamic_property = client.alert_rules.models.AlertPropertyMapping()
            for prop in dynamic_properties:
                alert_dynamic_property.alert_property = prop["property"]
                alert_dynamic_property.value = prop["column"]
                alert_dynamic_properties.append(alert_dynamic_property)

            details_overrides.alert_dynamic_properties = alert_dynamic_properties

        rule.alert_details_override = details_overrides

        # Custom Details
        custom_details = mdr_sentinel.get("alert.custom_details")
        if custom_details:
            cleaned_custom_details = {}
            for detail in custom_details:
                cleaned_custom_details[detail["key"]] = detail["column"]

            rule.custom_details = cleaned_custom_details

        # Event Grouping
        event_grouping = client.alert_rules.models.EventGroupingSettings()
        event_grouping.aggregation_kind = mdr_sentinel.get("grouping.event")

        # Incident Configuration
        alert_enabled = mdr_sentinel["alert.create_incident"]
        incident_configuration = client.alert_rules.models.IncidentConfiguration(
            create_incident=alert_enabled
        )

        # Alert Grouping Configuration
        grouping_enabled = mdr_sentinel["grouping.alert.enabled"]
        grouping_lookback = iso_duration_timedelta(
            mdr_sentinel["grouping.alert.grouping_lookback"]
        )
        reopen_closed_incident = mdr_sentinel["grouping.alert.reopen_closed_incidents"]
        matching_method = mdr_sentinel["grouping.alert.matching"]
        group_by_entities = mdr_sentinel.get(
            "grouping.alert.matching.group_by_entities"
        )
        group_by_alert_details = mdr_sentinel.get(
            "grouping.alert.matching.group_by_alert_details"
        )
        group_by_custom_details = mdr_sentinel.get(
            "grouping.alert.matching.group_by_custom_details"
        )
        grouping_configuration = client.alert_rules.models.GroupingConfiguration(
            enabled=grouping_enabled,
            lookback_duration=grouping_lookback,
            reopen_closed_incident=reopen_closed_incident,
            matching_method=matching_method,
            group_by_entities=group_by_entities,
            group_by_alert_details=group_by_alert_details,
            group_by_custom_details=group_by_custom_details,
        )

        incident_configuration.grouping_configuration = grouping_configuration
        rule.incident_configuration = incident_configuration

        # Entity Mapping
        entity_data = mdr_sentinel.get("entities")
        entity_mappings = []
        if entity_data:
            for entity in entity_data:
                mappings = client.alert_rules.models.EntityMapping()
                mappings.entity_type = entity["entity"]
                field_mappings = []

                for field in entity["mappings"]:
                    field_mapping = client.alert_rules.models.FieldMapping()
                    field_mapping.identifier = field["identifier"]
                    field_mapping.column_name = field["column"]
                    field_mappings.append(field_mapping)

                mappings.field_mappings = field_mappings
                entity_mappings.append(mappings)
        rule.entity_mappings = entity_mappings
        # Add automated query extensions
        rule.query = build_query(data)

        # Assign severity, Capping at high which is the maximum in Sentinel
        severity = data["response"]["alert_severity"]
        if severity == "Critical":
            severity = "High"
        rule.severity = severity

        # Human readable name and description on the console
        rule.display_name = data["name"]
        rule.description = build_description(data)

        # Auto-enrich with techniques resolver
        techniques = techniques_resolver(mdr_uuid)
        if techniques:
            tactics = list()
            for t in techniques:
                # Sentinel backend expects PascalCase
                vocab_tactics = [
                    t.title().replace(" ", "").strip()
                    for t in get_vocab_entry("att&ck", t, "tide.vocab.stages")
                ]
                tactics.extend(vocab_tactics)

            # Sentinel does not currently support sub-techniques for mapping
            techniques = [t.split(".")[0] for t in techniques]

            # Remove duplicates from returned techniques and tactics
            techniques = list(dict.fromkeys(techniques))
            tactics = list(dict.fromkeys(tactics))

            rule.tactics = tactics
            rule.techniques = techniques

        return rule

    def deploy_mdr(self, data, client: SecurityInsights):
        """
        Deployment routine, connecting to the platform and deploying the configuration
        """

        mdr_name = data["name"]
        mdr_uuid = data.get("uuid") or data["metadata"]["uuid"]
        mdr_status = data["configurations"][self.DEPLOYER_IDENTIFIER]["status"]

        if mdr_status in ["REMOVED"]:
            log(
                "WARNING",
                "The rule will be removed from the Sentinel Workspace",
                mdr_name,
            )
            client.alert_rules.delete(
                resource_group_name=self.AZURE_SENTINEL_RESOURCE_GROUP,
                workspace_name=self.AZURE_SENTINEL_WORKSPACE_NAME,
                rule_id=mdr_uuid,
            )

            log("SUCCESS", "Deleted rule from workspace")
            return True

        log("ONGOING", "Compiling Scheduled Alert Object")
        alert_rule = self.config_mdr(data, client)

        log("INFO", "Deploying rule to Sentinel")
        client.alert_rules.create_or_update(
            resource_group_name=self.AZURE_SENTINEL_RESOURCE_GROUP,
            workspace_name=self.AZURE_SENTINEL_WORKSPACE_NAME,
            rule_id=mdr_uuid,
            alert_rule=alert_rule,
        )

        log("SUCCESS", "Deployed MDR Successfully", mdr_name)
        return True

    def deploy(self, deployment: list[str]):

        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        # Connect to client that is injected into deployment
        client = connect_sentinel(
            client_id=self.AZURE_CLIENT_ID,
            client_secret=self.AZURE_CLIENT_SECRET,
            tenant_id=self.AZURE_TENANT_ID,
            subscription_id=self.AZURE_SUBSCRIPTION_ID,
            ssl_enabled=self.SSL_ENABLED
        )

        for mdr in deployment:
            print(deployment)
            mdr_data = DataTide.Objects.mdr[mdr]

            # Check if modified MDR contains a platform entry (by safety, but should not happen since
            # the orchestrator will filter for the platform)
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"].keys():
                self.deploy_mdr(mdr_data, client)
            else:
                log(
                    "SKIP",
                    "Skipping {mdr_data.get('name')} as does not contain a Sentinel rule",
                )


def declare():
    return SentinelDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)