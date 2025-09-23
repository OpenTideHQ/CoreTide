import git
import json
import sys
from typing import Sequence


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.systems.sentinel import (
    SentinelService,
    iso_duration_timedelta,
)
from Engines.modules.framework import get_vocab_entry, techniques_resolver
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.plugins import DeployMDR
from Engines.modules.models import (TideModels,
                                    TideConfigs,TenantDeployment,
                                    DeploymentStrategy) 
from Engines.modules.deployment import TideDeployment
from Engines.modules.errors import TideErrors

from azure.mgmt.securityinsight import SecurityInsights


class SentinelDeploy(DeployMDR):

    def compile_deployment(self,
                           service: SecurityInsights,
                           data:TideModels.MDR):

        rule = service.alert_rules.models.ScheduledAlertRule()
        
        configuration = data.configurations.sentinel
        if not configuration:
            raise Exception
        status = configuration.status
        rule.enabled = True
        rule.query = configuration.query

        if status in ["DISABLED"]:
            rule.enabled = False

        suppression = configuration.alert.suppression

        # Handle suppression setting
        if type(suppression) is str:
            rule.suppression_enabled = True
            rule.suppression_duration = iso_duration_timedelta(suppression)
        # Handle disables suppression
        elif suppression is False:
            rule.suppression_enabled = False
            rule.suppression_duration = iso_duration_timedelta("1h") #Requires a default value, even if disabled
        else:
            raise TideErrors.TideMDRDataModelErrors("Suppression set to true, must be false or int")
        
        if configuration.scheduling.nrt is True:
            rule.kind = "NRT"
        else:
            if not configuration.scheduling.frequency:
                raise TideErrors.TideMDRDataModelErrors("Missing frequency")
            if not configuration.scheduling.lookback:
                raise TideErrors.TideMDRDataModelErrors("Missing lookback")

            rule.query_frequency = iso_duration_timedelta(
                configuration.scheduling.frequency
            )
            rule.query_period = iso_duration_timedelta(
                configuration.scheduling.lookback
            )
            if configuration.trigger:
                rule.trigger_threshold = configuration.trigger.threshold
                rule.trigger_operator = configuration.trigger.operator

        details_overrides = service.alert_rules.models.AlertDetailsOverride()

        if alert_title:=configuration.alert.title:
            details_overrides.alert_display_name_format = alert_title
        if alert_description:=configuration.alert.description:
            details_overrides.alert_description_format = alert_description

        if dynamic_properties:=configuration.alert.dynamic_properties:
            alert_dynamic_properties = []
            alert_dynamic_property = service.alert_rules.models.AlertPropertyMapping()
            for property in dynamic_properties:
                alert_dynamic_property.alert_property = property.property
                alert_dynamic_property.value = property.column
                alert_dynamic_properties.append(alert_dynamic_property)

            details_overrides.alert_dynamic_properties = alert_dynamic_properties

        rule.alert_details_override = details_overrides

        # MITRE ATT&CK Mapping
        if techniques:=configuration.alert.techniques:
            rule.techniques = techniques
        if tactics:=configuration.alert.tactics:
            rule.tactics = tactics

        # Custom Details
        if custom_details:=configuration.alert.custom_details:
            rule.custom_details = {detail.key:detail.column for detail in custom_details}

        # Event Grouping
        if not configuration.grouping:
            raise TideErrors.TideMDRDataModelErrors("Missing Grouping > Event")
        log("INFO", "Event grouping configuration", configuration.grouping.event)
        event_grouping = service.alert_rules.models.EventGroupingSettings()
        event_grouping.aggregation_kind = configuration.grouping.event
        rule.event_grouping_settings = event_grouping
        
        # Incident Configuration
        alert_enabled = configuration.alert.create_incident
        log("INFO", "Alert Enabled", str(alert_enabled))
        incident_configuration = service.alert_rules.models.IncidentConfiguration(
            create_incident=alert_enabled
        )

        # Alert Grouping Configuration
        grouping_enabled = configuration.grouping.alert.enabled
        log("INFO", "Alert Grouping Enabled", str(grouping_enabled))

        grouping_lookback = configuration.grouping.alert.grouping_lookback
        if grouping_enabled:
            if not grouping_lookback:
                raise TideErrors.TideMDRDataModelErrors("Missing Grouping Lookback")
            grouping_lookback = iso_duration_timedelta(
                grouping_lookback
            )
        else:
            if not grouping_lookback:
                grouping_lookback = iso_duration_timedelta("1h")
        
        reopen_closed_incident = configuration.grouping.alert.reopen_closed_incidents or False
        matching_method = configuration.grouping.alert.matching or "AllEntities" #Sane default, needed for typing
        group_by_entities = configuration.grouping.alert.group_by_entities
        group_by_alert_details = configuration.grouping.alert.group_by_alert_details
        group_by_custom_details = configuration.grouping.alert.group_by_custom_details

        grouping_configuration = service.alert_rules.models.GroupingConfiguration(
            enabled=grouping_enabled,
            lookback_duration=grouping_lookback, #type: ignore
            reopen_closed_incident=reopen_closed_incident,
            matching_method=matching_method,
            group_by_entities=group_by_entities, #type: ignore
            group_by_alert_details=group_by_alert_details,#type: ignore
            group_by_custom_details=group_by_custom_details,#type: ignore
        )

        incident_configuration.grouping_configuration = grouping_configuration
        rule.incident_configuration = incident_configuration

        # Entity Mapping
        entity_data = configuration.entities
        entity_mappings = []
        if entity_data:
            for entity in entity_data:
                mappings = service.alert_rules.models.EntityMapping()
                mappings.entity_type = entity.entity
                field_mappings = []

                for field in entity.mappings:
                    field_mapping = service.alert_rules.models.FieldMapping()
                    field_mapping.identifier = field.identifier
                    field_mapping.column_name = field.column
                    field_mappings.append(field_mapping)

                mappings.field_mappings = field_mappings
                entity_mappings.append(mappings)
        rule.entity_mappings = entity_mappings


        # Assign severity, Capping at high which is the maximum in Sentinel
        severity = configuration.alert.severity or data.response.alert_severity
        if severity == "Critical":
            severity = "High"
        rule.severity = severity

        # Human readable name and description on the console
        rule.display_name = data.name
        rule.description = data.description
        
        # Auto-enrich with techniques resolver
        techniques = techniques_resolver(data.metadata.uuid)
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

        log("INFO", "Compiled Rule", json.dumps(rule.as_dict()))

        return rule

    def deploy_mdr(self,
                data:TideModels.MDR,
                service:SecurityInsights,
                tenant_config:TideConfigs.Systems.Sentinel.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """

        if not data.configurations.sentinel:
            raise TideErrors.TideSystemConfigurationErrors("Missing Sentinel")

        mdr_name = data.name
        mdr_uuid = data.metadata.uuid

        if data.configurations.sentinel.status == "REMOVED":
            log(
                "WARNING",
                "The rule will be removed from the Sentinel Workspace",
                mdr_name,
            )
            service.alert_rules.delete(
                resource_group_name=tenant_config.setup.resource_group,
                workspace_name=tenant_config.setup.workspace_name,
                rule_id=mdr_uuid,
            )

            log("SUCCESS", "Deleted rule from workspace")
            return True

        log("ONGOING", "Compiling Scheduled Alert Object")
        alert_rule = self.compile_deployment(data=data,
                                             service=service)

        log("INFO", "Deploying rule to Sentinel")
        service.alert_rules.create_or_update(
            resource_group_name=tenant_config.setup.resource_group,
            workspace_name=tenant_config.setup.workspace_name,
            rule_id=mdr_uuid,
            alert_rule=alert_rule,
        )

        log("SUCCESS", "Deployed MDR Successfully", mdr_name)
        return True

    def deploy(self, mdr_deployment: Sequence[TideModels.MDR] | list[str], deployment_plan:DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or TideModels.MDR Objects
        """
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

        for tenant_deployment in deployment.rule_deployment: #type:ignore 
            tenant_deployment: TenantDeployment.Sentinel # Force assignment here as case switch in TideDeployment doesn't seem to resolve perfectly
            log("ONGOING", "Currently targeting tenant", tenant_deployment.tenant.name)
            service = SentinelService(tenant_deployment.tenant).connect()
            for mdr in tenant_deployment.rules:
                log("ONGOING", "Processing rule", mdr.name, mdr.metadata.uuid)
                self.deploy_mdr(data=mdr,
                                service=service,
                                tenant_config=tenant_deployment.tenant)



def declare():
    return SentinelDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelDeploy().deploy(["5e791284-684c-4245-9ac7-cf00a1d041d6"], DeploymentStrategy.DEBUG)