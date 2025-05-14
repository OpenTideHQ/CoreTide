import git
import sys

from typing import Sequence
from dataclasses import dataclass

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems, TideLoader
from Engines.modules.plugins import DeployMDR
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy) 
from Engines.modules.deployment import TideDeployment
from Engines.modules.logs import log

from Engines.modules.systems.defender_for_endpoint import (DetectionRule,
                                                           Severity,
                                                           SeverityMapping,
                                                           DefenderForEndpointService)
    




class DefenderForEndpointDeploy(DeployMDR):
    
    def deploy_mdr(self, data:TideModels.MDR, service:DefenderForEndpointService, tenant:str):

        def lower_first_character(string:str)->str:
            return string[0].lower() + string[1:]

        mdr_config = data.configurations.defender_for_endpoint
        
        if not mdr_config:
            exit()

        # Handle Response Actions 
        response_actions = []

        if mdr_config.actions:
            @dataclass
            class ResponseAction(DetectionRule.DetectionAction.ResponseAction):...
            @dataclass
            class ResponseActionIsolateDevice(DetectionRule.DetectionAction.ResponseActionIsolateDevice):...
            @dataclass
            class ResponseActionFileActions(DetectionRule.DetectionAction.ResponseActionFileActions):...

            if device_actions:=mdr_config.actions.devices:
                if isolation_type:=device_actions.isolate_device:
                    response_actions.append(ResponseActionIsolateDevice(odata_type="#microsoft.graph.security.isolateDeviceResponseAction",
                                                                        isolationType=lower_first_character(isolation_type)))

                if device_actions.collect_investigation_package:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.collectInvestigationPackageResponseAction"))

                if device_actions.initiate_investigation:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.initiateInvestigationResponseAction"))

                if device_actions.restrict_app_execution:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.restrictAppExecutionResponseAction"))

                if device_actions.run_antivirus_scan:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.runAntivirusScanResponseAction"))

            if file_actions:=mdr_config.actions.files:
                if file_actions.allow_block:
                    scope = []
                    identifer = file_actions.allow_block.identifier
                    if file_actions.allow_block.groups:
                        if file_actions.allow_block.groups.selection == "Specific":
                            scope = file_actions.allow_block.groups.device_groups

                    if file_actions.allow_block.action == "Allow":
                        response_actions.append(ResponseActionFileActions(odata_type="#microsoft.graph.security.allowFileResponseAction",
                                                                            identifier=lower_first_character(identifer),
                                                                            deviceGroupNames=scope))

                    elif file_actions.allow_block.action == "Block":
                        response_actions.append(ResponseActionFileActions(odata_type="#microsoft.graph.security.blockFileResponseAction",
                                                                            identifier=lower_first_character(identifer),
                                                                            deviceGroupNames=scope))

                if identifier:=file_actions.quarantine_file:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.stopAndQuarantineFileResponseAction",
                                                            identifier=identifier))

            if user_actions:=mdr_config.actions.users:
                if identifer:=user_actions.mark_as_compromised:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.markUserAsCompromisedResponseAction",
                                                            identifier=lower_first_character(identifer)))

                if identifer:=user_actions.disable_user:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.disableUserResponseAction",
                                                            identifier=lower_first_character(identifer)))

                if identifer:=user_actions.force_password_reset:
                    response_actions.append(ResponseAction(odata_type="#microsoft.graph.security.forceUserPasswordResetResponseAction",
                                                            identifier=lower_first_character(identifer)))


        # Handle Impacted Assets
        impacted_assets = []
        if mdr_config.impacted_entities:
            
            @dataclass
            class ImpactedAsset(DetectionRule.DetectionAction.AlertTemplate.ImpactedAsset):...

            if identifier:=mdr_config.impacted_entities.device:
                impacted_assets.append(ImpactedAsset(odata_type="#microsoft.graph.security.impactedDeviceAsset",
                                                    identifier=lower_first_character(identifier)))

            if identifier:=mdr_config.impacted_entities.user:
                impacted_assets.append(ImpactedAsset(odata_type="#microsoft.graph.security.impactedUserAsset",
                                                    identifier=lower_first_character(identifier)))
            if identifier:=mdr_config.impacted_entities.mailbox:
                impacted_assets.append(ImpactedAsset(odata_type="#microsoft.graph.security.impactedMailboxAsset",
                                                    identifier=lower_first_character(identifier)))

        # Handle Severity
        if mdr_config.alert.severity:
            severity = SeverityMapping[mdr_config.alert.severity].value
        else:
            severity = data.response.alert_severity
            severity = SeverityMapping[severity].value

        alert_template = DetectionRule.DetectionAction.AlertTemplate(title = mdr_config.alert.title or data.name,
                                                                    description=data.description,
                                                                    severity=severity, 
                                                                    category=mdr_config.alert.category,
                                                                    mitreTechniques=[],
                                                                    impactedAssets=impacted_assets,
                                                                    recommendedActions=mdr_config.alert.recommendation or None)

        scheduling = mdr_config.scheduling if mdr_config.scheduling != "NRT" else "0"
        
        is_enabled = False if mdr_config.status == "DISABLED" else True
        
        # Handle Query and Exclusions
        query = mdr_config.query.replace("\n","")
        if exclusions:=mdr_config.exclusions:
            for exclusion in exclusions:
                if exclusion.tenant == tenant:
                    query += exclusion.query.replace("\n","")
                    
        rule = DetectionRule(displayName=data.name,
                            isEnabled=is_enabled,
                            queryCondition=DetectionRule.QueryCondition(queryText=query),
                            schedule=DetectionRule.Schedule(period=scheduling), # type: ignore
                            detectionAction=DetectionRule.DetectionAction(alertTemplate=alert_template,
                                                                            responseActions=response_actions))

        if mdr_config.rule_id:
            rule_id = mdr_config.rule_id.get(tenant)
            log("INFO",
                f"Retrieved ID for tenant {tenant} in MDR",
                str(rule_id),
                "Will perform an update")
        else:
            log("INFO",
                f"Could not retrieve ID for tenant {tenant} in MDR",
                "Will create a new rule, and write back the ID to the file")

            rule_id = None
            
        if mdr_config.status == "REMOVED":
            if not rule_id:
                log("FATAL",
                    "Cannot remove the rule as a rule_id could not be found in the file",
                    "You will need to manually check the target system to remove the rule")
            else:
                log("ONGOING",
                    f"Proceeding with deletion of rule against tenant {tenant}",
                    str(rule_id))
                
                service.delete_detection_rule(rule_id)
                file_path = DataTide.Configurations.Global.Paths.Tide.mdr / DataTide.Models.files[data.metadata.uuid]
                with open(file_path, "r", encoding="utf-8") as mdr_file:
                    content = mdr_file.readlines()

                updated_content = list()

                #Remove previous rule ID from file
                for line in content:
                    if line.strip() != f"rule_id::{tenant}: {rule_id}":
                        updated_content.append(line)

                with open(file_path, "w", encoding="utf-8") as mdr_file:
                    log("SUCCESS",
                    f"Removed ID in MDR File for tenant {tenant}")
                    mdr_file.writelines(updated_content)

        else:
            if rule_id:
                service.update_detection_rule(rule, rule_id)
        
            else:
                rule_id = service.create_detection_rule(rule)
                file_path = DataTide.Configurations.Global.Paths.Tide.mdr / DataTide.Models.files[data.metadata.uuid]
                with open(file_path, "r", encoding="utf-8") as mdr_file:
                    content = mdr_file.readlines()
                
                updated_content = list()
                for line in content:
                    log("DEBUG", line)
                    if line.strip() == 'defender_for_endpoint:':
                        updated_content.append(line)
                        updated_content.append(f"    rule_id::{tenant}: {rule_id}\n")
                        log("DEBUG", "Appending line", str(rule_id))
                    else:
                        updated_content.append(line)

                with open(file_path, "w", encoding="utf-8") as mdr_file:
                    log("SUCCESS",
                    f"Updated MDR File with new ID for tenant {tenant}",
                    str(rule_id))
                    mdr_file.writelines(updated_content)

    
    def deploy(self, mdr_deployment: Sequence[TideModels.MDR], deployment_plan:DeploymentStrategy):
        
        mdr_deployment = [DataTide.Models.MDR[uuid] for uuid in mdr_deployment]

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.DEFENDER_FOR_ENDPOINT,
                                    strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            a = tenant_deployment.tenant
            service = DefenderForEndpointService(tenant_deployment.tenant) #type: ignore

            for mdr in tenant_deployment.rules:
                self.deploy_mdr(data=mdr, service=service, tenant=tenant_deployment.tenant.name)

            

def declare():
    return DefenderForEndpointDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    DefenderForEndpointDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)