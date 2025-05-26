import git
import sys

from typing import Sequence, Optional, Literal
from dataclasses import dataclass, asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.plugins import DeployMDR
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy) 
from Engines.modules.deployment import TideDeployment, ExternalIdHelper
from Engines.modules.logs import log
from Engines.modules.models import TideConfigs
from Engines.modules.errors import TideErrors

from Engines.modules.systems.crowdstrike import CrowdstrikeService, DetectionRule



class CrowdstrikeDeploy(DeployMDR):

    def compile_deployment(self,
                           data:TideModels.MDR,
                           tenant_config:TideConfigs.Systems.Crowdstrike.Tenant)->DetectionRule:
        """
        Builds the Detection Rule call made to the API
        """
        
        def map_severity(severity:str)->int:
            match severity:
                case "Informational":
                    return 10
                case "Low":
                    return 30
                case "Medium":
                    return 50
                case "High":
                    return 70
                case "Critical":
                    return 90
                case _:
                    log("FATAL",
                        "Could not map severity to expected Crowdstrike values",
                        "Expected Informational, Low, Medium, High or Critical")
                    raise TideErrors.TideConfigurationErrors("Invalid Severity")
        
        configuration = data.configurations.crowdstrike
        if not configuration:
            log("FATAL",
                f"[{data.metadata.uuid}] {data.name} does not contain a crowdstrike section")
            raise TideErrors.TideConfigurationErrors("Missing Crowdstrike Section")
        name = configuration.details.name or data.name
        description = configuration.details.description or data.description
        #Customer ID must be lowercase, and without the -XX suffix
        customer_id = tenant_config.setup.customer_id.split("-")[0].lower()
        tactic = configuration.details.tactic
        technique = configuration.details.technique
        status = "active" if configuration.status != "DISABLED" else "inactive"
        severity = configuration.details.severity or data.response.alert_severity
        severity = map_severity(severity)
        
        
        filter = configuration.query
        lookback = configuration.schedule.lookback
        outcome = configuration.details.outcome.lower()
        trigger_mode = configuration.details.trigger.lower()
        
        if outcome not in ["detection", "incident"]:
            log("FATAL",
                "outcome value not expected",
                str(outcome),
                "Expects detection or incident")
            raise TideErrors.TideConfigurationErrors("Invalid Crowdstrike outcome value")
        
        if trigger_mode not in ["verbose", "summary"]:
            log("FATAL",
                "trigger value not expected",
                str(outcome),
                "Expects verbose or summary")
            raise TideErrors.TideConfigurationErrors("Invalid Crowdstrike outcome value")
        
        search = DetectionRule.Search(outcome=outcome, #type: ignore
                                        filter=filter,
                                        lookback=lookback,
                                        trigger_mode=trigger_mode) #type: ignore

        definition = configuration.schedule.frequency
        schedule = DetectionRule.Operation.Schedule(definition=f"@every {definition}")
        
        
        def fix_datetime(timestamp:str)->str:
            """
            Fixes edge case in YAML where the user doesn't encapsulate the timestamp
            as a string, which will mess it up during serialization.
            
            For example

            * `2025-04-15T19:00:00Z` in YAML will be stored as a datetime type with string
            representation `2025-04-15 19:00:00+00:00`. This function transforms it back into 
            `2025-04-15T19:00:00Z`
            * `"2025-04-15T19:00:00Z"` in YAML will be correctly serialized, and left untouched 
            
            -> This function always returns the expected `YYYY-MM-DDTHH:MM:SSZ` format
            """
            timestamp = str(timestamp)
            if "Z" not in timestamp:
                return timestamp.replace(" ", "T").split("+")[0] + "Z"
            else: 
                return timestamp
             
        start_on = configuration.schedule.start
        start_on = fix_datetime(start_on) if start_on else None
        stop_on = configuration.schedule.end
        stop_on = fix_datetime(stop_on) if stop_on else None
        operation = DetectionRule.Operation(schedule=schedule,
                                            start_on=start_on,
                                            stop_on=stop_on)
        contributors = configuration.contributors 
        author = contributors or [data.metadata.author]
        author = ", ".join(author)
        comment = f"Updated by OpenTide Crowdstrike Deployer - Author(s) : {author}"
        return DetectionRule(name=name, 
                             description=description,
                             customer_id=customer_id,
                             tactic=tactic,
                             technique=technique,
                             status=status,
                             severity=severity,
                             search=search,
                             operation=operation,
                             comment=comment)
    
    def deploy_mdr(self,
                data:TideModels.MDR,
                service:CrowdstrikeService,
                tenant_config:TideConfigs.Systems.Crowdstrike.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """
        mdr_config = data.configurations.crowdstrike
        if not mdr_config:
            raise Exception
    
        rule = self.compile_deployment(data=data, tenant_config=tenant_config)

        if mdr_config.rule_id_bundle:
            mdr_config.rule_id_bundle
            rule_id = mdr_config.rule_id_bundle.get(tenant_config.name.strip()) #type:ignore
            if rule_id:
                log("INFO",
                    f"Retrieved ID for tenant {tenant_config.name} in MDR",
                    str(rule_id),
                    "Will perform an update")
            else:
                log("INFO",
                    f"Could not retrieve ID for tenant {tenant_config.name} in MDR existing rule IDs",
                    str(mdr_config.rule_id_bundle),
                    "Will create a new rule, and write back the ID to the file")
        else:
            log("INFO",
                f"Could not retrieve ID for tenant {tenant_config.name} in MDR",
                "Will create a new rule, and write back the ID to the file")
            rule_id = None

        if mdr_config.status == "REMOVED":
            if not rule_id:
                log("FATAL",
                    "Cannot remove the rule as a rule_id could not be found in the file",
                    "You will need to manually check the target system to remove the rule")
            else:
                log("ONGOING",
                    f"Proceeding with deletion of rule against tenant {tenant_config.name}",
                    str(rule_id))
                
                service.delete_detection_rule(rule_id=rule_id)
                ExternalIdHelper.remove_id(rule_id=rule_id,
                                           tenant_name=tenant_config.name,
                                           mdr_uuid=data.metadata.uuid)

        else:
            if rule_id:
                log("INFO", f"Found Rule ID", str(rule_id), "Going to update the rule")
                service.update_detection_rule(rule=rule,
                                              rule_id=rule_id)
        
            else:
                rule_id = service.create_detection_rule(rule)
                ExternalIdHelper.insert_id(rule_id=rule_id,
                                           tenant_name=tenant_config.name,
                                           mdr_uuid=data.metadata.uuid,
                                           system_name=DataTide.Configurations.Systems.Crowdstrike.platform.identifier)



    def deploy(self, mdr_deployment: Sequence[TideModels.MDR] | list[str], deployment_plan:DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or TideModels.MDR Objects
        """
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Objects.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.CROWDSTRIKE,
                                    strategy=deployment_plan)

        for tenant_deployment in deployment.rule_deployment:
            log("ONGOING", "Currently targeting tenant", tenant_deployment.tenant.name)
            service = CrowdstrikeService(tenant_deployment.tenant) #type: ignore

            for mdr in tenant_deployment.rules:
                log("ONGOING", "Processing rule", mdr.name, mdr.metadata.uuid)
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant) #type: ignore

def declare():
    return CrowdstrikeDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CrowdstrikeDeploy().deploy(["8e9d2ad5-6488-48b5-bedd-f971303f5d38"], DeploymentStrategy.DEBUG)