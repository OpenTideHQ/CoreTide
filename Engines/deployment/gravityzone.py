import git
import sys

from typing import Sequence

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.plugins import DeployMDR
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.debug import DebugEnvironment
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy) 
from Engines.modules.deployment import TideDeployment, ExternalIdHelper, check_status
from Engines.modules.models import TideConfigs, StatusStrategy

from Engines.modules.systems.gravityzone import GravityZoneService, GenericRule, SeverityMapping, AutomaticActions
from Engines.modules.logs import log

class GravityZoneDeployer(DeployMDR):

    def compile_deployment(self,
                        data:TideModels.MDR,
                        tenant_config:TideConfigs.Systems.GravityZone.Tenant)->GenericRule:
        """
        Builds the Detection Rule structure to be submitted to the GravityZone API.
        
        Converts internal TideModels.MDR.Configurations.GravityZone format to API-compliant
        GenericRule dataclass with proper field mapping and value transformations.
        
        Args:
            data: MDR model containing GravityZone configuration
            tenant_config: Tenant-specific configuration
            
        Returns:
            GenericRule dataclass ready for API submission
        """
        mdr_config = data.configurations.gravityzone
        
        if not mdr_config:
            log("FAILURE", "Missing GravityZone configuration in MDR", data.metadata.uuid)
            raise Exception("GravityZone configuration not found")
        
        # Base details
        rule_name = data.name
        rule_description = data.description
        rule_status = 0 if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT else 1
        
        # Map severity from MDR response to GravityZone severity levels
        rule_severity = SeverityMapping[data.response.alert_severity].value
        if mdr_config.severity:
            rule_severity = SeverityMapping[mdr_config.severity].value
        
        # Convert target to lowercase as required by API
        rule_target = mdr_config.target.lower()
        
        # Build criteria list
        criteria_list = []
        for criterion in mdr_config.criteria:
            # Convert relation to lowercase ('Is' -> 'is', 'Contains' -> 'contains', 'Is One Of' -> 'any')
            relation_mapping = {
                "Is": "is",
                "Contains": "contains",
                "Is One Of": "any"
            }
            relation = relation_mapping.get(criterion.relation, criterion.relation.lower())
            
            # Ensure we have a valid relation string
            if relation is None:
                log("WARNING", f"Unknown relation type: {criterion.relation}", "Defaulting to 'is'")
                relation = "is"
            
            # Ensure value is always a list of strings
            if isinstance(criterion.value, list):
                value = [str(v) for v in criterion.value]
            else:
                value = [str(criterion.value)]
            
            # Prefix field with target type if not already prefixed
            # API requires: File.Name, Process.Path, Connection.SourceIP, Registry.Key, etc.
            field = criterion.field
            target_prefix = mdr_config.target + "."
            if not field.startswith(target_prefix):
                field = target_prefix + field
                log("DEBUG", f"Prefixed field with target", f"{criterion.field} -> {field}")
            
            criteria_list.append(GenericRule.Settings.CriteriaItem(
                field=field,
                relation=relation,
                value=value
            ))
        
        # Build automatic actions if specified
        automatic_actions = None
        if mdr_config.actions:
            automatic_actions = []
            actions = mdr_config.actions
            
            if actions.isolate:
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.Isolate.value,
                    enabled=True
                ))
            
            if actions.collect_investigation_package:
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.CollectInvestigationPackage.value,
                    enabled=True
                ))
            
            if actions.add_to_sandbox:
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.AddToSandbox.value,
                    enabled=True
                ))
            
            if actions.kill_process:
                # Map kill_process scope to settings
                settings = None
                if actions.kill_process == "Include Parent Process":
                    settings = GenericRule.Settings.AutomaticAction.ActionSettings(includeParent=True)
                elif actions.kill_process == "Include Child Processes":
                    settings = GenericRule.Settings.AutomaticAction.ActionSettings(includeChildren=True)
                elif actions.kill_process == "Full":
                    settings = GenericRule.Settings.AutomaticAction.ActionSettings(
                        includeParent=True,
                        includeChildren=True
                    )
                
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.KillProcess.value,
                    enabled=True,
                    settings=settings
                ))
            
            if actions.antimalware_scan:
                scan_type = 1 if actions.antimalware_scan == "Quick" else 2
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.Scan.value,
                    enabled=True,
                    settings=GenericRule.Settings.AutomaticAction.ActionSettings(scanType=scan_type)
                ))
            
            if actions.quarantine:
                # Map quarantine scope to settings
                settings = None
                if actions.quarantine == "Include Parent Process File":
                    settings = GenericRule.Settings.AutomaticAction.ActionSettings(includeParent=True)
                elif actions.quarantine == "Include Files of Child Processes":
                    settings = GenericRule.Settings.AutomaticAction.ActionSettings(includeChildren=True)
                elif actions.quarantine == "Full":
                    settings = GenericRule.Settings.AutomaticAction.ActionSettings(
                        includeParent=True,
                        includeChildren=True
                    )
                
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.Quarantine.value,
                    enabled=True,
                    settings=settings
                ))
            
            if actions.risk_scan:
                automatic_actions.append(GenericRule.Settings.AutomaticAction(
                    type=AutomaticActions.RiskScan.value,
                    enabled=True
                ))
        
        # Note: Exclusions are handled as separate rule deployments (type=2), not as filters
        # They will be deployed independently with their own rule IDs
        
        # Build settings object
        settings = GenericRule.Settings(
            status=rule_status,
            severity=rule_severity,
            target=rule_target,
            criteriaList=criteria_list,
            automaticActions=automatic_actions if automatic_actions else None,
            filters=None
        )
        
        # Build tags list
        tags = list(mdr_config.tags) if mdr_config.tags else None
        
        # Get company ID from tenant config - required for GravityZone API
        if not tenant_config.setup.company_id:
            log("FATAL",
                f"Missing company_id for tenant {tenant_config.name}",
                "The company_id field is required in the tenant setup configuration",
                "Add company_id to your gravityzone.toml [tenants.setup] section")
            raise Exception(f"Missing required company_id for tenant {tenant_config.name}")
        
        company_id = tenant_config.setup.company_id
        
        # Create the detection rule (type 1)
        return GenericRule(
            type=1,
            name=rule_name,
            settings=settings,
            companyId=company_id,
            description=rule_description,
            tags=tags,
            returnRuleId=True
        )
    
    def deploy_mdr(self,
            data:TideModels.MDR,
            service:GravityZoneService,
            tenant_config:TideConfigs.Systems.GravityZone.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """
        mdr_config = data.configurations.gravityzone
        if not mdr_config:
            raise Exception("GravityZone configuration not found")
        
        rule = self.compile_deployment(data=data, tenant_config=tenant_config)

        if mdr_config.rule_id_bundle:
            rule_id = mdr_config.rule_id_bundle.get(tenant_config.name.strip())
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

        
        if check_status(mdr_config.status) is StatusStrategy.DELETION:
            if not rule_id:
                log("FATAL",
                    "Cannot remove the rule as a rule_id could not be found in the file",
                    "You will need to manually check the target system to remove the rule")
            else:
                log("ONGOING",
                    f"Proceeding with deletion of rule against tenant {tenant_config.name}",
                    str(rule_id))
                
                service.delete_rule(rule_id=rule_id)
                ExternalIdHelper.remove_id(rule_id=rule_id,
                                           tenant_name=tenant_config.name,
                                           mdr_uuid=data.metadata.uuid)

        else:
            if rule_id:
                log("INFO", f"Found Rule ID", str(rule_id), "Going to update the rule")
                service.update_rule(rule_id=str(rule_id), rule=rule)
        
            else:
                rule_id = service.create_rule(rule)
                ExternalIdHelper.insert_id(rule_id=rule_id,
                                           tenant_name=tenant_config.name,
                                           mdr_uuid=data.metadata.uuid,
                                           system_name=DataTide.Configurations.Systems.GravityZone.platform.identifier)


    def deploy(self, mdr_deployment: Sequence[TideModels.MDR] | list[str], deployment_plan:DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or TideModels.MDR Objects
        """
        
        log("INFO", "Received deployment information", str(mdr_deployment))
        
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Models.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.GRAVITYZONE,
                                    strategy=deployment_plan)

        for tenant_deployment in deployment.rule_deployment:
            service = GravityZoneService(tenant_deployment.tenant) #type: ignore

            for mdr in tenant_deployment.rules:
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant) #type: ignore

def declare():
    return GravityZoneDeployer()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    GravityZoneDeployer().deploy(["701b9c83-15f9-411d-bf3f-d11597b62f8b"], DeploymentStrategy.DEBUG)