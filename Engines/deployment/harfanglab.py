import git
import sys

from typing import Sequence
from dataclasses import asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.plugins import DeployMDR
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy) 
from Engines.modules.deployment import TideDeployment, ExternalIdHelper, check_status
from Engines.modules.logs import log
from Engines.modules.models import TideConfigs, StatusStrategy

from Engines.modules.systems.harfanglab import (
    HarfangLabService,
    SigmaRule,
    SigmaRuleBuilder
)


class HarfangLabDeploy(DeployMDR):
    """
    Deployer for HarfangLab EDR.
    Supports both Sigma rules (behavioral detection) and YARA rules (memory/file scanning).
    """

    def compile_sigma_deployment(
        self,
        data: TideModels.MDR,
        tenant_config: TideConfigs.Systems.HarfangLab.Tenant
    ) -> SigmaRule:
        """
        Builds the Sigma Rule for deployment to HarfangLab API.
        Converts OpenTide's selection-based format to HarfangLab's Sigma format.
        """
        mdr_config = data.configurations.harfanglab

        if not mdr_config:
            log("FATAL", "Missing HarfangLab configuration in MDR", data.metadata.uuid)
            raise Exception("Missing HarfangLab configuration")
        
        if not mdr_config.sigma:
            log("FATAL", "Sigma configuration expected but not found", data.metadata.uuid)
            raise Exception("Missing Sigma configuration")

        sigma_config = mdr_config.sigma
        
        # Build rule name and description
        rule_name = data.name
        rule_description = data.description
        
        # Map maturity to hl_status
        hl_status = "experimental"  # default
        if mdr_config.maturity:
            hl_status = HarfangLabService.map_maturity_to_hl_status(mdr_config.maturity)
        
        # Map action to global_state
        global_state = "alert"  # default
        action = sigma_config.action or mdr_config.action
        if action:
            global_state = HarfangLabService.map_action_to_global_state(action)
        
        # Determine enabled/disabled state
        enabled = True
        if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT:
            enabled = False
            global_state = "disabled"
        
        # Map confidence
        rule_confidence = None
        confidence = sigma_config.confidence or mdr_config.confidence
        if confidence:
            rule_confidence = HarfangLabService.map_confidence(confidence)
        
        # Map severity to level
        rule_level = HarfangLabService.map_level(data.response.alert_severity)
        
        # Build selections for Sigma rule
        selections = []
        for sel in sigma_config.selections:
            selections.append({
                "name": sel.name,
                "field": sel.field,
                "modifiers": sel.modifiers or [],
                "value": sel.value
            })
        
        # Build the Sigma YAML content
        sigma_yaml = SigmaRuleBuilder.build_sigma_yaml(
            title=rule_name,
            description=rule_description,
            rule_id=data.metadata.uuid,
            logsource_category=sigma_config.logsource.category,
            logsource_product=sigma_config.logsource.product,
            selections=selections,
            condition=sigma_config.condition,
            level=rule_level,
            status=hl_status,
            tags=sigma_config.tags,
            false_positives=sigma_config.false_positives,
            author=data.metadata.author
        )
        
        # Determine block/quarantine settings from action
        block_on_agent = False
        quarantine_on_agent = False
        if global_state in ["block", "quarantine"]:
            block_on_agent = True
        if global_state == "quarantine":
            quarantine_on_agent = True
        
        return SigmaRule(
            name=rule_name,
            content=sigma_yaml,
            source_id=data.metadata.uuid,
            enabled=enabled,
            global_state=global_state,
            hl_status=hl_status,
            block_on_agent=block_on_agent,
            quarantine_on_agent=quarantine_on_agent,
            rule_confidence_override=rule_confidence,
            rule_level_override=rule_level
        )

    def deploy_mdr(
        self,
        data: TideModels.MDR,
        service: HarfangLabService,
        tenant_config: TideConfigs.Systems.HarfangLab.Tenant
    ):
        """
        Deploys the detection rule: creation, update, deletion, and disabling.
        Currently supports Sigma rules. YARA support can be added similarly.
        """
        mdr_config = data.configurations.harfanglab
        if not mdr_config:
            log("FATAL", "Missing HarfangLab configuration", data.metadata.uuid)
            raise Exception("Missing HarfangLab configuration")
        
        # Determine rule type and build appropriate rule
        if mdr_config.sigma:
            rule = self.compile_sigma_deployment(data=data, tenant_config=tenant_config)
        elif mdr_config.yara:
            log("WARNING", 
                "YARA rule deployment not yet fully implemented",
                data.metadata.uuid,
                "Sigma rules are fully supported")
            return
        else:
            log("FATAL",
                "MDR must contain either sigma or yara configuration",
                data.metadata.uuid)
            raise Exception("Invalid HarfangLab configuration")

        # Check for existing rule ID
        rule_id = None
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

        # Handle deletion status
        if check_status(mdr_config.status) is StatusStrategy.DELETION:
            if not rule_id:
                log("FATAL",
                    "Cannot remove the rule as a rule_id could not be found in the file",
                    "You will need to manually check the target system to remove the rule")
            else:
                log("ONGOING",
                    f"Proceeding with deletion of rule against tenant {tenant_config.name}",
                    str(rule_id))
                
                service.delete_sigma_rule(rule_id=rule_id)
                ExternalIdHelper.remove_id(
                    rule_id=rule_id,
                    tenant_name=tenant_config.name,
                    mdr_uuid=data.metadata.uuid
                )
        else:
            # Create or update rule
            if rule_id:
                log("INFO", f"Found Rule ID", str(rule_id), "Going to update the rule")
                service.update_sigma_rule(rule=rule, rule_id=rule_id)
            else:
                rule_id = service.create_sigma_rule(rule)
                ExternalIdHelper.insert_id(
                    rule_id=rule_id,
                    tenant_name=tenant_config.name,
                    mdr_uuid=data.metadata.uuid,
                    system_name=DataTide.Configurations.Systems.HarfangLab.platform.identifier
                )

    def deploy(
        self,
        mdr_deployment: Sequence[TideModels.MDR] | list[str],
        deployment_plan: DeploymentStrategy
    ):
        """
        Triggers the deployment sequence for a series of MDR uuids or TideModels.MDR Objects
        """
        log("INFO", "Received HarfangLab deployment information", str(mdr_deployment))
        
        # Load MDR objects if UUIDs were provided
        loaded_mdr = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(DataTide.Models.MDR[mdr])
            elif isinstance(mdr, TideModels.MDR):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        deployment = TideDeployment(
            deployment=mdr_deployment,
            system=DetectionSystems.HARFANGLAB,
            strategy=deployment_plan
        )

        for tenant_deployment in deployment.rule_deployment:
            log("ONGOING", "Currently targeting tenant", tenant_deployment.tenant.name)
            service = HarfangLabService(tenant_deployment.tenant)  # type: ignore

            for mdr in tenant_deployment.rules:
                log("ONGOING", "Processing rule", mdr.name, mdr.metadata.uuid)
                self.deploy_mdr(
                    data=mdr,
                    service=service,
                    tenant_config=tenant_deployment.tenant  # type: ignore
                )


def declare():
    return HarfangLabDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    # Debug testing entrypoint
    HarfangLabDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
