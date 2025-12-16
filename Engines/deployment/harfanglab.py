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
from Engines.modules.deployment import TideDeployment, check_status
from Engines.modules.logs import log
from Engines.modules.models import TideConfigs, StatusStrategy

from Engines.modules.systems.harfanglab import (
    HarfangLabService,
    SigmaRule,
    YaraRule,
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
        
        # source_id comes from the tenant configuration
        source_id = tenant_config.setup.source_id
        
        return SigmaRule(
            name=rule_name,
            content=sigma_yaml,
            source_id=source_id,
            enabled=enabled,
            global_state=global_state,
            hl_status=hl_status,
            block_on_agent=block_on_agent,
            quarantine_on_agent=quarantine_on_agent,
            rule_confidence_override=rule_confidence,
            rule_level_override=rule_level
        )

    def compile_yara_deployment(
        self,
        data: TideModels.MDR,
        tenant_config: TideConfigs.Systems.HarfangLab.Tenant
    ) -> YaraRule:
        """
        Builds the YARA Rule for deployment to HarfangLab API.
        Converts OpenTide's YARA format to HarfangLab's YARA format.
        """
        mdr_config = data.configurations.harfanglab

        if not mdr_config:
            log("FATAL", "Missing HarfangLab configuration in MDR", data.metadata.uuid)
            raise Exception("Missing HarfangLab configuration")
        
        if not mdr_config.yara:
            log("FATAL", "YARA configuration expected but not found", data.metadata.uuid)
            raise Exception("Missing YARA configuration")

        yara_config = mdr_config.yara
        
        # Build rule name
        rule_name = data.name
        
        # Build YARA rule content
        # We need to construct a valid YARA rule from the components
        # Escape double quotes in description and author to prevent YARA syntax errors
        def escape_yara_string(s: str) -> str:
            return s.replace('\\', '\\\\').replace('"', '\\"') if s else ""
        
        yara_lines = []
        yara_lines.append(f"rule {data.metadata.uuid.replace('-', '_')} {{")
        
        # Add meta section if present
        if yara_config.meta:
            yara_lines.append("    meta:")
            yara_lines.append(f'        description = "{escape_yara_string(data.description)}"')
            yara_lines.append(f'        author = "{escape_yara_string(data.metadata.author)}"')
            if yara_config.meta.context:
                yara_lines.append(f'        context = "{yara_config.meta.context}"')
            if yara_config.meta.os:
                yara_lines.append(f'        os = "{yara_config.meta.os}"')
        
        # Add strings section
        yara_lines.append("    strings:")
        for line in yara_config.strings.strip().split('\n'):
            yara_lines.append(f"        {line}")
        
        # Add condition section
        yara_lines.append("    condition:")
        for line in yara_config.condition.strip().split('\n'):
            yara_lines.append(f"        {line}")
        
        yara_lines.append("}")
        yara_content = '\n'.join(yara_lines)
        
        # Determine enabled/disabled state
        enabled = True
        if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT:
            enabled = False
        
        # source_id comes from the tenant configuration
        source_id = tenant_config.setup.source_id
        
        return YaraRule(
            name=rule_name,
            content=yara_content,
            source_id=source_id,
            enabled=enabled
        )

    def deploy_mdr(
        self,
        data: TideModels.MDR,
        service: HarfangLabService,
        tenant_config: TideConfigs.Systems.HarfangLab.Tenant
    ):
        """
        Deploys the detection rule: creation, update, deletion, and disabling.
        Supports both Sigma rules and YARA rules.
        Uses the MDR UUID as the rule identifier - no external ID tracking needed.
        """
        mdr_config = data.configurations.harfanglab
        if not mdr_config:
            log("FATAL", "Missing HarfangLab configuration", data.metadata.uuid)
            raise Exception("Missing HarfangLab configuration")
        
        # The rule_id is the MDR UUID - no external ID helper needed
        rule_id = data.metadata.uuid
        
        # Determine rule type (Sigma or YARA)
        is_sigma = mdr_config.sigma is not None
        is_yara = mdr_config.yara is not None
        
        if not is_sigma and not is_yara:
            log("FATAL",
                "MDR must contain either sigma or yara configuration",
                data.metadata.uuid)
            raise Exception("Invalid HarfangLab configuration")

        # Handle deletion status
        if check_status(mdr_config.status) is StatusStrategy.DELETION:
            log("ONGOING",
                f"Proceeding with deletion of rule against tenant {tenant_config.name}",
                str(rule_id))
            
            if is_sigma:
                service.delete_sigma_rule(rule_id=rule_id)
            elif is_yara:
                service.delete_yara_rule(rule_id=rule_id)
            return

        # Build and deploy the rule
        if is_sigma:
            rule = self.compile_sigma_deployment(data=data, tenant_config=tenant_config)
            log("ONGOING", "Deploying Sigma rule", rule.name, str(rule_id))
            service.create_or_update_sigma_rule(rule=rule, rule_id=rule_id)
        elif is_yara:
            rule = self.compile_yara_deployment(data=data, tenant_config=tenant_config)
            log("ONGOING", "Deploying YARA rule", rule.name, str(rule_id))
            service.create_or_update_yara_rule(rule=rule, rule_id=rule_id)

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
