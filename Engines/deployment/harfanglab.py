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


# YARA score mapping from alert severity levels
# Based on HarfangLab criticality levels:
# 0-20: Informational, 21-40: Low, 41-60: Medium, 61-80: High, 81-100: Critical
SEVERITY_TO_SCORE = {
    "Informational": 10,
    "Low": 30,
    "Medium": 50,
    "High": 70,
    "Critical": 90
}

# Score mapping for explicit severity override in YARA meta
SCORE_OVERRIDE_MAP = {
    "Informational": 10,
    "Low": 30,
    "Medium": 50,
    "High": 70,
    "Critical": 90
}

# OS to file context mapping for YARA rules
OS_TO_FILE_CONTEXT = {
    "Windows": "file.pe",
    "MacOS": "file.macho",
    "Linux": "file.elf"
}


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
        
        # Map maturity to hl_status (REQUIRED field)
        hl_status = HarfangLabService.map_maturity_to_hl_status(mdr_config.maturity)
        
        # Map action to global_state (REQUIRED field)
        global_state = HarfangLabService.map_action_to_global_state(mdr_config.action)
        
        # Determine enabled/disabled state
        enabled = True
        if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT:
            enabled = False
            global_state = "disabled"
        
        # Map confidence (REQUIRED field)
        rule_confidence = HarfangLabService.map_confidence(mdr_config.confidence)
        
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
        # Tags are now at top-level mdr_config, not inside sigma section
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
            tags=mdr_config.tags,
            false_positives=sigma_config.false_positives,
            author=data.metadata.author
        )
        
        # Debug output: display compiled Sigma rule
        log("DEBUG", "Compiled Sigma rule content:", f"\n{sigma_yaml}")
        
        # Determine block/quarantine settings from action
        block_on_agent = global_state in ["block", "quarantine"]
        quarantine_on_agent = global_state == "quarantine"
        
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
        
        Features:
        - Automatic id field for rule identification
        - Score derived from alert_severity (can be overridden)
        - Context auto-routing based on OS (file -> file.pe/file.macho/file.elf)
        - Import statements for YARA modules
        - Rule name from MDR name (lowercased, underscored)
        """
        mdr_config = data.configurations.harfanglab

        if not mdr_config:
            log("FATAL", "Missing HarfangLab configuration in MDR", data.metadata.uuid)
            raise Exception("Missing HarfangLab configuration")
        
        if not mdr_config.yara:
            log("FATAL", "YARA configuration expected but not found", data.metadata.uuid)
            raise Exception("Missing YARA configuration")

        yara_config = mdr_config.yara
        
        # Build rule name from MDR name (lowercased, spaces to underscores)
        rule_name = data.name
        yara_rule_name = data.name.lower().replace(' ', '_').replace('-', '_')
        # Remove any non-alphanumeric characters except underscores
        yara_rule_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in yara_rule_name)
        # Ensure it doesn't start with a number
        if yara_rule_name and yara_rule_name[0].isdigit():
            yara_rule_name = f"rule_{yara_rule_name}"
        
        # Escape special characters in YARA meta string values
        def escape_yara_string(s: str) -> str:
            if not s:
                return ""
            s = s.replace('\\', '\\\\')
            s = s.replace('"', '\\"')
            s = s.replace('\n', '\\n')
            s = s.replace('\r', '')
            return s
        
        yara_lines = []
        
        # Add import statements if specified
        if yara_config.imports:
            for module in yara_config.imports:
                yara_lines.append(f'import "{module}"')
            yara_lines.append("")  # Blank line after imports
        
        yara_lines.append(f"rule {yara_rule_name} {{")
        
        # Determine author
        if author := data.metadata.author:
            author = author
        elif organisation := data.metadata.organisation:
            author = organisation.name
        else:
            author = ""

        # Meta section is ALWAYS generated because id is required for HarfangLab API rule identification
        yara_lines.append("    meta:")
        # CRITICAL: id field is required for HarfangLab to properly identify and update rules
        yara_lines.append(f'        id = "{data.metadata.uuid}"')
        yara_lines.append(f'        title = "{escape_yara_string(data.name)}"')
        yara_lines.append(f'        description = "{escape_yara_string(data.description)}"')
        yara_lines.append(f'        author = "{escape_yara_string(author)}"')
        
        # Add date metadata from MDR
        if data.metadata.created:
            yara_lines.append(f'        date = "{data.metadata.created}"')
        if data.metadata.modified:
            yara_lines.append(f'        modified = "{data.metadata.modified}"')
        
        # Add references if present
        if data.references and data.references.public:
            refs = "\\n".join([str(ref) for ref in data.references.public.values()])
            yara_lines.append(f'        references = "{refs}"')
        
        # Add tags if present (semicolon-separated format for HarfangLab)
        # Tags are now at the top-level mdr_config, not inside yara section
        if mdr_config.tags:
            tags_str = ";".join(mdr_config.tags)
            yara_lines.append(f'        tags = "{tags_str}"')
        
        # Build context with OS-based file routing
        # meta is now required, so yara_config.meta is always present
        os_value = yara_config.meta.os
        contexts = yara_config.meta.context
        
        # Auto-route 'file' context to OS-specific format
        compiled_contexts = []
        for ctx in contexts:
            if ctx == "file" and os_value in OS_TO_FILE_CONTEXT:
                compiled_contexts.append(OS_TO_FILE_CONTEXT[os_value])
            else:
                compiled_contexts.append(ctx)
        
        if compiled_contexts:
            yara_lines.append(f'        context = "{','.join(compiled_contexts)}"')
        
        yara_lines.append(f'        os = "{os_value}"')
        
        if yara_config.meta.arch:
            arch_str = ','.join(yara_config.meta.arch) if isinstance(yara_config.meta.arch, list) else yara_config.meta.arch
            yara_lines.append(f'        arch = "{arch_str}"')
        if yara_config.meta.classification:
            yara_lines.append(f'        classification = "{escape_yara_string(yara_config.meta.classification)}"')
        
        # Compute score: explicit override > default from alert_severity
        score = None
        if yara_config.meta.score:
            # User specified explicit severity level, map to numeric score
            score = SCORE_OVERRIDE_MAP.get(yara_config.meta.score)
        
        if score is None:
            # Derive from alert_severity
            score = SEVERITY_TO_SCORE.get(data.response.alert_severity, 50)
        
        yara_lines.append(f'        score = {score}')
        
        # Map confidence from MDR config (top-level, now REQUIRED)
        confidence_value = HarfangLabService.map_confidence(mdr_config.confidence)
        yara_lines.append(f'        confidence = "{confidence_value}"')
        
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
        
        # Debug output: display compiled YARA rule
        log("DEBUG", "Compiled YARA rule content:", f"\n{yara_content}")
        
        # Determine enabled/disabled state
        enabled = True
        if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT:
            enabled = False
        
        # source_id comes from the tenant configuration
        source_id = tenant_config.setup.source_id
        
        # Map maturity to hl_status (REQUIRED field)
        hl_status = HarfangLabService.map_maturity_to_hl_status(mdr_config.maturity)
        log("DEBUG", f"Maturity mapping: '{mdr_config.maturity}' -> hl_status='{hl_status}'")
        
        # Map confidence
        rule_confidence = HarfangLabService.map_confidence(mdr_config.confidence)
        log("DEBUG", f"Confidence mapping: '{mdr_config.confidence}' -> rule_confidence_override='{rule_confidence}'")
        
        # Map action to global_state
        global_state = HarfangLabService.map_action_to_global_state(mdr_config.action)
        log("DEBUG", f"Action mapping: '{mdr_config.action}' -> global_state='{global_state}'")
        
        # Map severity to level
        rule_level = HarfangLabService.map_level(data.response.alert_severity)
        log("DEBUG", f"Severity mapping: '{data.response.alert_severity}' -> rule_level_override='{rule_level}'")
        
        return YaraRule(
            name=rule_name,
            content=yara_content,
            source_id=source_id,
            global_state=global_state,
            hl_status=hl_status,
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
            tenant_type = tenant_deployment.tenant.setup.type  # type: ignore

            for mdr in tenant_deployment.rules:
                # Determine rule type
                mdr_config = mdr.configurations.harfanglab
                if not mdr_config:
                    log("WARNING", "Skipping MDR - no HarfangLab config", mdr.name)
                    continue
                
                is_sigma = mdr_config.sigma is not None
                is_yara = mdr_config.yara is not None
                rule_type = "Sigma" if is_sigma else "YARA" if is_yara else None
                
                # Skip if tenant type doesn't match rule type
                if rule_type != tenant_type:
                    log("INFO", f"Skipping {rule_type} rule on {tenant_type} tenant", 
                        mdr.name, tenant_deployment.tenant.name)
                    continue
                
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
