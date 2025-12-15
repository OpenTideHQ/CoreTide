import sys
import os
import requests 
import json

import git

from dataclasses import dataclass, asdict
from typing import Literal, Optional, Sequence
from enum import Enum

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from Engines.modules.models import TideConfigs
from Engines.modules.deployment import Proxy
from Engines.modules.errors import TideErrors


class GlobalState(Enum):
    """HarfangLab global_state values"""
    ALERT = "alert"
    BACKEND_ALERT = "backend_alert"
    BLOCK = "block"
    DISABLED = "disabled"
    QUARANTINE = "quarantine"


class HLStatus(Enum):
    """HarfangLab hl_status (maturity) values"""
    EXPERIMENTAL = "experimental"
    TESTING = "testing"
    STABLE = "stable"


class ConfidenceLevel(Enum):
    """HarfangLab rule_confidence_override values"""
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


class LevelOverride(Enum):
    """HarfangLab rule_level_override values"""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def remove_none_values(data: dict) -> dict:
    """Recursively remove None values from dictionaries"""
    if isinstance(data, dict):
        return {k: remove_none_values(v) for k, v in data.items() if v is not None}
    elif isinstance(data, list):
        return [remove_none_values(v) for v in data if v is not None]
    else:
        return data


@dataclass
class SigmaRule:
    """
    Dataclass representing a HarfangLab Sigma rule for the API.
    Maps OpenTide's HarfangLab configuration to HarfangLab's API format.
    """
    name: str
    content: str  # Full Sigma YAML content
    source_id: str  # Unique identifier (usually MDR UUID)
    enabled: bool = True
    global_state: str = "alert"  # alert, backend_alert, block, disabled, quarantine
    hl_status: str = "experimental"  # experimental, testing, stable
    block_on_agent: bool = False
    quarantine_on_agent: bool = False
    rule_confidence_override: Optional[str] = None  # weak, moderate, strong
    rule_level_override: Optional[str] = None  # informational, low, medium, high, critical
    overwrite: bool = False


@dataclass
class YaraRule:
    """
    Dataclass representing a HarfangLab YARA rule for the API.
    Note: This is a placeholder as YARA rules may use a different endpoint.
    """
    name: str
    content: str  # Full YARA rule content
    source_id: str
    enabled: bool = True


class SigmaRuleBuilder:
    """
    Builds a Sigma-compliant YAML string from OpenTide's selection-based format.
    Transforms the OpenTide format to standard Sigma format.
    """

    @staticmethod
    def build_sigma_yaml(
        title: str,
        description: str,
        rule_id: str,
        logsource_category: str,
        logsource_product: str,
        selections: list,
        condition: str,
        level: str = "medium",
        status: str = "experimental",
        tags: Optional[list] = None,
        false_positives: Optional[list] = None,
        author: Optional[str] = None,
        references: Optional[list] = None
    ) -> str:
        """
        Build a Sigma-compliant YAML string from structured components.
        
        Args:
            title: Rule title
            description: Rule description
            rule_id: Unique rule identifier (UUID)
            logsource_category: Log source category (e.g., process_creation)
            logsource_product: Log source product (e.g., windows)
            selections: List of selection dictionaries with name, field, modifiers, value
            condition: Boolean condition combining selections
            level: Criticality level
            status: Rule status (experimental, testing, stable)
            tags: List of tags (MITRE ATT&CK, etc.)
            false_positives: List of known false positive scenarios
            author: Rule author
            references: List of reference URLs
            
        Returns:
            A Sigma-compliant YAML string
        """
        lines = []
        
        # Header section
        lines.append(f"title: {title}")
        lines.append(f"id: {rule_id}")
        
        if description:
            # Handle multiline description
            if "\n" in description:
                lines.append("description: |")
                for desc_line in description.split("\n"):
                    lines.append(f"    {desc_line}")
            else:
                lines.append(f"description: {description}")
        
        if author:
            lines.append(f"author: {author}")
        
        if references:
            lines.append("references:")
            for ref in references:
                lines.append(f"    - {ref}")
        
        lines.append(f"status: {status}")
        
        if tags:
            lines.append("tags:")
            for tag in tags:
                lines.append(f"    - {tag}")
        
        # Log source section
        lines.append("logsource:")
        lines.append(f"    category: {logsource_category}")
        lines.append(f"    product: {logsource_product}")
        
        # Detection section
        lines.append("detection:")
        
        for selection in selections:
            selection_name = selection.get("name", "selection")
            field_name = selection.get("field", "")
            modifiers = selection.get("modifiers", [])
            values = selection.get("value", [])
            
            # Build field name with modifiers
            if modifiers:
                field_with_modifiers = f"{field_name}|{'|'.join(modifiers)}"
            else:
                field_with_modifiers = field_name
            
            lines.append(f"    {selection_name}:")
            
            # Handle single value vs list of values
            if isinstance(values, list):
                lines.append(f"        {field_with_modifiers}:")
                for val in values:
                    lines.append(f"            - {SigmaRuleBuilder._escape_value(val)}")
            else:
                lines.append(f"        {field_with_modifiers}: {SigmaRuleBuilder._escape_value(values)}")
        
        lines.append(f"    condition: {condition}")
        
        # False positives section
        if false_positives:
            lines.append("falsepositives:")
            for fp in false_positives:
                lines.append(f"    - {fp}")
        
        lines.append(f"level: {level}")
        
        return "\n".join(lines)

    @staticmethod
    def _escape_value(value) -> str:
        """Escape special characters in YAML values"""
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return str(value)
        value = str(value)
        # Quote strings that contain special characters
        if any(c in value for c in [":", "#", "{", "}", "[", "]", ",", "&", "*", "?", "|", "-", "<", ">", "=", "!", "%", "@", "\\"]):
            return f"'{value}'"
        return value


class HarfangLabService:
    """
    Interface to connect and deploy MDRs to HarfangLab.
    Initialized on a single tenant basis.
    """

    def __init__(self, tenant_config: TideConfigs.Systems.HarfangLab.Tenant) -> None:
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = DataTide.Configurations.Systems.HarfangLab.platform.identifier
        self.tenant_config = tenant_config
        
        base_url = self.tenant_config.setup.url.rstrip("/")
        self.SIGMA_RULES_ENDPOINT = f"{base_url}/api/data/threat_intelligence/SigmaRule/"
        
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.tenant_config.setup.api_token}",
            "Content-Type": "application/json"
        })

        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()

    def _http_errors(self, response: requests.Response, error):
        """Handle HTTP errors from HarfangLab API"""
        match response.status_code:
            case 400:
                log("FATAL",
                    "Received code [400], Invalid request",
                    str(response.text))
                raise error

            case 401:
                log("FATAL",
                    "Received code [401], Unauthorized access",
                    str(response.text),
                    "Check your API token configuration")
                raise TideErrors.TideTenantConfigurationMissingPermissions

            case 403:
                log("FATAL",
                    "Received code [403], Forbidden",
                    str(response.text),
                    "Check your API permissions")
                raise TideErrors.TideTenantConfigurationMissingPermissions

            case 404:
                log("FATAL",
                    f"Received code [404], Resource not found",
                    str(response.text))
                raise error
        
            case _:
                log("FATAL", f"Unforeseen error with code [{response.status_code}]",
                    str(response.text))
                raise error

    def create_sigma_rule(self, rule: SigmaRule) -> str:
        """
        Create a new Sigma rule in HarfangLab.
        
        Args:
            rule: SigmaRule dataclass with rule details
            
        Returns:
            The rule ID assigned by HarfangLab
        """
        rule_body = remove_none_values(asdict(rule))
        rule_body = json.dumps(rule_body)
        
        log("ONGOING", "Creating Sigma rule in HarfangLab", rule.name)
        
        response = self.session.post(
            url=self.SIGMA_RULES_ENDPOINT,
            data=rule_body,
            verify=self.tenant_config.setup.ssl
        )

        if response.status_code in [200, 201]:
            log("SUCCESS", f"Created Sigma rule: {rule.name}")
            try:
                response_data = response.json()
                rule_id = response_data.get("id") or response_data.get("source_id")
                return str(rule_id)
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                log("WARNING", "Could not extract rule ID from response", str(e))
                return rule.source_id
        else:
            self._http_errors(response, TideErrors.DetectionRuleCreationFailed)
            raise TideErrors.DetectionRuleCreationFailed

    def update_sigma_rule(self, rule: SigmaRule, rule_id: str) -> None:
        """
        Update an existing Sigma rule in HarfangLab.
        
        Args:
            rule: SigmaRule dataclass with updated rule details
            rule_id: The HarfangLab rule ID to update
        """
        rule_body = remove_none_values(asdict(rule))
        rule_body["overwrite"] = True
        rule_body = json.dumps(rule_body)
        
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        
        log("ONGOING", f"Updating Sigma rule {rule_id} in HarfangLab", rule.name)
        
        response = self.session.put(
            url=endpoint,
            data=rule_body,
            verify=self.tenant_config.setup.ssl
        )

        if response.status_code == 200:
            log("SUCCESS", f"Updated Sigma rule: {rule.name}", str(rule_id))
        else:
            self._http_errors(response, TideErrors.DetectionRuleUpdateFailed)

    def delete_sigma_rule(self, rule_id: str) -> None:
        """
        Delete a Sigma rule from HarfangLab.
        
        Args:
            rule_id: The HarfangLab rule ID to delete
        """
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        
        log("ONGOING", "Deleting Sigma rule from HarfangLab", str(rule_id))
        
        response = self.session.delete(
            url=endpoint,
            verify=self.tenant_config.setup.ssl
        )

        if response.status_code in [200, 204]:
            log("SUCCESS", f"Deleted Sigma rule with ID {rule_id}")
        else:
            self._http_errors(response, TideErrors.DetectionRuleDeletionFailed)

    def disable_sigma_rule(self, rule_id: str) -> None:
        """
        Disable a Sigma rule in HarfangLab by setting global_state to disabled.
        
        Args:
            rule_id: The HarfangLab rule ID to disable
        """
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        
        update_body = json.dumps({
            "global_state": "disabled",
            "enabled": False
        })
        
        log("ONGOING", "Disabling Sigma rule in HarfangLab", str(rule_id))
        
        response = self.session.patch(
            url=endpoint,
            data=update_body,
            verify=self.tenant_config.setup.ssl
        )

        if response.status_code == 200:
            log("SUCCESS", f"Disabled Sigma rule with ID {rule_id}")
        else:
            self._http_errors(response, TideErrors.DetectionRuleDisablingFailed)

    @staticmethod
    def map_action_to_global_state(action: str) -> str:
        """
        Map OpenTide action values to HarfangLab global_state values.
        
        Args:
            action: OpenTide action string (Alert, Alert & Block, etc.)
            
        Returns:
            HarfangLab global_state value
        """
        action_mapping = {
            "Alert": "alert",
            "Alert & Block": "block",
            "Alert, Block & Quarantine": "quarantine"
        }
        return action_mapping.get(action, "alert")

    @staticmethod
    def map_maturity_to_hl_status(maturity: str) -> str:
        """
        Map OpenTide maturity values to HarfangLab hl_status values.
        
        Args:
            maturity: OpenTide maturity string (Stable, Testing, Experimental)
            
        Returns:
            HarfangLab hl_status value
        """
        maturity_mapping = {
            "Stable": "stable",
            "Testing": "testing",
            "Experimental": "experimental"
        }
        return maturity_mapping.get(maturity, "experimental")

    @staticmethod
    def map_confidence(confidence: str) -> str:
        """
        Map OpenTide confidence values to HarfangLab rule_confidence_override values.
        
        Args:
            confidence: OpenTide confidence string (Weak, Moderate, Strong)
            
        Returns:
            HarfangLab rule_confidence_override value
        """
        confidence_mapping = {
            "Weak": "weak",
            "Moderate": "moderate",
            "Strong": "strong"
        }
        return confidence_mapping.get(confidence, "moderate")

    @staticmethod
    def map_level(level: str) -> str:
        """
        Map alert severity to HarfangLab rule_level_override values.
        
        Args:
            level: Alert severity (Informational, Low, Medium, High, Critical)
            
        Returns:
            HarfangLab rule_level_override value
        """
        level_mapping = {
            "Informational": "informational",
            "Low": "low",
            "Medium": "medium",
            "High": "high",
            "Critical": "critical"
        }
        return level_mapping.get(level, "medium")
