import base64
import requests
import json
import uuid

from typing import Optional, Literal
from enum import Enum
from dataclasses import dataclass, asdict

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from Engines.modules.models import TideConfigs
from Engines.modules.deployment import Proxy
from Engines.modules.errors import TideErrors

class SeverityMapping(Enum):
    Informational = 1
    Low = 1
    Medium = 2
    High = 3
    Critical = 3

class AutomaticActions(Enum):
    Isolate = 1
    CollectInvestigationPackage = 2
    AddToSandbox = 3
    KillProcess = 4
    Scan = 5
    Quarantine = 6
    RiskScan = 7

@dataclass
class GenericRule:
    """Bitdefender GravityZone Detection Rule structure matching API specification."""
    
    @dataclass
    class Settings:
        """Rule settings container."""
        
        @dataclass
        class CriteriaItem:
            """Individual criteria condition."""
            field: str
            """The type of entity the condition applies to (e.g., Process.Name, File.Path)"""
            relation: str
            """Relationship operator: 'is', 'contains', 'any'"""
            value: list[str]
            """Array of values to match against"""
        
        @dataclass
        class AutomaticAction:
            """Automatic response action configuration."""
            
            @dataclass
            class ActionSettings:
                """Optional settings for specific action types."""
                includeParent: Optional[bool] = None
                """Include parent process (for Kill process and Quarantine actions)"""
                includeChildren: Optional[bool] = None
                """Include child processes (for Kill process and Quarantine actions)"""
                scanType: Optional[int] = None
                """Scan type: 1=Quick, 2=Full (for Scan action type 5)"""
            
            type: int
            """Action type: 1=Isolate, 2=Collect investigation package, 3=Add to Sandbox, 4=Kill process, 5=Scan, 6=Quarantine, 7=Risk scan"""
            enabled: bool
            """Whether this action is enabled"""
            settings: Optional[ActionSettings] = None
            """Additional settings for certain action types"""
        
        @dataclass
        class Filter:
            """Exclusion filter for the rule."""
            field: str
            """Filter field (currently only 'detection' is supported)"""
            value: list[str]
            """Array of values to filter/exclude"""
        
        status: Literal[0,1]
        """Rule status: 0=inactive, 1=active"""
        severity: int
        """Incident severity: 1=Low, 2=Medium, 3=High"""
        target: str
        """Target entity type: 'process', 'file', 'connection', 'registry'"""
        criteriaList: list[CriteriaItem]
        """List of criteria conditions that trigger the rule"""
        automaticActions: Optional[list[AutomaticAction]] = None
        """Optional automatic response actions"""
        filters: Optional[list[Filter]] = None
        """Optional exclusion filters"""
    
    type: int
    """Rule type: 1=Detection, 2=Exclusion"""
    name: str
    """Name of the rule"""
    settings: Settings
    """Rule settings and configuration"""
    companyId: Optional[str] = None
    """Company ID (optional, may be auto-assigned)"""
    description: Optional[str] = None
    """Optional rule description"""
    tags: Optional[list[str]] = None
    """Optional list of tags"""
    returnRuleId: bool = True
    """Request to return the rule ID after creation"""

class GravityZoneService:
    """
    Interface to connect and deploy MDRs to Bitdefender GravityZone. Initialized on a single
    tenant basis.
    """

    def __init__(self, tenant_config:TideConfigs.Systems.GravityZone.Tenant) -> None:
        """
        Initialize the GravityZone service with tenant-specific configuration.
        
        Sets up authentication, API endpoint, and proxy settings for interacting with
        the Bitdefender GravityZone API.
        
        Args:
            tenant_config: Tenant-specific configuration including API token and SSL settings
        """
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = DataTide.Configurations.Systems.GravityZone.platform.identifier
        self.tenant_config = tenant_config

        # Select API endpoint based on location
        if tenant_config.setup.location == "EU":
            self.API_ENDPOINT = "https://cloudgz.gravityzone.bitdefender.com/api/v1.0/jsonrpc"
        else:  # Non-EU
            self.API_ENDPOINT = "https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc"
        
        log("INFO", f"Using GravityZone API endpoint for {tenant_config.setup.location}", self.API_ENDPOINT)

        self.session = requests.Session()

        # Encode API key exactly as shown in GravityZone docs
        login_string = self.tenant_config.setup.api_token + ":"
        encoded_token_bytes = base64.b64encode(login_string.encode('utf-8'))
        encoded_token_string = encoded_token_bytes.decode('utf-8')
        
        self.session.headers.update({
            "Authorization": f"Basic {encoded_token_string}",
            "Content-Type": "application/json"
        })
        
        log("DEBUG", "Authorization Header", f"Basic {encoded_token_string[:20]}...")
        log("DEBUG", "API Token (first 10 chars)", self.tenant_config.setup.api_token[:10])
        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
            import os
            os.environ["HTTP_PROXY"] = "http://bessoam:N1ghtm4r@proxy-t2-bx.welcome.ec.europa.eu:8012/"
            os.environ["HTTPS_PROXY"] = "http://bessoam:N1ghtm4r@proxy-t2-bx.welcome.ec.europa.eu:8012/"


    def _build_json_request(self, params:dict, method:str)->str:
        """
        Build a JSON-RPC 2.0 formatted request for the GravityZone API.
        
        Args:
            params: Dictionary of parameters for the API method
            method: Name of the API method to invoke
            
        Returns:
            JSON-formatted string ready for API submission
        """
        request = {
            "params": params,
            "jsonrpc": "2.0",
            "method": method,
            "id": str(uuid.uuid4())
        }

        return json.dumps(request)

    def create_rule(self, rule:GenericRule)->str:
        """
        Create a custom detection rule in GravityZone.
        
        Converts the rule dataclass to API-compliant JSON, removes null values,
        and submits via JSON-RPC 2.0 protocol.
        
        Args:
            rule: GenericRule dataclass containing rule configuration
            
        Returns:
            Rule ID string returned by the GravityZone API
            
        Raises:
            TideErrors.DetectionRuleCreationFailed: If API call fails
        """
        def _remove_nulls(value):
            """Recursively remove None values from dictionaries and lists."""
            if isinstance(value, dict):
                return {k: _remove_nulls(v) for k, v in value.items() if v is not None}
            elif isinstance(value, list):
                return [_remove_nulls(item) for item in value if item is not None]
            else:
                return value

        endpoint = self.API_ENDPOINT + "/incidents"
        method = "createCustomRule"

        rule_body = _remove_nulls(asdict(rule))
        json_request = self._build_json_request(params=rule_body, #type:ignore
                                           method=method)
        log("INFO", "Compiled API Request", str(json_request))        

        log("ONGOING", "Executing API call to create Custom Detection Rule")
        Error = TideErrors.DetectionRuleCreationFailed
        response = self.session.post(url=endpoint,
                                    verify=self.tenant_config.setup.ssl,
                                    data=json_request)

        if response.status_code == 200:
            result = response.json()
            
            # Check if the response contains an error even with 200 status
            if "error" in result:
                error_details = result["error"]
                error_data = error_details.get('data', {})
                details = error_data.get('details', 'No additional details')
                
                log("FATAL", 
                    "GravityZone API Error",
                    f"Code: {error_details.get('code')}",
                    f"Message: {error_details.get('message')}",
                    f"Details: {details}")
                raise Error
            
            # Success - return the rule ID
            log("SUCCESS", "Created rule in GravityZone", str(result.get("result")))
            return str(result["result"])
        else:
            log("FATAL", "HTTP Error", str(response.status_code), response.text)
            raise Error


    def update_rule(self, rule_id: str, rule: GenericRule) -> bool:
        """
        Update an existing custom detection rule in GravityZone.
        
        Args:
            rule_id: The ID of the rule to update
            rule: GenericRule dataclass containing updated rule configuration
            
        Returns:
            True if update was successful
            
        Raises:
            TideErrors.DetectionRuleCreationFailed: If API call fails
        """
        def _remove_nulls(value):
            """Recursively remove None values from dictionaries and lists."""
            if isinstance(value, dict):
                return {k: _remove_nulls(v) for k, v in value.items() if v is not None}
            elif isinstance(value, list):
                return [_remove_nulls(item) for item in value if item is not None]
            else:
                return value

        endpoint = self.API_ENDPOINT + "/incidents"
        method = "updateCustomRule"

        # Convert rule to dict and add the ruleId for update
        rule_body = _remove_nulls(asdict(rule))
        params = {**rule_body, "ruleId": rule_id}  # type: ignore
        
        json_request = self._build_json_request(params=params, #type:ignore
                                           method=method)
        log("INFO", "Compiled API Update Request", str(json_request))        

        log("ONGOING", f"Executing API call to update Custom Detection Rule {rule_id}")
        Error = TideErrors.DetectionRuleCreationFailed
        response = self.session.post(url=endpoint,
                                    verify=self.tenant_config.setup.ssl,
                                    data=json_request)

        if response.status_code == 200:
            result = response.json()
            
            # Check if the response contains an error even with 200 status
            if "error" in result:
                error_details = result["error"]
                error_data = error_details.get('data', {})
                details = error_data.get('details', 'No additional details')
                
                log("FATAL", 
                    "GravityZone API Error",
                    f"Code: {error_details.get('code')}",
                    f"Message: {error_details.get('message')}",
                    f"Details: {details}")
                raise Error
            
            # Success
            log("SUCCESS", f"Updated rule {rule_id} in GravityZone", str(result.get("result")))
            return True
        else:
            log("FATAL", "HTTP Error", str(response.status_code), response.text)
            raise Error


    def delete_rule(self, rule_id)->None:
        """
        Delete a custom detection rule from GravityZone.
        
        Args:
            rule_id: The ID of the rule to delete
            
        Raises:
            TideErrors.DetectionRuleDeletionFailed: If API call fails
        """
        params =  {"type":1, "ruleId":rule_id}
        method = "deleteCustomRule"

        endpoint = self.API_ENDPOINT + "/incidents"

        json_request = self._build_json_request(params=params,
                                           method=method)
        response = self.session.post(url=endpoint,
                                    verify=self.tenant_config.setup.ssl,
                                    data=json_request)

        match response.status_code:
            case 200:
                log("SUCCESS", f"Deleted rule with id {rule_id} from Gravityzone", str(response.json()))

            case _:
                raise TideErrors.DetectionRuleDeletionFailed