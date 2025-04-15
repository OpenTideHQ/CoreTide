import sys
import os
import requests 
import json

import git

from dataclasses import dataclass, asdict, is_dataclass
from typing import Literal, Never, ClassVar, Sequence, overload, Any, Optional
from enum import Enum, auto
from datetime import datetime, timedelta
from pprint import pprint

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from Engines.modules.models import TideConfigs
from Engines.modules.deployment import Proxy
from Engines.modules.errors import TideErrors

class SeverityMapping(Enum):
    Informational = 10
    Low = 30
    Medium = 50
    High = 70
    Critical = 90

@dataclass
class DetectionRule:
    @dataclass
    class Search:
        outcome: Literal["detection", "incident"]
        filter: str
        lookback: str
        trigger_mode: Literal["summary", "verbose"]

    @dataclass
    class Operation:
        @dataclass
        class Schedule:
            definition: str

        schedule: Schedule
        start_on: Optional[str] = None
        stop_on: Optional[str] = None
    
    name: str
    description: str
    customer_id: str
    severity: int
    search: Search
    operation: Operation
    status: Literal["active", "inactive"]
    tactic: Optional[str] = None
    technique: Optional[str] = None
    comment: Optional[str] = None

def remove_none_values(data:dict)->dict:
    if isinstance(data, dict):
        return {k: remove_none_values(v) for k, v in data.items() if v is not None}
    elif isinstance(data, list):
        return [remove_none_values(v) for v in data if v is not None]
    else:
        return data


@dataclass
class CrowdstrikeService:
    """
    Interface to connect and deploy MDRs to SentinelOne. Initialized on a single
    tenant basis.
    """

    def __init__(self, tenant_config:TideConfigs.Systems.Crowdstrike.Tenant) -> None:


        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = DataTide.Configurations.Systems.SentinelOne.platform.identifier
        self.tenant_config = tenant_config
        BASE_URL = self._get_base_api(self.tenant_config.setup.api)
        self.OAUTH_TOKEN_ENDPOINT = BASE_URL + "/oauth2/token"
        self.CORRELATION_RULES_ENDPOINT = BASE_URL + "/correlation-rules/entities/rules/v1"

        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
        
        self.access_token = self._get_access_token(self.tenant_config.setup.client_id,
                                                   self.tenant_config.setup.client_secret)
        self.session = requests.Session()
        self.session.headers.update({"Authorization" : f"Bearer {self.access_token}",
                                                        "Content-Type" : "application/json",
                                                        "accept": "application/json"})


    def _get_base_api(self, domain:str)->str:
        match domain:
            case "US-1":
                return "https://api.crowdstrike.com"
            case "US-2":
                return "https://api.us-2.crowdstrike.com"
            case "EU-1":
                return "https://api.eu-1.crowdstrike.com"
            case "US-GOV-1:":
                return "https://api.laggar.gcw.crowdstrike.com"
            case "US-GOV-2":
                return "https://api.falcon.us-gov-2.crowdstrike.mil"
            case _:
                log("FATAL",
                    "The configured Crowdstrike API domain isn't valid",
                    "Expects : US-1 , US-2 , EU-1 , US-GOV-1 , US-GOV-2")
                raise TideErrors.TideSystemConfigurationErrors("Invalid API Domain")

    def _get_access_token(self, client_id:str, client_secret:str):
        
        data = {"client_id":client_id,
                "client_secret":client_secret}
        
        response = requests.post(data=data,
                                 url=self.OAUTH_TOKEN_ENDPOINT, 
                                 verify=self.tenant_config.setup.ssl)
        
        if response.status_code == 201:
            log("INFO",
                f"Successfully authenticated against {self.tenant_config.name}",
                str(response.json()))
            return response.json()["access_token"]

        else:
            log("FATAL",
                f"Cannot authenticate against {self.tenant_config.name} - Error Code {response.status_code}",
                str(response.json()),
                f"client_id: {client_id}, client_secret: {client_secret[:10]}...")
            raise TideErrors.TenantConnectionError("Cannot authenticate with the tenant configuration")

    def create_detection_rule(self, rule:DetectionRule)->str:

        rule_body = remove_none_values(asdict(rule))
        rule_body = json.dumps(rule_body)
        response = self.session.post(url=self.CORRELATION_RULES_ENDPOINT,
                                     data=rule_body,
                                     verify=self.tenant_config.setup.ssl)

        if response.status_code == 200:
            log("INFO",
                f"Successfully created rule {rule.name}",
                f"On tenant : {self.tenant_config.name}",
                str(response.json()))
            try:
                rule_id = response.json()["resources"][0]["id"]
                return rule_id
            except:
                log("FATAL",
                    "The rule id was not present in the response body",
                    str(response.json()))
                raise TideErrors.DetectionRulesOperationErrors("Could not retrieve rule ID") 
            
        else:
            log("FATAL",
                f"Was not able to create rule against tenant {self.tenant_config.name} - Error Code {response.status_code}",
                str(response.json()))
            raise TideErrors.DetectionRuleCreationFailed("Could not create rule")

    def update_detection_rule(self, rule_id: str, rule:DetectionRule):
        
        rule_body = remove_none_values(asdict(rule))
        rule_body.update({"id":rule_id})
        rule_body = json.dumps([rule_body])

        response = self.session.patch(url=self.CORRELATION_RULES_ENDPOINT,
                                    data=rule_body,
                                    verify=self.tenant_config.setup.ssl)

        if response.status_code == 200:
            log("INFO",
                f"Successfully update rule {rule.name} with id {rule_id} on {self.tenant_config.name}",
                str(response.json()))
            
        else:
            log("FATAL",
                f"Was not able to create update rule with id {rule_id} against tenant {self.tenant_config.name} - Error Code {response.status_code}",
                str(response.json()))
            log("INFO", "Request body", str(rule_body))
            raise TideErrors.DetectionRuleUpdateFailed("Could not update rule")


    def delete_detection_rule(self, rule_id:str):

        params = {"ids": rule_id}

        response = self.session.delete(params=params,
                                        url=self.CORRELATION_RULES_ENDPOINT,
                                        verify=self.tenant_config.setup.ssl)

        if response.status_code == 200:
            log("SUCCESS",
                f"Removed detection rule with ID {rule_id}",
                f"Against tenant {self.tenant_config.name}")
            return
        else:
            log("FATAL",
                f"Was not able to delete rule with ID {rule_id}",
                f"Against tenant {self.tenant_config.name}",
                "Verify API permission, and check if the rule was not already removed from the console")

            raise TideErrors.DetectionRuleDeletionFailed("Could not delete rule")