import sys
import os
import requests 
import json

import git

from dataclasses import dataclass, asdict
from typing import Literal, Never, ClassVar, Sequence, overload, Any, Optional
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from Engines.modules.models import TideConfigs
from Engines.modules.deployment import Proxy
from Engines.modules.errors import TideErrors

class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    
class SeverityMapping(Enum):
    Informational = Severity.informational
    Low = Severity.low
    Medium = Severity.medium
    High = Severity.high
    Critical = Severity.high 

@dataclass
class DetectionRule:    
    
    @dataclass
    class QueryCondition:
        queryText: str

    @dataclass
    class Schedule:
        period: Literal["0", "1H", "3H", "12H", "24H"]

    @dataclass
    class DetectionAction:
        
        @dataclass
        class AlertTemplate:
            
            @dataclass
            class ImpactedAsset:
                odata_type: str
                identifier: str

            title: str
            description: str
            severity: Severity
            category: str
            mitreTechniques: Optional[Sequence[Never] | Sequence[str]] = None
            impactedAssets: Optional[Sequence[Never] | Sequence[ImpactedAsset]] = None 
            recommendedActions: Optional[str] = None

        @dataclass
        class ResponseAction:
            odata_type: str
            identifier: Any = "deviceId"

        @dataclass
        class ResponseActionIsolateDevice(ResponseAction):
            isolationType: str = ""

        @dataclass
        class ResponseActionFileActions(ResponseAction):
            deviceGroupNames: Optional[Sequence[str]] = None
            
        @dataclass
        class OrganizationalScope:
            scopeType = "deviceGroup"
            scopeNames = Sequence[str]

        alertTemplate: AlertTemplate
        responseActions: Sequence[ResponseAction]
        organizationalScope: Optional[OrganizationalScope] = None
       
    displayName: str
    queryCondition: QueryCondition
    schedule: Schedule
    detectionAction: DetectionAction
    isEnabled: bool = False

GOOD_TEST = {
  "displayName": "ANOTHER RULE NAME",
  "isEnabled": True,
  "queryCondition": {
    "queryText": 'DeviceEvents| where DeviceName == "N/A"'
  },
  "schedule": {
    "period": "12H"
  },
  "detectionAction": {
    "alertTemplate": {
      "title": "ANOTHER RULE NAME",
      "description": "Some alert description",
      "severity": "medium",
      "category": "Execution",
      "recommendedActions": None,
      "mitreTechniques": [],
      "impactedAssets": [
        {
          "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
          "identifier": "deviceId"
        }
      ]
    },
    "organizationalScope": None,
    "responseActions": [
      {
        "@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction",
        "identifier": "deviceId",
        "isolationType": "full"
      }
    ],
  }
}

TEST = """
{
    "displayName": "MDR Deployment Testing Template 5",
    "queryCondition": {
        "queryText": "DeviceFileEvents \\n| take 10"
    },
    "schedule": {
        "period": "0"
    },
    "detectionAction": {
        "alertTemplate": {
            "title": "Test Deployment 5",
            "description": "This MDR is used for testing deployment, documentation and\\nother automations. If this triggers an alert, please close and\\nreport back to amine.besson@ext.ec.europa.eu.\\n",
            "severity": "low",
            "category": "Execution",
            "mitreTechniques": [],
            "impactedAssets": [
                {
                    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                    "identifier": "deviceId"
                }
            ],
            "recommendedActions": "Do something about it ! <3\\n"
        },
        "responseActions": [
            {
            "@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction",
            "identifier": "deviceId",
            "isolationType": "full"
            },

            {
                "@odata.type": "#microsoft.graph.security.restrictAppExecutionResponseAction",
                "identifier": "deviceId"
            }
        ],
        "organizationalScope": null
    },
    "isEnabled": true
}
"""
class DefenderForEndpointService:
    """
    Interface to connect and deploy MDRs to MDE. Initialized on a single
    tenant basis.
    """
    def __init__(self, tenant_config:TideConfigs.Systems.DefenderForEndpoint.Tenant) -> None:

        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = DataTide.Configurations.Systems.DefenderForEndpoint.platform.identifier
        self.OAUTH_TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.GRAPH_API_ENDPOINT = "https://graph.microsoft.com/beta/security"
        self.DETECTION_RULES_ENDPOINT = self.GRAPH_API_ENDPOINT + "/rules/detectionRules"
        self.HUNTING_QUERY_ENDPOINT = self.GRAPH_API_ENDPOINT + "/runHuntingQuery"

        self.tenant_config = tenant_config

        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()
        
        log("INFO",
            "VARIABLES",
            f"client_id: {tenant_config.setup.client_id}, tenant_id: {tenant_config.setup.tenant_id}, client_secret: {tenant_config.setup.client_secret[:10]}...")
        self.access_token = self._connect_to_tenant(self.tenant_config.setup.client_id,
                                                   self.tenant_config.setup.tenant_id,
                                                   self.tenant_config.setup.client_secret)
        
        self.session = requests.Session()
        self.session.headers.update({"Authorization" : f"Bearer {self.access_token}",
                                                        "Content-Type" : "application/json"})


    def _connect_to_tenant(self, client_id:str, tenant_id:str, client_secret:str):
        
        data = {"client_id":client_id,
                "client_secret":client_secret,
                "grant_type":"client_credentials",
                "scope":"https://graph.microsoft.com/.default"}
        
        response = requests.post(data=data,
                                 url=self.OAUTH_TOKEN_ENDPOINT.format(tenant_id=tenant_id))
        
        if response.status_code == 200:
            log("DEBUG",
                f"Successfully authenticated against {self.tenant_config.name}",
                str(response.json()))
            return response.json()["access_token"]

        else:
            log("FATAL",
                f"Cannot authenticate against {self.tenant_config.name}",
                str(response.json()))
            raise TideErrors.TenantConnectionError("Cannot authenticate with the tenant configuration")

    
    def _safer_configuation(self, rule:DetectionRule)->DetectionRule:
        """
        Reconfigures a deployment to remove all known problematic identifiers
        and attempt deployment in a minimal but functional state
        """
        if rule.detectionAction.alertTemplate.impactedAssets:
            log("INFO", "Reassigning Impacted Entities to Device with deviceId identifier")
            ImpactedAssets = DetectionRule.DetectionAction.AlertTemplate.ImpactedAsset
            rule.detectionAction.alertTemplate.impactedAssets = [ImpactedAssets(odata_type="#microsoft.graph.security.impactedDeviceAsset",
                                                                                identifier="deviceId")]
        if response_actions:=rule.detectionAction.responseActions:
            new_response_actions = []
            RISKY_RESPONSE_ACTIONS = ["#microsoft.graph.security.markUserAsCompromisedResponseAction",
                                        "#microsoft.graph.security.disableUserResponseAction",
                                        "#microsoft.graph.security.forceUserPasswordResetResponseAction"]
            for action in response_actions:
                if action.odata_type not in RISKY_RESPONSE_ACTIONS:
                    new_response_actions.append(action)
                else:
                    log("INFO",
                        f"Removing response action as can lead to mapping issues",
                        action.odata_type)
            rule.detectionAction.responseActions = new_response_actions

        return rule

    def validate_query(self, query:str)->bool:
        """
        Performs a query against the MDE tenant to validate if the query is able to run.
        Timespan gets forced to one hour to avoid any performance hits. 
        """
        request = self.session.post(url=self.HUNTING_QUERY_ENDPOINT,
                                    verify=self.tenant_config.setup.ssl,
                                    json={"Query" : query,
                                          "Timespan": "PT1H"})
        
        if request.status_code == 200:
            log("SUCCESS", 
                "Query was able to run on tenant", self.tenant_config.name)
            return True
        else:
            if request.status_code == 403:
                log("FATAL", 
                    f"Missing permissions to run query against tenant {self.tenant_config.name} - Error Code {request.status_code}",
                    str(request.json()),
                    "Add the permissions mentionsed above to the service principal to fix this")
                raise Exception

            error_message = request.json().get("error", {}).get("message") or request.json()
            print(request.json())

            log("FATAL", 
                f"Error Code {request.status_code} - {error_message}",
                "The query could not run due to a syntax error. Confirm that it can run on the console and try again",
                query)
            return False

    def create_detection_rule(self, rule:DetectionRule)->int:
        
        # Replace odata_type to @odata.type ans re-dump into a JSON body
        rule_body = json.dumps(asdict(rule))
        rule_body = rule_body.replace("odata_type", "@odata.type")
        rule_body = json.loads(rule_body)
        
        request = self.session.post(url=self.DETECTION_RULES_ENDPOINT,
                                    verify=self.tenant_config.setup.ssl,
                                    json=rule_body)

        if request.status_code == 201:
            log("SUCCESS", "Created rule in MDE", str(request.json()))
            return int(request.json()["id"])
        else:
            log("FATAL",
                f"Failed to create detection rule in tenant {self.tenant_config.name}",
                str(request.json()),
                "Will attempt redeployment, with minimal configurations : impacted_entities"
                "will be set to Device with DeviceId mapping, user response actions will be"
                "removed as they can lead to mapping issues. If successful, this pipeline will"
                "fail with warning, and you will need to check the GUI to see which identifiers"
                "are available based on your query")
            
            rule = self._safer_configuation(rule)
            rule_body = json.dumps(asdict(rule))
            rule_body = rule_body.replace("odata_type", "@odata.type")
            rule_body = json.loads(rule_body)

            log("ONGOING",
                "Attempting redeployment with safer configuration",
                str(rule_body))
            
            request = self.session.post(url=self.GRAPH_API_ENDPOINT,
                                        json=rule_body)
            if request.status_code == 201:
                log("SUCCESS", "Created rule in MDE", str(request.json()))
                log("WARNING",
                    "This is a partial deployment, check the MDE GUI to see the available identifiers")
                os.environ["DEPLOYMENT_WARNING_RAISED"]
                return int(request.json()["id"])
            else:
                raise TideErrors.DetectionRuleCreationFailed

    def update_detection_rule(self, rule:DetectionRule, rule_id:int):
        
        # Replace odata_type to @odata.type ans re-dump into a JSON body
        rule_body = json.dumps(asdict(rule))
        rule_body = rule_body.replace("odata_type", "@odata.type")
        rule_body = json.loads(rule_body)
        
        request = self.session.patch(url=self.GRAPH_API_ENDPOINT + f"/{rule_id}",
                                     verify=self.tenant_config.setup.ssl,
                                     json=rule_body)
        
        if request.status_code == 200:
            log("SUCCESS", "Created Updated Rules in MDE", str(request.json()))
        else:
            log("FATAL",
                f"Failed to create detection rule with id {rule_id} in tenant {self.tenant_config.name}",
                str(request.json()), str(rule_body))
            raise TideErrors.DetectionRuleUpdateFailed

    def delete_detection_rule(self, rule_id:int):
        request = self.session.delete(url=self.GRAPH_API_ENDPOINT + f"/{rule_id}",
                                      verify=self.tenant_config.setup.ssl)
        if request.status_code == 204:
            log("SUCCESS", "Removed Detection Rule from MDE Tenant")
        else:
            log("FATAL",
                f"Failed to create detection rule with id {rule_id} in tenant {self.tenant_config.name}",
                "Double check scope permissions, and whether the ID actually exists")
            raise TideErrors.DetectionRuleDeletionFailed