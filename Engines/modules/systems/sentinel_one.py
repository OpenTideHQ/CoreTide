import sys
import requests 
import json

import git

from dataclasses import dataclass, asdict
from typing import Literal, Optional
from enum import Enum
from datetime import datetime, timedelta

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide
from Engines.modules.models import TideConfigs
from Engines.modules.deployment import Proxy
from Engines.modules.errors import TideErrors


    
class SeverityMapping(Enum):
    Informational = "Low"
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

@dataclass
class DetectionRule:    

    @dataclass
    class Data:
        
        @dataclass
        class CoolOffSettings:
            renotifyMinutes:int
        
        @dataclass
        class CorrelationParams:
            @dataclass
            class SubQueries:
                matchesRequired: int
                subQuery: str

            @dataclass
            class TimeWindow:
                windowMinutes: int

            entity:str #Already validated in JSON Schema
            matchInOrder: bool
            subQueries: SubQueries
            timeWindow: Optional[TimeWindow] = None

        expirationMode:Literal["Permanent", "Temporary"]
        name: str
        description: str
        queryType:Literal["correlation", "events"]
        severity:str
        status:Literal["Active", "Disabled"]
        networkQuarantine: Optional[bool] = None
        treatAsThreat: Optional[Literal["UNDEFINED", "Suspicious", "Malicious"]] = None
        queryLang: Literal["1.0", "2.0"] = "2.0"
        s1ql: Optional[str] = None #Only for single event 
        expiration: Optional[str] = None
        coolOffSetting:Optional[CoolOffSettings] = None
        correlationParams:Optional[CorrelationParams] = None
    
    @dataclass
    class Filter:
        accountIds:Optional[list[str]] = None
        siteIds:Optional[list[str]] = None
        
    data:Data
    filter: Filter


class SentinelOneService:
    """
    Interface to connect and deploy MDRs to SentinelOne. Initialized on a single
    tenant basis.
    """

    def __init__(self, tenant_config:TideConfigs.Systems.SentinelOne.Tenant) -> None:


        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = DataTide.Configurations.Systems.SentinelOne.platform.identifier
        self.tenant_config = tenant_config
        
        self.CUSTOM_DETECTION_RULES_ENDPOINT = self.tenant_config.setup.url + "/web/api/v2.1/cloud-detection/rules"
        self.CREATE_QUERY_ENDPOINT = self.tenant_config.setup.url + "/web/api/v2.1/dv/events/pq"

        self.session = requests.Session()
        self.session.headers.update({"Authorization" : f"ApiToken {self.tenant_config.setup.api_token}",
                                     "Content-Type" : "application/json"})

        if tenant_config.setup.proxy:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()

    def _http_errors(self, response:requests.Response, error):
        match response.status_code:
            case 400:
                log("FATAL",
                    "Received code [400], Invalid user input received",
                    str(response.text))
                raise error

            case 401:
                log("FATAL",
                    "Received code [401], Unauthorized access",
                    str(response.text),
                    "Check your configuration and API permissions again")
                raise TideErrors.TideTenantConfigurationMissingPermissions

            case 404:
                log("FATAL",
                    f"Received code [404], Custom Detection rule not found with id in MDR file",
                    str(response.text),
                    "Go to SentinelOne Console and check if your rule still exists. If not, remove the rule id entry from the MDR file")
                raise error
        
            case _:
                log("FATAL", f"Unforeseen error with code [{response.status_code}]",
                    str(response.json()))
                raise error
    
    def validate_query(self, query:str)->bool:
        """
        Performs a Power Query against the SentinelOne tenant to validate if the query is able to run
        May not be able to catch every edge cases, but will replicate most frontend errors
        """
        request = {}
        request["accountIds"] = str(self.tenant_config.setup.account_id)
        if site_id:=self.tenant_config.setup.site_id:
            request["site_id"] = str(site_id)
        request["query"] = query
        now = datetime.now()
        from_date = now - timedelta(minutes=1)
        request["toDate"] = str(now.isoformat()) + "Z"
        request["fromDate"] = str(from_date.isoformat()) + "Z"
        
        request =json.dumps(request, indent=4)
        response = self.session.post(url=self.CREATE_QUERY_ENDPOINT,
                                    verify=self.tenant_config.setup.ssl,
                                    data=request)

        match response.status_code:
            case 200:
                log("SUCCESS", "The query was able to run")
                return True
            case 400:
                try:
                    error = response.json().get("errors")[0].get("detail")
                except:
                    error = str(response.json())
                log("FATAL",
                    f"The query failed to be validated on tenant {self.tenant_config.name}",
                    error,
                    "Double check your query on the Sentinel One Event Search interface")
                return False
            case _:
                self._http_errors(response, error=TideErrors.TideQueryValidationError)
            
                
    def create_update_detection_rule(self, rule:DetectionRule, rule_id:Optional[int]=None)->int:

        def _remove_nulls(value):
            if isinstance(value, dict):
                return {k: _remove_nulls(v) for k, v in value.items() if v is not None}
            elif isinstance(value, list):
                return [_remove_nulls(item) for item in value if item is not None]
            else:
                return value
        
        rule_body = json.dumps(_remove_nulls(asdict(rule)))
        log("INFO", str(rule_body))        
        
        endpoint = self.CUSTOM_DETECTION_RULES_ENDPOINT
        if rule_id:
            log("ONGOING", "Executing API call to update STAR Custom Rule with id", str(rule_id))
            endpoint += f"/{rule_id}"
            error = TideErrors.DetectionRuleUpdateFailed
            request = self.session.put(url=endpoint,
                                        verify=self.tenant_config.setup.ssl,
                                        data=rule_body)
        else:
            log("ONGOING", "Executing API call to create STAR Custom Rule")
            error = TideErrors.DetectionRuleCreationFailed
            request = self.session.post(url=endpoint,
                                        verify=self.tenant_config.setup.ssl,
                                        data=rule_body)

        match request.status_code:
            case 200:
                log("SUCCESS", "Created rule in SentinelOne", str(request.json()))
                return int(request.json()["data"]["id"])

            case _:
                self._http_errors(request, error=error)


    def disable_detection_rule(self, rule_id:int):
        filter = {"filter": {"ids":[rule_id]}}
        filter = json.dumps(filter)

        log("ONGOING", "Disabling Rule with ID", str(rule_id))
        request = self.session.put(url=self.CUSTOM_DETECTION_RULES_ENDPOINT,
                                    verify=self.tenant_config.setup.ssl,
                                    data=filter)
        match request.status_code:
            case 200:
                log("SUCCESS", f"Disabled rule with id {rule_id} in SentinelOne", str(request.json()))

            case _:
                self._http_errors(request,
                                  error=TideErrors.DetectionRuleDisablingFailed)


    def delete_detection_rule(self, rule_id:int):
        
        filter = {"filter": {"ids":[rule_id]}}
        filter = json.dumps(filter)
        
        log("ONGOING", "Deleting Rule with ID", str(rule_id))
        request = self.session.delete(url=self.CUSTOM_DETECTION_RULES_ENDPOINT,
                                        verify=self.tenant_config.setup.ssl,
                                        data=filter)
        match request.status_code:
            case 200:
                log("SUCCESS", f"Deleted rule with id {rule_id} in SentinelOne", str(request.json()))

            case _:
                self._http_errors(request,
                                  error=TideErrors.DetectionRuleDeletionFailed)