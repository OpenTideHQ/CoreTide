import git
import sys

from typing import Sequence
from dataclasses import asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems, TideLoader
from Engines.modules.plugins import DeployMDR
from Engines.modules.models import (TideModels,
                                    DeploymentStrategy) 
from Engines.modules.deployment import TideDeployment, ExternalIdHelper
from Engines.modules.logs import log
from Engines.modules.models import TideConfigs

from Engines.modules.systems.sentinel_one import SentinelOneService, DetectionRule, SeverityMapping

class SentinelOneDeploy(DeployMDR):

    def compile_deployment(self,
                           data:TideModels.MDR,
                           tenant_config:TideConfigs.Systems.SentinelOne.Tenant)->DetectionRule:
        """
        Builds the Detection Rule call made to the API
        """
        def _convert_to_minutes(timespan:str)->int:
            """
            Helper class to normalize all time expression to minutes
            """
            if timespan.endswith("m"):
                timespan_in_minute = timespan.removesuffix("m")
            elif timespan.endswith("h"):
                timespan_in_minute = int(timespan.removesuffix("h")) * 60 

            return int(timespan_in_minute)

        mdr_config = data.configurations.sentinel_one

        if not mdr_config:
            exit()
        
        #Base Details
        rule_name = data.name
        rule_description = data.description
        rule_expiration_mode = "Permanent"
        rule_severity = SeverityMapping[data.response.alert_severity].value
        rule_expiration = None
        rule_status = "Disabled" if mdr_config.status == "DISABLED" else "Active"
        
        # Details Section
        if details:=mdr_config.details:
            if details.name:
                rule_name = details.name
            if details.description:
                rule_description = details.description
            if details.severity:
                rule_severity = details.severity
            if details.expiration:
                rule_expiration_mode = "Temporary"
                rule_expiration = details.expiration

        # Response Section
        if mdr_config.response:
            treat_as_threat = mdr_config.response.treat_as_threat
            network_quarantine = mdr_config.response.network_quarantine
            if treat_as_threat is False:
                treat_as_threat = "UNDEFINED"
        else:
            treat_as_threat = None
            network_quarantine = None

        # Condition Section
        cool_off = mdr_config.condition.cool_off
        if cool_off is str:
            cool_off = DetectionRule.Data.CoolOffSettings(renotifyMinutes=_convert_to_minutes(cool_off))

        # Rule type sanity checker
        if mdr_config.condition.type not in ["Single Event", "Correlation"]:
            raise Exception
        
        if mdr_config.condition.type == "Single Event":
            single_event_data = mdr_config.condition.single_event
            if not single_event_data:
                log("FAILURE", "Missing Single Event section in MDR", data.metadata.uuid)
                raise Exception
            query = single_event_data.query
            rule_data = DetectionRule.Data(name=rule_name,
                                            queryType="events",
                                            s1ql=query,
                                            severity=rule_severity,
                                            status=rule_status,
                                            expirationMode=rule_expiration_mode,
                                            expiration=rule_expiration,
                                            description=rule_description,
                                            networkQuarantine=network_quarantine,
                                            treatAsThreat=treat_as_threat,
                                            coolOffSetting=cool_off) # type: ignore
        
        elif mdr_config.condition.type == "Correlation":
            correlation_data = mdr_config.condition.correlation
            if not correlation_data:
                log("FAILURE", "Missing correlation section in MDR", data.metadata.uuid)
                raise Exception
            sub_queries = []
                        
            for sub_query in correlation_data.sub_queries:
                sub_queries.append(DetectionRule.Data.CorrelationParams.SubQueries(matchesRequired=sub_query.matches_required,
                                                                                   subQuery=sub_query.query))

            time_window_config = None
            if correlation_data.time_window:
                
                time_window_data = correlation_data.time_window                                    
                time_window_config = DetectionRule.Data.CorrelationParams.TimeWindow(windowMinutes = _convert_to_minutes(time_window_data))

            correlation_config = DetectionRule.Data.CorrelationParams(entity=correlation_data.entity,
                                                                      matchInOrder=correlation_data.match_in_order,
                                                                      subQueries=sub_queries, #type: ignore
                                                                      timeWindow=time_window_config)
            
            rule_data = DetectionRule.Data(name=rule_name,
                                            queryType="correlation",
                                            correlationParams=correlation_config,
                                            severity=rule_severity,
                                            status=rule_status,
                                            expirationMode=rule_expiration_mode,
                                            expiration=rule_expiration,
                                            description=rule_description,
                                            networkQuarantine=network_quarantine,
                                            treatAsThreat=treat_as_threat,
                                            coolOffSetting=cool_off) # type: ignore

        # Filter Setup
        if tenant_config.setup.site_id:
            deployment_filter = DetectionRule.Filter(siteIds=[str(tenant_config.setup.site_id)])
        elif tenant_config.setup.account_id:
            deployment_filter = DetectionRule.Filter(accountIds=[str(tenant_config.setup.account_id)])

        return DetectionRule(data=rule_data,
                             filter=deployment_filter)




    def deploy_mdr(self,
                   data:TideModels.MDR,
                   service:SentinelOneService,
                   tenant_config:TideConfigs.Systems.SentinelOne.Tenant):
        """
        Deploys the detection rule : creation, update, deletion and disabling.
        """

        mdr_config = data.configurations.sentinel_one
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
                service.create_update_detection_rule(rule, rule_id)
        
            else:
                rule_id = service.create_update_detection_rule(rule)
                ExternalIdHelper.insert_id(rule_id=rule_id,
                                           tenant_name=tenant_config.name,
                                           mdr_uuid=data.metadata.uuid,
                                           system_name=DataTide.Configurations.Systems.SentinelOne.platform.identifier)


    def deploy(self, mdr_deployment: Sequence[TideModels.MDR] | list[str], deployment_plan:DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or TideModels.MDR Objects
        """
        
        log("INFO", "Received deployment information", str(mdr_deployment))
        
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Objects.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionSystems.SENTINEL_ONE,
                                    strategy=deployment_plan)

        for tenant_deployment in deployment.rule_deployment:
            service = SentinelOneService(tenant_deployment.tenant) #type: ignore

            for mdr in tenant_deployment.rules:
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant) #type: ignore

def declare():
    return SentinelOneDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelOneDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)