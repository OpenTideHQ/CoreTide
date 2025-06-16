import os
import sys
from tokenize import String
import git

from dataclasses import dataclass
from typing import Literal, Never, Optional, Sequence, Mapping, Any, Union
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

# TODO - Re-Architect Uber Class by merging this and DataTide

# OpenTide.Models. #DataModels
# OpenTide.Objects. #Returning Models
# OpenTide.Configurations.
# OpenTide.Deployment. #Returns Initialized deployment classes
# OpenTide.Vocabularies.
# OpenTide.Schemas.Json / OpenTide.Schemas.Yaml

class BaseModels:

    class Enums:
        ...
    class Objects:
        ...
    class Deployment:
        ...

class DetectionSystems(Enum):
    DEFENDER_FOR_ENDPOINT = auto()
    CARBON_BLACK_CLOUD = auto()
    SPLUNK = auto()
    SENTINEL = auto()
    SENTINEL_ONE = auto()
    CROWDSTRIKE = auto()

class DeploymentStrategy(Enum):
    STAGING = auto()
    PRODUCTION = auto()
    FULL = auto()
    ALWAYS = auto()
    MANUAL = auto()
    DEBUG = auto()

    @staticmethod
    def load_from_environment():
        """
        Read the DEPLOYMENT_PLAN environment variable and maps it to 
        DeploymentStrategy valid values. In case of an illegal value, 
        or missing environment variable will raise an exception
        """
        SUPPORTED_PLANS = [plan.name for plan in DeploymentStrategy]
        DEPLOYMENT_PLAN = str(os.getenv("DEPLOYMENT_PLAN")) or None
        if not DEPLOYMENT_PLAN:
            log(
                "FATAL",
                "No deployment plan, ensure that the CI variable DEPLOYMENT_PLAN is set correctly",
            )
            raise Exception("NO DEPLOYMENT PLAN")

        try:
            DEPLOYMENT_PLAN = DeploymentStrategy[DEPLOYMENT_PLAN]
        except:

                log(
                    "FATAL",
                    "The following deployment plan is not supported",
                    DEPLOYMENT_PLAN,
                    f"Supported plan : {SUPPORTED_PLANS}",
                )
                raise AttributeError("UNSUPPORTED DEPLOYMENT PLAN")

        return DEPLOYMENT_PLAN


@dataclass
class SystemConfig:

    @dataclass
    class Platform:
        enabled: bool
        identifier: str
        name: str
        subschema: str
        description: str
        flags: list[str]

    @dataclass
    class Modifiers:
        @dataclass
        class Conditions:
            status: Optional[Sequence[str]] = None
            flags: Optional[Sequence[Never] | Sequence[str]] = None
            tenants: Optional[Sequence[Never] | Sequence[str]] = None
            default: Optional[bool] = None
        
        conditions: Conditions
        modifications: Mapping[Any, str]
        name: Optional[str] = None
        description: Optional[str] = None

    @dataclass 
    class Tenant:
        @dataclass
        class Setup:
            proxy: bool
            ssl: bool

        @dataclass
        class Parameters:
            ...
        
        name: str
        description: str
        deployment: Union[DeploymentStrategy, str]
        setup: Setup
        parameters: Optional[Parameters] = None

        def __post_init__(self):
            if type(self.deployment) is str:
                self.deployment = DeploymentStrategy[self.deployment]

    platform: Platform
    tenants: Optional[Sequence[Tenant]]
    modifiers: Optional[Sequence[Modifiers]] = None

@dataclass
class TideConfigs:

    @dataclass
    class Systems:

        @dataclass
        class Sentinel(SystemConfig):
            
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    resource_group: str
                    workspace_name: str
                    workspace_id: str
                    azure_tenant_id: str
                    azure_subscription_id: str
                    azure_client_id: str
                    azure_client_secret: str

                setup: Setup
        @dataclass
        class Splunk(SystemConfig):
            ...

        @dataclass
        class CarbonBlackCloud(SystemConfig):
            ...

        @dataclass
        class SentinelOne(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url:str
                    account_id:int
                    api_token:str
                    site_id:Optional[int] = None

                setup:Setup

        @dataclass
        class DefenderForEndpoint(SystemConfig):
            
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Parameters:
                    device_groups: Optional[Sequence[str]] = None

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    tenant_id: str
                    client_id: str
                    client_secret: str

                setup:Setup
                parameters: Optional[Parameters] = None

            tenants: Optional[Sequence[Tenant]]

        @dataclass
        class Crowdstrike(SystemConfig):
            
            @dataclass
            class Tenant(SystemConfig.Tenant):

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    api: str
                    client_id: str
                    client_secret: str
                    customer_id: str

                setup:Setup

            tenants: Optional[Sequence[Tenant]]


class TideDefinitionsModels:

    @dataclass
    class TideObjectMetadata:
        uuid: str
        schema: str
        version: str | int
        created: str
        modified: str
        tlp: str
        author: str
        contributors: Optional[Sequence[str]] = None

    @dataclass
    class TideObjectReferences:
        public: Optional[Mapping[int, str]] = None
        internal: Optional[Mapping[str, str]] = None
        reports: Optional[Sequence[str]] = None

    @dataclass
    class SystemConfigurationModel:
        schema: str
        status: str
        flags: Optional[list[Never] | list[str]]
        tenants: Optional[list[str]]
        contributors: Optional[list[str]]


class TideModels:

    @dataclass
    class MDR:
    
        @dataclass
        class Response:
            @dataclass
            class Procedure:
                @dataclass
                class Search:
                    purpose: str
                    system: str
                    query: str

                analysis: str
                searches: Optional[Sequence[Search]] = None
                containment: Optional[str] = None

            alert_severity: str = "Informational" 
            playbook: Optional[str] = None
            responders: Optional[str] = None
            procedure: Optional[Procedure] = None

        @dataclass
        class Configurations:
            
            @dataclass
            class SentinelOne(TideDefinitionsModels.SystemConfigurationModel):
                @dataclass
                class Details:
                    name: Optional[str] = None
                    description: Optional[str] = None
                    severity: Optional[str] = None
                    expiration: Optional[str] = None
                
                @dataclass
                class Condition:
                    @dataclass
                    class SingleEvent:
                        query: str

                    @dataclass
                    class Correlation:
                        @dataclass
                        class SubQueries:
                            query: str
                            matches_required: int
                        entity: str
                        match_in_order: bool
                        time_window: str
                        sub_queries: Sequence[SubQueries]
                    
                    type:Literal["Single Event", "Correlation"]
                    single_event: Optional[SingleEvent] = None
                    correlation: Optional[Correlation] = None
                    cool_off: Optional[str] = None
                
                @dataclass
                class Response:
                    treat_as_threat:Literal[False, "Malicious", "Suspicious"]
                    network_quarantine:bool

                condition: Condition
                response: Optional[Response] = None
                details:Optional[Details] = None
                rule_id_bundle: Optional[Mapping[str, int]] = None

            @dataclass
            class DefenderForEndpoint(TideDefinitionsModels.SystemConfigurationModel):
                @dataclass
                class Alert:
                    category: str
                    title: Optional[str] = None
                    severity: Optional[str] = None
                    recommendation: Optional[str] = None
                    techniques: Optional[Sequence[str]] = None

                @dataclass
                class ImpactedEntities:
                    device: Optional[str] = None
                    mailbox: Optional[str] = None
                    user: Optional[str] = None

                @dataclass
                class GroupScoping:
                    selection: Literal["All", "Specific"]
                    device_groups: Optional[Sequence[str]] = None

                @dataclass
                class ResponseActions:
                    
                    @dataclass
                    class Files:
                                    
                        @dataclass
                        class AllowBlockAction:
                        
                            @dataclass
                            class GroupScoping:
                                selection: Literal["All", "Specific"]
                                device_groups: Optional[Sequence[str]] = None

                            action: Literal["Allow", "Block"]
                            identifier: str
                            groups: Optional[GroupScoping] = None
            
                        allow_block: Optional[AllowBlockAction] = None
                        quarantine_file: Optional[str] = None

                    @dataclass
                    class Devices:
                        isolate_device: Optional[str] = None
                        collect_investigation_package: bool = False
                        run_antivirus_scan:bool = False
                        initiate_investigation:bool = False
                        restrict_app_execution:bool = False

                    @dataclass
                    class Users:
                        mark_as_compromised: Optional[str] = None
                        disable_user: Optional[str] = None
                        force_password_reset: Optional[str] = None

                    devices: Optional[Devices] = None
                    files: Optional[Files] = None
                    users: Optional[Users] = None

                @dataclass
                class Exclusion:
                    query: str
                    reason: str
                    tenant: Optional[str]=None
                    
                schema: str
                alert: Alert
                query: str
                impacted_entities: ImpactedEntities
                scheduling: Literal["NRT", "1H", "3H", "12H", "24H"]
                rule_id: Optional[Mapping[str, int]] = None
                actions: Optional[ResponseActions] = None
                scope: Optional[GroupScoping] = None
                exclusions: Optional[Sequence[Exclusion]] = None
            
            
            @dataclass
            class Crowdstrike(TideDefinitionsModels.SystemConfigurationModel):
                @dataclass
                class Details:
                    trigger: str
                    outcome: str
                    name: Optional[str] = None
                    description: Optional[str] = None
                    severity: Optional[str] = None
                    tactic: Optional[str] = None
                    technique: Optional[str] = None
                
                @dataclass
                class Schedule:
                    frequency: str
                    lookback: str
                    start: Optional[str] = None
                    end: Optional[str] = None

                details: Details
                schedule: Schedule
                query: str
                rule_id_bundle: Optional[Mapping[str, str]] = None

            @dataclass
            class Splunk(TideDefinitionsModels.SystemConfigurationModel):
                ...

            @dataclass
            class Sentinel(TideDefinitionsModels.SystemConfigurationModel):
                
                @dataclass
                class Trigger:
                    operator: str
                    threshold: int

                @dataclass
                class Scheduling:
                    nrt: Optional[bool] = None
                    frequency: Optional[str] = None
                    lookback: Optional[str] = None

                @dataclass
                class Alert:

                    @dataclass
                    class CustomDetails:
                        key: str
                        column: str

                    @dataclass
                    class DynamicProperties:
                        property: str
                        column: str

                    title: Optional[str] = None
                    description: Optional[str] = None
                    suppression: Union[str, bool] = False
                    create_incident: bool = True 
                    tactics: Optional[Sequence[str]] = None
                    techniques: Optional[Sequence[str]] = None
                    custom_details: Optional[Sequence[CustomDetails]] = None
                    dynamic_properties: Optional[Sequence[DynamicProperties]] = None


                @dataclass
                class Grouping:

                    @dataclass
                    class AlertGrouping:
                        # Required: enabled must be provided, others are optional.
                        enabled: bool
                        reopen_closed_incidents: Optional[bool] = None
                        grouping_lookback: Optional[str] = None
                        matching: Optional[str] = None
                        group_by_entities: Optional[Sequence[str]] = None
                        group_by_alert_details: Optional[Sequence[str]] = None
                        group_by_custom_details: Optional[Sequence[str]] = None

                    # The overall grouping configuration contains the event grouping details (required)
                    # and an optional alert grouping configuration.
                    event: str
                    alert: AlertGrouping

                @dataclass
                class EntityMapping:

                    @dataclass
                    class MappingEntry:
                        identifier: str
                        column: str

                    entity: str
                    mappings: Sequence[MappingEntry]

                query: str
                scheduling: Scheduling
                alert: Alert
                trigger: Optional[Trigger] = None
                grouping: Optional[Grouping] = None
                entities: Optional[Sequence[EntityMapping]] = None

            @dataclass
            class CarbonBlackCloud(TideDefinitionsModels.SystemConfigurationModel):
                ...
                        
            sentinel: Optional[Sentinel] = None
            defender_for_endpoint: Optional[DefenderForEndpoint] = None
            sentinel_one: Optional[SentinelOne] = None
            crowdstrike: Optional[Crowdstrike] = None
            carbon_black_cloud: Optional[Mapping] = None
            splunk: Optional[Mapping] = None

        name: str
        metadata: TideDefinitionsModels.TideObjectMetadata
        description: str
        response: Response
        configurations: Configurations
        detection_model: Optional[str] = None
        references: Optional[TideDefinitionsModels.TideObjectReferences] = None


@dataclass
class TenantDeploymentModel:
    """
    Base common dataclass used to construct tenant deployment
    per system
    """
    tenant: SystemConfig.Tenant
    rules: Sequence[TideModels.MDR]

class TenantDeployment:

    @dataclass
    class Splunk(TenantDeploymentModel):
        tenant: TideConfigs.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Sentinel(TenantDeploymentModel):
        tenant: TideConfigs.Systems.Sentinel.Tenant

    @dataclass
    class CarbonBlackCloud(TenantDeploymentModel):
        tenant: TideConfigs.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class SentinelOne(TenantDeploymentModel):
        tenant: TideConfigs.Systems.SentinelOne.Tenant

    @dataclass
    class DefenderForEndpoint(TenantDeploymentModel):
        tenant: TideConfigs.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Crowdstrike(TenantDeploymentModel):
        tenant: TideConfigs.Systems.Crowdstrike.Tenant
