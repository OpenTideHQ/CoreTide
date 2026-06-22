import os
import sys
from tokenize import String
import git

from dataclasses import dataclass
from typing import Literal, Never, Optional, List, Sequence, Mapping, Any, Union
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

class SharedModels:

    @dataclass
    class ObjectMetadata:
        
        @dataclass
        class Organisation:
            uuid: str
            name: str
            
        uuid: str
        schema: str
        version: str | int
        created: str
        modified: str
        tlp: str
        author: Optional[str] = None
        contributors: Optional[Sequence[str]] = None
        organisation: Optional[Organisation] = None

    @dataclass
    class ObjectReferences:
        public: Optional[Mapping[int, str]] = None
        internal: Optional[Mapping[str, str]] = None
        reports: Optional[Sequence[str]] = None

    @dataclass
    class PlatformConfigurationBase:
        schema: str
        status: str
        flags: Optional[list[Never] | list[str]]
        tenants: Optional[list[str]]
        contributors: Optional[list[str]]


@dataclass
class DetectionRule:
    
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
        class SentinelOne(SharedModels.PlatformConfigurationBase):
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
        class DefenderForEndpoint(SharedModels.PlatformConfigurationBase):
            @dataclass
            class Alert:
                category: str
                title: Optional[str] = None
                description: Optional[str] = None
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
                tenant: Optional[str] = None
                let: Optional[Mapping[str, Any]] = None
                
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
        class Crowdstrike(SharedModels.PlatformConfigurationBase):
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
        class Splunk(SharedModels.PlatformConfigurationBase):
            ...

        @dataclass
        class Sentinel(SharedModels.PlatformConfigurationBase):
            
            @dataclass
            class Template:
                uuid: str
                version: str

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
                severity: Optional[str] = None
                suppression: Union[str, bool] = False
                create_incident: bool = True 
                tactics: Optional[List[str]] = None
                techniques: Optional[List[str]] = None
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

            @dataclass
            class Exclusion:
                query: str
                reason: str
                tenant: Optional[str] = None
                let: Optional[Mapping[str, Any]] = None

            query: str
            scheduling: Scheduling
            alert: Alert
            exclusions: Optional[Sequence[Exclusion]] = None
            template: Optional[Template] = None
            trigger: Optional[Trigger] = None
            grouping: Optional[Grouping] = None
            entities: Optional[Sequence[EntityMapping]] = None

        @dataclass
        class CarbonBlackCloud(SharedModels.PlatformConfigurationBase):
            ...

        @dataclass
        class HarfangLab(SharedModels.PlatformConfigurationBase):
            """HarfangLab MDR Configuration supporting Sigma and YARA rules"""
            
            @dataclass
            class Sigma:
                """Sigma rule configuration for behavioral detection"""
                
                @dataclass
                class LogSource:
                    category: str
                    product: str
                
                @dataclass
                class Selection:
                    name: str
                    field: str
                    value: Union[str, List[str], bool, int, float]
                    modifiers: Optional[List[str]] = None
                
                logsource: LogSource
                selections: Sequence[Selection]
                condition: str
                false_positives: Optional[List[str]] = None
            
            @dataclass
            class Yara:
                """YARA rule configuration for memory/file scanning"""
                
                @dataclass
                class Meta:
                    """YARA meta section with HarfangLab-specific fields"""
                    context: List[str]  # process, thread, memory, file (REQUIRED)
                    os: str  # Windows, Linux, MacOS (REQUIRED)
                    arch: Optional[List[str]] = None  # x86, x64
                    score: Optional[str] = None  # Severity level override: Informational, Low, Medium, High, Critical
                    classification: Optional[str] = None  # e.g., Windows.Loader.3CXSupplyChainAttack
                
                meta: Meta  # REQUIRED
                strings: str
                condition: str
                imports: Optional[List[str]] = None  # YARA modules: pe, dotnet, elf, hash, math, time, string, macho

            # HarfangLab-specific fields (REQUIRED)
            maturity: str  # Stable, Testing, Experimental
            confidence: str  # Weak, Moderate, Strong
            action: str  # Alert, Alert & Block, Alert, Block & Quarantine
            # Optional fields
            tags: Optional[List[str]] = None  # MITRE ATT&CK tags (used by both Sigma and YARA)
            sigma: Optional[Sigma] = None
            yara: Optional[Yara] = None
            rule_id_bundle: Optional[Mapping[str, str]] = None
                    
        sentinel: Optional[Sentinel] = None
        defender_for_endpoint: Optional[DefenderForEndpoint] = None
        sentinel_one: Optional[SentinelOne] = None
        crowdstrike: Optional[Crowdstrike] = None
        carbon_black_cloud: Optional[Mapping] = None
        splunk: Optional[Mapping] = None
        harfanglab: Optional[HarfangLab] = None

    name: str
    metadata: SharedModels.ObjectMetadata
    description: str
    response: Response
    configurations: Configurations
    detection_model: Optional[str] = None
    references: Optional[SharedModels.ObjectReferences] = None


# Legacy compatibility aliases
TideDefinitionsModels = SharedModels
TideDefinitionsModels.TideObjectMetadata = SharedModels.ObjectMetadata  # type: ignore[attr-defined]
TideDefinitionsModels.TideObjectReferences = SharedModels.ObjectReferences  # type: ignore[attr-defined]
TideDefinitionsModels.SystemConfigurationModel = SharedModels.PlatformConfigurationBase  # type: ignore[attr-defined]

class TideModels:
    MDR = DetectionRule
