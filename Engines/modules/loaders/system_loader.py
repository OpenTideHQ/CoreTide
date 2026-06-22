import os
import git
import sys
from pathlib import Path
import json
from typing import (
    Any,
    Dict,
    Literal,
    Mapping,
    Never,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)
from functools import cache
from abc import ABC
from importlib import import_module
from copy import deepcopy

from dataclasses import dataclass, asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.indexing.indexer import indexer
from Engines.modules.logs import log
from Engines.modules.models import (DetectionSystems,
                                    TideModels,
                                    TideDefinitionsModels,
                                    TideConfigs,
                                    SystemConfig)
from Engines.modules.patching import Tide2Patching
from Engines.modules.datamodels.objects import Objects
from Engines.modules.datamodels.configurations import Configurations

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
class PlatformConfigLoader:

    @staticmethod
    def _base_configuration(mdr_config:dict[str, Any])->Tuple[dict[str, Any], TideDefinitionsModels.SystemConfigurationModel]:
        """Extract common top-level configuration fields from an MDR config.

        Many MDR system-specific configuration blocks share a small set of
        common keys: ``schema``, ``status``, ``tenants``, ``flags`` and
        ``contributors``. This helper pops those values from the provided
        mapping and returns a tuple containing the remaining mapping and a
        populated SystemConfigurationModel instance.

        Args:
            mdr_config: A mutable mapping with MDR configuration fields. The
                common keys will be popped from this mapping.

        Returns:
            A tuple (remaining_config, BaseConfigModel) where ``remaining_config``
            is the original mapping with the common fields removed and
            ``BaseConfigModel`` is a TideDefinitionsModels.SystemConfigurationModel
            constructed from the popped values.
        """

        BaseConfigModel = TideDefinitionsModels.SystemConfigurationModel
        schema = mdr_config.pop("schema", None)
        status = mdr_config.pop("status", None)
        tenants:list[str] = mdr_config.pop("tenants", None)
        flags:list[str] = mdr_config.pop("flags", None)
        contributors:list[str] = mdr_config.pop("contributors", None)

        return mdr_config, BaseConfigModel(schema=schema,
                                            tenants=tenants,
                                            status=status,
                                            flags=flags,
                                            contributors=contributors)

    @staticmethod
    def _external_rule_id(mdr_config:dict[str, Any])->Tuple[dict[str, Any], Union[Mapping[str, int], Mapping[str,str]]]:
        """Collect external rule id mappings from an MDR configuration.

        Some configurations store rule identifiers per-tenant using keys of the
        form ``"rule_id::<tenant>"`` or using a pre-built ``rule_id_bundle``
        mapping. This helper normalizes both formats and returns the cleaned
        configuration and the resolved rule id mapping.

        Args:
            mdr_config: The MDR configuration mapping to process. The function
                will pop any ``rule_id::...`` keys it finds.

        Returns:
            A tuple (remaining_config, rule_id_bundle) where ``rule_id_bundle``
            is a mapping from tenant to rule id (or an empty dict if none
            present).
        """

        rule_id_bundle = {}
        
        # In case was already parsed into bundle
        if "rule_id_bundle" in mdr_config:
            rule_id_bundle = mdr_config.pop("rule_id_bundle")
            return mdr_config, rule_id_bundle
        
        for key in mdr_config.copy():
            if key.startswith("rule_id::"):
                tenant = key.split("rule_id::")[1]
                rule_id_bundle[tenant] = mdr_config.pop(key)

        return mdr_config, rule_id_bundle

    @staticmethod
    def sentinel(mdr_config: dict[str, Any]) -> TideModels.MDR.Configurations.Sentinel:
        """Build a Sentinel system configuration object from raw MDR config.

        This function maps the dictionary structure used in the index/TOML
        files into a strongly-typed ``TideModels.MDR.Configurations.Sentinel``
        instance. It extracts shared base configuration values, converts any
        nested structures (template, trigger, scheduling, alert, grouping,
        entities) to their corresponding dataclass representations and returns
        the populated Sentinel configuration object.

        Args:
            mdr_config: A mapping containing the sentinel configuration as
                produced by the indexer or TOML loader. The mapping will be
                mutated (popped) while the function extracts nested fields.

        Returns:
            A ``TideModels.MDR.Configurations.Sentinel`` instance populated
            from the provided configuration mapping.
        """

        Sentinel = TideModels.MDR.Configurations.Sentinel

        mdr_config, base_config = SystemLoader._base_configuration(mdr_config)

        query = mdr_config.pop("query")

        template = mdr_config.pop("template", None)
        if template:
            template = Sentinel.Template(**template)

        trigger = mdr_config.pop("trigger", None)
        if trigger:
            trigger = Sentinel.Trigger(**trigger)   
        
        scheduling = Sentinel.Scheduling(**mdr_config.pop("scheduling", None))
        
        custom_details = dynamic_properties = None
        
        alert = mdr_config.pop("alert", None)
        if alert:
            custom_details = alert.pop("custom_details", None)
            dynamic_properties = alert.pop("dynamic_properties", None)
            
            if custom_details:
                custom_details = [Sentinel.Alert.CustomDetails(**detail) for detail in custom_details]
            if dynamic_properties:
                dynamic_properties = [Sentinel.Alert.DynamicProperties(**property) for property in dynamic_properties]

        alert = Sentinel.Alert(**alert or {},
                               custom_details=custom_details,
                               dynamic_properties=dynamic_properties)

        grouping = mdr_config.pop("grouping", None)
        if grouping:
            event = grouping.pop("event")
            alert_grouping = grouping.pop("alert", None)
            if alert_grouping:
                alert_grouping = Sentinel.Grouping.AlertGrouping(**alert_grouping)
            
            grouping = Sentinel.Grouping(event=event,
                                         alert=alert_grouping)

        entity_list = mdr_config.pop("entities", None)
        entities = None
        if entity_list:
            entities = []
            for mapping in entity_list:
                entities.append(
                    Sentinel.EntityMapping(
                        entity=mapping["entity"],
                        mappings=[Sentinel.EntityMapping.MappingEntry(**entry)
                                    for entry in mapping["mappings"]]
                    )
                )

        exclusions = mdr_config.pop("exclusions", None)
        if exclusions:
            exclusions_data = []
            for exclusion in exclusions:
                exclusions_data.append(Sentinel.Exclusion(**exclusion))
            exclusions = exclusions_data

        return Sentinel(
            schema=base_config.schema,
            status=base_config.status,
            contributors=base_config.contributors,
            tenants=base_config.tenants,
            flags=base_config.flags,
            query=query,
            template=template,
            trigger=trigger,
            scheduling=scheduling,
            alert=alert,
            grouping=grouping,
            entities=entities,
            exclusions=exclusions
        )

    @staticmethod
    def crowdstrike(mdr_config:dict[str, Any])->TideModels.MDR.Configurations.Crowdstrike:
        """Build a Crowdstrike system configuration object from raw MDR config.

        Transforms the provided mapping into a ``TideModels.MDR.Configurations.Crowdstrike``
        instance by extracting the base configuration values, resolving any
        external rule id bundle, and converting nested detail and schedule
        structures.

        Args:
            mdr_config: A mapping containing crowdstrike configuration fields.

        Returns:
            A ``TideModels.MDR.Configurations.Crowdstrike`` instance.
        """

        Crowdstrike = TideModels.MDR.Configurations.Crowdstrike

        mdr_config, base_config = SystemLoader._base_configuration(mdr_config)
        mdr_config, rule_id_bundle = SystemLoader._external_rule_id(mdr_config)
        
        details = Crowdstrike.Details(**mdr_config.pop("details"))
        schedule = Crowdstrike.Schedule(**mdr_config.pop("schedule"))
        query = mdr_config.pop("query")

        return Crowdstrike(schema=base_config.schema,
                           status=base_config.status,
                           contributors=base_config.contributors,
                           tenants=base_config.tenants,
                           flags=base_config.flags,
                           rule_id_bundle=rule_id_bundle, #type:ignore
                           details=details,
                           schedule=schedule,
                           query=query)

    @staticmethod
    def sentinel_one(mdr_config:dict[str, Any])->TideModels.MDR.Configurations.SentinelOne:
        """Build a SentinelOne system configuration object from raw MDR config.

        Parses details, condition (including single_event and correlation
        subqueries), optional cool-off settings and response information, and
        returns a populated ``TideModels.MDR.Configurations.SentinelOne``
        instance.

        Args:
            mdr_config: A mapping containing sentinel_one configuration fields.

        Returns:
            A ``TideModels.MDR.Configurations.SentinelOne`` instance.
        """

        SentinelOne = TideModels.MDR.Configurations.SentinelOne
        
        mdr_config, base_config = SystemLoader._base_configuration(mdr_config)
        mdr_config, rule_id_bundle = SystemLoader._external_rule_id(mdr_config)
        
        details = None
        if mdr_config.get("details"):
            details = SentinelOne.Details(**mdr_config.pop("details"))

        condition = mdr_config.pop("condition")
        rule_type = condition.pop("type")
        single_event = None
        if condition.get("single_event"):
            single_event = SentinelOne.Condition.SingleEvent(**condition.pop("single_event"))
        
        correlation = None
        if condition.get("correlation"):
            sub_queries = condition["correlation"].pop("sub_queries")
            sub_queries = [SentinelOne.Condition.Correlation.SubQueries(**sub) for sub in sub_queries]
            correlation = SentinelOne.Condition.Correlation(**condition.pop("correlation"),
                                                            sub_queries=sub_queries)

        cool_off = mdr_config.pop("cool_off", None)
        condition = SentinelOne.Condition(type=rule_type,
                                          single_event=single_event,
                                          correlation=correlation,
                                          cool_off=cool_off)

        response = SentinelOne.Response(**mdr_config.pop("response"))
        
        return SentinelOne(schema=base_config.schema,
                           status=base_config.status,
                           contributors=base_config.contributors,
                           tenants=base_config.tenants,
                           flags=base_config.flags,
                           rule_id_bundle=rule_id_bundle, #type: ignore
                           details=details,
                           condition=condition,
                           response=response)

    @staticmethod
    def defender_for_endpoint(mdr_config:dict[str, Any])->TideModels.MDR.Configurations.DefenderForEndpoint:
        """Build a Defender for Endpoint system configuration from raw MDR config.

        Converts the dictionary representation into a
        ``TideModels.MDR.Configurations.DefenderForEndpoint`` instance. This
        includes parsing nested alert, impacted_entities, scope and response
        actions structures. The function supports legacy per-tenant ``rule_id::``
        keys and will assemble a rule id bundle if present.

        Args:
            mdr_config: A mapping containing defender_for_endpoint configuration
                fields.

        Returns:
            A ``TideModels.MDR.Configurations.DefenderForEndpoint`` instance.
        """

        DefenderForEndpoint = TideModels.MDR.Configurations.DefenderForEndpoint

        mdr_config, base_config = SystemLoader._base_configuration(mdr_config)
        #TODO Migrate to new rule ID bundle method
        
        rule_id_bundle = {}
        for key in mdr_config.copy():
            if key.startswith("rule_id::"):
                tenant = key.split("rule_id::")[1]
                rule_id_bundle[tenant] = mdr_config.pop(key)
        rule_id = rule_id_bundle if rule_id_bundle else mdr_config.pop("rule_id", None)


        alert = DefenderForEndpoint.Alert(**mdr_config.pop("alert"))
        impacted_entities = DefenderForEndpoint.ImpactedEntities(**mdr_config.pop("impacted_entities"))
        group_scoping = DefenderForEndpoint.GroupScoping(**mdr_config.pop("scope"))

        actions:dict = mdr_config.pop("actions", None)
        response_actions = None 
        if mdr_config.get("actions"):
            devices = None
            files = None
            users = None

            if actions.get("devices"):
                devices = DefenderForEndpoint.ResponseActions.Devices(**actions.pop("devices"))
            if actions.get("files"):
                FileActions = DefenderForEndpoint.ResponseActions.Files
                allow_block_action = None
                if actions["files"].get("allow_block"):
                    allow_block = actions["files"].pop("allow_block", None)
                    device_groups = FileActions.AllowBlockAction.GroupScoping(**allow_block.pop("groups"))
                    allow_block_action = FileActions.AllowBlockAction(**allow_block,
                                                                        groups=device_groups)                    

                quarantine_file = actions["files"].pop("quarantine_files", None)
                files = DefenderForEndpoint.ResponseActions.Files(allow_block=allow_block_action,
                                                                        quarantine_file=quarantine_file)

            if actions.get("users"):
                users = DefenderForEndpoint.ResponseActions.Users(**actions.pop("users"))


            if devices or files or users:
                response_actions = DefenderForEndpoint.ResponseActions(devices=devices,
                                                                        files=files,
                                                                        users=users)
        exclusions = mdr_config.pop("exclusions", None)
        if exclusions:
            exclusions_data = []
            for exclusion in exclusions:
                exclusions_data.append(DefenderForEndpoint.Exclusion(**exclusion))
            exclusions = exclusions_data
        
        return DefenderForEndpoint( **mdr_config,
                                    schema=base_config.schema,
                                    status=base_config.status,
                                    rule_id=rule_id,
                                    contributors=base_config.contributors,
                                    flags=base_config.flags,
                                    tenants=base_config.tenants,
                                    alert=alert,
                                    actions=response_actions,
                                    impacted_entities=impacted_entities,
                                    scope=group_scoping,
                                    exclusions=exclusions)

    @staticmethod
    def harfanglab(mdr_config: dict[str, Any]) -> TideModels.MDR.Configurations.HarfangLab:
        """Build a HarfangLab system configuration object from raw MDR config.

        Parses sigma and yara rule configurations, along with common HarfangLab
        metadata like maturity, confidence, and action settings.

        Args:
            mdr_config: A mapping containing harfanglab configuration fields.

        Returns:
            A ``TideModels.MDR.Configurations.HarfangLab`` instance.
        """
        HarfangLab = TideModels.MDR.Configurations.HarfangLab
        
        mdr_config, base_config = SystemLoader._base_configuration(mdr_config)
        mdr_config, rule_id_bundle = SystemLoader._external_rule_id(mdr_config)
        
        # Extract HarfangLab-specific fields (REQUIRED, but provide defaults for backwards compatibility)
        maturity = mdr_config.pop("maturity", "Experimental")
        confidence = mdr_config.pop("confidence", "Moderate")
        action = mdr_config.pop("action", "Alert")
        # Tags are optional, at top level (used by both Sigma and YARA)
        tags = mdr_config.pop("tags", None)
        
        # Parse Sigma configuration if present
        sigma = None
        sigma_config = mdr_config.pop("sigma", None)
        if sigma_config:
            logsource = HarfangLab.Sigma.LogSource(**sigma_config.pop("logsource"))
            selections_data = sigma_config.pop("selections", [])
            selections = [HarfangLab.Sigma.Selection(**sel) for sel in selections_data]
            sigma = HarfangLab.Sigma(
                logsource=logsource,
                selections=selections,
                condition=sigma_config.pop("condition"),
                false_positives=sigma_config.pop("false_positives", None)
            )
        
        # Parse YARA configuration if present
        yara = None
        yara_config = mdr_config.pop("yara", None)
        if yara_config:
            # meta is REQUIRED with context and os
            meta_config = yara_config.pop("meta")
            meta = HarfangLab.Yara.Meta(**meta_config)
            yara = HarfangLab.Yara(
                meta=meta,
                strings=yara_config.pop("strings"),
                condition=yara_config.pop("condition"),
                imports=yara_config.pop("imports", None)
            )
        
        return HarfangLab(
            schema=base_config.schema,
            status=base_config.status,
            contributors=base_config.contributors,
            tenants=base_config.tenants,
            flags=base_config.flags,
            maturity=maturity,
            confidence=confidence,
            action=action,
            tags=tags,
            sigma=sigma,
            yara=yara,
            rule_id_bundle=rule_id_bundle if rule_id_bundle else None  # type: ignore
        )


SystemLoader = PlatformConfigLoader
