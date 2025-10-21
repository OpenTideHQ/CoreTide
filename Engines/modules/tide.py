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


# Configuration Models. Used to facilitate type hinting
class HelperTide:
    @staticmethod
    def is_debug() -> bool:
        """
        Provides an interface to discover whether the current execution
        context is considered to be in a debugging scenario.
        """
        if (
            os.environ.get("DEBUG") == True
            or os.environ.get("TERM_PROGRAM") == "vscode"
        ):
            return True
        else:
            return False

    @staticmethod
    def fetch_config_envvar(config_secrets: dict[str,str]) -> dict[str, Any]:
        """Resolve and replace environment-variable placeholders in a config mapping.

        Many configuration files in TIDE use strings that begin with ``$`` to indicate
        that the real value should be read from an environment variable. This
        function walks the provided mapping and replaces any such placeholders
        with the corresponding environment value. It also prints debug guidance
        when running in debug mode and logs missing values.

        Args:
            config_secrets: A mapping of configuration keys to values. Values that
                are strings beginning with ``$`` will be treated as environment
                variable references and replaced with the variable's value.

        Returns:
            The same mapping (mutated in place) with placeholders replaced by
            environment values where applicable.

        Notes:
            - If a referenced environment variable is missing and the runtime is
              not in debug mode, a fatal log entry will be emitted and the
              function will mark that an environment variable error occurred.
            - When running in debug mode, a local helper module
              ``Engines.modules.local_secrets`` is imported (if present) to help
              set environment variables for local development.
        """
        #Allows to print all errors at once before raising exception
        missing_envvar_error = False
        
        if HelperTide.is_debug():
            try:
                import_module("Engines.modules.local_secrets")
            except:
                print("[FAILURE]",
                    "Could not find local python file at `Engines.modules.local_secrets` to set secret environment variables",
                    "Parts of this module may not work properly",
                    "Refer to the relevant TOML conguration file to find which variables may be necessary")


        for sec in config_secrets.copy():
            if not config_secrets[sec]:
                log("SKIP", "Did not found an entry for", sec,
                    "If there are deployment issue, review if it is relevant to configure")
                continue
            if type(config_secrets[sec]) == str:
                if config_secrets[sec].startswith("$"):
                    if config_secrets[sec].removeprefix("$") in os.environ:
                        env_variable = str(config_secrets.pop(sec)).removeprefix("$")
                        config_secrets[sec] = os.environ.get(env_variable, "")
                        log("SUCCESS", "Fetched environment secret", env_variable)
                    else:
                        if HelperTide.is_debug():
                            log("SKIP", 
                                "Could not find expected environment variable",
                                config_secrets[sec],
                                "Debug Mode identified, continuing - remember that this may break some deployments")
                        else:
                            log(
                                "FATAL",
                                "Could not find expected environment variable",
                                config_secrets[sec],
                                "Review configuration file and execution environment",
                            )
                            missing_envvar_error = True

        if missing_envvar_error:
            log("FATAL",
                "Some environment variable specified in configuration files were not found"
                "Review the previous errors to find which ones were missing",
                "Check your CI settings to ensure these environment variables are properly injected",
                "This may not be a critical issue, for example if you didn't enable a particular system")

        return config_secrets


class IndexTide:
    """
    Helper class for callable Index related functions. Designed to power
    `DataTide` initialization routine.
    """
    @staticmethod
    def reload():
        """Force a re-import of the tide module to refresh the in-memory index.

        DataTide is implemented as a self-initializing dataclass that captures
        the repository index at import time and then remains static. When the
        underlying index changes during a long-running process (for example
        during orchestration), calling this function removes the module from
        ``sys.modules`` so a subsequent import will re-run the module top-level
        code and create a fresh DataTide instance using the updated index.

        This method has the side effect of re-executing module import-time
        actions; callers should ensure that it is safe to reload the module in
        their runtime environment.
        """
        log("WARNING", "DataTide re-indexation")
        log("INFO", "The repository will be reindexed to update DataTide")
        del sys.modules["Engines.modules.tide"]
        from Engines.modules.tide import DataTide

    @cache #Memoization as load() is called multiple times as DataTide initializes
    @staticmethod
    def load() -> Dict[str, dict]:
        """Load the OpenTide instance index from disk or generate it in memory.

        The loader will:
        1. Load or generate the base index
        2. Reconcile with staging index if present and load fresh configurations

        Returns:
            A dictionary representing the full TIDE index structure with fresh 
            configurations from staging reconciliation.

        Raises:
            Exception: If the index cannot be loaded or generated in memory.
        """
        EXPECTED_INDEX_PATH = ROOT / "index.json"
        INDEX_PATH = Path(os.getenv("INDEX_PATH") or EXPECTED_INDEX_PATH)

        print("📂 Index not found in memory, first seeking index file...")
        if os.path.isfile(INDEX_PATH):
            _tide_index = json.load(open(INDEX_PATH))
        else:
            # Generate index in memory
            print("💽 Could not find index file, generating it in memory")
            _tide_index = indexer()
            if not _tide_index:
                raise Exception("INDEX COULD NOT BE LOADED IN MEMORY")
        
        # Reconcile with staging index if present
        _tide_index = IndexTide.reconcile_staging(_tide_index)
        return _tide_index

    @staticmethod
    def reconcile_staging(index):
        """Merge staging index model data into the provided production index.

        If a staging index exists (``staging_index.json`` by default or as
        specified by ``STAGING_INDEX_PATH``), this routine will:
        
        1. Load the staging index
        2. Merge model data (MDRs) from staging into production, where:
           - New MDRs from staging are added
           - MDRs with higher version in staging replace production versions
        3. Load fresh configurations from TOML files

        Args:
            index: The production index dictionary to reconcile against.

        Returns:
            A new index dictionary that contains reconciled model data and fresh
            configurations.
        """
        log("INFO", "Entering staging index reconciliation routine")
        EXPECTED_STAGING_INDEX_PATH = ROOT / "staging_index.json"
        STAGING_INDEX_PATH = os.getenv("STAGING_INDEX_PATH") or EXPECTED_STAGING_INDEX_PATH

        if not os.path.exists(STAGING_INDEX_PATH):
            log("SKIP", "No Staging Index to reconcile")
            return index

        from Engines.modules.files import resolve_configurations
        RECONCILED_INDEX = index.copy()
        STG_INDEX = json.load(open(Path(STAGING_INDEX_PATH)))
        added_mdr = list()
        updated_mdr = list()

        patch = Tide2Patching()

        for mdr in STG_INDEX:
            if mdr not in RECONCILED_INDEX["objects"]["mdr"]:
                log("INFO", "Patching MDR in staging index", mdr)
                RECONCILED_INDEX["objects"]["mdr"][mdr] = patch.tide_1_patch(STG_INDEX[mdr], "mdr")
                added_mdr.append(mdr)
            else:
                main_mdr_metadata = (
                    RECONCILED_INDEX["objects"]["mdr"][mdr].get("meta") or RECONCILED_INDEX["objects"]["mdr"][mdr]["metadata"]
                )
                main_version = main_mdr_metadata["version"]
                stg_mdr_metadata = (
                    STG_INDEX[mdr].get("meta") or STG_INDEX[mdr]["metadata"]
                )
                stg_version = stg_mdr_metadata["version"]

                mdr_name = (
                    STG_INDEX[mdr].get("name")
                    or STG_INDEX[mdr]["title"].split("$")[0].strip()
                )

                if stg_version > main_version:
                    log("INFO",
                        f"🔄 Replacing MDR {mdr_name} from prod index with"
                        f" staging data, as version is higher (main : v{main_version}"
                        f" staging : v{stg_version})"
                    )
                    log("INFO", "Doing a safety patching to avoid edge cases")
                    RECONCILED_INDEX["objects"]["mdr"][mdr] = patch.tide_1_patch(STG_INDEX[mdr], "mdr")
                    updated_mdr.append(mdr)
        
        # Always load fresh configurations after model data reconciliation
        log("INFO", "Loading fresh configurations from TOML files")
        RECONCILED_INDEX["configurations"] = resolve_configurations()
        
        log("SUCCESS", "Finalized Staging Reconciliation Routine")
        log("INFO", "Updated MDRs from Production Index with Staging Data", str(len(updated_mdr)))
        log("INFO", "New MDR added from Staging Data ", str(len(added_mdr)))
        return RECONCILED_INDEX

    @staticmethod
    def compute_chains(tvm_index: dict) -> dict:
        """Compute chaining relationships between threat vector models (TVMs).

        This function inspects the provided TVM index and builds a mapping of
        TVM UUIDs to their chaining relations. The returned structure maps each
        TVM to another mapping where keys are relation names and values are
        lists of vectors (UUIDs) that are linked under that relation.

        Args:
            tvm_index: A dictionary where keys are TVM identifiers and values
                contain a ``threat`` key which may include a ``chaining`` list.

        Returns:
            A dictionary of the form {tvm_id: {relation: [vector_id, ...]}}
            only for TVMs that include chaining definitions.
        """

        chain = dict()
        for tvm in (n := tvm_index):
            if "chaining" in n[tvm]["threat"]:
                if tvm not in chain:
                    chain[tvm] = dict()
                for link in n[tvm]["threat"]["chaining"]:
                    if link["relation"] not in chain[tvm]:
                        chain[tvm][link["relation"]] = []
                    if link["vector"] not in chain[tvm][link["relation"]]:
                        chain[tvm][link["relation"]].append(link["vector"])

        return chain

    @staticmethod
    def return_paths(tier: Literal["all", "core", "tide"]) -> dict[str, Path]:
        """Return pre-computed path mappings from the index for the requested tier.

        Args:
            tier: One of ``"all"``, ``"core"``, or ``"tide"`` specifying the
                scope of paths to return.

        Returns:
            A dict mapping logical path names to Path objects for the requested
            tier. ``"all"`` returns the full paths mapping, while ``"core"``
            and ``"tide"`` return the respective sub-mapping.
        """

        if tier == "all":
            return IndexTide.load()["paths"]
        if tier == "core":
            return IndexTide.load()["paths"]["core"]
        if tier == "tide":
            return IndexTide.load()["paths"]["tide"]

                

class SystemLoader:

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
            entities=entities
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


class ConfigurationsLoader:
    @staticmethod
    def load_statuses(statuses_configuration:list[dict])->Sequence[TideConfigs.Deployment.Status]:
        """
        Converts a list of status configuration dictionaries into a sequence of TideConfigs.Deployment.Status objects.
        Args:
            statuses_configuration (list[dict]): A list of dictionaries where each dictionary contains the parameters 
                                                   to instantiate a TideConfigs.Deployment.Status object.
        Returns:
            Sequence[TideConfigs.Deployment.Status]: A sequence of TideConfigs.Deployment.Status instances created 
                                                       from the provided configuration dictionaries.
        """
        Status = TideConfigs.Deployment.Status
        parsed_configuration = list()
        for status_configuration in statuses_configuration:
            parsed_configuration.append(Status(**status_configuration))

        return parsed_configuration

    @staticmethod
    def load_visibility(config: dict) -> Optional[Configurations.Visibility]:
        """Load visibility configuration from a dictionary into a strongly-typed dataclass.
        
        This method processes the visibility configuration which consists of three main components:
        1. Assets - Business or technical assets that generate logs
        2. Log Sources - Specific sources that can be queried for detection purposes
        3. Detectors - External detection capabilities from third-party tools and platforms
        
        Args:
            config: Dictionary containing the visibility configuration with 'assets', 'logsources', and 'detectors' sections
            
        Returns:
            Configurations.Visibility: Populated dataclass if configuration exists
            None: If no visibility configuration is found
            
        Raises:
            ValueError: If the configuration is malformed, missing required fields,
                      or contains references to non-existent assets
        """
        # Early return if no configuration exists
        if not config:
            return None
            
        try:
            # Process assets section first to build reference set
            assets = None
            asset_names = set()
            if asset_configuration:=config.get("assets"):
                assets = []
                for asset_config in asset_configuration:
                    asset = Configurations.Visibility.Asset(**asset_config)
                    assets.append(asset)
                    asset_names.add(asset.name)
                
            # Process log sources section and validate asset references
            logsources = []
            for source_config in config.get("logsources", []):
                # Validate asset references before creating LogSource
                if source_assets := source_config.get("assets"):
                    invalid_assets = [asset for asset in source_assets if asset not in asset_names]
                    if invalid_assets:
                        log("FAILURE", 
                            f"Log source '{source_config.get('name')}' references non-existent assets",
                            f"Invalid assets: {', '.join(invalid_assets)}",
                            "These assets must be defined in the assets section",
                            "Configuration will load but may be incomplete")
                
                logsources.append(Configurations.Visibility.LogSource(**source_config))
                
            # Process detectors section and validate asset references
            detectors = []
            for detector_config in config.get("detectors", []):
                # Validate asset references before creating Detector
                if detector_assets := detector_config.get("assets"):
                    invalid_assets = [asset for asset in detector_assets if asset not in asset_names]
                    if invalid_assets:
                        log("FAILURE", 
                            f"Detector '{detector_config.get('name')}' references non-existent assets",
                            f"Invalid assets: {', '.join(invalid_assets)}",
                            "These assets must be defined in the assets section",
                            "Configuration will load but may be incomplete")
                
                detectors.append(Configurations.Visibility.Detector(**detector_config))
                
            # Create and return the complete configuration
            return Configurations.Visibility(
                logsources=logsources if logsources else None,
                assets=assets if assets else None,
                detectors=detectors if detectors else None
            )
            
        except (KeyError, TypeError) as e:
            log("FATAL",
                "Failed to load visibility configuration",
                f"Error details: {str(e)}",
                "Ensure all required fields are present and properly formatted",
                "Check the schema documentation for complete requirements")
            raise ValueError(f"Failed to load visibility configuration: {str(e)}")


class TideLoader:

    @staticmethod
    def load_signal(signal: dict) -> Objects.DetectionObjective.Objective.Signal:
        try:
            # Process data field - required
            if "data" not in signal:
                log("FATAL", "Missing required data field for signal", str(signal))
                raise KeyError(f"Required 'data' field missing from signal")
            
            data = Objects.DetectionObjective.Objective.Signal.Data(**signal.pop("data"))
            
            # Process optional lists
            detectors = [Objects.DetectionObjective.Objective.Signal.Detector(**ext) 
                        for ext in signal.pop("detectors", [])]
            examples = [Objects.DetectionObjective.Objective.Signal.Example(**comm) 
                        for comm in signal.pop("examples", [])]
            
            # Create signal with remaining fields
            return Objects.DetectionObjective.Objective.Signal(
                data=data,
                detectors=detectors if detectors else None,
                examples=examples if examples else None,
                **signal
                )
            
        except (KeyError, TypeError) as e:
            log("FATAL", "Failed to process signal", str(e))
            raise ValueError("Invalid signal configuration")


    @staticmethod
    def load_dom(dom: dict) -> Objects.DetectionObjective:
        """Transform a raw Detection Objective dictionary into a strongly-typed dataclass.
        
        Args:
            dom: Raw dictionary loaded from a Detection Objective YAML file
            
        Returns:
            Objects.DetectionObjective: Fully populated Detection Objective dataclass
            
        Raises:
            KeyError: If required fields are missing
            ValueError: If data validation fails
        """
        dom = deepcopy(dom)
        
        # Check for name first since we need it for meaningful error messages
        if "name" not in dom:
            log("FATAL", "Missing required field 'name' in Detection Objective")
            raise KeyError("Missing required field 'name' in Detection Objective")
            
        log("ONGOING", "Loading Detection Objective", dom["name"])
        
        # Check remaining required top-level fields
        if not all(key in dom for key in ["metadata", "objective"]):
            missing = [k for k in ["name", "metadata", "objective"] if k not in dom]
            log("FATAL", "Missing required top-level fields", ", ".join(missing))
            raise KeyError("Required fields missing from Detection Objective")

        try:
            # Process metadata and references
            metadata = TideDefinitionsModels.TideObjectMetadata(**dom.pop("metadata"))
            references = None
            if "references" in dom:
                references = TideDefinitionsModels.TideObjectReferences(**dom.pop("references"))

            # Process objective section
            objective_data = dom.pop("objective")
            if not objective_data:
                log("FATAL", "Empty objective section")
                raise ValueError("Objective section cannot be empty")
            
            attack = objective_data.pop("att&ck", None)

            # Process signals with error handling
            if "signals" not in objective_data:
                log("FATAL", "Missing signals section in objective")
                raise KeyError("Required 'signals' field missing from objective")
                
            signals = []
            for signal in objective_data.pop("signals"):
                signals.append(TideLoader.load_signal(signal))
                
            # Process composition - required
            if "composition" not in objective_data:
                log("FATAL", "Missing composition section in objective")
                raise KeyError("Required 'composition' field missing from objective")
            
            composition = Objects.DetectionObjective.Objective.Composition(**objective_data.pop("composition"))
            
            # Create objective with remaining fields
            objective = Objects.DetectionObjective.Objective(
                signals=signals,
                composition=composition,
                attack=attack,
                **objective_data
            )
            
            result = Objects.DetectionObjective(
                name=dom["name"],
                metadata=metadata,
                objective=objective,
                composition=composition,
                references=references
            )
            
            log("ONGOING", "Detection Objective loaded successfully", dom["name"])
            return result
            
        except Exception as e:
            log("FATAL", f"Failed to load Detection Objective '{dom.get('name', 'unnamed')}':", str(e))
            raise


    @staticmethod
    def load_mdr(mdr:dict)->TideModels.MDR:
        """Convert a raw MDR mapping from the index into a TideModels.MDR object.

        This function takes the raw dictionary representation of a Managed
        Detection Rule (MDR) as produced by the indexer or loaded from TOML
        files and transforms nested fields into the project's typed model
        classes. It handles metadata, optional organisation metadata,
        response/procedure/searches conversion, references and per-system
        configurations by delegating to the SystemLoader helpers.

        Args:
            mdr: A dictionary representing an MDR entry from the index. The
                mapping is copied internally to avoid mutating the original.

        Returns:
            A ``TideModels.MDR`` instance populated with parsed nested
            structures and typed sub-objects.
        """

        mdr = deepcopy(mdr)

        metadata = mdr.pop("metadata")
        organisation = metadata.pop("organisation", None)

        if organisation:
            organisation = TideDefinitionsModels.TideObjectMetadata.Organisation(**organisation)
        
        metadata = TideDefinitionsModels.TideObjectMetadata(**metadata,
                                                            organisation=organisation)
        
        response_config = mdr.pop("response", {})
        if response_config:
            procedure = response_config.pop("procedure", None)
            if procedure:
                searches = None
                searches_data = procedure.pop("searches", None)
                if searches_data:
                    searches = []
                    for search in searches_data:
                        searches.append(TideModels.MDR.Response.Procedure.Search(**search))
                procedure = TideModels.MDR.Response.Procedure(**procedure,
                                                              searches=searches)
            response = TideModels.MDR.Response(**response_config,
                                               procedure=procedure)

        references = TideDefinitionsModels.TideObjectReferences(**mdr.pop("references", {}))

        configurations = TideModels.MDR.Configurations()
        system_configurations:dict[str,Any] = mdr.pop("configurations")
        if system_configurations.get("sentinel"):
            configurations.sentinel = SystemLoader.sentinel(system_configurations.pop("sentinel"))
        if system_configurations.get("defender_for_endpoint"):
            configurations.defender_for_endpoint = SystemLoader.defender_for_endpoint(system_configurations.pop("defender_for_endpoint"))
        if system_configurations.get("sentinel_one"):
            configurations.sentinel_one = SystemLoader.sentinel_one(system_configurations.pop("sentinel_one"))
        if system_configurations.get("crowdstrike"):
            configurations.crowdstrike = SystemLoader.crowdstrike(system_configurations.pop("crowdstrike"))

        return TideModels.MDR(**mdr,
                                metadata=metadata,
                                response=response,
                                references=references,
                                configurations=configurations)

    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.SENTINEL])->TideConfigs.Systems.Sentinel.Platform: ...
    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.CROWDSTRIKE])->TideConfigs.Systems.Crowdstrike.Platform: ...
    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.SENTINEL_ONE])->TideConfigs.Systems.SentinelOne.Platform: ...
    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.DEFENDER_FOR_ENDPOINT])->TideConfigs.Systems.DefenderForEndpoint.Platform: ...
    @staticmethod
    def load_platform_config(platform_config:dict, system:DetectionSystems):
        """Load and type a platform configuration for a given detection system.

        The function validates that a platform configuration mapping is
        present and returns a typed platform configuration object specific to
        the requested detection system. It supports Sentinel, Crowdstrike,
        Defender for Endpoint and SentinelOne; unknown systems fall back to the
        generic ``SystemConfig.Platform`` type.

        Args:
            platform_config: Mapping containing platform-specific configuration
                values.
            system: A ``DetectionSystems`` enum value identifying the target
                system for which the platform configuration should be loaded.

        Returns:
            An instance of the platform configuration dataclass appropriate to
            the requested system.

        Raises:
            NotImplementedError: If ``platform_config`` is falsy or missing.
        """

        if not platform_config:
            log("FATAL", f"Could not find any platform configuration for platform f{system.name}",
            "Ensure that the platform configuration section is present")
            raise NotImplementedError("Missing Configuration Segment")

        match system:
            case DetectionSystems.CROWDSTRIKE:
                return TideConfigs.Systems.Crowdstrike.Platform(**platform_config)

            case DetectionSystems.SENTINEL:
                return TideConfigs.Systems.Sentinel.Platform(**platform_config)

            case DetectionSystems.DEFENDER_FOR_ENDPOINT:
                return TideConfigs.Systems.DefenderForEndpoint.Platform(**platform_config)

            case DetectionSystems.SENTINEL_ONE:
                return TideConfigs.Systems.SentinelOne.Platform(**platform_config)

            case _:
                return SystemConfig.Platform(**platform_config)
    
    @staticmethod
    def load_modifiers_config(modifiers_config:list[dict])->Sequence[SystemConfig.Modifiers] | list[Never]:
        """Parse a list of modifier configuration mappings into typed objects.

        Modifiers are runtime configuration units that describe conditional
        modifications to platform behavior. Each entry must contain
        ``conditions`` and ``modifications`` keys. This function validates the
        presence of required keys, constructs typed ``SystemConfig.Modifiers``
        instances and returns the sequence.

        Args:
            modifiers_config: A list of mappings describing modifiers.

        Returns:
            A sequence of ``SystemConfig.Modifiers`` instances. If the input
            is falsy, an empty list is returned.

        Raises:
            Exception: If any modifier mapping is missing required keys.
        """

        if not modifiers_config:
            log("SKIP", "No modifiers configuration could be found")
            return []
        
        modifiers = []
        
        for modifier in modifiers_config:
            log("DEBUG", "Current Modifier Evaluated", str(modifier))
            if ("conditions" not in modifier) or ("modifications" not in modifier):
                log("FATAL", "Could not load the modifier configuration, does not contain 'conditions' or 'modifications key'",
                    str(modifier))
                raise Exception

            name = modifier.get("name")
            description = modifier.get("description")
            conditions = SystemConfig.Modifiers.Conditions(**modifier["conditions"])
            modifications:dict = modifier["modifications"]
            
            modifiers.append(SystemConfig.Modifiers(name=name,
                                                    description=description,
                                                    conditions=conditions,
                                                    modifications=modifications))
        
        return modifiers

    @staticmethod
    def load_tenants_config(tenants_config:Sequence[dict], platform:DetectionSystems):
        """Load tenant configurations for a specific detection system.

        Each tenant mapping must contain a ``setup`` section which may include
        environment-variable placeholders. This helper resolves secrets via
        ``HelperTide.fetch_config_envvar``, converts system-specific setup and
        parameter blocks into typed dataclasses and returns a list of
        ``SystemConfig.Tenant`` instances.

        Args:
            tenants_config: Sequence of tenant mappings from the platform
                configuration.
            platform: A ``DetectionSystems`` enum value indicating how to parse
                each tenant's setup block.

        Returns:
            A list of ``SystemConfig.Tenant`` instances suitable for runtime
            usage.

        Raises:
            NotImplementedError: If tenants_config is empty or a tenant lacks
                the required ``setup`` key.
        """

        if not tenants_config:
            log("FATAL", f"Could not find any tenant information for platform f{platform.name}",
                "Ensure that at least one tenant is present in the platform configuration TOML file")
            raise NotImplementedError("Missing Configuration Segment")
        tenants = []
        for tenant in tenants_config:
            tenant = tenant.copy() #Avoids removing data from index with .pop() operations later
            if "setup" not in tenant:
                log("FATAL", f"Could not find a tenant setup configuration for platform {platform.name}",
                    "Ensure that the setup section is correctly entered in platform configuration TOML file")
                raise NotImplementedError("Missing Configuration Segment")

            setup_with_secrets = HelperTide.fetch_config_envvar(tenant.pop("setup"))
            parameters = tenant.pop("parameters", None)
            match platform:
                case DetectionSystems.SENTINEL:
                    setup = TideConfigs.Systems.Sentinel.Tenant.Setup(**setup_with_secrets)

                case DetectionSystems.DEFENDER_FOR_ENDPOINT:
                    if parameters:
                        parameters = TideConfigs.Systems.DefenderForEndpoint.Tenant.Parameters(**parameters)
                    setup = TideConfigs.Systems.DefenderForEndpoint.Tenant.Setup(**setup_with_secrets)

                case DetectionSystems.SENTINEL_ONE:
                    setup = TideConfigs.Systems.SentinelOne.Tenant.Setup(**setup_with_secrets)

                case DetectionSystems.CROWDSTRIKE:
                    setup = TideConfigs.Systems.Crowdstrike.Tenant.Setup(**setup_with_secrets)

                case _:
                    raise NotImplementedError(f"Platform {platform.name} is not recognized")

            tenants.append(SystemConfig.Tenant(**tenant,
                                               setup=setup,
                                               parameters=parameters)) #type: ignore

        return tenants

class DataTide:
    """Unified programmatic interface to access all data in the
    TIDE instance. Calling this class triggers an indexation of the
    entire repository and stores it in memory.

    DataTide execution model as a self-initializing dataclass means
    it will fetch all index data dynamically when the tide module is first
    imported in the execution environment, then freeze this state. To
    refresh DataTide, call `IndexTide.reload()` , a new DataTide object
    will be initialized. 
    """

    # Index = _retrieve_index
    """Return the raw index content"""

    Index = IndexTide.load()
    
    @dataclass(frozen=True)
    class Models:
        """TIDE Lookups Interface.

        Exposes all the configurations of the instance
        """
        Index = dict(IndexTide.load()["objects"])
        """Index containing model types"""
        tvm = dict(Index["tvm"])
        """Threat Vector Models Data Index"""
        dom = dict(Index["dom"])
        """Detection Objectives Raw Index"""
        DOM = {uuid:TideLoader.load_dom(deepcopy(data)) for (uuid, data) in dict(Index.copy()["dom"]).items()} 
        """Detection Objectives Pre-Loaded Index"""
        signal = dict(Index["signal"])
        """Detection Objectives Signals Raw Index"""
        Signal = {uuid:TideLoader.load_signal(deepcopy(data)) for (uuid, data) in dict(Index.copy()["signal"]).items()} 
        """Detection Objectives Signals Pre-Loaded Index"""
        bdr = dict(Index["bdr"])
        """Business Detection Rules Data Index"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Models Data Index"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rules Data Index"""
        # We need to do a deepcopy to ensure that loading steps aren't modifying the original data
        MDR = {uuid:TideLoader.load_mdr(deepcopy(data)) for (uuid, data) in dict(Index.copy()["mdr"]).items()} 
        """Model Mapped Managed Detection Rules Data Index"""
        chaining = IndexTide.compute_chains(tvm)
        """Index of all chaining relationships"""
        FlatIndex =  tvm | dom | signal | cdm | mdr | bdr
        """Flat Key Value pair structure of all UUIDs in the index"""
        files = dict(IndexTide.load()["files"])
    
    @dataclass(frozen=True)
    class Vocabularies:
        """TIDE Schema Interface.

        Exposes the vocabularies used across the instance
        """

        Index = dict(IndexTide.load()["vocabs"])

    @dataclass(frozen=True)
    class Indexes:
        """
        Interface to compiled indexes
        """
        Index = dict(IndexTide.load()["indexes"])
        revisions = dict(Index.get("revisions", {})) #TODO Loader class for revisions
        objects = dict(Index.get("objects", {}))


    @dataclass(frozen=True)
    class JsonSchemas:
        """
        Interface to all the JSON Schemas generated from TideS
        """

        Index = dict(IndexTide.load()["json_schemas"])
        tvm = dict(Index.get("tvm", {}))
        """Threat Vector Model JSON Schema"""
        dom = dict(Index.get("dom", {}))
        """Detection Objective Model JSON Schema"""
        cdm = dict(Index.get("cdm", {}))
        """Cyber Detection Model JSON Schema"""
        mdr = dict(Index.get("mdr", {}))
        """Managed Detection Rule JSON Schema"""
        bdr = dict(Index.get("bdr", {}))
        """Business Detection Request JSON Schema"""

    @dataclass(frozen=True)
    class Templates:
        """
        Interface to all the templates generated from TideSchemas
        """

        Index = dict(IndexTide.load()["templates"])
        tvm = str(Index.get("tvm"))
        """Threat Vector Model Object Template"""
        dom = str(Index.get("cdm"))
        """Detection Objective Model Object Template"""
        cdm = str(Index.get("cdm"))
        """Cyber Detection Model Object Template"""
        mdr = str(Index.get("mdr"))
        """Managed Detection Rule Object Template"""
        bdr = str(Index.get("bdr"))
        """Business Detection Request Object Template"""

    @dataclass(frozen=True)
    class TideSchemas:
        """OpenTide Meta Schema Interface.

        Exposes the different schemas used across the instance
        """

        Index = dict(IndexTide.load()["metaschemas"])
        subschemas = dict(IndexTide.load()["subschemas"])
        definitions = dict(IndexTide.load()["definitions"])
        templates = dict(IndexTide.load()["templates"])
        tvm = dict(Index["tvm"])
        """Threat Vector Model Tide Schema"""
        dom = dict(Index["dom"])
        """Detection Objective Model Tide Schema"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Model Tide Schema"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rule Tide Schema"""
        mdrv2 = dict(Index.get("mdrv2", {}))
        """DEPRECATED - Legacy MDR Version for backward compatibility use cases"""
        bdr = dict(Index["bdr"])
        """Business Detection Request Tide Schema"""

    @dataclass(frozen=True)
    class Lookups:
        """TIDE Lookups Interface.

        Exposes the lookups data within of the instance
        """

        lookups = dict(IndexTide.load()["lookups"]["lookups"])
        metadata = dict(IndexTide.load()["lookups"]["metadata"])

    @dataclass(frozen=True)
    class Configurations:
        Index = dict(IndexTide.load()["configurations"])
        DEBUG = HelperTide.is_debug()
        """Discovers whether the current execution context is considered
        to be a debugging one"""
        
        @dataclass(frozen=True)
        class Global:
            
            @dataclass
            class Indexes:
                objects: str
                revisions: str

            @dataclass
            class Exports:
                attack_layer: str
                table: str

            Index = dict(IndexTide.load()["configurations"]["global"])
            objects = Index["objects"]
            indexes = Indexes(**dict(Index["indexes"]))
            exports = Exports(**dict(Index["exports"]))
            metaschemas = dict(Index["metaschemas"])
            recomposition = dict(Index["recomposition"])
            json_schemas = dict(Index["json_schemas"])
            data_fields = dict(Index["data_fields"])
            templates = dict(Index["templates"])

            @dataclass(frozen=True)
            class Paths:
                Index = IndexTide.return_paths(tier="all")
                _raw = dict(IndexTide.load()["paths"]["raw"])
                """Paths without the proper absolute calculation.
                Only use for specific use cases, for any others prefer
                the other attributes which are precomputed"""

                @dataclass(frozen=True)
                class Core:
                    """Paths to Tide Internals"""

                    Index = IndexTide.return_paths(tier="core")
                    _raw = dict(IndexTide.load()["paths"]["raw"]["core"])
                    """Paths without the proper absolute calculation.
                    Only use for specific use cases, for any others prefer
                    the other attributes which are precomputed"""
                    vocabularies = Index["vocabularies"]
                    configurations = Index["configurations"]
                    metaschemas = Index["configurations"]
                    subschemas = Index["subschemas"]
                    definitions = Index["definitions"]
                    wiki_docs_folder = Index["wiki_docs_folder"]
                    models_docs_folder = Index["models_docs_folder"]
                    schemas_docs_folder = Index["schemas_docs_folder"]
                    vocabularies_docs = Index["vocabularies_docs"]
                    resources = Index["resources"]

                @dataclass(frozen=True)
                class Tide:
                    """Paths to Tide Content, Models, and Artifacts at
                    the top level directory"""

                    Index = IndexTide.return_paths(tier="tide")
                    _raw = dict(IndexTide.load()["paths"]["raw"]["tide"])
                    """Paths without the proper absolute calculation.
                    Only use for specific use cases, for any others prefer
                    the other attributes which are precomputed"""
                    
                    tvm = Index["tvm"]
                    dom = Index["dom"]
                    cdm = Index["cdm"]
                    mdr = Index["mdr"]
                    bdr = Index["bdr"]
                    lookups = Index["lookups"]
                    analytics = Index["analytics"]
                    snippet_file = Index["snippet_file"]
                    json_schemas = Index["json_schemas"]
                    templates = Index["templates"]
                    tide_indexes = Index["tide_indexes"]
                    exports = Index["exports"]

        @dataclass(frozen=True)
        class Systems:
            Index = dict(IndexTide.load()["configurations"]["systems"])

            @dataclass(frozen=True)
            class Splunk:
                Index = dict(IndexTide.load()["configurations"]["systems"]["splunk"])
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                defaults = dict(Index["defaults"])
                lookups = dict(Index.get("lookups", {}))
                modifiers = dict(Index.get("modifiers", {}))

            @dataclass(frozen=True)
            class CarbonBlackCloud:
                Index = dict(
                    IndexTide.load()["configurations"]["systems"]["carbon_black_cloud"]
                )
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                validation = dict(Index["validation"])

            @dataclass
            class Sentinel(TideConfigs.Systems.Sentinel):
                raw = dict(
                    IndexTide.load()["configurations"]["systems"]["sentinel"]
                )
                platform = TideLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.SENTINEL)
                modifiers = TideLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = TideLoader.load_tenants_config(raw["tenants"], DetectionSystems.SENTINEL) if raw.get("tenants") else None

            @dataclass
            class DefenderForEndpoint(TideConfigs.Systems.DefenderForEndpoint):
                raw = dict(
                    IndexTide.load()["configurations"]["systems"]["defender_for_endpoint"]
                )
                platform = TideLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.DEFENDER_FOR_ENDPOINT)
                modifiers = TideLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = TideLoader.load_tenants_config(raw["tenants"], DetectionSystems.DEFENDER_FOR_ENDPOINT) if raw.get("tenants") else None

            @dataclass
            class SentinelOne(TideConfigs.Systems.SentinelOne):
                raw = dict(
                    IndexTide.load()["configurations"]["systems"]["sentinel_one"]
                )
                platform = TideLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.SENTINEL_ONE)
                modifiers = TideLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = TideLoader.load_tenants_config(raw["tenants"], DetectionSystems.SENTINEL_ONE) if raw.get("tenants") else None

            @dataclass
            class Crowdstrike(TideConfigs.Systems.Crowdstrike):
                raw = dict(
                    IndexTide.load()["configurations"]["systems"]["crowdstrike"]
                )
                platform = TideLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.CROWDSTRIKE)
                modifiers = TideLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = TideLoader.load_tenants_config(raw["tenants"], DetectionSystems.CROWDSTRIKE) if raw.get("tenants") else None

        @dataclass(frozen=True)
        class Documentation:
            """Parameters describing how documentation should be generated."""


            Index = dict(IndexTide.load()["configurations"]["documentation"])
            scope = list(Index["scope"])
            skip_model_keys = list(Index["skip_model_keys"])
            skip_vocabularies = list(Index["skip_model_keys"])
            gitlab = dict(Index.get("gitlab", {}))
            model_cover_pages:bool = Index.get("model_cover_pages", False)
            cve = dict(Index["cve"])
            wiki = dict(Index.get("wiki",{}))
            object_names = dict(Index["object_names"])
            titles = dict(Index["titles"])
            icons = dict(Index["icons"])
            models_docs_folder:Path = Path(
                IndexTide.load()["configurations"]["global"]["paths"]["core"][
                    "models_docs_folder"
                ]
            )

        @dataclass(frozen=True)
        class Resources:
            """Parameters pointing to External resources used by engines."""
            Index = dict(IndexTide.load()["configurations"]["resources"])
            attack = dict(Index["attack"])
            d3fend = dict(Index["d3fend"])
            engage = dict(Index["engage"])
            nist = dict(Index["nist"])
            misp = dict(Index["misp"])

        @dataclass(frozen=True)
        class Deployment:
            """Generic deployment parameters."""

            Index = dict(IndexTide.load()["configurations"]["deployment"])
            print(Index)
            statuses = ConfigurationsLoader.load_statuses(Index["statuses"])
            promotion = dict(Index["promotion"])
            default_responders = str(Index["default_responders"])
            proxy = dict(Index["proxy"])
            metadata_lookup = dict(Index["metadata_lookup"])
            debug = dict(Index["debug"])

        @dataclass(frozen=True)
        class Visibility:
            """OpenTide instance visibility configuration including logsources, assets, and detectors"""
            Index = dict(IndexTide.load()["configurations"]["visibility"])
            visibility = ConfigurationsLoader.load_visibility(Index)
            assets = visibility.assets if visibility else None
            detectors = visibility.detectors if visibility else None
            logsources = visibility.logsources if visibility else None

        @dataclass(frozen=True)
        class Lookups:
            """Lookups feature management"""

            Index = dict(IndexTide.load()["configurations"]["lookups"])
            validation = dict(Index["validation"])

        """TIDE Configuration Interface.

        Exposes all the configurations of the instance
        """
        Index = dict(IndexTide.load()["configurations"])
        """Contains all configurations"""