import os
import git
import sys
from pathlib import Path
import json
from typing import Literal, Dict, Mapping, Tuple, Never, overload, Any, Sequence, Mapping, Union
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
                                    SystemConfig,
                                    Configurations)
from Engines.modules.patching import Tide2Patching

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))


# Configuration Models. Used to facilitate type hinting
class HelperTide:
    @staticmethod
    def is_debug()->bool:
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
        """
        Replace placeholder variables with environment
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
        """
        Due to the execution model of DataTide, the dataclass gets initialized 
        immediately with current index, and the class can't be updated dynamically
        with index changes.

        Calling this function hard removes the module from `sys.modules` and reimports
        it in the execution context calling the module. This is intended to be used in 
        Orchestration chains where the index has to be updated at some point between two steps,
        for example as framework elements gets updated, and should be reinjected in a later
        toolchain stage.
        """
        log("WARNING", "DataTide re-indexation")
        log("INFO", "The repository will be reindexed to update DataTide")
        del sys.modules["Engines.modules.tide"]
        from Engines.modules.tide import DataTide

    @cache #Memoization as load() is called multiple times as DataTide initializes
    @staticmethod
    def load() -> Dict[str, dict]:
        """
        Resolves the current index from a local index json or dynamically. 
        
        Once DataTide is initialized, it becomes a static object containing all
        of the Tide Instance data at the time the object is created. To update DataTide,
        call `IndexTide.reload()` to return the latest DataTide object.
        """
        EXPECTED_INDEX_PATH = ROOT / "index.json"
        INDEX_PATH = Path(os.getenv("INDEX_PATH") or EXPECTED_INDEX_PATH)

        print("📂 Index not found in memory, first seeking index file...")
        if os.path.isfile(INDEX_PATH):
            _tide_index = json.load(open(INDEX_PATH))
            _tide_index = IndexTide.reconcile_staging(_tide_index)
            return _tide_index
        else:
            # Generate index in memory
            print("💽 Could not find index file, generating it in memory")
            _tide_index = indexer()
            _tide_index = IndexTide.reconcile_staging(_tide_index)
            if not _tide_index:
                raise Exception("INDEX COULD NOT BE LOADED IN MEMORY")
            return _tide_index

    @staticmethod
    def reconcile_staging(index):
        """
        Helper function of `IndexTide.load()` designed to seek a staging index
        and dynamically reconcile in flight.
        """

        log("INFO", "Entering staging index reconciliation routine")
        EXPECTED_STAGING_INDEX_PATH = ROOT / "staging_index.json"
        STAGING_INDEX_PATH = os.getenv("STAGING_INDEX_PATH") or EXPECTED_STAGING_INDEX_PATH

        if not os.path.exists(STAGING_INDEX_PATH):
            log("SKIP", "No Staging Index to reconcile")
            return index

        RECONCILED_INDEX = index.copy()
        STG_INDEX = json.load(open(Path(STAGING_INDEX_PATH)))
        BANNER_MESSAGE = "⚠️ This documentation reflects the latest staging deployment from this MDR. Production status on mainline is, but staging deployment is currently overriding it"
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

                    updated_mdr = list()

                    log("INFO", "Doing a safety patching to avoid edge cases")
                    RECONCILED_INDEX["objects"]["mdr"][mdr] = patch.tide_1_patch(STG_INDEX[mdr], "mdr")
        
        log("SUCCESS", "Finalized Staging Reconciliation Routine")
        log("INFO", "Updated MDRs from Production Index with Staging Data", str(len(updated_mdr)))
        log("INFO", "New MDR added from Staging Data ", str(len(added_mdr)))
        return RECONCILED_INDEX

    @staticmethod
    def compute_chains(tvm_index: dict) -> dict:
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
        if tier == "all":
            return IndexTide.load()["paths"]
        if tier == "core":
            return IndexTide.load()["paths"]["core"]
        if tier == "tide":
            return IndexTide.load()["paths"]["tide"]

                

class SystemLoader:

    @staticmethod
    def _base_configuration(mdr_config:dict[str, Any])->Tuple[dict[str, Any], TideDefinitionsModels.SystemConfigurationModel]:
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
    def crowdstrike(mdr_config:dict[str, Any])->TideModels.MDR.Configurations.Crowdstrike:

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
        exclusions = None
        if mdr_config.get("exclusions"):
            exclusions = []
            for exclusion in mdr_config.pop("exclusions"):
                exclusions.append(DefenderForEndpoint.Exclusion(**exclusion))

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


class TideLoader:

    @staticmethod
    def load_logsources(config:dict)->Sequence[Configurations.Logsource]|None:
        logsources_config = config.get("logsource")
        if not logsources_config:
            return None
        else:
            logsources = [] 
            for logsource in logsources_config:
                logsources.append(Configurations.Logsource(**logsource))
            return logsources

    @staticmethod
    def load_mdr(mdr:dict)->TideModels.MDR:
        mdr = deepcopy(mdr)
        metadata = TideDefinitionsModels.TideObjectMetadata(**mdr.pop("metadata"))
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
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.CROWDSTRIKE])->TideConfigs.Systems.Crowdstrike.Platform: ...
    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.SENTINEL_ONE])->TideConfigs.Systems.SentinelOne.Platform: ...
    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.DEFENDER_FOR_ENDPOINT])->TideConfigs.Systems.DefenderForEndpoint.Platform: ...
    @staticmethod
    def load_platform_config(platform_config:dict, system:DetectionSystems):
        if not platform_config:
            log("FATAL", f"Could not find any platform configuration for platform f{system.name}",
            "Ensure that the platform configuration section is present")
            raise NotImplementedError("Missing Configuration Segment")

        match system:

            case DetectionSystems.DEFENDER_FOR_ENDPOINT:
                return TideConfigs.Systems.DefenderForEndpoint.Platform(**platform_config)

            case DetectionSystems.SENTINEL_ONE:
                return TideConfigs.Systems.SentinelOne.Platform(**platform_config)

            case _:
                return SystemConfig.Platform(**platform_config)
    
    @staticmethod
    def load_modifiers_config(modifiers_config:list[dict])->Sequence[SystemConfig.Modifiers] | list[Never]:
        
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
    class Objects:
        """TIDE Lookups Interface.

        Exposes all the configurations of the instance
        """
        Index = dict(IndexTide.load()["objects"])
        """Index containing model types"""
        tvm = dict(Index["tvm"])
        """Threat Vector Models Data Index"""
        dom = dict(Index["dom"])
        """Detection Objective Models Data Index"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Models Data Index"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rules Data Index"""
        # We need to do a deepcopy to ensure that loading steps aren't modifying the original data
        MDR = {uuid:TideLoader.load_mdr(deepcopy(data)) for (uuid, data) in dict(Index.copy()["mdr"]).items()} 
        """Model Mapped Managed Detection Rules Data Index"""
        bdr = dict(Index["bdr"])
        """Business Detection Rules Data Index"""
        chaining = IndexTide.compute_chains(tvm)
        """Index of all chaining relationships"""
        FlatIndex =  tvm | cdm | mdr | bdr
        """Flat Key Value pair structure of all UUIDs in the index"""
        files = dict(IndexTide.load()["files"])
    @dataclass(frozen=True)
    class Vocabularies:
        """TIDE Schema Interface.

        Exposes the vocabularies used across the instance
        """

        Index = dict(IndexTide.load()["vocabs"])

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
        """TIDE Schema Interface.

        Exposes the different schemas used across the instance
        """

        Index = dict(IndexTide.load()["metaschemas"])
        subschemas = dict(IndexTide.load()["subschemas"])
        definitions = dict(IndexTide.load()["definitions"])
        templates = dict(IndexTide.load()["templates"])
        tvm = dict(Index["tvm"])
        """Threat Vector Model Tide Schema"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Model Tide Schema"""
        dom = dict(Index["dom"])
        """Detection Objective Model Tide Schema"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rule Tide Schema"""
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
            Index = dict(IndexTide.load()["configurations"]["global"])
            objects = Index["objects"]
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
                    objects_docs_folder = Index["objects_docs_folder"]
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
            class Sentinel:
                Index = dict(IndexTide.load()["configurations"]["systems"]["sentinel"])
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                defaults = dict(Index["defaults"])
                lookups = dict(Index["lookups"])

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
            documentation_target = str(Index.get("documentation_target"))
            scope = list(Index["scope"])
            skip_model_keys = list(Index["skip_model_keys"])
            skip_vocabularies = list(Index["skip_model_keys"])
            gitlab = dict(Index.get("gitlab", {}))
            cve = dict(Index["cve"])
            wiki = dict(Index.get("wiki",{}))
            object_names = dict(Index["object_names"])
            titles = dict(Index["titles"])
            icons = dict(Index["icons"])
            objects_docs_folder: Path = Path(
                IndexTide.load()["configurations"]["global"]["paths"]["core"][
                    "objects_docs_folder"
                ]
            )
            objects_docs_folder = (
                Path(str(objects_docs_folder).replace(" ", "-"))
                if documentation_target == "gitlab"
                else objects_docs_folder
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
            status = dict(Index["status"])
            promotion = dict(Index["promotion"])
            default_responders = str(Index["default_responders"])
            proxy = dict(Index["proxy"])
            metadata_lookup = dict(Index["metadata_lookup"])
            debug = dict(Index["debug"])

        @dataclass(frozen=True)
        class Lookups:
            """Lookups feature management"""

            Index = dict(IndexTide.load()["configurations"]["lookups"])
            validation = dict(Index["validation"])

        @dataclass(frozen=True)
        class Logsources:
            """OpenTide instance logsource definition"""
            Index = dict(IndexTide.load()["configurations"]["logsources"])
            logsources = TideLoader.load_logsources(Index)
        """TIDE Configuration Interface.

        Exposes all the configurations of the instance
        """
        Index = dict(IndexTide.load()["configurations"])
        """Contains all configurations"""