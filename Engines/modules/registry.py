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
from Engines.modules.datamodels.objects import Objects
from Engines.modules.datamodels.configurations import Configurations

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
from Engines.modules.environment import HelperTide
from Engines.modules.index import IndexTide
from Engines.modules.loaders.config_loader import ConfigurationsLoader
from Engines.modules.loaders.object_loader import TideLoader
from Engines.modules.loaders.system_loader import SystemLoader
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
        dom = dict(Index.get("dom", {}))
        """Detection Objectives Raw Index"""
        DOM = {uuid:TideLoader.load_dom(deepcopy(data)) for (uuid, data) in dict(Index.copy().get("dom", {})).items()} if dom else None
        """Detection Objectives Pre-Loaded Index"""
        signal = dict(Index.get("signal", {}))
        """Detection Objectives Signals Raw Index"""
        Signal = {uuid:TideLoader.load_signal(deepcopy(data)) for (uuid, data) in dict(Index.copy().get("signal", {})).items()} if signal else None 
        """Detection Objectives Signals Pre-Loaded Index"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Models Data Index"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rules Data Index"""
        # We need to do a deepcopy to ensure that loading steps aren't modifying the original data
        MDR = {uuid:TideLoader.load_mdr(deepcopy(data)) for (uuid, data) in dict(Index.copy()["mdr"]).items()} 
        """Model Mapped Managed Detection Rules Data Index"""
        chaining = IndexTide.compute_chains(tvm)
        """Index of all chaining relationships"""
        FlatIndex =  tvm | dom | signal | cdm | mdr
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
        dom = dict(Index.get("dom", {}))
        """Detection Objective Model Tide Schema"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Model Tide Schema"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rule Tide Schema"""
        mdrv2 = dict(Index.get("mdrv2", {}))
        """DEPRECATED - Legacy MDR Version for backward compatibility use cases"""

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
            config_metaschemas = dict(Index.get("config_metaschemas", {}))
            config_json_schemas = dict(Index.get("config_json_schemas", {}))
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
                    dom = Index.get("dom")
                    cdm = Index["cdm"]
                    mdr = Index["mdr"]
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

            @dataclass
            class HarfangLab(TideConfigs.Systems.HarfangLab):
                raw = dict(
                    IndexTide.load()["configurations"]["systems"]["harfanglab"]
                )
                platform = TideLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.HARFANGLAB)
                modifiers = TideLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = TideLoader.load_tenants_config(raw["tenants"], DetectionSystems.HARFANGLAB) if raw.get("tenants") else None

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
            statuses = ConfigurationsLoader.load_statuses(Index["statuses"])
            promotion = dict(Index["promotion"])
            default_responders = str(Index["default_responders"])
            proxy = dict(Index["proxy"])
            debug = dict(Index["debug"])

        @dataclass(frozen=True)
        class Visibility:
            """OpenTide instance visibility configuration including logsources, assets, and detectors"""
            Index = dict(IndexTide.load()["configurations"]["visibility"])
            visibility = ConfigurationsLoader.load_visibility(Index)
            assets = visibility.assets if visibility else None
            detectors = visibility.detectors if visibility else None
            logsources = visibility.logsources if visibility else None

        """TIDE Configuration Interface.

        Exposes all the configurations of the instance
        """
        Index = dict(IndexTide.load()["configurations"])
        """Contains all configurations"""