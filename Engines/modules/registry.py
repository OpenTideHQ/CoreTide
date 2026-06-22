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
from Engines.modules.models import (
    DetectionPlatforms,
    DetectionSystems,
    DetectionRule,
    ConfigurationModels,
    SharedModels,
    SystemConfig,
)
from Engines.modules.environment import debug_enabled
from Engines.modules.index import IndexManager
from Engines.modules.loaders.config_loader import ConfigurationsLoader
from Engines.modules.loaders.object_loader import ObjectLoader
from Engines.modules.platform_config import build_system_config, systems_raw_index


class _OpenTideMeta(type):
    @property
    def Platforms(cls) -> "PlatformsCollection":
        if cls._platforms is None:
            from Engines.modules.platforms import PlatformsCollection

            cls._platforms = PlatformsCollection()
        return cls._platforms


class OpenTide(metaclass=_OpenTideMeta):
    """Unified programmatic interface to the OpenTide instance."""

    _platforms = None

    Index = IndexManager.load()

    _objects = dict(IndexManager.load()["objects"])
    _rules_raw = dict(_objects["mdr"])
    Rules = {
        uuid: ObjectLoader.load_rule(deepcopy(data))
        for uuid, data in deepcopy(_rules_raw).items()
    }
    _threats_raw = dict(_objects["tvm"])
    Threats = dict(_threats_raw)
    _objectives_raw = dict(_objects.get("dom", {}))
    Objectives = (
        {
            uuid: ObjectLoader.load_objective(deepcopy(data))
            for uuid, data in deepcopy(_objectives_raw).items()
        }
        if _objectives_raw
        else {}
    )

    @classmethod
    def initialise(cls) -> None:
        """Ensure platform engines and configuration are loaded."""
        _ = cls.Platforms

    @classmethod
    def _systems_raw_index(cls) -> dict:
        return systems_raw_index()

    @classmethod
    def _build_system_config(cls, system: str, raw: dict | None = None):
        return build_system_config(system, raw)

    @dataclass(frozen=True)
    class Models:
        """TIDE Lookups Interface.

        Exposes all the configurations of the instance
        """
        Index = dict(IndexManager.load()["objects"])
        """Index containing model types"""
        tvm = dict(Index["tvm"])
        """Threat Vector Models Data Index"""
        dom = dict(Index.get("dom", {}))
        """Detection Objectives Raw Index"""
        DOM = {uuid:ObjectLoader.load_dom(deepcopy(data)) for (uuid, data) in dict(Index.copy().get("dom", {})).items()} if dom else None
        """Detection Objectives Pre-Loaded Index"""
        signal = dict(Index.get("signal", {}))
        """Detection Objectives Signals Raw Index"""
        Signal = {uuid:ObjectLoader.load_signal(deepcopy(data)) for (uuid, data) in dict(Index.copy().get("signal", {})).items()} if signal else None 
        """Detection Objectives Signals Pre-Loaded Index"""
        cdm = dict(Index["cdm"])
        """Cyber Detection Models Data Index"""
        mdr = dict(Index["mdr"])
        """Managed Detection Rules Data Index"""
        # We need to do a deepcopy to ensure that loading steps aren't modifying the original data
        MDR = {uuid:ObjectLoader.load_mdr(deepcopy(data)) for (uuid, data) in dict(Index.copy()["mdr"]).items()} 
        """Model Mapped Managed Detection Rules Data Index"""
        chaining = IndexManager.compute_chains(tvm)
        """Index of all chaining relationships"""
        FlatIndex =  tvm | dom | signal | cdm | mdr
        """Flat Key Value pair structure of all UUIDs in the index"""
        files = dict(IndexManager.load()["files"])
    
    @dataclass(frozen=True)
    class Vocabularies:
        """TIDE Schema Interface.

        Exposes the vocabularies used across the instance
        """

        Index = dict(IndexManager.load()["vocabs"])

    @dataclass(frozen=True)
    class Indexes:
        """
        Interface to compiled indexes
        """
        Index = dict(IndexManager.load()["indexes"])
        revisions = dict(Index.get("revisions", {})) #TODO Loader class for revisions
        objects = dict(Index.get("objects", {}))


    @dataclass(frozen=True)
    class JsonSchemas:
        """
        Interface to all the JSON Schemas generated from TideS
        """

        Index = dict(IndexManager.load()["json_schemas"])
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

        Index = dict(IndexManager.load()["templates"])
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

        Index = dict(IndexManager.load()["metaschemas"])
        subschemas = dict(IndexManager.load()["subschemas"])
        definitions = dict(IndexManager.load()["definitions"])
        templates = dict(IndexManager.load()["templates"])
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
        Index = dict(IndexManager.load()["configurations"])
        DEBUG = debug_enabled()
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

            Index = dict(IndexManager.load()["configurations"]["global"])
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
                Index = IndexManager.return_paths(tier="all")
                _raw = dict(IndexManager.load()["paths"]["raw"])
                """Paths without the proper absolute calculation.
                Only use for specific use cases, for any others prefer
                the other attributes which are precomputed"""

                @dataclass(frozen=True)
                class Core:
                    """Paths to Tide Internals"""

                    Index = IndexManager.return_paths(tier="core")
                    _raw = dict(IndexManager.load()["paths"]["raw"]["core"])
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

                    Index = IndexManager.return_paths(tier="tide")
                    _raw = dict(IndexManager.load()["paths"]["raw"]["tide"])
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
            Index = dict(IndexManager.load()["configurations"]["systems"])

            @dataclass(frozen=True)
            class Splunk:
                Index = dict(IndexManager.load()["configurations"]["systems"]["splunk"])
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                defaults = dict(Index["defaults"])
                modifiers = dict(Index.get("modifiers", {}))

            @dataclass(frozen=True)
            class CarbonBlackCloud:
                Index = dict(
                    IndexManager.load()["configurations"]["systems"]["carbon_black_cloud"]
                )
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                validation = dict(Index["validation"])

            @dataclass
            class Sentinel(ConfigurationModels.Systems.Sentinel):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["sentinel"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.SENTINEL)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionSystems.SENTINEL) if raw.get("tenants") else None

            @dataclass
            class DefenderForEndpoint(ConfigurationModels.Systems.DefenderForEndpoint):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["defender_for_endpoint"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.DEFENDER_FOR_ENDPOINT)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionSystems.DEFENDER_FOR_ENDPOINT) if raw.get("tenants") else None

            @dataclass
            class SentinelOne(ConfigurationModels.Systems.SentinelOne):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["sentinel_one"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.SENTINEL_ONE)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionSystems.SENTINEL_ONE) if raw.get("tenants") else None

            @dataclass
            class Crowdstrike(ConfigurationModels.Systems.Crowdstrike):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["crowdstrike"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.CROWDSTRIKE)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionSystems.CROWDSTRIKE) if raw.get("tenants") else None

            @dataclass
            class HarfangLab(ConfigurationModels.Systems.HarfangLab):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["harfanglab"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionSystems.HARFANGLAB)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionSystems.HARFANGLAB) if raw.get("tenants") else None

        @dataclass(frozen=True)
        class Documentation:
            """Parameters describing how documentation should be generated."""


            Index = dict(IndexManager.load()["configurations"]["documentation"])
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
                IndexManager.load()["configurations"]["global"]["paths"]["core"][
                    "models_docs_folder"
                ]
            )

        @dataclass(frozen=True)
        class Resources:
            """Parameters pointing to External resources used by engines."""
            Index = dict(IndexManager.load()["configurations"]["resources"])
            attack = dict(Index["attack"])
            d3fend = dict(Index["d3fend"])
            engage = dict(Index["engage"])
            nist = dict(Index["nist"])
            misp = dict(Index["misp"])

        @dataclass(frozen=True)
        class Deployment:
            """Generic deployment parameters."""

            Index = dict(IndexManager.load()["configurations"]["deployment"])
            statuses = ConfigurationsLoader.load_statuses(Index["statuses"])
            promotion = dict(Index["promotion"])
            default_responders = str(Index["default_responders"])
            proxy = dict(Index["proxy"])
            debug = dict(Index["debug"])

        @dataclass(frozen=True)
        class Visibility:
            """OpenTide instance visibility configuration including logsources, assets, and detectors"""
            Index = dict(IndexManager.load()["configurations"]["visibility"])
            visibility = ConfigurationsLoader.load_visibility(Index)
            assets = visibility.assets if visibility else None
            detectors = visibility.detectors if visibility else None
            logsources = visibility.logsources if visibility else None

        @dataclass(frozen=True)
        class Schema:
            Index = dict(IndexManager.load()["configurations"].get("schema", {}))

        @dataclass(frozen=True)
        class Sharing:
            Index = dict(IndexManager.load()["configurations"].get("sharing", {}))

        Index = dict(IndexManager.load()["configurations"])


# Canonical names + legacy aliases
OpenTide.MetaSchemas = OpenTide.TideSchemas
OpenTide.Schemas = OpenTide.JsonSchemas
OpenTide.Configuration = OpenTide.Configurations

DataTide = OpenTide