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
from Engines.modules.loaders.system_loader import PlatformConfigLoader
class ObjectLoader:

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
        configurations by delegating to the PlatformConfigLoader helpers.

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
            configurations.sentinel = PlatformConfigLoader.sentinel(system_configurations.pop("sentinel"))
        if system_configurations.get("defender_for_endpoint"):
            configurations.defender_for_endpoint = PlatformConfigLoader.defender_for_endpoint(system_configurations.pop("defender_for_endpoint"))
        if system_configurations.get("sentinel_one"):
            configurations.sentinel_one = PlatformConfigLoader.sentinel_one(system_configurations.pop("sentinel_one"))
        if system_configurations.get("crowdstrike"):
            configurations.crowdstrike = PlatformConfigLoader.crowdstrike(system_configurations.pop("crowdstrike"))
        if system_configurations.get("harfanglab"):
            configurations.harfanglab = PlatformConfigLoader.harfanglab(system_configurations.pop("harfanglab"))

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
    @overload
    @staticmethod
    def load_platform_config(platform_config:dict, system:Literal[DetectionSystems.HARFANGLAB])->TideConfigs.Systems.HarfangLab.Platform: ...
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

            case DetectionSystems.HARFANGLAB:
                return TideConfigs.Systems.HarfangLab.Platform(**platform_config)

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

                case DetectionSystems.HARFANGLAB:
                    setup = TideConfigs.Systems.HarfangLab.Tenant.Setup(**setup_with_secrets)

                case _:
                    raise NotImplementedError(f"Platform {platform.name} is not recognized")

            tenants.append(SystemConfig.Tenant(**tenant,
                                               setup=setup,
                                               parameters=parameters)) #type: ignore

        return tenants


# Legacy aliases
TideLoader = ObjectLoader
ObjectLoader.load_rule = staticmethod(ObjectLoader.load_mdr)  # type: ignore[method-assign]
ObjectLoader.load_objective = staticmethod(ObjectLoader.load_dom)  # type: ignore[method-assign]
