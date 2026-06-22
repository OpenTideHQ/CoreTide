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
from Engines.modules.datamodels.configurations import Configurations

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
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

