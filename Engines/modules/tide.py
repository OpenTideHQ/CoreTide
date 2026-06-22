# Engines/modules/tide.py — backward compatibility shim
from Engines.modules.registry import OpenTide, DataTide
from Engines.modules.index import IndexManager, IndexTide
from Engines.modules.environment import HelperTide, debug_enabled
from Engines.modules.enums import DetectionPlatforms, DetectionSystems
from Engines.modules.loaders.object_loader import ObjectLoader, TideLoader

__all__ = [
    "OpenTide",
    "DataTide",
    "IndexManager",
    "IndexTide",
    "HelperTide",
    "debug_enabled",
    "DetectionPlatforms",
    "DetectionSystems",
    "ObjectLoader",
    "TideLoader",
]
