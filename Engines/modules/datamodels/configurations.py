import sys
import git
from dataclasses import dataclass
from typing import Sequence, Optional, Mapping

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

@dataclass
class Configurations:
    """Root configuration class for the TIDE framework."""

    @dataclass
    class LogSources:
        """Configuration specification for log sources and assets in the TIDE framework."""

        @dataclass
        class Asset:
            """Defines a business or technical asset that generates logs."""
            
            name: str
            """Unique identifier for the asset, typically in format 'Organization::AssetName'"""

            description: str
            """Detailed description of what the asset does or represents"""

            criticality: str
            """Business criticality level indicating the asset's importance and potential impact.
            
            Valid values:
            - Crown Jewel: Systems critical to both business operations and security posture
            - High Value: Systems with significant business value and security implications
            - Operational: Systems essential for day-to-day security operations
            - Supporting: Systems that enhance security posture but aren't primary controls
            """

            custom_details: Optional[Mapping[str,str]] = None
            """Additional custom attributes for the asset"""

        @dataclass
        class LogSource:
            """Defines a specific log source that can be queried for detection purposes."""
            
            name: str
            """Name of the log source"""

            description: str
            """Detailed description of the log source and its purpose"""

            system: str
            """The system or platform that generates/collects these logs"""

            assets: Optional[Sequence[str]] = None
            """List of asset names (references) that this log source monitors"""

            tenants: Optional[Sequence[str]] = None
            """Optional list of tenant identifiers for multi-tenant setups"""

            references: Optional[Sequence[str]] = None
            """Optional external references or documentation"""
        
        logsources: Sequence[LogSource]
        """Log sources that collect and provide log data"""

        assets: Optional[Sequence[Asset]] = None
        """List of assets that generate logs in the environment"""
