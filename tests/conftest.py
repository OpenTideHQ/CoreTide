"""Pytest configuration for CoreTIDE test suite."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import git
import pytest

# Add project root to Python path
project_root = Path(git.Repo(".", search_parent_directories=True).working_dir)
sys.path.insert(0, str(project_root))


# Mock HelperTide for environment variable resolution
class MockHelperTide:
    """Mock HelperTide for tests that need environment variable resolution."""
    
    @staticmethod
    def is_debug():
        return True
    
    @staticmethod
    def fetch_config_envvar(config_secrets):
        """Resolve $-prefixed environment variables from os.environ."""
        for key in list(config_secrets.keys()):
            if isinstance(config_secrets[key], str) and config_secrets[key].startswith('$'):
                env_var_name = config_secrets[key][1:]
                if env_var_name in os.environ:
                    config_secrets[key] = os.environ[env_var_name]
        return config_secrets


# Setup mocks before importing modules that depend on tide
# This prevents the DataTide class from trying to load the index at import time
mock_tide = MagicMock()
mock_tide.HelperTide = MockHelperTide
mock_tide.DataTide = MagicMock()
sys.modules['Engines.modules.tide'] = mock_tide

# Mock the logs module
mock_logs = MagicMock()
mock_logs.log = MagicMock()
sys.modules['Engines.modules.logs'] = mock_logs
