# Engines/modules/splunk.py — backward compatibility shim
from Engines.modules.systems.splunk import (
    SplunkEngineInit,
    connect_splunk,
    create_query,
    cron_to_timeframe,
    correct_timerange_mode,
    splunk_timerange,
    custom_request_handler,
)

__all__ = [
    "SplunkEngineInit",
    "connect_splunk",
    "create_query",
    "cron_to_timeframe",
    "correct_timerange_mode",
    "splunk_timerange",
    "custom_request_handler",
]
