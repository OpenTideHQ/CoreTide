from random import randrange
from datetime import datetime
import urllib.request
from urllib.error import HTTPError
import sys
import ssl
from splunklib import client
import os
import git
from io import BytesIO
from typing import Literal
from abc import ABC

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, HelperTide
from Engines.modules.deployment import Proxy

class SplunkEngineInit(ABC):
    """
    Utility class used to initialize all constant relevant to operations with Splunk 
    """
    def __init__(self):
        self.DEBUG = DebugEnvironment.ENABLED

        # Writes each parameter successively to saved search to identify blocking element
        self.DEBUG_STEP = True if self.DEBUG else False

        SPLUNK_CONFIG = DataTide.Configurations.Systems.Splunk
        SPLUNK_SETUP = HelperTide.fetch_config_envvar(SPLUNK_CONFIG.setup)
        SPLUNK_SECRETS = HelperTide.fetch_config_envvar(SPLUNK_CONFIG.secrets)
        
        self.DEFAULT_CONFIG = SPLUNK_CONFIG.defaults
        self.DEPLOYER_IDENTIFIER = "splunk"

        self.SSL_ENABLED:bool = SPLUNK_SETUP["ssl"]
        if self.DEBUG:
            self.SSL_ENABLED = DebugEnvironment.SSL_ENABLED
        self.SPLUNK_URL = SPLUNK_SETUP["url"]
        try:
            self.SPLUNK_PORT = int(SPLUNK_SETUP["port"])
        except:
            self.SPLUNK_PORT = SPLUNK_SETUP["port"]
        self.SPLUNK_APP = SPLUNK_SETUP["app"]
        self.SPLUNK_TOKEN = SPLUNK_SECRETS["token"]

        self.PROXY_ENABLED = SPLUNK_SETUP["proxy"]

        self.CORRELATION_SEARCHES = SPLUNK_SETUP["correlation_searches"]
        self.SPLUNK_ACTIONS = SPLUNK_SETUP["actions_enabled"]
        self.STATUS_MODIFIERS = SPLUNK_CONFIG.modifiers
        self.SPLUNK_DEFAULT_ACTIONS = SPLUNK_SETUP.get("default_actions") or []        
        
        self.TIMERANGE_MODE = correct_timerange_mode(SPLUNK_SETUP.get("frequency_scheduling", ""))
        self.SPLUNK_SUBSCHEMA = DataTide.TideSchemas.subschemas["systems"][
            self.DEPLOYER_IDENTIFIER
        ]["properties"]
        
        self.LOOKUPS_METADATA_INDEX = DataTide.Lookups.metadata
        self.LOOKUPS_INDEX = DataTide.Lookups.lookups["splunk"]

        self.ALERT_SEVERITY_MAPPING = {
            "Informational": 2,
            "Low": 3,
            "Medium": 4,
            "High": 5,
            "Critical": 6,
        }

        # Skewing Setup
        SKEWING = SPLUNK_SETUP.get("allow_skew")
        self.SKEWING_VALUE: int | float
        if SKEWING:
            self.SKEWING_VALUE = float(
                SKEWING.replace("%", "e-2")
            )  # Converts skewing into 2 decimal equivalent
        else:
            self.SKEWING_VALUE = 0
        # Optional added offset
        self.OFFSET = int(SPLUNK_SETUP.get("schedule_offset", 0)) 
        log("INFO", "SSL has been set to",
        str(self.SSL_ENABLED),
        "This can be adjusted in splunk.toml with the setup.ssl keyword")

    def configure_proxy(self):
        """Applies the proxy configuration for this system.
        Called before operational methods (deploy/validate) to avoid
        global proxy state conflicts during plugin loading."""
        if self.PROXY_ENABLED:
            Proxy.set_proxy()
        else:
            Proxy.unset_proxy()

def correct_timerange_mode(timerange:str)->Literal["random", "current", "custom"]:
    corrected_timerange:Literal["random", "current", "custom"]
    if timerange not in ["random", "current", "custom"]:
        log("WARNING", "The frequency_scheduling setting was not correct set",
            "hard setting it to current", "Expected values are random, current, or custom")
        corrected_timerange = "current"
    else:
        corrected_timerange = timerange #type: ignore
    return corrected_timerange

def splunk_timerange(time: str, skewing: float | int = 1, offset: int = 0) -> str:
    """
    Converts a Nd, Nh or Nm format into an splunk compatible earliest_at equivalent.
    Optionally supports skewing and offset

    Keyword arguments:
    time -- the original timeformat
    skewing -- [optional] splunk parameter to align with the skewing strategy (technique in
    splunk to evenly distribute scheduled search)
    offset -- [optional] added value to the result
    """
    skewing += 1  # So can multiply
    unit = time[-1]
    count = int(time[:-1])

    if unit == "m":
        count = count
    elif unit == "h":
        count = count * 60
    elif unit == "d":
        count = count * 1440
    else:
        raise Exception(
            "⚠️ [FATAL] Time Unit not supported by splunk earliest at converter (expects m, h or d)"
        )

    converted = offset + round(
        count * skewing
    )  # Implementation of time skewing and offset
    converted = f"-{converted}m@m"

    return converted


def cron_to_timeframe(
    frequency: str,
    mode: Literal["random", "current", "custom"] = "current",
    custom_time=None,
) -> str:

    unit = frequency[-1]
    count = int(frequency[:-1])
    min = hour = str()
    if (
        (unit == "m" and count > 59)
        or (unit == "h" and count > 23)
        or (unit == "d" and count > 30)
    ):
        # Non blocking error, normally validation should have catched it al
        log(
            "WARNING",
            "Time boundaries were bypassed, expected usage 1-59m , 1-23h or 1-30d.",
            "Proceeding, but note that behaviour is not guaranteed",
        )

    if mode == "random":
        min = str(randrange(60))
        hour = str(randrange(24))

    if mode == "current":
        now = datetime.now()
        min = now.strftime("%M")
        hour = now.strftime("%H")

    if mode == "custom":
        if not custom_time:
            raise Exception(
                "☢️ [FATAL] When selecting a custom time, you need to input a time in the correct format : HHhmm."
            )
        else:
            hour, min = custom_time.split("h")

    match unit:
        case "m":
            cron = f"*/{count} * * * *"
        case "h":
            cron = f"{min} */{count} * * *"
        case "d":
            cron = f"{min} {hour} */{count} * *"
        case _:
            raise Exception(
                "⚠️ [FATAL] Time Unit not supported by crontab converter (expects m, h or d)"
            )

    return cron


def custom_request_handler(url, message):
    method = message["method"].lower()
    data = message.get("body", "") if method == "post" else None
    headers = dict(message.get("headers", []))
    req = urllib.request.Request(url, data, headers)
    response = None
    try:
        if os.environ["TIDE_SPLUNK_SSL_ENABLED"]:
            response = urllib.request.urlopen(req)
        else:
            response = urllib.request.urlopen(req, context=ssl._create_unverified_context())
    
    except HTTPError as error:  # type: ignore
        response = error
        #Workaround as the Splunk SDK reuses this object and we can't communicate with kwargs
        if os.getenv("TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS") == "True":
            response.code = 19 #Trick the SDK into not interrupting the return so we can print the details
            pass  # Propagate HTTP errors via the returned response message
        else:
            log("FATAL", f"Received HTTP Error Code {repr(error)}", str(response.read()))

    return {
        "status": response.code,  # type: ignore
        "reason": response.msg,  # type: ignore
        "headers": dict(response.info()),  # type: ignore
        "body": BytesIO(response.read()),  # type: ignore
    }


def connect_splunk(
    host: str,
    port: str | int,
    token: str,
    app: str,
    allow_http_errors:bool=False,
    ssl_enabled:bool=True
) -> client.Service:
    port = int(port)
    

    if allow_http_errors:
        os.environ["TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS"] = "True"
        log("INFO", "HTTP Errors will be returned with error code 19", "Ensure to handle them appropriately")
        
    # Setting this signal over environment variables to workaround how the handler function is passed 
    os.environ["TIDE_SPLUNK_SSL_ENABLED"] = "True"
    
    service = client.connect(
        handler=custom_request_handler,
        host=host,
        port=port,
        token=token,
        autologin=True,
        app=app,
        sharing="app",
    )

    log("SUCCESS", "Successfully connected to Splunk !")

    return service


### CUSTOM FUNCTIONALITIES


def create_query(data: dict) -> str:
    """
    Automatically adds certain lines to the analyst defined SPL
    """

    # Backwards compatible with 1.0 data model
    uuid = data.get("uuid") or data["metadata"]["uuid"]
    mdr_splunk = data["configurations"]["splunk"]
    status = mdr_splunk["status"]
    spl = mdr_splunk["query"].strip()

    macro = f'| eval MDR_UUID="{uuid}", MDR_status="{status}" \n|`soc_macro_auto_mdr_mapping(MDR_UUID)`'

    return spl + "\n" + macro
