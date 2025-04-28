import os
import git
import sys
from datetime import datetime
from pathlib import Path


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log, ANSI, coretide_intro
from Engines.validation import (
    tide_schema,
    id_uniqueness,
    uuid_v4,
    cve,
)
from Engines.modules.deployment import CIEnvironment

print(coretide_intro())

quickstream = rf"""
{ANSI.Colors.ORANGE}  
  ____  __  _____________ _______________  _______   __  ___  
 / __ \/ / / /  _/ ___/ //_/ __/_  __/ _ \/ __/ _ | /  |/  /  
/ /_/ / /_/ // // /__/ ,< _\ \  / / / , _/ _// __ |/ /|_/ /   
\___\_\____/___/\___/_/|_/___/ /_/ /_/|_/___/_/ |_/_/  /_/    
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}CoreTIDE Object Data Validation Orchestration

{ANSI.Formatting.STOP}
"""

print(quickstream)

os.environ["VALIDATION_ERROR_RAISED"] = ""
os.environ["VALIDATION_WARNING_RAISED"] = ""

id_uniqueness.run()
uuid_v4.run()
tide_schema.run()
#cve.run()


if os.environ.get("VALIDATION_ERROR_RAISED"):
    log(
        "WARNING",
        "Some validation scripts failed.",
        advice="Review the error logs to discover the problem",
    )
    raise Exception("Validation Failed")

if os.environ.get("VALIDATION_WARNING_RAISED"):
    environment = CIEnvironment().environment
    log("WARNING", "Passed validation, but with some warning", 
                    "Review the warning logs to discover the problem")


    # We only exit with a specific error code for Gitlab CI
    # as it will be caught by the pipeline and will warn the job
    # that it has failed, but not block the pipeline.
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)
else:
    log("SUCCESS", "All content successfully passed validation")
