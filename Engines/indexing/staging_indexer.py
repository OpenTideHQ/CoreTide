import yaml
import json
from pathlib import Path
import os
import git
import toml
from datetime import datetime
import sys
import traceback

toolchain_start_time = datetime.now()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.deployment import modified_mdr_files, DeploymentStrategy
from Engines.modules.files import resolve_paths

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
TIDE_CONFIG = toml.load(
    open(ROOT / "Configurations/global.toml", encoding="utf-8")
)
PATHS = resolve_paths()
PROJECT_NAME = os.getenv("CI_PROJECT_NAME")
STG_INDEX_PATH = ROOT / TIDE_CONFIG["paths"]["core"]["staging_index_output"]

DEPLOYMENT_PLAN = os.getenv("DEPLOYMENT_PLAN")

SCRIPT_NAME = "MDR Staging Index Updater"
SCRIPT_DESCRIPTION = (
    "Updates the Staging Index maintained in the Wiki with the latest modification"
)

print("\n\n" + SCRIPT_NAME.center(80, "="))
print("\n ⚙️" + SCRIPT_DESCRIPTION + "\n")

log("TITLE", "Staging Index Reconcilier")
log("INFO", "Loads a version of the index which adds data from mdr in staging.")

mdr_to_index = modified_mdr_files(DeploymentStrategy.STAGING)

if len(mdr_to_index) == 0:  # In case of no deployments possible
    try:
        print("🛑 No deployment possible, could not identify MDRs that can be deployed")
        raise Exception("NO_DEPLOYMENT_FOUND")
    except:
        traceback.print_exc()
        sys.exit(19)
else:
    os.environ["DEPLOYMENT"] = str(mdr_to_index)

current_stg_index = dict()

# In this context, the deployment give the absolute path to each modified files
for mdr in mdr_to_index:
    mdr_data = yaml.safe_load(open(mdr, encoding="utf-8"))
    mdr_name = mdr_data.get("name") or mdr_data["title"]
    log("ONGOING", "Updating the staging index", mdr_name)
    
    # TODO Backwards compatible with OpenTIDE 1.0, to deprecate at some point
    uuid = mdr_data.get("uuid") or mdr_data["metadata"]["uuid"]
    current_stg_index[uuid] = mdr_data

if not os.path.exists(STG_INDEX_PATH):
    print("🌟 Could not find a staging index file, will create one")
    with open(STG_INDEX_PATH, "w+") as out:
        json.dump(current_stg_index, out, default=str)

else:
    print("🔔 Found MDR index, extending it with latest values")

    stg_index = json.load(open(Path(STG_INDEX_PATH)))
    stg_index.update(current_stg_index)

    with open(STG_INDEX_PATH, "w+") as out:
        json.dump(stg_index, out, default=str, indent=4)

print("\n" + "Execution Report".center(80, "="))

time_to_execute = datetime.now() - toolchain_start_time
time_to_execute = "%.2f" % time_to_execute.total_seconds()

print("\n⌛ Exported Staging index in {} seconds".format(time_to_execute))
