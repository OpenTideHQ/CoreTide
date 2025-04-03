import sys
import os
import git
import uuid
from pathlib import Path

import yaml

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.files import safe_file_name, resolve_configurations, resolve_paths

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
CONFIGURATIONS = resolve_configurations()
PATHS = resolve_paths()
MODELS_TYPES = CONFIGURATIONS["global"]["models"]


def run():

    log("TITLE", "File Name Aligner")
    log(
        "INFO",
        "Aligns the file name with the YAML Content and assigns"
        " ID if missing (non-MDR objects only)",
    )

    MODELS_TYPES.remove("mdr")
    for model in MODELS_TYPES:
        for file in sorted(os.listdir(PATHS[model])):
            if not file.endswith(".yaml") or not file.endswith(".yml"):
                log("INFO", "The file doesn't end with .yaml or .yml, skipping", file)
                continue  

            data = yaml.safe_load(open(PATHS[model] / file, encoding="utf-8"))
            model_name = data["name"]
            standard_name = f"{safe_file_name(model_name)}.yaml"

            if file != standard_name:
                log("INFO", "Re-aligning file name with model_data", file)
                # Renaming goes through a temp file to still rename in case-insensitive OSs
                # when the only difference is capitalization
                os.rename(
                    PATHS[model] / file,
                    PATHS[model] / (standard_name + ".tmp"),
                )
                os.rename(
                    PATHS[model] / (standard_name + ".tmp"),
                    PATHS[model] / standard_name,
                )
                log("SUCCESS", f"Alligned file name with model data", standard_name)


        else:
            log("SKIP", "No files to assign ID or fix file names in model type", model)


if __name__ == "__main__":
    run()
