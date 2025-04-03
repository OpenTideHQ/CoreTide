### Keeping as manual for now as non-urgent and low volume
import os
import git
import sys
import toml
from pathlib import Path

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.files import resolve_paths

removal = """
#validation:
  #prerequisites: |
    #Type Here
  #commands:
    #-
"""

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

PATHS = resolve_paths()
CDM_FOLDER = PATHS["cdm"]


def run():

    log("TITLE", "CDM Validation Block Removal")
    log("INFO", "Remove unused validation block from CDM")

    for file in os.listdir(CDM_FOLDER):
        if not file.endswith(".yaml"):
            if not file.endswith(".yml"):
              log("INFO", "The file doesn't end with .yaml or .yml, skipping", file)
              continue  

        file_path = CDM_FOLDER / file
        file_content = open(file_path, "r", encoding="utf-8").read()

        if removal in file_content:
            print(f"Removing legacy validation template from {file}")
            file_content = file_content.replace(removal, "")
            with open(file_path, "w", encoding="utf-8") as out:
                out.write(file_content)


if __name__ == "__main__":
    run()
