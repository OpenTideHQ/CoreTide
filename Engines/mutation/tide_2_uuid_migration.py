import git
import os
import re
import sys
import uuid
import json

import yaml

from pathlib import Path

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.files import safe_file_name, resolve_configurations, resolve_paths

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
CONFIGURATIONS = resolve_configurations()
PATHS = resolve_paths()
TIDE_INDEXES_PATH = PATHS["tide_indexes"]
MODELS_TYPES = CONFIGURATIONS["global"]["models"]

MAPPING_FILE = "legacy_uuid_mapping.json"

def id_to_uuid_mapper():

    mapping = dict()
    for model in MODELS_TYPES:
        if model == "mdr":
            continue
        for file in sorted(os.listdir(PATHS[model])):
            if not file.endswith(".yaml") or not file.endswith(".yml"):
                log("INFO", "The file doesn't end with .yaml or .yml, skipping", file)
                continue  

            data = yaml.safe_load(open(PATHS[model] / file, encoding="utf-8"))
            old_id:str = data.get("id")
            if not old_id:
                continue
            if old_id.endswith("0000"):
                continue
            
            new_uuid = str(uuid.uuid4())
            name = data["name"]
            
            log("INFO", f"Processing {old_id} - {name}", new_uuid)
            mapping[old_id] = {"uuid": new_uuid, "name": name}

    export:dict = json.load(open(TIDE_INDEXES_PATH/MAPPING_FILE))
    export.update(mapping)
    json.dump(export, open(TIDE_INDEXES_PATH/MAPPING_FILE, "w"), indent=6)
    log("SUCCESS", "Updated and re-exported mapping")

def schema_update():
    mapping:dict = json.load(open(TIDE_INDEXES_PATH/MAPPING_FILE))

    for model in MODELS_TYPES:
        schema_version = model + "::2.0"

        for file in sorted(os.listdir(PATHS[model])):
            data = yaml.safe_load(open(PATHS[model] / file, encoding="utf-8"))
            if "uuid" in data["metadata"]:
                log("SKIP", "Already Migrated")
                continue
            if model == "mdr":
                new_uuid = data["uuid"]
            elif data.get("id", "").endswith("0000"):
                new_uuid = str(uuid.uuid4())
            else:
                new_uuid = mapping[data["id"]]["uuid"]
            
            # Migrate UUID and add schema under metadata
            raw_content = open(PATHS[model] / file, encoding="utf-8").readlines()
            migrated_content = []
            for line in raw_content:
                if line.startswith("id: "):
                    continue
                elif line.startswith("uuid: "):
                    continue
                elif line.startswith("metadata:"):
                    migrated_content.append(line)
                    migrated_content.append(f"  uuid: {new_uuid}\n")
                    migrated_content.append(f"  schema: {schema_version}\n")

                elif re.search(r'(TVM|CDM|BDR)[0-9]{4}', line):
                    
                
                    match = "".join(re.findall(r'(TVM|CDM|BDR)([0-9]{4})', line)[0])
                    replacement = mapping[match]['uuid']
                    if "#" not in line:
                        replacement += " #" + mapping[match]['name']
                    log("ONGOING", "Replacing old ids", file, f"match: {match} - replacement, {mapping[match]['uuid']}")
                    line = line.replace(match, replacement)
                    migrated_content.append(line)
                elif line.startswith("  splunk:"):
                    migrated_content.append(line)
                    migrated_content.append("    schema: splunk::2.0\n")

                elif line.startswith("  sentinel:"):
                    migrated_content.append(line)
                    migrated_content.append("    schema: sentinel::2.0\n")

                elif line.startswith("  carbon_black_cloud:"):
                    migrated_content.append(line)
                    migrated_content.append("    schema: carbon_black_cloud::2.0\n")

                else:
                    migrated_content.append(line)

            with open(PATHS[model] / file, "w+", encoding="utf-8") as export:
                export.write("".join(migrated_content))
            if data.get("id"):
                os.rename(PATHS[model] / file, PATHS[model] / (data["name"] + ".yaml"))
    return

def run():
    id_to_uuid_mapper()
    schema_update()

if __name__ == "__main__":
    run()
