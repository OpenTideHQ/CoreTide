import os
import git
import json
import sys
import git
import uuid
from pprint import pprint

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.files import resolve_paths
from Engines.modules.logs import log

class Tide2Patching:
    """
    Class encapsulating all relevant behaviours to patch Tide 1 objects into Tide 2
    """
    def __init__(self):
        TIDE_PATHS, CORE_PATHS = resolve_paths(separate=True)
        PATHS = TIDE_PATHS | CORE_PATHS
        TIDE_INDEXES_PATH = PATHS["tide_indexes"]
        try:
            self.LEGACY_UUID_MAPPING = json.load(open(TIDE_INDEXES_PATH / "legacy_uuid_mapping.json"))
            log("SUCCESS", "Found a legacy ID to UUID Mapping")
        except:
            log("SKIP", "Did not find a legacy id to uuid mapping")
            self.LEGACY_UUID_MAPPING = None
            pass

    def tide_1_patch(self, object:dict, object_type:str)->dict:
        """
        Dynamic Micro-Patching on the fly object in staging with new UUIDs to pass validation.
        Once merged to main they will be migrated definitely.
        TODO - Remove before public release, as only concerns existing repositories
        """
        LEGACY_UUID_MAPPING = self.LEGACY_UUID_MAPPING
        
        if os.getenv("CI_COMMIT_REF_NAME") == "main":
            if os.getenv("DEPLOYMENT_PLAN") not in ["PRODUCTION", "STAGING"]:
                if object_type != "mdr": # Allowing this option for Staging MDR documentation patching
                    log("SKIP", "Not patching for validation, in main", object.get("name", ""))
                    return object

        if object.get("metadata", {}).get("schema"):
            return object

        log("ONGOING", f"Evaluating patching validation requirements for {object['name']}")

        if not object.get("metadata"):
            log("INFO", "Missing metadata section", "Transferring meta section to metadata")
            object["metadata"] = object.pop("meta")

        if not object.get("metadata", {}).get("schema"):
            schema_identifier = object_type.lower() + "::2.0"
            object["metadata"]["schema"] = object_type.lower() + "::2.0"
            log("INFO", "Adding schema identifier", f"{object['name']} => {schema_identifier}")
        
        if not object.get("metadata", {}).get("uuid"):
            if "uuid" in object:
                object["metadata"]["uuid"] = object.pop("uuid")
                log("INFO", f"Relocating UUID in {object['name']} to new location")
            elif "id" in object:
                old_id = object.pop("id")
                if LEGACY_UUID_MAPPING:
                    if old_id in LEGACY_UUID_MAPPING:
                        object["metadata"]["uuid"] = LEGACY_UUID_MAPPING[old_id]["uuid"]
                        log("INFO", f"Adding temporary new UUID to {object['name']}", f"{old_id} => {object['metadata']['uuid']}")

                    else:
                        object["metadata"]["uuid"] = str(uuid.uuid4())
                        log("INFO", f"Adding temporary UUID to {object['name']}", f"{old_id} => {object['metadata']['uuid']}")
                        
                else:
                    object["metadata"]["uuid"] = str(uuid.uuid4())
                    log("INFO", f"Adding temporary UUID to {object['name']}", object["metadata"]["uuid"])

            else:
                object["metadata"]["uuid"] = str(uuid.uuid4())
                log("INFO", f"Adding temporary UUID to {object['name']}", object["metadata"]["uuid"])

        if LEGACY_UUID_MAPPING:
            if old_ids:=object.get("threat", {}).get("actors"):
                updated_ids = []
                for old in old_ids:
                    if old in LEGACY_UUID_MAPPING:
                        new_uuid = LEGACY_UUID_MAPPING[old]["uuid"]
                        updated_ids.append(new_uuid)
                        log("INFO",
                            f"Updated old ids in object {object['name']}",
                            f"field: threat.vectors , {old} => {new_uuid}")
                    else:
                        updated_ids.append(old)
                object["threat"]["actors"] = updated_ids

            if old_ids:=object.get("detection", {}).get("vectors"):
                updated_ids = []
                for old in old_ids:
                    if old in LEGACY_UUID_MAPPING:
                        new_uuid = LEGACY_UUID_MAPPING[old]["uuid"]
                        updated_ids.append(new_uuid)
                        log("INFO",
                            f"Updated old ids in object {object['name']}",
                            f"field: detection.vectors , {old} => {new_uuid}")
                    else:
                        updated_ids.append(old)
                object["detection"]["vectors"] = updated_ids

            if old:=object.get("detection_object"):
                if old in LEGACY_UUID_MAPPING:
                    new_uuid = LEGACY_UUID_MAPPING[old]["uuid"]
                    log("INFO",
                        f"Updated old ids in object {object['name']}",
                        f"field: detection_object , {old} => {new_uuid}")
                    object["detection_object"] = new_uuid

        return object
