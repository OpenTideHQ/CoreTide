import json
import git
import sys
import os
from collections import OrderedDict
from pathlib import Path
from urllib.parse import quote

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.tide import DataTide

TIDE_INDEXES_PATH = Path(DataTide.Configurations.Global.Paths.Tide.tide_indexes)
ICONS = DataTide.Configurations.Documentation.icons
WIKI_PATH = (
    str(DataTide.Configurations.Documentation.models_docs_folder)
    .replace("../", "")
    .replace(" ", "-")
)
WIKI_MODEL_FOLDER = DataTide.Configurations.Documentation.object_names
# Extracting the name of the top-level folder containing models documentation
WIKI_MODEL_DOCUMENTATION_FOLDER = DataTide.Configurations.Global.Paths.Core._raw[
    "models_docs_folder"
].split("/")[-2]
DEBUG = DataTide.Configurations.DEBUG


def run():

    log("TITLE", "Generate Vocabularies from Model Data")
    log(
        "INFO",
        "Creates Vocabulary like schema CoreTIDE models, so they can be used within JSON Schema for validation.",
    )

    OBJECT_SCOPE = DataTide.Configurations.Global.objects
    ICONS = DataTide.Configurations.Documentation.icons
    EXPORT_INDENT = 0
    if DEBUG:
        EXPORT_INDENT = 4
    
    try:
        object_index = json.load(open(TIDE_INDEXES_PATH / OBJECTS_INDEX_FILE))
    except:
        object_index = {}

    for object_type in OBJECT_SCOPE:

        index_name = DataTide.Configurations.Documentation.object_names[object_type]
        metadata = {
            "field": object_type,
            "icon": ICONS.get(object_type) or "",
            "name": index_name,
            "description": index_name,
            "object": True,
        }
        entries = {}
        registry = DataTide.Objects.Index[object_type]

        for object in registry:

            object_data = registry[object]

            entry = {}
            entry["name"] = object_data["name"]
            entry["object"] = True  # Allows certain switches when generating json schema
            entry["tlp"] = object_data["metadata"]["tlp"]
            entry["criticality"] = object_data.get("criticality")

            description = str()

            match object_type:
                case "tvm":
                    description = object_data.get("threat", {}).get("description")
                case "dom":
                    description = object_data.get("objective", {}).get("description")
                    entry["criticality"] = object_data.get("objective", {}).get("priority")
                case "cdm":
                    description = object_data.get("detection", {}).get("guidelines")
                case "bdr":
                    description = object_data.get("request", {}).get("description")
                case "mdr":
                    description = object_data.get("description") or ""

            entry["description"] = description

            # Filter out None values
            entry = {k: v for k, v in entry.items() if v is not None}
            # Replace newlines to improve display
            entry = {
                k: v.replace("\n ", " ") if type(v) is str else v
                for k, v in entry.items()
            }

            entries[object] = entry
            
            #Handles inserting signals as part of the object index under the same object type
            if object_type == "dom":
                for signal in object_data["objective"]["signals"]:
                    entry = {}
                    signal_uuid = signal["uuid"]
                    entry["name"] = object_data["name"] + "::" + signal["name"]
                    entry["object"] = True  # Allows certain switches when generating json schema
                    entry["tide.object.parent"] = object
                    entry["tlp"] = object_data["metadata"]["tlp"]
                    entry["criticality"] = signal["severity"]
                    entry["description"] = signal["description"]
                    # Filter out None values
                    entry = {k: v for k, v in entry.items() if v is not None}
                    # Replace newlines to improve display
                    entry = {
                        k: v.replace("\n ", " ") if type(v) is str else v
                        for k, v in entry.items()
                    }

                    entries[signal_uuid] = entry

        object_index[object_type] = {}
        object_index[object_type]["metadata"] = metadata
        object_index[object_type]["entries"] = entries

    with open(TIDE_INDEXES_PATH / OBJECTS_INDEX_FILE, "w+", encoding="utf-8") as export:
        export.write("")
        json.dump(object_index, export, indent=EXPORT_INDENT)

    log("SUCCESS", "Finished indexing all objects as vocabularies")


if __name__ == "__main__":
    run()
