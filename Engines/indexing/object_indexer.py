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

    MODEL_SCOPE = DataTide.Configurations.Global.objects
    ICONS = DataTide.Configurations.Documentation.icons
    EXPORT_INDENT = 0
    if DEBUG:
        EXPORT_INDENT = 4
    
    model_index = json.load(open(TIDE_INDEXES_PATH / "models.json"))

    for model_type in MODEL_SCOPE:

        index_name = DataTide.Configurations.Documentation.object_names[model_type]
        metadata = {
            "field": model_type,
            "icon": ICONS[model_type],
            "name": index_name,
            "description": index_name,
            "model": True,
        }
        entries = {}
        registry = DataTide.Objects.Index[model_type]

        for model in registry:

            model_data = registry[model]

            entry = {}
            entry["name"] = model_data["name"]
            entry["model"] = True  # Allows certain switches when generating json schema
            entry["tlp"] = model_data["metadata"]["tlp"]
            entry["criticality"] = model_data.get("criticality")
            entry["aliases"] = model_data.get("actor", {}).get("aliases")

            description = str()

            match model_type:
                case "tvm":
                    description = model_data.get("threat", {}).get("description")
                case "cdm":
                    description = model_data.get("detection", {}).get("guidelines")
                case "bdr":
                    description = model_data.get("request", {}).get("description")
                case "mdr":
                    description = model_data.get("description") or ""

            entry["description"] = description

            # Filter out None values
            entry = {k: v for k, v in entry.items() if v is not None}
            # Replace newlines to improve display
            entry = {
                k: v.replace("\n ", " ") if type(v) is str else v
                for k, v in entry.items()
            }

            entries[model] = entry

        model_index[model_type] = {}
        model_index[model_type]["metadata"] = metadata
        model_index[model_type]["entries"] = entries

    with open(TIDE_INDEXES_PATH / "models.json", "w+", encoding="utf-8") as export:
        export.write("")
        json.dump(model_index, export, indent=EXPORT_INDENT)

    log("SUCCESS", "Finished indexing all models as vocabularies")


if __name__ == "__main__":
    run()
