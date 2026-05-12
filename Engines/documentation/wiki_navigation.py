import pandas as pd
import os
import git
import time
import sys

from pathlib import Path
from typing import Literal, Optional, Tuple

start_time = time.time()


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.framework import (
    techniques_resolver,
    relations_list,
    get_type,
    get_vocab_entry,
    keep_active_mdr,
)
from Engines.modules.documentation import (
    model_value_doc,
    get_icon,
    get_field_title,
    make_json_table,
    backlink_resolver,
    rich_attack_links,
    DOCUMENTATION_TARGET,
)
from Engines.modules.logs import log
from Engines.modules.tide import DataTide
from Engines.modules.debug import DebugEnvironment
from Engines.modules.deployment import CIEnvironment, DEPRECATED_STATUSES

COVER_PAGES_ENABLED = DataTide.Configurations.Documentation.model_cover_pages

MODELS_INDEX = DataTide.Models.Index
METASCHEMAS_INDEX = DataTide.TideSchemas.Index
ICONS = DataTide.Configurations.Documentation.icons

PATHS_CONFIG = DataTide.Configurations.Global.Paths.Index

MODELS_DOCS_PATH = Path(str(DataTide.Configurations.Global.Paths.Core.models_docs_folder).replace(" ", "-"))
MODELS_SCOPE = DataTide.Configurations.Documentation.scope
MODELS_NAME = DataTide.Configurations.Documentation.object_names

CHARS_CLIP = 150
NAV_INDEX_FIELDS = {
    "tvm": [
        "uuid",
        "name",
        "criticality",
        "tlp",
        "description",
        "modified",
        "implementations",
        "criticality",
        "surface",
        "att&ck",
        "actors",
        "cve",
        "impact",
        "leverage",
    ],
    "dom": [
        "uuid",
        "name",
        "priority",
        "tlp",
        "att&ck",
        "objective",
        "modified",
        "threats",
        "implementations"
    ],
    "cdm": [
        "uuid",
        "name",
        "criticality",
        "tlp",
        "att&ck",
        "guidelines",
        "modified",
        "vectors",
        "implementations",
        "criticality",
        "methods",
        "datasources",
        "collection",
        "artifacts",
    ],
    "mdr": [
        "uuid",
        "name",
        "description",
        "modified",
        "statuses",
        "att&ck",
        "detection_model"    
    ],
}

MODELS = NAV_INDEX_FIELDS.keys()


def build_search(model_type, mdr_status:Optional[Literal["ACTIVE", "DEPRECATED"]]=None):

    index = list()
    index_data = MODELS_INDEX.get(model_type)
    if not index_data:
        return "❌ No objects were indexed"
    
    system_column = "🔧 Detection Systems"
    mdr_statuses = "♻️ Status"
    implementation_column = "🪛 Implementations"
    schema_version = "🏷️ Schema Version"
    mdr_attack_technique = "🗡️ MDR Technique"

    custom_cols = [
        system_column,
        implementation_column,
        schema_version,
        mdr_attack_technique,
        mdr_statuses,
    ]

    for entry in index_data:
        row = dict()
        
        # Logic to retain only MDR in the correct status, to allow breaking
        # the table into two
        if model_type == "mdr":
            active_mdr = True if keep_active_mdr([entry]) != [] else False
            if mdr_status == "ACTIVE":
                if not active_mdr:
                    continue
            
            elif mdr_status == "DEPRECATED":
                if active_mdr:
                    continue
        
        for value in NAV_INDEX_FIELDS[model_type]:


            if value == "name":
                object_backlink = str(backlink_resolver(str(model_value_doc(entry, "uuid"))))
                object_backlink = object_backlink.replace("../", "./")
                row[value] = object_backlink

            elif value == "att&ck":
                techniques = techniques_resolver(entry)
                if techniques:
                    techniques = rich_attack_links(techniques)
                    if model_type == "mdr":
                        value = mdr_attack_technique
                    row[value] = techniques
                else:
                    "❔ No ATT&CK Technique Mapped"

            elif value == "implementations":
                relations = relations_list(entry, mode="count", direction="downstream")
                implementations = []

                if not relations:
                    implementations = ["⛔ None"]

                for k, v in relations.items():
                    title = f"{get_icon(k)} {k.upper()} : {v}"

                    implementations.append(title)

                row[implementation_column] = " // ".join(implementations)

            elif model_type == "tvm" and value == "actors":
                actors_list = []
                actors = model_value_doc(entry, "actors") or []
                for actor in actors:
                    if type(actor) is dict:
                        raw_id = actor.get("name", "").split("::")[1]
                        clean_id = raw_id.split(" #")[0].strip()
                        actor_name = get_vocab_entry("actors", clean_id, "name")
                        actor_aliases = get_vocab_entry("actors", clean_id, "alias")
                        if actor_aliases:
                            actor_aliases = list(set(actor_aliases))
                            actor_name += ", " + ", ".join(actor_aliases)
                        actors_list.append(actor_name)
                
                actors_list = list(set(actors_list))
                actors_list = ", ".join(actors_list)
                row[value] = actors_list

            elif model_type == "cdm" and value == "vectors":
                vectors = model_value_doc(entry, "vectors")
                if vectors:
                    vectors = [vectors] if type(vectors) is str else vectors
                    vectors_links = []
                    for vector in vectors:
                        object_backlink = str(backlink_resolver(str(vector)))
                        object_backlink = object_backlink.replace("../", "./")
                        vectors_links.append(object_backlink)
                    row[value] = ", ".join(vectors_links)
                else:
                    row[value] = "❔ No Object Mapped"

            elif model_type == "dom" and value == "threats":
                vectors = model_value_doc(entry, "threats")
                if vectors:
                    vectors = [vectors] if type(vectors) is str else vectors
                    vectors_links = []
                    for vector in vectors:
                        object_backlink = str(backlink_resolver(str(vector)))
                        object_backlink = object_backlink.replace("../", "./")
                        vectors_links.append(object_backlink)
                    row[value] = ", ".join(vectors_links)
                else:
                    row[value] = "❔ No Object Mapped"

            elif model_type == "dom" and value == "objective":
                objective_section:dict = model_value_doc(entry, "objective") #type: ignore
                objective_description = objective_section.get("description") or ""
                objective_description = objective_description.replace("\n", " ")
                row[value] = objective_description


            elif model_type == "mdr":

                if value == "statuses":

                    # Build a key value dict of systems and their status
                    statuses = dict()
                    configurations = model_value_doc(entry, "configurations") or {}
                    for system in configurations:
                        sys_status = configurations[system]["status"]  # type: ignore
                        if mdr_status == "ACTIVE" and sys_status not in DEPRECATED_STATUSES:
                            statuses[system] = sys_status

                        elif mdr_status == "DEPRECATED" and sys_status in DEPRECATED_STATUSES:
                            statuses[system] = sys_status

                    # Pretty print statuses
                    statuses = ", ".join(
                        [f"{k.capitalize()}:{v}" for k, v in statuses.items()]
                    )
                    row[mdr_statuses] = statuses

                elif value == "att&ck":
                    model_value = (
                        techniques_resolver(str(model_value_doc(entry, "uuid")))
                        or ""
                    )
                    if model_value:
                        model_value = ", ".join(model_value)
                    row[mdr_attack_technique] = model_value

                elif value == "detection_model":
                    model_value = model_value_doc(entry, "detection_model")
                    if model_value:
                        object_backlink = str(backlink_resolver(str(model_value)))
                        object_backlink = object_backlink.replace("../", "./")
                        row[value] = object_backlink
                    else:
                        row[value] = "❔ No Object Mapped"

                else:
                    model_value = model_value_doc(
                        entry, value, with_icon=True, max_chars=CHARS_CLIP
                    )
                    row[value] = str(model_value).replace("\n", " ").replace('"', "")

            else:
                model_value = model_value_doc(
                    entry, value, with_icon=True, max_chars=CHARS_CLIP
                )

                model_value = f"`{model_value}`" if value == "uuid" else model_value

                if type(model_value) == list:
                    if model_value != [None]:
                        model_value = ", ".join(model_value)

                elif type(model_value) == dict:
                    # Mitigation for a possible edge case where list in a dict
                    # can be empty without invalidating validation.
                    # This approach removes dicts containing empty lists but
                    # keeps other dicts that contain values.
                    model_value_iter = model_value.copy()
                    for v in model_value_iter:
                        if model_value_iter[v] == None or model_value_iter[v] == [None]:
                            model_value.pop(v)
                    if model_value != {}:
                        flat_values = [
                            k.capitalize() + " : " + ", ".join(model_value[k])
                            for k in model_value
                        ]
                        model_value = ", ".join(flat_values)
                    else:
                        model_value = ""

                row[value] = str(model_value).replace("\n", " ").replace('"', "")

        index.append(row)

    df = pd.DataFrame(index)

    rename_mapping = {
        c: f"{get_field_title(c, METASCHEMAS_INDEX[model_type]['properties'])}"
        for c in [x for x in df.columns if x not in custom_cols]
    }
    df = df.rename(columns=rename_mapping)

    if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
        nav_index = make_json_table(df)
    else:
        nav_index = df.to_markdown(index=False)

    return nav_index


CENTER_TEXT = """
<div align="center">

### {icon} {count} {model_title}
</div>
"""

def construct_navigation_index(model):

    icon = ICONS[model]
    model_title = DataTide.Configurations.Documentation.object_names[model]
    nav_index = str()


    if model == "mdr":
        total_mdr_count = len(MODELS_INDEX["mdr"])
        active_mdr_count = len(keep_active_mdr(MODELS_INDEX["mdr"]))
        deprecated_mdr_count = total_mdr_count - active_mdr_count
        
        active_mdr_title = "Active " + model_title
        active_mdr_summary = CENTER_TEXT.format(icon=icon,
                                                count=active_mdr_count,
                                                model_title=active_mdr_title)
        active_mdr_details = build_search(model, mdr_status="ACTIVE")
        
        deprecated_mdr_title = "Deprecated " + model_title
        deprecated_mdr_summary = CENTER_TEXT.format(icon=icon,
                                                    count=deprecated_mdr_count,
                                                    model_title=deprecated_mdr_title)
        deprecated_mdr_details = build_search(model, mdr_status="DEPRECATED")

        nav_index = active_mdr_summary + "\n\n" + active_mdr_details
        nav_index += "\n\n---\n" + deprecated_mdr_summary + "\n\n" + deprecated_mdr_details

    else:
        count = len(MODELS_INDEX.get(model, []))
        summary = CENTER_TEXT.format(icon=icon,
                                    count=count,
                                    model_title=model_title)

        details = build_search(model)
        nav_index = summary + "\n\n" + details

    return nav_index


def run():


    log("TITLE", "Wiki Navigation Index")
    log(
        "INFO",
        "Assembles tables exposing CoreTIDE data to make the dataset easier to navigate",
    )

    if not COVER_PAGES_ENABLED:
        log("SKIP",
            "Disabled in configuration",
            "Not generating cover pages as set to false or missing key",
            "You can enable this feature by setting model_cover_pages to True in documentation.toml")
        return

    if not os.path.exists(MODELS_DOCS_PATH):
        log("ONGOING", "Create wiki and documentation folder")
        MODELS_DOCS_PATH.mkdir(parents=True)

    for model in MODELS:
        log("ONGOING", "Generating navigation index for model type", model)
        
        nav_index = construct_navigation_index(model)
        navigation_index_path = MODELS_DOCS_PATH / (MODELS_NAME[model] + ".md")
        navigation_index_path = Path(str(navigation_index_path).replace(" ", "-"))

        with open(navigation_index_path, "w+", encoding="utf-8") as out:
            out.write(nav_index)

    time_to_execute = "%.2f" % (time.time() - start_time)
    print("\n⏱️ Generated navigation index in {} seconds".format(time_to_execute))


if __name__ == "__main__":
    run()
