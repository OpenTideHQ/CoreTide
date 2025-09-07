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
    keep_active_mdr
)
from Engines.modules.documentation import (
    object_value_doc,
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

DOCUMENTATION_TARGET = DataTide.Configurations.Documentation.documentation_target
COVER_PAGES_ENABLED = DataTide.Configurations.Documentation.gitlab.get("object_cover_pages", False)

# For testing purposes, enabling this script to execute
if DebugEnvironment.ENABLED:
    DOCUMENTATION_TARGET = "gitlab"
    COVER_PAGES_ENABLED = True

OBJECTS_INDEX = DataTide.Objects.Index
METASCHEMAS_INDEX = DataTide.TideSchemas.Index
ICONS = DataTide.Configurations.Documentation.icons

PATHS_CONFIG = DataTide.Configurations.Global.Paths.Index

OBJECTS_DOCS_PATH = Path(str(DataTide.Configurations.Global.Paths.Core.objects_docs_folder).replace(" ", "-"))
OBJECTS_SCOPE = DataTide.Configurations.Documentation.scope
OBJECTS_NAME = DataTide.Configurations.Documentation.object_names

DEPRECATED_STATUSES = ["DISABLED", "REMOVED"]

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
        "targets",
        "platforms",
        "att&ck",
        "actors",
        "cve",
        "impact",
        "leverage",
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
    "bdr": [
        "uuid",
        "name",
        "criticality",
        "tlp",
        "description",
        "modified"
        "implementations",
        "criticality",
        "violation",
        "domains",
    ],
    "mdr": [
        "uuid",
        "name",
        "description",
        "modified",
        "statuses",
        "att&ck",
        "detection_object"    
    ],
}

OBJECTS = NAV_INDEX_FIELDS.keys()


def build_search(object_type, mdr_status:Optional[Literal["ACTIVE", "DEPRECATED"]]=None):

    index = list()
    index_data = OBJECTS_INDEX[object_type]
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
        
        for value in NAV_INDEX_FIELDS[object_type]:

            if value == "name":
                object_backlink = str(backlink_resolver(str(object_value_doc(entry, "uuid"))))
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

            if object_type == "tvm":
                if value == "actors":
                    actors_list = []
                    actors = object_value_doc(entry, "actors") or []
                    for actor in actors:
                        if type(actor) is dict:
                            actor_name = get_vocab_entry("actors", actor.get("name", "").split("::")[1], "name")
                            actor_aliases = get_vocab_entry("actors", actor.get("name", "").split("::")[1], "alias")
                            if actor_aliases:
                                actor_name += ", " + ", ".join(actor_aliases)
                            actors_list.append(actor_name)
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

            elif model_type == "mdr":

                if value == "statuses":

                    # Build a key value dict of systems and their status
                    statuses = dict()
                    configurations = object_value_doc(entry, "configurations") or {}
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

                elif value == "name":
                    mdr_name = object_value_doc(entry, "name")
                    row[value] = mdr_name

                # List
                elif value == "att&ck":
                    object_value = (
                        techniques_resolver(str(object_value_doc(entry, "uuid")))
                        or ""
                    )
                    if object_value:
                        object_value = ", ".join(object_value)
                    row[mdr_attack_technique] = object_value

                elif value == "detection_model":
                    model_value = object_value_doc(entry, "detection_model")
                    if model_value:
                        object_backlink = str(backlink_resolver(str(model_value)))
                        object_backlink = object_backlink.replace("../", "./")
                        row[value] = object_backlink
                    else:
                        row[value] = "❔ No Object Mapped"

                elif value == "detection_model":
                    model_value = object_value_doc(entry, "detection_model")
                    if model_value:
                        object_backlink = str(backlink_resolver(str(model_value)))
                        object_backlink = object_backlink.replace("../", "./")
                        row[value] = object_backlink
                    else:
                        row[value] = "❔ No Object Mapped"

                else:
                    object_value = object_value_doc(
                        entry, value, with_icon=True, max_chars=CHARS_CLIP
                    )
                    row[value] = object_value

            else:
                object_value = object_value_doc(
                    entry, value, with_icon=True, max_chars=CHARS_CLIP
                )

                if type(object_value) == list:
                    if object_value != [None]:
                        object_value = ", ".join(object_value)

                elif type(object_value) == dict:
                    # Mitigation for a possible edge case where list in a dict
                    # can be empty without invalidating validation.
                    # This approach removes dicts containing empty lists but
                    # keeps other dicts that contain values.
                    object_value_iter = object_value.copy()
                    for v in object_value_iter:
                        if object_value_iter[v] == None or object_value_iter[v] == [None]:
                            object_value.pop(v)
                    if object_value != {}:
                        flat_values = [
                            k.capitalize() + " : " + ", ".join(object_value[k])
                            for k in object_value
                        ]
                        object_value = ", ".join(flat_values)
                    else:
                        object_value = ""

                row[value] = str(object_value).replace("\n", " ").replace('"', "")

        index.append(row)

    df = pd.DataFrame(index)

    rename_mapping = {
        c: f"{get_field_title(c, METASCHEMAS_INDEX[object_type]['properties'])}"
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

### {icon} {count} {object_title}
</div>
"""

def construct_navigation_index(object):

    icon = ICONS[object]
    object_title = DataTide.Configurations.Documentation.object_names[object]
    nav_index = str()

    def count_mdr_statuses()->Tuple[int,int]:
        active_mdr = dict()
        deprecated_mdr = dict()
        for mdr in MODELS_INDEX["mdr"]:
            for system in MODELS_INDEX["mdr"][mdr]["configurations"]:
                if MODELS_INDEX["mdr"][mdr]["configurations"][system]["status"] in DEPRECATED_STATUSES:
                    deprecated_mdr[mdr] = MODELS_INDEX["mdr"][mdr]
                else:
                    active_mdr[mdr] = MODELS_INDEX["mdr"][mdr]

        return len(active_mdr), len(deprecated_mdr)


    if model == "mdr":
        active_mdr_count, deprecated_mdr_count = count_mdr_statuses()
        
        active_mdr_title = "Active " + object_title
        active_mdr_summary = CENTER_TEXT.format(icon=icon,
                                                count=active_mdr_count,
                                                object_title=active_mdr_title)
        active_mdr_details = build_search(object, mdr_status="ACTIVE")
        
        deprecated_mdr_title = "Deprecated " + object_title
        deprecated_mdr_summary = CENTER_TEXT.format(icon=icon,
                                                    count=deprecated_mdr_count,
                                                    object_title=deprecated_mdr_title)
        deprecated_mdr_details = build_search(object, mdr_status="DEPRECATED")

        nav_index = active_mdr_summary + "\n\n" + active_mdr_details
        nav_index += "\n\n---\n" + deprecated_mdr_summary + "\n\n" + deprecated_mdr_details

    else:
        count = len(OBJECTS_INDEX[object])
        summary = CENTER_TEXT.format(icon=icon,
                                    count=count,
                                    object_title=object_title)

        details = build_search(object)
        nav_index = summary + "\n\n" + details

    return nav_index


def run():


    log("TITLE", "Wiki Navigation Index")
    log(
        "INFO",
        "Assembles tables exposing CoreTIDE data to make the dataset easier to navigate",
    )

    if DOCUMENTATION_TARGET not in [CIEnvironment.CIPlatforms.GitlabCI,
                                    CIEnvironment.CIPlatforms.AzurePipeline] :
        log("SKIP",
            "This is a Gitlab Wiki or Azure Pipeline only feature",
            f"documentation_target is currently set to : {DOCUMENTATION_TARGET}")
        return 

    if not COVER_PAGES_ENABLED:
        log("SKIP",
            "Disabled in configuration",
            "Not generating cover pages as set to false or missing key",
            "You can enable this feature by setting gitlab.object_cover_pages to True in documentation.toml")
        return

    if not os.path.exists(OBJECTS_DOCS_PATH):
        log("ONGOING", "Create wiki and documentation folder")
        OBJECTS_DOCS_PATH.mkdir(parents=True)

    for object in OBJECTS:
        log("ONGOING", "Generating navigation index for object type", object)
        
        nav_index = construct_navigation_index(object)
        navigation_index_path = OBJECTS_DOCS_PATH / (OBJECTS_NAME[object] + ".md")
        navigation_index_path = Path(str(navigation_index_path).replace(" ", "-"))

        with open(navigation_index_path, "w+", encoding="utf-8") as out:
            out.write(nav_index)

    time_to_execute = "%.2f" % (time.time() - start_time)
    print("\n⏱️ Generated navigation index in {} seconds".format(time_to_execute))


if __name__ == "__main__":
    run()
