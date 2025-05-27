import os
import git
from pathlib import Path
import sys
import shutil
import time

start_time = time.time()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))
from Engines.modules.framework import (
    get_type,
    childs,
    parents,
    techniques_resolver,
    get_vocab_entry,
)
from Engines.modules.documentation import (
    get_icon,
    rich_attack_links,
    GitlabMarkdown,
    sanitize_hover,
    FOLD,
)
from Engines.modules.documentation_components import (
    criticality_doc,
    classification_doc,
    metadata_doc,
    reference_doc,
    tlp_doc,
    relations_table,
    cve_doc,
    actors_doc,
    object_data_table,
)
from Engines.modules.files import safe_file_name
from Engines.modules.graphs import relationships_graph, chaining_graph
from Engines.modules.tide import DataTide
from Engines.modules.logs import log
from Engines.modules.deployment import Proxy
from Engines.templates.objects import OBJECT_DOC_TEMPLATE

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
OBJECTS_DOCS_PATH = Path(DataTide.Configurations.Global.Paths.Core.objects_docs_folder)
OBJECTS_SCOPE = DataTide.Configurations.Documentation.scope

DOCUMENTATION_TARGET = DataTide.Configurations.Documentation.documentation_target
if DOCUMENTATION_TARGET == "gitlab":
    UUID_PERMALINKS = DataTide.Configurations.Documentation.gitlab.get("uuid_permalinks", False)
else:
    UUID_PERMALINKS = False

OBJECTS_INDEX = DataTide.Objects.Index
OBJECTS_NAME = DataTide.Configurations.Documentation.object_names

if DataTide.Configurations.Documentation.cve.get("proxy"):
    Proxy.set_proxy()
else:
    Proxy.unset_proxy()


def documentation(object):

    object_uuid = object.get("metadata", {}).get("uuid")
    object_type = get_type(object_uuid)
    title = f"{get_icon(object_type)} {object['name']}"
    frontmatter = ""
    
    if DOCUMENTATION_TARGET == "gitlab":
        if UUID_PERMALINKS:
            frontmatter = f"---\ntitle: {title}\n---"            
        title = ""
    elif DOCUMENTATION_TARGET == "generic":
        title = "# " + title
        
    object_datafield = DataTide.Configurations.Global.data_fields[object_type]
    criticality = criticality_doc(object["criticality"])
    metadata = object.get("metadata") or object.get("meta") or {}
    metadata = {k: v for k, v in metadata.items() if k != "tlp"}
    metadata = metadata_doc(metadata, object_type="tvm")

    expand_header = ""
    expand_description = ""
    expand_graphs = ""

    actors_sightings = ""

    if DOCUMENTATION_TARGET == "gitlab":
        title = ""

    references = object.get("references")
    
    if references:
        # To deprecate once everything is migrated to new reference system
        if type(references) is list:
            references = "- " + "\n- ".join(references)
        elif type(references) is dict:
            references = reference_doc(references)
        references = "### 🔗 References\n\n" + references

    else:
        references = ""

    description = object[object_datafield].get("description") or object[
        object_datafield
    ].get("guidelines")
    description = description.replace("\n", "\n> ")

    tlp = tlp_doc((object.get("metadata") or object["meta"])["tlp"])
    classification = (object.get("metadata") or object["meta"]).get(
        "classification"
    ) or ""
    if classification:
        classification = classification_doc(classification)

    techniques = techniques_resolver(object_uuid, recursive=False)
    if techniques:
        techniques = rich_attack_links(techniques)
        techniques = f'{get_icon("att&ck")} **ATT&CK Techniques** {techniques}'
    else:
        techniques = ""

    relation_graph = relationships_graph(object_uuid)
    relation_table = ""
    if childs(object_uuid):
        relation_table = "\n\n **Descendants** \n\n" + relations_table(
            object_uuid, direction="downstream"
        )
    if parents(object_uuid):
        relation_table += "\n\n **Ascendants** \n\n"
        relation_table += relations_table(object_uuid, direction="upstream")

    if not relation_graph and not relation_table:
        relation_graph = "🚫 No related OpenTide objects indexed."
        if DOCUMENTATION_TARGET == "gitlab":
            GitlabMarkdown.negative_diff(relation_graph)

    if object_type == "bdr":
        justification = object[object_datafield]["justification"].replace("\n", "\n> ")
        expand_description += f"\n\n## ❓ Justification \n\n > {justification}"

    if object_type == "cdm":
        tuning = object[object_datafield]["tuning"].replace("\n", "\n> ")
        expand_description += f"\n\n## 🔧 Tuning \n\n > {tuning}"

    if object_type == "tvm":

        terrain = object[object_datafield]["terrain"].replace("\n", "\n> ")
        expand_description += f"\n\n## 🖥️ Terrain \n\n > {terrain}"

        if actors:=object[object_datafield].get("actors"):
            # Filter out legacy actor definitions
            if type(actors[0]) is str:
                pass 
            else:
                actors_sightings = "\n\n### 🐲 Actors sightings \n\n"
                actors_sightings += actors_doc(actors)


        cve = object[object_datafield].get("cve")
        if cve:
            cve = cve_doc(cve)
            expand_description += f"\n\n {cve}"

        chain_diagram, chain_table = chaining_graph(object_uuid)
        if chain_diagram and chain_table:
            expand_graphs += "\n\n --- \n\n### ⛓️ Threat Chaining\n\n"
            expand_graphs += chain_diagram + "\n\n"
            expand_graphs += (
                FOLD.format("Expand chaining data", chain_table)
            )

    data_table, tags = object_data_table(object[object_datafield], object_uuid)

    if DOCUMENTATION_TARGET == "gitlab":
        tags = ""
    else:
        tags = "---\n\n#### 🏷️ Tags\n\n"
        tags += "#" + ", #".join(tags)

    doc = OBJECT_DOC_TEMPLATE.format(frontmatter=frontmatter,
                                    title=title,
                                    actors_sightings=actors_sightings,
                                    criticality=criticality,
                                    tlp=tlp,
                                    techniques=techniques,
                                    expand_header=expand_header,
                                    metadata=metadata,
                                    description=description,
                                    expand_description=expand_description,
                                    relation_graph=relation_graph,
                                    relation_table=relation_table,
                                    expand_graphs=expand_graphs,
                                    data_table=data_table,
                                    references=references,
                                    tags=tags)

    return doc


def run():

    log("TITLE", "objects Documentation")
    log(
        "INFO",
        "Generates the documentation for all objects, with hyperlinks in a folder structure",
    )

    # Initialize a counter of created documents
    doc_count = 0

    for object_type in OBJECTS_SCOPE:

        doc_type_path = (
            OBJECTS_DOCS_PATH
            / OBJECTS_NAME[object_type]
        )
        if DOCUMENTATION_TARGET== "gitlab":
            doc_type_path = Path(str(doc_type_path).replace(" ", "-"))

        # Remove everything in the doc folder for the object
        if os.path.exists(doc_type_path):
            shutil.rmtree(doc_type_path)
        log(
            "INFO",
            "📁 Creating documentation folder : {}... ".format(str(doc_type_path)),
        )
        doc_type_path.mkdir(parents=True)

        for object in OBJECTS_INDEX[object_type]:

            # Make a file name based on  data
            object_data:dict = OBJECTS_INDEX[object_type][object]
            object_name = object_data["name"]
            object_uuid = object_data.get("metadata",{}).get("uuid")

            if UUID_PERMALINKS:
                doc_file_name = object_uuid + ".md"
            else:
                doc_name = object_name.replace("_", " ")
                doc_file_name = (
                    f"{get_icon(object_type)} {doc_name.strip()}.md"
                )

            doc_file_name = safe_file_name(doc_file_name)
            doc_path = doc_type_path / doc_file_name

            # Replace whitespace in file name as it becomes a path in the Gitlab OBJECTS_DOCS_PATH
            if DOCUMENTATION_TARGET == "gitlab":
                doc_path = Path(str(doc_path).replace(" ", "-"))

            log("ONGOING",
                f"Generating {object_type.upper()} documentation",
                object_name,
                object_uuid)
            
            document = documentation(object_data)

            with open(doc_path, "w+", encoding="utf-8") as output:
                output.write(document)
                doc_count += 1

    if DOCUMENTATION_TARGET == "generic":
        doc_format_log = "✒️ standard markdown"
    elif DOCUMENTATION_TARGET == "gitlab":
        doc_format_log = "🦊 Gitlab Flavored Markdown"
    else:
        doc_format_log = ""

    time_to_execute = "%.2f" % (time.time() - start_time)

    log("INFO", f"Generated {doc_count} documents in {time_to_execute} seconds")
    log("SUCCESS", "Successfully built CoreTIDE documentation in format", doc_format_log)


if __name__ == "__main__":
    run()
