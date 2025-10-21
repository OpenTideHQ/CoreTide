import pandas as pd
import os
import git
import sys
from mitrecve import crawler
from typing import Tuple, Literal


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.tide import DataTide, IndexTide
from Engines.modules.deployment import CIEnvironment
from Engines.modules.framework import techniques_resolver
from Engines.modules.documentation import rich_attack_links

CONFIG = DataTide.Configurations
INDEX = DataTide.Index
SKIP_KEYS = DataTide.Configurations.Documentation.skip_model_keys
DOCUMENTATION_TARGET = CIEnvironment()._check_ci_environment()
DEFINITIONS_INDEX = DataTide.TideSchemas.definitions

from Engines.modules.framework import (
    relations_downstream,
    relations_upstream,
    get_type,
    get_vocab_entry,
    vocab_metadata,
    relations_list,
)
from Engines.modules.documentation import (
    get_icon,
    get_vocab_description,
    get_field_title,
    backlink_resolver,
    make_vocab_link,
    GitlabMarkdown,
)
from Engines.modules.models import StatusStrategy
from Engines.modules.logs import log


GET_CVE_DETAILS = CONFIG.Documentation.cve["retrieve_details"]
CVE_DB_LINK = CONFIG.Documentation.cve["default_db_link"]
FOOTER_CAPTION = "Generated from CoreTIDE Indexed Data @ "


def status_enriched(status_name:str)->str:
    statuses = DataTide.Configurations.Deployment.statuses
    for status in statuses:
        if status_name == status.name:
            strategy = status.strategy.name #type: ignore
            description = f">**Status** : `{status_name}` - _{status.description}_"
            description += f"\n>**Strategy** : `{strategy}` - _{StatusStrategy[strategy].value}_"
            return description
    
    log("FATAL",
        "Could not look up requested status in existing statuses",
        f"Requested status : {status_name}",
        f"Available statuses in deployment.toml : {statuses}")
    raise Exception

def actors_doc(actors:list[dict])->str:
    data = []
    sources = {}
    actor_vocab_stages = vocab_metadata("actors", "stages")
    for stage in actor_vocab_stages:
        sources[stage.get("id")] = stage.get("icon") + " " + stage.get("name") #type: ignore

    for actor in actors:
        details = {}
        actor_name:str = actor.get("name", "")
        actor_data:dict = get_vocab_entry("actors", actor_name.split("::")[1]) #type: ignore
        details["Actor"] = actor_data.get("name")
        details["Description"] = str(actor_data.get("description")).replace("\n", "")
        details["Aliases"] = ", ".join(actor_data.get("alias", [])) #type: ignore
        details["Source"] = sources[actor_name.split("::")[0]]
        details["Sighting"] = actor.get("sighting", "No documented sighting").replace("\n", "")
        details["Reference"] = ", ".join(actor.get("references", ["No documented references"]))
        data.append(details)

    return pd.DataFrame(data).to_markdown(index=False)

def attack_techniques(uuid:str) -> str:
    """
    Generate a formatted string of ATT&CK techniques for a given UUID.
    Manages inheritance and technique overwriting.
    Args:
        uuid (str): The unique identifier for which to retrieve ATT&CK techniques.
    Returns:
        str: A formatted string containing ATT&CK techniques with icons and links,
             or an empty string if no techniques are found.
    """
    
    techniques = techniques_resolver(uuid)
    if techniques:
        techniques = rich_attack_links(techniques, output="string")
        return f"{get_icon('att&ck')} **ATT&CK Techniques** :  {techniques}"
    else:
        return ""



def frontmatter_doc(object_name:str)->str:
    """
    Generate YAML frontmatter for wiki pages.
    
    Args:
        wiki_target: Target CI environment platform
        object_name: Page title
    
    Returns:
        YAML frontmatter string or empty string if not applicable
    """
    
    if CIEnvironment()._check_ci_environment() is not CIEnvironment.CIPlatforms.GitlabCI:
        return ""    
    if DataTide.Configurations.Documentation.gitlab.get("uuid_permalinks", False):
        return f"---\ntitle: {object_name}\n---"
    else:
        return ""

def criticality_doc(criticality_data: str) -> str:
    criticality_icon = get_icon("criticality")
    criticality_data_icon = get_icon(criticality_data, vocab="criticality")
    criticality_description = get_vocab_description("criticality", criticality_data)

    criticality_doc_markdown = f"{criticality_icon} **Criticality:{criticality_data}** {criticality_data_icon} : {criticality_description} "

    return criticality_doc_markdown


def metadata_doc(metadata: dict, model_type: str) -> str:
    """
    Generates a standardized metadata markdown format
    """
    metaschema = INDEX["metaschemas"][model_type]["properties"]
    metadata_enriched = dict()
    schema = dict()

    for key, value in metadata.items():
        if key == "tlp":
            continue
        meta_title = get_field_title(key, metaschema)
        if meta_title:
            # Push schema at the end of the line
            if key == "schema":
                schema = {meta_title: value}
            else:
                metadata_enriched[meta_title] = value
        else:
            log("WARNING", f"Missing title in metaschema : {metaschema} for key : {key}")
            metadata_enriched[key] = value
    
    metadata_enriched.update(schema)
    for m in metadata_enriched:
        if type(metadata_enriched[m]) is list:
            metadata_enriched[m] = ", ".join(metadata_enriched[m])
        
    metadata_doc_markdown = " **|** ".join([f"`{m} : {metadata_enriched[m]}`" for m in metadata_enriched])

    return metadata_doc_markdown


def reference_doc(references: dict) -> str:
    if not references:
        return ""

    reference_doc_markdown = str()
    reference_labels = list()
    for scope in references:
        
        if not references[scope]:
            continue
        
        scope_title = get_field_title(
            scope, DEFINITIONS_INDEX["references"]["properties"]
        )

        references_list = [f"[_{k}_] {v}" for k, v in references[scope].items()]
        reference_labels.extend(
            [f"[{k}]: {v}" for k, v in references[scope].items()]
        )

        references_list = "- " + "\n- ".join(references_list)
        reference_doc_markdown += f"\n\n**{scope_title}**\n\n{references_list}"

    reference_labels = "\n".join(reference_labels)
    reference_doc_markdown += "\n\n" + reference_labels
    return reference_doc_markdown


def relations_table(
    id: str, direction: Literal["upstream", "downstream"] = "downstream", raw_data=False
):

    tree = None
    model_type = get_type(id)

    if direction == "downstream":
        tree = relations_downstream(id)
    elif direction == "upstream":
        tree = relations_upstream(id)

    if not tree:
        return ""

    def unfold_trunk(trunk):
        if type(trunk) is dict:
            if trunk:
                branch_data = {}
                for branch in sorted(trunk):
                    branch_type = get_type(branch)
                    if branch_data.get(branch_type):
                        branch_data[branch_type] = (
                            branch_data[branch_type]
                            + "<br>"
                            + (backlink_resolver(branch))
                        )
                    else:
                        branch_data[branch_type] = backlink_resolver(branch)

                    if trunk[branch]:
                        unfold = unfold_trunk(trunk[branch]) or {}
                        branch_data.update(unfold)

                return branch_data

        if type(trunk) is list:
            if trunk:
                branch_data = {}
                branch_data[get_type(trunk[0])] = "<br>".join(
                    [backlink_resolver(b) for b in trunk if b != "Unknown"] #type: ignore
                ) #type: ignore
                return branch_data

    data = []
    if type(tree) is list:
        tree = {id: tree}

    for trunk in sorted(tree):

        trunk_data = unfold_trunk({trunk: tree[trunk]}) or {}  # type: ignore

        if direction == "downstream":

            if model_type == "tvm":
                trunk_data["cdm"] = (
                    None if "cdm" not in trunk_data else trunk_data["cdm"]
                )
                trunk_data["dom"] = (
                    None if "dom" not in trunk_data else trunk_data["dom"]
                )
            if model_type in ["tvm", "dom", "cdm", "bdr"]:
                trunk_data["mdr"] = (
                    None if "mdr" not in trunk_data else trunk_data["mdr"]
                )

        elif direction == "upstream":
            if "bdr" not in trunk_data:
                if model_type in ["mdr", "dom", "cdm"]:
                    trunk_data["tvm"] = (
                        None if "tvm" not in trunk_data else trunk_data["tvm"]
                    )
                if model_type in ["mdr"]:
                    trunk_data["cdm"] = (
                        None if "cdm" not in trunk_data else trunk_data["cdm"]
                    )
                    trunk_data["dom"] = (
                        None if "dom" not in trunk_data else trunk_data["dom"]
                    )

        data.append(trunk_data)

    for col in data:
        if col.get(model_type):
            col.pop(model_type)
    table = pd.DataFrame(data)

    metrics = relations_list(id, mode="count", direction=direction)

    for column in table.columns:
        filler = f"❌ No {CONFIG.Documentation.object_names[column]}"
        table[column] = table[column].fillna(filler)

    def column_rename(col):
        count = f"({metrics.get(col)})" if metrics.get(col, 0) > 1 else ""
        col_title = CONFIG.Documentation.object_names[col.lower()]
        col_name = f"{get_icon(col)} {col_title} {count}"
        return col_name

    new_columns = {old: column_rename(old) for old in table.columns}
    table = table.rename(columns=new_columns)
    table = table.to_markdown(index=False)

    return table


def model_data_table(model_data: dict, id: str) -> Tuple[str, list[str]]:

    metadata_doc = str()
    tag_list = list()
    model_type = get_type(id)
    metaschema = INDEX["metaschemas"][model_type]["properties"]
    for field in model_data:

        if field not in SKIP_KEYS:
            value = model_data[field]
            field_title = get_field_title(field, metaschema)
            field_description = vocab_metadata(field, "description")
            value_doc = ""
            if type(value) is str or (type(value) is list and len(value) == 1):
                if type(value) is list:
                    value = value[0]

                value_title = make_vocab_link(field, value)
                value_description = get_vocab_description(field, value).replace(
                    "\n", " "
                )
                value_doc = f"{value_title} : {value_description}"
                tag_list.append(value)

            elif type(value) == list:

                value_doc = [
                    f"{make_vocab_link(field, key)} : {get_vocab_description(field, key)}"
                    for key in value
                ]
                value_doc = " - " + "\n - ".join(value_doc)
                tag_list.extend(value)

            if field_title and field_description and value_doc:
                metadata_doc += f"#### **{field_title}**"
                metadata_doc += f"\n\n > {field_description}"
                metadata_doc += f"\n\n {value_doc}"
                metadata_doc += "\n\n---\n\n"

    tag_list = [
        x.replace(" &", "").replace("(", "").replace(")", "").replace(" ", "_")
        for x in tag_list
    ]

    return metadata_doc, tag_list


def tlp_doc(tlp_data: str, description: bool = True) -> str:
    tlp_description = ""
    tlp_icon = get_icon("tlp")
    tlp_rating_icon = get_icon(tlp_data, vocab="tlp")
    if description:
        tlp_description = f" : {get_vocab_description('tlp', tlp_data)}"
    tlp_doc_markdown = (
        f"{tlp_icon} **TLP:{tlp_data.upper()}** {tlp_rating_icon}{tlp_description}"
    )

    return tlp_doc_markdown


def classification_doc(classification_data: str) -> str:
    classification_icon = get_icon("classification")
    classification_rating_icon = get_icon(classification_data, vocab="tlp")
    classification_description = get_vocab_description("tlp", classification_data)
    classification_doc_markdown = f"{classification_icon} **TLP:{classification_data.upper()}** {classification_rating_icon} : {classification_description}"

    return classification_doc_markdown


def cve_doc(cve_list: list[str]) -> str:
    broken_cve = list()
    cve_data = str()
    if GET_CVE_DETAILS:
        cve_details_list = list()

        for vuln in cve_list:
            try:
                details = crawler.get_main_page(vuln)
                details = crawler.get_cve_detail(details)[0]

                cve_details = dict()
                cve_details["CVE"] = f"[**{vuln}**]({CVE_DB_LINK}{vuln})"
                cve_details["Release Date"] = f"`{details['RELEASE_DATE']}`"
                cve_details["Description"] = details["DESC"]
                cve_details_list.append(cve_details)

            except Exception as error:
                log("WARNING", "Retrieving CVE details failed", str(error))
                broken_cve.append(vuln)

        if not broken_cve:
            cve_data = pd.DataFrame(cve_details_list).to_markdown(index=False)

    if not GET_CVE_DETAILS or broken_cve:

        cve_doc_list = [
            f"[{vuln}]({CVE_DB_LINK}{vuln})"
            for vuln in cve_list
            if vuln not in broken_cve
        ]

        if broken_cve:
            for broken_vuln in broken_cve:
                cve_doc_list.append(f"[💔 {broken_vuln}]({CVE_DB_LINK}{broken_vuln})")

            cve_error_banner = "⚠️ ERROR : Could not successfully retrieve CVE Details, double check the broken links below to confirm the CVE ID exists."
            if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
                cve_error_banner = GitlabMarkdown.negative_diff(cve_error_banner)
            cve_data = "- " + "\n- ".join(cve_doc_list)
            cve_data = cve_error_banner + "\n\n" + cve_data

        else:
            cve_data = "- " + "\n- ".join(cve_doc_list)

    cve_doc_markdown = f"&nbsp;\n### {get_icon('cve')} Common Vulnerability Enumeration\n\n{cve_data}\n\n&nbsp;"

    return cve_doc_markdown
