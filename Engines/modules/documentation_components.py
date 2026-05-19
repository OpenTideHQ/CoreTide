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
        # Strip inline comment annotations (e.g. "G0007 #[Mobile] APT28, ...")
        # to obtain the bare vocabulary identifier (e.g. "G0007")
        raw_identifier = actor_name.split("::")[1]
        clean_identifier = raw_identifier.split(" #")[0].strip()
        actor_data = get_vocab_entry("actors", clean_identifier)
        if not isinstance(actor_data, dict):
            log("WARNING",
                f"Could not retrieve actor data for identifier [{clean_identifier}] — skipping actor",
                actor_name)
            continue
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



def frontmatter_doc(object_name:str, object_uuid:str)->str:
    """
    Generate YAML frontmatter for wiki pages.
    
    Args:
        wiki_target: Target CI environment platform
        object_name: Page title
        object_uuid: UUID of the object
    
    Returns:
        YAML frontmatter string or empty string if not applicable
    """
    
    if CIEnvironment()._check_ci_environment() is not CIEnvironment.CIPlatforms.GitlabCI:
        return ""    
    if DataTide.Configurations.Documentation.gitlab.get("uuid_permalinks", False):
        return f"---\ntitle: {get_icon(get_type(object_uuid))} {object_name}\n---"
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

    current_page = "dom" if model_type == "dom" else None

    if direction == "downstream":
        tree = relations_downstream(id)
        print(tree)
    elif direction == "upstream":
        tree = relations_upstream(id)
        print(tree)

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
                            + (backlink_resolver(branch, current_page=current_page))
                        )
                    else:
                        branch_data[branch_type] = backlink_resolver(branch, current_page=current_page)

                    if trunk[branch]:
                        unfold = unfold_trunk(trunk[branch]) or {}
                        branch_data.update(unfold)

                return branch_data

        if type(trunk) is list:
            if trunk:
                branch_data = {}
                branch_data[get_type(trunk[0])] = "<br>".join(
                    [backlink_resolver(b, current_page=current_page) for b in trunk if b != "Unknown"] #type: ignore
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

            if model_type in ["tvm", "dom", "cdm"]:
                trunk_data["mdr"] = (
                    None if "mdr" not in trunk_data else trunk_data["mdr"]
                )

            if model_type == "dom":
                    trunk_data["signal"] = (
                    None if "signal" not in trunk_data else trunk_data["signal"]
                )


        elif direction == "upstream":
            if model_type in ["mdr", "dom", "cdm"]:
                trunk_data["tvm"] = (
                    None if "tvm" not in trunk_data else trunk_data["tvm"]
                )

            if model_type == "signal":
                trunk_data["dom"] = (
                    None if "dom" not in trunk_data else trunk_data["dom"]
                )

            if model_type in ["mdr"]:
                trunk_data["cdm"] = (
                    None if "cdm" not in trunk_data else trunk_data["cdm"]
                )
                trunk_data["dom"] = (
                    None if "dom" not in trunk_data else trunk_data["dom"]
                )
                trunk_data["signal"] = (
                    None if "signal" not in trunk_data else trunk_data["signal"]
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

    # Surface is rendered in its own dedicated Threat Surface section for TVMs
    SURFACE_KEYS = {"surface"}

    metadata_doc = str()
    tag_list = list()
    model_type = get_type(id)
    metaschema = INDEX["metaschemas"][model_type]["properties"]
    for field in model_data:

        if field not in SKIP_KEYS and field not in SURFACE_KEYS:
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


def _surface_matches(tvm_surfaces: list[str], asset_surfaces: list[str]) -> list[str]:
    """Determine which surface entries overlap between a TVM and an asset.
    
    Uses hierarchical prefix matching: 'os::Windows' on an asset matches
    'os::Windows::Credential Management' on a TVM, and vice versa.
    
    Returns the list of matching surface entries from the TVM side.
    """
    matched = []
    for tvm_s in tvm_surfaces:
        for asset_s in asset_surfaces:
            if tvm_s.startswith(asset_s) or asset_s.startswith(tvm_s):
                matched.append(tvm_s)
                break
    return matched


def threat_surface_doc(tvm_surface: list[str]) -> str:
    """Generate a unified Threat Surface documentation section for a TVM.
    
    Renders:
    1. Surface entries with descriptions directly under the heading
    2. Targeted Assets table with inline visibility status
    3. Detection sources detail (log sources / detectors) in a collapsible
       section, only when coverage exists
    
    Args:
        tvm_surface: List of threat surface vocabulary entries from the TVM
        
    Returns:
        Formatted markdown string, or empty string if no surface data
    """
    if not tvm_surface:
        return ""
    
    sections = []
    
    # Surface entries with descriptions — listed directly, no sub-header
    surface_entries = []
    for entry in tvm_surface:
        entry_link = make_vocab_link("surface", entry)
        entry_description = get_vocab_description("surface", entry).replace("\n", " ")
        if entry_description:
            surface_entries.append(f"- {entry_link} — {entry_description}")
        else:
            surface_entries.append(f"- {entry_link}")
    
    surface_list = "\n".join(surface_entries)
    sections.append(surface_list)
    
    # Targeted assets with inline visibility status
    visibility = CONFIG.Visibility
    if visibility and visibility.assets:
        # Build lookup of log sources and detectors per asset
        ls_by_asset: dict[str, list[str]] = {}
        if visibility.logsources:
            for ls in visibility.logsources:
                if ls.assets:
                    for a in ls.assets:
                        ls_by_asset.setdefault(a, []).append(ls.name)
        
        det_by_asset: dict[str, list[str]] = {}
        if visibility.detectors:
            for det in visibility.detectors:
                if det.assets:
                    for a in det.assets:
                        det_by_asset.setdefault(a, []).append(det.name)
        
        asset_rows = []
        matched_asset_names = set()
        covered_assets = set()
        for asset in visibility.assets:
            if not asset.surface:
                continue
            matches = _surface_matches(tvm_surface, list(asset.surface))
            if matches:
                matched_asset_names.add(asset.name)
                has_ls = asset.name in ls_by_asset
                has_det = asset.name in det_by_asset
                if has_ls or has_det:
                    visibility_status = "✅ Covered"
                    covered_assets.add(asset.name)
                else:
                    visibility_status = "⚠️ Blind Spot"
                asset_rows.append({
                    "Asset": asset.name,
                    "Criticality": asset.criticality,
                    "Matching Surface": ", ".join(matches),
                    "Visibility": visibility_status,
                })
        
        if asset_rows:
            table = pd.DataFrame(asset_rows).to_markdown(index=False)
            sections.append(f"### 🎯 Targeted Assets\n\n{table}")
            
            # Detection sources detail — only if any coverage exists
            if covered_assets:
                detail_parts = []
                
                # Log sources for matched assets
                logsource_data = []
                if visibility.logsources:
                    for ls in visibility.logsources:
                        if ls.assets:
                            covered = [a for a in ls.assets if a in matched_asset_names]
                            if covered:
                                logsource_data.append({
                                    "Log Source": ls.name,
                                    "System": ls.system,
                                    "Covered Assets": ", ".join(covered),
                                })
                
                if logsource_data:
                    ls_table = pd.DataFrame(logsource_data).to_markdown(index=False)
                    detail_parts.append(f"#### 📡 Log Sources\n\n{ls_table}")
                
                # Detectors for matched assets
                detector_data = []
                if visibility.detectors:
                    for det in visibility.detectors:
                        if det.assets:
                            covered = [a for a in det.assets if a in matched_asset_names]
                            if covered:
                                detector_data.append({
                                    "Detector": det.name,
                                    "Covered Assets": ", ".join(covered),
                                })
                
                if detector_data:
                    det_table = pd.DataFrame(detector_data).to_markdown(index=False)
                    detail_parts.append(f"#### 🛡️ External Detectors\n\n{det_table}")
                
                if detail_parts:
                    detail_body = "\n\n".join(detail_parts)
                    sections.append(f"### 👁️ Detection Sources\n\n{detail_body}")
        else:
            sections.append("_No assets in the visibility configuration match this threat surface._")
    
    body = "\n\n".join(sections)
    return f"\n\n## 🌐 Threat Surface\n\n{body}\n"
