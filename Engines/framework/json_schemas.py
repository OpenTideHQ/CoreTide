import yaml
import os
import git
import json
from pathlib import Path
import sys

from typing import Literal, Tuple
from io import StringIO

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.framework import get_vocab_entry, get_type
from Engines.modules.documentation import get_icon
from Engines.modules.logs import log
from Engines.modules.tide import DataTide
from Engines.modules.models import StatusStrategy
from Engines.modules.files import resolve_paths
from Engines.modules.deployment import enabled_systems

GLOBAL_CONFIG = DataTide.Configurations.Global

VOCAB_INDEX = DataTide.Vocabularies.Index
CONFIG_INDEX = DataTide.Configurations.Index
PATHS = resolve_paths()

# Configuration settings fetching routine
METASCHEMAS_FOLDER = Path(PATHS["metaschemas"])
VOCABS_FOLDER = Path(PATHS["vocabularies"])
JSON_SCHEMA_FOLDER = Path(PATHS["json_schemas"])
ICONS = DataTide.Configurations.Documentation.icons
TIDE_MODELS = DataTide.Configurations.Global.objects
SUBSCHEMAS_PATH = Path(PATHS["subschemas"])
RECOMPOSITION = GLOBAL_CONFIG.recomposition

STAGE_DESCRIPTION_LIMIT = 300


DROPDOWN_TEMPLATE = """
### {icon} {name}

{id_icon} **Identifier** : `{identifier}`

_Vocabulary_ : `{source_vocab}`

{criticality} {tlp}

{stage}

{link}

---

{description}
"""

FOLDABLE = """
<details><summary>{}</summary>

{}

</details>
""".strip()
    
class FetchEnums:
    """Utility class for fetching configuration data and formatting it for JSON schemas.
    
    Provides static methods to retrieve log sources and statuses from TIDE configuration,
    returning them as tuples of (enum_values, markdown_descriptions).
    """

    @staticmethod
    def logsources() -> None | tuple[list[str], list[str]]:
        """Retrieve log source entries with formatted descriptions.
        
        Returns:
            tuple[list[str], list[str]]: (identifiers, markdown_descriptions)
            None: If no log sources are configured.
            
        Example:
            >>> fetch_logsources()
            (
                ['splunk::tenant1::windows_logs', 'splunk::tenant2::windows_logs'],
                ['### Windows Event Logs\n**System**: Splunk\n**Tenant**: tenant1\n...']
            )
        """
        # Early return if no configuration exists
        visibility_data = DataTide.Configurations.Visibility.visibility
        if not visibility_data or not visibility_data.logsources:
            return None 
        
        # Initialize our return lists
        enums = []
        descriptions = []
        
        # Build a mapping of asset names to their details for quick lookup (assets are optional)
        asset_map = {}
        if visibility_data.assets:
            asset_map = {asset.name: asset for asset in visibility_data.assets}
        
        for logsource in visibility_data.logsources:
            # Format base markdown template for this log source
            base_description = f"""### {logsource.name}
**System**: {logsource.system}
**Description**: {logsource.description}

"""
            # Add asset information if available
            if logsource.assets:
                base_description += "### Associated Assets:\n"
                for asset_name in logsource.assets:
                    if asset := asset_map.get(asset_name):
                        base_description += f"""
- **{asset.name}**
- _Criticality_: {asset.criticality}
- _Description_: {asset.description}"""
                        
                        if asset.custom_details:
                            base_description += "\n  - _Custom Details_:"
                            for key, value in asset.custom_details.items():
                                base_description += f"\n    - {key}: {value}"
                        base_description += "\n"
                    else:
                        base_description += f"""
- ⚠️ **{asset_name}**
- _Warning_: Asset not found in configuration
- _Action Required_: Define this asset in the assets section"""
            
            # Generate entries for each tenant if specified, otherwise just one entry
            if tenants := logsource.tenants:
                for tenant in tenants:
                    enum = f"{logsource.system}::{tenant}::{logsource.name}"
                    description = base_description.replace("**System**:", f"**System**: {logsource.system}\n**Tenant**: {tenant}")
                    enums.append(enum)
                    descriptions.append(description)
            else:
                enum = f"{logsource.system}{logsource.name}"
                enums.append(enum)
                descriptions.append(base_description)
        
        return enums, descriptions

    @staticmethod
    def detectors() -> None | tuple[list[str], list[str]]:
        """Retrieve external detector entries with formatted descriptions.
        
        Returns:
            tuple[list[str], list[str]]: (identifiers, markdown_descriptions)
            None: If no detectors are configured.
            
        Example:
            >>> fetch_detectors()
            (
                ['guardduty::unauthorized_access', 'sentinel::suspicious_login'],
                ['### GuardDuty Finding\n**Name**: UnauthorizedAccess...\n']
            )
        """
        # Early return if no configuration exists
        visibility_data = DataTide.Configurations.Visibility.visibility
        if not visibility_data or not visibility_data.detectors:
            return None 
        
        # Initialize our return lists
        enums = []
        descriptions = []
        
        # Build a mapping of asset names to their details for quick lookup (assets are optional)
        asset_map = {}
        if visibility_data.assets:
            asset_map = {asset.name: asset for asset in visibility_data.assets}
        
        for detector in visibility_data.detectors:
            # Format base markdown template for this detector
            base_description = f"""### {detector.name}
**Description**: {detector.description}

"""
            # Add references if available
            if detector.references:
                base_description += "### References:\n"
                for ref in detector.references:
                    base_description += f"- {ref}\n"
                base_description += "\n"
            
            # Add asset information if available
            if detector.assets:
                base_description += "### Monitored Assets:\n"
                for asset_name in detector.assets:
                    if asset := asset_map.get(asset_name):
                        base_description += f"""
- **{asset.name}**
  - _Criticality_: {asset.criticality}
  - _Description_: {asset.description}"""
                        
                        if asset.custom_details:
                            base_description += "\n  - _Custom Details_:"
                            for key, value in asset.custom_details.items():
                                base_description += f"\n    - {key}: {value}"
                        base_description += "\n"
                    else:
                        base_description += f"""
- ⚠️ **{asset_name}**
  - _Warning_: Asset not found in configuration
  - _Action Required_: Define this asset in the assets section
"""
            
            enums.append(detector.name)
            descriptions.append(base_description)
        
        return enums, descriptions

    @staticmethod
    def statuses()->Tuple[list[str], list[str]]:
        status_config = DataTide.Configurations.Deployment.statuses
        statuses = list()
        statuses_descriptions = list()

        for status in status_config:
            statuses.append(status.name)
            strategy = status.strategy.name #type: ignore
            description = f"**Strategy** : `{strategy}` - _{StatusStrategy[strategy].value}_"
            description += f"\n\n{status.description}"
            statuses_descriptions.append(description)

        return statuses, statuses_descriptions

    @staticmethod
    def config_parameter_list(dot_path:str)->list:
        config_index = DataTide.Configurations.Index
        config_path = dot_path.split(".")
        key = config_path[0]
        while key != config_path[-1]:
            
            if key == "tenants":
                print(config_index)
                parameter_list = []
                parameter_key = config_path[config_path.index(key) + 1] 
                for tenant in config_index["tenants"]:
                    tenant_name = tenant.get("name").strip()                
                    if parameter_key in tenant.get("parameters", {}):
                        parameter_list.extend([tenant_name + "::" + item.strip() for item in tenant["parameters"][parameter_key]])
                return parameter_list
            
            if key in config_index:
                config_index = config_index[key]
                key = config_path[config_path.index(key) + 1]
            else:
                raise ValueError(f"Key : {key} could not be found in path {dot_path}")
        
        if type(config_index[key]) is list:
            return config_index[key]
        else:
            raise ValueError(f"Config path {dot_path} must be a valid path to a list parameter")

    @staticmethod
    def config_system_tenants_list(system:str)->Tuple[list[str], list[str]]:
        system_config_index = DataTide.Configurations.Index
        system_config = system_config_index.get("systems", {}).get(system)
        
        if not system_config:
            log("FATAL",
                f"Could not retrieve an available configuration for system {system}",
                f"Indexed Configurations : {str(system_config_index.keys())}")
            raise ValueError(f"Missing configuration for system {system}")
        
        tenants:list[dict] = system_config.get("tenants")
        
        if not tenants:
            log("FATAL",
                "Cannot retrieve a tenants section within the system configuration",
                str(system_config))
            raise ValueError(f"System Configuration for {system} does not contain a tenants section")
        
        tenants_list = list()
        tenants_descriptions = list()
        
        for tenant_config in tenants:
            tenant_name = tenant_config.get("name")
            tenant_description = tenant_config.get("description", "No Description")
            if tenant_name:
                log("INFO",
                    f"Discovered tenant definition {tenant_name}",
                    tenant_config.get("description", ""))
                tenants_descriptions.append(tenant_description)
                tenants_list.append(tenant_name)            
            else:
                log("FATAL",
                "Cannot retrieve a tenant name in tenant definition",
                str(tenant_config))
                raise ValueError(f"Missing name field in tenant definition")

        return tenants_list, tenants_descriptions

def stage_documentation(field: str, stages: str | list) -> str:

    vocab_stages = VOCAB_INDEX[field]["metadata"].get("stages")
    stages = [stages] if type(stages) is str else stages
    if not vocab_stages:
        log("WARNING", f"Could not find stages in vocabulary {field}")
        return ""

    stage_doc = str()

    for stage in stages:
        stage_name = stage_icon = stage_description = ""

        for stage_data in vocab_stages:
            if type(stage_data) is dict:  # Need to interop with older style vocabs
                stage_identifier = stage_data.get("id") or stage_data.get("name")
                if (type(stage_data) is dict) and stage_identifier == stage:
                    stage_name = stage_data.get("name") or ""
                    stage_icon = stage_data.get("icon") or ""
                    stage_description = stage_data["description"]

        if stage_description:
            if not stage_name:
                stage_name = stage
            if len(stage_description) > STAGE_DESCRIPTION_LIMIT:
                stage_description = stage_description[:STAGE_DESCRIPTION_LIMIT] + "..."

            stage_doc += (
                f"\n\n{stage_icon} **{stage_name}** : _{stage_description.strip()}_"
            )

    return stage_doc


def make_markdown_dropdown(name, key, field=""):

    identifier = key.get("id") or name
    name = key.get("name") or name

    if name.islower():
        name.title()

    icon = (
        key.get("icon")
        or VOCAB_INDEX.get(field, {}).get("metadata", {}).get("icon")
        or ICONS.get(field)
        or ""
    )

    source_vocab = VOCAB_INDEX.get(field, {}).get("metadata", {}).get("name")
    link = key.get("link") or ""

    stage = key.get("tide.vocab.stages") or ""
    tlp = key.get("tlp") or ""
    description = key.get("description") or ""

    criticality = ""
    id_icon = ICONS["id"]

    if (get_type(identifier, mute=True) or "") in TIDE_MODELS:
        criticality = key.get("criticality")
        crit_icon = get_icon("criticality")
        if not criticality:
            crit_value_icon = ""
            criticality = "No Criticality Assigned"
        else:
            crit_value_icon = get_vocab_entry("criticality", criticality, "icon")
        criticality = f"{crit_icon} **Criticality** : {crit_value_icon} {criticality}"
    
    if tlp:
        tlp = f" | **{get_icon(tlp, vocab='tlp')}TLP:{tlp.upper()}**"
    if stage:
        stage_description = stage_documentation(field, stage)
        if stage_description:
            stage = "{}".format(stage_description)
        else:
            if type(stage) == list:
                stage = ", ".join(stage)
            stage = "`{}`".format(stage)

    dropdown = DROPDOWN_TEMPLATE.format(
        icon=icon,
        name=name,
        id_icon=id_icon,
        identifier=identifier,
        source_vocab=source_vocab,
        criticality=criticality,
        tlp=tlp,
        stage=stage,
        link=link,
        description=description
    )

    return dropdown


def gen_lib_schema(
    vocab: str,
    stages: str | list | None = None,
    no_wrap: bool = False,
    scoped: bool = False,
) -> list | Tuple[list, list]:
    """
    Returns all the possible values and description for a given field

    Parameters
    ----------
    field : vocab field to return the possible values
    stages : (optional) return only vocabulary entries belonging to the stages defined

    Returns
    -------
    array : returns an array of dictionaries, each one being a possible
            value and accompanying documentation

    """

    # Structure for anyOf
    array = []
    buffer = {}

    # Structure for enum
    log("DEBUG", "Generating schema for vocab", vocab)
    enum = []
    enum_description = []
    enum_helper = []
    # Loops through all vocabulary files
    if vocab not in VOCAB_INDEX:
        log("WARNING", "Could not retrieve vocabulary", vocab)
    else:
        # Edge case for possible model references, there is no description
        # in that case, only the id which is what the user needs to input
        # and the name used as a description.
        # Search Hints only set to False if explicitely done from vocabulary
        search_hints = VOCAB_INDEX[vocab]["metadata"].get("vocab.search_hints", True)
        if (VOCAB_INDEX[vocab]["metadata"].get("model")) or (vocab in TIDE_MODELS):
            for key in VOCAB_INDEX[vocab]["entries"]:
                value = key
                key_data = VOCAB_INDEX[vocab]["entries"][key]
                buffer["const"] = value

                dropdown = make_markdown_dropdown(key, key_data, field=vocab)
                buffer["description"] = key_data.get("description") or ""
                buffer["markdownDescription"] = dropdown

                # Handle if scoped
                if scoped:
                    stage = key_data.get("tide.vocab.stages")
                    if stage:
                        value = stage + "::" + key

                tips = (key_data.get("name") or "") 
                if key_data.get("alias"):
                    tips += ", " + ", ".join(key_data["alias"])
                helper = value + " #" + tips.strip()
                if not no_wrap:
                    if len(helper) > 60:
                        helper = (
                            helper.replace(" and ", " & ")
                            .replace(" without ", " w/o ")
                            .replace(" with ", " w/ ")
                            .replace(" to ", " ")
                            .replace(" of ", " ")
                            .replace(" a ", " ")
                            .replace(" an ", " ")
                            .replace("Use", " ")
                            .replace("used", " ")
                            .replace("Using", " ")
                        )

                # Due to line breaks in vscode
                copied = buffer.copy()
                array.append(copied)


                if value not in enum:
                    enum.append(value)
                    if search_hints:
                        enum_helper.append(helper)
                    enum_description.append(dropdown)
                else:
                    log(
                        "INFO",
                        f"Skipping value from vocab : {vocab} as cannot handle duplicates"
                        "when generating json schema with enums",
                        value,
                    )

        # General case where ID is not required
        else:

            for key in VOCAB_INDEX[vocab]["entries"]:
                key_data = VOCAB_INDEX[vocab]["entries"][key]
                value_stages = key_data.get("tide.vocab.stages", [])

                # Normalizing to arrays so we can compare
                value_stages = (
                    [value_stages] if type(value_stages) is not list else value_stages
                )
                stages = [stages] if (type(stages) is not list and stages) else stages

                # If there are stages passed, we filter out the vocab key stages that
                # do not match
                if stages:
                    value_stages = [s for s in value_stages if s in stages]

                # Addresses the following scenarios (non-scoped keys):
                # 1 : Stages were passed, and they match the ones on the vocab key
                # 1b : The key stages do not match the stages passed
                # 2 : No stages were passed at all, we can proceed
                if ((stages and value_stages) or not stages) and not scoped:
                    value = key
                    buffer["const"] = value

                    dropdown = make_markdown_dropdown(key, key_data, field=vocab)

                    buffer["description"] = key_data.get("description") or ""
                    buffer["markdownDescription"] = dropdown

                    copied = buffer.copy()
                    array.append(copied)

                    if value not in enum:
                        enum.append(value)
                        enum_description.append(dropdown)
                    else:
                        log(
                            "INFO",
                            f"Skipping value from vocab : {vocab} as cannot handle duplicates"
                            "when generating json schema with enums",
                            value,
                        )

                elif scoped and value_stages:
                    for stage in value_stages:
                        value = stage + "::" + key

                        buffer["const"] = value

                        # Allows scoped keys to each have their respective
                        # Stage documentation
                        temp_key_data = key_data.copy()
                        temp_key_data["tide.vocab.stages"] = stage

                        dropdown = make_markdown_dropdown(
                            key, temp_key_data, field=vocab
                        )

                        buffer["description"] = key_data.get("description") or ""
                        buffer["markdownDescription"] = dropdown

                        copied = buffer.copy()
                        array.append(copied)

                        if value not in enum:
                            enum.append(value)
                            enum_description.append(dropdown)
                        else:
                            log(
                                "INFO",
                                f"Skipping value from vocab : {vocab} as cannot handle duplicates"
                                "when generating json schema with enums",
                                value,
                            )

    if not enum:
        enum = [""]
    if enum_helper and search_hints:
        enum.extend(enum_helper)
        enum_description.extend(enum_description)

    return enum, enum_description



def remove_tide_keywords(dictionary:dict)->dict:
    """
    The metaschema is a superset of JSON Schema in YAML, and thus has extra keys
    useful for other purposes (documentation, template etc.). They should
    not break JSON Schemas, but will lead to warnings and is cleaner to remove.
    """
    # dict_foo is used to avoid errors when iterating and modifying the same
    # dictionary
    dict_foo = dictionary.copy()
    for field in dict_foo.keys():
        if field.startswith("tide."):
            del dictionary[field]
        else:
            if type(dict_foo[field]) is dict:
                remove_tide_keywords(dictionary[field])
    return dictionary


def recomposition_handler(entry_point):

    recompositions = CONFIG_INDEX[entry_point]
    subschema_folder = DataTide.Configurations.Global.recomposition[entry_point]
    recomposition = dict()
    # Generate a list of pivots
    for entry in recompositions:
        data = recompositions[entry]
        enabled = False

        if data.get("tide"):
            config_keyword = "tide"
        else:
            config_keyword = "platform"

        if data[config_keyword]["enabled"] == True:
            # recomp_entry = dict()
            recomp_identifier = entry
            recomposition[recomp_identifier] = dict()
            recomposition[recomp_identifier]["title"] = data[config_keyword]["name"]
            recomposition[recomp_identifier]["description"] = data[config_keyword][
                "description"
            ]
            recomposition[recomp_identifier]["type"] = "object"

            recomp_source = data[config_keyword]["subschema"] + ".yaml"
            recomp_source_path = SUBSCHEMAS_PATH / subschema_folder / recomp_source
            recomp_data = yaml.safe_load(open(recomp_source_path, encoding="utf-8"))
            recomposition[recomp_identifier].update(recomp_data)

    return recomposition


def gen_json_schema(dictionary):
    """
    Fills in all coretide defined fields by calling gen_lib_schema for
    each field identified recursively by the coretide tag. It performs
    recursive exploration by calling itself if the key is iself a dict.
    ----------
    dictionary : Nested dictionary to search into

    Returns
    -------
    dictionary : Iteration of the dictionary where the explored depths
                 has been dynamically mapped with coretide keys.

    """
    dict_foo = dictionary.copy()
    icon = ""
    for field in dict_foo.keys():
        query = field
        # checks if the key is a dict
        if type(dict_foo[field]) == dict:

            if "tide.meta.definition" in dict_foo[field].keys():
                if (metadef := dict_foo[field]["tide.meta.definition"]) is True:
                    temp = DataTide.TideSchemas.definitions[field]
                else:
                    temp = DataTide.TideSchemas.definitions[metadef]

                if deprecation_message := dict_foo[field].get("tide.meta.deprecation"):
                    temp["title"] = "⚠️ DEPRECATION WARNING"
                    temp["description"] = "⚠️ DEPRECATED : " + deprecation_message

                dictionary[field] = temp

                gen_json_schema({field: dictionary[field]})

            else:
                title = dict_foo[field].get("title")

                if "icon" in dictionary[field].keys():
                    icon = dictionary[field]["icon"]
                else:
                    icon = get_icon(field)

                if title:
                    if icon:
                        dictionary[field]["title"] = f"{icon} {title}"
                    else:
                        dictionary[field]["title"] = title

                if deprecation_message := dict_foo[field].get("tide.meta.deprecation"):
                    dict_foo[field]["title"] = "⚠️ DEPRECATION WARNING"
                    dict_foo[field]["description"] = "⚠️ DEPRECATED : " + deprecation_message

                # If additionalProperties is not configured, we force it to
                # False. This prevents the users from adding invalid keys (
                # typos, or indentation error for example that
                # wouldn't be flagged by the validation, and not be processed
                # correctly.
                if dict_foo[field].get("type") == "object":
                    if not dict_foo[field].get("additionalProperties"):
                        dictionary[field]["additionalProperties"] = False

                # If within that dict a key is called coretide, the dict will receive
                # fields generated from the libraries to allow multi or single
                # field validation with JSON Schema
                if "recomposition" in dict_foo[field].keys():
                    temp = recomposition_handler(dict_foo[field]["recomposition"])
                    dictionary[field]["properties"] = temp

                # Handles retrieval of logsources
                if dict_foo[field].get("tide.config.visibility.logsources"):
                    logsources_result = FetchEnums.logsources()
                    if logsources_result:
                        enums, descriptions = logsources_result
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = enums
                        dictionary[field]["items"]["markdownEnumDescriptions"] = descriptions
                        dictionary[field]["items"]["uniqueItems"] = True
                
                # Handles retrieval of detectors
                if dict_foo[field].get("tide.config.visibility.detectors"):
                    detectors_result = FetchEnums.detectors()
                    if detectors_result:
                        enums, descriptions = detectors_result
                        if dict_foo[field].get("type") == "string":
                            dictionary[field]["enum"] = enums
                            dictionary[field]["markdownEnumDescriptions"] = descriptions
                        elif dict_foo[field].get("type") == "array":
                            dictionary[field]["items"] = {}
                            dictionary[field]["items"]["enum"] = enums
                            dictionary[field]["items"]["markdownEnumDescriptions"] = descriptions
                            dictionary[field]["items"]["uniqueItems"] = True

                # Handles the case when a list of values has to be fetched from
                # the configuration files.
                if config_fetch:=dict_foo[field].get("tide.config.parameter-list"):
                    values_list = FetchEnums.config_parameter_list(config_fetch)
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True

                # Handles the case where we want to dynamically return a list
                # of available systems
                if dict_foo[field].get("tide.config.systems::enabled"):
                    values_list = enabled_systems()
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True

                # Special handling to specifically get the available tenants
                if system:=dict_foo[field].get("tide.config.system.tenants"):
                    values_list, descriptions_list = FetchEnums.config_system_tenants_list(system)
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                        dictionary[field]["markdownEnumDescriptions"] = descriptions_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True
                        dictionary[field]["items"]["markdownEnumDescriptions"] = descriptions_list

                # Special handling to specifically get the available statuses
                if system:=dict_foo[field].get("tide.config.statuses"):
                    values_list, descriptions_list = FetchEnums.statuses()
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                        dictionary[field]["markdownEnumDescriptions"] = descriptions_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True
                        dictionary[field]["markdownEnumDescriptions"] = descriptions_list

                # Handles vocabularies
                if vocab:=dict_foo[field].get("tide.vocab"):
                    if type(vocab) is str:
                        # Add icon if available to title
                        icon = get_icon(query)
                        if icon:
                            dictionary[field]["title"] = icon + " " + dictionary[field]["title"]
                    if type(vocab) is bool:
                        vocab = field
                    scoped = dict_foo[field].get("tide.vocab.scoped")
                    hint_no_wrap = dict_foo[field].get("tide.vocab.hints.no-wrap")
                    stages = dict_foo[field].get("tide.vocab.stages")
        
                    # Normalize vocabs to list to support all variants
                    vocabs = [vocab] if type(vocab) is not list else vocab
                    
                    temp = {}
                    enum = []
                    markdown_enum = []
                    for vocab in vocabs:
                        new_enum, new_markdown_enum = gen_lib_schema(
                            vocab=vocab,
                            no_wrap=hint_no_wrap,
                            stages=stages,
                            scoped=scoped,
                        )
                        enum.extend(new_enum)
                        markdown_enum.extend(new_markdown_enum)
                    temp["enum"] = enum
                    temp["markdownEnumDescriptions"] = markdown_enum

                    # When no field type is present, assume it's a direct string
                    # When the type is set to string, oneOf allows only one value
                    # to be selected
                    field_types =dict_foo[field].get("type")
                    if field_types:
                        field_types = (
                            [field_types] if type(field_types) is str() else field_types
                        )
                    if field_types is None:
                        dictionary[field].update(temp)
                    elif "string" in field_types:
                        dictionary[field].update(temp)
                    elif "array" in field_types:
                        dictionary[field]["items"] = temp
                        dictionary[field]["uniqueItems"] = True

                else:
                    gen_json_schema(dictionary[field])

    return dictionary


def run():

    log("TITLE", "Metaschema to JSON Schema Assembler")
    log(
        "INFO",
        "Generates JSON Schemas from metaschema files, dynamically "
        "looking up Vocabulary values. JSON Schemas allow to validate the models "
        "as per the CoreTIDE schema.",
    )

    # Loops through all source yaml defined in meta_to_json and generates the
    # corresponding json structure before writing to the associated output file
    for meta in GLOBAL_CONFIG.metaschemas:

        if meta in GLOBAL_CONFIG.json_schemas:

            yaml_input = METASCHEMAS_FOLDER / GLOBAL_CONFIG.metaschemas[meta]
            json_output = JSON_SCHEMA_FOLDER / GLOBAL_CONFIG.json_schemas[meta]
            
            parsing = yaml.safe_load(open(yaml_input, encoding="utf-8"))
            placeholders = parsing.get("tide.placeholders") or {}

            log("ONGOING", "Generating json schema for : " + str(yaml_input))
            
            # Generate Schema
            generated = gen_json_schema(parsing)

            # Removes the OpenTide reserved schema keys
            cleaned = remove_tide_keywords(generated)

            # Export JSON Schemas
            log("ONGOING", "Exporting generated schema to : " + str(json_output))
            output = json.dumps(cleaned, indent=4, sort_keys=False, default=str)
            for placeholder in placeholders:
                log("ONGOING", f"Replacing all occurence of placeholder {placeholder} with value {placeholders[placeholder]}")
                output = output.replace(f"${placeholder}", placeholders[placeholder])

            output_file = open((json_output), "w", encoding="utf-8")
            output_file.write(output)
            output_file.close()
            log("SUCCESS", "Correctly exported")

    log("SUCCESS", "Generated all JSON Schemas")


if __name__ == "__main__":
    run()
