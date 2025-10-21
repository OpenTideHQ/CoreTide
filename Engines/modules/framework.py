import os
import git
import uuid
import sys
from typing import Literal, overload, Tuple

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.tide import DataTide
from Engines.modules.logs import log

DEFINITIONS_INDEX = DataTide.TideSchemas.definitions
VOCAB_INDEX = DataTide.Vocabularies.Index
MODELS_INDEX = DataTide.Models.Index
CHAINING_INDEX = DataTide.Models.chaining


def unroll_dot_dict(dot_dict, separator="."):
    """
    Processes a dot (or other arbitrary symbol) separated dictionary into a nested dictionary
    Useful for turning nested params into a data structure that
    can be merged into another config dictionary.
    """
    if len(dot_dict.keys()) > 1:
        print(
            f"⚠️ Cannot process dictionary {str(dot_dict)}, expecting a single item dictionary"
        )
        return None

    ((long_key, value),) = dot_dict.items()
    nested_keys = long_key.split(separator)

    # Reverse dictionary so it can nest dictionaries backwards
    nested_keys.reverse()

    unrolled = dict()

    for key in nested_keys:

        current_index = nested_keys.index(key)

        # Check if first item in reversed keys, and assign terminal value to the key
        if current_index == 0:
            unrolled[key] = value

        else:
            # Copy dictionary, empty it and nest it
            copy_dict = unrolled.copy()
            unrolled = {}
            unrolled[key] = copy_dict.copy()

    return unrolled


def key_value_transform(kv_store_list: list) -> dict:
    kv_store = dict()
    for elem in kv_store_list:
        kv_store[elem["key"]] = elem["value"]
    return kv_store


# def rename_param_nest(nest, schema):
#
#    nest_copy= nest.copy()
#
#    for item in nest_copy:
#        if type(nest_copy[item]) == list:
#            parameter_name = get_value_metaschema(item, schema, "tide.mdr.parameter")
#
#            # Case for key:value format
#            if get_value_metaschema(item, schema, "key_value_store"):
#                nest[parameter_name] = key_value_transform(nest.pop(item))
#
#            else:
#                nest[parameter_name] = nest.pop(item)
#                for elem in nest_copy[item]:
#                    rename_param_nest(elem,schema)
#
#        elif type(nest_copy[item]) == dict:
#            parameter_name = get_value_metaschema(item, schema, "tide.mdr.parameter")
#            nest[parameter_name] = nest.pop(item)
#            rename_param_nest(nest[parameter_name], schema)
#
#        else:
#            parameter_name = get_value_metaschema(item, schema, "tide.mdr.parameter")
#            temp = nest[item] #Avoids conflicts if coretide name and param names are the same
#            nest.pop(item)
#            nest[parameter_name] = temp
#
#    return nest


def get_value_metaschema(
    field, metaschema: dict, retrieve: str | Literal["tide.meta"], scope=None
):
    """
    Retreives any field from the metaschema at any depth

    Parameters
    ----------
    field : from which the corresponding title will be retrieved
    metaschema : search space
    retrieve: the key to be retrieved.
    scope: Allows to first narrow down a search namespace. Useful to allow for keys named in the same way at different
    nesting levels throughout the template

    Returns
    -------
    title: the title of the field to research.

    """
    if not metaschema:
        return None

    if scope:
        scoped_meta = get_value_metaschema(scope, metaschema, retrieve="tide.meta")
        if scope == "threat_objects":
            return get_value_metaschema(field, scoped_meta, retrieve)  # type: ignore

    if field in metaschema.keys():
        if retrieve == "tide.meta":
            return {field: metaschema[field]}
        else:
            return metaschema[field].get(retrieve)

    else:
        for key in metaschema.keys():
            if metadef := metaschema[key].get("tide.meta.definition"):
                if metadef is True:
                    definition = DEFINITIONS_INDEX[key]
                else:
                    definition = DEFINITIONS_INDEX[metadef]
                if field == key:
                    return DEFINITIONS_INDEX[key].get(retrieve)
                elif (
                    get_value_metaschema(field, definition.get("properties"), retrieve)
                    != None
                ):
                    return get_value_metaschema(
                        field, definition.get("properties"), retrieve
                    )

            if (
                metaschema[key].get("type") == "object"
                and "recomposition" not in metaschema[key].keys()
            ):
                if "additionalProperties" not in metaschema[key].keys():
                    # Trick since recursive function would not return for all
                    # occurence, would break on first return. If the return is not
                    # None, it means it's the title and thus returns.
                    if (
                        get_value_metaschema(
                            field, metaschema[key].get("properties"), retrieve
                        )
                        != None
                    ):
                        return get_value_metaschema(
                            field, metaschema[key].get("properties"), retrieve
                        )

            # Handle case for arrays of items
            if (
                metaschema[key].get("type") == "array"
                and "properties" in metaschema[key].get("items", {}).keys()
            ):
                if (
                    get_value_metaschema(
                        field, metaschema[key]["items"].get("properties"), retrieve
                    )
                    != None
                ):
                    return get_value_metaschema(
                        field, metaschema[key]["items"].get("properties"), retrieve
                    )


def rename_param_nest(nest, schema, scope=None):
    print("SCOPE ", scope)
    nest_copy = nest.copy()

    for item in nest_copy:
        parameter_name = get_value_metaschema(
            item, schema, "tide.mdr.parameter", scope=scope
        )
        temp = nest[
            item
        ]  # Avoids conflicts if coretide name and param names are the same
        nest.pop(item)
        nest[parameter_name] = temp

        if type(nest_copy[item]) == list:
            # Case for key:value format
            if get_value_metaschema(item, schema, "key_value_store"):
                nest[parameter_name] = key_value_transform(nest_copy[item])
            else:
                for elem in nest_copy[item]:
                    rename_param_nest(elem, schema, scope=item)

        elif type(nest_copy[item]) == dict:
            rename_param_nest(nest[parameter_name], schema, scope=item)

    return nest


def deep_update(dictionary, key, new_value):
    """
    Walks a nested dictionary at all depth until it meets key, then updates with new_value
    Note that the dictionary must contain the expected key at some depth, else
    will return None.
    """

    dict_copy = dictionary.copy()

    if key in dict_copy.keys():
        dictionary[key] = new_value

    else:
        for k in dict_copy:
            if type(dict_copy[k]) == dict:
                deep_update(dictionary[k], key, new_value)

    return dictionary


def vocab_metadata(vocab: str, field=None) -> str | dict:
    """
    Returns the metadata (description, links, icon etc.) for a given vocabulary.
    If field is set to None returns the entire metadata
    """

    if vocab not in VOCAB_INDEX.keys():
        return ""

    vocab_data = VOCAB_INDEX[vocab]["metadata"]

    if field:
        if field not in vocab_data:
            log("FAILURE", f"{field} does not exist in vocab", vocab)
            return ""
        else:
            return vocab_data.get(field)
    else:
        return vocab_data

def get_vocab_stage_details(vocabulary:str, stage_identifier:str)->None|Tuple[str,str]:
    """
    Return a tuple of the name and description for a particular stage of a vocabulary.
    If no stage correspond, or the vocabulary has no stages, returns nothing. 
    """
    if vocabulary not in VOCAB_INDEX:
        log("FAILURE",
            "The requested vocabulary does not exist in the index space",
            vocabulary)
        return None

    stages_section = VOCAB_INDEX[vocabulary]["metadata"].get("stages")
    if not stages_section:
        log("FAILURE",
            "The requested vocabulary does not contain a stage section",
            vocabulary)
        return None
    
    for stage in stages_section:
        if stage.get("id") == stage_identifier:
            log("INFO",
                f"Found corresponding stage in the requested vocabulary {vocabulary}",
                stage_identifier,
                str(stage))
            return stage.get("name"), stage.get("description")
    
    return None

def get_vocab_entry(vocab, identifier, field=None, newlines=False):
    """
    Returns data for a particular entry of a voacbulary.
    Supports two modes : if field is None, will return all data from
    the entry as a dict, else will fetch the data for the given
    identifier.
    """

    if vocab not in VOCAB_INDEX.keys():
        return ""

    identifier = identifier.split("::")[-1] if "::" in identifier else identifier

    if identifier in VOCAB_INDEX[vocab]["entries"].keys():
        entry_data = VOCAB_INDEX[vocab]["entries"][identifier]

        if field is None:
            return entry_data

        elif field in entry_data.keys():
            data = entry_data[field]
            if newlines is False and type(data) == str:
                return data.replace("\n", "")
            else:
                return data
        else:
            print(
                f"⚠️ Could not retrieve parameter [ {field} ] for entry with identifier [ {identifier} ] from vocabulary data of : {vocab}"
            )
            return ""

    # Lookup for legacy entries in vocab if all things fail
    else:
        vocab_data = VOCAB_INDEX[vocab]["entries"]
        for v in vocab_data:
            if vocab_data[v].get("legacy") == identifier:
                entry_data = VOCAB_INDEX[vocab]["entries"][identifier]
                if field is None:
                    return entry_data

                if field is None:
                    return entry_data

                elif field in entry_data.keys():
                    data = entry_data[field]
                    if newlines is False:
                        return data.replace("\n", "")
                    else:
                        return data

    print(
        f"⚠️ Could not retrieve identifier [ {identifier} ] from vocabulary data of : {vocab}"
    )
    return ""


def get_key_in_model_body(model_body, key):
    """
    Self-recursive function to return the value of a key nested within
    the body of a model data.
    """
    if key in model_body.keys():
        return model_body[key]

    else:
        for model_key in model_body.keys():
            if type(model_body[model_key]) is dict:
                # Trick since recursive function would not return for all
                # occurence, would break on first return. If the return is not
                # None, it means it's the title and thus returns.
                if get_key_in_model_body(model_body[model_key], key) != None:
                    return get_key_in_model_body(model_body[model_key], key)


def model_value(id, key):
    model_type = get_type(id)
    data = MODELS_INDEX[model_type][id]
    value = get_key_in_model_body(data, key)
    return value


def parents(id: str) -> list:
    """
    Returns the list of parents for any given CoreTIDE Object.
    If the Object does not have possible parent relationships,
    or in other word is a top-level Object, returns an empty string.
    """

    model_type = get_type(id)
    parents = []
    parent_mappings = {
        "dom": {"data": "objective", "parent": "threats"},
        "cdm": {"data": "detection", "parent": "vectors"},
        "mdr": {"parent": "detection_model"},
    }

    if model_type not in parent_mappings:
        return []

    model_data = MODELS_INDEX[model_type][id]
    parent_loc = parent_mappings[model_type]

    if "data" in parent_loc:
        parents = model_data[parent_loc["data"]].get(parent_loc["parent"]) or []

    else:
        parents = model_data.get(parent_loc["parent"]) or []

    if type(parents) is str:
        parents = [parents]

    return parents


def childs(model_id: str) -> list:
    """
    Returns the list of direct descendants for any given CoreTIDE Object,
    by performing a forward search.

    If the object can not have descendants, or in other word is a last-line
    Object (such as MDRs), will return an empty list
    """

    implementations = []

    mappings = {
        "tvm": {"child_type": "cdm", "data": "detection", "reference": "vectors"},
        "dom": {"child_type": "mdr", "reference": "detection_model"},
        "cdm": {"child_type": "mdr", "reference": "detection_model"},
        "bdr": {"child_type": "mdr", "reference": "detection_model"},
    }

    model_type = get_type(model_id)

    if model_type not in mappings.keys():
        return []

    child_type = mappings[model_type]["child_type"]
    data = mappings[model_type].get("data", None)
    reference = mappings[model_type]["reference"]

    CHILDS_INDEX = MODELS_INDEX[child_type]
    for child in CHILDS_INDEX:
        if child_type == "mdr":
            data = None
        
        if data:
            if model_id in CHILDS_INDEX[child].get(data, {}).get(reference, []):
                implementations.append(child)
        else:
            if model_id in CHILDS_INDEX[child].get(reference, []):
                implementations.append(child)


    return implementations

@overload
def get_type(model_uuid:str)->str:
    ...
@overload
def get_type(model_uuid:str, mute:Literal[True])->str|None:
    ...
@overload
def get_type(model_uuid:str, mute:Literal[False])->str:
    ...
def get_type(model_uuid:str, mute:bool=False):
    """
    Return the model type based on the schema identifier format.
    """

    model_body = DataTide.Models.FlatIndex.get(model_uuid, {})

    if not model_body:
        if mute:
            return None
        else:
            log("FATAL", "UUID does not exist in the index of Tide Objects", model_uuid)
            raise Exception

    schema = model_body.get("metadata", {}).get("schema")
    if not schema:
        #TODO For backwards compatibility with MDR still on 1.0. To be deprecated.
        if model_body.get("configurations"):
            return "mdr"
        if mute:
            return None
        else:
            log("FATAL", "Missing schema identifier in object", model_body.get("name", "NAME NOT FOUND"))
            raise Exception
        
    return schema.split("::")[0]

def keep_active_mdr(mdr_list:list[str])->list[str]:
    """
    Given a list of MDRs, only keep the ones considered Active,
    which mean none of the system they configure are set with a
    Deprecated status. 
    """
    from Engines.modules.deployment import check_status, DEPRECATED_STATUSES

    active_mdr = []
    for mdr in mdr_list:
        try:
            mdr_data = DataTide.Models.Index["mdr"][mdr]
        except:
            log("FAILURE",
                "Could not retrieve UUID in MDR Index",
                mdr)
            continue
        deprecated = False
        for system in mdr_data["configurations"]:
            system_data = mdr_data["configurations"][system]
            if check_status(system_data["status"]) in DEPRECATED_STATUSES:
                log("INFO",
                    "Skipping MDR as is in a deprecated status",
                    mdr)
                deprecated = True
        if deprecated is False:
            active_mdr.append(mdr)
    
    return active_mdr

def techniques_resolver(model_id: str, recursive=True) -> list:
    """
    Returns the relevant technique for any object, based on its own
    and its parent properties. WARNING : only works when index is loaded
    in memory.

    Returns
    -------
    techniques: List of resolved techniques.
    """

    techniques = []

    # Find the model_type
    model_type = get_type(model_id)
        
    # Load Model Data
    model_body = MODELS_INDEX[model_type][model_id]

    if model_type == "bdr":
        return []  # Case for BDR, as they do not relate to a technique concept

    if model_type == "mdr":
        parent_id = model_body.get("detection_model") or model_body.get("tags", {}).get(
            "coretide"
        )
        if not parent_id:
            return []  # Case when there is no parent CDM
        else:
            if recursive:
                techniques.extend(techniques_resolver(parent_id))
            else:
                return techniques

    if model_type == "dom":
        if "att&ck" in model_body["objective"]:
            techniques = model_body["objective"]["att&ck"]
        else:
            parent_ids = model_body["objective"].get("threats")
            if recursive:
                if parent_ids:
                    for parent_id in parent_ids:
                        techniques.extend(techniques_resolver(parent_id))
            else:
                return techniques

    if model_type == "cdm":
        if "att&ck" in model_body["detection"]:
            techniques = [model_body["detection"]["att&ck"]]
        else:
            parent_ids = model_body["detection"]["vectors"]
            if recursive:
                for parent_id in parent_ids:
                    techniques.extend(techniques_resolver(parent_id))
            else:
                return techniques

    if model_type == "tvm":
        techniques = model_body["threat"]["att&ck"]

    # Deduplicate techniques in case they were present
    # across multiple
    techniques = list(dict.fromkeys(techniques))

    return techniques


def relations_downstream(id):

    tree = {}

    if get_type(id) in ["dom", "cdm", "bdr"]:
        tree = keep_active_mdr(childs(id))
    else:
        for c in childs(id):
            tree[c] = relations_downstream(c)

    return tree


def relations_upstream(id):

    tree = {}
    if get_type(id) == "tvm":
        tree = []
    else:
        for p in parents(id):
            tree[p] = relations_upstream(p)

    return tree


def relations_list(
    id,
    mode: Literal["count", "flat"] = "flat",
    direction: Literal["upstream", "downstream", "both"] = "downstream",
):

    flat = {}

    if direction == "upstream":
        relations = relations_upstream(id)
    elif direction == "downstream":
        relations = relations_downstream(id)
    elif direction == "both":
        merged = relations_list(id, mode, direction="downstream")
        merged.update(relations_list(id, mode, "upstream"))
        return merged

    def recursive_items(dictionary):
        for key, value in dictionary.items():
            if type(value) is dict:
                yield (key, value)
                yield from recursive_items(value)
            else:
                yield (key, value)

    if relations and type(relations) is list:
        flat[get_type(relations[0])] = relations

    if type(relations) is dict:
        for k, v in recursive_items(relations):
            if k:
                if type(k) is list:
                    k_type = get_type(k[0])
                    flat.setdefault(k_type, [])
                    flat[k_type].extend(k)
                if type(k) is str:
                    k_type = get_type(k)
                    flat.setdefault(k_type, [])
                    flat[k_type].append(k)
            if v:
                if type(v) is list:
                    v_type = get_type(v[0])
                    flat.setdefault(v_type, [])
                    flat[v_type].extend(v)
                if type(v) is str:
                    v_type = get_type(v)
                    flat.setdefault(v_type, [])
                    flat[v_type].append(v)

    for k, v in flat.items():
        flat[k] = list(set(v))

    if mdr_list:=flat.get("mdr"):
        active_mdr = keep_active_mdr(mdr_list)
        flat["mdr"] = active_mdr
    
    if mode == "count":
        for k, v in flat.items():
            flat[k] = len(v)

    return flat


def chain_resolver(entry_point: str, chain: dict = {}) -> dict:
    """
    Search all chaining nodes and relations links
    of a given tvm to the n node, and recursively search for all returned value
    to reconstruct the full chain.
    """
    vector_chaining = CHAINING_INDEX.get(entry_point)
    if vector_chaining:
        for link in vector_chaining:
            if entry_point not in chain:
                chain[entry_point] = dict()
            if link not in chain[entry_point]:
                chain[entry_point][link] = []
            for v in vector_chaining[link]:
                if v not in chain[entry_point][link]:
                    chain[entry_point][link].append(v)
                    chain = chain_resolver(v, chain)

    return chain
