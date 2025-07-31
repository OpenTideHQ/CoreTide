import os
import git
import sys
import json
import pandas as pd

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.framework import (
    relations_downstream,
    relations_upstream,
    chain_resolver,
    get_vocab_entry,
    model_value,
    techniques_resolver,
)
from Engines.modules.documentation import (
    object_name,
    backlink_resolver,
    rich_attack_links,
    DOCUMENTATION_TARGET,
    CIEnvironment
)
from Engines.modules.tide import DataTide

CHAINING_INDEX = DataTide.Models.chaining

def mermaid_sanitizer(string:str)->str:
    """
    Removes reserved characters in mermaid syntax to avoid
    breaking the parser
    """

    FORBIDDEN_CHARACTERS = ["(", ")", "[", "]", "{", "}", "|"]
    for character in FORBIDDEN_CHARACTERS:
        string = string.replace(character, "")

    return string

def relationships_graph(id):

    def replace_keys(dictionary: dict, fun) -> dict:
        empty = {}
        # special case when it is called for element of array being NOT a dictionary
        if type(dictionary) == str:
            # nothing to do
            return dictionary

        for k, v in dictionary.items():
            if k:
                if type(v) == dict:
                    empty[fun(k)] = replace_keys(v, fun)

                elif type(v) == list:
                    newvalues = [fun(x) for x in v]
                    empty[fun(k)] = newvalues

                else:
                    empty[fun(k)] = v
        return empty

    remove = ["{", "}", "'", '"', "[", "]", ",", ":", "(", ")", "-"]

    childs = relations_downstream(id)
    parents = relations_upstream(id)

    if not childs and not parents:
        return ""

    graph = {"": {}}

    if childs:
        if type(childs) is list:
            graph.update({c: [] for c in childs})
        else:
            graph.update(childs)

    if parents:
        if type(parents) is list:
            graph.update({p: [] for p in parents})
        else:
            graph.update(parents)

    graph = replace_keys(graph, object_name)

    # For debugging purposes
    # with open("./graph.json", "w+", encoding="utf-8") as json_graph:
    #    json.dump(graph, json_graph, ensure_ascii=False)

    graph = json.dumps(graph, sort_keys=False, indent=4, ensure_ascii=False)

    mindmap = "".join([char for char in graph if char not in remove]).replace(
        "++", "::"
    )

    graph_mermaid = f"""
        mindmap
            Root[{mermaid_sanitizer(object_name(id).strip())}]
                {mindmap}
        """

    if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.AzurePipeline:
        graph_mermaid = f"""
            ::: mermaid
            {graph_mermaid}
            :::
            """
    else:
        graph_mermaid = f"""
            ```mermaid
            {graph_mermaid}
            ```
            """

    return graph_mermaid

def chaining_graph(tvm):
    graph = str()
    chaining_structure = dict()
    # Search in every direction
    #
    # Data Structure
    # TVM9001: succeeds : TVM9002
    #                     TVM9005
    # TVM9005: preceeds : TVM9001
    #
    # Drawing algo checks relationship type from vocab
    # If to draws if from reverses order
    # Have buffer to check for duplicate commands (else will add two arrows)
    # First commands are adding all relevant infos
    # Following are adding links

    chaining_data = dict()

    # Retrosearching for any other TVM which are chaining to the
    # entry point
    for vector in CHAINING_INDEX:
        for link in CHAINING_INDEX[vector]:
            if tvm in CHAINING_INDEX[vector][link]:
                if vector not in chaining_data:
                    chaining_data[vector] = dict()
                if link not in chaining_data[vector]:
                    chaining_data[vector][link] = []
                # Avoid duplication
                if tvm not in chaining_data[vector][link]:
                    chaining_data[vector][link].append(tvm)

    # Walk in those references to return all relations
    for v in chaining_data.copy():
        chaining_data = chain_resolver(v, chaining_data)

    # Walk through all the chain links from the model
    chaining_data = chain_resolver(tvm, chaining_data)

    if not chaining_data:
        return None, None

    vector_links = []
    header = []
    killchain_vectors = {}

    table_data = []

    for v in chaining_data:
        for link in chaining_data[v]:
            for target in chaining_data[v][link]:
                data = {}
                data["☣️ Vector"] = backlink_resolver(v)
                data["⛓️ Link"] = f"`{link}`"
                data["🎯 Target"] = backlink_resolver(target)
                data["⛰️ Terrain"] = str(model_value(target, "terrain")).replace(
                    "\n", " "
                )
                data["🗡️ ATT&CK"] = rich_attack_links(
                    techniques_resolver(target), wrap=5
                )
                table_data.append(data)

    table = pd.DataFrame(table_data).to_markdown(index=False)

    for v in chaining_data:
        if v not in header:
            header.append(v)
        for link in chaining_data[v]:
            for chain_v in chaining_data[v][link]:
                # Check link type
                link_type = get_vocab_entry(
                    "chaining_relations",
                    link.split("::")[1],
                    field="tide.vocab.relation.type",
                )
                if link_type == "to":
                    chain = f"{v} -->|{link.split('::')[1]}| {chain_v}"
                elif link_type == "from":
                    chain = f"{chain_v} -->|{link.split('::')[1]}| {v}"
                elif link_type == "bidirectional":
                    chain = f"{v} <-->|{link.split('::')[1]}| {chain_v}"
                else:
                    chain = ""

                if chain_v not in header:
                    header.append(chain_v)

                if chain:
                    if chain not in vector_links:
                        vector_links.append(chain)

    for v in header:
        killchain = model_value(v, "killchain")
        if killchain:
            if type(killchain) is list:
                killchain = killchain[0]
            if killchain not in killchain_vectors:
                killchain_vectors[killchain] = []
            killchain_vectors[killchain].append(v)

    killchain_subgraphs = []
    for killchain in killchain_vectors:
        killchain_subgraphs.append(f"subgraph {killchain}")
        killchain_subgraphs.extend(killchain_vectors[killchain])
        killchain_subgraphs.append("end")
    killchain_subgraphs = "\n".join(killchain_subgraphs)

    # These props allow to expand the chaining diagram with more
    # metadata present in the model
    graph_properties = {
        "cve": {"relation": "exploits", "direction": "to", "shape": "flag"},
        "platforms": {"relation": "targets", "direction": "to", "shape": "database"},
        "actors" : {"relation" : "performs", "direction": "from", "shape": "hexagon"}  
    }

    properties_node_graph = []
    properties_link_graph = []
    for prop in graph_properties:
        for v in header:
            data = model_value(v, prop)            
            if data:
                # Processing and cleaning up actors for graph display
                if prop == "actors":
                    if type(data[0]) is dict:
                        clean_data = []
                        for actor in data:
                            actor_name = get_vocab_entry("actors", actor.get("name").split("::")[1], "name")
                            actor_name = actor_name.replace("[Enterprise]", "")
                            actor_name = actor_name.replace("[Mobile]", "")
                            actor_name = actor_name.replace("[ICS]", "")
                            actor_name = actor_name.strip()
                            clean_data.append(actor_name)   
                        data = clean_data
                    else:
                        continue  

                for value in data:
                    if (
                        value != "Unknown"
                    ):  # TODO Remove once Unknown is fully removed from TVM actors field
                        keyword = graph_properties[prop]["relation"]
                        shape = graph_properties[prop]["shape"]
                        direction = graph_properties[prop].get("direction")
                        node = str()
                        if shape == "database":
                            node = f"{value.replace(' ','')}[({value})]"
                        elif shape == "flag":
                            node = f"{value.replace(' ','')}>{value}]"
                        elif shape == "pill":
                            node = f"{value.replace(' ', '')}([{value}])"
                        # Append new shapes from this code block
                        elif shape == "hexagon":
                            node = f"{value.replace(' ', '')}" + '{{' + value + '}}'

                        if node not in properties_node_graph:
                            properties_node_graph.append(node)

                        if direction == "from":
                            link = f"{value.replace(' ','')} -.-> |{keyword}| {v}"

                        elif direction == "to":
                            link = f"{v} -.->|{keyword}| {value.replace(' ','')}"
                        else:
                            link = f"{v} -.-|{keyword}| {value.replace(' ','')}"

                        if link not in properties_link_graph:
                            properties_link_graph.append(link)

    properties_graph = (
        "\n".join(properties_node_graph) + "\n\n" + "\n".join(properties_link_graph)
    )

    def mermaid_breakspace(data: str, limit=15) -> str:
        words = data.split(" ")
        br_data = []
        count = 0
        for word in words:
            count += len(word) + 1
            if count < limit:
                br_data.append(word)
            else:
                br_data.append("<br>")
                br_data.append(word)
                count = 0

        br_data = " ".join(br_data)
        return br_data

    header_data = "\n".join(
        [f"{v}[{mermaid_sanitizer(mermaid_sanitizer(str(model_value(v, 'name'))))}]" for v in header]
    )

    vector_links = "\n".join(vector_links)

    diagram = f"flowchart LR\n\n{header_data}\n\n{killchain_subgraphs}\n\n{properties_graph}\n\n{vector_links}"

    if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.AzurePipeline:
        diagram = f"::: mermaid\n\n{diagram}\n\n:::"
    else:
        diagram = f"```mermaid\n\n{diagram}\n\n```"

    return diagram, table
