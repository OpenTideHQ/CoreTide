import json
import os
import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.tide import DataTide

ANALYTICS_PATH = DataTide.Configurations.Global.Paths.Tide.analytics


def run():

    log("TITLE", "ATT&CK Navigator Layer")
    log("INFO", "Generate mappings to MITRE ATT&CK as a Navigator Layer")

    complete_layer = ANALYTICS_PATH / "Complete Layer.json"
    layer = {}
    tvm_techniques = {}
    cdm_techniques = {}
    mdr_techniques = {}

    def recursive_filter(item, *forbidden):
        if isinstance(item, list):
            return [
                recursive_filter(entry, *forbidden)
                for entry in item
                if entry not in forbidden
            ]
        if isinstance(item, dict):
            result = {}
            for key, value in item.items():
                value = recursive_filter(value, *forbidden)
                if key not in forbidden and value not in forbidden:
                    result[key] = value
            return result
        return item

    for tvm in DataTide.Objects.tvm:
        object_data = {}
        object = DataTide.Objects.tvm[tvm]
        object_id = object.get("metadata",{}).get("uuid")
        object_data["techniques"] = object["threat"]["att&ck"]
        object_data["name"] = object["name"]
        tvm_techniques[object_id] = object_data

    # Pivoting tvm data to make comments easier

    for cdm in DataTide.Objects.cdm:
        object_data = {}
        object = DataTide.Objects.cdm[cdm]
        object_id = object.get("metadata",{}).get("uuid")
        object_data["name"] = object["name"]

        if "att&ck" in object["detection"].keys():
            cdm_technique = []
            cdm_technique.append(object["detection"]["att&ck"])
            object_data["techniques"] = cdm_technique

        else:
            vec_techniques = []
            vectors = object["detection"]["vectors"]
            for v in vectors:
                for tvm in DataTide.Objects.tvm:
                    vec = DataTide.Objects.tvm[tvm]
                    if vec["id"] == v:
                        for t in vec["threat"]["att&ck"]:
                            vec_techniques.append(t)
            object_data["techniques"] = vec_techniques

        cdm_techniques[object_id] = object_data

    for mdr in DataTide.Objects.mdr:
        object_data = {}
        object = DataTide.Objects.mdr[mdr]
        object_id = object["metadata"]["uuid"]
        object_data["name"] = object["name"]
        parent = object.get("detection_model")

        if parent and not parent.startswith("BDR"):

            for cdm in DataTide.Objects.cdm:
                object = DataTide.Objects.cdm[cdm]
                if object.get("metadata",{}).get("uuid") == parent:

                    if "att&ck" in object["detection"].keys():
                        cdm_technique = []
                        cdm_technique.append(object["detection"]["att&ck"])
                        object_data["techniques"] = cdm_technique

                    else:
                        vec_techniques = []
                        vectors = object["detection"]["vectors"]
                        for v in vectors:
                            for tvm in DataTide.Objects.tvm:
                                vec = DataTide.Objects.tvm[tvm]
                                if vec.get("metadata",{}).get("uuid") == v:
                                    for t in vec["threat"]["att&ck"]:
                                        vec_techniques.append(t)

                        object_data["techniques"] = vec_techniques

            mdr_techniques[object_id] = object_data

    pivot = {}
    for i in tvm_techniques:
        for t in tvm_techniques[i]["techniques"]:
            if t in pivot.keys():
                pivot[t] += ", " + i + " " + tvm_techniques[i]["name"]
            else:
                pivot[t] = i + " " + tvm_techniques[i]["name"]

    for r in cdm_techniques:
        for c in cdm_techniques[r]["techniques"]:
            if c in pivot.keys():
                pivot[c] += ", " + r + " " + cdm_techniques[r]["name"]
            else:
                pivot[c] = r + " " + cdm_techniques[r]["name"]

    for m in mdr_techniques:
        for l in mdr_techniques[m]["techniques"]:
            if l in pivot.keys():
                pivot[l] += ", " + "MDR : " + mdr_techniques[m]["name"]
            else:
                pivot[l] = "MDR : " + mdr_techniques[m]["name"]

    # Creating layer compatible array
    layer_techniques = []

    legendItems = [
        {"label": "TVM, CDM and MDR Coverage", "color": "#74c476"},
        {"label": "TVM and CDM Coverage", "color": "#9e9ac8"},
        {"label": "Only TVM Coverage", "color": "#fc6b6b"},
        {"label": "Only CDM Coverage", "color": "#6baed6"},
    ]

    for p in pivot:
        temp = {}
        temp["techniqueID"] = p
        if "TVM" in pivot[p] and "CDM" in pivot[p] and "MDR" in pivot[p]:
            temp["color"] = "#74c476"

        elif "TVM" in pivot[p] and "CDM" in pivot[p]:
            temp["color"] = "#9e9ac8"

        elif "CDM" in pivot[p] and "TVM" not in pivot[p]:
            temp["color"] = "#6baed6"

        else:
            temp["color"] = "#fc6b6b"

        temp["comment"] = pivot[p]
        layer_techniques.append(temp)

    layer["name"] = "CoreTIDE ATT&CK Coverage"
    layer["description"] = (
        "Automatically filled in by CoreTIDE Toolchain based on latest content"
    )
    layer["domain"] = "mitre-enterprise"
    layer["techniques"] = layer_techniques
    layer["legendItems"] = legendItems

    with open(complete_layer, "w+") as out:
        output = json.dumps(layer, indent=4, sort_keys=False, default=str)
        out.write(output)


if __name__ == "__main__":
    run()
