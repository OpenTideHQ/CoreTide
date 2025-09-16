import git
import sys
import os
import json

from dataclasses import dataclass, asdict
from typing import Optional, Literal

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.tide import DataTide
from Engines.modules.framework import techniques_resolver

@dataclass
class LayerColor:
    red:str= "#fc6b6b"
    blue:str= "#6baed6"
    green:str= "#74c476"
    purple:str= "#9e9ac8"

@dataclass
class TechniqueLayer:
    techniqueID: str
    color:str
    comment:str
    enabled:bool = True

@dataclass
class LegendEntry:
    label:str
    color:str

@dataclass
class NavigatorLayer:
    versions:dict
    techniques:list[TechniqueLayer]
    name:str = "layer"
    domain:str = "enterprise-attack"
    hideDisabled:bool = False
    legendItems:Optional[list[LegendEntry]] = None

@dataclass
class TechniqueIndexEntry:
    objects_names:list[str]
    objects_uuids:list[str]

class AttackNavigatorLayer:

    def __init__(self):
        self.EXPORT_PATH = DataTide.Configurations.Global.Paths.Tide.exports
        self.EXPORT_FILE_NAME = DataTide.Configurations.Global.exports.attack_layer
        self.EXPORT_FILE_PATH = self.EXPORT_PATH / self.EXPORT_FILE_NAME

    def create_layer(self):
        technique_layer = self.generate_technique_layer()
        full_layer = self.assemble_full_layer(technique_layer=technique_layer)
        self.export_layer(layer=full_layer)

    def map_objects_and_techniques(self, model_type:Literal["tvm", "cdm", "mdr"])->dict[str, TechniqueIndexEntry]:

        match model_type:
            case "tvm":
                index = DataTide.Models.tvm
            case "cdm":
                index = DataTide.Models.cdm
            case "mdr":
                index = DataTide.Models.mdr

        technique_mapping:dict[str, TechniqueIndexEntry] = {}

        for object in index:
            techniques = techniques_resolver(object)
            name = index[object]["name"]
            uuid = index[object]["metadata"]["uuid"]
            for technique in techniques:
                if technique in technique_mapping:
                    technique_mapping[technique].objects_names.append(f"[{model_type.upper()}] " + name)
                    technique_mapping[technique].objects_uuids.append(uuid)
                else:
                    technique_mapping[technique] = TechniqueIndexEntry(objects_names=[f"[{model_type.upper()}] " + name], objects_uuids=[uuid])

        #log("ONGOING", "Compiled mapping index for object type", model_type, str(technique_mapping))

        return technique_mapping
    
    def generate_technique_layer(self)->list[TechniqueLayer]:
        
        tvm_techniques = self.map_objects_and_techniques(model_type="tvm")
        cdm_techniques = self.map_objects_and_techniques(model_type="cdm")
        mdr_techniques = self.map_objects_and_techniques(model_type="mdr")

        technique_layer:list[TechniqueLayer] = []

        for technique in tvm_techniques:
            mapping_detail = tvm_techniques[technique]
            #Technique mapped by TVM, not downstream
            if technique not in cdm_techniques:
                log("INFO", f"{technique} only at TVM level, found in : ", str(mapping_detail.objects_names))
                technique_layer.append(TechniqueLayer(techniqueID=technique,
                                                      color=LayerColor.red,
                                                      comment=", ".join(mapping_detail.objects_names)))
            #Technique also mapped in CDMs
            else:
                cdm_mapping_detail = cdm_techniques[technique]
                cdm_updated_mapping = TechniqueIndexEntry(objects_names= mapping_detail.objects_names + cdm_mapping_detail.objects_names,
                                                        objects_uuids= mapping_detail.objects_uuids + cdm_mapping_detail.objects_uuids)
                                   
                #Technique also mapped by MDRs
                if technique in mdr_techniques:

                    mdr_mapping_detail = mdr_techniques[technique]
                    mdr_updated_mapping = TechniqueIndexEntry(objects_names= cdm_mapping_detail.objects_names + mdr_mapping_detail.objects_names,
                                        objects_uuids= cdm_mapping_detail.objects_uuids + mdr_mapping_detail.objects_uuids)
                    log("INFO", f"{technique} Fully Mapped, found in : ", str(mdr_updated_mapping.objects_names))
                    technique_layer.append(TechniqueLayer(techniqueID=technique,
                                                        color=LayerColor.green,
                                                        comment=", ".join(mdr_updated_mapping.objects_names)))
                #Stops at CDM level
                else:
                    log("INFO", f"{technique} mapped at TVM level and MDR level, found in : ", str(cdm_updated_mapping.objects_names))
                    technique_layer.append(TechniqueLayer(techniqueID=technique,
                                    color=LayerColor.purple,
                                    comment=", ".join(cdm_updated_mapping.objects_names)))

        # Edge case, when CDM override TVM with new techniques
        for technique in cdm_techniques:
            if technique in tvm_techniques:
                continue

            cdm_mapping_detail = cdm_techniques[technique]
            technique_layer.append(TechniqueLayer(techniqueID=technique,
                            color=LayerColor.purple,
                            comment=", ".join(cdm_mapping_detail.objects_names)))

        return technique_layer


    def assemble_full_layer(self, technique_layer:list[TechniqueLayer])->NavigatorLayer:
        
        legend = list()
        legend.append(LegendEntry(label="TVM Only", color=LayerColor.red))
        legend.append(LegendEntry(label="TVM + CDM", color=LayerColor.purple))
        legend.append(LegendEntry(label="Full Coverage", color=LayerColor.green))
        legend.append(LegendEntry(label="CDM Only - Needs to be checked", color=LayerColor.blue))
        return NavigatorLayer(versions={"layer": "4.5"},
                              techniques=technique_layer,
                              legendItems=legend)

    def export_layer(self, layer:NavigatorLayer):
        
        with open(self.EXPORT_FILE_PATH, "w+") as export:
            json.dump(layer, export, indent=4, sort_keys=False, default=str)


def run():
    AttackNavigatorLayer().create_layer()

if __name__ == "__main__":
    run()
