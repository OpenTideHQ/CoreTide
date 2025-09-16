import json
import git
import sys
import os
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Sequence

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.tide import DataTide
from Engines.modules.framework import childs, parents, get_vocab_entry

import pandas as pd

@dataclass
class TableEntry:
    uuid:str
    name:str
    type:str
    description:str
    version:str
    created:str
    modified:str
    childs:str
    parents:str
    chaining:str
    actors:str
    attack:str

class TableExporter:

    def __init__(self):

        self.TIDE_EXPORTS_PATH = Path(DataTide.Configurations.Global.Paths.Tide.exports)
        self.OBJECT_SCOPE = DataTide.Configurations.Global.objects
        self.OBJECT_NAMES = DataTide.Configurations.Documentation.object_names
        self.EXPORT_NAME = DataTide.Configurations.Global.exports.table
        self.EXPORT_PATH = self.TIDE_EXPORTS_PATH / self.EXPORT_NAME

    def run(self):
        dataset = self._create_dataset()
        dataset = [asdict(entry) for entry in dataset]
        dataset = pd.DataFrame(dataset)
        dataset = self._rename_columns(dataset)
        self._export(dataset)

    def _rename_columns(self, dataset:pd.DataFrame)->pd.DataFrame:
        new_columns = {}
        for column in dataset.columns:
            if column == "actors":
                new_columns[column] = "Threat Actors"
            elif column == "attack":
                new_columns[column] = "ATT&CK"
            elif column == "uuid":
                new_columns[column] = "UUID"
            else:
                new_columns[column] = column.capitalize()
        
        dataset.rename(columns=new_columns, inplace=True)
        
        return dataset


    def _flatten_actors(self, actors:list[dict])->list:
       
        def _enrich_actor_name(actor:str)->str:
            actor_data:dict = get_vocab_entry("actors", actor.split("::")[1]) #type: ignore
            return str(actor_data.get("name"))
        
        return [_enrich_actor_name(str(actor.get("name"))) for actor in actors]

    def _flatten_chaining(self, chains:list[dict])->dict[str, Sequence]:
        flat_chains = dict()
        for chain in chains:
            flat_chains.setdefault(chain["relation"], [])
            flat_chains[chain["relation"]].append(chain["vector"])
        
        return flat_chains

    def _create_entry(self, object:str, object_type:str)->TableEntry:

        object_data = DataTide.Models.Index[object_type][object]
        
        uuid = object
        name = object_data["name"]
        object_type_name = self.OBJECT_NAMES[object_type]
        version = str(object_data["metadata"]["version"])
        created = object_data["metadata"]["created"]
        modified = object_data["metadata"]["modified"]
        
        #Defaults as only for TVM
        actors = attack = chaining = ""

        object_childs = childs(uuid)
        object_childs = ", ".join(object_childs) if object_childs else ""

        object_parents = parents(uuid) or ""
        object_parents = ", ".join(object_parents) if object_parents else ""

        match object_type:
            case "tvm":
                description = object_data.get("threat", {}).get("description")
                chains = object_data["threat"].get("chaining") or ""
                if chains:
                    chaining = self._flatten_chaining(chains)
                    chaining = str(chaining)
                actors = object_data["threat"].get("actors") or ""
                if actors:
                    actors = self._flatten_actors(actors)
                    actors = ", ".join(actors)
                attack = object_data["threat"]["att&ck"]
                attack = ", ".join(attack)

            case "cdm":
                description = object_data["detection"].get("guidelines")
                if techniques:=object_data["detection"].get("att&ck"):
                    attack = ", ".join(techniques)

            case "bdr":
                description = object_data["request"].get("description")
            case "mdr":
                description = object_data["description"]

        return TableEntry(uuid=uuid,
                          name=name,
                          type=object_type_name,
                          description=description,
                          version=version,
                          created=created,
                          modified=modified,
                          childs=object_childs,
                          parents=object_parents,
                          chaining=chaining,
                          actors=actors,
                          attack=attack)

    def _create_dataset(self)->Sequence[TableEntry]:
        
        dataset = list()
        for object_type in self.OBJECT_SCOPE:
            for object in DataTide.Models.Index[object_type]:
                dataset.append(self._create_entry(object, object_type))

        return dataset


    def _export(self, export:pd.DataFrame):
        
        export.to_csv(self.EXPORT_PATH,
                           index=False)
        
if __name__ == "__main__":
    TableExporter().run()