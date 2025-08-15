import json
import git
import sys
import os
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.tide import DataTide
from Engines.modules.deployment import TideRepo

@dataclass
class RevisionTracker:
    date: str
    message: str
    author: str
    commit: str

@dataclass
class RevisionIndexEntry:
    name: str
    object: str
    description: str
    revisions: Dict[str, RevisionTracker]


class RevisionIndexer:

    def __init__(self):

        self.TIDE_INDEXES_PATH = Path(DataTide.Configurations.Global.Paths.Tide.tide_indexes)
        self.OBJECT_SCOPE = DataTide.Configurations.Global.objects
        self.OBJECT_NAMES = DataTide.Configurations.Documentation.object_names
        self.INDEX_NAME = DataTide.Configurations.Global.indexes.revisions
        self.RAW_REVISIONS_INDEX = json.load(open(self.TIDE_INDEXES_PATH / self.INDEX_NAME))
        self.REVISIONS_INDEX = self._load_revision_index(self.RAW_REVISIONS_INDEX)

    def run(self):
        new_index = self._create_index()
        print(new_index)
        new_index = {k:asdict(v) for k,v in new_index.items()}
        self._export(new_index)

    def _load_revision_index(self, revisions_index:dict)->Dict[str, RevisionIndexEntry]:
        revisions_index = revisions_index.copy()
        parsed_index = dict()
        for entry in revisions_index:
            tracked_revisions = revisions_index[entry].pop("revisions")
            parsed_revisions = dict()
            try:
                for revision in tracked_revisions:
                    parsed_revisions[revision] = RevisionTracker(**tracked_revisions[revision])
            except:
                log("FATAL", "Unparsable tracked revisions entries")
                raise Exception
            try:
                parsed_index[entry] = RevisionIndexEntry(**revisions_index[entry], revisions=parsed_revisions)
            except:
                log("FATAL", "Unparsable object revisions entry")
                raise Exception
        return parsed_index

    def _new_revision(self, object_author:str="")->RevisionTracker:
        commit_details = TideRepo().last_commit_details
        return RevisionTracker(date=datetime.today().strftime('%Y-%m-%d'),
                                message=commit_details.message,
                                author=commit_details.author,
                                commit=commit_details.sha)

    def _create_entry(self, object:str, object_type:str):

        object_data = DataTide.Models.Index[object_type][object]
        object_version = str(object_data.get("metadata", {}).get("version"))
        if not object_version:
            log("FATAL", "Missing Object version, can't proceed")
            raise Exception

        if existing_entry:=self.REVISIONS_INDEX.get(object):

            if object_version not in existing_entry.revisions:
                existing_entry.revisions[object_version] = self._new_revision()
                return existing_entry
            else:
                return existing_entry

        else:
            object_type_name = self.OBJECT_NAMES[object_type]
            name = object_data["name"]
            match object_type:
                case "tvm":
                    description = object_data.get("threat", {}).get("description")
                case "cdm":
                    description = object_data.get("detection", {}).get("guidelines")
                case "bdr":
                    description = object_data.get("request", {}).get("description")
                case "mdr":
                    description = object_data.get("description") or ""

            return RevisionIndexEntry(name=name,
                                      object=object_type_name,
                                      description=description,
                                      revisions={object_version: self._new_revision()})

    def _create_index(self)->Dict[str, RevisionIndexEntry]:
        
        updated_index = dict()
        for object_type in self.OBJECT_SCOPE:
            for object in DataTide.Models.Index[object_type]:
                updated_index[object] = self._create_entry(object, object_type)

        return updated_index

    def _export(self, index:dict, file:str=""):
        
        if not file:
            file = self.INDEX_NAME
        with open(self.TIDE_INDEXES_PATH / file, "w+", encoding="utf-8") as export:
            export.write("")
            json.dump(index, export, indent=4)


if __name__ == "__main__":
    RevisionIndexer().run()