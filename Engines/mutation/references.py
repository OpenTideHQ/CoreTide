import os
import git
import sys
from pathlib import Path
import yaml

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.files import resolve_paths

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

PATHS = resolve_paths()
MODELS_SCOPE = ["tvm", "cdm", "bdr", "mdr"]
MODELS_FOLDER = dict()

for model in MODELS_SCOPE:
    MODELS_FOLDER[model] = PATHS[model]
PRIVATE_DOMAIN = "s.cec.eu.int"
REF_TEMPLATE = """#references:
  #public:
    #1: 
  #internal:
    #a:
  #restricted:
    #A:
"""


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


def upgrade_refs(old_refs):

    new = dict()

    if old_refs:
        public_refs = dict()
        internal_refs = dict()

        internal_refs_list = [
            ref.strip()
            for ref in old_refs
            if PRIVATE_DOMAIN in ref or (".pdf" in ref and "https" not in ref)
        ]
        public_refs_list = [
            ref.strip() for ref in old_refs if ref not in internal_refs_list
        ]

        public_counter = 1
        for pub_ref in public_refs_list:
            public_refs[public_counter] = pub_ref
            public_counter += 1

        internal_counter = "a"
        for int_ref in internal_refs_list:
            internal_refs[chr(ord(internal_counter))] = int_ref
            internal_counter = chr(ord(internal_counter) + 1)

        if public_refs:
            new["public"] = public_refs
        else:
            new["com_public"] = {"com_1": "rem"}

        if internal_refs:
            new["internal"] = internal_refs
        else:
            new["com_internal"] = {"com_a": "rem"}

        new["com_restricted"] = {"com_A": "rem"}
        new["com_reports"] = ["list"]

        new = {"references": new}
        new = yaml.dump(new, sort_keys=False)
        new = new.replace("com_", "#")
        new = new.replace("rem", "")
        new = new.replace("- list", "  #-")  # Handle indent here since only case
    else:
        new = REF_TEMPLATE
    return new


def run():

    for model_type in MODELS_SCOPE:
        folder = MODELS_FOLDER[model_type]
        if not folder.exists():
            log(
                "WARNING",
                "Model folder configured but not found, skipping",
                f"{model_type} -> {folder}",
            )
            continue
        log("INFO", "Now processing all files under model type", model_type)
        for file in sorted(os.listdir(folder)):
            if not file.endswith(".yaml"):
                if not file.endswith(".yml"):
                    log("INFO", "The file doesn't end with .yaml or .yml, skipping", file)
                    continue  

            raw_body = open(folder / file, "r", encoding="utf-8").read()
            yaml_body = yaml.safe_load(raw_body)
            current_references = yaml_body.get("references")

            if "meta" in yaml_body:
                metadata_keyword = "meta:"
            elif "metadata" in yaml_body:
                metadata_keyword = "metadata:"

            if current_references and (type(current_references) is not list):
                log("DEBUG", "No need to migrate", file)

            elif (current_references and type(current_references) is not dict) or ("#public:" not in raw_body.split(metadata_keyword)[0]):
                log("ONGOING", "Migrating to new references model", file)
                
                header = raw_body.split(metadata_keyword)[0]
                large_block = "metadata:" + raw_body.split(metadata_keyword)[1]

                if not current_references:
                    new_references = REF_TEMPLATE
                    header = header.split("#references")[0]
                    large_block = "\n" + large_block

                if current_references:
                    new_references = upgrade_refs(current_references)
                    new_references = new_references + "\n"
                    header = header.split("references")[0]

                body = ""
                body = header + new_references + large_block

                output_path = folder / file
                # output_path = Path("./DEBUG") / file
                with open(output_path, "w+", encoding="utf-8") as export:
                    export.write(body)
                    log("SUCCESS", "Migrated reference schema correctly")


    log("SUCCESS", "Ensured all files are migrated to the new reference schema")


if __name__ == "__main__":
    run()
