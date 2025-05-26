from jsonschema import Draft7Validator
from tabulate import tabulate
import os
import git
import sys
import json
import uuid


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.tide import DataTide
from Engines.modules.logs import log

JSONSCHEMAS_INDEX = DataTide.JsonSchemas.Index
OBJECTS_INDEX = DataTide.Objects.Index


def run():

    log("TITLE", "JSON Schema Validation")
    log("INFO", "Validates all CoreTIDE objects against their respective json schemas")

    errorslist = {}
    stats = dict()
    overall = 0

    for schema in JSONSCHEMAS_INDEX:
        count = 0

        if schema in OBJECTS_INDEX:
            schema_data = JSONSCHEMAS_INDEX[schema]
            v = Draft7Validator(schema_data)

            for model in OBJECTS_INDEX[schema]:
                count += 1

                body = OBJECTS_INDEX[schema][model]
                metadata = body.get("metadata") or body["meta"]
                metadata["created"] = str(metadata["created"])
                metadata["modified"] = str(metadata["modified"])

                # YAML supports int as keys, JSON doesn't. jsonschema team
                # decided not to support serialization, which creates a lot
                # of difficulties validating public references.
                # Solution is to remove public refs, and validate it separately.
                # Other parts of the reference will work as they don't use ints as key.
                public_refs = None

                if type(body.get("references")) is dict:
                    if body.get("references", {}).get("public"):
                        public_refs = body["references"].pop("public")
                        if body["references"] == {}:
                            del body["references"]

                
                errors = list()
                errors = sorted(v.iter_errors(body), key=lambda e: e.path)

                if public_refs:
                    for ref in public_refs:
                        if type(ref) is not int:
                            errors.append(
                                f"Reference '{ref}' in public references should be an integer"
                            )

                if len(errors) != 0:
                    name = f"{body['name']} ({model})"
                    errorslist[name] = errors

            stats[schema.upper()] = count
            overall += count

    for model_name in errorslist:
        for error in errorslist[model_name]:
            if type(error) is not str:
                error = error.message.replace("\n", "")
                if len(error) > 160:
                    error = error[:160] + f" [...Truncated Error Message]"
            log("FATAL", f"Failed validation in Object - {model_name}", error)

    if len(errorslist) != 0:
        log("FATAL", "Failed Schema Validation",
            "CoreTIDE objects currently do not match up to the metaschemas",
            "Review the files before running the validation again" )
        os.environ["VALIDATION_ERROR_RAISED"] = "True"

    else:
        statstable = [["Category", "Count"]]

        for y in stats:
            statstable.append([y, stats[y]])
        statstable = tabulate(statstable, headers="firstrow")

        log("SUCCESS", f"Successfully verified {overall} coretide objects")
        print(statstable)


if __name__ == "__main__":
    run()
