import yaml
import sys
import git
from pathlib import Path

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.framework import get_value_metaschema
from Engines.modules.logs import log
from Engines.modules.tide import DataTide

# Configuration settings fetching routine
CONFIG_INDEX = DataTide.Configurations.Index
PATHS = DataTide.Configurations.Global.Paths.Index

METASCHEMAS_FOLDER = Path(PATHS["metaschemas"])
SUBSCHEMAS_FOLDER = Path(PATHS["subschemas"])
RECOMPOSITION = DataTide.Configurations.Global.recomposition


class IndentFullDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(IndentFullDumper, self).increase_indent(flow, False)


def fetch_config_template(dot_path:str)->str:
    print(dot_path)
    config_index = DataTide.Configurations.Index
    config_path = dot_path.split(".")
    key = config_path[0]
    while key != config_path[-1]:
        print(config_index)
        if key in config_index:
            config_index = config_index[key]
            key = config_path[config_path.index(key) + 1]
        else:
            raise ValueError(f"Key : {key} could not be found in path {dot_path}")
    
    try:
        return str(config_index[key]).strip()
    except:
        log("WARNING",
            "Could not the expected template",
            dot_path,
            "This is non blocking, but check why the template could not be fetched")
        return ""


def replace_strings_in_file(file_path, strings, replacement):
    """
    Replaces strings in target file with another chosen string in place,
    without creating intermediary files.

    Parameters
    ----------
    file_path :
    strings : arrays of strings to locate
    replacement : what the strings will be replaced with

    Returns
    -------
    True if executed
    """
    file = open(file_path, "r")
    buffer = []
    for line in file:
        for word in strings:
            if word in line:
                line = line.replace(word, replacement)
        buffer.append(line)
    file.close()
    file = open(file_path, "w")
    for line in buffer:
        file.write(line)
    file.close()
    return True


def remove_blanks(path):
    file = open(path, "r")
    clean = "".join(line for line in file if not line.isspace())

    file = open(path, "w")
    file.write(clean)

    return True


def get_required(metaschema, required_list):

    for key in metaschema.keys():
        if key in required_list:
            if metaschema[key].get("type") == "object":
                if r := metaschema[key].get("required"):
                    required_list.extend(r)
                    required_list.extend(
                        get_required(
                            metaschema[key]["properties"], required_list=required_list
                        )
                    )
                if fr := metaschema[key].get("tide.template.force-required"):
                    required_list.extend(fr)

    return required_list


def definition_handler(entry_point):
    definition = DataTide.TideSchemas.definitions[entry_point]
    return definition


def gen_template(metaschema, required):
    body = {}
    for key in metaschema:
        
        if not metaschema[key].get("tide.template.hide"):

            if metadef := metaschema[key.replace("#", "")].get("tide.meta.definition"):
                if key not in required:
                    key = "#" + key
                if metadef is True:
                    temp = definition_handler(key.replace("#", ""))
                    definition_required = temp.get("required", [])
                    definition_required.extend(temp.get("tide.template.force-required", []))
                else:
                    temp = definition_handler(metadef)
                    definition_required = temp.get("required", [])
                    definition_required.extend(temp.get("tide.template.force-required", []))

                template = gen_template(
                    {key.replace("#", ""): temp}, required=definition_required
                )
                template = (
                    template.get(key)
                    or template.get(key.replace("#", ""))
                    or template.get("#" + key)
                )
                body[key] = template

            else:
                keyword_type = (
                    metaschema[key].get("type") or "string"
                )  # Assuming object by default to circumvent validations errors

                # If multiple types are accepted, considering only the first one in list for template
                if type(keyword_type) is list:
                    keyword_type = str(keyword_type[0])

                if keyword_type == "object":
                    if key not in required:
                        if config:=metaschema[key].get("tide.template.config.required"):
                            if fetch_config_template(config) == "False":
                                key = "#" + key
                        else:
                            key = "#" + key

                    if "recomposition" in metaschema[key.replace("#", "")].keys():
                        recomp_cat = metaschema[key.replace("#", "")]["recomposition"]
                        recomp_entries = dict()
                        for entry in CONFIG_INDEX[recomp_cat]:
                            recomp_entry = CONFIG_INDEX[recomp_cat][entry]
                            try:
                                if recomp_entry["tide"]["enabled"] == True:
                                    recomp_entries[f"#{entry}"] = "blank"
                            except:
                                if recomp_entry["platform"]["enabled"] == True:
                                    recomp_entries[f"#{entry}"] = "blank"

                        body[key] = recomp_entries

                    else:
                        if (
                            "additionalProperties"
                            in metaschema[key.replace("#", "")].keys()
                        ):
                            if (
                                type(
                                    metaschema[key.replace("#", "")][
                                        "additionalProperties"
                                    ]
                                )
                                is not bool
                            ):
                                sample = (
                                    metaschema[key.replace("#", "")]
                                    .get("additionalProperties")
                                    .get("example")
                                )
                                if sample not in metaschema[key.replace("#", "")].get(
                                    "additionalProperties"
                                ).get("required", []):
                                    sample = "#" + sample
                                body[key] = {sample: "blank"}
                        if "patternProperties" in metaschema[key.replace("#", "")]:
                            first_item = list(
                                metaschema[key.replace("#", "")]["patternProperties"]
                            )[0]
                            sample = metaschema[key.replace("#", "")][
                                "patternProperties"
                            ][first_item].get("example")

                            if sample not in metaschema[key.replace("#", "")].get(
                                "patternProperties"
                            )[first_item].get("required", []):
                                sample = "#" + str(sample)

                            if sample:
                                body[key] = {sample: "blank"}
                            else:
                                body[key] = {}

                        else:
                            body[key] = gen_template(
                                metaschema[key.replace("#", "")].get("properties"),
                                required=required,
                            )

                elif (
                    "items" in metaschema[key].keys()
                    and "properties" in metaschema[key].get("items").keys()
                ):

                    if key in required:
                        sub_req = metaschema[key]["items"]["required"]

                    else:
                        key = "#" + key
                        sub_req = []

                    values = gen_template(
                        metaschema[key.replace("#", "")]["items"]["properties"],
                        required=sub_req,
                    )

                    # To properly display a commented list with also commented subkeys,
                    # we need to rename the first item in place to the expected format that
                    # will be replaced
                    if sub_req == []:
                        first_key = list(values)[0]
                        commented_first_key = "Comment out " + first_key.replace(
                            "#", ""
                        )
                        values = {commented_first_key: values.pop(first_key), **values}

                    body[key] = [values]

                else:

                    content = "blank"

                    # Additional custom requirements checks, easiest to resolve it at this 
                    # final level
                    local_required = False
                    if key in required:
                        local_required = True
                    
                    if metaschema[key].get("tide.template.required") is True:
                        local_required = True


                    if config:=metaschema[key].get("tide.template.config.required"):
                        enabled = fetch_config_template(config)
                        if enabled == "True":
                            local_required = True
                        elif enabled == "False":
                            local_required = False
                            
                    if config_path:=metaschema[key].get("tide.template.config.default.enabled"):
                        if fetch_config_template(config_path) != "False":
                            if config_path:=metaschema[key].get("tide.template.config.default"):
                                content = fetch_config_template(config_path)
                                if metaschema[key].get("tide.template.multiline"):
                                    if not content:
                                        content = "..."
                                    if local_required:
                                        # Trick to respect newlines
                                        content = content.replace("\n\n", "\nforce_space")
                                    else:
                                        # When commented out, newlines are respected as-is
                                        content = "\n".join(["#" + line for line in content.split("\n")])

                                    content = "|\n'" + content

                    if metaschema[key].get("tide.template.required") is False:
                        local_required = False

                    elif metaschema[key].get("format") == "date":
                        content = "YYYY-MM-DD"
                    elif metaschema[key].get("format") == "number":
                        content = 3
                    elif metaschema[key].get("format") == "email":
                        content = "author@domain.com"
                    elif metaschema[key].get("format") == "uri":
                        content = "https://"
                    elif metaschema[key].get("tide.template.multiline"):
                        if local_required:
                            content = "|\n'..."
                        else:
                            content = "|\n'#..."
                    elif "default" in metaschema[key]:
                        content = metaschema[key]["default"]
                    elif "const" in metaschema[key]:
                        content = metaschema[key]["const"]

                    if metaschema[key].get("tide.template.no-space"):
                        content = "no-space" + str(content)

                    if keyword_type == "array":
                        if not local_required:
                            key = "#" + key
                            content = "Comment out"

                        body[key] = [content]

                    else:
                        if not local_required:
                            key = "#" + key

                        body[key] = content

    return body


def make_spaces(template_path, metaschema):

    template = open(template_path, "r").readlines()
    spaced = []

    for line in template:
        key = line.split(":")[0].replace(" ", "")
        force_space = True if "force_space" in line else False
        no_space = True if "no-space" in line else False
        spacer = get_value_metaschema(
            key.replace("#", ""), metaschema, "tide.template.spacer"
        )
        key_type = get_value_metaschema(key.replace("#", ""), metaschema, "type")
        if key_type == "object" or spacer or force_space:
            if spacer != False:
                if not no_space:
                    spaced.append("\n")
            if force_space:
                line = line.replace("force_space", "")
            if no_space:
                line = line.replace("no-space", "")

        spaced.append(line)

    file = open(template_path, "w")
    for s in spaced:
        file.write(s)

    return True


def indent_template(template_path, identation):
    template = open(template_path, "r").readlines()
    indented = []
    for line in template:
        indented_line = " " * identation + line

        indented.append(indented_line)
    file = open(template_path, "w")
    for s in indented:
        file.write(s)

    return True


def run():

    log("TITLE", "Generate Templates from TideSchemas")
    log(
        "INFO",
        "Converts the metaschema into a template that can be reused"
        "for documentation, snippets etc. and make correct model creation easier",
    )

    for meta in (m := DataTide.Configurations.Global.metaschemas):

        if meta in (t := DataTide.Configurations.Global.templates):
            template_path = Path(PATHS["templates"]) / t[meta]

            log("ONGOING", "Generating template", str(meta))

            parsed = DataTide.TideSchemas.Index[meta]
            placeholders:dict = parsed.get("tide.placeholders") or {}
            required = get_required(parsed["properties"], parsed["required"])
            required.extend(parsed.get("tide.template.force-required") or [])
            template = gen_template(parsed["properties"], required)

            with open(template_path, "w+") as output:
                yaml.dump(template, output, sort_keys=False, Dumper=IndentFullDumper)

            replace_strings_in_file(template_path, ["- Comment out"], "#-")
            replace_strings_in_file(template_path, ["blank", "'"], "")
            replace_strings_in_file(template_path, ["spacer"], '    ')

            for placeholder in placeholders:
                replace_strings_in_file(template_path, [f"${placeholder}"], placeholders[placeholder])

            remove_blanks(template_path)
            make_spaces(template_path, parsed["properties"])

    for recomp in RECOMPOSITION:
        subschema_type_folder = RECOMPOSITION[recomp]
        for entry in CONFIG_INDEX[recomp]:
            recomp_entry = CONFIG_INDEX[recomp][entry]
            enabled = False
            try:
                if recomp_entry["tide"]["enabled"] == True:
                    enabled = True
            except:
                if recomp_entry["platform"]["enabled"] == True:
                    enabled = True

            if enabled:
                try:
                    subschema_name = recomp_entry["tide"]["name"]
                except:
                    subschema_name = recomp_entry["platform"]["name"]

                subchema_template_name = f"{subschema_name} Template.yaml"
                subschema_template_path = (
                    SUBSCHEMAS_FOLDER
                    / subschema_type_folder
                    / "Templates"
                    / subchema_template_name
                )

                parsed = DataTide.TideSchemas.subschemas[recomp][entry]

                log("ONGOING", "Generating template", subschema_name)
                required = get_required(parsed["properties"], parsed["required"])
                required.extend(parsed.get("tide.template.force-required") or [])

                subschema_template = gen_template(parsed["properties"], required)

                with open(subschema_template_path, "w+") as output:
                    yaml.dump(
                        subschema_template,
                        output,
                        sort_keys=False,
                        Dumper=IndentFullDumper,
                    )

                replace_strings_in_file(
                    subschema_template_path, ["- Comment out"], "#-"
                )
                replace_strings_in_file(subschema_template_path, ["blank", "'"], "")
                remove_blanks(subschema_template_path)
                make_spaces(subschema_template_path, parsed["properties"])
                # Current implementation to indent fields, if recomposition is used again we'll make
                # it a dynamic resolution - may need to make a tie in config between
                # model type and recomp fields.
                indent_template(subschema_template_path, 2)

    log("SUCCESS", "All Templates correctly generated")


if __name__ == "__main__":
    run()
