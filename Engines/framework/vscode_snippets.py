import json
from pathlib import Path
import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.tide import DataTide

# Config fetch routine
ICONS = DataTide.Configurations.Documentation.icons
PATHS = DataTide.Configurations.Global.Paths.Index
SNIPPETS_PATH = DataTide.Configurations.Global.Paths.Tide.snippet_file

RECOMPOSITION = DataTide.Configurations.Global.recomposition
SUBSCHEMAS_FOLDER = Path(DataTide.Configurations.Global.Paths.Core.subschemas)
CONFIG_INDEX = DataTide.Configurations.Index


def vs_code_snippet_generator(template_path, prefix, blanks=0):
    """
    Generates the body of a snippet by reading the file lines by line, which
    when dumped to json creates an array of strings preserving spaces as per
    vscode requirement.

    Parameters
    ----------
    template_path : path of the template file to convert to vscode snippet
    description : description of the snippet (will be shown to user)
    prefix : keywords that will trigger intellisense

    Returns
    -------
    snippet : snippet body, to be assembled in final snippet json file

    """

    # Read template file line by line and add to an array, which preserves
    # the template structure.
    file = open(template_path, "r")
    buffer = []
    for b in range(0, blanks):
        buffer.append("")
    for line in file:
        buffer.append(line)
    file.close()

    # Replace \n newline symbol that is present when the file is read
    buffer = [word.replace("\n", "") for word in buffer]

    # Constructs required data structure
    snippet = {}
    snippet["prefix"] = prefix
    snippet["body"] = buffer

    return snippet


def run():

    log("TITLE", "Generate VSCode Snippets")
    log(
        "INFO",
        "Converts the templates into vscode formatted snippets in"
        "project level settings, where keywords are used to generate the template",
    )

    snippets = {}

    for model in DataTide.Configurations.Global.metaschemas:

        if model in (t := DataTide.Configurations.Global.templates):
            # Extracts parameters from dictionaries, that will be represented in snippet
            # description = CONFIG["artifacts"]["snippets"]["models"][model]["description"]
            model_icon = ICONS.get(model) or ""

            full_name = DataTide.Configurations.Documentation.object_names[model]
            keyword = f"{model_icon} {full_name} Template"
            template_path = Path(PATHS["templates"]) / t[model]

            log("ONGOING", "Generating snippets for", full_name)

            snippet = vs_code_snippet_generator(template_path, keyword)
            snippets[keyword] = snippet

    for recomp in RECOMPOSITION:
        subschema_type_folder = RECOMPOSITION[recomp]
        subschema_icon = ICONS[recomp]

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

                log("ONGOING", "Generating snippets for", subschema_name)

                subchema_template_name = f"{subschema_name} Template.yaml"
                subschema_template_path = (
                    SUBSCHEMAS_FOLDER
                    / subschema_type_folder
                    / "Templates"
                    / subchema_template_name
                )

                keyword = f"{subschema_icon} {subschema_type_folder} : {subschema_name} Template"

                snippet = vs_code_snippet_generator(
                    subschema_template_path, keyword, blanks=1
                )
                snippets[keyword] = snippet

    # Exporting to .vscode folder in project allows user to have the snippets with
    # any git pull, and without having to copy paste.
    output = open(SNIPPETS_PATH, "w")
    json.dump(snippets, output, indent=4, sort_keys=False, default=str)
    output.close()


if __name__ == "__main__":
    run()
