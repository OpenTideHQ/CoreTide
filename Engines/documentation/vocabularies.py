import pandas as pd
import os
import git
import shutil
import sys
from pathlib import Path

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.documentation import (
    get_icon,
    make_json_table,
    DOCUMENTATION_TARGET,
    TARGET_WITH_DASH_PATHS
)
from Engines.modules.tide import DataTide
from Engines.modules.logs import log
from Engines.modules.deployment import CIEnvironment
from Engines.templates.models import VOCABS_DOC_TEMPLATE

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

VOCAB_INDEX = DataTide.Vocabularies.Index
ICONS = DataTide.Configurations.Documentation.icons
VOCAB_DOCS_PATH = Path(DataTide.Configurations.Global.Paths.Core.vocabularies_docs)
SKIP_VOCABS = DataTide.Configurations.Documentation.skip_vocabularies


def make_vocab_doc(vocab_field, vocabulary):
    """
    Parses a vocabulary file and returns the markdown documentation for the
    field

    Parameters
    ----------
    vocabulary : YAML vocabulary according to CoreTIDE specs

    Returns
    -------
    gen_body : markdown representation of the vocabulary table and
               documentation
    gen_toc : markdown links that make up the table of content
    """
    # Generate a dataframe of the possible keys for the field, with ID as index
    keys = vocabulary["entries"]

    df = pd.DataFrame.from_dict(keys).transpose()

    # Case for vocabs where the id is the prevalent index, often when using
    # other frameworks - determined by indexer under which key to set the entry
    if "id" in df.columns:
        df["name"] = df.index
    else:
        df["id"] = df.index

    df = df.sort_values(by=["id"])
    df = df.replace("\n", "", regex=True)
    df = df.replace(r"\|", r" \| ", regex=True)

    df = df.sort_values(by=["id"])

    df.set_index("id", drop=True, inplace=True)

    if "icon" in df.columns:

        df["name"] = df["icon"] + " " + df["name"]
        df = df.drop(["icon"], axis=1)

    if "name" in df.columns:
        first_col = df.pop("name")
        df.insert(0, "name", first_col)
        second_col = df.pop("description")
        df.insert(1, "description", second_col)

    else:
        second_col = df.pop("description")
        df.insert(0, "description", second_col)

    df.reset_index(inplace=True)

    rename_mapping = {c: f"{get_icon(c)} {c.capitalize()}" for c in df.columns}
    df = df.rename(columns=rename_mapping)

    name = vocabulary["metadata"]["name"]
    field = vocab_field
    vocab_description = vocabulary["metadata"]["description"]
    stages = vocabulary["metadata"].get("stages") or ""

    if stages:
        if type(stages) is list and type(stages[0]) is str:
            stages = "- " + "\n- ".join(stages)
            stages = "_This vocabulary contains multiple stages :_ \n\n" + stages
        # Handle rich type of stage documentation, especially used for scoped
        # vocabularies
        elif type(stages) is list and type(stages[0]) is dict:
            stage_doc = []
            for stage in stages:
                buffer = {}
                if stage.get("id"):
                    buffer["ID"] = stage["id"]
                buffer["Name"] = stage.get("icon", "") + " " + stage["name"]
                buffer["Description"] = stage.get("description")
                stage_doc.append(buffer)
            stages = pd.DataFrame(stage_doc).to_markdown(index=False)
    
    df = df.replace("\n", ". ", regex=True)
    table = str()

    if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
        title = ""
        table = make_json_table(df)
        
    else:
        if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.AzurePipeline:
            title = ""
        else:
            title = "# " + name
        table = df.to_markdown(index=False)

    documentation = VOCABS_DOC_TEMPLATE.format(
        title=title,
        vocab_description=vocab_description,
        stages=stages,
        table=table,
        field=field,
    )

    return documentation, name


def run():

    log("TITLE", "Vocabulary Documentation")
    log("INFO", "Generates documentation for vocabulary files in the Tide Instance")

    # Remove output folder if previously created
    if os.path.exists(VOCAB_DOCS_PATH):
        shutil.rmtree(VOCAB_DOCS_PATH)
    VOCAB_DOCS_PATH.mkdir(parents=True)

    for voc in VOCAB_INDEX:

        if voc in SKIP_VOCABS:
            log("SKIP", f"Skipping vocab as is in skip list",voc)
        else:
            if  VOCAB_INDEX[voc]["metadata"].get("model", False):
                log("SKIP",
                    "Not creating vocabulary documentation, was detected as an OpenTIDE model index",
                    voc)
                continue
            else:
                icon = get_icon(voc) or ICONS["vocab"] or ""
                print(f"{icon} Generating Vocabulary Documentation for field : {voc}...")
                if not VOCAB_INDEX[voc]["entries"]:
                    log("SKIP", "The vocabulary is empty, will not document", voc)
                else:
                    documentation, name = make_vocab_doc(voc, VOCAB_INDEX[voc])

                    output_name = icon + " " + name + ".md"
                    output_path = VOCAB_DOCS_PATH / output_name

                    if DOCUMENTATION_TARGET in TARGET_WITH_DASH_PATHS:
                        output_path = Path(str(output_path).replace(" ", "-"))

                    with open(output_path, "w+", encoding="utf-8") as output:
                        output.write(documentation)
    log("SUCCESS", "Successfully built vocabulary documentation")

if __name__ == "__main__":
    run()
