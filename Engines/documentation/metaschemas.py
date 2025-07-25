import os
import git
import sys
import shutil
import time
from pathlib import Path
import pandas as pd

start_time = time.time()


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.documentation import get_icon, name_subschema_doc
from Engines.modules.logs import log
from Engines.modules.tide import DataTide
from Engines.modules.deployment import CIEnvironment

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

METASCHEMAS_INDEX = DataTide.TideSchemas.Index
SUBSCHEMAS_INDEX = DataTide.TideSchemas.subschemas
TEMPLATES_INDEX = DataTide.Templates.Index

# Configuration settings fetching routine
SCHEMA_DOCS_PATH = Path(DataTide.Configurations.Global.Paths.Core.schemas_docs_folder)
DOC_TITLES = DataTide.Configurations.Documentation.titles
ICONS = DataTide.Configurations.Documentation.icons
DOCUMENTATION_TARGET = CIEnvironment()._check_ci_environment()

# Columns of the dataframe which will constructs the table
columns = ["Field", "Name", "Description", "Type", "Example"]


METASCHEMA_DOC_TEMPLATE = '''

> {description}

{table}

### Template

`{template_name}`

```yaml
{template}
```

'''

def gen_schema_md(metaschema, template, model_type=None):
    '''
    Generates the markdown documentation for a given metaschema path

    Parameters
    ----------
    metaschema_path : Body of metaschema yaml file
    template_path : Body of the template corresponding to the metaschema, so
                    it may be appended to the documentation

    Returns
    -------
    schemamarkdown : Markdown formatted representation of the metaschema
    toc : Separate corresponding table of content entry

    '''

    # Parses the metaschema to extract relevant fields    
    title = DOC_TITLES.get(model_type, " ")
    description = metaschema.get("description", "")
    template_name = ""

    if model_type:
        if model_type == "mdr":
            template_name = "MDR Detection Name.yaml"
        else:
            template_name = f"{model_type.upper()}0001 - Object Name.yaml"

    table = gen_schema_md_table(metaschema)
    template = template.rstrip()
    
    # Final assembly
    documentation = METASCHEMA_DOC_TEMPLATE.format(title=title,
                                                   description=description,
                                                   table=table,
                                                   template=template,
                                                   template_name=template_name)
    
    if DOCUMENTATION_TARGET is not CIEnvironment.CIPlatforms.GitlabCI:
        if title:
            documentation = f"# {title} \n\n" + documentation

    return documentation

def definition_handler(entry_point):
    return DataTide.TideSchemas.definitions[entry_point]

def construct_meta_doc_data(metaschema, assembly=[], depth=0):

    recurs = "Sub" * depth + "Field"
    for key in metaschema:
        buffer = {}
        if type(metaschema[key]) == dict:
            if "tide.meta.definition" in metaschema[key]:
                if metaschema[key]["tide.meta.definition"] == True:
                    assembly = construct_meta_doc_data(
                                {key:definition_handler(key)},
                                assembly=assembly,
                                depth=depth)
                else:
                    assembly = construct_meta_doc_data(
                                {key:definition_handler(metaschema[key]["tide.meta.definition"])},
                                assembly=assembly,
                                depth=depth)
            else:

                buffer[recurs] = "`" + key + "`"
                title = metaschema[key].get("title")
                icon = get_icon(key, metaschema=metaschema) or get_icon(key)
                buffer["Name"] = f"{icon} {title}".strip()
                buffer["Description"] = metaschema[key].get("description", "").replace("\n", " ")
                buffer["Type"] = metaschema[key].get("type")
                buffer["Example"] = metaschema[key].get("example") or ""
                if "parameter" in metaschema[key].keys():
                    buffer["Parameter"] = metaschema[key]["parameter"]
                
                assembly.append(buffer)


                if "properties" in metaschema[key]:
                    assembly = construct_meta_doc_data(
                        metaschema[key]["properties"],
                        assembly=assembly,
                        depth=depth+1)
                    
                elif "items" in metaschema[key]:
                    if "properties" in metaschema[key]["items"].keys():
                        assembly = construct_meta_doc_data(
                            metaschema[key]["items"]["properties"],
                            assembly=assembly,
                            depth=depth+1)

    return assembly


def gen_schema_md_table(metaschema):
    recursion = construct_meta_doc_data(metaschema["properties"], assembly=[])
    df = pd.DataFrame(recursion)
    df.fillna('', inplace=True)
    df.insert(0, 'Name', df.pop('Name'))
    if "Parameter" in df.keys():
        new_order = ["Description", "Parameter","Type", "Example"]
    else:
        new_order = ["Description", "Type", "Example"]

    for key in new_order:
        insert = df.pop(key)
        df.insert(len(df.columns), key, insert)

    markdown = df.to_markdown(index=False)

    return markdown



def run():

    log("TITLE", "Schema Documentation")
    log("INFO", "Generates documentation for Tide Schemas and SubSchemas.")
    
    #Remove previous documentation
    if os.path.exists(SCHEMA_DOCS_PATH):
        shutil.rmtree(SCHEMA_DOCS_PATH)
    SCHEMA_DOCS_PATH.mkdir(parents=True)


    for model in METASCHEMAS_INDEX:
        if model in DOC_TITLES.keys():
            icon = ICONS.get(model) or ICONS.get("metaschemas") or ""
            print(f"{icon} Generating documentation for {model.upper()} metaschema")
            
            meta = METASCHEMAS_INDEX[model]
            template = TEMPLATES_INDEX[model]
            doc = gen_schema_md(meta, template, model)
            output_path = SCHEMA_DOCS_PATH / (icon + " " + DOC_TITLES[model] + ".md")
            
            if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
                output_path = Path(str(output_path).replace(" ", "-"))
            
            with open(output_path, "w+", encoding='utf-8') as output:
                output.write(doc)

    #Sub Schema Documentation
    for recomp in SUBSCHEMAS_INDEX:
        for sub in SUBSCHEMAS_INDEX[recomp]:
            icon = ICONS.get("subschemas")
            subschema = SUBSCHEMAS_INDEX[recomp][sub]
            sub_template = TEMPLATES_INDEX[recomp].get(sub)
            if sub_template:
                subschema_name = name_subschema_doc(recomp, sub)

                log("ONGOING", "Generating Sub Schema Documentation", subschema_name)

                doc = gen_schema_md(subschema, sub_template)
                output_path = SCHEMA_DOCS_PATH / (subschema_name + ".md")
            
                if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
                    output_path = Path(str(output_path).replace(" ", "-"))

                with open(output_path, "w+", encoding='utf-8') as output:
                    output.write(doc)


    if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
        doc_format_log = "🦊 Gitlab Flavored Markdown"    
    else:
        doc_format_log = "✒️ Standard markdown"

    time_to_execute = "%.2f" % (time.time() - start_time)

    print("\n⏱️ Generated documentation in {} seconds".format(time_to_execute))
    print("✅ Successfully built CoreTIDE documentation in {}".format(doc_format_log))

if __name__ == "__main__":
    run()