import pandas as pd
import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.tide import DataTide

playbook_mapping = list()

for mdr in DataTide.Objects.mdr:

    content = DataTide.Objects.mdr[mdr]

    if content["status"] == "PRODUCTION":

        row = dict()
        row["File Name"] = mdr
        row["Name"] = content["title"]
        row["Author"] = content["meta"]["author"]
        row["Playbook"] = content.get("tags", {}).get("playbook") or ""

        if row["Playbook"] == "":
            print(f"❌ No playbook entry for {content['title']}")
        else:
            print(f"👣 Found playbook entry for {content['title']}")

        playbook_mapping.append(row)

table = pd.DataFrame(playbook_mapping)
excel = table.to_excel("playbook_map.xlsx")
