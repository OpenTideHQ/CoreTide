import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from pprint import pprint

from Engines.modules.tide import DataTide

tvm_count = len(DataTide.Models.tvm)
cdm_count = len(DataTide.Models.cdm)
mdr_count = len(DataTide.Models.mdr)
mdr_system_count = dict()

for mdr in DataTide.Models.mdr:
    data = DataTide.Models.mdr[mdr]
    for system in data.get("configurations"):
        if system not in mdr_system_count:
            mdr_system_count[system] = 1
        else:
            mdr_system_count[system] += 1

report = {"Threat Vectors" : tvm_count,
          "Detection Models" : cdm_count,
          "Detection Rules" : {"Total" : mdr_count,
                               "Systems" : mdr_system_count}}

pprint(report, sort_dicts=False)