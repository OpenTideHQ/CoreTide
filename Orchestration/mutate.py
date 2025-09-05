import os
import git
import toml
import sys
from datetime import datetime
from pathlib import Path

toolchain_start_time = datetime.now()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log, ANSI, coretide_intro
from Engines.mutation import (
    file_name,
    remove_cdm_validation,
    references,
    security_domain,
    tide_2_uuid_migration
)

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

print(coretide_intro())
print(f"""
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
CoreTide Data Mutation
{ANSI.Formatting.STOP}
""")

file_name.run()
remove_cdm_validation.run()
references.run()
security_domain.run()
tide_2_uuid_migration.run()

print("\n" + "Execution Report".center(80, "="))

time_to_execute = datetime.now() - toolchain_start_time
time_to_execute = "%.2f" % time_to_execute.total_seconds() + " seconds"

log("SUCCESS", "Completed mutation toolchain", time_to_execute)
