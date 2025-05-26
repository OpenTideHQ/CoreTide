from datetime import datetime
import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log, ANSI, coretide_intro
from Engines.modules.tide import IndexTide
from Engines.indexing import object_indexer
from Engines.framework import templates
print(coretide_intro())

riptide = rf"""
{ANSI.Colors.ORANGE}
   ___  _______  _____________  ____  
  / _ \/  _/ _ \/_  __/  _/ _ \/ __/ 
 / , _// // ___/ / / _/ // // / _/    
/_/|_/___/_/    /_/ /___/____/___/    
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}CoreTIDE Meta Model Compilation Orchestration
{ANSI.Formatting.STOP}
"""

print(riptide)

log("TITLE", "TIDE Indexes Generation")
log(
    "INFO",
    "Generate entries in Tide namespace containing model data supportive of other generation routines",
)

object_indexer.run()
templates.run()

IndexTide.reload()
from Engines.framework import json_schemas, vscode_snippets

json_schemas.run()
vscode_snippets.run()