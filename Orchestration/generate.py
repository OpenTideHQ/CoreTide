import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log, print_banner
from Engines.modules.tide import IndexTide
from Engines.indexing import objects_indexer
from Engines.indexing.revisions import RevisionIndexer
from Engines.framework import templates

print_banner("CoreTide Meta Model Compilation")

log("TITLE", "TIDE Indexes Generation")
log(
    "INFO",
    "Generate entries in Tide namespace containing model data supportive of other generation routines",
)

objects_indexer.run()
templates.run()

IndexTide.reload()
from Engines.framework import json_schemas, vscode_snippets
from Engines.export import attack_navigator_layer
from Engines.export.table_export import TableExporter

json_schemas.run()
RevisionIndexer().run()
vscode_snippets.run()
attack_navigator_layer.run()
TableExporter().run()