import sys
import git
from datetime import datetime

toolchain_start_time = datetime.now()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import coretide_intro, ANSI

# This trick caches a special version of the index which will seek
# and reconcile the staging index for MDRs which are in a Merge Request
from Engines.documentation import (
    dom,
    mdr,
    metaschemas,
    models,
    vocabularies,
    wiki_navigation
    )

print(coretide_intro())
print(f"""
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
CoreTide Documentation
{ANSI.Formatting.STOP}
""")

vocabularies.run()
metaschemas.run()
models.run()
dom.run()
mdr.run()
wiki_navigation.run()