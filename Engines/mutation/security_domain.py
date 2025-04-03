# This mutation was introduced to fix a previous schema error where 
# the security_domain keyword, which is a notable parameter, was
# not nested under the notable block. It also indent drilldown, 
# which on some older MDR may not be indented correctly.

import sys
import os
import git
from pathlib import Path

import yaml

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log
from Engines.modules.files import resolve_paths

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

PATHS = resolve_paths()
MDR_PATH = PATHS["mdr"]

class MigrateSecurityDomainMDR:
    """
    If security_domain is commented, or uncommented, simply makes an indent
    to re-nest under notable. In edge cases where notable is uncommented but
    not security_domain, indent and uncomment notable. In edge cases where 
    security_domain is not present at all, will not add it by safety.
    """

    def indent_security_domain(self, file_path:Path):
        data = open(MDR_PATH/file_path, encoding="utf-8").readlines()
        buffer = []
        for line in data:
            if line.startswith("    security_domain:"):
                line = "  " + line
                log("SUCCESS", "Found and added indent to security_domain")
            buffer.append(line)
        
        if buffer != data:
            with open(MDR_PATH/file_path, "w", encoding="utf-8") as file:
                for line in buffer:
                    file.write(line)
            log("SUCCESS", "Rewrote file")
    
    def uncomment_keyword(self, file_path:Path, keyword:str):
        data = open(MDR_PATH/file_path, encoding="utf-8").readlines()
        buffer = []
        for line in data:
            if line.strip().replace("#","").split(":")[0] == keyword:
                line = line.replace("#","")
                log("SUCCESS", "Found and uncommented target keyword", keyword)
            buffer.append(line)
        
        if buffer != data:
            with open(MDR_PATH/file_path, "w", encoding="utf-8") as file:
                for line in buffer:
                    file.write(line)
                log("SUCCESS", "Rewrote file")

    def indent_drilldown_section(self, file_path:Path):
        data = open(MDR_PATH/file_path, encoding="utf-8").readlines()
        buffer = []
        DRILLDOWN_RAW = ["    #drilldown:\n",
                         "      #name: \n",
                         "      #search: |\n",
                         "        #Type Here\n"]
        for line in data:
            if line in DRILLDOWN_RAW:
                    line = "  " + line
                    log("SUCCESS", "Indented part of the drilldown section")
            buffer.append(line)
        
        if buffer != data:
            with open(MDR_PATH/file_path, "w", encoding="utf-8") as file:
                for line in buffer:
                    file.write(line)
            log("SUCCESS", "Rewrote file")


    def migrate(self):
        for mdr in os.listdir(PATHS["mdr"]):
            if not mdr.endswith(".yaml") or not mdr.endswith(".yml"):
                log("INFO", "The file doesn't end with .yaml or .yml, skipping", mdr)
                continue  

            data = yaml.safe_load(open(MDR_PATH/mdr, encoding="utf-8"))
            mdr_name = data["name"]
            log("INFO", "Assessing if security_domain should be migrated", mdr_name)

            if "splunk" not in data["configurations"]:
                continue
            
            config = data["configurations"]["splunk"]
            if "security_domain" in config:
                log("ONGOING", "Migrating security_domain under the notable block")
                self.indent_security_domain(MDR_PATH/mdr)
                if "notable" not in config:
                    log("ONGOING", "Uncommenting notable to allow nesting")
                    self.uncomment_keyword(MDR_PATH/mdr, "notable")
            else:
                self.indent_security_domain(MDR_PATH/mdr)

            if "drilldown" not in config.get("notable",{}):
                log("INFO", "Drilldown section not found, will run a cleanup in case it is not indented properly")
                self.indent_drilldown_section(MDR_PATH/mdr)

def run():
    MigrateSecurityDomainMDR().migrate()

if __name__ == "__main__":
    run()