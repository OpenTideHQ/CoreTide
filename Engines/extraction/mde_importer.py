import git
import sys
import requests
import json 

from dataclasses import dataclass

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.systems.defender_for_endpoint import DefenderForEndpointService 
from Engines.modules.models import TideConfigs

class DefenderForEndpointImporter(DefenderForEndpointService):
    
    def list_rules(self):
        response = self.session.get(self.DETECTION_RULES_ENDPOINT)
        return response.json()


#TODO - Iterate over available tenants. For import exercises - update those values manually for now
setup = TideConfigs.Systems.DefenderForEndpoint.Tenant.Setup(proxy=False,
                                                             ssl=True,
                                                             tenant_id="",
                                                             client_id="",
                                                             client_secret="",)

tenant = TideConfigs.Systems.DefenderForEndpoint.Tenant(name="",
                                                        description="",
                                                        deployment="",
                                                        setup=setup)

service = DefenderForEndpointImporter(tenant) #type:ignore
rules = service.list_rules()

template = """
name: "{name}"
#references:
  #public:
    #1: 
  #internal:
    #a: 

metadata:
  uuid: {uuid}
  schema: mdr::2.1
  version: 1
  created: {created}
  modified: {modified}
  tlp: amber+strict
  author: {author}
  #contributors:
    #-

description: |
{description}
#detection_model: 

response:
  alert_severity: {alert_severity}
  #playbook: https://
  #responders: 
  #procedure:

configurations:
  defender_for_endpoint: 
    rule_id::PandoraStores: {rule_id}
    schema: defender_for_endpoint::2.0
    status: {status}
    {contributors}
    tenants:
      - PandoraStores
    #flags:
      #-
    
    scheduling: {schedule}
    
    alert:
      #title: 
      category: {category}{techniques}
      #severity: 
      {alert_recommendation}
    
    {impacted_entities_flag}impacted_entities:
      {impacted_device}
      #mailbox: 
      {impacted_user} 
    
    #actions:
    
      #devices:
        #isolate_device: 
        #collect_investigation_package: true
        #run_antivirus_scan: true
        #initiate_investigation: true
        #restrict_app_execution: true
    
      #files:
        #allow_block:
          #action: 
          #column: 
          #groups:
            #selection: 
            #device_groups:
              #-
        #quarantine_file: 
    
    scope:
      selection: All
      #device_groups:
        #-
    
    query: |
{query}
"""

no_contributors_template = """
    #contributors:
      #-
"""

contributors_template = """
    contributors:
      - {contributor}
"""

no_recommendation_template = """
      #recommendation: |
        #Type Here
"""

recommendation_template = """
      recommendation: |
{recommendation}
"""

techniques_template = """
      techniques:
        {techniques_list}
"""

def add_space_before_uppercase(s):
    result = ""
    for i, char in enumerate(s):
        if char.isupper() and i > 0:  # Add a space before uppercase letters, except the first character
            result += " "
        result += char
    return result

def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    sanitized_name = ""
    for char in name:
        if char in invalid_chars:
            sanitized_name += " "
        else:
            sanitized_name += char
    return sanitized_name

def fix_multiline(string:str, indentation:int):
    lines = string.splitlines()
    fixed_lines = []
    for line in lines:
        if line.strip():
            fixed_lines.append(" " * indentation + line.strip())
    return "\n".join(fixed_lines)

for rule in rules["value"]:
    rule_name = rule["displayName"]
    rule_id = rule["id"]
    rule_uuid = rule["detectorId"]
    rule_created = rule["createdDateTime"].split("T")[0]
    rule_modified = rule["lastModifiedDateTime"].split("T")[0]
    rule_severity = rule["detectionAction"].get("alertTemplate", {}).get("severity")
    rule_author = rule["createdBy"]
    rule_description = rule["detectionAction"].get("alertTemplate", {}).get("description")
    rule_schedule = rule["schedule"]["period"] if rule["schedule"]["period"] != "0" else "NRT"
    rule_category = add_space_before_uppercase(rule["detectionAction"].get("alertTemplate", {}).get("category"))
    rule_query = rule["queryCondition"].get("queryText")
    rule_status = "PRODUCTION" if rule.get("isEnabled") else "DISABLED"
    
    #Contributors resolution
    if rule["lastModifiedBy"] != rule_author:
        contributors = contributors_template.format(contributor=rule["lastModifiedBy"]).strip()
    else:
        contributors = no_contributors_template.strip()

    #Techniques, if added
    techniques = ""
    if t:=rule["detectionAction"].get("alertTemplate", {}).get("mitreTechniques"):
      techniques_list = "- " + "\n        - ".join(t)
      print(techniques_list)
      techniques = techniques_template.format(techniques_list=techniques_list).rstrip()
    
    #Recommended actions, if added
    if not rule["detectionAction"].get("alertTemplate", {}).get("recommendedActions"):
        alert_recommendation = no_recommendation_template.strip()
    else:
        rule_description += "\n\n---\n" + "Recommended Actions : " + rule["detectionAction"].get("alertTemplate", {}).get("recommendedActions")
        alert_recommendation = recommendation_template.format(recommendation=fix_multiline(rule["detectionAction"].get("alertTemplate", {}).get("recommendedActions"), 8)).strip()
    

    #Impacted Assets
    impacted_device = "#device:"
    impacted_user = "#user:"
    impacted_entities_flag = "#"
    for impacted_asset in rule["detectionAction"]["alertTemplate"]["impactedAssets"]:
        if impacted_asset["@odata.type"].endswith("impactedDeviceAsset"):
            identifier = impacted_asset['identifier']
            impacted_device = f"device: {identifier[0].upper() + identifier[1:]}"
            impacted_entities_flag = ""
        if impacted_asset["@odata.type"].endswith("impactedUserAsset"):
            identifier = impacted_asset['identifier']
            impacted_user = f"user: {identifier[0].upper() + identifier[1:]}"
            impacted_entities_flag = ""

    with open(f"Imported/{sanitize_filename(rule_name)}.yaml", "w+", encoding="utf-8") as f:
        f.write(template.format(name=rule_name,
                                uuid=rule_uuid,
                                rule_id=rule_id,
                                created=rule_created,
                                modified=rule_modified,
                                alert_severity=rule_severity.title(),
                                alert_recommendation=alert_recommendation,
                                impacted_device=impacted_device,
                                impacted_user=impacted_user,
                                impacted_entities_flag=impacted_entities_flag,
                                author=rule_author,
                                contributors=contributors,
                                description=fix_multiline(rule_description, 2),
                                schedule=rule_schedule,
                                category=rule_category,
                                techniques=techniques,
                                query=fix_multiline(rule_query, 6),
                                status=rule_status).strip())
