import git
import sys
from pathlib import Path

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.systems.sentinel import (
    SentinelService,
)
from Engines.modules.logs import log
from Engines.modules.tide import DataTide


GROUPING_CONFIGURATION = """
      grouping_lookback: {grouping_lookback}
      matching: {grouping_matching_method}
{group_by_entities}
{group_by_alert_details}
{group_by_custom_details}
""".strip("\n")

DYNAMIC_PROPERTIES_TEMPLATE = """
      #- property: 
        #column: 
""".strip("\n")

DYNAMIC_PROPERTIES = """
      - property: {property} 
        column: {column}
""".strip("\n")

ENTITIES_TEMPLATE = """
  #entities:
    #- entity: 
      #mappings:
        #- identifier: 
          #column: 
""".strip("\n")

ENTITIES_MAPPINGS = """
        - identifier: {identifier} 
          column: {column}
""".strip("\n")

ENTITIES = """
    - entity: {entity} 
      mappings:
{mappings}
""".strip("\n")

TRIGGER_TEMPLATE = """
  #trigger:
    #operator: 
    #threshold: 
""".strip("\n")

TRIGGER = """
  trigger:
    operator: {operator}
    threshold: {threshold}
""".strip("\n")

SCHEDULING = """
  scheduling:
    #nrt: false
    frequency: {frequency} 
    lookback: {lookback}
""".strip("\n")

NRT_SCHEDULING = """
  scheduling:
    nrt: true
""".strip("\n")

CUSTOM_DETAILS_TEMPLATE = """
      #- key: 
        #column: 
""".strip("\n")

CUSTOM_DETAILS = """
      - key: {key} 
        column: {column}
""".strip("\n")


MDR = """
name: {rule_name}

#references:
  #public:
    #1: 
  #internal:
    #a: 

metadata:
  uuid: {rule_uuid}
  schema: mdr::2.1
  version: 
  created: {rule_creation}
  modified: {rule_modified}
  tlp: amber
  author: {rule_author} 
  #contributors:
    #-

description: |
  {rule_description}
#detection_model: 

response:
  alert_severity: {rule_severity}
  #playbook: https://
  #responders: 
  #procedure:
    #analysis: |
      #...
    #searches:
      #- purpose: |
          #...
        #system: 
        #query: |
          #...
    #containment: |
      #...

configurations:
  sentinel: 
{sentinel}
"""

SENTINEL = """
  schema: sentinel::2.1
  status: PRODUCTION
  tenants:
    - {tenant_name}
  #contributors:
    #-
  
{trigger}
  
{scheduling}
  
  alert:
    create_incident: {create_incident}
    suppression: {alert_suppression}
    {alert_title_commented}title: {alert_title_override} 
    {alert_description_commented}description: |
      {alert_description_override} 
    {custom_details_commented}custom_details:
{custom_details}
    {dynamic_properties_commented}dynamic_properties:
{dynamic_properties}
    {tactics}
    {techniques}

  grouping:
    event: {event_aggregation}
  
    alert:
      enabled: {alert_grouping_enabled}
      {reopen_closed_incidents_commented}reopen_closed_incidents: {reopen_closed_incidents}
{grouping_configuration}

  {entities_commented}entities:
{entities}
  
  query: |
    {query}
"""

if not DataTide.Configurations.Systems.Sentinel.tenants:
    log("FATAL", "You must first have Sentinel tenants configured to initiate the import")
    raise Exception 

def convert_period(period:str)->str:
    return period.removeprefix("PT").removeprefix("P").lower()
def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    sanitized_name = ""
    for char in name:
        if char in invalid_chars:
            sanitized_name += " "
        else:
            sanitized_name += char
    return sanitized_name

for tenant in DataTide.Configurations.Systems.Sentinel.tenants:  # type: ignore
    service = SentinelService(tenant).connect() #type: ignore
    rules = service.alert_rules.list(resource_group_name=tenant.setup.resource_group, # type: ignore
                                    workspace_name=tenant.setup.workspace_name # type: ignore
                                    )
    import json
    
    rules_list = [rule.as_dict() for rule in rules]

    with open("output.json", "w+", encoding="utf-8") as f:
        json.dump(rules_list, f, indent=4)
    
    for rule in rules_list:
        tenant_name = tenant.name
        
        
        # Trigger and Scheduling
        if rule.get("kind") == "nrt":
            trigger = TRIGGER_TEMPLATE
            scheduling = NRT_SCHEDULING
        elif rule.get("kind") == "Scheduled":
            trigger = TRIGGER.format(operator=rule["trigger_operator"],
                                     threshold=rule["trigger_threshold"])
            scheduling = SCHEDULING.format(frequency=convert_period(rule["query_frequency"]),
                                           lookback=convert_period(rule["query_period"])
                                           )
        else:
            continue # Do not process other types of detections
        create_incident = rule.get("incident_configuration", {}).get("create_incidentt", "false")
        
        # Suppression
        if rule.get("suppression_enabled", False) is False:
            alert_suppression = "false"
        else:
            alert_suppression = convert_period(rule["suppression_duration"])
        
        # Custom Details Handling
        if custom_details:=rule.get("custom_details"):
            custom_details_commented = ""
            custom_details = "\n".join([CUSTOM_DETAILS.format(key=k, column=v).strip("\n") for k,v in custom_details.items()])
        else:
            custom_details_commented = "#"
            custom_details = CUSTOM_DETAILS_TEMPLATE.strip("\n")

        # Dynamic Properties Handling
        if dynamic_properties:=rule.get("custom_details"):
            dynamic_properties_commented = ""
            dynamic_properties = "\n".join([CUSTOM_DETAILS.format(key=k, column=v).strip("\n") for k,v in dynamic_properties.items()])
        else:
            dynamic_properties_commented = "#"
            dynamic_properties = DYNAMIC_PROPERTIES_TEMPLATE.strip("\n")

        # Alert override settings
        alert_details_override = rule.get("alert_details_override")
        if not alert_details_override:
            alert_title_commented = "#"
            alert_description_commented = "#"
            alert_title_override = ""
            alert_description_override = "#..."
            dynamic_properties_commented = "#"
        else:
            if title_override:=alert_details_override.get("alert_display_name_format"):
                alert_title_commented = ""
                alert_title_override = title_override
            else:
                alert_title_commented = "#"
                alert_title_override = ""
            
            if description_override:=alert_details_override.get("alert_description_format"):
                alert_description_commented = ""
                alert_description_override = "\n      ".join(description_override.split("\n"))
            else:
                alert_description_commented = "#"
                alert_description_override = "#..."

            if dynamic_props:=alert_details_override.get("alert_dynamic_properties"):
                dynamic_properties_commented = ""
                dynamic_properties = ""
                for dp in dynamic_props:
                    dynamic_properties += "\n" + DYNAMIC_PROPERTIES.format(property = dp["alert_property"],
                                                                           column = dp["value"])
            else:
                dynamic_properties_commented = "#"
                dynamic_properties = DYNAMIC_PROPERTIES_TEMPLATE.strip("\n")

        # MITRE ATT&CK Tactics and Techniques
        if tactics:=rule.get("tactics"):
            tactics = "tactics:\n" + "      - " + "\n      - ".join(tactics)
        else:
            tactics = "OPENTIDE::REMOVE"
        if techniques:=rule.get("techniques"):
            techniques = "techniques:\n" + "      - " + "\n      - ".join(techniques)
        else:
            techniques = "OPENTIDE::REMOVE"

        # Alert and Incident Grouping
        event_aggregation = rule.get("event_grouping_settings",{}).get("aggregation_kind") or "SingleAlert"
        incident_configuration = rule.get("incident_configuration")
        grouping_configuration = incident_configuration.get("grouping_configuration") or {}


        if grouping_configuration["enabled"] is False:
            alert_grouping_enabled = "false"
            grouping_configuration = ""
            reopen_closed_incidents_commented = "#"
            reopen_closed_incidents = ""

        else:
            alert_grouping_enabled = "true"
            reopen_closed_incidents_commented = ""
            reopen_closed_incidents = grouping_configuration.get("reopen_closed_incident", "false")

            grouping_lookback = convert_period(grouping_configuration["lookback_duration"])
            grouping_matching_method = grouping_configuration["matching_method"]
            if group_by_entities:=grouping_configuration.get("group_by_entities"):
                group_by_entities = "      - " + "\n      - ".join([group_by_entities])
            else:
                group_by_entities = "OPENTIDE::REMOVE"
            if group_by_alert_details:=grouping_configuration.get("group_by_alert_details"):
                group_by_alert_details = "      - " + "\n      - ".join([group_by_alert_details])
            else:
                group_by_alert_details = "OPENTIDE::REMOVE"
            if group_by_custom_details:=grouping_configuration.get("group_by_custom_details"):
                group_by_custom_details = "      - " + "\n      - ".join([group_by_custom_details])
            else:
                group_by_custom_details = "OPENTIDE::REMOVE"

            grouping_configuration = GROUPING_CONFIGURATION.format(**locals()).strip("\n")

        #Entity Mappings
        if entity_mappings:=rule.get("entity_mappings"):
            entities_commented = ""
            entities = []
            for entity in entity_mappings:
                field_mappings = entity["field_mappings"]
                mappings = []
                for mapping in field_mappings:
                    mappings.append(ENTITIES_MAPPINGS.format(identifier=mapping["identifier"],
                                    column=mapping["column_name"]).strip("\n"))
                mappings = "\n".join(mappings)
                entities.append(ENTITIES.format(entity=entity["entity_type"],
                                mappings=mappings).strip("\n")) 
            entities = "\n".join(entities)
        else:
            entities_commented = "#"
            entities = ENTITIES_TEMPLATE.strip("\n")

        query = "\n    ".join(rule["query"].split("\n"))
        sentinel = SENTINEL.format(**locals())
        sentinel = "\n  ".join(sentinel.split("\n")).strip("\n")

        rule_name = rule["display_name"] + " - " + tenant_name
        rule_uuid = rule["name"]
        rule_description = "\n  ".join(rule["description"].split("\n"))
        rule_creation = rule_modified = rule["last_modified_utc"].split("T")[0]
        rule_severity = rule["severity"]
        rule_author = "OpenTide Sentinel Importer"
        mdr = MDR.format(**locals()).strip("\n")
        mdr = "\n".join([line for line in mdr.split("\n") if "OPENTIDE::REMOVE" not in line])

        Path("Imported").mkdir(exist_ok=True)
        with open(f"Imported/{sanitize_filename(rule_name)}.yaml", "w+", encoding="utf-8") as f:
            f.write(mdr)