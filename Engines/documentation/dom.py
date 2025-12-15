from __future__ import annotations

import pandas as pd
import os
import git
from pathlib import Path
import sys
import shutil

from dataclasses import asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.framework import (
    get_vocab_stage_details
)
from Engines.modules.documentation import (
    get_vocab_description,
)
from Engines.modules.files import safe_file_name
from Engines.templates.dom import DETECTION_OBJECTIVE_TEMPLATE, SIGNAL_TEMPLATE
from Engines.modules.documentation_components import (
    tlp_doc,
    metadata_doc,
    attack_techniques,
    frontmatter_doc,
    relations_table,
    reference_doc,
)
from Engines.modules.tide import DataTide
from Engines.modules.logs import log
from Engines.modules.graphs import relationships_graph
from Engines.modules.deployment import CIEnvironment
from Engines.modules.datamodels.objects import Objects
from Engines.modules.datamodels.configurations import Configurations
from Engines.modules.documentation import (
    TARGET_WITH_DASH_PATHS,
    DOCUMENTATION_TARGET,
    UUID_PERMALINKS,
    get_icon
)

class DetectionObjectivesWiki:

    def __init__(self):
        WIKI_PATH = Path(DataTide.Configurations.Global.Paths.Core.models_docs_folder)
        self.DOCUMENTATION_PATH = WIKI_PATH / DataTide.Configurations.Documentation.object_names["dom"]
        if DOCUMENTATION_TARGET in TARGET_WITH_DASH_PATHS:
            self.MDR_WIKI_PATH = Path(str(self.MDR_WIKI_PATH).replace(" ", "-"))
            log("INFO",
                "Going to create file paths with dashes instead of space for the given environment",
                str(DOCUMENTATION_TARGET))


    def create_wiki(self):
        if not DataTide.Models.DOM:
            return
        self._recreate_folder()
        for objective in DataTide.Models.DOM:
            objective_content = DataTide.Models.DOM[objective]
            wiki_content = self._create_wiki_page(objective_content)
            self._export(objective_content, wiki_content)
    
    def _recreate_folder(self):
        if os.path.exists(self.DOCUMENTATION_PATH):
            shutil.rmtree(self.DOCUMENTATION_PATH)
        self.DOCUMENTATION_PATH.mkdir(parents=True)


    def _create_wiki_page(self, objective:Objects.DetectionObjective)->str:
        
        frontmatter = frontmatter_doc(objective.name, objective.metadata.uuid)
        tlp = tlp_doc(objective.metadata.tlp)
        techniques = attack_techniques(objective.metadata.uuid)
        metadata = metadata_doc(asdict(objective.metadata), model_type="dom")
        objective_type_description = get_vocab_description("detection.types", objective.objective.type)
        strategy_description = get_vocab_description("detection.composition", objective.objective.composition.strategy)
        relation_graph = relationships_graph(objective.metadata.uuid) 
        related_threat_vectors = relations_table(objective.metadata.uuid, direction="upstream") or "_❌ No related threat vector_"
        related_detection_rules = relations_table(objective.metadata.uuid, direction="downstream") or "_❌ No related detection rules_"
        signals_list = [self._create_signal_content(signal) for signal in objective.objective.signals]
        signals_list = "\n\n".join(signals_list)
        references = reference_doc(asdict(objective.references)) if objective.references else "_❌ No references_"

        return DETECTION_OBJECTIVE_TEMPLATE.format(
            frontmatter=frontmatter,
            name=f"# {get_icon("dom")} " + objective.name if not UUID_PERMALINKS else "",
            priority=objective.objective.priority,
            tlp=tlp,
            techniques=techniques,
            metadata=metadata,
            objective_type=objective.objective.type,
            objective_type_description=objective_type_description,
            description=objective.objective.description.replace("\n", "\n> "),
            strategy=objective.objective.composition.strategy.replace("\n", "\n> "),
            strategy_description=strategy_description,
            composition_description=objective.objective.composition.description,
            relation_graph=relation_graph,
            related_threat_vectors=related_threat_vectors,
            related_detection_rules=related_detection_rules,
            signals_list=signals_list,
            references=references
        )

    def _create_signal_content(self, signal:Objects.DetectionObjective.Objective.Signal)->str:

        logsource_table = self.Helpers().builders.logsources(signal.data.logsources) if signal.data.logsources else "_❌ No logsources mentioned_"
        entities_table = self.Helpers().builders.entities(signal.entities)
        detectors_table = self.Helpers().builders.detectors(signal.detectors) if signal.detectors else "_❌ No detectors mentioned_"
        examples_table = self.Helpers().builders.examples(signal.examples) if signal.examples else "_❌ No examples mentioned_"
        
        return SIGNAL_TEMPLATE.format(
            name=signal.name,
            uuid=signal.uuid,
            description=signal.description,
            data_availability=signal.data.availability,
            data_requirements=signal.data.requirements,
            logsource_table=logsource_table,
            entities_table=entities_table,
            detectors_table=detectors_table,
            examples_table=examples_table
        )

    class Helpers:

        def __init__(self):
            self.fetchers = self.Fetchers()
            self.builders = self.Builders(self.fetchers)

        class Fetchers:
            
            def asset(self, asset_name:str)->None|Configurations.Visibility.Asset:
                assets = DataTide.Configurations.Visibility.assets
                if not assets:
                    return None
                for asset in assets:
                    if asset.name == asset_name:
                        return asset
                return None

            def detector(self, technology_name:str)->None|Configurations.Visibility.Detector:
                detectors = DataTide.Configurations.Visibility.detectors
                if not detectors:
                    return None
                for technology in detectors:
                    if technology.name == technology_name:
                        return technology
                return None

            def logsource(self, logsource_name:str)->None|Configurations.Visibility.LogSource:
                logsources = DataTide.Configurations.Visibility.logsources
                if not logsources:
                    return None
                
                logsource_name = logsource_name.split("::")[-1] if "::" in logsource_name else logsource_name
                for logsource in logsources:
                    if logsource.name == logsource_name:
                        return logsource
                return None
        
        class Builders:

            def __init__(self, fetchers: DetectionObjectivesWiki.Helpers.Fetchers):
                self.fetchers: DetectionObjectivesWiki.Helpers.Fetchers = fetchers

            def logsources(self, logsources: list[str]) -> str:

                def _monitored_assets(logsource:str) -> str:
                    logsource_details = self.fetchers.logsource(logsource)
                    if logsource_details and logsource_details.assets:
                        assets_documentation = []
                        for asset in logsource_details.assets:
                            asset_details = self.fetchers.asset(asset)
                            if asset_details:
                                assets_documentation.append(f"_{asset_details.name}_ ({asset_details.criticality}) : {asset_details.description}")
                            else:
                                assets_documentation.append("Missing asset documentation for referenced asset "+ asset)
                        
                        return "- " + "\n- ".join(assets_documentation)

                    return "_❌ No assets configured_"

                logsources_data = []
                for logsource in logsources:
                    logsource_data = {}
                    logsource_details = self.fetchers.logsource(logsource)
                    logsource_data["Name"] = logsource.split("::")[-1]
                    logsource_data["Description"] = logsource_details.description if logsource_details else "_❌ Could not retrieve logsource details in visibility configuration_"
                    logsource_data["Data System"] = logsource_details.system if logsource_details else "_❌ Could not retrieve logsource details in visibility configuration_"
                    logsource_data["Tenants"] = ", ".join(logsource_details.tenants) if logsource_details and logsource_details.tenants else "_❌ Could not retrieve logsource details in visibility configuration_"
                    logsource_data["Assets"] = _monitored_assets(logsource) if logsource_details else "_❌ Could not retrieve logsource details in visibility configuration_"

                    logsources_data.append(logsource_data)

                return pd.DataFrame(logsources_data).to_markdown(index=False)



            def detectors(self, detectors: list[Objects.DetectionObjective.Objective.Signal.Detector]) -> str:
                
                def _technology(detector: Objects.DetectionObjective.Objective.Signal.Detector) -> str:
                    detector_details = self.fetchers.detector(detector.technology)
                    if detector_details:
                        return f"**{detector_details.name}** : {detector_details.description}"
                    return f"_❌ No detector technology configured under visibility for {detector.technology}_"
                
                def _monitored_assets(detector: Objects.DetectionObjective.Objective.Signal.Detector) -> str:
                    detector_details = self.fetchers.detector(detector.technology)
                    if detector_details and detector_details.assets:
                        assets_documentation = []
                        for asset in detector_details.assets:
                            asset_details = self.fetchers.asset(asset)
                            if asset_details:
                                assets_documentation.append(f"_{asset_details.name}_ ({asset_details.criticality}) : {asset_details.description}")
                            else:
                                assets_documentation.append("Missing asset documentation for referenced asset "+ asset)
                        
                        return "- " + "\n- ".join(assets_documentation)

                    return "_❌ No assets configured_"
                
                detectors_data = []
                for detector in detectors:
                    detector_data = {}
                    detector_data["Name"] = detector.name
                    detector_data["Description"] = detector.description
                    detector_data["Technology"] = _technology(detector)
                    detector_data["Monitored Assets"] = _monitored_assets(detector)
                    detector_data["Link"] = f'[Link]({detector.link} "{detector.link}")' if detector.link else "_❌ No link referenced_"
                    
                    detectors_data.append(detector_data)

                return pd.DataFrame(detectors_data).to_markdown(index=False)


            def entities(self, entities:list[str])->str:
                entities_data = []
                for entity in entities:
                    entity_data = {}
                    entity_data["Name"] = entity.split("::")[-1]
                    stage_details = get_vocab_stage_details("signal.entities", entity.split("::")[0])
                    if stage_details:
                        stage_name, stage_description = stage_details
                        stage_details = f"**{stage_name}** : {stage_description}"
                    else:
                        stage_details = "Could not enrich stage"
                    entity_data["Category"] = stage_details
                    entity_data["Description"] = get_vocab_description("signal.entities", entity)
                    entities_data.append(entity_data)
                
                return pd.DataFrame(entities_data).to_markdown(index=False)

            def examples(self, examples:list[Objects.DetectionObjective.Objective.Signal.Example])->str:

                examples_data = []
                for example in examples:
                    example_data = {}
                    example_data["Description"] = example.description.replace('\n', '<br>')
                    example_data["Source"] = f'<a href="{example.link}" title="{example.link}">Link</a>'
                    example_data["Language"] = example.language if example.language else "_❌ No Language mentioned_"
                    if example.query:
                        # Replace escaped newlines with actual newlines
                        query_formatted = example.query.strip().replace('\n', '<br>')
                        example_data["Query"] = f'<pre><code class="sql">{query_formatted}</code></pre>'
                    else:
                        example_data["Query"] = "<em>❌ No query mentioned</em>"

                    examples_data.append(example_data)

                return pd.DataFrame(examples_data).to_html(index=False, escape=False)


    def _export(self, objective:Objects.DetectionObjective, content:str):
        
        if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI and UUID_PERMALINKS:
            log("INFO", "Generating docs with UUID as file name")
            file_name = objective.metadata.uuid + ".md"
        else:
            objective_icon = get_icon("dom")
            file_name = objective_icon + " " + objective.name + ".md"
            file_name = safe_file_name(file_name)

        export_path = self.DOCUMENTATION_PATH / file_name

        if DOCUMENTATION_TARGET in TARGET_WITH_DASH_PATHS:
            export_path = Path(str(export_path).replace(" ", "-"))

        with open(export_path, "w+", encoding="utf-8") as output:
            output.write(content)


def run():
    objectives_wiki = DetectionObjectivesWiki()
    objectives_wiki.create_wiki()

if __name__ == "__main__":
    run()