DETECTION_OBJECTIVE_TEMPLATE = '''{frontmatter}

{name}

**🚩 Priority : `{priority}`**

{tlp}

{techniques}

---

{metadata}

## 💡 Objective

**🏷️ Type** : {objective_type} - {objective_type_description}

> {description}

**🎼 Composition** : {strategy} - {strategy_description}

> {composition_description}

### 🌊 Related OpenTide Objects

{relation_graph}

{relation_table}


## 📡 Signals

{signals_list}


## References

{references}

'''

SIGNAL_TEMPLATE = '''
### {name}

🪪 **UUID** : `{uuid}`

> {description}

**🔎 Data Visibility**

- **Availability** : {data_availability}
- **Requirements** : `{data_requirements}`

_💾 Possible logsources_

{logsource_table}

**🧲 Related Entities**

{entities_table}

**⚠️ Detectors**

{detectors_table}

**🌐 Examples**

{examples_table}
'''
