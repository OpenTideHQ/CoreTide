---
description: "Use when migrating a detection system deployer from MDRv3 (dict-based) to MDRv4 (typed dataclass) framework. Covers the full migration pattern across models, tide, deployment, TOML config, and deployer files. Use when working on system migration, typed framework, dataclass hierarchy, SystemLoader, or TideLoader."
---

# MDRv4 Migration Pattern

## Overview

MDRv4 replaces raw dictionary access (`mdr["configurations"]["system"]`) with typed Python dataclasses (`mdr.configurations.system.query`). Each system migration follows an identical pattern across 6-7 files.

## File Change Matrix

| File | Change |
|------|--------|
| `Engines/modules/models.py` | Add typed `TideConfigs.Systems.<System>` hierarchy + typed `TideModels.MDR.Configurations.<System>` |
| `Engines/modules/tide.py` | Add `SystemLoader.<system>()` method, route in `TideLoader.load_mdr()`, update `DataTide.Configurations.Systems.<System>` |
| `Engines/modules/deployment.py` | Uncomment/add `system_configuration_resolver` + `mdr_configuration_resolver` cases |
| `Configurations/systems/<system>.toml` | Add new `[platform]`/`[[tenants]]`/`[[modifiers]]` format alongside legacy |
| `Engines/deployment/<system>.py` | Add `deploy_mdr_v4()` method, update `deploy()` with dual signature |
| `Engines/modules/<system>.py` | Update init for new config format with fallback |
| `Engines/validation/<system>_query.py` | Add v4 query extraction path (optional) |

## 1. Models (`models.py`)

### System Configuration Hierarchy

```python
@dataclass(frozen=True)
class TideConfigs:
    class Systems:
        @dataclass(frozen=True)
        class SystemName(SystemConfig):
            @dataclass(frozen=True)
            class Tenant:
                @dataclass(frozen=True)
                class Setup:
                    url: str
                    # system-specific fields
                name: str
                setup: Setup
                secrets: Optional[Mapping] = None
            tenants: Sequence[Tenant] = field(default_factory=tuple)
```

### MDR Configuration Model

```python
@dataclass(frozen=True)
class TideModels:
    class MDR:
        class Configurations:
            @dataclass(frozen=True)
            class SystemName(TideDefinitionsModels.SystemConfigurationModel):
                query: Optional[str] = None
                # system-specific MDR fields
```

### Backwards Compatibility

The MDR configuration field uses `Union` for dual support:
```python
system_name: Optional[Union[TideModels.MDR.Configurations.SystemName, Mapping]] = None
```

## 2. Tide (`tide.py`)

### SystemLoader Method

```python
@staticmethod
def system_name(system_config: Mapping) -> TideModels.MDR.Configurations.SystemName:
    return TideModels.MDR.Configurations.SystemName(
        query=system_config.get("query"),
        # map all fields
    )
```

### TideLoader Routing

In `load_mdr()`, add schema version routing:
```python
case "system_name":
    if schema_version == "system_name::3.0":
        mdr_configurations["system_name"] = SystemLoader.system_name(config_data)
```

### DataTide Configuration

Update `DataTide.Configurations.Systems.SystemName` to use `TideLoader` pipeline instead of raw dict passthrough. Add cases in `load_platform_config()` and `load_tenants_config()`.

## 3. Deployment (`deployment.py`)

Add/uncomment the system in both resolver methods:
```python
# system_configuration_resolver
case DetectionSystems.SYSTEM_NAME:
    return DataTide.Configurations.Systems.SystemName

# mdr_configuration_resolver
case DetectionSystems.SYSTEM_NAME:
    return mdr.configurations.system_name
```

## 4. TOML Config

Add new format alongside legacy:
```toml
# === New MDRv4 Format ===
[platform]
enabled = false

[[tenants]]
name = "tenant_name"
# tenant-specific config

[[modifiers]]
# deployment modifiers

# === Legacy Format (deprecated) ===
[tide]
enabled = false
[setup]
# legacy setup fields
[secrets]
# legacy secrets
```

## 5. Deployer

### Dual Deploy Signature

```python
def deploy(self,
           deployment: list[str] = None,           # MDRv3
           mdr_deployment: Sequence = None,         # MDRv4
           deployment_plan: DeploymentStrategy = None):  # MDRv4
    if mdr_deployment is not None:
        self.deploy_mdr_v4(mdr_deployment, deployment_plan)
    else:
        # Legacy MDRv3 path
        for uuid in deployment:
            data = DataTide.Models.MDR[uuid]
            self.deploy_mdr(data)
```

### MDRv4 Deploy Method

```python
def deploy_mdr_v4(self, mdr_deployment, deployment_plan):
    for mdr in mdr_deployment:
        config = mdr.configurations.system_name  # Typed access
        # Use typed attributes instead of dict access
```

## Deprecation Breadcrumbs

Mark all legacy code paths with:
```python
# TODO: DEPRECATED [system-mdrv4] — Remove after full migration
```

## Key Principles

1. **Never break existing deployments** — legacy dict path must remain functional
2. **Schema version gates typed parsing** — only parse to typed when schema declares v3.0+
3. **Dual TOML format** — new `[platform]`/`[[tenants]]` coexists with `[tide]`/`[setup]`/`[secrets]`
4. **Fix existing bugs** — e.g. wrong tenant references in `TenantDeployment`
5. **Test both paths** — ensure v3 dict access and v4 typed access both work
