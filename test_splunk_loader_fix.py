"""Isolated reproduction test for SystemLoader.splunk() flat v2.x normalization."""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path
from typing import Any

from Engines.modules.models import TideDefinitionsModels, TideModels

ROOT = Path(__file__).resolve().parent
TIDE_PY = ROOT / "Engines/modules/tide.py"


def _base_configuration(mdr_config: dict[str, Any]):
    schema = mdr_config.pop("schema", None)
    status = mdr_config.pop("status", None)
    tenants = mdr_config.pop("tenants", None)
    flags = mdr_config.pop("flags", None)
    contributors = mdr_config.pop("contributors", None)
    base = TideDefinitionsModels.SystemConfigurationModel(
        schema=schema, tenants=tenants, status=status, flags=flags, contributors=contributors
    )
    return mdr_config, base


class _SystemLoaderStub:
    _base_configuration = staticmethod(_base_configuration)


def _load_splunk_method():
    source = TIDE_PY.read_text()
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "SystemLoader":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "splunk":
                    return item
    raise RuntimeError("SystemLoader.splunk not found")


def _make_splunk_loader():
    func_def = _load_splunk_method()
    module_src = "class SystemLoader:\n" + textwrap.indent(ast.unparse(func_def), "    ")
    namespace: dict[str, Any] = {
        "Any": Any,
        "TideModels": TideModels,
        "SystemLoader": _SystemLoaderStub,
    }
    exec(compile(module_src, str(TIDE_PY), "exec"), namespace)
    namespace["SystemLoader"]._base_configuration = _SystemLoaderStub._base_configuration
    return namespace["SystemLoader"].splunk


splunk = _make_splunk_loader()


def test_source_has_no_duplicate_trigger_pop() -> None:
    splunk_source = ast.get_source_segment(TIDE_PY.read_text(), _load_splunk_method()) or ""
    trigger_pops = re.findall(r"""mdr_config\.pop\(['"]trigger['"]""", splunk_source)
    assert len(trigger_pops) == 1


def test_source_initializes_scheduling() -> None:
    splunk_source = ast.get_source_segment(TIDE_PY.read_text(), _load_splunk_method()) or ""
    assert "scheduling = None" in splunk_source


def test_flat_v2x_trigger_and_actions_preserved() -> None:
    mdr_config = {
        "schema": "splunk::2.0",
        "status": "production",
        "query": "index=main | stats count",
        "throttling": {"duration": "5m", "fields": ["src_ip"]},
        "threshold": 10,
        "notable": {
            "security_domain": "endpoint",
            "event": {"title": "Test Alert"},
        },
    }

    result = splunk(mdr_config)

    assert result.trigger is not None
    assert result.trigger.throttling is not None
    assert result.trigger.threshold == 10
    assert result.actions is not None
    assert result.actions.notable is not None
    assert result.actions.notable.security_domain == "endpoint"


def test_missing_scheduling_no_unbound_local_error() -> None:
    mdr_config = {
        "schema": "splunk::2.0",
        "status": "production",
        "query": "index=main | stats count",
    }

    result = splunk(mdr_config)
    assert result.scheduling is None
    assert result.query == "index=main | stats count"


if __name__ == "__main__":
    test_source_has_no_duplicate_trigger_pop()
    test_source_initializes_scheduling()
    test_flat_v2x_trigger_and_actions_preserved()
    test_missing_scheduling_no_unbound_local_error()
    print("All tests passed.")
