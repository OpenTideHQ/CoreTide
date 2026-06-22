"""Regression tests for Splunk and Carbon Black Cloud MDRv4 SystemLoader paths."""

from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

from Engines.modules.models import TideModels
from Engines.modules.tide import SystemLoader, TideLoader


def _splunk_base(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "schema": "splunk::2.1",
        "status": "staging",
        "flags": None,
        "tenants": ["default"],
        "contributors": None,
        "query": "index=main | stats count by host",
    }
    config.update(overrides)
    return config


def _cbc_base(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "schema": "carbon_black_cloud::4.0",
        "status": "staging",
        "flags": None,
        "tenants": ["default"],
        "contributors": None,
        "query": "process_name:cmd.exe",
        "organizations": ["org-a"],
        "watchlist": "wl-123",
        "tags": ["attack.execution"],
    }
    config.update(overrides)
    return config


def _minimal_mdr(system_key: str, system_config: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Test MDR",
        "description": "Regression fixture",
        "metadata": {
            "uuid": "00000000-0000-4000-8000-000000000099",
            "schema": "mdr::1.0",
            "version": 1,
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "tlp": "clear",
        },
        "response": {},
        "references": {},
        "configurations": {system_key: system_config},
    }


class TestSystemLoaderSplunk(unittest.TestCase):
    def test_flat_v2_trigger_and_actions_normalised(self) -> None:
        raw = _splunk_base(
            throttling={"fields": ["host"], "duration": "1h", "group_name": "grp"},
            threshold=5,
            notable={"security_domain": "access"},
        )

        result = SystemLoader.splunk(deepcopy(raw))

        self.assertIsInstance(result, TideModels.MDR.Configurations.Splunk)
        self.assertIsNotNone(result.trigger)
        assert result.trigger is not None
        self.assertEqual(result.trigger.threshold, 5)
        self.assertIsNotNone(result.trigger.throttling)
        assert result.trigger.throttling is not None
        self.assertEqual(result.trigger.throttling.fields, ["host"])
        self.assertIsNotNone(result.actions)
        assert result.actions is not None
        self.assertIsNotNone(result.actions.notable)
        assert result.actions.notable is not None
        self.assertEqual(result.actions.notable.security_domain, "access")

    def test_scheduling_absent_is_none(self) -> None:
        raw = _splunk_base(threshold=1)

        result = SystemLoader.splunk(deepcopy(raw))

        self.assertIsNone(result.scheduling)

    def test_flat_v2_scheduling_normalised(self) -> None:
        raw = _splunk_base(
            scheduling={
                "frequency": "15m",
                "lookback": "1h",
            }
        )

        result = SystemLoader.splunk(deepcopy(raw))

        self.assertIsNotNone(result.scheduling)
        assert result.scheduling is not None
        self.assertIsNotNone(result.scheduling.schedule)
        assert result.scheduling.schedule is not None
        self.assertEqual(result.scheduling.schedule.frequency, "15m")
        self.assertIsNotNone(result.scheduling.timerange)
        assert result.scheduling.timerange is not None
        self.assertEqual(result.scheduling.timerange.lookback, "1h")

    def test_nested_trigger_not_double_popped(self) -> None:
        """Explicit trigger/actions must survive when already nested (no duplicate pop bug)."""
        raw = _splunk_base(
            trigger={
                "threshold": 10,
                "throttling": {"fields": ["src_ip"], "duration": "30m"},
            },
            actions={"notable": {"security_domain": "endpoint"}},
        )

        result = SystemLoader.splunk(deepcopy(raw))

        assert result.trigger is not None
        self.assertEqual(result.trigger.threshold, 10)
        assert result.actions is not None
        assert result.actions.notable is not None
        self.assertEqual(result.actions.notable.security_domain, "endpoint")


class TestSystemLoaderCarbonBlackCloud(unittest.TestCase):
    def test_typed_configuration(self) -> None:
        raw = _cbc_base(rule_id_bundle={"default": "rule-42"})

        result = SystemLoader.carbon_black_cloud(deepcopy(raw))

        self.assertIsInstance(result, TideModels.MDR.Configurations.CarbonBlackCloud)
        self.assertEqual(result.query, "process_name:cmd.exe")
        self.assertEqual(result.organizations, ["org-a"])
        self.assertEqual(result.watchlist, "wl-123")
        self.assertEqual(result.tags, ["attack.execution"])
        self.assertEqual(result.rule_id_bundle, {"default": "rule-42"})

    def test_organization_alias(self) -> None:
        raw = _cbc_base()
        raw.pop("organizations")
        raw["organization"] = ["legacy-org"]

        result = SystemLoader.carbon_black_cloud(raw)

        self.assertEqual(result.organizations, ["legacy-org"])


class TestLoadMdrRouting(unittest.TestCase):
    def test_load_mdr_routes_splunk(self) -> None:
        mdr = _minimal_mdr("splunk", _splunk_base(threshold=3, notable={"security_domain": "threat"}))

        loaded = TideLoader.load_mdr(deepcopy(mdr))

        self.assertIsNotNone(loaded.configurations.splunk)
        assert loaded.configurations.splunk is not None
        self.assertIsInstance(loaded.configurations.splunk, TideModels.MDR.Configurations.Splunk)
        assert loaded.configurations.splunk.trigger is not None
        self.assertEqual(loaded.configurations.splunk.trigger.threshold, 3)

    def test_load_mdr_routes_carbon_black_cloud(self) -> None:
        mdr = _minimal_mdr("carbon_black_cloud", _cbc_base())

        loaded = TideLoader.load_mdr(deepcopy(mdr))

        self.assertIsNotNone(loaded.configurations.carbon_black_cloud)
        cbc = loaded.configurations.carbon_black_cloud
        self.assertIsInstance(cbc, TideModels.MDR.Configurations.CarbonBlackCloud)
        assert isinstance(cbc, TideModels.MDR.Configurations.CarbonBlackCloud)
        self.assertEqual(cbc.query, "process_name:cmd.exe")

    def test_load_mdr_empty_response_defaults(self) -> None:
        mdr = _minimal_mdr("splunk", _splunk_base())

        loaded = TideLoader.load_mdr(deepcopy(mdr))

        self.assertIsInstance(loaded.response, TideModels.MDR.Response)
        self.assertEqual(loaded.response.alert_severity, "Informational")


class TestDeployBackwardCompat(unittest.TestCase):
    def test_deploy_signatures_support_v3_and_v4(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        splunk_source = (repo_root / "Engines/deployment/splunk.py").read_text()
        cbc_source = (repo_root / "Engines/deployment/carbon_black_cloud.py").read_text()

        self.assertIn("deployment: list[str] | None = None", splunk_source)
        self.assertIn("mdr_deployment: Sequence[TideModels.MDR] | list[str] | None = None", splunk_source)
        self.assertIn("if deployment is not None and mdr_deployment is None:", splunk_source)

        self.assertIn("deployment: Optional[list[str]] = None", cbc_source)
        self.assertIn("mdr_deployment: Optional[Sequence[TideModels.MDR]] = None", cbc_source)

    def test_splunk_deploy_accepts_legacy_v3_signature(self) -> None:
        from Engines.deployment.splunk import SplunkDeploy

        deployer = SplunkDeploy()
        with patch.object(deployer, "deploy_legacy") as legacy:
            deployer.deploy(deployment=["uuid-1"])
            legacy.assert_called_once_with(["uuid-1"])


if __name__ == "__main__":
    unittest.main()
