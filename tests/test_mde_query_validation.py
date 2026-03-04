"""
Tests for MDE (Microsoft Defender for Endpoint) custom detection query
validation. Validates that required columns (Timestamp, DeviceId, ReportId)
are preserved through the KQL pipeline.

Reference: https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from Engines.validation.kql import (
    MDE_REQUIRED_COLUMNS,
    validate_mde_required_columns,
    _normalize_kql,
    _extract_main_query,
    _split_kql_pipeline,
    _extract_output_columns,
)


# ---------------------------------------------------------------------------
# Helper constants
# ---------------------------------------------------------------------------
VALID = True
INVALID = False


# ---------------------------------------------------------------------------
# Tests: validate_mde_required_columns – valid queries
# ---------------------------------------------------------------------------
class TestValidQueries:
    """Queries that should pass required-column validation."""

    def test_simple_table_no_project(self):
        """MDE tables contain required columns by default."""
        query = """DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessName == "cmd.exe"
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_project_with_all_required_columns(self):
        query = """DeviceProcessEvents
| where ProcessName == "cmd.exe"
| project Timestamp, DeviceId, ReportId, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_project_with_extra_columns(self):
        query = """DeviceNetworkEvents
| project Timestamp, DeviceId, ReportId, RemoteIP, RemotePort
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_extend_does_not_remove_columns(self):
        query = """DeviceProcessEvents
| extend Risk = "High"
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_project_away_unrelated_columns(self):
        query = """DeviceProcessEvents
| project-away InitiatingProcessSHA256
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_where_and_sort_preserve_columns(self):
        query = """DeviceProcessEvents
| where Timestamp > ago(24h)
| sort by Timestamp desc
| take 100
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_summarize_with_all_required_columns(self):
        query = """DeviceProcessEvents
| summarize Count = count() by Timestamp, DeviceId, ReportId
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_distinct_with_all_required_columns(self):
        query = """DeviceProcessEvents
| distinct Timestamp, DeviceId, ReportId, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_project_rename_unrelated_column(self):
        query = """DeviceProcessEvents
| project-rename Process = ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_project_reorder_preserves_columns(self):
        query = """DeviceProcessEvents
| project-reorder Timestamp, DeviceId
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_let_statement_before_main_query(self):
        query = """let lookback = 1h;
DeviceProcessEvents
| where Timestamp > ago(lookback)
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_extend_restores_after_project(self):
        """An extend can re-add columns removed by a prior project."""
        query = """DeviceProcessEvents
| project ProcessName, Timestamp
| extend DeviceId = "restored", ReportId = "restored"
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_project_keep_with_all_required(self):
        query = """DeviceProcessEvents
| project-keep Timestamp, DeviceId, ReportId, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []

    def test_multiline_project_with_required_columns(self):
        query = """DeviceProcessEvents
| project
    Timestamp,
    DeviceId,
    ReportId,
    ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True
        assert missing == []


# ---------------------------------------------------------------------------
# Tests: validate_mde_required_columns – invalid queries
# ---------------------------------------------------------------------------
class TestInvalidQueries:
    """Queries that should fail required-column validation."""

    def test_project_missing_all_required(self):
        query = """DeviceProcessEvents
| project ProcessName, FileName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId", "ReportId"}

    def test_project_missing_device_id(self):
        query = """DeviceProcessEvents
| project Timestamp, ReportId, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert missing == ["DeviceId"]

    def test_project_missing_timestamp(self):
        query = """DeviceProcessEvents
| project DeviceId, ReportId, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert missing == ["Timestamp"]

    def test_project_missing_report_id(self):
        query = """DeviceProcessEvents
| project Timestamp, DeviceId, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert missing == ["ReportId"]

    def test_project_away_removes_timestamp(self):
        query = """DeviceProcessEvents
| project-away Timestamp
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert missing == ["Timestamp"]

    def test_project_away_removes_multiple_required(self):
        query = """DeviceProcessEvents
| project-away Timestamp, DeviceId
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId"}

    def test_summarize_without_required_columns(self):
        query = """DeviceProcessEvents
| summarize Count = count() by ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId", "ReportId"}

    def test_summarize_partial_required(self):
        query = """DeviceProcessEvents
| summarize Count = count() by Timestamp, ProcessName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"DeviceId", "ReportId"}

    def test_distinct_without_required_columns(self):
        query = """DeviceProcessEvents
| distinct ProcessName, FileName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId", "ReportId"}

    def test_project_rename_renames_required_column(self):
        query = """DeviceProcessEvents
| project-rename TS = Timestamp
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert missing == ["Timestamp"]

    def test_project_keep_missing_required(self):
        query = """DeviceProcessEvents
| project-keep ProcessName, FileName
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId", "ReportId"}

    def test_intermediate_project_removes_columns(self):
        """A project in the middle that removes required columns
        and they are not restored later."""
        query = """DeviceProcessEvents
| project ProcessName
| where ProcessName == "cmd.exe"
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId", "ReportId"}


# ---------------------------------------------------------------------------
# Tests: KQL parsing helpers
# ---------------------------------------------------------------------------
class TestNormalizeKql:
    def test_removes_single_line_comments(self):
        query = "Table // this is a comment\n| where x > 1"
        result = _normalize_kql(query)
        assert "//" not in result
        assert "| where x > 1" in result

    def test_removes_multiline_comments(self):
        query = "Table /* comment\nspanning lines */ | where x > 1"
        result = _normalize_kql(query)
        assert "/*" not in result
        assert "*/" not in result


class TestExtractMainQuery:
    def test_no_let_statements(self):
        query = "DeviceProcessEvents | where x > 1"
        assert _extract_main_query(query) == query

    def test_single_let(self):
        result = _extract_main_query("let x = 1; Table | where y > x")
        assert result == "Table | where y > x"

    def test_multiple_lets(self):
        result = _extract_main_query("let a = 1; let b = 2; Table | project a, b")
        assert result == "Table | project a, b"


class TestSplitKqlPipeline:
    def test_simple_pipeline(self):
        stages = _split_kql_pipeline("Table | where x > 1 | project y")
        assert stages == ["Table", "where x > 1", "project y"]

    def test_pipe_inside_string(self):
        stages = _split_kql_pipeline('Table | where Name == "a|b"')
        assert len(stages) == 2

    def test_pipe_inside_parentheses(self):
        stages = _split_kql_pipeline("Table | where x in (A | project y)")
        assert len(stages) == 2


class TestExtractOutputColumns:
    def test_simple_columns(self):
        cols = _extract_output_columns("Timestamp, DeviceId, ReportId")
        assert cols == {"Timestamp", "DeviceId", "ReportId"}

    def test_alias_expression(self):
        cols = _extract_output_columns("Count = count(), Timestamp")
        assert cols == {"Count", "Timestamp"}

    def test_function_call_without_alias(self):
        cols = _extract_output_columns("count()")
        assert cols == {"count"}

    def test_nested_function(self):
        cols = _extract_output_columns("Name = strcat(First, ', ', Last)")
        assert cols == {"Name"}


# ---------------------------------------------------------------------------
# Tests: edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_comments_hiding_project(self):
        """A commented-out project should not trigger validation failure."""
        query = """DeviceProcessEvents
// | project ProcessName
| where Timestamp > ago(1h)
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True

    def test_pipe_in_string_literal(self):
        query = """DeviceProcessEvents
| where CommandLine contains "| project evil"
| project Timestamp, DeviceId, ReportId
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True

    def test_query_with_join(self):
        """Join without explicit project preserves source columns."""
        query = """DeviceProcessEvents
| join kind=inner (DeviceNetworkEvents) on DeviceId
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True

    def test_project_alias_preserves_required(self):
        """Using required column name as alias is valid."""
        query = """DeviceProcessEvents
| project Timestamp, DeviceId = DeviceName, ReportId
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is True

    def test_case_sensitivity_of_column_names(self):
        """Column names in KQL are case-sensitive."""
        query = """DeviceProcessEvents
| project timestamp, deviceid, reportid
"""
        is_valid, missing = validate_mde_required_columns(query)
        assert is_valid is False
        assert set(missing) == {"Timestamp", "DeviceId", "ReportId"}
