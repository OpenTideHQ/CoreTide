"""
KQL (Kusto Query Language) query analysis utilities for MDE custom
detection rule validation.

Provides static analysis of KQL query pipelines to verify that required
output columns are preserved through schema-modifying operators such as
``project``, ``project-away``, ``summarize``, and ``distinct``.

Reference
---------
https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules
    "For Microsoft Defender for Endpoint tables, the Timestamp, DeviceId,
    and ReportId columns must appear in the same event"
"""

import re

# Required output columns for MDE custom detection rules
MDE_REQUIRED_COLUMNS = frozenset({"Timestamp", "DeviceId", "ReportId"})


def _normalize_kql(query: str) -> str:
    """Remove comments and normalize a KQL query for analysis."""
    query = re.sub(r"//.*?$", "", query, flags=re.MULTILINE)
    query = re.sub(r"/\*.*?\*/", "", query, flags=re.DOTALL)
    return query


def _extract_main_query(query: str) -> str:
    """Extract the main query body, stripping any leading ``let`` statements."""
    statements = [s.strip() for s in query.split(";") if s.strip()]
    if not statements:
        return query
    for stmt in reversed(statements):
        if not re.match(r"\blet\b", stmt, re.IGNORECASE):
            return stmt
    return statements[-1]


def _split_respecting_nesting(text: str, delimiter: str) -> list[str]:
    """Split *text* by *delimiter*, respecting string literals and parentheses."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    string_char = ""

    for ch in text:
        if in_string:
            current.append(ch)
            if ch == string_char:
                in_string = False
        elif ch in ('"', "'"):
            in_string = True
            string_char = ch
            current.append(ch)
        elif ch in ("(", "["):
            depth += 1
            current.append(ch)
        elif ch in (")", "]"):
            depth -= 1
            current.append(ch)
        elif ch == delimiter and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    remainder = "".join(current).strip()
    if remainder:
        parts.append(remainder)
    return parts


def _split_kql_pipeline(query: str) -> list[str]:
    """Split a KQL query into pipeline stages by top-level pipe operators."""
    return _split_respecting_nesting(query, "|")


def _extract_output_columns(clause: str) -> set[str]:
    """
    Extract output column names from a KQL project/summarize/distinct clause.

    Handles:
      - Simple column references: ``Timestamp`` → ``Timestamp``
      - Alias expressions: ``Count = count()`` → ``Count``
    """
    columns: set[str] = set()
    parts = _split_respecting_nesting(clause, ",")

    for part in parts:
        part = part.strip()
        if not part:
            continue
        alias_match = re.match(r"(\w+)\s*=", part)
        if alias_match:
            columns.add(alias_match.group(1))
        else:
            col_match = re.match(r"(\w+)", part)
            if col_match:
                columns.add(col_match.group(1))
    return columns


def validate_mde_required_columns(query: str) -> tuple[bool, list[str]]:
    """
    Validate that an MDE custom detection KQL query preserves the required
    ``Timestamp``, ``DeviceId``, and ``ReportId`` columns in its output.

    Traces through the KQL pipeline operators that modify the output schema
    (``project``, ``project-away``, ``project-keep``, ``project-rename``,
    ``extend``, ``summarize``, ``distinct``) and tracks whether each required
    column remains available.

    Returns:
        A tuple of ``(is_valid, missing_columns)`` where *missing_columns*
        lists the required column names that are absent from the query output.
    """
    query = _normalize_kql(query)
    query = _extract_main_query(query)
    stages = _split_kql_pipeline(query)

    # All MDE source tables natively contain the required columns
    required_available: dict[str, bool] = {col: True for col in MDE_REQUIRED_COLUMNS}

    for stage in stages[1:]:  # Skip first stage (table name)
        stage_stripped = stage.strip()
        operator_match = re.match(r"([\w-]+)\s*(.*)", stage_stripped, re.DOTALL)
        if not operator_match:
            continue

        operator = operator_match.group(1).lower()
        clause = operator_match.group(2).strip()

        if operator in ("project", "project-keep"):
            output_cols = _extract_output_columns(clause)
            for col in MDE_REQUIRED_COLUMNS:
                required_available[col] = col in output_cols

        elif operator == "project-away":
            removed_cols = _extract_output_columns(clause)
            for col in MDE_REQUIRED_COLUMNS:
                if col in removed_cols:
                    required_available[col] = False

        elif operator == "project-rename":
            for part in _split_respecting_nesting(clause, ","):
                rename_match = re.match(r"(\w+)\s*=\s*(\w+)", part.strip())
                if rename_match:
                    new_name, old_name = rename_match.group(1), rename_match.group(2)
                    if old_name in MDE_REQUIRED_COLUMNS:
                        required_available[old_name] = False
                    if new_name in MDE_REQUIRED_COLUMNS:
                        required_available[new_name] = True

        elif operator == "extend":
            extended_cols = _extract_output_columns(clause)
            for col in MDE_REQUIRED_COLUMNS:
                if col in extended_cols:
                    required_available[col] = True

        elif operator == "summarize":
            by_parts = re.split(r"\bby\b", clause, maxsplit=1, flags=re.IGNORECASE)
            output_cols: set[str] = set()
            for part in by_parts:
                output_cols |= _extract_output_columns(part)
            for col in MDE_REQUIRED_COLUMNS:
                required_available[col] = col in output_cols

        elif operator == "distinct":
            output_cols = _extract_output_columns(clause)
            for col in MDE_REQUIRED_COLUMNS:
                required_available[col] = col in output_cols

    missing = sorted(col for col, avail in required_available.items() if not avail)
    return (len(missing) == 0, missing)
