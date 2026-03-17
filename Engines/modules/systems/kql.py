from typing import Optional, Sequence, Union

from Engines.modules.logs import log
from Engines.modules.models import TideModels

MDE_Exclusion = TideModels.MDR.Configurations.DefenderForEndpoint.Exclusion
Sentinel_Exclusion = TideModels.MDR.Configurations.Sentinel.Exclusion
KQLExclusion = Union[MDE_Exclusion, Sentinel_Exclusion]


def compile_kql_query(
    base_query: str,
    exclusions: Optional[Sequence[KQLExclusion]],
    tenant: str,
) -> str:
    """Compile a KQL query by prepending let statements and appending exclusion filters.

    Iterates through the provided exclusions and, for each one that matches the
    given tenant (or has no tenant specified), collects its ``let`` variable
    assignments and its filter fragment.  Let statements are prepended to the
    base query in the order they appear; exclusion filter fragments are appended
    in the same order.

    If the same variable name is declared across multiple exclusions, the last
    definition takes precedence (last-write-wins) to prevent duplicate ``let``
    declarations which would cause a KQL compile error.

    Args:
        base_query: The base KQL query string to build upon.
        exclusions: A sequence of exclusion objects exposing ``tenant``,
            ``let``, and ``query`` attributes, or ``None`` when there are no
            exclusions to apply.
        tenant: The name of the tenant being deployed to.

    Returns:
        The compiled KQL query string with applicable let statements prepended
        and exclusion filter fragments appended.
    """
    # Use a dict to map variable names to their pre-formatted KQL literals.
    # Dict order (Python 3.7+) preserves declaration order; later definitions
    # for the same variable name overwrite earlier ones (last-write-wins) to
    # prevent duplicate KQL let declarations, which would be a compile error.
    let_kql_literals: dict[str, str] = {}
    exclusion_queries: list[str] = []

    if exclusions:
        for exclusion in exclusions:
            if (exclusion.tenant == tenant) or (not exclusion.tenant):
                log("INFO", "Applying exclusion", exclusion.query)
                exclusion_queries.append(exclusion.query)

                if exclusion.let:
                    for variable, value in exclusion.let.items():
                        if isinstance(value, bool):
                            formatted_value = "true" if value else "false"
                        elif isinstance(value, (int, float)):
                            formatted_value = str(value)
                        elif isinstance(value, str):
                            formatted_value = f'"{value}"'
                        else:
                            log("WARNING",
                                f"Unsupported type for KQL let variable '{variable}'",
                                f"Got {type(value).__name__}, expected str, int, float or bool — skipping")
                            continue
                        let_kql_literals[variable] = formatted_value

    let_statements = []
    for var, val in let_kql_literals.items():
        statement = f"let {var} = {val};"
        log("INFO", "Applying let statement", statement)
        let_statements.append(statement)

    query = base_query
    if let_statements:
        query = "\n".join(let_statements) + "\n" + query
    if exclusion_queries:
        query = query + "\n" + "\n".join(exclusion_queries)

    return query
