---
description: "Use when writing or reviewing Python code in the CoreTide project. Covers Python best practices, type safety, security, and code quality standards specific to this codebase."
applyTo: "**/*.py"
---

# Python Code Quality

## Type Safety

- Use type hints on all function signatures and return types
- Prefer `Sequence` over `list`, `Mapping` over `dict` for input parameters
- Use `Optional[T]` for nullable values; never use `T | None` syntax to maintain 3.10 compat
- Use `@overload` for functions with polymorphic signatures
- Frozen dataclasses (`frozen=True`) for immutable data structures

## Security

- Never log secrets or API keys — use `HelperTide.fetch_config_envvar()` for secret resolution
- Validate all external input at system boundaries (API responses, user YAML, TOML configs)
- Use parameterised queries/API calls — never string-concatenate untrusted input into queries
- SSL verification should default to enabled; only disable with explicit configuration

## Error Handling

- Never use bare `except:` — always catch specific exception types
- Use the `TideErrors` hierarchy from `Engines/modules/errors.py`
- Log failures with `log("FATAL", ...)` before raising
- System-specific errors: `DetectionRuleCreationFailed`, `DetectionRuleUpdateFailed`, `TenantConnectionError`

## Logging

- Always use `log(LEVEL, *messages)` from `Engines/modules/logs.py`
- Never use `print()` for operational output
- Choose appropriate levels: `INFO` for progress, `SUCCESS` for completions, `WARNING` for non-fatal issues, `FATAL` for blocking errors

## British English

- Use British spelling throughout: favour, realise, colour, behaviour, initialise, organisation
- This applies to code comments, log messages, documentation, and variable names where English words are used

## Imports

- Use absolute imports from repository root: `from Engines.modules.tide import DataTide`
- Include the standard git-root path setup at the top of executable scripts:
  ```python
  import sys, git
  sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))
  ```
