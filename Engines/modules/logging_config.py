"""CoreTide logging bootstrap — structlog with Rich or JSON rendering."""

from __future__ import annotations

import logging
import os
import sys
from functools import lru_cache
from typing import Any

import structlog
from rich.console import Console
from rich.theme import Theme

CORETIDE_THEME = Theme(
    {
        "info": "blue",
        "success": "green",
        "warning": "yellow",
        "error": "bold red",
        "critical": "bold white on red",
        "ongoing": "yellow",
        "skip": "cyan",
        "debug": "dim magenta",
        "title": "bold magenta",
        "detail": "magenta",
        "advice": "cyan",
        "brand.core": "bold blue",
        "brand.tide": "bold yellow",
        "muted": "dim",
    }
)

_CATEGORY_STYLES: dict[str, tuple[str, str]] = {
    "ONGOING": ("ongoing", "ONGOING"),
    "SUCCESS": ("success bold", "SUCCESS"),
    "WARNING": ("warning bold", "WARNING"),
    "INFO": ("info", "INFO"),
    "FAILURE": ("error", "FAILURE"),
    "FATAL": ("critical", "FATAL ERROR"),
    "DEBUG": ("debug", "DEBUG"),
    "SKIP": ("skip", "SKIPPED"),
    "TITLE": ("title", "TITLE"),
}

_configured = False


def is_ci_environment() -> bool:
    return bool(
        os.getenv("GITHUB_ACTIONS")
        or os.getenv("GITLAB_CI")
        or os.getenv("TF_BUILD")
        or (os.getenv("CI") and not os.getenv("TIDE_DEBUG_ENABLED"))
    )


def is_plain_output() -> bool:
    """Use plain text when IDE panels or debug mode cannot render Rich."""
    return bool(
        os.getenv("TIDE_DEBUG_ENABLED")
        or os.environ.get("TERM_PROGRAM") == "vscode"
    )


@lru_cache(maxsize=2)
def get_console(*, plain: bool) -> Console:
    return Console(
        theme=CORETIDE_THEME,
        force_terminal=not plain,
        no_color=plain,
        highlight=False,
        width=100,
    )


def get_category_style(category: str) -> tuple[str, str]:
    return _CATEGORY_STYLES.get(category, ("", category))


def _plain_renderer(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> str:
    category = str(event_dict.pop("category", "INFO"))
    message = str(event_dict.pop("event", ""))
    highlight = str(event_dict.pop("detail", "") or "")
    advice = str(event_dict.pop("advice", "") or "")

    style, header = get_category_style(category)
    del style

    if category == "TITLE":
        width = 80
        padded = f" {message} ".center(width, "~")
        lines = ["", padded, ""]
    elif category == "FATAL":
        lines = [f"[{header}] {message}"]
        if highlight:
            lines.append(f"  Detail: {highlight}")
        if advice:
            lines.append(f"  Advice: {advice}")
        lines = ["", *lines, ""]
    else:
        lines = [f"[{header}] {message}"]
        if highlight:
            lines.append(f"  Detail: {highlight}")
        if advice:
            lines.append(f"  Advice: {advice}")

    event_dict.clear()
    return "\n".join(lines)


def _rich_renderer(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> str:
    from rich import box
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.tree import Tree

    category = str(event_dict.pop("category", "INFO"))
    message = str(event_dict.pop("event", ""))
    highlight = str(event_dict.pop("detail", "") or "")
    advice = str(event_dict.pop("advice", "") or "")
    console = get_console(plain=is_plain_output())

    with console.capture() as capture:
        if category == "TITLE":
            console.print()
            console.print(Rule(f" {message} ", style="title", characters="~"))
            console.print()
        elif category == "FATAL":
            body = message
            if highlight:
                body += f"\n\n[detail]Detail[/detail]\n{highlight}"
            if advice:
                body += f"\n\n[advice]Advice[/advice]\n{advice}"
            console.print(
                Panel(
                    body,
                    title="[critical]FATAL ERROR[/critical]",
                    border_style="red",
                    box=box.DOUBLE_EDGE,
                    padding=(1, 2),
                    width=82,
                )
            )
        else:
            style, header = get_category_style(category)
            if highlight or advice:
                tree = Tree(f"[{style}][{header}][/] {message}")
                if highlight:
                    detail_branch = tree.add("[detail]Detail[/detail]")
                    detail_branch.add(highlight)
                if advice:
                    advice_branch = tree.add("[advice]Advice[/advice]")
                    advice_branch.add(advice)
                console.print(tree)
            else:
                console.print(f"[{style}][{header}][/] {message}")

    event_dict.clear()
    return capture.get()


def _json_renderer(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> str:
    import json

    payload = {
        "timestamp": event_dict.pop("timestamp", None),
        "level": event_dict.pop("level", "info"),
        "category": event_dict.pop("category", "INFO"),
        "event": event_dict.pop("event", ""),
    }
    for key in ("detail", "advice"):
        value = event_dict.pop(key, None)
        if value:
            payload[key] = value
    event_dict.clear()
    return json.dumps(payload, default=str)


def _dispatch_renderer(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> str:
    if is_ci_environment():
        return _json_renderer(logger, method_name, event_dict)
    if is_plain_output():
        return _plain_renderer(logger, method_name, event_dict)
    return _rich_renderer(logger, method_name, event_dict)


def configure_logging() -> None:
    global _configured
    if _configured:
        return

    log_level = logging.DEBUG if os.getenv("TIDE_DEBUG_ENABLED") else logging.INFO

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        _dispatch_renderer,
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    _configured = True


def get_logger(name: str = "coretide"):
    configure_logging()
    return structlog.get_logger(name)
