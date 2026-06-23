"""CoreTide console logging — structlog backend with Rich rendering."""

from __future__ import annotations

import os
from typing import Literal

from rich.text import Text

from Engines.modules.logging_config import (
    configure_logging,
    get_console,
    get_logger,
    is_ci_environment,
    is_plain_output,
)

LogCategory = Literal[
    "ONGOING",
    "SUCCESS",
    "WARNING",
    "INFO",
    "FAILURE",
    "FATAL",
    "DEBUG",
    "SKIP",
    "TITLE",
]

_CORETIDE_ASCII = """
            :--==-:.
         -+*###*####*+:
       -=:   .:  =-*##*.
     -=.  .:.     .+.*=:+
  .-+:  .-:  :  .-- :  .
+*#+   -=.  -:  : :=              The engine powering OpenTIDE Instances
#*-  .==.  :=  .-  +            Part of the OpenThreat Informed Detection Engineering Initiative
:   :==:   =-  .=. .+
   :==-   :=-   --  .+:
  :===.   ==-   :=-   :=-
 .====    ===.   -=-.
""".strip("\n")


def log(
    category: LogCategory,
    message: str,
    highlight: str = "",
    advice: str = "",
    icon: str = "",
) -> None:
    del icon  # legacy parameter, intentionally unused

    if category == "DEBUG" and not os.getenv("TIDE_DEBUG_ENABLED"):
        return

    configure_logging()

    payload: dict[str, str] = {"category": category}
    if highlight:
        payload["detail"] = str(highlight)
    if advice:
        payload["advice"] = str(advice)

    logger = get_logger()
    logger.info(str(message), **payload)


def section_header(title: str) -> None:
    if is_ci_environment() or is_plain_output():
        print(f"\n{title}\n", flush=True)
        return

    console = get_console(plain=is_plain_output())
    console.print()
    console.print(Text(title, style="bold italic blue"))
    console.print()


def coretide_intro() -> str:
    """Return the CoreTide ASCII banner (plain text for compatibility)."""
    return _CORETIDE_ASCII


def print_banner(subtitle: str | None = None) -> None:
    """Print the CoreTide intro banner and optional section subtitle."""
    configure_logging()
    if is_ci_environment() or is_plain_output():
        print(_CORETIDE_ASCII, flush=True)
        if subtitle:
            section_header(subtitle)
        return

    console = get_console(plain=False)
    lines = _CORETIDE_ASCII.split("\n")
    console.print()
    for index, line in enumerate(lines):
        if index == 3:
            console.print(
                Text.assemble(
                    (line[:6], "brand.core"),
                    (line[6:22], "brand.tide"),
                    (line[22:], "brand.core"),
                    ("    Powered by ", "bold"),
                    ("Core", "brand.core"),
                    ("TIDE", "brand.tide"),
                )
            )
        elif index in (4, 5):
            console.print(Text(line, style="muted italic"))
        elif index == 6:
            console.print(
                Text.assemble(
                    (line, "brand.core"),
                    ("    https://code.europa.eu/ec-digit-s2/opentide/coretide", "muted"),
                )
            )
        else:
            console.print(Text(line, style="brand.core"))
    console.print()

    if subtitle:
        section_header(subtitle)
