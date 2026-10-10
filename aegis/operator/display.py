from __future__ import annotations

import json
import sys

from aegis.cli_support import terminal_text

from .common import (
    redact,
)

try:
    from rich.console import Console
    from rich.json import JSON
    from rich.panel import Panel
    from rich.theme import Theme

    console = Console(
        theme=Theme(
            {
                "info": "bold #8b5cf6",
                "warning": "bold yellow",
                "danger": "bold #dc143c",
                "verified": "bold #50c878",
                "quarantine": "bold #dc143c",
                "step": "bold cyan",
            }
        ),
        force_terminal=True,
    )
    has_rich = True
except ImportError:
    has_rich = False
    console = None


def print_result(value, *, json_output=False, plain=False, console=console, has_rich=has_rich):
    redacted = redact(value)
    if json_output:
        print(json.dumps(redacted, ensure_ascii=True, separators=(",", ":")))
    elif isinstance(value, dict) and value.get("kind") == "guide":
        print(terminal_text(value["title"]))
        print(terminal_text(value.get("reference", "")))
        for index, step in enumerate(value.get("steps", []), 1):
            print(f"{index}. {terminal_text(step)}")
    elif isinstance(value, dict) and value.get("kind") == "diagnostics":
        print(terminal_text(f"Aegis doctor | {value['status']} | {value['api_url']}"))
        for check in redacted["checks"]:
            print(terminal_text(f"[{check['status']}] {check['check']}: {check['detail']}"))
            if check["status"] != "PASS":
                print(terminal_text("  Next: " + check["next_step"]))
        print(terminal_text(value["scope"]))
    elif has_rich and not plain and sys.stdout.isatty():
        from rich.text import Text

        if isinstance(value, dict) and "patch" in value and isinstance(value["patch"], str):
            console.print(
                Panel(
                    Text(terminal_text(redacted["patch"])),
                    title="Generated Patch",
                    border_style="#50c878",
                )
            )
            v2 = {k: v for k, v in redacted.items() if k != "patch"}
            if v2:
                console.print(JSON(json.dumps(v2)))
        elif isinstance(value, dict) and "answer" in value and isinstance(value["answer"], str):
            from rich.markdown import Markdown

            console.print(Markdown(terminal_text(redacted["answer"])))
            v2 = {k: v for k, v in redacted.items() if k != "answer"}
            if v2:
                console.print(JSON(json.dumps(v2)))
        else:
            console.print(JSON(json.dumps(redacted)))
    else:
        print(json.dumps(redacted, indent=2, ensure_ascii=True))
