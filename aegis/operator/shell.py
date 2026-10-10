from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys

from aegis import __version__
from aegis.cli_support import terminal_text

from .common import (
    CLIError,
)
from .goal import goal_workflow
from .registration import register_workflow


def compose(client):
    print(
        "Multiline prompt. /preview reviews; /clear resets; /send submits; /cancel discards. Limit: 8000 characters."
    )
    lines = []
    while True:
        try:
            line = input("... ")
        except (EOFError, KeyboardInterrupt):
            print()
            return {"status": "CANCELLED", "model_calls": 0}
        if line == "/cancel":
            return {"status": "CANCELLED", "model_calls": 0}
        if line == "/clear":
            lines.clear()
        elif line == "/preview":
            print(terminal_text("\n".join(lines)) or "(empty)")
        elif line == "/send":
            text = "\n".join(lines)
            if not text.strip():
                print("Prompt is empty. Add text or /cancel.")
                continue
            return client.run(text)
        elif len("\n".join([*lines, line])) > 8000:
            print(
                "That line exceeds the 8000-character limit and was not added. Use /clear or /cancel."
            )
        else:
            lines.append(line)


def run_sovereign_pipeline_ui(
    prompt="Review Pump P-204 vibration readings against engineering SOP", plain=False, client=None
):
    """Explicit fixture only; always use the authenticated, demo-gated API."""
    if prompt != "Review Pump P-204 vibration readings against engineering SOP":
        raise CLIError(
            "The demo accepts its fixed fixture only. Use advisory-run for real source-backed requests."
        )
    if client is None:
        raise CLIError(
            "The demo requires an authenticated local API client and enabled demo endpoints"
        )
    return client.call("/control/demo/run", "POST", {"scenario": "success"})


def shell(client, parser, *, plain=False, context):
    console, has_rich = context.console, context.has_rich
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    styled = has_rich and not plain and interactive
    has_pt = False
    if interactive and not plain:
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.completion import Completer, Completion
            from prompt_toolkit.lexers import PygmentsLexer
            from prompt_toolkit.shortcuts import CompleteStyle
            from prompt_toolkit.styles import Style
            from pygments.lexers.markup import MarkdownLexer

            has_pt = True
        except ImportError:
            pass

    def show_banner():
        if styled:
            from rich.align import Align
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text

            # Aegis-style ASCII art
            from aegis.ui_constants import AEGIS_BANNER, AEGIS_INFO_PANEL, AEGIS_LOGO_RICH

            banner = AEGIS_BANNER
            # Preserve the artwork's own indentation; center the entire block,
            # never its individual lines.
            logo = Text.from_markup(AEGIS_LOGO_RICH, justify="left", overflow="crop")
            logo.no_wrap = True
            info = AEGIS_INFO_PANEL

            term_width = getattr(console, "width", 80) or 80
            if term_width >= 90:
                console.print(banner)
            else:
                console.print("[bold #8b5cf6]=== AEGIS SOVEREIGN AI BROKER ===[/]")

            side_by_side_width = (
                console.measure(logo).maximum + console.measure(Text.from_markup(info)).maximum + 16
            )
            if term_width < side_by_side_width:
                table = Table.grid(padding=(1, 0), expand=True)
                table.add_column(justify="left")
                table.add_row(logo)
                table.add_row(Align.left(info))
                panel_content = table
            else:
                table = Table.grid(padding=(0, 3), expand=False)
                table.add_column(no_wrap=True, justify="left")
                table.add_column(justify="left")
                table.add_row(logo, Align.left(info, vertical="middle"))
                panel_content = table

            panel = Panel(
                panel_content,
                title=f"[dim #8b5cf6]--- Aegis Console v{__version__} - Sovereign AI Broker ---[/]",
                border_style="dim #8b5cf6",
            )
            console.print(panel)
            console.print(
                "[dim info]Welcome to the Aegis operator console. Type /register to sign up, /goal for tasks, or /help for guidance.[/]"
            )
            console.print(
                "[verified]System Status:[/] [dim]All telemetry locked. Use /doctor and /context to inspect active security controls.[/]"
            )
        else:
            print(f"Aegis terminal | {client.url}")
            print(
                "Use /help, /register, /login <actor>, /goal, /doctor, /context, /compose, /clear, /exit."
            )

    show_banner()

    pt_session = None
    if has_pt:

        class SlashCommandCompleter(Completer):
            def __init__(self, commands_dict):
                self.commands = commands_dict

            def get_completions(self, document, complete_event):
                text = document.text_before_cursor
                if text.startswith("/"):
                    word = text.lstrip("/")
                    for cmd, desc in self.commands.items():
                        if cmd.startswith(word):
                            yield Completion(
                                f"/{cmd}",
                                start_position=-len(text),
                                display=f"/{cmd}".ljust(33),
                                display_meta=desc,
                            )

        aegis_commands = {
            "register": "New user registration & onboarding guidance (or sign-up)",
            "signup": "Alias for /register",
            "login": "Sign in locally; password is prompted securely",
            "goal": "Autonomous thorough goal execution & milestone tracking (Antigravity/Codex style)",
            "demo": "Run explicitly enabled deterministic control fixture (Capsule -> Attestation -> RAG -> Cache -> Tripwire -> Receipt)",
            "pipeline": "Run explicitly enabled deterministic control fixture",
            "help": "Guided workflows or exact command arguments",
            "doctor": "Read-only local diagnostics",
            "context": "Inspect identity, selected lease and current incident authorization",
            "compose": "Multiline prompt",
            "shell": "Interactive operator shell",
            "status": "Authentication and local runtime status",
            "logout": "Revoke and clear this servers session",
            "whoami": "Show authenticated identity",
            "state": "Coding workspace state",
            "control-state": "Control plane state",
            "providers": "List local provider profiles",
            "tasks": "List your coding tasks",
            "leases": "List visible coding leases",
            "repositories": "List visible repository snapshots",
            "validate": "Run local negative-case validation",
            "telemetry": "Read measured local telemetry",
            "receipts": "List control receipts",
            "endpoints": "Discover available API endpoints",
            "lockdown": "Inspect or change the Security Officer incident stop",
            "maintenance": "Inspect quotas or archive expired operational records",
            "exit": "Exit the shell",
            "clear": "Clear the terminal screen",
        }

        style = Style.from_dict(
            {
                "completion-menu.completion": "bg:#222222 #eeeeee",
                "completion-menu.completion.current": "bg:#444444 #ffffff bold",
                "completion-menu.meta.completion": "bg:#222222 #888888",
                "completion-menu.meta.completion.current": "bg:#444444 #cccccc",
            }
        )

        command_completer = SlashCommandCompleter(aegis_commands)
        pt_session = PromptSession(
            completer=command_completer, complete_style=CompleteStyle.MULTI_COLUMN, style=style
        )

    while True:
        actor = client.session.value.get("actor", "signed-out")
        selected = client.session.value.get("selected_lease", {})
        label = terminal_text(
            f"{actor} | {selected.get('mode', 'lease')} {selected['id']}"
            if selected.get("id")
            else f"{actor} | no lease"
        )

        try:
            if has_pt:
                cols = shutil.get_terminal_size().columns
                lease_id = selected.get("id", "NOT_SELECTED")
                model_name = selected.get("model", "NOT_SELECTED")
                print(
                    f" 🛡 {model_name} │ Lease: {lease_id} │ Transport: LOCAL_API │ Authorization: USE_CONTEXT"
                )
                print("─" * cols)
                line = pt_session.prompt("❯ ", lexer=PygmentsLexer(MarkdownLexer)).strip()
                print("─" * cols)
            else:
                line = input(f"aegis[{label}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not line:
            continue
        if line == "/exit":
            return 0
        if line in {"/clear", "/quit"}:
            if os.name == "nt":
                os.system("cls")
            else:
                os.system("clear")
            if console:
                console.clear()
            show_banner()
            continue
        if line == "/?":
            line = "/help"
        try:
            if line == "/compose":
                result = compose(client)
            elif (
                line in {"/register", "/signup"}
                or line.startswith("/register ")
                or line.startswith("/signup ")
            ):
                result = register_workflow(
                    line, client, console=console, styled=styled, plain=plain
                )
                if styled:
                    continue
            elif line == "/goal" or line.startswith("/goal "):
                result = goal_workflow(line, client, console=console, styled=styled, plain=plain)
                if styled:
                    continue
            elif (
                line in {"/demo", "/pipeline"}
                or line.startswith("/demo ")
                or line.startswith("/pipeline ")
            ):
                prompt_arg = (
                    line.split(" ", 1)[1]
                    if " " in line
                    else "Review Pump P-204 vibration readings against engineering SOP"
                )
                result = context.run_sovereign_pipeline_ui(prompt_arg, plain=plain, client=client)
            elif not line.startswith("/"):
                result = (
                    client.chat(line)
                    if client.session.value.get("public_auto_chat")
                    else client.run(line)
                )
            else:
                words = shlex.split(line[1:], posix=False)
                words = [
                    w[1:-1] if len(w) >= 2 and w[0] == w[-1] and w[0] in "'\"" else w for w in words
                ]
                args = parser.parse_args(words)
                if not args.command or args.command == "shell":
                    raise CLIError("Already in the Aegis shell")
                if args.persona:
                    client.persona(args.persona)
                if styled and args.command not in {"login", "users", "backup"}:
                    with console.status(f"[verified]Running {args.command}...[/]", spinner="dots"):
                        result = context.execute(args, client)
                else:
                    result = context.execute(args, client)
            context.print_result(result, plain=plain)
            if context.failed_result(result):
                if styled:
                    console.print(
                        "[danger]Operation did not complete; inspect status and reason above.[/]"
                    )
                else:
                    print(
                        "Operation did not complete; inspect status and reason above.",
                        file=sys.stderr,
                    )
        except SystemExit:
            continue
        except (CLIError, OSError, ValueError, subprocess.SubprocessError) as error:
            print("Error: " + terminal_text(error), file=sys.stderr)
        except KeyboardInterrupt:
            print(
                "\nCommand interrupted locally. Server work may continue; inspect task status before retrying.",
                file=sys.stderr,
            )
