from __future__ import annotations

import re
import shlex
import sys
from getpass import getpass

from aegis.cli_support import terminal_text
from aegis.control import policy


def display_registration_guide(console=None, styled=False):
    """Render comprehensive onboarding and registration guidance."""
    if styled and console:
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        title = "[bold #8b5cf6]--- AEGIS USER REGISTRATION & ONBOARDING GUIDE ---[/]"

        body_text = (
            "[bold white]Welcome to the Aegis Sovereign AI Broker.[/]\n"
            "[dim]Aegis operates in an air-gapped, zero-egress environment. Accounts are stored "
            "locally with cryptographic scrypt password hashing. No external accounts or cloud "
            "credentials are ever required or contacted.[/]\n\n"
            "[bold #a78bfa]--- AVAILABLE ROLES & ACCESS CONTROL ---[/]"
        )

        table = Table(box=None, padding=(0, 2), expand=True)
        table.add_column("Role Template", style="bold cyan", no_wrap=True)
        table.add_column("Clearance", style="bold yellow", no_wrap=True)
        table.add_column("Compartments", style="green", no_wrap=True)
        table.add_column("Purpose / Responsibilities", style="dim white")

        table.add_row(
            "operator",
            "INTERNAL",
            "Eng, Maint, Public",
            "Standard operator for daily AI queries, code analysis & leases (Recommended for new users)",
        )
        table.add_row(
            "data-owner",
            "CONFIDENTIAL",
            "All Compartments",
            "Governs source repositories, imports code workspaces & authorizes coding leases",
        )
        table.add_row(
            "security-officer",
            "CONFIDENTIAL",
            "All Compartments",
            "Administers security controls, emergency /lockdown, dual approvals & audits",
        )
        table.add_row(
            "model-custodian",
            "PUBLIC",
            "None",
            "Manages local AI model custody, verification, bundles & provider qualifications",
        )

        instructions = (
            "\n[bold #a78bfa]--- ACCOUNT RULES & REQUIREMENTS ---[/]\n"
            "- [bold white]Username:[/] 1-64 lowercase alphanumeric chars & hyphens ([cyan]operator[/], [cyan]alice[/], [cyan]dev-lead[/]).\n"
            "- [bold white]Password:[/] 12-256 characters. Entered securely without terminal echo.\n"
            "- [bold white]Custom Accounts:[/] Inherit permissions from a built-in template ([cyan]--like operator[/]).\n\n"
            "[bold #a78bfa]--- REGISTRATION & LOGIN WORKFLOW ---[/]\n"
            "1. [bold cyan]/register[/]                      Start interactive sign-up wizard\n"
            "2. [bold cyan]/register <name> [--like <role>][/] Direct registration command\n"
            "3. [bold cyan]/login <name>[/]                  Sign into your newly created account\n"
            "4. [bold cyan]/whoami[/]                       Verify active identity, clearance & roles\n"
            "5. [bold cyan]/users mfa-enroll <name>[/]       (Optional) Enroll local TOTP/authenticator"
        )

        content = Group(
            Text.from_markup(body_text),
            table,
            Text.from_markup(instructions),
        )

        panel = Panel(
            content,
            title=title,
            border_style="#8b5cf6",
            padding=(1, 2),
        )
        console.print(panel)
    else:
        print("=== AEGIS USER REGISTRATION & ONBOARDING GUIDE ===")
        print(
            "Aegis operates in an air-gapped, zero-egress environment. Accounts are stored locally\n"
            "with cryptographic scrypt password hashing. No external accounts or cloud credentials\n"
            "are ever required or contacted.\n"
        )
        print("--- AVAILABLE ROLES & ACCESS CONTROL ---")
        print(
            "  - operator         [INTERNAL]     - Standard operator for queries & coding leases (Recommended)"
        )
        print("  - data-owner       [CONFIDENTIAL] - Governs source repositories & issues leases")
        print("  - security-officer [CONFIDENTIAL] - Manages security policies, /lockdown & audits")
        print(
            "  - model-custodian  [PUBLIC]       - Manages model bundles & provider qualifications\n"
        )
        print("--- ACCOUNT RULES & REQUIREMENTS ---")
        print(
            "  - Username: 1-64 lowercase alphanumeric characters and hyphens (e.g. operator, alice)"
        )
        print("  - Password: 12-256 characters entered securely with confirmation")
        print("  - Custom Accounts: Inherit from built-in role template (--like operator)\n")
        print("--- REGISTRATION & LOGIN COMMANDS ---")
        print("  1. /register                      - Start interactive sign-up wizard")
        print("  2. /register <name> [--like <role>] - Direct registration command")
        print("  3. /login <name>                  - Sign into your newly created account")
        print("  4. /whoami                        - Inspect active identity, clearance & role")
        print("  5. /users mfa-enroll <name>        - (Optional) Enroll local TOTP/authenticator\n")


def parse_register_args(line: str) -> tuple[str | None, str | None, bool]:
    """Parse /register command line into (username, template, is_help)."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()

    # Drop leading command (/register or /signup)
    args = tokens[1:] if len(tokens) > 1 else []

    if args and args[0].lower() in {"help", "--help", "-h", "/?"}:
        return None, None, True

    username = None
    template = None

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--like" and idx + 1 < len(args):
            template = args[idx + 1]
            idx += 2
        elif not arg.startswith("-") and username is None:
            username = arg
            idx += 1
        else:
            idx += 1

    return username, template, False


def register_user_interactive(
    *,
    client=None,
    username: str | None = None,
    template: str | None = None,
    console=None,
    styled=False,
    password_reader=getpass,
    input_reader=input,
) -> dict:
    """Interactively prompt for credentials and provision a new Aegis account."""
    from aegis.control import store
    from aegis.security.auth import provision
    from aegis.storage.database import init_db

    # Prompt for username if not supplied
    if not username:
        try:
            val = input_reader("> Enter username [operator]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return {"status": "CANCELLED"}
        username = val if val else "operator"

    username = username.lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", username):
        err = "Username must be 1-64 lowercase letters, digits, and hyphens (e.g. 'operator' or 'alice')."
        if styled and console:
            console.print(f"[bold red]Error:[/] {err}")
        else:
            print(f"Error: {err}")
        return {"status": "FAILED", "reason": err}

    # Determine template
    if username in policy.ACTORS:
        template = username
    elif not template:
        print("\nSelect a role template for this account:")
        print("  1) operator         (Standard AI operations, coding & leases - Recommended)")
        print("  2) data-owner       (Source repositories & lease management)")
        print("  3) security-officer (Security controls, lockdown & dual approvals)")
        print("  4) model-custodian  (Local model custody & qualifications)")
        try:
            choice = input_reader("> Choose role template [1]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return {"status": "CANCELLED"}

        role_map = {
            "1": "operator",
            "2": "data-owner",
            "3": "security-officer",
            "4": "model-custodian",
            "operator": "operator",
            "data-owner": "data-owner",
            "security-officer": "security-officer",
            "model-custodian": "model-custodian",
        }
        template = role_map.get(choice, "operator" if not choice else None)
        if not template or template not in policy.ACTORS:
            print(f"Unrecognized choice '{choice}'. Defaulting to 'operator'.")
            template = "operator"

    # Prompt for password
    try:
        pw1 = password_reader("> Enter new password (12-256 characters): ")
        if not (12 <= len(pw1) <= 256):
            err = "Password must be 12-256 characters."
            if styled and console:
                console.print(f"[bold red]Error:[/] {err}")
            else:
                print(f"Error: {err}")
            return {"status": "FAILED", "reason": err}

        pw2 = password_reader("> Confirm password: ")
        if pw1 != pw2:
            err = "Passwords do not match."
            if styled and console:
                console.print(f"[bold red]Error:[/] {err}")
            else:
                print(f"Error: {err}")
            return {"status": "FAILED", "reason": err}
    except (EOFError, KeyboardInterrupt):
        print()
        return {"status": "CANCELLED"}

    # Provision
    try:
        init_db()
        store.init_control()
        provision(username, pw1, template=template)
    except Exception as exc:
        err = f"Account provisioning failed: {terminal_text(exc)}"
        if styled and console:
            console.print(f"[bold red]Error:[/] {err}")
        else:
            print(f"Error: {err}")
        return {"status": "FAILED", "reason": str(exc)}

    # Success notification
    if styled and console:
        console.print(
            f"[bold #50c878][PASS] Account '{username}' successfully registered with role '{template}'![/]"
        )
    else:
        print(f"Account '{username}' successfully registered with role '{template}'!")

    # Prompt to log in immediately
    try:
        login_choice = input_reader("> Sign in as this user now? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        login_choice = "n"

    if login_choice in {"", "y", "yes"}:
        if client is not None:
            try:
                body = {"username": username, "password": pw1}
                login_res = client.call("/auth/login", "POST", body, public=True)
                if isinstance(login_res, dict) and login_res.get("access_token"):
                    client.session.value = {
                        key: login_res[key] for key in ("access_token", "actor", "expires_at")
                    }
                    client.session.save()
                    if styled and console:
                        console.print(
                            f"[bold #8b5cf6][SESSION] Active session established for '{username}'. Type /whoami or /help to begin.[/]"
                        )
                    else:
                        print(
                            f"Session active. Signed in as '{username}'. Type /whoami or /help to begin."
                        )
                    return {
                        "status": "SUCCESS",
                        "action": "REGISTERED_AND_LOGGED_IN",
                        "actor": username,
                        "role": login_res.get("role", template),
                    }
            except Exception:
                # If API is not running or network issue, user can login later
                pass
        if styled and console:
            console.print(
                f"[dim]Account provisioned locally. When the server is active, sign in via: [bold cyan]/login {username}[/][/]"
            )
        else:
            print(
                f"Account provisioned locally. When the server is active, sign in via: /login {username}"
            )
    else:
        if styled and console:
            console.print(
                f"When ready, sign into your account with: [bold cyan]/login {username}[/]"
            )
        else:
            print(f"When ready, sign into your account with: /login {username}")

    return {
        "status": "SUCCESS",
        "action": "REGISTERED",
        "actor": username,
        "role": template,
    }


def register_workflow(
    line: str,
    client,
    *,
    console=None,
    styled=False,
    plain=False,
    password_reader=getpass,
    input_reader=input,
) -> dict | None:
    """Entry point for /register command in the Aegis shell."""
    username, template, is_help = parse_register_args(line)

    if is_help:
        display_registration_guide(console=console, styled=styled and not plain)
        return {"action": "GUIDE_DISPLAYED", "status": "COMPLETED"}

    # If direct username passed: e.g. /register operator or /register alice --like operator
    if username:
        return register_user_interactive(
            client=client,
            username=username,
            template=template,
            console=console,
            styled=styled and not plain,
            password_reader=password_reader,
            input_reader=input_reader,
        )

    # Bare /register command: Display full guidance first
    display_registration_guide(console=console, styled=styled and not plain)

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        return {"action": "GUIDE_DISPLAYED", "status": "COMPLETED"}

    try:
        choice = (
            input_reader("\n> Would you like to register a new account now? [Y/n]: ")
            .strip()
            .lower()
        )
    except (EOFError, KeyboardInterrupt):
        print()
        return {"status": "CANCELLED"}

    if choice not in {"", "y", "yes"}:
        if styled and console and not plain:
            console.print("[dim]You can type [bold cyan]/register[/] at any time to sign up.[/]")
        else:
            print("You can type /register at any time to sign up.")
        return {"action": "GUIDE_DISPLAYED", "status": "COMPLETED"}

    return register_user_interactive(
        client=client,
        console=console,
        styled=styled and not plain,
        password_reader=password_reader,
        input_reader=input_reader,
    )
