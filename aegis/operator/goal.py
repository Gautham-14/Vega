from __future__ import annotations

import json
import os
import shlex
import sys
import time
from pathlib import Path

from aegis.cli_support import terminal_text


class GoalManager:
    """Manage persistent goal tracking for autonomous thorough execution."""

    def __init__(self, directory: Path | None = None):
        base_dir = directory or os.environ.get("AEGIS_CLIENT_DIR") or Path.home() / ".aegis"
        self.directory = Path(base_dir)
        self.file_path = self.directory / "active_goal.json"

    def _ensure_dir(self):
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def load_goal(self) -> dict | None:
        """Load the active goal if it exists."""
        if not self.file_path.exists():
            return None
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "objective" in data:
                return data
        except (OSError, ValueError):
            pass
        return None

    def save_goal(self, goal: dict):
        """Save the active goal atomically."""
        self._ensure_dir()
        goal["updated_at"] = time.time()
        temp_file = self.file_path.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(goal, f, indent=2, ensure_ascii=False)
            if os.name == "nt" and self.file_path.exists():
                self.file_path.unlink()
            temp_file.rename(self.file_path)
        except OSError:
            # Fallback direct write
            try:
                with open(self.file_path, "w", encoding="utf-8") as f:
                    json.dump(goal, f, indent=2, ensure_ascii=False)
            except OSError:
                pass

    def clear_goal(self) -> bool:
        """Clear the active goal."""
        if self.file_path.exists():
            try:
                self.file_path.unlink()
                return True
            except OSError:
                return False
        return False

    def create_goal(
        self,
        objective: str,
        milestones: list[str] | None = None,
        mode: str = "thorough",
    ) -> dict:
        """Create a new autonomous goal with milestone plan."""
        clean_obj = objective.strip()
        if not milestones:
            milestones = [
                f"Analyze requirements & inspect code context for '{clean_obj}'",
                f"Implement solutions & generate patch for '{clean_obj}'",
                "Execute test suite & verify edge cases thoroughly",
                "Review diff, audit security compliance & confirm receipt",
            ]

        items = []
        for idx, m_title in enumerate(milestones, start=1):
            items.append(
                {
                    "id": idx,
                    "title": m_title,
                    "status": "PENDING",  # PENDING, IN_PROGRESS, COMPLETED
                    "task_id": None,
                    "completed_at": None,
                }
            )

        if items:
            items[0]["status"] = "IN_PROGRESS"

        goal = {
            "objective": clean_obj,
            "mode": mode,
            "status": "IN_PROGRESS",
            "created_at": time.time(),
            "updated_at": time.time(),
            "milestones": items,
            "current_milestone_id": 1,
            "iterations": 0,
            "history": [],
        }
        self.save_goal(goal)
        return goal

    def add_milestone(self, title: str) -> dict | None:
        """Add a custom milestone to the active goal."""
        goal = self.load_goal()
        if not goal:
            return None
        next_id = max((m["id"] for m in goal.get("milestones", [])), default=0) + 1
        goal.setdefault("milestones", []).append(
            {
                "id": next_id,
                "title": title.strip(),
                "status": "PENDING",
                "task_id": None,
                "completed_at": None,
            }
        )
        self.save_goal(goal)
        return goal

    def complete_milestone(self, milestone_id: int | None = None) -> dict | None:
        """Mark a milestone (or current milestone) as completed."""
        goal = self.load_goal()
        if not goal or not goal.get("milestones"):
            return None

        target_id = milestone_id or goal.get("current_milestone_id", 1)
        for m in goal["milestones"]:
            if m["id"] == target_id:
                m["status"] = "COMPLETED"
                m["completed_at"] = time.time()
                break

        # Advance current milestone to next pending
        next_pending = next(
            (m for m in goal["milestones"] if m["status"] == "PENDING"),
            None,
        )
        if next_pending:
            next_pending["status"] = "IN_PROGRESS"
            goal["current_milestone_id"] = next_pending["id"]
        else:
            goal["status"] = "ACHIEVED"
            goal["current_milestone_id"] = None

        self.save_goal(goal)
        return goal


def display_goal_guide(console=None, styled=False):
    """Render /goal usage guidance inspired by Antigravity and Codex."""
    if styled and console:
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        title = "[bold #8b5cf6]--- AEGIS /GOAL AUTONOMOUS EXECUTION GUIDE ---[/]"

        body_text = (
            "[bold white]Autonomous Goal-Driven Execution (Antigravity / Codex style)[/]\n"
            "[dim]The /goal command allows you to define a persistent high-level objective and "
            "direct Aegis to be extra thorough, decomposing work into actionable milestones "
            "and iteratively validating until the goal is fully achieved.[/]\n\n"
            "[bold #a78bfa]--- COMMAND REFERENCE ---[/]"
        )

        table = Table(box=None, padding=(0, 2), expand=True)
        table.add_column("Command", style="bold cyan", no_wrap=True)
        table.add_column("Action / Description", style="dim white")

        table.add_row(
            "/goal",
            "View active goal dashboard, progress bar, checklist & next action",
        )
        table.add_row(
            "/goal <objective>",
            "Initialize a new goal with an automated milestone breakdown",
        )
        table.add_row(
            "/goal run",
            "Execute the current milestone autonomously using the selected coding lease",
        )
        table.add_row(
            "/goal complete [num]",
            "Mark current or specified milestone as completed and advance",
        )
        table.add_row(
            "/goal add <title>",
            "Add a custom milestone to the active goal checklist",
        )
        table.add_row(
            "/goal clear",
            "Reset and clear the active goal",
        )
        table.add_row(
            "/goal help",
            "Show this reference guide",
        )

        footer = (
            "\n[bold #a78bfa]--- WORKFLOW TIP ---[/]\n"
            "Combine [bold cyan]/goal[/] with coding leases ([bold cyan]/leases[/], [bold cyan]use <id>[/]) "
            "for autonomous multi-step code generation, diff inspection, and test verification."
        )

        content = Group(
            Text.from_markup(body_text),
            table,
            Text.from_markup(footer),
        )

        panel = Panel(content, title=title, border_style="#8b5cf6", padding=(1, 2))
        console.print(panel)
    else:
        print("=== AEGIS /GOAL AUTONOMOUS EXECUTION GUIDE ===")
        print(
            "The /goal command sets a persistent high-level objective and executes work with\n"
            "extra thoroughness, tracking milestones until the objective is fully achieved.\n"
        )
        print("--- COMMAND REFERENCE ---")
        print("  /goal                  - View active goal dashboard & progress")
        print("  /goal <objective>      - Set a new goal with automated milestone plan")
        print("  /goal run              - Execute the current milestone with the selected lease")
        print("  /goal complete [num]   - Mark milestone as completed and advance")
        print("  /goal add <title>      - Add a custom milestone to the checklist")
        print("  /goal clear            - Reset and clear the active goal")
        print("  /goal help             - Show this reference guide\n")


def display_goal_dashboard(goal: dict, console=None, styled=False):
    """Render the active goal dashboard, progress bar, and milestone checklist."""
    milestones = goal.get("milestones", [])
    total = len(milestones)
    completed = sum(1 for m in milestones if m.get("status") == "COMPLETED")
    pct = int((completed / total * 100)) if total else 0

    if styled and console:
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        title = f"[bold #8b5cf6]--- ACTIVE GOAL DASHBOARD ({goal.get('mode', 'thorough').upper()}) ---[/]"

        # Progress bar
        bar_len = 30
        filled = int(bar_len * (completed / total)) if total else 0
        bar_str = "█" * filled + "░" * (bar_len - filled)
        status_style = "bold green" if goal.get("status") == "ACHIEVED" else "bold yellow"

        header_text = (
            f"[bold white]Objective:[/] [cyan]{goal['objective']}[/]\n"
            f"[bold white]Status:[/] [{status_style}]{goal.get('status', 'IN_PROGRESS')}[/] │ "
            f"[bold white]Progress:[/] [{status_style}]{bar_str} {pct}% ({completed}/{total} completed)[/]\n\n"
            "[bold #a78bfa]--- MILESTONE CHECKLIST ---[/]"
        )

        table = Table(box=None, padding=(0, 2), expand=True)
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Milestone Description", style="white")
        table.add_column("Task ID / Note", style="dim cyan", no_wrap=True)

        for m in milestones:
            m_status = m.get("status", "PENDING")
            if m_status == "COMPLETED":
                badge = "[bold green][✔] COMPLETED[/]"
            elif m_status == "IN_PROGRESS":
                badge = "[bold yellow][▶] IN PROGRESS[/]"
            else:
                badge = "[dim][ ] PENDING[/]"

            task_info = m.get("task_id") or ""
            table.add_row(str(m["id"]), badge, m["title"], task_info)

        footer_text = (
            "\n[bold #a78bfa]--- NEXT ACTIONS ---[/]\n"
            "• [bold cyan]/goal run[/]      - Execute current milestone with model\n"
            "• [bold cyan]/goal complete[/] - Mark milestone completed\n"
            "• [bold cyan]/goal add <m>[/]  - Add new milestone\n"
            "• [bold cyan]/goal clear[/]    - Reset active goal"
        )

        content = Group(
            Text.from_markup(header_text),
            table,
            Text.from_markup(footer_text),
        )

        panel = Panel(content, title=title, border_style="#8b5cf6", padding=(1, 2))
        console.print(panel)
    else:
        print(f"=== ACTIVE GOAL: {goal['objective']} ===")
        print(
            f"Status: {goal.get('status', 'IN_PROGRESS')} | Progress: {pct}% ({completed}/{total} completed)\n"
        )
        print("--- MILESTONES ---")
        for m in milestones:
            m_status = m.get("status", "PENDING")
            mark = (
                "[X]" if m_status == "COMPLETED" else "[>]" if m_status == "IN_PROGRESS" else "[ ]"
            )
            task_str = f" (Task: {m['task_id']})" if m.get("task_id") else ""
            print(f"  {mark} {m['id']}. {m['title']}{task_str}")
        print("\nCommands: /goal run | /goal complete [num] | /goal add <title> | /goal clear\n")


def goal_workflow(
    line: str,
    client,
    *,
    console=None,
    styled=False,
    plain=False,
    input_reader=input,
    manager: GoalManager | None = None,
) -> dict | None:
    """Entry point for /goal command in the Aegis operator shell."""
    mgr = manager or GoalManager()
    tokens = shlex.split(line) if line else []
    args = tokens[1:] if len(tokens) > 1 else []

    # 1. /goal help
    if args and args[0].lower() in {"help", "--help", "-h", "/?"}:
        display_goal_guide(console=console, styled=styled and not plain)
        return {"action": "GUIDE_DISPLAYED", "status": "COMPLETED"}

    # 2. Bare /goal
    if not args:
        active = mgr.load_goal()
        if active:
            display_goal_dashboard(active, console=console, styled=styled and not plain)
            return {"action": "DASHBOARD_DISPLAYED", "goal": active}

        # No active goal
        display_goal_guide(console=console, styled=styled and not plain)
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if not interactive:
            return {"action": "GUIDE_DISPLAYED", "status": "NO_ACTIVE_GOAL"}

        try:
            prompt_str = "\n> Enter goal objective (or press Enter to cancel): "
            obj_input = input_reader(prompt_str).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return {"status": "CANCELLED"}

        if not obj_input:
            return {"status": "CANCELLED"}

        new_goal = mgr.create_goal(obj_input)
        display_goal_dashboard(new_goal, console=console, styled=styled and not plain)
        return {"action": "GOAL_CREATED", "goal": new_goal}

    subcmd = args[0].lower()

    # 3. /goal status
    if subcmd == "status":
        active = mgr.load_goal()
        if not active:
            msg = "No active goal. Set one with: /goal <objective>"
            if styled and console and not plain:
                console.print(f"[dim]{msg}[/]")
            else:
                print(msg)
            return {"status": "NO_ACTIVE_GOAL"}
        display_goal_dashboard(active, console=console, styled=styled and not plain)
        return {"action": "DASHBOARD_DISPLAYED", "goal": active}

    # 4. /goal clear / reset / cancel
    if subcmd in {"clear", "reset", "cancel"}:
        active = mgr.load_goal()
        if not active:
            msg = "No active goal to clear."
            if styled and console and not plain:
                console.print(f"[dim]{msg}[/]")
            else:
                print(msg)
            return {"status": "NO_ACTIVE_GOAL"}

        mgr.clear_goal()
        msg = "Active goal cleared."
        if styled and console and not plain:
            console.print(f"[bold #50c878][✔] {msg}[/]")
        else:
            print(msg)
        return {"status": "GOAL_CLEARED"}

    # 5. /goal add <milestone>
    if subcmd == "add":
        m_title = " ".join(args[1:]).strip()
        if not m_title:
            err = "Specify milestone title: /goal add <description>"
            if styled and console and not plain:
                console.print(f"[bold red]Error:[/] {err}")
            else:
                print(f"Error: {err}")
            return {"status": "FAILED", "reason": err}
        active = mgr.load_goal()
        if not active:
            err = "No active goal. Set a goal first with: /goal <objective>"
            if styled and console and not plain:
                console.print(f"[bold red]Error:[/] {err}")
            else:
                print(f"Error: {err}")
            return {"status": "FAILED", "reason": err}

        updated = mgr.add_milestone(m_title)
        display_goal_dashboard(updated, console=console, styled=styled and not plain)
        return {"status": "MILESTONE_ADDED", "goal": updated}

    # 6. /goal complete [id] or /goal done [id]
    if subcmd in {"complete", "done", "achieve"}:
        target_id = None
        if len(args) > 1 and args[1].isdigit():
            target_id = int(args[1])
        active = mgr.load_goal()
        if not active:
            err = "No active goal to complete."
            if styled and console and not plain:
                console.print(f"[dim]{err}[/]")
            else:
                print(err)
            return {"status": "NO_ACTIVE_GOAL"}

        updated = mgr.complete_milestone(target_id)
        display_goal_dashboard(updated, console=console, styled=styled and not plain)
        return {"status": "MILESTONE_COMPLETED", "goal": updated}

    # 7. /goal run / next / step / execute
    if subcmd in {"run", "next", "step", "execute"}:
        active = mgr.load_goal()
        if not active:
            err = "No active goal to run. Set one with: /goal <objective>"
            if styled and console and not plain:
                console.print(f"[bold red]Error:[/] {err}")
            else:
                print(f"Error: {err}")
            return {"status": "NO_ACTIVE_GOAL"}

        current_id = active.get("current_milestone_id")
        current_m = next((m for m in active.get("milestones", []) if m["id"] == current_id), None)
        if not current_m:
            msg = "All milestones are already completed for this goal!"
            if styled and console and not plain:
                console.print(f"[bold green][✔] {msg}[/]")
            else:
                print(msg)
            return {"status": "GOAL_ALREADY_COMPLETED", "goal": active}

        # Check for active lease
        selected_lease = (
            client.session.value.get("selected_lease")
            if client and hasattr(client, "session")
            else None
        )
        if not selected_lease or not selected_lease.get("id"):
            msg = (
                f"Milestone #{current_m['id']}: '{current_m['title']}'\n\n"
                "No coding lease is currently selected. To run autonomous model execution:\n"
                "  1. Inspect leases: /leases\n"
                "  2. Select lease:   use <lease-id>\n"
                "  3. Execute:        /goal run\n\n"
                "Or mark completion manually once verified: /goal complete"
            )
            if styled and console and not plain:
                console.print(f"[yellow]{msg}[/]")
            else:
                print(msg)
            return {"status": "AWAITING_LEASE", "milestone": current_m}

        # Build prompt
        prompt = (
            f"[AUTONOMOUS GOAL EXECUTION]\n"
            f"Overarching Goal: {active['objective']}\n"
            f"Active Milestone #{current_m['id']}: {current_m['title']}\n"
            f"Requirement: Thoroughly inspect, implement, and verify the necessary changes "
            f"for this milestone. Validate all tests and maintain zero regressions."
        )

        if styled and console and not plain:
            console.print(
                f"[bold #8b5cf6]▶ Running Milestone #{current_m['id']}:[/] {current_m['title']}..."
            )
        else:
            print(f"Running Milestone #{current_m['id']}: {current_m['title']}...")

        try:
            result = client.run(prompt)
            task_id = result.get("task_id") if isinstance(result, dict) else None
            current_m["task_id"] = task_id
            mgr.save_goal(active)
            mgr.complete_milestone(current_m["id"])
            updated = mgr.load_goal()
            display_goal_dashboard(updated, console=console, styled=styled and not plain)
            return {"status": "MILESTONE_EXECUTED", "task_id": task_id, "goal": updated}
        except Exception as exc:
            err = f"Execution error: {terminal_text(exc)}"
            if styled and console and not plain:
                console.print(f"[bold red]{err}[/]")
            else:
                print(err)
            return {"status": "FAILED", "reason": str(exc)}

    # 8. /goal <objective description>
    objective = " ".join(args).strip()
    new_goal = mgr.create_goal(objective)
    display_goal_dashboard(new_goal, console=console, styled=styled and not plain)
    return {"action": "GOAL_CREATED", "goal": new_goal}
