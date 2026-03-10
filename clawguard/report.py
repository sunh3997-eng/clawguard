"""Rich terminal report renderer for ClawGuard scan results."""

from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .scanners.ports import PortScanResult
from .scanners.secrets import SecretScanResult
from .scanners.permissions import PermissionScanResult, PermissionIssue

console = Console()


# ──────────────────────────────────────────────
# Score calculation
# ──────────────────────────────────────────────

def calculate_score(
    port_result: PortScanResult,
    secret_result: SecretScanResult,
    perm_result: PermissionScanResult,
) -> int:
    penalty = (
        port_result.score_penalty
        + secret_result.score_penalty
        + perm_result.score_penalty
    )
    return max(0, 100 - penalty)


# ──────────────────────────────────────────────
# Severity helpers
# ──────────────────────────────────────────────

def _icon(severity: str) -> str:
    return {"ok": "✅", "warning": "⚠️", "critical": "❌"}.get(severity, "❓")


def _color(severity: str) -> str:
    return {"ok": "green", "warning": "yellow", "critical": "red"}.get(severity, "white")


def _score_color(score: int) -> str:
    if score >= 80:
        return "bold green"
    if score >= 50:
        return "bold yellow"
    return "bold red"


# ──────────────────────────────────────────────
# Section renderers
# ──────────────────────────────────────────────

def _render_ports(result: PortScanResult) -> None:
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("", width=3)
    table.add_column("Port", style="bold", width=6)
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Fix", overflow="fold")

    for r in result.results:
        if not r.is_open:
            status = Text("Closed", style="green")
        elif r.is_exposed:
            status = Text("EXPOSED (0.0.0.0)", style="bold red")
        else:
            status = Text("Open (localhost only)", style="yellow")

        fix = r.fix_command or ""
        table.add_row(
            _icon(r.severity),
            str(r.port),
            r.description,
            status,
            Text(fix, style="dim"),
        )

    console.print(
        Panel(table, title="[bold cyan]Port Exposure Scan[/bold cyan]", border_style="cyan")
    )


def _render_secrets(result: SecretScanResult) -> None:
    if result.findings:
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold red",
            expand=True,
        )
        table.add_column("", width=3)
        table.add_column("File", overflow="fold")
        table.add_column("Line", width=5)
        table.add_column("Type")
        table.add_column("Match (redacted)", overflow="fold")
        table.add_column("Fix", overflow="fold")

        for f in result.findings:
            table.add_row(
                "❌",
                f.file_path,
                str(f.line_number),
                f.secret_type,
                Text(f.redacted_match, style="bold red"),
                Text(f.fix_suggestion, style="italic dim"),
            )
    else:
        table = Text("  ✅  No hardcoded secrets found.", style="green")

    scanned_note = f"  [dim]{result.files_scanned} config file(s) scanned[/dim]"
    console.print(
        Panel(
            table,
            title="[bold red]API Key & Secret Leak Scan[/bold red]",
            border_style="red",
            subtitle=scanned_note,
        )
    )


def _render_permissions(result: PermissionScanResult) -> None:
    if result.issues:
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column("", width=3)
        table.add_column("File", overflow="fold")
        table.add_column("Current", width=10)
        table.add_column("Expected", width=10)
        table.add_column("Issue")
        table.add_column("Fix", overflow="fold")

        for issue in result.issues:
            icon = _icon(issue.severity)
            table.add_row(
                icon,
                issue.file_path,
                f"{issue.current_mode} ({issue.current_mode_str})",
                issue.expected_mode,
                Text(issue.issue_description, style=_color(issue.severity)),
                Text(issue.fix_command, style="bold magenta"),
            )
    else:
        table = Text("  ✅  All file permissions look good.", style="green")

    checked_note = f"  [dim]{result.files_checked} file(s) checked[/dim]"
    console.print(
        Panel(
            table,
            title="[bold yellow]Permission Audit[/bold yellow]",
            border_style="yellow",
            subtitle=checked_note,
        )
    )


# ──────────────────────────────────────────────
# Summary banner
# ──────────────────────────────────────────────

def _render_summary(score: int, port_result: PortScanResult, secret_result: SecretScanResult, perm_result: PermissionScanResult) -> None:
    total_issues = port_result.failures + secret_result.failures + perm_result.failures
    total_warnings = port_result.warnings + perm_result.warnings

    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"

    score_text = Text()
    score_text.append(f"\n  Security Score: ", style="bold white")
    score_text.append(f"{score}/100  (Grade {grade})\n", style=_score_color(score))
    score_text.append(f"\n  Critical Issues : {total_issues}\n", style="red" if total_issues else "green")
    score_text.append(f"  Warnings        : {total_warnings}\n", style="yellow" if total_warnings else "green")

    if total_issues == 0 and total_warnings == 0:
        score_text.append("\n  Your OpenClaw instance looks secure! Keep it up.\n", style="bold green")
    elif total_issues > 0:
        score_text.append("\n  Action required — fix critical issues immediately.\n", style="bold red")
    else:
        score_text.append("\n  Review warnings to further harden your setup.\n", style="bold yellow")

    console.print(
        Panel(
            score_text,
            title="[bold white]ClawGuard Security Summary[/bold white]",
            border_style=_score_color(score),
        )
    )


# ──────────────────────────────────────────────
# Auto-fix output
# ──────────────────────────────────────────────

def render_fix_results(messages: List[str]) -> None:
    console.print("\n[bold magenta]── Auto-fix Results ──[/bold magenta]")
    for msg in messages:
        style = "green" if msg.startswith("Fixed") else "red"
        console.print(f"  [{style}]{msg}[/{style}]")


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────

def render_report(
    port_result: PortScanResult,
    secret_result: SecretScanResult,
    perm_result: PermissionScanResult,
) -> int:
    """Render the full report and return the security score."""
    console.print()
    console.print(
        Panel(
            "[bold cyan]ClawGuard[/bold cyan]  [dim]— OpenClaw Security Scanner[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )
    console.print()

    _render_ports(port_result)
    console.print()
    _render_secrets(secret_result)
    console.print()
    _render_permissions(perm_result)
    console.print()

    score = calculate_score(port_result, secret_result, perm_result)
    _render_summary(score, port_result, secret_result, perm_result)
    console.print()

    return score
