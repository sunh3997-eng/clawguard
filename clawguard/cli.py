"""ClawGuard CLI — entry point."""

import sys
from typing import Optional

import click
from rich.console import Console

from . import __version__
from .scanners import scan_ports, scan_secrets, scan_permissions
from .scanners.permissions import fix_permissions
from .report import render_report, render_fix_results

console = Console()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="clawguard")
@click.option(
    "--target",
    default="127.0.0.1",
    show_default=True,
    metavar="HOST",
    help="Target host to probe for open ports.",
)
@click.option(
    "--scan-dir",
    "scan_dirs",
    multiple=True,
    metavar="DIR",
    help="Extra directory to include in secret/permission scans. Can be repeated.",
)
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help="Automatically apply safe fixes (chmod only). Requires confirmation.",
)
@click.option(
    "--skip-ports",
    is_flag=True,
    default=False,
    help="Skip port exposure scan.",
)
@click.option(
    "--skip-secrets",
    is_flag=True,
    default=False,
    help="Skip secret/API-key scan.",
)
@click.option(
    "--skip-permissions",
    is_flag=True,
    default=False,
    help="Skip file permission audit.",
)
@click.option(
    "--fail-under",
    default=0,
    metavar="SCORE",
    help="Exit with code 1 if the security score is below this value (0–100).",
)
def main(
    target: str,
    scan_dirs: tuple,
    fix: bool,
    skip_ports: bool,
    skip_secrets: bool,
    skip_permissions: bool,
    fail_under: int,
) -> None:
    """
    \b
     ██████╗██╗      █████╗ ██╗    ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║     ██║     ███████║██║ █╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║     ██║     ██╔══██║██║███╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ╚██████╗███████╗██║  ██║╚███╔███╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

    One-command security scan for your OpenClaw instance.

    Checks port exposure, hardcoded secrets, and file permissions, then
    outputs a colour-coded report with a 0–100 security score and
    actionable fix commands for every finding.
    """
    extra_dirs = list(scan_dirs) if scan_dirs else None

    # ── Run scanners ──────────────────────────────────────────────────────────

    if not skip_ports:
        console.print(f"[dim]Scanning ports on {target}...[/dim]")
        port_result = scan_ports(target)
    else:
        from .scanners.ports import PortScanResult
        port_result = PortScanResult()

    if not skip_secrets:
        console.print("[dim]Scanning for hardcoded secrets...[/dim]")
        secret_result = scan_secrets(extra_dirs)
    else:
        from .scanners.secrets import SecretScanResult
        secret_result = SecretScanResult()

    if not skip_permissions:
        console.print("[dim]Auditing file permissions...[/dim]")
        perm_result = scan_permissions(extra_dirs)
    else:
        from .scanners.permissions import PermissionScanResult
        perm_result = PermissionScanResult()

    # ── Render report ─────────────────────────────────────────────────────────

    score = render_report(port_result, secret_result, perm_result)

    # ── Auto-fix ──────────────────────────────────────────────────────────────

    if fix and perm_result.issues:
        click.confirm(
            f"\nApply {len(perm_result.issues)} permission fix(es) now?",
            abort=True,
        )
        messages = fix_permissions(perm_result.issues)
        render_fix_results(messages)
    elif fix:
        console.print("[green]Nothing to fix — permissions are already correct.[/green]")

    # ── Exit code ─────────────────────────────────────────────────────────────

    if fail_under > 0 and score < fail_under:
        console.print(
            f"[bold red]Score {score} is below threshold {fail_under}. Exiting with code 1.[/bold red]"
        )
        sys.exit(1)
