"""File permission auditor for OpenClaw configuration and key files."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class PermissionIssue:
    file_path: str
    current_mode: str       # e.g. "0o644"
    current_mode_str: str   # e.g. "-rw-r--r--"
    expected_mode: str      # e.g. "0o600"
    issue_description: str
    severity: str           # "critical" or "warning"
    fix_command: str


@dataclass
class PermissionScanResult:
    issues: List[PermissionIssue] = field(default_factory=list)
    files_checked: int = 0
    score_penalty: int = 0

    @property
    def passed(self) -> int:
        return self.files_checked - len(self.issues)

    @property
    def failures(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def warnings(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")


# Rules: (glob_pattern, max_allowed_octal_mode, severity, description)
PERMISSION_RULES = [
    # Private keys must be owner-read-only
    ("*.pem",       0o600, "critical", "Private key file is world/group readable"),
    ("*.key",       0o600, "critical", "Private key file is world/group readable"),
    ("id_rsa",      0o600, "critical", "SSH private key is world/group readable"),
    ("id_ed25519",  0o600, "critical", "SSH private key is world/group readable"),
    # .env files should not be readable by others
    (".env",        0o600, "critical", ".env file is readable by group/others"),
    (".env.*",      0o600, "critical", ".env file is readable by group/others"),
    # Config files should not be world-writable
    ("*.conf",      0o644, "warning",  "Config file is world/group writable"),
    ("*.yaml",      0o644, "warning",  "Config file is world/group writable"),
    ("*.yml",       0o644, "warning",  "Config file is world/group writable"),
    ("*.json",      0o644, "warning",  "Config file is world/group writable"),
    ("config.py",   0o644, "warning",  "Config file is world/group writable"),
    ("settings.py", 0o644, "warning",  "Config file is world/group writable"),
]

# Common OpenClaw directories to inspect
DEFAULT_SCAN_DIRS = [
    os.path.expanduser("~/.openclaw"),
    os.path.expanduser("~/.config/openclaw"),
    os.path.expanduser("~/.ssh"),
    "/etc/openclaw",
    os.getcwd(),
]


def _mode_string(mode: int) -> str:
    """Convert a stat mode integer to a human-readable string like -rwxr-xr-x."""
    flags = [
        (stat.S_IRUSR, "r"), (stat.S_IWUSR, "w"), (stat.S_IXUSR, "x"),
        (stat.S_IRGRP, "r"), (stat.S_IWGRP, "w"), (stat.S_IXGRP, "x"),
        (stat.S_IROTH, "r"), (stat.S_IWOTH, "w"), (stat.S_IXOTH, "x"),
    ]
    result = "-"
    for flag, char in flags:
        result += char if mode & flag else "-"
    return result


def _matches_pattern(name: str, pattern: str) -> bool:
    """Simple glob-style matching (supports leading/trailing '*')."""
    if pattern.startswith("*") and pattern.endswith("*"):
        return pattern[1:-1] in name
    if pattern.startswith("*"):
        return name.endswith(pattern[1:])
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def _check_file(path: Path, result: PermissionScanResult) -> None:
    try:
        file_stat = path.stat()
    except (PermissionError, OSError):
        return

    result.files_checked += 1
    actual_mode = stat.S_IMODE(file_stat.st_mode)

    for pattern, max_mode, severity, description in PERMISSION_RULES:
        if not _matches_pattern(path.name, pattern):
            continue

        # Check if actual mode is stricter than allowed (i.e., has extra permission bits)
        excess_bits = actual_mode & ~max_mode
        if excess_bits == 0:
            continue  # Permissions are fine

        issue = PermissionIssue(
            file_path=str(path),
            current_mode=oct(actual_mode),
            current_mode_str=_mode_string(actual_mode),
            expected_mode=oct(max_mode),
            issue_description=description,
            severity=severity,
            fix_command=f"chmod {oct(max_mode)[2:]} {path}",
        )
        result.issues.append(issue)
        result.score_penalty += 15 if severity == "critical" else 5
        break  # One rule per file is enough


def scan_permissions(scan_dirs: Optional[List[str]] = None) -> PermissionScanResult:
    """
    Audit file permissions in common OpenClaw config directories.

    Checks that private keys and config files are not overly permissive.
    """
    if scan_dirs is None:
        scan_dirs = DEFAULT_SCAN_DIRS

    result = PermissionScanResult()

    for base_dir in scan_dirs:
        base = Path(base_dir)
        if not base.exists() or not base.is_dir():
            continue

        try:
            for entry in base.rglob("*"):
                if entry.is_file():
                    _check_file(entry, result)
        except PermissionError:
            continue

    return result


def fix_permissions(issues: List[PermissionIssue]) -> List[str]:
    """
    Apply the suggested chmod fix for each issue.

    Returns a list of messages describing what was changed.
    """
    messages = []
    for issue in issues:
        path = Path(issue.file_path)
        try:
            expected = int(issue.expected_mode, 8)
            os.chmod(path, expected)
            messages.append(f"Fixed: {issue.file_path}  {issue.current_mode} -> {issue.expected_mode}")
        except (ValueError, PermissionError, OSError) as exc:
            messages.append(f"Failed to fix {issue.file_path}: {exc}")
    return messages
