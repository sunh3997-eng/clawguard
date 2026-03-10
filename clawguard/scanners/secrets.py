"""API key and secret leak scanner for OpenClaw config files."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# Regex patterns for common secret types
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    (
        "Generic API Key",
        re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'),
        "Rotate the key immediately and remove it from the file.",
    ),
    (
        "Generic Secret / Password",
        re.compile(r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
        "Move sensitive values to environment variables or a secrets manager.",
    ),
    (
        "Bearer / Auth Token",
        re.compile(r'(?i)(token|auth_token|access_token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?'),
        "Store tokens in environment variables, not config files.",
    ),
    (
        "AWS Access Key",
        re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        "Revoke this AWS key immediately via the AWS IAM console.",
    ),
    (
        "AWS Secret Key",
        re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'),
        "Revoke via AWS IAM and rotate credentials.",
    ),
    (
        "GitHub Token",
        re.compile(r'(ghp_[A-Za-z0-9]{36}|github[_-]?token\s*[=:]\s*["\']?[A-Za-z0-9_]{20,}["\']?)'),
        "Revoke the token at github.com/settings/tokens.",
    ),
    (
        "Private Key Header",
        re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "Never commit private keys. Use SSH agent or a secrets vault.",
    ),
    (
        "Database URL with credentials",
        re.compile(r'(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@\s]+@'),
        "Use environment variable DATABASE_URL or a secrets manager.",
    ),
]

# Files and directories to scan
CONFIG_FILENAMES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    "config.yml",
    "config.yaml",
    "config.json",
    "settings.py",
    "settings.json",
    "application.yml",
    "application.yaml",
    "app.config",
    "openclaw.conf",
    "openclaw.yaml",
    "openclaw.json",
]

# Directories to skip
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
}


@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    secret_type: str
    redacted_match: str
    fix_suggestion: str
    severity: str = "critical"


@dataclass
class SecretScanResult:
    findings: List[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    score_penalty: int = 0

    @property
    def passed(self) -> bool:
        return len(self.findings) == 0

    @property
    def failures(self) -> int:
        return len(self.findings)


def _redact(match: str) -> str:
    """Show only the first 4 and last 2 characters of a secret."""
    if len(match) <= 8:
        return "***"
    return match[:4] + "*" * (len(match) - 6) + match[-2:]


def _scan_file(path: Path, result: SecretScanResult) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return

    result.files_scanned += 1

    for line_number, line in enumerate(text.splitlines(), start=1):
        # Skip commented-out lines
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for secret_type, pattern, fix in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                raw = match.group(0)
                result.findings.append(
                    SecretFinding(
                        file_path=str(path),
                        line_number=line_number,
                        secret_type=secret_type,
                        redacted_match=_redact(raw),
                        fix_suggestion=fix,
                    )
                )
                result.score_penalty += 20
                # Only report the first match per line to avoid duplicates
                break


def scan_secrets(scan_dirs: Optional[List[str]] = None) -> SecretScanResult:
    """
    Scan common config files in the given directories for hardcoded secrets.

    Defaults to current directory and common OpenClaw config locations.
    """
    if scan_dirs is None:
        scan_dirs = [
            os.getcwd(),
            os.path.expanduser("~/.openclaw"),
            os.path.expanduser("~/.config/openclaw"),
            "/etc/openclaw",
        ]

    result = SecretScanResult()

    for base_dir in scan_dirs:
        base = Path(base_dir)
        if not base.exists():
            continue

        # Check named config files at this level
        for filename in CONFIG_FILENAMES:
            candidate = base / filename
            if candidate.is_file():
                _scan_file(candidate, result)

        # Walk subdirectories up to depth 3
        _walk_for_configs(base, result, max_depth=3)

    return result


def _walk_for_configs(base: Path, result: SecretScanResult, max_depth: int, _depth: int = 0) -> None:
    if _depth >= max_depth:
        return
    try:
        entries = list(base.iterdir())
    except PermissionError:
        return

    for entry in entries:
        if entry.is_dir() and entry.name not in SKIP_DIRS:
            _walk_for_configs(entry, result, max_depth, _depth + 1)
        elif entry.is_file() and entry.name in CONFIG_FILENAMES:
            _scan_file(entry, result)
