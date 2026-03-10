"""Port exposure scanner for OpenClaw instances."""

import socket
from dataclasses import dataclass, field
from typing import List, Optional

# Common OpenClaw ports and their descriptions
OPENCLAW_PORTS = {
    3000: "OpenClaw Web UI (default)",
    3001: "OpenClaw API",
    8080: "OpenClaw HTTP proxy",
    8443: "OpenClaw HTTPS proxy",
    9090: "OpenClaw metrics/admin",
    9091: "OpenClaw internal API",
    27017: "MongoDB (common OpenClaw backend)",
    6379: "Redis (common OpenClaw cache)",
    5432: "PostgreSQL (common OpenClaw backend)",
}

BIND_ALL_INTERFACES = "0.0.0.0"
LOCALHOST = "127.0.0.1"


@dataclass
class PortResult:
    port: int
    description: str
    is_open: bool
    is_exposed: bool  # True if bound to 0.0.0.0 (externally reachable)
    severity: str  # "critical", "warning", "ok"
    fix_command: Optional[str] = None


@dataclass
class PortScanResult:
    results: List[PortResult] = field(default_factory=list)
    score_penalty: int = 0

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.severity == "ok")

    @property
    def warnings(self) -> int:
        return sum(1 for r in self.results if r.severity == "warning")

    @property
    def failures(self) -> int:
        return sum(1 for r in self.results if r.severity == "critical")


def _check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Return True if the port accepts a connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def scan_ports(target: str = LOCALHOST) -> PortScanResult:
    """
    Scan common OpenClaw ports on both localhost and 0.0.0.0.

    A port is flagged as 'exposed' if it responds on 0.0.0.0, meaning any
    interface on the machine can reach it — a potential network-level risk.
    """
    result = PortScanResult()

    for port, description in OPENCLAW_PORTS.items():
        local_open = _check_port(LOCALHOST, port)
        external_open = _check_port(BIND_ALL_INTERFACES, port)

        is_open = local_open or external_open
        is_exposed = external_open

        if not is_open:
            severity = "ok"
            fix_command = None
        elif is_exposed:
            severity = "critical"
            fix_command = _build_fix_command(port)
            result.score_penalty += 15
        else:
            # Open only on localhost — acceptable but worth noting
            severity = "warning"
            fix_command = None
            result.score_penalty += 3

        result.results.append(
            PortResult(
                port=port,
                description=description,
                is_open=is_open,
                is_exposed=is_exposed,
                severity=severity,
                fix_command=fix_command,
            )
        )

    return result


def _build_fix_command(port: int) -> str:
    """Suggest a firewall rule to block external access to the port."""
    return (
        f"sudo ufw deny {port}/tcp  "
        f"# or: sudo iptables -A INPUT -p tcp --dport {port} -j DROP"
    )
