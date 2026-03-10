# ClawGuard

**One-command security scanner for OpenClaw instances.**

ClawGuard audits your local OpenClaw setup across three attack surfaces and
outputs a colour-coded report with a 0–100 security score, a per-finding
severity badge, and ready-to-run fix commands.

---

## Features

| Check | What it detects |
|---|---|
| **Port Exposure** | Common OpenClaw ports open on `0.0.0.0` (externally reachable) |
| **Secret Leaks** | Hardcoded API keys, passwords, tokens, AWS/GitHub credentials in config files |
| **Permission Audit** | Private keys and `.env` files with overly permissive `chmod` modes |

- Score 0–100 with letter grade (A–F)
- `✅ / ⚠️ / ❌` per finding
- Auto-fix mode (`--fix`) applies safe `chmod` corrections after confirmation
- `--fail-under <SCORE>` exits with code 1 — ideal for CI pipelines

---

## Requirements

- Python 3.8+
- Dependencies: `click >= 8.0`, `rich >= 13.0`

---

## Installation

```bash
pip install clawguard
```

Or install from source:

```bash
git clone https://github.com/openclaw/clawguard
cd clawguard
pip install -e .
```

---

## Usage

```
clawguard [OPTIONS]

Options:
  --target HOST          Host to probe for open ports  [default: 127.0.0.1]
  --scan-dir DIR         Extra directory for secret/permission scans (repeatable)
  --fix                  Auto-apply safe chmod fixes (prompts for confirmation)
  --skip-ports           Skip port exposure scan
  --skip-secrets         Skip hardcoded secret scan
  --skip-permissions     Skip file permission audit
  --fail-under SCORE     Exit 1 if score < SCORE (for CI)
  -V, --version          Show version and exit
  -h, --help             Show this message and exit
```

### Examples

```bash
# Full scan of localhost
clawguard

# Scan a different host and include an extra directory
clawguard --target 192.168.1.10 --scan-dir ~/projects/myapp

# Auto-fix permission issues
clawguard --fix

# Fail CI if score drops below 80
clawguard --fail-under 80
```

---

## Sample Output

```
╭──────────────────────────────────────────╮
│  ClawGuard  — OpenClaw Security Scanner  │
╰──────────────────────────────────────────╯

╭─ Port Exposure Scan ───────────────────────────────────────────────────────╮
│  ✅  3000  OpenClaw Web UI (default)      Closed                           │
│  ❌  8080  OpenClaw HTTP proxy            EXPOSED (0.0.0.0)  sudo ufw ...  │
│  ⚠️   9090  OpenClaw metrics/admin        Open (localhost only)            │
╰────────────────────────────────────────────────────────────────────────────╯

╭─ API Key & Secret Leak Scan ───────────────────────────────────────────────╮
│  ❌  ./config.yaml  line 12  Generic API Key  apik****ey  Rotate the ...   │
╰────────────────────────────────────────────────────────────────────────────╯

╭─ Permission Audit ─────────────────────────────────────────────────────────╮
│  ❌  ~/.openclaw/id_rsa  0o644 (-rw-r--r--)  0o600  chmod 600 ...         │
╰────────────────────────────────────────────────────────────────────────────╯

╭─ ClawGuard Security Summary ───────────────────────────────────────────────╮
│  Security Score: 50/100  (Grade F)                                         │
│  Critical Issues : 3                                                       │
│  Warnings        : 1                                                       │
│  Action required — fix critical issues immediately.                        │
╰────────────────────────────────────────────────────────────────────────────╯
```

---

## Scoring

The base score is **100**. Penalties are deducted per finding:

| Finding type | Penalty |
|---|---|
| Port exposed on `0.0.0.0` | −15 per port |
| Port open on localhost only | −3 per port |
| Hardcoded secret / credential | −20 per occurrence |
| Critical file permission issue | −15 per file |
| Warning-level permission issue | −5 per file |

Score is clamped to `[0, 100]`.

---

## License

MIT — see [LICENSE](LICENSE).
