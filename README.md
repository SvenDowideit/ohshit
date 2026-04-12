# oh-shit

A terminal dashboard that scans your home network, SSH-spiders into reachable
hosts, and gives you a live view of security risks, severity scores, and
remediation steps.

```
┌─ Oh-Shit Network Security Dashboard ──────────── High risk (score 22) ─┐
│ Hosts          │ Host Details  │ Findings  │ Remediation               │
│                │                                                        │
│ CRIT router    │  192.168.1.1 (router) — Critical risk (score 32)      │
│ HIGH myserver  │  OS: OpenWrt 23.05                                     │
│  LOW laptop    │  Kernel: 5.15.134                                      │
│  LOW pi-hole   │  MAC: aa:bb:cc:dd:ee:ff                                │
│                │                                                        │
│                │  Open Ports:                                           │
│                │  22  tcp  ssh      OpenSSH 9.1                         │
│                │  80  tcp  http     lighttpd 1.4.73                     │
│                │  443 tcp  https    lighttpd 1.4.73                     │
│────────────────────────────────────────────────────────────────────────│
│ [SSH: myserver]                                              [████  80%]│
│ 14:32:07 Discovery done: 8 hosts found                                  │
└────────────────── r:Re-scan  s:Re-scan host  e:Export  q:Quit ─────────┘
```

## Quick start

```bash
git clone <this-repo>
cd oh-shit
make setup
make run
```

That's it. `make setup` installs [uv](https://docs.astral.sh/uv/) if it isn't
already on your system, then creates a virtual environment and installs all
Python dependencies.

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.12+ | Managed automatically by `uv` |
| `ping` | Present on all Linux/macOS systems |
| `ip` / `arp` | Standard Linux networking tools |
| `nmap` (optional) | Enables port scanning and OS detection. `sudo apt install nmap` |
| SSH key or agent | Used to log into discovered hosts |

> **Root / sudo:** Not required to run. Some data (OS fingerprinting via
> `nmap -O`, reading remote `iptables` rules) requires root on the target
> host. The tool degrades gracefully when privileges are unavailable.

## Make targets

```
make setup        Install uv (if needed) and all Python dependencies
make run          Launch the full TUI — discovers hosts then SSH-collects data
make run-no-ssh   Discovery only, no SSH login (faster, less detail)
make run-dev      Textual hot-reload mode for UI development
make test         Run the test suite
make lint         Syntax-check all source files
make clean        Remove .venv and cache directories
```

## How it works

### 1 — Discovery (all methods run in parallel)

| Method | What it finds |
|--------|--------------|
| Local ARP table (`/proc/net/arp`) | Hosts your machine already knows about |
| ICMP ping sweep | All live hosts on the detected subnet (up to /24) |
| Gateway ARP table | SSH into your router and read its neighbour table |
| nmap `-sV` | Open ports, service names, and version banners |

The subnet and gateway are detected automatically from `ip route`. Override
with `--subnet 192.168.1.0/24` if needed.

### 2 — SSH collection

For each reachable host, the tool connects with your existing SSH key or agent
(`SSH_AUTH_SOCK`) and runs ~13 read-only commands concurrently:

- OS and kernel version
- Running systemd services
- Listening ports (`ss -tlnp`)
- UFW / iptables firewall status
- `/etc/ssh/sshd_config` audit
- Available package upgrades (`apt`)
- Docker containers and images
- User accounts and sudo membership
- Shadow file readability

Up to 5 hosts are collected in parallel. Hosts that are unreachable or reject
the key are marked **SSH Failed** and shown without findings.

> **Note:** SSH host-key verification is disabled by default so newly
> re-imaged LAN devices don't block scans. Enable strict checking with
> `ohshit --strict-host-keys`.

### 3 — Risk scoring

Each collected data point is evaluated against 14 security rules:

| Rule | Severity | Score |
|------|----------|------:|
| No active firewall | Critical | 10 |
| `/etc/shadow` world-readable | Critical | 10 |
| Accounts with empty passwords | Critical | 10 |
| Telnet (port 23) open | Critical | 10 |
| Docker socket / daemon port exposed | Critical | 10 |
| SSH `PasswordAuthentication yes` | High | 5 |
| SSH `PermitRootLogin yes` | High | 5 |
| Kernel update available | High | 5 |
| Privileged Docker containers | High | 5 |
| FTP (port 21) open | High | 5 |
| SSH `X11Forwarding yes` | Medium | 2 |
| >10 outdated packages | Medium | 2 |
| HTTP without HTTPS | Medium | 2 |
| Unexpected service on `0.0.0.0` | Medium | 2 |
| 1–10 outdated packages | Low | 1 |

**Per-host score** = sum of finding scores.  
**Risk label:** Critical ≥ 30 · High ≥ 15 · Medium ≥ 8 · Low > 0 · Info = 0  
**Network score** = max(host scores) + mean(host scores)

### 4 — Dashboard

The Textual TUI refreshes as data arrives:

- **Left panel** — host list sorted by risk score, with coloured severity badges
- **Right panel (tabbed)**
  - *Host Details* — IP, MAC, OS, kernel, open ports
  - *Findings* — table of all findings sorted by severity
  - *Remediation* — copy-pasteable fix commands for each finding
- **Bottom** — scan progress bar and live log

#### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `r` | Re-scan all hosts |
| `s` | Re-scan the selected host |
| `e` | Export Markdown report to `~/network-security-report-<timestamp>.md` |
| `q` | Quit |

## CLI options

```
ohshit [--no-ssh] [--subnet CIDR] [--strict-host-keys]

  --no-ssh            Discovery only — skip SSH login and data collection
  --subnet CIDR       Override auto-detected subnet, e.g. 192.168.1.0/24
  --strict-host-keys  Verify SSH host keys via ~/.ssh/known_hosts
```

## Project layout

```
src/ohshit/
  models.py          Dataclasses: Host, Finding, ScanResult, enums
  discovery.py       ARP / ping sweep / nmap / router ARP
  ssh_collector.py   asyncssh remote command collection
  risk_engine.py     Scoring rules → Finding objects
  report.py          Markdown report generator
  main.py            CLI entry point
  tui/
    app.py           Textual App, workers, bindings
    widgets.py       Custom widgets (host list, findings table, etc.)
    app.tcss         Textual CSS layout and theming
```

## Development

```bash
make setup          # first-time setup
make run-dev        # hot-reload TUI (changes to .py/.tcss reload instantly)
make test           # pytest
make lint           # syntax check
```

The TUI is built with [Textual](https://textual.textualize.io/). Network
discovery and SSH collection are fully async (`asyncio` + `asyncssh`) and run
as Textual worker tasks on the same event loop — no threads needed.

## Security notes

- The tool only reads data from remote hosts; it does not modify anything.
- All SSH connections use your existing keys/agent — no passwords are stored.
- `known_hosts` checking is off by default for LAN convenience; use
  `--strict-host-keys` in higher-trust environments.
- The exported Markdown report may contain sensitive system information
  (open ports, package versions, account names). Treat it accordingly.
