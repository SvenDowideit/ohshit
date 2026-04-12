# oh-shit

A terminal dashboard that scans your home network, SSH-spiders into reachable
hosts, and gives you a live view of security risks, severity scores, remediation
steps, and a full Software Bill of Materials (SBOM) for every host.

```
┌─ Oh-Shit Network Security Dashboard ──────────── High risk (score 22) ─┐
│ Hosts          │ Host Details  │ Findings  │ Remediation  │ SBOM  │ Vulns│
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
└────────── r:Re-scan  s:Re-scan host  b:SBOM  v:Vulns  e:Export  q:Quit ┘
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
(`SSH_AUTH_SOCK`) and runs read-only commands concurrently:

- OS and kernel version
- Running systemd services
- Listening ports (`ss -tlnp`)
- UFW / iptables firewall status
- `/etc/ssh/sshd_config` audit
- Available package upgrades (`apt`)
- Docker containers and images
- User accounts and sudo membership
- Shadow file readability
- Package inventory for SBOM (see below)

Up to 5 hosts are collected in parallel. Hosts that are unreachable or reject
the key are marked **SSH Failed** and shown without findings.

> **Note:** SSH host-key verification is disabled by default so newly
> re-imaged LAN devices don't block scans. Enable strict checking with
> `ohshit --strict-host-keys`.

### 3 — Passive IoT detection

Before per-host SSH collection, the tool listens passively on the LAN for
device announcements:

- **mDNS / Bonjour** — captures device names and service types advertised on
  `224.0.0.251:5353`
- **SSDP / UPnP** — sends an M-SEARCH multicast and parses SSDP responses for
  friendly names and model information
- **MAC OUI lookup** — maps the first 24 bits of each MAC address to a vendor
  name (IEEE registry, cached locally)
- **Banner grabbing** — connects to common IoT ports and reads the first bytes
  to identify device type
- **ESPHome native API** — probes port 6053 for ESPHome firmware metadata
  (device name, version, board, project)
- **Home Assistant** — optionally queries the HA REST API (pass `--ha-token`)
  to correlate devices with HA entity IDs

### 4 — Risk scoring

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

### 5 — SBOM collection

After a successful SSH session, the tool collects a full Software Bill of
Materials for the host by querying the package managers available on the
remote system:

| Tool / command | Package type | What is collected |
|----------------|-------------|-------------------|
| `dpkg-query -W` | `deb` | All installed Debian/Ubuntu packages — name, version, architecture |
| `rpm -qa` | `rpm` | All installed RPM packages (RHEL, Fedora, openSUSE) — name, version-release, architecture |
| `snap list` | `snap` | Installed Snap packages — name, version |
| `flatpak list` | `flatpak` | Installed Flatpak apps — application ID, version, origin |
| `pip3 list --format=freeze` | `python` | System Python packages (both system-wide and user `--user` installs) |
| `docker images` | `container` | All container images present on the host — repository, tag |

Only the tools present on the target host produce output; the rest return
nothing and are silently skipped.

#### Storage

Each SBOM collection is stored as its own DuckDB database:

```
sbom/
  <host-id>/           # MAC address preferred, IP fallback
    20260412T143200.duckdb
    20260411T091500.duckdb
    ...
  sbom_catalog.ducklake   # DuckLake catalog index
  catalog_data/           # DuckLake Parquet data files
```

The **host ID** uses the MAC address when known so SBOM history follows the
hardware, not the IP — useful when DHCP leases change.

Under normal operation only the **latest** SBOM for each host is shown in the
UI. All historical databases are kept on disk for manual comparison or
archaeology — they are never deleted and never overwritten. A new SBOM is only
collected if none exists for the host, or if the most recent one is more than
24 hours old.

The [DuckLake](https://ducklake.select/) extension provides a unified catalog
view across all per-host databases. It is installed automatically by DuckDB on
first run (`INSTALL ducklake`).

### 6 — Vulnerability matching

After SBOM collection, press `v` to query public vulnerability databases for
every package on the selected host.  Results are cached locally and shown
immediately on subsequent launches.

#### Sources

| Source | What it covers | Auth required |
|--------|---------------|---------------|
| [OSV](https://osv.dev/) (Google) | Debian, Ubuntu, PyPI, Red Hat, openSUSE, Alpine, Rocky Linux, AlmaLinux, Fedora, npm, Cargo, Go, RubyGems, NuGet, and 30+ more ecosystems | None |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CISA) | ~1,500 CVEs with confirmed active exploitation in the wild | None |

Snap, Flatpak, and container image tags are not indexed by OSV and produce no
results.

#### Ecosystem mapping

| SBOM source | OSV ecosystems queried |
|-------------|----------------------|
| `dpkg` | Debian, Ubuntu |
| `rpm` | Red Hat, openSUSE, AlmaLinux, Rocky Linux, Fedora |
| `pip` | PyPI |
| `snap` | — (not indexed) |
| `flatpak` | — (not indexed) |
| `docker` | — (image tags not indexed) |

#### Cache

Vulnerability data is cached in `~/.cache/ohshit/vuln.duckdb` — separate from
the per-project `ohshit.db` so it is shared across runs and reused when you
re-scan different subnets.

#### Display

- **SBOM tab** — adds a `CVEs` column showing the count of matching advisories
  per package (shown in red when non-zero).
- **Vulnerabilities tab** — full advisory table with advisory ID, a `★` badge
  for entries in the CISA KEV catalog (actively exploited), severity, CVSS
  score, affected package, and summary text.  Packages with the most CVEs are
  listed first.

### 7 — Dashboard

The Textual TUI refreshes as data arrives:

- **Left panel** — host list sorted by risk score, with coloured severity badges
- **Right panel (tabbed)**
  - *Host Details* — IP, MAC, OS, kernel, vendor, IoT identifiers, open ports
  - *Findings* — table of all findings sorted by severity
  - *Remediation* — copy-pasteable fix commands for each finding
  - *SBOM* — package inventory for the selected host, showing release age, source, name,
    version, architecture, and CVE count; header shows collection timestamp and
    total package count
  - *Vulnerabilities* — CVE advisory list for the selected host's packages,
    with KEV active-exploitation badge (★), severity, CVSS score, and summary
- **Bottom** — scan progress bar and live log

#### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `r` | Re-scan all hosts |
| `s` | Re-scan the selected host |
| `b` | Force SBOM collection for the selected host (bypasses the 24 h age check) |
| `v` | Query vulnerability databases for the selected host's SBOM packages |
| `e` | Export Markdown report to `~/network-security-report-<timestamp>.md` |
| `q` | Quit |

## CLI options

```
ohshit [--no-ssh] [--subnet CIDR] [--strict-host-keys] [--ha-token TOKEN] [--db PATH]

  --no-ssh            Discovery only — skip SSH login and data collection
  --subnet CIDR       Override auto-detected subnet, e.g. 192.168.1.0/24
  --strict-host-keys  Verify SSH host keys via ~/.ssh/known_hosts
  --ha-token TOKEN    Home Assistant long-lived access token for IoT correlation
  --db PATH           Path to the main DuckDB database (default: ohshit.db)
```

## Data persistence

All scan data is stored in a DuckDB database (`ohshit.db` by default) and
persists across runs. Hosts are never deleted — offline hosts are marked
**Unreachable** and remain in the list. Previously seen MAC addresses are
tracked in a separate append-only history table to detect hardware repurposing.

SBOM databases accumulate in the `sbom/` directory next to the main database
and are never automatically removed.

Vulnerability data is cached in `~/.cache/ohshit/vuln.duckdb` and is shared
across all projects and runs.  It is never automatically purged — press `v`
to refresh it on demand.

## Project layout

```
src/ohshit/
  models.py          Dataclasses: Host, Finding, PortInfo, IotInfo, ScanResult, enums
  discovery.py       ARP / ping sweep / nmap / router ARP
  ssh_collector.py   asyncssh remote command collection + SBOM command definitions
  risk_engine.py     Scoring rules → Finding objects
  sbom.py            SBOM collection, parsing, per-host DuckDB storage, DuckLake catalog
  vuln_db.py         Vulnerability cache — OSV + CISA KEV, local DuckDB at ~/.cache/ohshit/vuln.duckdb
  port_probe.py      Deep port banner / TLS / ESPHome probing
  iot.py             mDNS sniff, UPnP/SSDP, Home Assistant, IoT device detection
  oui_db.py          MAC OUI vendor lookup and MAC permanence classification
  report.py          Markdown report generator
  main.py            CLI entry point
  tui/
    app.py           Textual App, scanner pipeline, DB polling, SBOM/vuln wiring
    widgets.py       Custom widgets: host list, findings table, SBOM tab, vuln tab, etc.
    app.tcss         Textual CSS layout and theming
```

## Python dependencies

| Library | Purpose |
|---------|---------|
| [Textual](https://textual.textualize.io/) | Terminal UI framework |
| [asyncssh](https://asyncssh.readthedocs.io/) | Async SSH client for remote collection |
| [DuckDB](https://duckdb.org/) | Embedded analytics database (hosts, findings, SBOM, vuln cache) |
| [DuckLake](https://ducklake.select/) | Catalog layer unifying per-host SBOM databases (DuckDB extension, auto-installed) |
| [aiohttp](https://docs.aiohttp.org/) | Async HTTP for Home Assistant, UPnP probing, and OSV API queries |
| [aiofiles](https://github.com/Tinche/aiofiles) | Async file I/O for report export |
| [cryptography](https://cryptography.io/) | TLS certificate inspection |
| [rich](https://rich.readthedocs.io/) | Terminal formatting (used by Textual) |

## Development

```bash
make setup          # first-time setup
make run-dev        # hot-reload TUI (changes to .py/.tcss reload instantly)
make test           # pytest
make lint           # syntax check
```

The TUI is built with [Textual](https://textual.textualize.io/). Network
discovery and SSH collection are fully async (`asyncio` + `asyncssh`) and run
in a background thread with its own event loop, writing to DuckDB via WAL
which the UI thread reads without locking.

## Security notes

- The tool only reads data from remote hosts; it does not modify anything.
- All SSH connections use your existing keys/agent — no passwords are stored.
- `known_hosts` checking is off by default for LAN convenience; use
  `--strict-host-keys` in higher-trust environments.
- The exported Markdown report may contain sensitive system information
  (open ports, package versions, account names). Treat it accordingly.
- SBOM databases stored in `sbom/` contain full package inventories for each
  host. Restrict access to this directory appropriately.
- Vulnerability queries are sent to `api.osv.dev` (Google) and
  `www.cisa.gov` — the package names and versions of every installed package
  on your hosts are transmitted. Do not use `v` on air-gapped networks or
  where package inventory must remain confidential.
