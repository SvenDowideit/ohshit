from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Callable

from .models import Host, HostState, PortInfo


RAW_COMMANDS: dict[str, str] = {
    "uname":            "uname -a",
    "os_release":       "cat /etc/os-release 2>/dev/null || true",
    "kernel_upgrades":  "apt list --upgradable 2>/dev/null | grep -i linux | grep -v 'Listing' || true",
    "services":         "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || true",
    "listening_ports":  "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true",
    "passwd":           "cat /etc/passwd 2>/dev/null || true",
    "sudo_members":     "getent group sudo wheel 2>/dev/null || true",
    "ufw_status":       "sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null || true",
    "iptables":         "sudo -n iptables -L -n 2>/dev/null || true",
    "sshd_config":      "cat /etc/ssh/sshd_config 2>/dev/null || true",
    "docker_ps":        "docker ps -a 2>/dev/null || true",
    "docker_images":    "docker images 2>/dev/null || true",
    "apt_upgradable":   "apt list --upgradable 2>/dev/null || true",
    # SBOM collection commands
    "sbom_dpkg":        "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null || true",
    "sbom_rpm":         "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' 2>/dev/null || true",
    "sbom_snap":        "snap list 2>/dev/null || true",
    "sbom_flatpak":     "flatpak list --columns=application,version,origin 2>/dev/null || true",
    "sbom_pip":         "pip3 list --format=freeze 2>/dev/null || pip list --format=freeze 2>/dev/null || true",
    "sbom_pip_user":    "pip3 list --user --format=freeze 2>/dev/null || true",
}


class RemoteCollector:
    async def collect(self, host: Host) -> dict[str, Any]:
        """SSH into host and gather security-relevant data. Returns empty dict on failure."""
        try:
            import asyncssh
        except ImportError:
            host.state = HostState.SSH_FAILED
            host.ssh_error = "asyncssh not installed"
            return {}

        username = os.getenv("USER", "")
        connect_kwargs: dict[str, Any] = dict(
            username=username,
            agent_forwarding=True,
            known_hosts=None,
            connect_timeout=10,
            login_timeout=15,
        )

        # Add client keys explicitly if no agent socket
        if not os.environ.get("SSH_AUTH_SOCK"):
            key_paths = [
                os.path.expanduser("~/.ssh/id_ed25519"),
                os.path.expanduser("~/.ssh/id_rsa"),
                os.path.expanduser("~/.ssh/id_ecdsa"),
            ]
            existing_keys = [p for p in key_paths if os.path.exists(p)]
            if existing_keys:
                connect_kwargs["client_keys"] = existing_keys

        try:
            import asyncssh
            async with asyncssh.connect(host.ip, **connect_kwargs) as conn:
                host.state = HostState.SCANNING
                raw = await self._run_commands(conn)
                await self._check_shadow(conn, raw)
                host.state = HostState.SSH_SUCCESS
                return raw
        except Exception as exc:
            # Catch all asyncssh and network errors
            host.state = HostState.SSH_FAILED
            host.ssh_error = _summarise_error(exc)
            return {}

    async def _run_commands(self, conn: Any) -> dict[str, Any]:
        keys = list(RAW_COMMANDS.keys())
        cmds = list(RAW_COMMANDS.values())

        async def run_one(cmd: str) -> str:
            try:
                result = await conn.run(cmd, timeout=30)
                return result.stdout or ""
            except Exception:
                return ""

        outputs = await asyncio.gather(*[run_one(c) for c in cmds])
        return dict(zip(keys, outputs))

    async def _check_shadow(self, conn: Any, raw: dict[str, Any]) -> None:
        try:
            r = await conn.run("test -r /etc/shadow && echo READABLE || echo NOREAD", timeout=10)
            raw["shadow_readable"] = "READABLE" in (r.stdout or "")
        except Exception:
            raw["shadow_readable"] = False

        if raw.get("shadow_readable"):
            try:
                r = await conn.run(
                    "awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null || true",
                    timeout=10,
                )
                raw["shadow_empty_pw"] = [
                    u for u in (r.stdout or "").splitlines() if u.strip()
                ]
            except Exception:
                raw["shadow_empty_pw"] = []
        else:
            raw["shadow_empty_pw"] = []


def _apply_os_release(host: Host, raw: dict) -> None:
    """Parse uname + os-release + ss output from raw SSH data into host fields."""
    uname = raw.get("uname", "")
    if uname:
        parts = uname.split()
        if len(parts) >= 3:
            host.kernel_version = parts[2]
        if len(parts) >= 1:
            host.os_guess = host.os_guess or parts[0]

    os_release_raw = raw.get("os_release", "")
    if os_release_raw:
        parsed: dict[str, str] = {}
        for line in os_release_raw.splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                parsed[k.strip()] = v.strip().strip('"')
        if parsed:
            host.os_release = parsed
            host.os_guess = host.os_guess or parsed.get("PRETTY_NAME") or parsed.get("NAME")

    # Parse ss/netstat listening ports into open_ports.
    # Keep nmap-discovered ports for any port ss doesn't report (e.g. UDP).
    ss_ports = _parse_ss_ports(raw.get("listening_ports", ""))
    if ss_ports:
        # Merge: ss wins for TCP (it has process names); keep existing non-TCP ports
        existing_non_tcp = [p for p in host.open_ports if p.protocol != "tcp"]
        host.open_ports = ss_ports + existing_non_tcp


def _parse_ss_ports(ss_output: str) -> list[PortInfo]:
    """Parse `ss -tlnp` or `netstat -tlnp` output into PortInfo list.

    ss -tlnp columns (no Netid since -t filters to tcp):
      State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  [Process]

    netstat -tlnp columns:
      Proto  Recv-Q  Send-Q  Local Address  Foreign Address  State  [PID/prog]
    """
    ports: list[PortInfo] = []
    seen: set[int] = set()

    for line in ss_output.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        local_addr: str | None = None
        service_hint = ""

        # Detect format by first token
        first = parts[0].lower()

        if first in ("tcp", "tcp6", "udp", "udp6"):
            # netstat format: proto recv-q send-q local foreign state [pid/prog]
            if len(parts) < 4:
                continue
            local_addr = parts[3]
            if len(parts) >= 7:
                prog_field = parts[6]
                service_hint = prog_field.split("/")[-1] if "/" in prog_field else ""

        elif first in ("listen", "estab", "time-wait", "close-wait"):
            # ss format (no Netid column): state recv-q send-q local peer [process]
            if len(parts) < 4:
                continue
            local_addr = parts[3]
            if len(parts) >= 6:
                m = re.search(r'"([^"]+)"', parts[5])
                if m:
                    service_hint = m.group(1)

        elif first.startswith("netid") or first.startswith("state") or first.startswith("active") or first.startswith("proto"):
            continue  # header lines

        else:
            # ss format WITH Netid column (e.g. when run without -t):
            # netid state recv-q send-q local peer [process]
            if first in ("tcp", "udp") or len(parts) >= 5:
                if len(parts) >= 5:
                    local_addr = parts[4]
                if len(parts) >= 7:
                    m = re.search(r'"([^"]+)"', parts[6])
                    if m:
                        service_hint = m.group(1)

        if not local_addr:
            continue

        # Extract port: last colon-separated segment
        port_str = local_addr.rsplit(":", 1)[-1]
        if not port_str.isdigit():
            continue
        port = int(port_str)
        if port == 0 or port in seen:
            continue
        seen.add(port)

        if not service_hint:
            try:
                service_hint = __import__("socket").getservbyport(port, "tcp")
            except OSError:
                service_hint = ""

        ports.append(PortInfo(
            port=port,
            protocol="tcp",
            state="open",
            service=service_hint,
            version="",
        ))

    return sorted(ports, key=lambda p: p.port)


def _summarise_error(exc: Exception) -> str:
    name = type(exc).__name__
    msg = str(exc)
    return f"{name}: {msg[:120]}" if msg else name


async def collect_all(
    hosts: dict[str, Host],
    progress_cb: Callable[[str, int], None] | None = None,
    no_ssh: bool = False,
) -> dict[str, dict[str, Any]]:
    """Collect SSH data from all hosts. Returns {ip: raw_data}."""
    if no_ssh:
        return {}

    collector = RemoteCollector()
    sem = asyncio.Semaphore(5)
    results: dict[str, dict[str, Any]] = {}
    total = len(hosts)
    done = 0

    async def collect_one(host: Host) -> None:
        nonlocal done
        async with sem:
            raw = await collector.collect(host)
            results[host.ip] = raw
        done += 1
        pct = int(done / total * 100) if total else 100
        if progress_cb:
            progress_cb(f"SSH collected {host.display_name}", pct)

    await asyncio.gather(*[collect_one(h) for h in hosts.values()])
    return results
