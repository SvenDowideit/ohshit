from __future__ import annotations

import re
from typing import Any

from .models import Finding, Host, PortInfo, Severity


def _has_open_port(ports: list[PortInfo], port_num: int) -> bool:
    return any(p.port == port_num and p.state == "open" for p in ports)


def _sshd_option(config: str, key: str) -> str | None:
    """Return the effective value of a sshd_config option (ignores comments)."""
    for line in config.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(rf"^\s*{re.escape(key)}\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _check_firewall(host: Host, raw: dict[str, Any]) -> list[Finding]:
    ufw = raw.get("ufw_status", "")
    ipt = raw.get("iptables", "")
    ufw_inactive = "Status: inactive" in ufw or (not ufw.strip())
    ipt_empty = not ipt.strip() or all(
        "ACCEPT" in ln or not ln.strip() or ln.startswith("Chain") or "target" in ln
        for ln in ipt.splitlines()
    )
    if ufw_inactive and ipt_empty:
        return [Finding(
            host_ip=host.ip,
            category="firewall",
            severity=Severity.CRITICAL,
            title="No active firewall detected",
            description="Neither ufw nor iptables rules are configured. All ports are exposed.",
            remediation=[
                "sudo ufw enable",
                "sudo ufw default deny incoming",
                "sudo ufw default allow outgoing",
                "sudo ufw allow ssh",
                "sudo ufw status verbose",
            ],
            evidence=f"ufw: {ufw[:200]}\niptables: {ipt[:200]}",
        )]
    return []


def _check_shadow_readable(host: Host, raw: dict[str, Any]) -> list[Finding]:
    if not raw.get("shadow_readable"):
        return []
    return [Finding(
        host_ip=host.ip,
        category="accounts",
        severity=Severity.CRITICAL,
        title="/etc/shadow is world-readable",
        description="The shadow password file is readable by non-root users, exposing password hashes.",
        remediation=[
            "sudo chmod 640 /etc/shadow",
            "sudo chown root:shadow /etc/shadow",
        ],
    )]


def _check_empty_passwords(host: Host, raw: dict[str, Any]) -> list[Finding]:
    users = raw.get("shadow_empty_pw", [])
    if not users:
        return []
    return [Finding(
        host_ip=host.ip,
        category="accounts",
        severity=Severity.CRITICAL,
        title=f"Accounts with empty passwords: {', '.join(users)}",
        description="One or more user accounts have no password set, allowing passwordless login.",
        remediation=[
            f"sudo passwd {u}" for u in users
        ] + ["sudo passwd --lock <username>  # if account is unused"],
        evidence=", ".join(users),
    )]


def _check_telnet(host: Host, raw: dict[str, Any]) -> list[Finding]:
    if not _has_open_port(host.open_ports, 23):
        return []
    return [Finding(
        host_ip=host.ip,
        category="ports",
        severity=Severity.CRITICAL,
        title="Telnet port 23 is open",
        description="Telnet transmits credentials and data in plaintext. Replace with SSH.",
        remediation=[
            "sudo systemctl disable telnet --now",
            "sudo apt remove telnetd -y  # or equivalent for your distro",
            "Use SSH instead: ssh user@host",
        ],
    )]


def _check_docker_socket(host: Host, raw: dict[str, Any]) -> list[Finding]:
    ports_out = raw.get("listening_ports", "")
    if "docker.sock" not in ports_out and ":2375" not in ports_out and ":2376" not in ports_out:
        return []
    return [Finding(
        host_ip=host.ip,
        category="docker",
        severity=Severity.CRITICAL,
        title="Docker socket or daemon port exposed",
        description="The Docker socket or TCP daemon is accessible, granting root-equivalent control.",
        remediation=[
            "Ensure Docker daemon is not listening on TCP: remove -H tcp:// from dockerd args",
            "Check /etc/docker/daemon.json for 'hosts' key",
            "Restrict /var/run/docker.sock permissions: sudo chmod 660 /var/run/docker.sock",
            "Use rootless Docker or namespace isolation",
        ],
        evidence=ports_out[:300],
    )]


def _check_ssh_password_auth(host: Host, raw: dict[str, Any]) -> list[Finding]:
    config = raw.get("sshd_config", "")
    val = _sshd_option(config, "PasswordAuthentication")
    if val and val.lower() == "yes":
        return [Finding(
            host_ip=host.ip,
            category="ssh_config",
            severity=Severity.HIGH,
            title="SSH PasswordAuthentication is enabled",
            description="Password-based SSH logins are allowed, enabling brute-force attacks.",
            remediation=[
                "Edit /etc/ssh/sshd_config",
                "Set: PasswordAuthentication no",
                "sudo systemctl restart sshd",
            ],
        )]
    return []


def _check_ssh_permit_root(host: Host, raw: dict[str, Any]) -> list[Finding]:
    config = raw.get("sshd_config", "")
    val = _sshd_option(config, "PermitRootLogin")
    if val and val.lower() == "yes":
        return [Finding(
            host_ip=host.ip,
            category="ssh_config",
            severity=Severity.HIGH,
            title="SSH PermitRootLogin is enabled",
            description="Root can log in directly via SSH, bypassing audit trails.",
            remediation=[
                "Edit /etc/ssh/sshd_config",
                "Set: PermitRootLogin no  # or 'prohibit-password'",
                "sudo systemctl restart sshd",
            ],
        )]
    return []


def _check_kernel_updates(host: Host, raw: dict[str, Any]) -> list[Finding]:
    upgrades = raw.get("kernel_upgrades", "").strip()
    if not upgrades:
        return []
    return [Finding(
        host_ip=host.ip,
        category="kernel",
        severity=Severity.HIGH,
        title="Kernel updates available",
        description="Unpatched kernel may contain exploitable vulnerabilities.",
        remediation=[
            "sudo apt update && sudo apt upgrade -y",
            "sudo reboot  # to boot into new kernel",
        ],
        evidence=upgrades[:300],
    )]


def _check_docker_privileged(host: Host, raw: dict[str, Any]) -> list[Finding]:
    docker_ps = raw.get("docker_ps", "")
    if "--privileged" not in docker_ps.lower() and "privileged" not in docker_ps.lower():
        return []
    return [Finding(
        host_ip=host.ip,
        category="docker",
        severity=Severity.HIGH,
        title="Privileged Docker containers running",
        description="Privileged containers have full host access and can escape isolation.",
        remediation=[
            "Audit docker-compose.yml or run commands for --privileged flag",
            "Remove --privileged and use specific --cap-add capabilities instead",
            "Review: docker inspect <container> | grep Privileged",
        ],
        evidence=docker_ps[:300],
    )]


def _check_ftp(host: Host, raw: dict[str, Any]) -> list[Finding]:
    if not _has_open_port(host.open_ports, 21):
        return []
    return [Finding(
        host_ip=host.ip,
        category="ports",
        severity=Severity.HIGH,
        title="FTP port 21 is open",
        description="FTP transmits credentials in plaintext. Use SFTP or FTPS instead.",
        remediation=[
            "sudo systemctl disable vsftpd --now  # or your FTP daemon",
            "Use SFTP (built into SSH) instead: sftp user@host",
        ],
    )]


def _check_ssh_x11(host: Host, raw: dict[str, Any]) -> list[Finding]:
    config = raw.get("sshd_config", "")
    val = _sshd_option(config, "X11Forwarding")
    if val and val.lower() == "yes":
        return [Finding(
            host_ip=host.ip,
            category="ssh_config",
            severity=Severity.MEDIUM,
            title="SSH X11Forwarding is enabled",
            description="X11 forwarding can expose the display to hijacking attacks.",
            remediation=[
                "Edit /etc/ssh/sshd_config",
                "Set: X11Forwarding no",
                "sudo systemctl restart sshd",
            ],
        )]
    return []


def _check_outdated_packages(host: Host, raw: dict[str, Any]) -> list[Finding]:
    upgradable = raw.get("apt_upgradable", "")
    lines = [ln for ln in upgradable.splitlines() if ln.strip() and "Listing..." not in ln]
    count = len(lines)
    if count == 0:
        return []
    if count > 10:
        sev, title = Severity.MEDIUM, f"{count} outdated packages"
    else:
        sev, title = Severity.LOW, f"{count} outdated package(s)"
    return [Finding(
        host_ip=host.ip,
        category="packages",
        severity=sev,
        title=title,
        description=f"{count} packages have available upgrades, potentially including security fixes.",
        remediation=[
            "sudo apt update",
            "sudo apt upgrade -y",
            "sudo apt autoremove -y",
        ],
        evidence="\n".join(lines[:20]),
    )]


def _check_http_no_https(host: Host, raw: dict[str, Any]) -> list[Finding]:
    has_80 = _has_open_port(host.open_ports, 80)
    has_443 = _has_open_port(host.open_ports, 443)
    if has_80 and not has_443:
        return [Finding(
            host_ip=host.ip,
            category="ports",
            severity=Severity.MEDIUM,
            title="HTTP (port 80) open without HTTPS (443)",
            description="Unencrypted HTTP traffic can be intercepted or tampered with.",
            remediation=[
                "Configure your web server to serve HTTPS",
                "Obtain a certificate: sudo certbot --nginx  # or --apache",
                "Redirect HTTP to HTTPS in your server config",
            ],
        )]
    return []


def _check_world_listeners(host: Host, raw: dict[str, Any]) -> list[Finding]:
    """Flag unexpected services bound to 0.0.0.0."""
    ports_out = raw.get("listening_ports", "")
    known_ports = {22, 80, 443, 53, 123, 5353, 8080, 8443}
    unexpected: list[str] = []
    for line in ports_out.splitlines():
        # ss output: State Recv-Q Send-Q Local Address:Port Peer
        m = re.search(r"0\.0\.0\.0:(\d+)", line)
        if m:
            p = int(m.group(1))
            if p not in known_ports and p not in {port.port for port in host.open_ports}:
                unexpected.append(f"port {p}: {line.strip()}")
    if not unexpected:
        return []
    return [Finding(
        host_ip=host.ip,
        category="ports",
        severity=Severity.MEDIUM,
        title=f"Unexpected service(s) bound to all interfaces: {len(unexpected)} found",
        description="Services listening on 0.0.0.0 are accessible from any network interface.",
        remediation=[
            "Review: ss -tlnp  to identify these services",
            "Bind services to 127.0.0.1 if only local access is needed",
            "Configure firewall rules to restrict external access",
        ],
        evidence="\n".join(unexpected[:10]),
    )]


_RULES = [
    _check_firewall,
    _check_shadow_readable,
    _check_empty_passwords,
    _check_telnet,
    _check_docker_socket,
    _check_ssh_password_auth,
    _check_ssh_permit_root,
    _check_kernel_updates,
    _check_docker_privileged,
    _check_ftp,
    _check_ssh_x11,
    _check_outdated_packages,
    _check_http_no_https,
    _check_world_listeners,
]


class RiskEngine:
    def analyze(self, host: Host, raw: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in _RULES:
            try:
                findings.extend(rule(host, raw))
            except Exception:
                pass  # never let a bad rule crash the scan
        return sorted(findings, key=lambda f: f.score, reverse=True)
