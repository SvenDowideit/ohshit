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


def _update_cmds(host: Host) -> list[str]:
    """Return distro-appropriate package update commands for this host."""
    from .distro_eol import update_cmds
    return update_cmds(host.os_release)


def _svc_restart_cmd(host: Host, service: str) -> str:
    """Return the right restart command for systemd vs openrc vs other inits."""
    # Nearly all modern distros use systemd; keep it simple
    return f"sudo systemctl restart {service}"


def _check_firewall(host: Host, raw: dict[str, Any]) -> list[Finding]:
    ufw = raw.get("ufw_status", "")
    ipt = raw.get("iptables", "")
    ufw_inactive = "Status: inactive" in ufw or (not ufw.strip())
    ipt_empty = not ipt.strip() or all(
        "ACCEPT" in ln or not ln.strip() or ln.startswith("Chain") or "target" in ln
        for ln in ipt.splitlines()
    )
    if not (ufw_inactive and ipt_empty):
        return []

    from .distro_eol import pkg_manager
    pm = pkg_manager(host.os_release)

    # ufw is available on Debian/Ubuntu; nftables/firewalld elsewhere
    if pm == "apt":
        steps = [
            "sudo ufw enable",
            "sudo ufw default deny incoming",
            "sudo ufw default allow outgoing",
            "sudo ufw allow ssh",
            "sudo ufw status verbose",
        ]
    elif pm in ("dnf", "yum"):
        steps = [
            "sudo systemctl enable --now firewalld",
            "sudo firewall-cmd --set-default-zone=drop",
            "sudo firewall-cmd --permanent --add-service=ssh",
            "sudo firewall-cmd --reload",
            "sudo firewall-cmd --list-all",
        ]
    elif pm == "apk":
        steps = [
            "sudo apk add nftables",
            "sudo rc-update add nftables default",
            "# Create /etc/nftables.d/firewall.nft with your ruleset",
            "sudo rc-service nftables start",
        ]
    elif pm == "zypper":
        steps = [
            "sudo systemctl enable --now firewalld",
            "sudo firewall-cmd --set-default-zone=drop",
            "sudo firewall-cmd --permanent --add-service=ssh",
            "sudo firewall-cmd --reload",
        ]
    else:
        steps = [
            "sudo ufw enable  # Debian/Ubuntu",
            "sudo firewall-cmd --set-default-zone=drop  # RHEL/Fedora",
            "sudo ufw default deny incoming",
            "sudo ufw allow ssh",
        ]

    return [Finding(
        host_ip=host.ip,
        category="firewall",
        severity=Severity.CRITICAL,
        title="No active firewall detected",
        description="Neither ufw nor iptables rules are configured. All ports are exposed.",
        remediation=steps,
        evidence=f"ufw: {ufw[:200]}\niptables: {ipt[:200]}",
    )]


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

    from .distro_eol import pkg_manager
    pm = pkg_manager(host.os_release)
    if pm == "apt":
        remove_cmd = "sudo apt remove --purge telnetd inetutils-telnetd -y"
    elif pm in ("dnf", "yum"):
        remove_cmd = f"sudo {pm} remove telnet-server -y"
    elif pm == "apk":
        remove_cmd = "sudo apk del busybox-extras  # or whichever package provides telnetd"
    elif pm == "zypper":
        remove_cmd = "sudo zypper remove telnetd -y"
    else:
        remove_cmd = "sudo apt remove telnetd -y  # adjust for your distro"

    return [Finding(
        host_ip=host.ip,
        category="ports",
        severity=Severity.CRITICAL,
        title="Telnet port 23 is open",
        description="Telnet transmits credentials and data in plaintext. Replace with SSH.",
        remediation=[
            "sudo systemctl disable telnet.socket --now",
            remove_cmd,
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
            "sudo chmod 660 /var/run/docker.sock",
            "Use rootless Docker or namespace isolation",
        ],
        evidence=ports_out[:300],
    )]


def _check_ssh_password_auth(host: Host, raw: dict[str, Any]) -> list[Finding]:
    config = raw.get("sshd_config", "")
    val = _sshd_option(config, "PasswordAuthentication")
    if not (val and val.lower() == "yes"):
        return []
    return [Finding(
        host_ip=host.ip,
        category="ssh_config",
        severity=Severity.HIGH,
        title="SSH PasswordAuthentication is enabled",
        description="Password-based SSH logins are allowed, enabling brute-force attacks.",
        remediation=[
            "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            _svc_restart_cmd(host, "sshd"),
            "# Ensure you have a working SSH key before disabling passwords",
        ],
    )]


def _check_ssh_permit_root(host: Host, raw: dict[str, Any]) -> list[Finding]:
    config = raw.get("sshd_config", "")
    val = _sshd_option(config, "PermitRootLogin")
    if not (val and val.lower() == "yes"):
        return []
    return [Finding(
        host_ip=host.ip,
        category="ssh_config",
        severity=Severity.HIGH,
        title="SSH PermitRootLogin is enabled",
        description="Root can log in directly via SSH, bypassing audit trails.",
        remediation=[
            "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
            _svc_restart_cmd(host, "sshd"),
        ],
    )]


def _check_kernel_updates(host: Host, raw: dict[str, Any]) -> list[Finding]:
    upgrades = raw.get("kernel_upgrades", "").strip()
    if not upgrades:
        return []
    cmds = _update_cmds(host) + ["sudo reboot  # to boot into new kernel"]
    return [Finding(
        host_ip=host.ip,
        category="kernel",
        severity=Severity.HIGH,
        title="Kernel updates available",
        description="Unpatched kernel may contain exploitable vulnerabilities.",
        remediation=cmds,
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
            "sudo docker inspect <container> | grep Privileged",
        ],
        evidence=docker_ps[:300],
    )]


def _check_ftp(host: Host, raw: dict[str, Any]) -> list[Finding]:
    if not _has_open_port(host.open_ports, 21):
        return []

    from .distro_eol import pkg_manager
    pm = pkg_manager(host.os_release)
    if pm == "apt":
        remove_cmd = "sudo apt remove --purge vsftpd proftpd pure-ftpd -y 2>/dev/null || true"
    elif pm in ("dnf", "yum"):
        remove_cmd = f"sudo {pm} remove vsftpd -y"
    elif pm == "apk":
        remove_cmd = "sudo apk del vsftpd"
    elif pm == "zypper":
        remove_cmd = "sudo zypper remove vsftpd -y"
    else:
        remove_cmd = "sudo apt remove vsftpd -y  # adjust for your distro"

    return [Finding(
        host_ip=host.ip,
        category="ports",
        severity=Severity.HIGH,
        title="FTP port 21 is open",
        description="FTP transmits credentials in plaintext. Use SFTP or FTPS instead.",
        remediation=[
            "sudo systemctl disable vsftpd --now",
            remove_cmd,
            "Use SFTP (built into SSH) instead: sftp user@host",
        ],
    )]


def _check_ssh_x11(host: Host, raw: dict[str, Any]) -> list[Finding]:
    config = raw.get("sshd_config", "")
    val = _sshd_option(config, "X11Forwarding")
    if not (val and val.lower() == "yes"):
        return []
    return [Finding(
        host_ip=host.ip,
        category="ssh_config",
        severity=Severity.MEDIUM,
        title="SSH X11Forwarding is enabled",
        description="X11 forwarding can expose the display to hijacking attacks.",
        remediation=[
            "sudo sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
            _svc_restart_cmd(host, "sshd"),
        ],
    )]


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
        remediation=_update_cmds(host),
        evidence="\n".join(lines[:20]),
    )]


def _check_http_no_https(host: Host, raw: dict[str, Any]) -> list[Finding]:
    has_80 = _has_open_port(host.open_ports, 80)
    has_443 = _has_open_port(host.open_ports, 443)
    if not (has_80 and not has_443):
        return []

    from .distro_eol import pkg_manager
    pm = pkg_manager(host.os_release)
    if pm == "apt":
        certbot_cmd = "sudo apt install certbot python3-certbot-nginx -y  # or python3-certbot-apache"
    elif pm in ("dnf", "yum"):
        certbot_cmd = f"sudo {pm} install certbot python3-certbot-nginx -y"
    elif pm == "apk":
        certbot_cmd = "sudo apk add certbot certbot-nginx"
    elif pm == "zypper":
        certbot_cmd = "sudo zypper install certbot python3-certbot-nginx -y"
    else:
        certbot_cmd = "sudo apt install certbot -y  # adjust for your distro"

    return [Finding(
        host_ip=host.ip,
        category="ports",
        severity=Severity.MEDIUM,
        title="HTTP (port 80) open without HTTPS (443)",
        description="Unencrypted HTTP traffic can be intercepted or tampered with.",
        remediation=[
            "Configure your web server to serve HTTPS",
            certbot_cmd,
            "sudo certbot --nginx  # or --apache",
            "Redirect HTTP to HTTPS in your server config",
        ],
    )]


def _check_world_listeners(host: Host, raw: dict[str, Any]) -> list[Finding]:
    """Flag unexpected services bound to 0.0.0.0."""
    ports_out = raw.get("listening_ports", "")
    known_ports = {22, 80, 443, 53, 123, 5353, 8080, 8443}
    unexpected: list[str] = []
    for line in ports_out.splitlines():
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
            "sudo ss -tlnp  # identify which process owns each port",
            "Bind services to 127.0.0.1 if only local access is needed",
            "Configure firewall rules to restrict external access",
        ],
        evidence="\n".join(unexpected[:10]),
    )]


def _check_os_eol(host: Host, raw: dict[str, Any]) -> list[Finding]:
    """Check if the installed OS is at or near end-of-life."""
    from .distro_eol import get_eol_info, upgrade_steps, lts_upgrade_steps

    if not host.os_release:
        return []

    info = get_eol_info(host.os_release)
    if info is None:
        return []

    days = info.effective_days_remaining
    remediation = _eol_remediation(info, host.os_release)

    if days < 0:
        return [Finding(
            host_ip=host.ip,
            category="os_eol",
            severity=Severity.CRITICAL,
            title=f"OS end-of-life: {info.pretty}",
            description=(
                f"{info.pretty} reached end-of-life on "
                f"{info.effective_eol.strftime('%Y-%m-%d')} "
                f"({abs(days)} days ago). No security patches are being issued."
            ),
            remediation=remediation + [
                "EOL systems receive no security patches — treat as high-risk until migrated.",
            ],
            evidence=f"ID={host.os_release.get('ID','')} VERSION_ID={host.os_release.get('VERSION_ID','')}",
        )]

    if days < 90:
        return [Finding(
            host_ip=host.ip,
            category="os_eol",
            severity=Severity.CRITICAL,
            title=f"OS end-of-life in {days} days: {info.pretty}",
            description=(
                f"{info.pretty} reaches end-of-life on "
                f"{info.effective_eol.strftime('%Y-%m-%d')} "
                f"({days} days). Security patches will cease — schedule upgrade now."
            ),
            remediation=remediation + [
                "Schedule downtime and test the upgrade in a non-production environment first.",
            ],
            evidence=f"ID={host.os_release.get('ID','')} VERSION_ID={host.os_release.get('VERSION_ID','')}",
        )]

    if days < 180:
        return [Finding(
            host_ip=host.ip,
            category="os_eol",
            severity=Severity.HIGH,
            title=f"OS nearing end-of-life in {days} days: {info.pretty}",
            description=(
                f"{info.pretty} reaches end-of-life on "
                f"{info.effective_eol.strftime('%Y-%m-%d')} "
                f"(~{days // 30} months)."
            ),
            remediation=remediation,
            evidence=f"ID={host.os_release.get('ID','')} VERSION_ID={host.os_release.get('VERSION_ID','')}",
        )]

    if days < 365:
        return [Finding(
            host_ip=host.ip,
            category="os_eol",
            severity=Severity.MEDIUM,
            title=f"OS end-of-life within a year: {info.pretty}",
            description=(
                f"{info.pretty} reaches end-of-life on "
                f"{info.effective_eol.strftime('%Y-%m-%d')} "
                f"(~{days // 30} months)."
            ),
            remediation=remediation,
            evidence=f"ID={host.os_release.get('ID','')} VERSION_ID={host.os_release.get('VERSION_ID','')}",
        )]

    return []


def _eol_remediation(info: Any, os_release: dict[str, Any]) -> list[str]:
    """Build the remediation step list for an EOL finding.

    When the immediate successor is not an LTS release, includes two labelled
    options: Option A (next release) and Option B (skip ahead to nearest LTS).
    When both paths lead to the same target, only one set of steps is shown.
    """
    from .distro_eol import upgrade_steps, lts_upgrade_steps

    steps_a = upgrade_steps(info, os_release)
    steps_b = lts_upgrade_steps(info, os_release)

    if not steps_b:
        # Successor IS the LTS (or no LTS alternative known) — single path
        return steps_a

    # Two distinct paths — label Option A clearly too
    lts_target = info.next_lts
    successor = info.successor
    header_a = f"# Option A — upgrade to next release: {info.distro_id} {successor}"
    # steps_a already starts with a # comment line; replace it with the labelled header
    steps_a_labelled = [header_a] + (steps_a[1:] if steps_a and steps_a[0].startswith("#") else steps_a)

    return steps_a_labelled + [""] + steps_b


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
    _check_os_eol,
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

    def analyze_vulns(
        self,
        host: Host,
        vuln_matches: dict[str, list[dict]],
        kev_ids: frozenset[str],
    ) -> list[Finding]:
        """Generate findings from CVE/advisory data for this host.

        vuln_matches: {source:name:version: [advisory_dict, ...]}
        kev_ids: set of CVE IDs in the CISA Known Exploited Vulnerabilities catalog

        Scoring:
          - Any package with a KEV hit                → Critical (score 10) per finding
          - 50+ total CVEs on host                   → Critical (score 10)
          - 21–49 total CVEs                         → High (score 5)
          - 6–20 total CVEs                          → Medium (score 2)
          - 1–5 total CVEs                           → Low (score 1)
          - High/Critical severity CVEs              → additional High finding
        """
        if not vuln_matches:
            return []

        findings: list[Finding] = []

        # Flatten all unique advisories
        seen_ids: set[str] = set()
        all_advisories: list[dict] = []
        kev_hits: list[tuple[str, str]] = []  # (pkg_key, advisory_id)
        high_crit_hits: list[tuple[str, str]] = []  # (pkg_key, advisory_id)

        for pkg_key, advisories in vuln_matches.items():
            for adv in advisories:
                adv_id = adv.get("id", "")
                if not adv_id or adv_id in seen_ids:
                    continue
                seen_ids.add(adv_id)
                all_advisories.append(adv)

                aliases = adv.get("aliases", [])
                in_kev = adv_id in kev_ids or any(a in kev_ids for a in aliases)
                if in_kev:
                    kev_hits.append((pkg_key, adv_id))

                sev = (adv.get("severity") or "").lower()
                if sev in ("critical", "high"):
                    high_crit_hits.append((pkg_key, adv_id))

        total = len(all_advisories)
        if total == 0:
            return []

        # --- KEV finding (one per host, most severe) ---
        if kev_hits:
            kev_pkg_names = sorted({k.split(":")[1] for k, _ in kev_hits})[:5]
            kev_ids_list = [adv_id for _, adv_id in kev_hits[:5]]
            findings.append(Finding(
                host_ip=host.ip,
                category="vulnerabilities",
                severity=Severity.CRITICAL,
                title=f"{len(kev_hits)} actively-exploited CVE(s) (CISA KEV) in installed packages",
                description=(
                    f"{len(kev_hits)} installed package(s) have CVEs listed in the CISA Known "
                    f"Exploited Vulnerabilities catalog, meaning they are actively exploited in "
                    f"the wild. Immediate patching is required."
                ),
                remediation=_update_cmds(host) + [
                    f"Affected packages: {', '.join(kev_pkg_names)}",
                    f"KEV advisory IDs: {', '.join(kev_ids_list)}",
                ],
                evidence=f"KEV hits: {', '.join(adv_id for _, adv_id in kev_hits[:10])}",
                score=10,
            ))

        # --- High/Critical severity CVEs ---
        if high_crit_hits:
            hc_pkg_names = sorted({k.split(":")[1] for k, _ in high_crit_hits})[:5]
            findings.append(Finding(
                host_ip=host.ip,
                category="vulnerabilities",
                severity=Severity.HIGH,
                title=f"{len(high_crit_hits)} High/Critical severity CVE(s) in installed packages",
                description=(
                    f"{len(high_crit_hits)} installed package(s) have High or Critical severity "
                    f"CVEs. These should be patched promptly."
                ),
                remediation=_update_cmds(host) + [
                    f"Affected packages: {', '.join(hc_pkg_names)}",
                    "Press v then switch to Vulnerabilities tab for the full list",
                ],
                evidence=f"High/Critical CVEs: {', '.join(adv_id for _, adv_id in high_crit_hits[:10])}",
                score=5,
            ))

        # --- Total CVE count finding ---
        if total >= 50:
            sev, score = Severity.CRITICAL, 10
        elif total >= 21:
            sev, score = Severity.HIGH, 5
        elif total >= 6:
            sev, score = Severity.MEDIUM, 2
        else:
            sev, score = Severity.LOW, 1

        findings.append(Finding(
            host_ip=host.ip,
            category="vulnerabilities",
            severity=sev,
            title=f"{total} CVE(s) found across installed packages",
            description=(
                f"{total} CVE advisories matched against the package inventory for this host. "
                f"Use the Vulnerabilities tab for the full list."
            ),
            remediation=_update_cmds(host) + [
                "Press v to refresh vulnerability data, then review the Vulnerabilities tab",
            ],
            evidence=f"Total advisories: {total}  |  KEV hits: {len(kev_hits)}  |  High/Crit: {len(high_crit_hits)}",
            score=score,
        ))

        return findings
