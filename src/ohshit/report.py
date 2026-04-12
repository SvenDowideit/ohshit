from __future__ import annotations

from datetime import datetime

from .models import ScanResult, Severity


def generate_markdown_report(result: ScanResult) -> str:
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    net_label = result.network_risk_label.value.upper()
    net_score = result.network_risk_score

    lines += [
        "# Network Security Report",
        f"",
        f"**Generated:** {now}",
        f"**Network:** {result.network_cidr or 'unknown'}  |  **Gateway:** {result.gateway_ip or 'unknown'}",
        f"**Overall Risk:** **{net_label}** (score: {net_score})",
        f"",
        "---",
        f"",
        "## Network Summary",
        f"",
        "| IP | Hostname | Risk | Score | SSH Status |",
        "|----|----------|------|-------|------------|",
    ]

    for host in sorted(result.hosts.values(), key=lambda h: h.risk_score, reverse=True):
        lines.append(
            f"| {host.ip} | {host.hostname or '-'} "
            f"| {host.risk_label.value} | {host.risk_score} "
            f"| {host.state.value} |"
        )

    lines += ["", "---", ""]

    for host in sorted(result.hosts.values(), key=lambda h: h.risk_score, reverse=True):
        name = f"{host.ip}" + (f" ({host.hostname})" if host.hostname else "")
        lines += [
            f"## Host: {name}",
            f"",
            f"**Risk Score:** {host.risk_score} ({host.risk_label.value})",
            f"**State:** {host.state.value}",
        ]

        if host.os_guess:
            lines.append(f"**OS (nmap):** {host.os_guess}")
        if host.os_release:
            pretty = host.os_release.get("PRETTY_NAME") or host.os_release.get("NAME", "")
            if pretty:
                lines.append(f"**OS:** {pretty}")
        if host.kernel_version:
            lines.append(f"**Kernel:** {host.kernel_version}")
        if host.mac:
            lines.append(f"**MAC:** {host.mac}")
        lines.append("")

        if host.open_ports:
            lines += [
                "### Open Ports",
                "",
                "| Port | Protocol | Service | Version |",
                "|------|----------|---------|---------|",
            ]
            for p in sorted(host.open_ports, key=lambda x: x.port):
                if p.state == "open":
                    lines.append(f"| {p.port} | {p.protocol} | {p.service} | {p.version} |")
            lines.append("")

        if host.ssh_error:
            lines += [f"**SSH Error:** `{host.ssh_error}`", ""]

        if host.findings:
            lines += ["### Findings", ""]
            sev_order = {
                Severity.CRITICAL: 0, Severity.HIGH: 1,
                Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
            }
            for f in sorted(host.findings, key=lambda x: sev_order[x.severity]):
                lines += [
                    f"#### [{f.severity.value.upper()}] {f.title} (score: {f.score})",
                    f"",
                    f"{f.description}",
                    f"",
                ]
                if f.evidence:
                    lines += [
                        "<details><summary>Evidence</summary>",
                        "",
                        f"```",
                        f.evidence[:500],
                        f"```",
                        "</details>",
                        "",
                    ]
                if f.remediation:
                    lines += ["**Remediation:**", ""]
                    for step in f.remediation:
                        lines.append(f"```bash\n{step}\n```")
                    lines.append("")
        else:
            lines += ["*No findings.*", ""]

        lines += ["---", ""]

    return "\n".join(lines)
