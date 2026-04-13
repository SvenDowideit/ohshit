from __future__ import annotations

from datetime import datetime, timezone

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import (
    DataTable,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)
from textual.containers import Horizontal, VerticalScroll

from ..models import Finding, Host, HostState, ScanResult, Severity


def _ago(dt: datetime | None) -> str:
    """Return a compact relative-time string like '3 m ago' or '2 d ago'."""
    if dt is None:
        return "never"
    now = datetime.now(timezone.utc) if dt.tzinfo else datetime.now()
    secs = max(0, (now - dt).total_seconds())
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} m ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    if secs < 86400 * 14:
        return f"{int(secs // 86400)} d ago"
    return dt.strftime("%Y-%m-%d")


def _fmt_ts(dt: datetime | None) -> str:
    """Return a full timestamp string, or 'never'."""
    if dt is None:
        return "never"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Severity colour helpers
# ---------------------------------------------------------------------------

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold black on yellow",
    Severity.MEDIUM: "black on dark_orange3",
    Severity.LOW: "black on green",
    Severity.INFO: "white on blue",
}

SEVERITY_CSS_CLASSES: dict[Severity, str] = {
    Severity.CRITICAL: "badge-critical",
    Severity.HIGH: "badge-high",
    Severity.MEDIUM: "badge-medium",
    Severity.LOW: "badge-low",
    Severity.INFO: "badge-info",
}


def _sev_text(label: str, sev: Severity) -> Text:
    return Text(label, style=SEVERITY_STYLES.get(sev, ""))


# ---------------------------------------------------------------------------
# NetworkRiskBadge
# ---------------------------------------------------------------------------

class NetworkRiskBadge(Static):
    """Small inline coloured badge showing a severity label."""

    DEFAULT_CSS = """
    NetworkRiskBadge {
        width: auto;
        padding: 0 1;
    }
    """

    def __init__(self, severity: Severity, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._severity = severity

    def on_mount(self) -> None:
        self._refresh_label()

    def update_severity(self, sev: Severity) -> None:
        self._severity = sev
        self._refresh_label()

    def _refresh_label(self) -> None:
        short = self._severity.value[:4].upper()
        self.update(Text(f" {short} ", style=SEVERITY_STYLES[self._severity]))
        self.remove_class(*SEVERITY_CSS_CLASSES.values())
        self.add_class(SEVERITY_CSS_CLASSES[self._severity])


# ---------------------------------------------------------------------------
# HostListPanel
# ---------------------------------------------------------------------------

class HostListItem(ListItem):
    def __init__(self, host: Host) -> None:
        super().__init__()
        self.host = host

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield NetworkRiskBadge(self.host.risk_label)
            yield Label(
                self.host.display_name,
                classes="host-name",
            )
            eol_label, eol_class = self._eol_badge(self.host)
            if eol_label:
                lbl = Label(eol_label, classes=f"eol-badge {eol_class}")
            else:
                lbl = Label("", classes="eol-badge")
            yield lbl
            yield Label(
                self.host.state.value,
                classes="host-state",
            )

    @staticmethod
    def _eol_badge(host: Host) -> tuple[str, str]:
        if not host.os_release:
            return ("", "")
        try:
            from ..distro_eol import get_eol_info, eol_badge_text
            info = get_eol_info(host.os_release)
            if info is None:
                return ("", "")
            return eol_badge_text(info)
        except Exception:
            return ("", "")

    def refresh_host(self, host: Host) -> None:
        """Update badge, name, EOL indicator and state label in-place without re-mounting."""
        self.host = host
        try:
            self.query_one(NetworkRiskBadge).update_severity(host.risk_label)
            self.query_one(".host-name", Label).update(host.display_name)
            self.query_one(".host-state", Label).update(host.state.value)
            eol_label, eol_class = self._eol_badge(host)
            eol_widget = self.query_one(".eol-badge", Label)
            eol_widget.update(eol_label)
            # Update CSS class
            for cls in ("eol-badge-critical", "eol-badge-high", "eol-badge-medium"):
                eol_widget.remove_class(cls)
            if eol_class:
                eol_widget.add_class(eol_class)
        except Exception:
            pass


class HostListPanel(Widget):
    class HostSelected(Message):
        def __init__(self, ip: str) -> None:
            super().__init__()
            self.ip = ip

    def compose(self) -> ComposeResult:
        yield Label("Hosts", id="host-panel-title")
        yield ListView(id="host-list")

    # Ordered list of IPs as currently rendered (matches ListView children order)
    _rendered_order: list[str]

    def on_mount(self) -> None:
        self._rendered_order = []

    async def update_hosts(self, result: ScanResult) -> None:
        desired_order = [
            h.ip for h in sorted(result.hosts.values(), key=lambda h: (-h.risk_score, h.ip))
        ]
        lv = self.query_one("#host-list", ListView)
        rendered = self._rendered_order

        # Build index of currently rendered items by IP
        items_by_ip: dict[str, HostListItem] = {
            item.host.ip: item
            for item in lv.query(HostListItem)
        }

        # 1. Update or add each host
        for ip in desired_order:
            host = result.hosts[ip]
            if ip in items_by_ip:
                items_by_ip[ip].refresh_host(host)
            else:
                new_item = HostListItem(host)
                await lv.append(new_item)
                items_by_ip[ip] = new_item

        # 2. Remove hosts that are no longer in the result (shouldn't happen,
        #    but guard against stale items)
        for ip, item in list(items_by_ip.items()):
            if ip not in result.hosts:
                await item.remove()
                del items_by_ip[ip]

        # 3. Reorder only if the desired order differs from rendered order
        if desired_order != rendered:
            for target_idx, ip in enumerate(desired_order):
                item = items_by_ip[ip]
                # Re-query live children each iteration since moves change positions
                current_children = list(lv.query(HostListItem))
                if item not in current_children:
                    # Item was moved earlier in this loop and is mid-flight; skip —
                    # the next poll will converge the order.
                    continue
                current_idx = current_children.index(item)
                if current_idx != target_idx:
                    await item.remove()
                    if target_idx == 0:
                        remaining = list(lv.query(HostListItem))
                        if remaining:
                            await lv.mount(items_by_ip[ip], before=remaining[0])
                        else:
                            await lv.append(items_by_ip[ip])
                    else:
                        anchor_ip = desired_order[target_idx - 1]
                        await lv.mount(items_by_ip[ip], after=items_by_ip[anchor_ip])

        self._rendered_order = list(desired_order)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, HostListItem):
            self.post_message(self.HostSelected(item.host.ip))

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        item = event.item
        if isinstance(item, HostListItem):
            self.post_message(self.HostSelected(item.host.ip))


# ---------------------------------------------------------------------------
# HostDetailTab
# ---------------------------------------------------------------------------

class HostDetailTab(Widget):
    def compose(self) -> ComposeResult:
        yield Label("", id="detail-header")
        yield Label("", id="detail-os")
        yield Label("", id="detail-eol")
        yield Label("", id="detail-kernel")
        yield Label("", id="detail-mac")
        yield Label("", id="detail-ssh")
        yield Label("", id="detail-seen")
        yield Label("", id="detail-last-upgrade")
        yield Label("", id="detail-vendor")
        yield Label("", id="detail-iot")
        yield Label("", id="detail-repurpose")
        yield Label("", id="detail-esphome")
        yield Label("", id="detail-vuln-summary")
        yield Label("Open Ports:", id="ports-label")
        yield DataTable(id="ports-table")

    def on_mount(self) -> None:
        tbl = self.query_one("#ports-table", DataTable)
        tbl.add_columns("Port", "Proto", "State", "Service", "Version")

    def update_host(
        self,
        host: "Host | None",
        vuln_matches: "dict[str, list[dict]] | None" = None,
        packages: "list[dict] | None" = None,
    ) -> None:
        if host is None:
            self.query_one("#detail-header", Label).update(
                "← Select a host from the list to see details"
            )
            for wid in ("detail-os", "detail-eol", "detail-kernel", "detail-mac", "detail-ssh",
                        "detail-seen", "detail-last-upgrade", "detail-vendor", "detail-iot", "detail-repurpose",
                        "detail-esphome", "detail-vuln-summary"):
                self.query_one(f"#{wid}", Label).update("")
            self.query_one("#ports-table", DataTable).clear(columns=False)
            return

        name = host.display_name
        risk = host.risk_label.value
        self.query_one("#detail-header", Label).update(
            Text(f"  {name}  —  {risk} risk (score {host.risk_score})  ",
                 style=SEVERITY_STYLES.get(host.risk_label, ""))
        )

        os_info = host.os_guess or ""
        if host.os_release:
            pretty = host.os_release.get("PRETTY_NAME") or host.os_release.get("NAME", "")
            if pretty:
                os_info = pretty + (f"  [{os_info}]" if os_info else "")
        self.query_one("#detail-os", Label).update(f"OS: {os_info or 'unknown'}")

        # EOL information
        eol_label = self.query_one("#detail-eol", Label)
        if host.os_release:
            try:
                from ..distro_eol import get_eol_info
                eol_info = get_eol_info(host.os_release)
                if eol_info:
                    days = eol_info.effective_days_remaining
                    eol_date_str = eol_info.effective_eol.strftime("%Y-%m-%d")
                    support = eol_info.support_type
                    if days < 0:
                        style = "bold white on red"
                        status = f"END OF LIFE since {eol_date_str} ({abs(days)} days ago)"
                    elif days < 90:
                        style = "bold white on red"
                        status = f"EOL in {days} days ({eol_date_str})"
                    elif days < 180:
                        style = "bold black on yellow"
                        status = f"EOL in {days} days ({eol_date_str})"
                    elif days < 365:
                        style = "black on dark_orange3"
                        status = f"EOL in ~{days // 30} months ({eol_date_str})"
                    else:
                        style = "dim"
                        status = f"Supported until {eol_date_str} ({days // 30} months)"
                    upgrade = f"  →  upgrade to {eol_info.successor}" if eol_info.successor and days < 365 else ""
                    eol_label.update(
                        Text(f"  [{support}] {status}{upgrade}", style=style)
                    )
                else:
                    eol_label.update("")
            except Exception:
                eol_label.update("")
        else:
            eol_label.update("")

        self.query_one("#detail-kernel", Label).update(f"Kernel: {host.kernel_version or 'unknown'}")
        self.query_one("#detail-mac", Label).update(f"MAC: {host.mac or 'unknown'}  |  IP: {host.ip}")

        ssh_info = host.state.value
        if host.ssh_error:
            ssh_info += f"  ({host.ssh_error})"
        self.query_one("#detail-ssh", Label).update(f"SSH: {ssh_info}")

        seen_parts = [f"first seen {_fmt_ts(host.first_seen)}"]
        seen_parts.append(f"last seen {_fmt_ts(host.last_seen)}")
        if host.last_scan:
            seen_parts.append(f"last scanned {_fmt_ts(host.last_scan)}")
        self.query_one("#detail-seen", Label).update("  |  ".join(seen_parts))

        # Last package upgrade time
        upgrade_lbl = self.query_one("#detail-last-upgrade", Label)
        if host.os_release and host.last_pkg_upgrade:
            ago_str = _ago(host.last_pkg_upgrade)
            ts_str = _fmt_ts(host.last_pkg_upgrade)
            now = datetime.now(timezone.utc) if host.last_pkg_upgrade.tzinfo else datetime.now()
            days_ago = (now - host.last_pkg_upgrade).days
            if days_ago > 90:
                style = "bold black on yellow"
                warn = "  (!)"
            else:
                style = "dim"
                warn = ""
            upgrade_lbl.update(
                Text(f"Last pkg upgrade: {ago_str}  ({ts_str}){warn}", style=style)
            )
        elif host.os_release:
            # Linux host but no upgrade data collected yet
            upgrade_lbl.update(Text("Last pkg upgrade: unknown", style="dim"))
        else:
            upgrade_lbl.update("")

        # IoT vendor / device type + MAC permanence
        iot = host.iot_info
        vendor_parts = []
        if iot.vendor:
            vendor_parts.append(iot.vendor)
        if iot.device_type:
            vendor_parts.append(f"({iot.device_type})")
        if iot.mac_permanence:
            from ..oui_db import PERMANENCE_LABELS, PERMANENCE_VIRTUAL, PERMANENCE_EXTERNAL, PERMANENCE_REMOVABLE
            perm_label = PERMANENCE_LABELS.get(iot.mac_permanence, iot.mac_permanence)
            # Highlight removable/external/virtual with a visual cue
            if iot.mac_permanence in (PERMANENCE_VIRTUAL, PERMANENCE_EXTERNAL, PERMANENCE_REMOVABLE):
                vendor_parts.append(Text(f"[{perm_label}]", style="bold yellow"))
            else:
                vendor_parts.append(f"[{perm_label}]")

        if vendor_parts:
            # vendor_parts may mix str and Text — build a combined Text
            line = Text()
            line.append("Vendor: ")
            for i, part in enumerate(vendor_parts):
                if i:
                    line.append("  ")
                if isinstance(part, Text):
                    line.append_text(part)
                else:
                    line.append(part)
            self.query_one("#detail-vendor", Label).update(line)
        else:
            self.query_one("#detail-vendor", Label).update("")

        # IoT identifiers: mDNS names, UPnP, HA entity, detection methods
        iot_parts: list[str] = []
        if iot.mdns_names:
            iot_parts.append(f"mDNS: {', '.join(iot.mdns_names)}")
        if iot.upnp_friendly_name:
            name_str = iot.upnp_friendly_name
            if iot.upnp_model:
                name_str += f" / {iot.upnp_model}"
            iot_parts.append(f"UPnP: {name_str}")
        if iot.ha_entity_id:
            iot_parts.append(f"HA: {iot.ha_entity_id}")
        if iot.detection_methods:
            iot_parts.append(f"via {', '.join(iot.detection_methods)}")
        self.query_one("#detail-iot", Label).update("  ".join(iot_parts) if iot_parts else "")

        # Hardware repurposing warning
        repurpose = host.repurpose_note
        if repurpose:
            self.query_one("#detail-repurpose", Label).update(
                Text(f"  WARNING: {repurpose}  ", style="bold white on dark_red")
            )
        else:
            self.query_one("#detail-repurpose", Label).update("")

        # ESPHome device info
        esp = host.iot_info.esphome_info
        if esp:
            parts: list[str] = []
            if esp.get("friendly_name"):
                parts.append(f"ESPHome: {esp['friendly_name']}")
            elif esp.get("name"):
                parts.append(f"ESPHome: {esp['name']}")
            else:
                parts.append("ESPHome device")
            if esp.get("version"):
                parts.append(f"v{esp['version']}")
            if esp.get("model"):
                parts.append(esp["model"])
            if esp.get("platform") or esp.get("board"):
                hw = "/".join(filter(None, [esp.get("platform"), esp.get("board")]))
                parts.append(f"[{hw}]")
            if esp.get("project_name"):
                proj = esp["project_name"]
                if esp.get("project_version"):
                    proj += f" {esp['project_version']}"
                parts.append(f"project: {proj}")
            if esp.get("suggested_area"):
                parts.append(f"area: {esp['suggested_area']}")
            if esp.get("compilation_time"):
                parts.append(f"built: {esp['compilation_time']}")
            self.query_one("#detail-esphome", Label).update(
                Text("  ".join(parts), style="cyan")
            )
        else:
            self.query_one("#detail-esphome", Label).update("")

        # Vulnerability summary
        vuln_lbl = self.query_one("#detail-vuln-summary", Label)
        if vuln_matches:
            pkg_count = len(packages) if packages else "?"
            total_cves = sum(len(v) for v in vuln_matches.values())
            kev_count = sum(
                1 for advs in vuln_matches.values()
                for a in advs if a.get("source") == "kev"
            )
            ransomware_count = sum(
                1 for advs in vuln_matches.values()
                for a in advs if (a.get("ransomware") or "").lower() == "known"
            )
            # Count by severity (deduplicated across packages)
            seen: set[str] = set()
            sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for advs in vuln_matches.values():
                for a in advs:
                    aid = a.get("id", "")
                    if aid in seen:
                        continue
                    seen.add(aid)
                    sev = (a.get("severity") or "").capitalize()
                    if sev in sev_counts:
                        sev_counts[sev] += 1

            line = Text()
            line.append("CVEs: ")
            line.append(f"{total_cves} total", style="bold")
            line.append("  across ")
            line.append(f"{len(vuln_matches)}", style="bold")
            line.append(f" of {pkg_count} packages  |  ")
            # Severity breakdown
            for sev, style in (
                ("Critical", "bold white on red"),
                ("High",     "bold black on yellow"),
                ("Medium",   "black on dark_orange3"),
                ("Low",      "black on green"),
            ):
                n = sev_counts[sev]
                if n:
                    line.append(f" {sev[:4]}:{n} ", style=style)
                    line.append(" ")
            if kev_count:
                line.append(f"  ★ {kev_count} KEV", style="bold red")
            if ransomware_count:
                line.append(f"  R {ransomware_count} ransomware", style="bold red")
            vuln_lbl.update(line)
        elif packages:
            vuln_lbl.update(
                Text(f"CVEs: not yet queried — press ", style="dim") +
                Text("v", style="bold") +
                Text(" to query OSV", style="dim")
            )
        else:
            vuln_lbl.update("")

        tbl = self.query_one("#ports-table", DataTable)
        tbl.clear(columns=False)
        for p in sorted(host.open_ports, key=lambda x: x.port):
            if p.state == "open":
                tbl.add_row(str(p.port), p.protocol, p.state, p.service, p.version)


# ---------------------------------------------------------------------------
# FindingsTable
# ---------------------------------------------------------------------------

class FindingsTable(Widget):
    def compose(self) -> ComposeResult:
        yield DataTable(id="findings-dt")

    def on_mount(self) -> None:
        tbl = self.query_one("#findings-dt", DataTable)
        tbl.add_columns("Sev", "Category", "Title", "Score")
        tbl.cursor_type = "row"

    def update_host(self, host: Host | None) -> None:
        tbl = self.query_one("#findings-dt", DataTable)
        tbl.clear(columns=False)
        if host is None:
            return
        if not host.findings:
            # Add a single info row so the table isn't just blank
            tbl.add_row(Text("Info", style="white on blue"), "-", "No findings — host looks clean", "0")
            return
        for f in sorted(host.findings, key=lambda x: x.score, reverse=True):
            tbl.add_row(
                _sev_text(f.severity.value[:4], f.severity),
                f.category,
                f.title,
                str(f.score),
            )


# ---------------------------------------------------------------------------
# RemediationPanel
# ---------------------------------------------------------------------------

_SHELL_PREFIXES = (
    "sudo ", "apt ", "dnf ", "yum ", "apk ", "zypper ", "pacman ",
    "systemctl ", "sed ", "chmod ", "chown ", "docker ",
    "do-release-upgrade", "leapp ", "snap ",
)


def _is_shell_cmd(step: str) -> bool:
    """True if a remediation step looks like a shell command rather than prose."""
    s = step.strip()
    if s.startswith("#"):
        return True  # shell comment — render as code
    for prefix in _SHELL_PREFIXES:
        if s.startswith(prefix):
            return True
    return False


class _CmdBlock(TextArea):
    """Read-only TextArea for shell commands — mouse-selectable, y/c to copy."""

    BINDINGS = [Binding("y,c", "copy_selection", "Copy", show=False)]

    def on_mount(self) -> None:
        self.read_only = True

    def action_copy_selection(self) -> None:
        text = self.selected_text or self.text
        if text:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied to clipboard", timeout=2)


class RemediationPanel(Widget):
    BINDINGS = [("y", "yank_commands", "Copy commands")]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._current_host: Host | None = None

    def compose(self) -> ComposeResult:
        yield Label("", id="remed-hint")
        yield VerticalScroll(id="remed-scroll")

    async def update_host(self, host: Host | None) -> None:
        self._current_host = host
        hint = self.query_one("#remed-hint", Label)
        scroll = self.query_one("#remed-scroll", VerticalScroll)
        await scroll.remove_children()
        if host is None or not host.findings:
            hint.update("")
            scroll.mount(Label("No findings."))
            return

        has_cmds = any(
            _is_shell_cmd(step)
            for f in host.findings
            for step in f.remediation
        )
        hint.update("  Select text then press [bold]y[/bold] or [bold]c[/bold] to copy  " if has_cmds else "")

        for f in sorted(host.findings, key=lambda x: x.score, reverse=True):
            header = Text(
                f"[{f.severity.value.upper()}] {f.title}",
                style=SEVERITY_STYLES.get(f.severity, ""),
            )
            scroll.mount(Static(header, classes="remed-title"))
            scroll.mount(Static(f.description, classes="remed-desc"))
            if f.remediation:
                cmd_buf: list[str] = []

                def _flush_cmds(buf: list[str]) -> None:
                    if not buf:
                        return
                    block = _CmdBlock(
                        "\n".join(buf),
                        language="bash",
                        classes="remed-cmd-block",
                    )
                    scroll.mount(block)

                for step in f.remediation:
                    if step == "":
                        _flush_cmds(cmd_buf)
                        cmd_buf = []
                        scroll.mount(Static("", classes="remed-blank"))
                    elif _is_shell_cmd(step):
                        cmd_buf.append(step)
                    else:
                        _flush_cmds(cmd_buf)
                        cmd_buf = []
                        scroll.mount(Static(f"  {step}", classes="remed-note"))
                _flush_cmds(cmd_buf)

            if f.evidence:
                scroll.mount(Static(
                    Text("  Evidence: ", style="dim") + Text(f.evidence[:200], style="dim italic"),
                    classes="remed-evidence",
                ))
            scroll.mount(Static("─" * 60, classes="remed-sep"))

    def action_yank_commands(self) -> None:
        host = self._current_host
        if host is None:
            return
        lines: list[str] = []
        for f in sorted(host.findings, key=lambda x: x.score, reverse=True):
            cmds = [s for s in f.remediation if _is_shell_cmd(s)]
            if cmds:
                lines.append(f"# {f.title}")
                lines.extend(cmds)
                lines.append("")
        if lines:
            self.app.copy_to_clipboard("\n".join(lines))
            self.app.notify("Commands copied to clipboard", timeout=2)


# ---------------------------------------------------------------------------
# ScanProgressBar
# ---------------------------------------------------------------------------

class ScanProgressBar(Widget):
    step_name: reactive[str] = reactive("Idle")
    progress: reactive[float] = reactive(0.0)

    def compose(self) -> ComposeResult:
        yield Label("", id="step-label")
        yield ProgressBar(total=100, show_eta=False, id="prog-bar")

    def watch_step_name(self, name: str) -> None:
        self.query_one("#step-label", Label).update(name)

    def watch_progress(self, val: float) -> None:
        self.query_one("#prog-bar", ProgressBar).progress = val


# ---------------------------------------------------------------------------
# LogFeed
# ---------------------------------------------------------------------------

class LogFeed(Widget):
    def compose(self) -> ComposeResult:
        yield RichLog(max_lines=200, highlight=True, markup=True, id="rich-log")

    def write(self, line: str) -> None:
        self.query_one("#rich-log", RichLog).write(line)


# ---------------------------------------------------------------------------
# SbomTab
# ---------------------------------------------------------------------------

class SbomTab(Widget):
    """Displays SBOM (Software Bill of Materials) for the selected host."""

    def compose(self) -> ComposeResult:
        yield Label("", id="sbom-header")
        yield DataTable(id="sbom-table")

    def on_mount(self) -> None:
        tbl = self.query_one("#sbom-table", DataTable)
        tbl.add_columns("Risk", "CVEs", "Released", "Source", "Name", "Version", "Arch")
        tbl.cursor_type = "row"

    def update_sbom(
        self,
        packages: list[dict],
        host: "Host | None" = None,
        vuln_matches: "dict[str, list[dict]] | None" = None,
    ) -> None:
        """Refresh the SBOM display with the given package list.

        vuln_matches is {source:name:version: [advisory_dict, ...]} from vuln_db.
        """
        tbl = self.query_one("#sbom-table", DataTable)
        tbl.clear(columns=False)

        hdr = self.query_one("#sbom-header", Label)
        if not packages:
            if host is not None:
                hdr.update(f"No SBOM collected yet for {host.display_name}")
            else:
                hdr.update("No SBOM data — select a host after a scan completes")
            return

        collected_at = packages[0].get("collected_at")
        ts_str = _fmt_ts(collected_at) if collected_at else "unknown"
        count = len(packages)
        host_name = packages[0].get("hostname") or packages[0].get("ip", "")

        # Summarise vuln counts for the header
        total_vulns = sum(len(v) for v in (vuln_matches or {}).values())
        vuln_str = f"  |  {total_vulns} CVEs" if total_vulns else ""
        hdr.update(f"{host_name}  —  {count} packages  (collected {ts_str}){vuln_str}")

        _SEVER_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "": 4}
        _SEVER_STYLE = {
            "critical": ("CRIT", "bold white on red"),
            "high":     ("HIGH", "bold black on yellow"),
            "medium":   ("MED",  "black on dark_orange3"),
            "low":      ("LOW",  "black on green"),
        }

        def _sort_key(p: dict):
            key = f"{p.get('source', '')}:{p.get('name', '')}:{p.get('version', '')}"
            advisories = (vuln_matches or {}).get(key, [])

            # Worst severity among all advisories for this package
            worst = 4
            kev_hit = False
            for adv in advisories:
                sev = (adv.get("severity") or "").lower()
                worst = min(worst, _SEVER_RANK.get(sev, 4))
                if adv.get("source") == "kev":
                    kev_hit = True

            cve_count = len(advisories)

            ra = p.get("released_at")
            if ra is None:
                released_ts = datetime.min.replace(tzinfo=timezone.utc)
            else:
                released_ts = ra if ra.tzinfo else ra.replace(tzinfo=timezone.utc)

            return (
                0 if kev_hit else 1,
                worst,
                -cve_count,
                -released_ts.timestamp(),
            )

        for pkg in sorted(packages, key=_sort_key):
            ra = pkg.get("released_at")
            if ra is None:
                age_str = "unknown"
            else:
                if ra.tzinfo is None:
                    ra = ra.replace(tzinfo=timezone.utc)
                age_str = _ago(ra)

            key = f"{pkg.get('source', '')}:{pkg.get('name', '')}:{pkg.get('version', '')}"
            advisories = (vuln_matches or {}).get(key, [])

            # Compute worst severity and KEV status for this package
            worst_sev = ""
            kev_hit = False
            for adv in advisories:
                sev = (adv.get("severity") or "").lower()
                if _SEVER_RANK.get(sev, 4) < _SEVER_RANK.get(worst_sev, 4):
                    worst_sev = sev
                if adv.get("source") == "kev":
                    kev_hit = True

            # Risk badge
            if kev_hit:
                risk_text = Text(" ★KEV ", style="bold white on red")
            elif worst_sev in _SEVER_STYLE:
                label, style = _SEVER_STYLE[worst_sev]
                risk_text = Text(f" {label} ", style=style)
            else:
                risk_text = Text("")

            cve_text = Text(str(len(advisories)), style="bold red") if advisories else Text("")

            tbl.add_row(
                risk_text,
                cve_text,
                age_str,
                pkg.get("source", ""),
                pkg.get("name", ""),
                pkg.get("version", ""),
                pkg.get("arch", ""),
            )


# ---------------------------------------------------------------------------
# VulnTab
# ---------------------------------------------------------------------------

class VulnTab(Widget):
    """Shows vulnerability advisories matched against the selected host's SBOM."""

    def compose(self) -> ComposeResult:
        yield Label("", id="vuln-header")
        yield DataTable(id="vuln-table")

    def on_mount(self) -> None:
        tbl = self.query_one("#vuln-table", DataTable)
        tbl.add_columns("ID", "Exploit", "Severity", "CVSS", "EPSS%", "Package", "Summary")
        tbl.cursor_type = "row"

    def update_vulns(
        self,
        vuln_matches: "dict[str, list[dict]]",
        host: "Host | None" = None,
    ) -> None:
        """Populate the table from vuln_matches {source:name:ver: [advisory, ...]}."""
        tbl = self.query_one("#vuln-table", DataTable)
        tbl.clear(columns=False)
        hdr = self.query_one("#vuln-header", Label)

        if not vuln_matches:
            msg = "No vulnerability data" if host is None else f"No CVEs found for {host.display_name if host else ''}"
            if host and not vuln_matches:
                msg += " — press [bold]v[/bold] to query OSV"
            hdr.update(msg)
            return

        # Flatten all advisories, deduplicate by advisory ID
        rows: list[tuple[str, str, str, list[dict]]] = []  # (pkg_key, name, ver, [adv])
        for pkg_key, advisories in vuln_matches.items():
            parts = pkg_key.split(":", 2)
            pkg_name = parts[1] if len(parts) > 1 else pkg_key
            pkg_ver = parts[2] if len(parts) > 2 else ""
            rows.append((pkg_key, pkg_name, pkg_ver, advisories))

        total = sum(len(a) for _, _, _, a in rows)
        host_name = host.display_name if host else ""
        hdr.update(f"{host_name}  —  {total} vulnerabilities across {len(rows)} packages")

        # Sort: packages with most vulns first
        rows.sort(key=lambda r: len(r[3]), reverse=True)

        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "": 4}

        # Collect all advisory rows, then sort by exploitation risk
        adv_rows: list[tuple] = []  # (sort_key, display_fields...)
        seen_adv: set[str] = set()

        for _, pkg_name, pkg_ver, advisories in rows:
            for adv in advisories:
                adv_id = adv.get("id", "")
                if adv_id in seen_adv:
                    continue
                seen_adv.add(adv_id)

                # source='kev' is set by match_packages_to_vulns when the advisory
                # (or its derived CVE) is in the CISA KEV catalog
                in_kev = adv.get("source") == "kev"
                ransomware = (adv.get("ransomware") or "").lower() == "known"
                sev = adv.get("severity") or "Unknown"
                sev_order = _SEV_ORDER.get(sev.lower(), 4)
                cvss = adv.get("cvss_score")
                epss = adv.get("epss_score")
                epss_pct = adv.get("epss_percentile")

                # Sort key: KEV first, then ransomware, then EPSS percentile desc,
                # then severity, then CVSS desc
                sort_key = (
                    0 if in_kev else 1,
                    0 if ransomware else 1,
                    -(epss_pct or 0.0),
                    sev_order,
                    -(cvss or 0.0),
                )
                adv_rows.append((
                    sort_key,
                    adv_id, in_kev, ransomware, sev, cvss, epss, epss_pct,
                    f"{pkg_name} {pkg_ver}".strip(),
                    adv.get("summary") or "",
                ))

        adv_rows.sort(key=lambda r: r[0])

        for row in adv_rows:
            (_, adv_id, in_kev, ransomware, sev, cvss, epss, epss_pct,
             pkg_label, summary) = row

            # Exploit indicator column: ★ KEV + 🦠 ransomware
            exploit_parts: list[str] = []
            if in_kev:
                exploit_parts.append("★")
            if ransomware:
                exploit_parts.append("R")
            exploit_str = " ".join(exploit_parts)

            epss_str = f"{epss * 100:.1f}%" if epss is not None else ""
            cvss_str = f"{cvss:.1f}" if cvss is not None else ""
            summary_str = summary[:80]

            sev_style = {
                "Critical": "bold white on red",
                "High": "bold black on yellow",
                "Medium": "black on dark_orange3",
                "Low": "black on green",
            }.get(sev.capitalize(), "")

            exploit_style = "bold red" if in_kev or ransomware else ""

            tbl.add_row(
                adv_id,
                Text(exploit_str, style=exploit_style) if exploit_str else "",
                Text(sev, style=sev_style) if sev_style else sev,
                cvss_str,
                Text(epss_str, style="bold yellow" if epss is not None and epss >= 0.1 else "") if epss_str else "",
                pkg_label,
                summary_str,
            )


# ---------------------------------------------------------------------------
# Network Summary Panel
# ---------------------------------------------------------------------------

_SPARK_CHARS = " ▁▂▃▄▅▆▇█"


def _sparkline(values: list[int | float], width: int = 30) -> str:
    """Return a unicode sparkline string of the given values."""
    if not values:
        return " " * width
    mn = min(values)
    mx = max(values)
    span = mx - mn or 1
    chars = []
    for v in values[-width:]:
        idx = int((v - mn) / span * (len(_SPARK_CHARS) - 1))
        chars.append(_SPARK_CHARS[idx])
    # Pad left if shorter than width
    if len(chars) < width:
        chars = [" "] * (width - len(chars)) + chars
    return "".join(chars)


class NetworkSummaryPanel(Widget):
    """Full-panel summary: OS breakdown, state counts, top CVEs, risk sparklines."""

    DEFAULT_CSS = """
    NetworkSummaryPanel {
        width: 1fr;
        height: 1fr;
        overflow-y: auto;
    }
    NetworkSummaryPanel .summary-header {
        text-style: bold;
        color: $accent;
        padding: 0 1;
    }
    NetworkSummaryPanel .summary-section {
        padding: 0 1 1 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label("Network Summary", classes="summary-header")
        yield VerticalScroll(
            Static("", id="summary-body"),
        )

    def update(
        self,
        hosts: dict,
        vuln_matches: dict | None = None,
        risk_history: dict | None = None,
    ) -> None:
        self.post_message(self._UpdateMessage(hosts, vuln_matches or {}, risk_history or {}))

    class _UpdateMessage(Message):
        def __init__(
            self,
            hosts: dict,
            vuln_matches: dict,
            risk_history: dict,
        ) -> None:
            super().__init__()
            self.hosts = hosts
            self.vuln_matches = vuln_matches
            self.risk_history = risk_history

    def on_network_summary_panel__update_message(self, message: _UpdateMessage) -> None:
        from textual import work
        self._do_rebuild(message.hosts, message.vuln_matches, message.risk_history)

    def _do_rebuild(
        self,
        hosts: dict,
        vuln_matches: dict,
        risk_history: dict,
    ) -> None:
        lines: list[str] = []

        # ── OS / type breakdown ──────────────────────────────────────────────
        os_counts: dict[str, int] = {}
        for h in hosts.values():
            key = h.os_guess or "Unknown"
            # Shorten common long names
            if "Ubuntu" in key:
                key = "Ubuntu"
            elif "Debian" in key:
                key = "Debian"
            elif "Raspberry" in key:
                key = "Raspberry Pi OS"
            elif "Windows" in key:
                key = "Windows"
            elif "Darwin" in key:
                key = "macOS"
            os_counts[key] = os_counts.get(key, 0) + 1

        lines.append("── OS Distribution ─────────────────────────────────")
        if os_counts:
            total_hosts = len(hosts)
            for os_name, count in sorted(os_counts.items(), key=lambda x: -x[1]):
                bar_width = max(1, int(count / total_hosts * 30))
                bar = "█" * bar_width
                lines.append(f"  {os_name:<22} {bar} {count}")
        else:
            lines.append("  (no hosts)")

        # ── Host state breakdown ─────────────────────────────────────────────
        lines.append("")
        lines.append("── Host States ──────────────────────────────────────")
        state_counts: dict[str, int] = {}
        for h in hosts.values():
            s = h.state.value if hasattr(h.state, "value") else str(h.state)
            state_counts[s] = state_counts.get(s, 0) + 1
        for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {state:<20} {count}")

        # ── Top CVEs ─────────────────────────────────────────────────────────
        lines.append("")
        lines.append("── Top Vulnerabilities (by host count) ─────────────")
        cve_hosts: dict[str, set[str]] = {}
        cve_meta: dict[str, dict] = {}
        for ip, matches in vuln_matches.items():
            for adv in matches:
                adv_id = adv.get("id", "")
                if not adv_id:
                    continue
                if adv_id not in cve_hosts:
                    cve_hosts[adv_id] = set()
                    cve_meta[adv_id] = adv
                cve_hosts[adv_id].add(ip)

        # Sort by: KEV first, then ransomware, then EPSS, then host count
        def _cve_sort(item: tuple) -> tuple:
            adv_id, host_set = item
            meta = cve_meta.get(adv_id, {})
            in_kev = meta.get("source") == "kev"
            ransomware = bool(meta.get("ransomware"))
            epss = meta.get("epss_score") or 0.0
            return (0 if in_kev else 1, 0 if ransomware else 1, -epss, -len(host_set))

        top_cves = sorted(cve_hosts.items(), key=_cve_sort)[:20]
        if top_cves:
            lines.append(f"  {'ID':<28} {'Hosts':>5}  {'Sev':<8}  Flags")
            lines.append(f"  {'─'*28} {'─'*5}  {'─'*8}  {'─'*10}")
            for adv_id, host_set in top_cves:
                meta = cve_meta.get(adv_id, {})
                sev = (meta.get("severity") or "").capitalize()[:8]
                in_kev = meta.get("source") == "kev"
                ransomware = bool(meta.get("ransomware"))
                epss = meta.get("epss_score")
                flags = []
                if in_kev:
                    flags.append("★KEV")
                if ransomware:
                    flags.append("R")
                if epss is not None:
                    flags.append(f"EPSS:{epss*100:.0f}%")
                flags_str = " ".join(flags)
                lines.append(f"  {adv_id:<28} {len(host_set):>5}  {sev:<8}  {flags_str}")
        else:
            lines.append("  (no vulnerabilities found)")

        # ── Per-host risk sparklines ─────────────────────────────────────────
        lines.append("")
        lines.append("── Per-host Risk Trend (6 months) ──────────────────")
        net_history = risk_history.get("__network__", [])
        host_history_items = [(ip, v) for ip, v in risk_history.items() if ip != "__network__"]

        if host_history_items:
            for ip, history in sorted(host_history_items, key=lambda x: x[0]):
                host = hosts.get(ip)
                name = host.display_name if host else ip
                scores = [s for _, s in history]
                spark = _sparkline(scores, width=20)
                current = scores[-1] if scores else 0
                lines.append(f"  {name:<22} {spark}  {current:>4}")
        else:
            lines.append("  (no history yet — run a scan to populate)")

        # ── Network risk trend ───────────────────────────────────────────────
        lines.append("")
        lines.append("── Network Risk Trend ───────────────────────────────")
        if net_history:
            net_scores = [s for _, s in net_history]
            spark = _sparkline(net_scores, width=40)
            current_net = net_scores[-1] if net_scores else 0
            lines.append(f"  {spark}  current: {current_net}")
        else:
            lines.append("  (no history yet)")

        # Write to the static body widget
        body = self.query_one("#summary-body", Static)
        body.update("\n".join(lines))

