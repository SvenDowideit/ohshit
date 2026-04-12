from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
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
)
from textual.containers import Horizontal, VerticalScroll

from ..models import Finding, Host, HostState, ScanResult, Severity


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
            yield Label(
                self.host.state.value,
                classes="host-state",
            )

    def refresh_host(self, host: Host) -> None:
        """Update badge, name, and state label in-place without re-mounting."""
        self.host = host
        self.query_one(NetworkRiskBadge).update_severity(host.risk_label)
        self.query_one(".host-name", Label).update(host.display_name)
        self.query_one(".host-state", Label).update(host.state.value)


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
                current_idx = current_children.index(item)
                if current_idx != target_idx:
                    await item.remove()
                    if target_idx == 0:
                        # Find the new first child after removal
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
        yield Label("", id="detail-kernel")
        yield Label("", id="detail-mac")
        yield Label("", id="detail-ssh")
        yield Label("", id="detail-vendor")
        yield Label("", id="detail-iot")
        yield Label("", id="detail-repurpose")
        yield Label("Open Ports:", id="ports-label")
        yield DataTable(id="ports-table")

    def on_mount(self) -> None:
        tbl = self.query_one("#ports-table", DataTable)
        tbl.add_columns("Port", "Proto", "State", "Service", "Version")

    def update_host(self, host: Host | None) -> None:
        if host is None:
            self.query_one("#detail-header", Label).update(
                "← Select a host from the list to see details"
            )
            for wid in ("detail-os", "detail-kernel", "detail-mac", "detail-ssh",
                        "detail-vendor", "detail-iot", "detail-repurpose"):
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
        self.query_one("#detail-kernel", Label).update(f"Kernel: {host.kernel_version or 'unknown'}")
        self.query_one("#detail-mac", Label).update(f"MAC: {host.mac or 'unknown'}  |  IP: {host.ip}")

        ssh_info = host.state.value
        if host.ssh_error:
            ssh_info += f"  ({host.ssh_error})"
        self.query_one("#detail-ssh", Label).update(f"SSH: {ssh_info}")

        # IoT vendor / device type
        iot = host.iot_info
        vendor_parts = []
        if iot.vendor:
            vendor_parts.append(iot.vendor)
        if iot.device_type:
            vendor_parts.append(f"({iot.device_type})")
        self.query_one("#detail-vendor", Label).update(
            f"Vendor: {' '.join(vendor_parts)}" if vendor_parts else ""
        )

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

class RemediationPanel(Widget):
    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="remed-scroll")

    async def update_host(self, host: Host | None) -> None:
        scroll = self.query_one("#remed-scroll", VerticalScroll)
        await scroll.remove_children()
        if host is None or not host.findings:
            scroll.mount(Label("No findings."))
            return

        for f in sorted(host.findings, key=lambda x: x.score, reverse=True):
            header = Text(
                f"[{f.severity.value.upper()}] {f.title}",
                style=SEVERITY_STYLES.get(f.severity, ""),
            )
            scroll.mount(Static(header, classes="remed-title"))
            scroll.mount(Static(f.description, classes="remed-desc"))
            if f.remediation:
                for step in f.remediation:
                    scroll.mount(Static(f"  $ {step}", classes="remed-step"))
            scroll.mount(Static("─" * 60, classes="remed-sep"))


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
