from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any

import aiofiles
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Label, TabbedContent, TabPane

from ..discovery import discover_all
from ..models import Host, ScanResult, Severity
from ..report import generate_markdown_report
from ..risk_engine import RiskEngine
from ..ssh_collector import collect_all
from .widgets import (
    FindingsTable,
    HostDetailTab,
    HostListPanel,
    LogFeed,
    NetworkRiskBadge,
    RemediationPanel,
    ScanProgressBar,
)

CSS_PATH = Path(__file__).with_name("app.tcss")


class OhShitApp(App[None]):
    CSS_PATH = CSS_PATH

    BINDINGS = [
        Binding("r", "rescan_all", "Re-scan All", show=True),
        Binding("s", "rescan_selected", "Re-scan Host", show=True),
        Binding("e", "export_report", "Export Report", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    scan_result: reactive[ScanResult | None] = reactive(None)
    selected_ip: reactive[str | None] = reactive(None)
    scan_running: reactive[bool] = reactive(False)

    def __init__(
        self,
        no_ssh: bool = False,
        subnet_override: str | None = None,
        strict_host_keys: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._no_ssh = no_ssh
        self._subnet_override = subnet_override
        self._strict_host_keys = strict_host_keys
        self._risk_engine = RiskEngine()
        self._raw_data: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-body"):
            yield HostListPanel(id="host-panel")
            with Vertical(id="right-panel"):
                with TabbedContent(id="detail-tabs", initial="tab-details"):
                    with TabPane("Host Details", id="tab-details"):
                        yield HostDetailTab(id="host-detail")
                    with TabPane("Findings", id="tab-findings"):
                        yield FindingsTable(id="findings-table")
                    with TabPane("Remediation", id="tab-remediation"):
                        yield RemediationPanel(id="remediation-panel")
        with Vertical(id="bottom-panel"):
            yield ScanProgressBar(id="scan-progress")
            yield LogFeed(id="log-feed")
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self.title = "Oh-Shit Network Security Dashboard"
        self._log("Starting network scan... (press [bold]r[/bold] to re-scan at any time)")
        self.action_rescan_all()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_rescan_all(self) -> None:
        if self.scan_running:
            self._log("[yellow]Scan already running.[/yellow]")
            return
        self._run_full_scan()

    def action_rescan_selected(self) -> None:
        if not self.selected_ip:
            self._log("[yellow]No host selected.[/yellow]")
            return
        self._run_host_scan(self.selected_ip)

    async def action_export_report(self) -> None:
        if not self.scan_result:
            self.notify("No scan data to export yet.", severity="warning")
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path.home() / f"network-security-report-{ts}.md"
        content = generate_markdown_report(self.scan_result)
        async with aiofiles.open(path, "w") as f:
            await f.write(content)
        self.notify(f"Report saved to {path}", severity="information")
        self._log(f"[green]Report exported:[/green] {path}")

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    @work(exclusive=True, name="full-scan")
    async def _run_full_scan(self) -> None:
        self.scan_running = True
        self._log("[bold cyan]Starting full network scan...[/bold cyan]")
        self._set_progress("Initialising...", 0)

        try:
            result = await discover_all(
                progress_cb=self._on_discovery_progress,
                subnet_override=self._subnet_override,
            )

            self._log(f"Discovery done: {len(result.hosts)} hosts found.")

            if self._no_ssh:
                self._log("[dim]SSH collection skipped (--no-ssh)[/dim]")
            else:
                self._log(f"Starting SSH collection on {len(result.hosts)} hosts...")
            self._set_progress("SSH collection...", 0)

            raw = await collect_all(
                result.hosts,
                progress_cb=self._on_ssh_progress,
                no_ssh=self._no_ssh,
            )
            self._raw_data = raw

            self._log("Analysing findings...")
            self._set_progress("Analysing...", 95)
            for ip, host in result.hosts.items():
                host_raw = raw.get(ip, {})
                host.findings = self._risk_engine.analyze(host, host_raw)
                # Parse os-release into host fields
                _apply_os_release(host, host_raw)

            result.scan_end = datetime.now()
            self.scan_result = result
            await self._refresh_all_panels()
            self._set_progress("Scan complete", 100)

            net_label = result.network_risk_label.value.upper()
            net_score = result.network_risk_score
            self._log(
                f"[bold]Scan complete.[/bold] "
                f"Network risk: [{_sev_colour(result.network_risk_label)}]{net_label}[/] "
                f"(score {net_score})  |  "
                f"Use [bold]↑↓[/bold] to browse hosts · [bold]Tab[/bold] to switch panels · [bold]e[/bold] to export"
            )
        except Exception as exc:
            import traceback
            self._log(f"[bold red]Scan failed:[/bold red] {exc}")
            self._log(f"[dim red]{traceback.format_exc()[-300:]}[/dim red]")
            self._set_progress("Scan failed", 0)
        finally:
            self.scan_running = False

    @work(exclusive=False, name="host-scan")
    async def _run_host_scan(self, ip: str) -> None:
        if not self.scan_result or ip not in self.scan_result.hosts:
            return
        host = self.scan_result.hosts[ip]
        self._log(f"Re-scanning {host.display_name}...")

        from ..ssh_collector import RemoteCollector
        collector = RemoteCollector()
        raw = await collector.collect(host)
        self._raw_data[ip] = raw
        host.findings = self._risk_engine.analyze(host, raw)
        _apply_os_release(host, raw)

        await self._refresh_right_panel(host)
        self._log(f"[green]Done re-scanning {host.display_name}.[/green]")

    # ------------------------------------------------------------------
    # Progress callbacks
    # ------------------------------------------------------------------

    def _on_discovery_progress(self, step: str, pct: int) -> None:
        self._set_progress(f"Discovery: {step}", int(pct * 0.6))
        self._log(f"[dim]{step}[/dim]")

    def _on_ssh_progress(self, step: str, pct: int) -> None:
        self._set_progress(f"SSH: {step}", 60 + int(pct * 0.35))

    def _set_progress(self, step: str, pct: int) -> None:
        try:
            bar = self.query_one("#scan-progress", ScanProgressBar)
            bar.step_name = step
            bar.progress = float(pct)
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.query_one("#log-feed", LogFeed).write(f"[dim]{ts}[/dim] {msg}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Panel refresh helpers
    # ------------------------------------------------------------------

    async def _refresh_all_panels(self) -> None:
        if not self.scan_result:
            return
        await self.query_one("#host-panel", HostListPanel).update_hosts(self.scan_result)
        # Auto-select the highest-risk host if nothing is selected yet
        if not self.selected_ip and self.scan_result.hosts:
            top = max(self.scan_result.hosts.values(), key=lambda h: h.risk_score)
            self.selected_ip = top.ip
        if self.selected_ip and self.selected_ip in self.scan_result.hosts:
            await self._refresh_right_panel(self.scan_result.hosts[self.selected_ip])

    async def _refresh_right_panel(self, host: Host) -> None:
        self.query_one("#host-detail", HostDetailTab).update_host(host)
        self.query_one("#findings-table", FindingsTable).update_host(host)
        await self.query_one("#remediation-panel", RemediationPanel).update_host(host)

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------

    async def on_host_list_panel_host_selected(self, msg: HostListPanel.HostSelected) -> None:
        self.selected_ip = msg.ip
        if self.scan_result and msg.ip in self.scan_result.hosts:
            await self._refresh_right_panel(self.scan_result.hosts[msg.ip])

    # ------------------------------------------------------------------
    # Reactive watchers
    # ------------------------------------------------------------------

    def watch_scan_result(self, result: ScanResult | None) -> None:
        if result is None:
            return
        self.sub_title = (
            f"Network {result.network_risk_label.value} "
            f"(score {result.network_risk_score})  |  "
            f"{len(result.hosts)} hosts  |  "
            f"scanned {result.scan_start.strftime('%H:%M')}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_os_release(host: Host, raw: dict[str, Any]) -> None:
    """Parse os-release text into host.os_release dict and kernel_version."""
    os_rel = raw.get("os_release", "")
    parsed: dict[str, str] = {}
    for line in os_rel.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            parsed[k.strip()] = v.strip().strip('"')
    if parsed:
        host.os_release = parsed

    uname = raw.get("uname", "").strip()
    if uname:
        parts = uname.split()
        if len(parts) >= 3:
            host.kernel_version = parts[2]


def _sev_colour(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "yellow",
        Severity.MEDIUM: "dark_orange3",
        Severity.LOW: "green",
        Severity.INFO: "blue",
    }.get(sev, "white")
