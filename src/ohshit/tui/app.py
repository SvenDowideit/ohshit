"""Background scanner thread + DB-backed Textual UI.

Architecture
------------
                    ┌─────────────────────────────────┐
                    │  Scanner thread (asyncio loop)   │
                    │  discover → SSH → IoT → analyze  │
                    │  writes to DuckDB via writer_con  │
                    │  sets data_changed Event         │
                    └──────────────┬──────────────────┘
                                   │  DuckDB file (WAL)
                    ┌──────────────▼──────────────────┐
                    │  Textual event loop (UI thread)  │
                    │  reader_con polls DB every 2 s   │
                    │  OR on data_changed.is_set()     │
                    │  rebuilds Host objects, refreshes│
                    │  HostListPanel + right panel     │
                    └─────────────────────────────────┘

Synchronisation
---------------
- No shared Python objects between threads.
- DuckDB WAL ensures the UI reader always sees committed data.
- `db.data_changed` (threading.Event) lets the UI poll sooner when the
  scanner has just written something, without blocking on it.
- `scan_running` flag guards double-starts only.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading
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

from .. import db as DB
from ..discovery import discover_all, tcp_port_scan
from ..iot import detect_iot, passive_network_scan
from ..models import Host, IotInfo, ScanResult, Severity
from ..report import generate_markdown_report
from ..risk_engine import RiskEngine
from ..ssh_collector import collect_all, _apply_os_release
from .widgets import (
    FindingsTable,
    HostDetailTab,
    HostListPanel,
    LogFeed,
    RemediationPanel,
    ScanProgressBar,
)

CSS_PATH = Path(__file__).with_name("app.tcss")

# How often the UI polls the DB even without data_changed being set (seconds)
_POLL_INTERVAL = 2.0


class OhShitApp(App[None]):
    CSS_PATH = CSS_PATH

    BINDINGS = [
        Binding("r", "rescan_all", "Re-scan All", show=True),
        Binding("s", "rescan_selected", "Re-scan Host", show=True),
        Binding("e", "export_report", "Export Report", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    selected_ip: reactive[str | None] = reactive(None)
    scan_running: reactive[bool] = reactive(False)

    def __init__(
        self,
        no_ssh: bool = False,
        subnet_override: str | None = None,
        strict_host_keys: bool = False,
        db_path: Path = Path("ohshit.db"),
        ha_token: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._no_ssh = no_ssh
        self._subnet_override = subnet_override
        self._strict_host_keys = strict_host_keys
        self._db_path = db_path
        self._ha_token = ha_token
        self._risk_engine = RiskEngine()
        # Reader connection — UI thread only
        self._reader: Any = None
        # Cache of last-loaded hosts so selection survives refreshes
        self._hosts: dict[str, Host] = {}

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
        # Refresh OUI cache in background (non-blocking; falls back to mini-table)
        threading.Thread(target=self._refresh_oui_cache, daemon=True, name="oui-cache").start()
        # Open reader connection
        self._reader = DB.open_reader(self._db_path)
        # Load whatever is already in the DB immediately
        self._poll_db()
        self._log(f"Database: [bold]{self._db_path}[/bold]")
        self._log("Starting network scan… press [bold]r[/bold] to re-scan")
        # Start periodic UI poll
        self.set_interval(_POLL_INTERVAL, self._check_for_updates)
        # Launch initial scan
        self.action_rescan_all()

    def _refresh_oui_cache(self) -> None:
        from ..oui_db import refresh_cache
        if refresh_cache():
            self._thread_safe_log("[dim]OUI vendor database ready.[/dim]")

    def on_unmount(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # DB poll (UI thread)
    # ------------------------------------------------------------------

    def _check_for_updates(self) -> None:
        """Called by set_interval every _POLL_INTERVAL seconds."""
        if DB.data_changed.is_set():
            DB.data_changed.clear()
            self._poll_db()

    def _poll_db(self) -> None:
        """Read all hosts from DB and refresh panels."""
        try:
            # Re-open reader each poll so it sees latest committed data
            if self._reader:
                try:
                    self._reader.close()
                except Exception:
                    pass
            self._reader = DB.open_reader(self._db_path)
            self._hosts = DB.load_all_hosts(self._reader)
            summary = DB.load_scan_summary(self._reader)
            self._update_subtitle(summary)
            self.call_after_refresh(self._refresh_panels_sync)
        except Exception as exc:
            self._log(f"[dim red]DB poll error: {exc}[/dim red]")

    def _update_subtitle(self, summary: dict[str, Any]) -> None:
        total = summary["total_hosts"]
        recent = summary["recent_hosts"]
        status = summary["scan_status"] or "never"
        cidr = summary.get("cidr") or ""
        if not self._hosts:
            self.sub_title = "No data yet — scanning…"
            return
        result = ScanResult(hosts=self._hosts)
        label = result.network_risk_label.value
        score = result.network_risk_score
        self.sub_title = (
            f"{cidr}  |  {total} hosts ({recent} recently active)  |  "
            f"Network risk: {label} ({score})  |  scan: {status}"
        )

    # ------------------------------------------------------------------
    # Panel refresh (UI thread, called via call_after_refresh)
    # ------------------------------------------------------------------

    def _refresh_panels_sync(self) -> None:
        """Kick off async panel refresh from the sync poll callback."""
        self.run_worker(self._refresh_panels_async(), exclusive=False, name="ui-refresh")

    async def _refresh_panels_async(self) -> None:
        result = ScanResult(hosts=self._hosts)
        await self.query_one("#host-panel", HostListPanel).update_hosts(result)
        # Auto-select highest-risk host on first load
        if not self.selected_ip and self._hosts:
            top = max(self._hosts.values(), key=lambda h: h.risk_score)
            self.selected_ip = top.ip
        if self.selected_ip and self.selected_ip in self._hosts:
            await self._refresh_right_panel(self._hosts[self.selected_ip])

    async def _refresh_right_panel(self, host: Host) -> None:
        self.query_one("#host-detail", HostDetailTab).update_host(host)
        self.query_one("#findings-table", FindingsTable).update_host(host)
        await self.query_one("#remediation-panel", RemediationPanel).update_host(host)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_rescan_all(self) -> None:
        if self.scan_running:
            self._log("[yellow]Scan already running.[/yellow]")
            return
        self._launch_scanner_thread()

    def action_rescan_selected(self) -> None:
        if not self.selected_ip:
            self._log("[yellow]No host selected.[/yellow]")
            return
        if self.scan_running:
            self._log("[yellow]Scan already running.[/yellow]")
            return
        self._launch_scanner_thread(single_ip=self.selected_ip)

    async def action_export_report(self) -> None:
        if not self._hosts:
            self.notify("No scan data to export yet.", severity="warning")
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path.home() / f"network-security-report-{ts}.md"
        result = ScanResult(hosts=self._hosts)
        content = generate_markdown_report(result)
        async with aiofiles.open(path, "w") as f:
            await f.write(content)
        self.notify(f"Report saved to {path}", severity="information")
        self._log(f"[green]Report exported:[/green] {path}")

    # ------------------------------------------------------------------
    # Scanner thread launcher
    # ------------------------------------------------------------------

    def _launch_scanner_thread(self, single_ip: str | None = None) -> None:
        """Start the scanner in a background thread with its own asyncio loop."""
        self.scan_running = True
        self._set_progress("Starting scanner…", 0)

        def _thread_main() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    _scanner_async(
                        db_path=self._db_path,
                        no_ssh=self._no_ssh,
                        subnet_override=self._subnet_override,
                        ha_token=self._ha_token,
                        single_ip=single_ip,
                        progress_cb=self._thread_safe_progress,
                        log_cb=self._thread_safe_log,
                    )
                )
            except Exception as exc:
                import traceback
                self._thread_safe_log(f"[bold red]Scanner error:[/bold red] {exc}\n{traceback.format_exc()[-400:]}")
            finally:
                loop.close()
                # Signal UI to do a final poll
                DB.data_changed.set()
                self.call_from_thread(self._scanner_done)

        t = threading.Thread(target=_thread_main, daemon=True, name="ohshit-scanner")
        t.start()

    def _scanner_done(self) -> None:
        self.scan_running = False
        self._set_progress("Scan complete", 100)
        self._poll_db()

    # ------------------------------------------------------------------
    # Thread-safe UI callbacks (called from scanner thread)
    # ------------------------------------------------------------------

    def _thread_safe_progress(self, step: str, pct: int) -> None:
        self.call_from_thread(self._set_progress, step, pct)

    def _thread_safe_log(self, msg: str) -> None:
        self.call_from_thread(self._log, msg)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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
    # Message handlers
    # ------------------------------------------------------------------

    async def on_host_list_panel_host_selected(self, msg: HostListPanel.HostSelected) -> None:
        self.selected_ip = msg.ip
        if msg.ip in self._hosts:
            await self._refresh_right_panel(self._hosts[msg.ip])


# ---------------------------------------------------------------------------
# Scanner coroutine — runs in its own thread/loop
# ---------------------------------------------------------------------------

async def _scanner_async(
    db_path: Path,
    no_ssh: bool,
    subnet_override: str | None,
    ha_token: str | None,
    single_ip: str | None,
    progress_cb: Any,
    log_cb: Any,
) -> None:
    """Full scan pipeline.  Writes to DB as each host is processed."""
    writer = DB.open_writer(db_path)
    risk_engine = RiskEngine()

    def prog(step: str, pct: int) -> None:
        progress_cb(step, pct)

    # ── Phase 1: Discovery ──────────────────────────────────────────
    prog("Discovering hosts…", 2)
    log_cb("[bold cyan]Starting scan…[/bold cyan]")

    if single_ip:
        # Re-scan a single known host
        existing = DB.load_all_hosts(DB.open_reader(db_path))
        host = existing.get(single_ip) or Host(ip=single_ip)
        result = ScanResult(hosts={single_ip: host})
    else:
        try:
            result = await discover_all(
                progress_cb=lambda s, p: prog(f"Discovery: {s}", int(p * 0.25)),
                subnet_override=subnet_override,
            )
        except Exception as exc:
            log_cb(f"[red]Discovery failed: {exc}[/red]")
            return

        # Merge with DB so previously seen hosts are not lost
        existing = DB.load_all_hosts(DB.open_reader(db_path))
        for ip, host in existing.items():
            if ip not in result.hosts:
                # Keep offline hosts, mark unreachable
                host.state = __import__("ohshit.models", fromlist=["HostState"]).HostState.UNREACHABLE
                result.hosts[ip] = host

    log_cb(f"Discovery: {len(result.hosts)} hosts (includes previously seen offline hosts)")
    prog("Writing discovery data…", 26)

    # Write discovered hosts immediately so UI shows them
    for host in result.hosts.values():
        DB.upsert_host(writer, host)
        DB.replace_ports(writer, host)
    DB.data_changed.set()

    # ── Phase 2: Passive network IoT scan (mDNS + SSDP) ───────────
    prog("Passive IoT scan (mDNS/SSDP)…", 27)
    log_cb("Listening for mDNS/SSDP announcements…")
    passive = await passive_network_scan(timeout=3.0)
    for ip, iot in passive.items():
        if ip in result.hosts:
            _merge_iot(result.hosts[ip].iot_info, iot)
        else:
            # New host found passively
            h = Host(ip=ip, iot_info=iot)
            result.hosts[ip] = h
            DB.upsert_host(writer, h)
        DB.upsert_iot(writer, ip, result.hosts[ip].iot_info)
    if passive:
        log_cb(f"Passive scan: {len(passive)} devices announced themselves")
    DB.data_changed.set()

    # ── Phase 3: Per-host IoT detection + SSH collection ───────────
    total = len(result.hosts)
    prog("SSH + IoT per-host…", 30)

    hosts_list = list(result.hosts.values())
    # Process alive hosts first
    hosts_list.sort(key=lambda h: (
        0 if h.state.value not in ("Unreachable",) else 1,
        h.ip,
    ))

    ssh_sem = asyncio.Semaphore(5)
    iot_sem = asyncio.Semaphore(20)
    done = 0

    scan_id = DB.start_scan_log(writer, result.network_cidr, result.gateway_ip)

    async def process_host(host: Host) -> None:
        nonlocal done

        # IoT detection (always, even for non-SSH hosts)
        async with iot_sem:
            is_accessible = host.state.value not in ("Unreachable", "Alive")
            iot = await detect_iot(
                host.ip,
                mac=host.mac,
                is_ssh_accessible=is_accessible,
                ha_token=ha_token,
            )
            _merge_iot(host.iot_info, iot)

        # SSH collection
        raw: dict[str, Any] = {}
        if not no_ssh and host.state.value != "Unreachable":
            from ..ssh_collector import RemoteCollector
            async with ssh_sem:
                collector = RemoteCollector()
                raw = await collector.collect(host)
            if raw:
                _apply_os_release(host, raw)
                host.last_scan = datetime.now()

        # For hosts where SSH didn't run or failed, do a TCP connect scan
        # to populate open_ports (nmap may have already done this during
        # discovery, but single-IP rescans and --no-ssh mode skip nmap).
        ssh_gave_ports = bool(raw) and bool(host.open_ports)
        nmap_gave_ports = host.open_ports and not raw
        if not ssh_gave_ports and not nmap_gave_ports and host.state.value != "Unreachable":
            async with iot_sem:  # reuse semaphore to limit concurrent scanners
                scanned = await tcp_port_scan(host.ip)
                if scanned:
                    host.open_ports = scanned

        # Risk analysis
        host.findings = risk_engine.analyze(host, raw)

        # Write to DB — this is the only write per host
        DB.write_host_complete(writer, host)

        done += 1
        pct = 30 + int(done / total * 65)
        prog(f"[{done}/{total}] {host.display_name}", pct)

    await asyncio.gather(*[process_host(h) for h in hosts_list], return_exceptions=True)

    DB.finish_scan_log(writer, scan_id, len(result.hosts))
    writer.close()

    log_cb(
        f"[bold]Scan complete.[/bold] {total} hosts  |  "
        f"Use [bold]↑↓[/bold] to browse · [bold]Tab[/bold] switch panels · [bold]e[/bold] export"
    )


def _merge_iot(base: IotInfo, new: IotInfo) -> None:
    """Merge new IoT detection results into base, preferring non-None values."""
    base.vendor = base.vendor or new.vendor
    base.device_type = base.device_type or new.device_type
    for n in new.mdns_names:
        if n not in base.mdns_names:
            base.mdns_names.append(n)
    for s in new.mdns_services:
        if s not in base.mdns_services:
            base.mdns_services.append(s)
    base.upnp_friendly_name = base.upnp_friendly_name or new.upnp_friendly_name
    base.upnp_model = base.upnp_model or new.upnp_model
    base.ha_entity_id = base.ha_entity_id or new.ha_entity_id
    for t in new.mqtt_topics:
        if t not in base.mqtt_topics:
            base.mqtt_topics.append(t)
    base.banner_grabs.update(new.banner_grabs)
    for m in new.detection_methods:
        if m not in base.detection_methods:
            base.detection_methods.append(m)
