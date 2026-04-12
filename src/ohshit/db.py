"""DuckDB persistence layer.

Design
------
- One DuckDB file, opened in READ_WRITE mode.
- The scanner background thread gets its own connection (DuckDB supports
  multi-threaded access to the same file via separate connection objects).
- The UI (Textual event loop) also opens its own read-only connection for
  polling.  DuckDB WAL semantics mean the UI sees committed data immediately
  without needing any Python-level locking.
- The only synchronisation primitive is a threading.Event that the scanner
  fires after each host upsert so the UI poll knows there may be fresh data.
  The UI does NOT need to wait on it — it polls on a fixed timer too.

Schema notes
------------
- hosts          — one row per IP, all mutable columns updated on each scan.
- mac_history    — append-only log of (mac, ip) pairings with timestamps.
- ports          — current open ports per host, replaced each scan.
- findings       — current findings per host, replaced each scan.
- iot_info       — one row per IP, upserted with passive detection results.
- scan_log       — one row per scan attempt for the progress panel.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from .models import (
    Finding,
    Host,
    HostState,
    IotInfo,
    MacEvent,
    PortInfo,
    ScanResult,
    Severity,
)

# Fired by the writer connection after committing host data so the UI can
# refresh sooner than its next scheduled poll.
data_changed = threading.Event()

# Each entry is one complete DDL statement (no semicolons at end).
# Run individually because DuckDB has no executescript().
_SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS hosts (
    ip              TEXT PRIMARY KEY,
    mac             TEXT,
    hostname        TEXT,
    state           TEXT NOT NULL DEFAULT 'Alive',
    os_guess        TEXT,
    kernel_version  TEXT,
    os_release_json TEXT NOT NULL DEFAULT '{}',
    services_json   TEXT NOT NULL DEFAULT '[]',
    ssh_error       TEXT,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    last_scan       TIMESTAMPTZ
)""",
    """CREATE TABLE IF NOT EXISTS mac_history (
    id          TEXT PRIMARY KEY,
    mac         TEXT NOT NULL,
    ip          TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    UNIQUE (mac, ip)
)""",
    """CREATE TABLE IF NOT EXISTS ports (
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    state       TEXT NOT NULL,
    service     TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ip, port, protocol)
)""",
    """CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    score       INTEGER NOT NULL,
    remediation_json TEXT NOT NULL DEFAULT '[]'
)""",
    """CREATE TABLE IF NOT EXISTS iot_info (
    ip                  TEXT PRIMARY KEY,
    vendor              TEXT,
    device_type         TEXT,
    mac_permanence      TEXT,
    mdns_names_json     TEXT NOT NULL DEFAULT '[]',
    mdns_services_json  TEXT NOT NULL DEFAULT '[]',
    upnp_friendly_name  TEXT,
    upnp_model          TEXT,
    ha_entity_id        TEXT,
    mqtt_topics_json    TEXT NOT NULL DEFAULT '[]',
    banner_grabs_json   TEXT NOT NULL DEFAULT '{}',
    detection_methods_json TEXT NOT NULL DEFAULT '[]',
    esphome_info_json   TEXT NOT NULL DEFAULT '{}'
)""",
    """CREATE TABLE IF NOT EXISTS scan_log (
    id          TEXT PRIMARY KEY,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    cidr        TEXT,
    gateway     TEXT,
    hosts_found INTEGER,
    status      TEXT NOT NULL DEFAULT 'running'
)""",
    """CREATE TABLE IF NOT EXISTS sbom_index (
    host_id       TEXT NOT NULL,
    ip            TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    collected_at  TIMESTAMPTZ NOT NULL,
    db_path       TEXT NOT NULL,
    package_count INTEGER NOT NULL DEFAULT 0,
    is_latest     BOOLEAN NOT NULL DEFAULT TRUE
)""",
    """CREATE TABLE IF NOT EXISTS vuln_cache (
    ip            TEXT PRIMARY KEY,
    queried_at    TIMESTAMPTZ NOT NULL,
    matches_json  TEXT NOT NULL DEFAULT '{}'
)""",
    """CREATE TABLE IF NOT EXISTS risk_history (
    recorded_at      TIMESTAMPTZ NOT NULL,
    ip               TEXT NOT NULL,
    risk_score       INTEGER NOT NULL,
    network_score    INTEGER NOT NULL,
    PRIMARY KEY (recorded_at, ip)
)""",
]

# Migrations: ALTER TABLE statements to add columns to existing DB files.
# Each tuple is (table, column, sql_type_and_default).
_MIGRATIONS = [
    ("iot_info", "mac_permanence",    "TEXT"),
    ("iot_info", "esphome_info_json", "TEXT"),
]


def _ensure_schema(con: duckdb.DuckDBPyConnection) -> None:
    """Create any missing tables and apply pending migrations."""
    for stmt in _SCHEMA_STATEMENTS:
        con.execute(stmt)
    # Apply migrations: add columns that may not exist in older DB files.
    for table, column, sql_type in _MIGRATIONS:
        try:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
        except Exception:
            pass  # Column already exists — DuckDB raises on duplicate ADD COLUMN


def open_writer(path: Path) -> duckdb.DuckDBPyConnection:
    """Open a read-write connection and ensure schema is up to date."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    _ensure_schema(con)
    return con


def open_reader(path: Path) -> duckdb.DuckDBPyConnection:
    """Open a connection for the UI thread.

    DuckDB supports multiple concurrent read-write connections to the same
    file; read_only=True is NOT used because it cannot coexist with an open
    read-write connection (the scanner's writer). Both connections are opened
    read-write and DuckDB's own WAL handles isolation between them.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    _ensure_schema(con)
    return con


# ---------------------------------------------------------------------------
# Writer helpers  (called from scanner thread)
# ---------------------------------------------------------------------------

def upsert_host(con: duckdb.DuckDBPyConnection, host: Host) -> None:
    """Insert or update a host row.  Never removes a host that goes offline."""
    now = datetime.now()
    con.execute("""
        INSERT INTO hosts
            (ip, mac, hostname, state, os_guess, kernel_version,
             os_release_json, services_json, ssh_error,
             first_seen, last_seen, last_scan)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (ip) DO UPDATE SET
            mac             = COALESCE(excluded.mac, hosts.mac),
            hostname        = COALESCE(excluded.hostname, hosts.hostname),
            state           = excluded.state,
            os_guess        = COALESCE(excluded.os_guess, hosts.os_guess),
            kernel_version  = COALESCE(excluded.kernel_version, hosts.kernel_version),
            os_release_json = CASE WHEN excluded.os_release_json != '{}'
                                   THEN excluded.os_release_json
                                   ELSE hosts.os_release_json END,
            services_json   = excluded.services_json,
            ssh_error       = excluded.ssh_error,
            last_seen       = excluded.last_seen,
            last_scan       = excluded.last_scan
    """, [
        host.ip,
        host.mac,
        host.hostname,
        host.state.value,
        host.os_guess,
        host.kernel_version,
        json.dumps(host.os_release),
        json.dumps(host.services),
        host.ssh_error,
        host.first_seen,
        now,
        host.last_scan or now,
    ])

    # MAC history — record every new (mac, ip) pair we observe
    if host.mac:
        con.execute("""
            INSERT INTO mac_history (id, mac, ip, first_seen, last_seen, hostname, os_guess)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (mac, ip) DO UPDATE SET
                last_seen = excluded.last_seen,
                hostname  = COALESCE(excluded.hostname, mac_history.hostname),
                os_guess  = COALESCE(excluded.os_guess,  mac_history.os_guess)
        """, [
            f"{host.mac}:{host.ip}",
            host.mac, host.ip,
            host.first_seen, now,
            host.hostname, host.os_guess,
        ])


def replace_ports(con: duckdb.DuckDBPyConnection, host: Host) -> None:
    con.execute("DELETE FROM ports WHERE ip = ?", [host.ip])
    for p in host.open_ports:
        con.execute("""
            INSERT INTO ports (ip, port, protocol, state, service, version)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [host.ip, p.port, p.protocol, p.state, p.service, p.version])


def replace_findings(con: duckdb.DuckDBPyConnection, host: Host) -> None:
    con.execute("DELETE FROM findings WHERE ip = ?", [host.ip])
    for f in host.findings:
        con.execute("""
            INSERT INTO findings
                (id, ip, category, severity, title, description,
                 evidence, score, remediation_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            f.id, host.ip, f.category, f.severity.value,
            f.title, f.description, f.evidence, f.score,
            json.dumps(f.remediation),
        ])


def upsert_iot(con: duckdb.DuckDBPyConnection, ip: str, iot: IotInfo) -> None:
    con.execute("""
        INSERT INTO iot_info
            (ip, vendor, device_type, mac_permanence,
             mdns_names_json, mdns_services_json,
             upnp_friendly_name, upnp_model, ha_entity_id,
             mqtt_topics_json, banner_grabs_json, detection_methods_json,
             esphome_info_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (ip) DO UPDATE SET
            vendor              = COALESCE(excluded.vendor, iot_info.vendor),
            device_type         = COALESCE(excluded.device_type, iot_info.device_type),
            mac_permanence      = COALESCE(excluded.mac_permanence, iot_info.mac_permanence),
            mdns_names_json     = excluded.mdns_names_json,
            mdns_services_json  = excluded.mdns_services_json,
            upnp_friendly_name  = COALESCE(excluded.upnp_friendly_name, iot_info.upnp_friendly_name),
            upnp_model          = COALESCE(excluded.upnp_model, iot_info.upnp_model),
            ha_entity_id        = COALESCE(excluded.ha_entity_id, iot_info.ha_entity_id),
            mqtt_topics_json    = excluded.mqtt_topics_json,
            banner_grabs_json   = excluded.banner_grabs_json,
            detection_methods_json = excluded.detection_methods_json,
            esphome_info_json   = CASE WHEN excluded.esphome_info_json != '{}'
                                       THEN excluded.esphome_info_json
                                       ELSE iot_info.esphome_info_json END
    """, [
        ip,
        iot.vendor, iot.device_type, iot.mac_permanence,
        json.dumps(iot.mdns_names), json.dumps(iot.mdns_services),
        iot.upnp_friendly_name, iot.upnp_model, iot.ha_entity_id,
        json.dumps(iot.mqtt_topics),
        json.dumps(iot.banner_grabs),
        json.dumps(iot.detection_methods),
        json.dumps(iot.esphome_info),
    ])


def write_host_complete(con: duckdb.DuckDBPyConnection, host: Host) -> None:
    """Atomic write of all host data, then signal the UI."""
    upsert_host(con, host)
    replace_ports(con, host)
    replace_findings(con, host)
    iot = host.iot_info
    has_iot_data = bool(
        iot.detection_methods
        or iot.vendor
        or iot.device_type
        or iot.mdns_names
        or iot.upnp_friendly_name
        or iot.esphome_info
    )
    if has_iot_data:
        upsert_iot(con, host.ip, iot)
    data_changed.set()


def start_scan_log(con: duckdb.DuckDBPyConnection, cidr: str | None, gateway: str | None) -> str:
    scan_id = uuid.uuid4().hex
    con.execute("""
        INSERT INTO scan_log (id, started_at, cidr, gateway, status)
        VALUES (?, ?, ?, ?, 'running')
    """, [scan_id, datetime.now(), cidr, gateway])
    return scan_id


def finish_scan_log(con: duckdb.DuckDBPyConnection, scan_id: str, hosts_found: int, status: str = "complete") -> None:
    con.execute("""
        UPDATE scan_log SET finished_at = ?, hosts_found = ?, status = ?
        WHERE id = ?
    """, [datetime.now(), hosts_found, status, scan_id])


# ---------------------------------------------------------------------------
# Reader helpers  (called from UI / Textual event loop)
# ---------------------------------------------------------------------------

def load_all_hosts(con: duckdb.DuckDBPyConnection) -> dict[str, Host]:
    """Load all persisted hosts with their ports, findings, IoT info, and MAC history."""
    rows = con.execute("""
        SELECT ip, mac, hostname, state, os_guess, kernel_version,
               os_release_json, services_json, ssh_error,
               first_seen, last_seen, last_scan
        FROM hosts
        ORDER BY ip
    """).fetchall()

    hosts: dict[str, Host] = {}
    for row in rows:
        (ip, mac, hostname, state, os_guess, kernel_version,
         os_release_json, services_json, ssh_error,
         first_seen, last_seen, last_scan) = row
        h = Host(
            ip=ip,
            mac=mac,
            hostname=hostname,
            state=HostState(state) if state else HostState.ALIVE,
            os_guess=os_guess,
            kernel_version=kernel_version,
            os_release=json.loads(os_release_json or "{}"),
            services=json.loads(services_json or "[]"),
            ssh_error=ssh_error,
            first_seen=first_seen or datetime.now(),
            last_seen=last_seen or datetime.now(),
            last_scan=last_scan,
        )
        hosts[ip] = h

    if not hosts:
        return hosts

    # Bulk load ports
    port_rows = con.execute("""
        SELECT ip, port, protocol, state, service, version FROM ports
    """).fetchall()
    for ip, port, protocol, state, service, version in port_rows:
        if ip in hosts:
            hosts[ip].open_ports.append(
                PortInfo(port=port, protocol=protocol, state=state,
                         service=service or "", version=version or "")
            )

    # Bulk load findings
    finding_rows = con.execute("""
        SELECT id, ip, category, severity, title, description,
               evidence, score, remediation_json FROM findings
    """).fetchall()
    for fid, ip, category, severity, title, description, evidence, score, rem_json in finding_rows:
        if ip in hosts:
            hosts[ip].findings.append(Finding(
                id=fid,
                host_ip=ip,
                category=category,
                severity=Severity(severity),
                title=title,
                description=description,
                evidence=evidence or "",
                score=score,
                remediation=json.loads(rem_json or "[]"),
            ))

    # Bulk load IoT info
    iot_rows = con.execute("""
        SELECT ip, vendor, device_type, mac_permanence,
               mdns_names_json, mdns_services_json,
               upnp_friendly_name, upnp_model, ha_entity_id,
               mqtt_topics_json, banner_grabs_json, detection_methods_json,
               esphome_info_json
        FROM iot_info
    """).fetchall()
    for (ip, vendor, device_type, mac_permanence, mdns_names_json, mdns_services_json,
         upnp_friendly_name, upnp_model, ha_entity_id,
         mqtt_topics_json, banner_grabs_json, detection_methods_json,
         esphome_info_json) in iot_rows:
        if ip in hosts:
            hosts[ip].iot_info = IotInfo(
                vendor=vendor,
                device_type=device_type,
                mac_permanence=mac_permanence,
                mdns_names=json.loads(mdns_names_json or "[]"),
                mdns_services=json.loads(mdns_services_json or "[]"),
                upnp_friendly_name=upnp_friendly_name,
                upnp_model=upnp_model,
                ha_entity_id=ha_entity_id,
                mqtt_topics=json.loads(mqtt_topics_json or "[]"),
                banner_grabs={int(k): v for k, v in json.loads(banner_grabs_json or "{}").items()},
                detection_methods=json.loads(detection_methods_json or "[]"),
                esphome_info=json.loads(esphome_info_json or "{}"),
            )

    # Bulk load MAC history
    mac_rows = con.execute("""
        SELECT mac, ip, first_seen, last_seen, hostname, os_guess FROM mac_history
        ORDER BY ip, first_seen
    """).fetchall()
    for mac, ip, first_seen, last_seen, hostname, os_guess in mac_rows:
        if ip in hosts:
            hosts[ip].mac_history.append(MacEvent(
                mac=mac, ip=ip,
                first_seen=first_seen, last_seen=last_seen,
                hostname=hostname, os_guess=os_guess,
            ))

    return hosts


def load_scan_summary(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    """Return stats for the UI subtitle bar."""
    row = con.execute("""
        SELECT
            (SELECT COUNT(*) FROM hosts) AS total_hosts,
            (SELECT COUNT(*) FROM hosts WHERE last_seen > NOW() - INTERVAL 5 MINUTE) AS recent_hosts,
            (SELECT started_at FROM scan_log ORDER BY started_at DESC LIMIT 1) AS last_scan,
            (SELECT status FROM scan_log ORDER BY started_at DESC LIMIT 1) AS scan_status,
            (SELECT cidr FROM scan_log ORDER BY started_at DESC LIMIT 1) AS cidr
    """).fetchone()
    if row:
        return {
            "total_hosts": row[0] or 0,
            "recent_hosts": row[1] or 0,
            "last_scan": row[2],
            "scan_status": row[3] or "never",
            "cidr": row[4],
        }
    return {"total_hosts": 0, "recent_hosts": 0, "last_scan": None, "scan_status": "never", "cidr": None}


import uuid  # noqa: E402 (needed for start_scan_log above)


# ---------------------------------------------------------------------------
# Vuln cache helpers
# ---------------------------------------------------------------------------

def save_vuln_cache(con: duckdb.DuckDBPyConnection, ip: str, matches: dict) -> None:
    """Persist vuln matches for a host into ohshit.db."""
    con.execute(
        """INSERT INTO vuln_cache (ip, queried_at, matches_json)
           VALUES (?, ?, ?)
           ON CONFLICT (ip) DO UPDATE SET
               queried_at   = excluded.queried_at,
               matches_json = excluded.matches_json""",
        [ip, datetime.now(), json.dumps(matches)],
    )


def load_vuln_cache(con: duckdb.DuckDBPyConnection) -> dict[str, tuple[datetime, dict]]:
    """Load all persisted vuln matches. Returns {ip: (queried_at, matches)}."""
    rows = con.execute(
        "SELECT ip, queried_at, matches_json FROM vuln_cache"
    ).fetchall()
    result: dict[str, tuple[datetime, dict]] = {}
    for ip, queried_at, matches_json in rows:
        try:
            result[ip] = (queried_at, json.loads(matches_json or "{}"))
        except Exception:
            pass
    return result


# ---------------------------------------------------------------------------
# Risk history helpers
# ---------------------------------------------------------------------------

def save_risk_snapshot(
    con: duckdb.DuckDBPyConnection,
    hosts: "dict[str, Any]",
) -> None:
    """Record current risk scores for all hosts into risk_history.

    Called once per completed scan so the summary panel can plot trends.
    Skips hosts with score=0 that are Unreachable (no meaningful data).
    """
    from .models import ScanResult
    if not hosts:
        return
    result = ScanResult(hosts=hosts)
    network_score = result.network_risk_score
    now = datetime.now()
    for ip, host in hosts.items():
        if host.state.value == "Unreachable" and host.risk_score == 0:
            continue
        try:
            con.execute(
                """INSERT INTO risk_history (recorded_at, ip, risk_score, network_score)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT (recorded_at, ip) DO NOTHING""",
                [now, ip, host.risk_score, network_score],
            )
        except Exception:
            pass


def load_risk_history(
    con: duckdb.DuckDBPyConnection,
    months: int = 6,
) -> dict[str, list[tuple[datetime, int]]]:
    """Return per-host risk score history for the last N months.

    Returns {ip: [(recorded_at, risk_score), ...]} sorted oldest-first.
    Also includes a synthetic '__network__' key with network_score values.
    """
    rows = con.execute(
        """SELECT ip, recorded_at, risk_score, network_score
           FROM risk_history
           WHERE recorded_at > NOW() - INTERVAL ? MONTH
           ORDER BY recorded_at ASC""",
        [months],
    ).fetchall()

    by_ip: dict[str, list[tuple[datetime, int]]] = {}
    net: dict[datetime, int] = {}
    for ip, recorded_at, risk_score, network_score in rows:
        by_ip.setdefault(ip, []).append((recorded_at, risk_score))
        # Use most recent network_score for each timestamp
        net[recorded_at] = network_score

    if net:
        by_ip["__network__"] = sorted(net.items())

    return by_ip
