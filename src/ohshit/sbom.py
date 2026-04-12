"""SBOM (Software Bill of Materials) collection and storage.

Design
------
- Each SBOM collection for a host is stored in its own DuckDB file:
    sbom/<host_id>/<timestamp>.duckdb
  where host_id is the MAC address (preferred) or IP (fallback).

- An sbom_index table in the main ohshit.db tracks all per-host SBOM
  databases (path, timestamp, package count, is_latest flag).  This
  piggybacks on the existing DuckDB WAL concurrency so the scanner
  thread and UI thread can both access it without conflicts.

- DuckLake is used on demand to query across multiple per-host files
  (e.g. for historical comparison), but is NOT held open persistently.

- SBOM collection sources:
    dpkg/apt  — Debian/Ubuntu systems
    rpm       — Red Hat/Fedora/SUSE systems
    snap      — Snap packages
    flatpak   — Flatpak packages
    pip3      — System Python packages
    docker    — Running container images (from docker ps / docker images)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb


@dataclass
class SbomPackage:
    name: str
    version: str
    source: str          # "dpkg", "rpm", "snap", "flatpak", "pip", "docker"
    package_type: str    # "deb", "rpm", "snap", "flatpak", "python", "container"
    arch: str = ""
    released_at: datetime | None = None  # when the package/version was released by distro/author


_SBOM_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS packages (
        name         TEXT NOT NULL,
        version      TEXT NOT NULL,
        source       TEXT NOT NULL,
        package_type TEXT NOT NULL,
        arch         TEXT NOT NULL DEFAULT '',
        released_at  TIMESTAMPTZ,
        PRIMARY KEY (name, source)
    )""",
    """CREATE TABLE IF NOT EXISTS metadata (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
]


def _sbom_dir(base_dir: Path) -> Path:
    d = base_dir / "sbom"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _host_dir(base_dir: Path, host_id: str) -> Path:
    # Sanitise MAC/IP for use as directory name
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", host_id)
    d = _sbom_dir(base_dir) / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def latest_sbom_path(base_dir: Path, host_id: str) -> Path | None:
    """Return path to the most recent SBOM database for this host, or None."""
    hdir = _host_dir(base_dir, host_id)
    dbs = sorted(hdir.glob("*.duckdb"), reverse=True)
    return dbs[0] if dbs else None


def all_sbom_paths(base_dir: Path, host_id: str) -> list[Path]:
    """Return all SBOM database paths for this host, newest first."""
    hdir = _host_dir(base_dir, host_id)
    return sorted(hdir.glob("*.duckdb"), reverse=True)


def write_sbom(
    base_dir: Path,
    host_id: str,
    packages: list[SbomPackage],
    ip: str,
    hostname: str | None,
    collected_at: datetime | None = None,
) -> Path:
    """Write a new SBOM database for a host. Returns the path written."""
    ts = (collected_at or datetime.now()).strftime("%Y%m%dT%H%M%S")
    hdir = _host_dir(base_dir, host_id)
    db_path = hdir / f"{ts}.duckdb"

    con = duckdb.connect(str(db_path))
    for stmt in _SBOM_SCHEMA:
        con.execute(stmt)

    con.execute("DELETE FROM packages")
    for pkg in packages:
        con.execute(
            "INSERT INTO packages (name, version, source, package_type, arch, released_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [pkg.name, pkg.version, pkg.source, pkg.package_type, pkg.arch, pkg.released_at],
        )

    # Store collection metadata
    meta = {
        "ip": ip,
        "hostname": hostname or "",
        "host_id": host_id,
        "collected_at": (collected_at or datetime.now()).isoformat(),
        "package_count": str(len(packages)),
    }
    con.execute("DELETE FROM metadata")
    for k, v in meta.items():
        con.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            [k, v],
        )

    con.close()
    return db_path


def should_collect_sbom(base_dir: Path, host_id: str, max_age_hours: float = 24.0) -> bool:
    """Return True if no SBOM exists for this host or the latest is too old."""
    path = latest_sbom_path(base_dir, host_id)
    if path is None:
        return True
    # Parse timestamp from filename (YYYYMMDDTHHMMSS.duckdb)
    stem = path.stem
    try:
        ts = datetime.strptime(stem, "%Y%m%dT%H%M%S")
        age_hours = (datetime.now() - ts).total_seconds() / 3600
        return age_hours > max_age_hours
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Parsing functions — convert raw SSH output into SbomPackage lists
# ---------------------------------------------------------------------------

def _parse_dpkg_dates(raw: str) -> dict[str, datetime]:
    """Parse `stat -c $'%n\t%Y' /var/lib/dpkg/info/*.md5sums` output.

    The .md5sums file mtime is set when the .deb is unpacked and matches the
    package build/release date, not the install date.
    Returns a dict of package_name -> release datetime.
    Filenames are like /var/lib/dpkg/info/bash.md5sums or bash:amd64.md5sums.
    """
    dates: dict[str, datetime] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        path, _, ts_str = line.rpartition("\t")
        try:
            ts = int(ts_str)
        except ValueError:
            continue
        # Extract package name: /var/lib/dpkg/info/bash:amd64.md5sums -> bash
        name = path.rsplit("/", 1)[-1]
        name = name.removesuffix(".md5sums")
        name = name.split(":")[0]  # strip :arch suffix
        dates[name] = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dates


def parse_dpkg(raw: str, dates: dict[str, datetime] | None = None) -> list[SbomPackage]:
    """Parse dpkg-query -W output: name\tversion\tarch per line."""
    pkgs = []
    for line in raw.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            name = parts[0]
            pkgs.append(SbomPackage(
                name=name,
                version=parts[1],
                source="dpkg",
                package_type="deb",
                arch=parts[2] if len(parts) >= 3 else "",
                released_at=dates.get(name) if dates else None,
            ))
    return pkgs


def parse_rpm(raw: str) -> list[SbomPackage]:
    """Parse rpm -qa output: name\tversion-release\tarch\tbuildtime_unix_ts per line."""
    pkgs = []
    for line in raw.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            released_at = None
            if len(parts) >= 4 and parts[3].isdigit():
                try:
                    released_at = datetime.fromtimestamp(int(parts[3]), tz=timezone.utc)
                except (ValueError, OSError):
                    pass
            pkgs.append(SbomPackage(
                name=parts[0],
                version=parts[1],
                source="rpm",
                package_type="rpm",
                arch=parts[2] if len(parts) >= 3 else "",
                released_at=released_at,
            ))
    return pkgs


def parse_snap(raw: str) -> list[SbomPackage]:
    """Parse snap list output."""
    pkgs = []
    lines = raw.splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append(SbomPackage(
                name=parts[0],
                version=parts[1],
                source="snap",
                package_type="snap",
            ))
    return pkgs


def parse_flatpak(raw: str) -> list[SbomPackage]:
    """Parse flatpak list --columns=application,version,origin output."""
    pkgs = []
    for line in raw.splitlines():
        parts = line.strip().split("\t")
        if not parts or not parts[0]:
            continue
        if len(parts) < 2:
            parts = line.split()
        if len(parts) >= 2:
            pkgs.append(SbomPackage(
                name=parts[0],
                version=parts[1] if len(parts) > 1 else "",
                source="flatpak",
                package_type="flatpak",
            ))
    return pkgs


def parse_pip_freeze(raw: str) -> list[SbomPackage]:
    """Parse pip freeze output: name==version.

    Release dates for pip packages are not available locally; they would
    require querying PyPI. released_at is left None for now.
    """
    pkgs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, _, version = line.partition("==")
            pkgs.append(SbomPackage(
                name=name.strip(),
                version=version.strip(),
                source="pip",
                package_type="python",
            ))
    return pkgs


def parse_docker_images(raw: str) -> list[SbomPackage]:
    """Parse docker images output into SbomPackage entries."""
    pkgs = []
    lines = raw.splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            repo = parts[0]
            tag = parts[1]
            image_id = parts[2]
            if repo == "<none>":
                name = image_id
                version = "untagged"
            else:
                name = repo
                version = tag
            pkgs.append(SbomPackage(
                name=name,
                version=version,
                source="docker",
                package_type="container",
            ))
    return pkgs


def collect_packages_from_raw(raw: dict[str, Any]) -> list[SbomPackage]:
    """Extract all packages from a raw SSH collection dict."""
    all_pkgs: list[SbomPackage] = []
    seen: set[tuple[str, str]] = set()

    def add_unique(pkgs: list[SbomPackage]) -> None:
        for p in pkgs:
            key = (p.name, p.source)
            if key not in seen:
                seen.add(key)
                all_pkgs.append(p)

    dpkg_dates = _parse_dpkg_dates(raw.get("sbom_dpkg_dates", ""))

    if raw.get("sbom_dpkg"):
        add_unique(parse_dpkg(raw["sbom_dpkg"], dpkg_dates))
    if raw.get("sbom_rpm"):
        add_unique(parse_rpm(raw["sbom_rpm"]))
    if raw.get("sbom_snap"):
        add_unique(parse_snap(raw["sbom_snap"]))
    if raw.get("sbom_flatpak"):
        add_unique(parse_flatpak(raw["sbom_flatpak"]))
    if raw.get("sbom_pip"):
        add_unique(parse_pip_freeze(raw["sbom_pip"]))
    if raw.get("sbom_pip_user"):
        add_unique(parse_pip_freeze(raw["sbom_pip_user"]))
    if raw.get("docker_images"):
        add_unique(parse_docker_images(raw["docker_images"]))

    return all_pkgs


# ---------------------------------------------------------------------------
# sbom_index table — lives in the main ohshit.db, managed via the existing
# writer/reader connections so WAL concurrency is handled automatically.
# ---------------------------------------------------------------------------

_INDEX_SCHEMA = """CREATE TABLE IF NOT EXISTS sbom_index (
    host_id       TEXT NOT NULL,
    ip            TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    collected_at  TIMESTAMPTZ NOT NULL,
    db_path       TEXT NOT NULL,
    package_count INTEGER NOT NULL DEFAULT 0,
    is_latest     BOOLEAN NOT NULL DEFAULT TRUE
)"""


def ensure_sbom_schema(con: duckdb.DuckDBPyConnection) -> None:
    """Add sbom_index to an existing ohshit.db connection if not present."""
    con.execute(_INDEX_SCHEMA)


def register_sbom_in_catalog(
    con: duckdb.DuckDBPyConnection,
    host_id: str,
    ip: str,
    hostname: str | None,
    collected_at: datetime,
    db_path: Path,
    package_count: int,
) -> None:
    """Record a new SBOM database in sbom_index and mark previous as not latest."""
    con.execute(
        "UPDATE sbom_index SET is_latest = FALSE WHERE host_id = ?",
        [host_id],
    )
    con.execute(
        """INSERT INTO sbom_index
               (host_id, ip, hostname, collected_at, db_path, package_count, is_latest)
           VALUES (?, ?, ?, ?, ?, ?, TRUE)""",
        [host_id, ip, hostname or "", collected_at, str(db_path), package_count],
    )


def load_latest_packages(
    con: duckdb.DuckDBPyConnection,
    ip: str | None = None,
) -> list[dict]:
    """Load packages from the latest SBOM for each host (or a specific host)."""
    where = "WHERE is_latest = TRUE"
    params: list = []
    if ip:
        where += " AND ip = ?"
        params.append(ip)

    index_rows = con.execute(
        f"SELECT host_id, ip, hostname, collected_at, db_path FROM sbom_index {where}",
        params,
    ).fetchall()

    results = []
    for host_id, row_ip, hostname, collected_at, db_path in index_rows:
        db = Path(db_path)
        if not db.exists():
            continue
        try:
            hcon = duckdb.connect(str(db), read_only=True)
            pkgs = hcon.execute(
                "SELECT name, version, source, package_type, arch, released_at FROM packages ORDER BY source, name"
            ).fetchall()
            hcon.close()
            for name, version, source, package_type, arch, released_at in pkgs:
                results.append({
                    "host_id": host_id,
                    "ip": row_ip,
                    "hostname": hostname,
                    "collected_at": collected_at,
                    "name": name,
                    "version": version,
                    "source": source,
                    "package_type": package_type,
                    "arch": arch,
                    "released_at": released_at,
                })
        except Exception:
            pass
    return results


def load_sbom_summary(con: duckdb.DuckDBPyConnection) -> list[dict]:
    """Return per-host SBOM summary (latest only)."""
    rows = con.execute(
        """SELECT host_id, ip, hostname, collected_at, package_count
           FROM sbom_index
           WHERE is_latest = TRUE
           ORDER BY ip"""
    ).fetchall()
    return [
        {
            "host_id": r[0],
            "ip": r[1],
            "hostname": r[2],
            "collected_at": r[3],
            "package_count": r[4],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# DuckLake — on-demand cross-host queries (archaeology / comparison only)
# ---------------------------------------------------------------------------

def ducklake_query(base_dir: Path, sql: str) -> list[tuple]:
    """Open a short-lived DuckLake connection, run sql, return rows, close.

    Use this for historical / cross-host queries only — do not hold the
    connection open, as DuckLake only supports one concurrent connection.
    """
    catalog_path = _sbom_dir(base_dir) / "sbom_catalog.ducklake"
    data_dir = _sbom_dir(base_dir) / "catalog_data"
    data_dir.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect(":memory:")
    con.execute("INSTALL ducklake")
    con.execute("LOAD ducklake")
    con.execute(
        f"ATTACH 'ducklake:{catalog_path}' AS sbom_lake (DATA_PATH '{data_dir}')"
    )
    con.execute("USE sbom_lake")
    try:
        rows = con.execute(sql).fetchall()
    finally:
        con.close()
    return rows

