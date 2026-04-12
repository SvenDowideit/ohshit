"""Vulnerability database cache — OSV + CISA KEV.

Design
------
- Vulnerability data is cached in a local DuckDB file:
    ~/.cache/ohshit/vuln.duckdb

  This is intentionally separate from ohshit.db (which is per-project) so
  the vuln cache is shared across runs and survives project DB resets.

- Two primary sources:
    OSV (Open Source Vulnerabilities) — Google's multi-ecosystem advisory DB
      https://api.osv.dev/v1/querybatch
      Free, no API key, covers deb/rpm/PyPI/npm/Cargo/Go/etc.

    CISA KEV (Known Exploited Vulnerabilities) — CISA's actively-exploited list
      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      Free, no API key, JSON, updated regularly.

- Matching strategy:
    OSV ecosystem names for what we collect:
      dpkg / deb  → "Debian", "Ubuntu"  (OSV uses distro name, not "deb")
      rpm         → "Red Hat", "openSUSE", "Rocky Linux", "AlmaLinux", "Fedora"
      pip         → "PyPI"
      snap        → not supported by OSV (snap packages are not indexed)
      flatpak     → not supported by OSV
      docker      → not directly; use "PyPI" for base image Python pkgs, etc.

  We query OSV with the package name + version + ecosystem.
  For deb packages we try both "Debian" and "Ubuntu" (OSV has both).
  For rpm we try "Red Hat" primarily (covers RHEL/CentOS/Fedora lineage).

- The vuln cache stores raw advisory data (JSON) keyed by advisory ID.
  A separate package_vulns table maps (ecosystem, name, version) → advisory_id
  for fast lookup.

- Cache freshness: re-fetch if older than max_age_hours (default 24h).
  CISA KEV is re-fetched once a day.  OSV lookups are on-demand per package —
  we batch-query when an SBOM is available.

- Rate limits: OSV has no documented rate limit. We cap batch size at 1000
  packages per request to be polite.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache path
# ---------------------------------------------------------------------------

_CACHE_DIR = Path.home() / ".cache" / "ohshit"
_VULN_DB_PATH = _CACHE_DIR / "vuln.duckdb"

# OSV batch endpoint
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# CISA KEV feed
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# OSV ecosystems to try per SBOM source
_ECOSYSTEMS_FOR_SOURCE: dict[str, list[str]] = {
    "dpkg":    ["Debian", "Ubuntu"],
    "rpm":     ["Red Hat", "openSUSE", "AlmaLinux", "Rocky Linux", "Fedora"],
    "pip":     ["PyPI"],
    "snap":    [],       # OSV does not index snap packages
    "flatpak": [],       # OSV does not index flatpak packages
    "docker":  [],       # container image tags are not indexed by OSV
}

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS advisories (
        id           TEXT PRIMARY KEY,
        source       TEXT NOT NULL,       -- 'osv' or 'kev'
        aliases_json TEXT NOT NULL DEFAULT '[]',
        summary      TEXT NOT NULL DEFAULT '',
        details      TEXT NOT NULL DEFAULT '',
        severity     TEXT NOT NULL DEFAULT '',
        cvss_score   REAL,
        published    TIMESTAMPTZ,
        modified     TIMESTAMPTZ,
        raw_json     TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS package_vulns (
        advisory_id  TEXT NOT NULL,
        ecosystem    TEXT NOT NULL,
        pkg_name     TEXT NOT NULL,
        introduced   TEXT NOT NULL DEFAULT '',
        fixed        TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (advisory_id, ecosystem, pkg_name, introduced)
    )""",
    """CREATE TABLE IF NOT EXISTS fetch_log (
        key         TEXT PRIMARY KEY,     -- 'kev' or 'osv:<ecosystem>'
        fetched_at  TIMESTAMPTZ NOT NULL
    )""",
]


def _open_cache() -> duckdb.DuckDBPyConnection:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(_VULN_DB_PATH))
    for stmt in _SCHEMA:
        con.execute(stmt)
    return con


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

def _fetch_kev(con: duckdb.DuckDBPyConnection, log_cb=None) -> int:
    """Download and cache the CISA Known Exploited Vulnerabilities catalog.
    Returns number of new advisories stored."""
    import urllib.request

    if log_cb:
        log_cb("[dim]Vuln:[/dim] Fetching CISA KEV catalog…")
    try:
        with urllib.request.urlopen(_CISA_KEV_URL, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        if log_cb:
            log_cb(f"[dim red]Vuln:[/dim red] CISA KEV fetch failed: {exc}")
        return 0

    vulns = data.get("vulnerabilities", [])
    added = 0
    for v in vulns:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue
        summary = v.get("shortDescription", "")
        due_date = v.get("dueDate", "")
        pub_date = v.get("dateAdded", "")

        try:
            published = datetime.fromisoformat(pub_date) if pub_date else None
        except ValueError:
            published = None

        try:
            con.execute(
                """INSERT OR REPLACE INTO advisories
                       (id, source, aliases_json, summary, details, severity, published, raw_json)
                   VALUES (?, 'kev', ?, ?, ?, 'Critical', ?, ?)""",
                [
                    cve_id,
                    json.dumps([cve_id]),
                    summary,
                    f"Due date for remediation: {due_date}" if due_date else "",
                    published,
                    json.dumps(v),
                ],
            )
            added += 1
        except Exception:
            pass

    # Record fetch time
    con.execute(
        "INSERT OR REPLACE INTO fetch_log (key, fetched_at) VALUES ('kev', ?)",
        [datetime.now(timezone.utc)],
    )
    if log_cb:
        log_cb(f"[dim]Vuln:[/dim] CISA KEV: {added} known-exploited CVEs cached")
    return added


# ---------------------------------------------------------------------------
# OSV batch querying
# ---------------------------------------------------------------------------

def _osv_queries_for_packages(packages: list[dict]) -> list[dict]:
    """Build OSV query list from SBOM package dicts.

    Each entry: {"package": {"name": ..., "ecosystem": ...}, "version": ...}
    We skip sources with no OSV ecosystem mapping (snap, flatpak, docker).
    """
    queries = []
    seen: set[tuple[str, str, str]] = set()
    for pkg in packages:
        source = pkg.get("source", "")
        ecosystems = _ECOSYSTEMS_FOR_SOURCE.get(source, [])
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if not name or not ecosystems:
            continue
        for eco in ecosystems:
            key = (eco, name, version)
            if key in seen:
                continue
            seen.add(key)
            q: dict[str, Any] = {"package": {"name": name, "ecosystem": eco}}
            if version:
                q["version"] = version
            queries.append(q)
    return queries


def _store_osv_response(con: duckdb.DuckDBPyConnection, pairs: list[tuple[dict, list[dict]]]) -> int:
    """Parse OSV batch (query, vulns) pairs and store advisories + package_vulns rows.

    The querybatch response omits the full 'affected' array, so we derive the
    package→advisory mapping from the query input (ecosystem + name) rather
    than from the response's affected field.
    """
    stored = 0
    for query, vulns in pairs:
        pkg_info = query.get("package", {})
        eco = pkg_info.get("ecosystem", "")
        pkg_name = pkg_info.get("name", "")
        version = query.get("version", "")

        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue

            aliases = vuln.get("aliases", [])
            summary = vuln.get("summary", "")
            details = vuln.get("details", "") or ""
            published_str = vuln.get("published", "")
            modified_str = vuln.get("modified", "")

            # Determine severity / CVSS
            severity = ""
            cvss_score = None
            for sev_entry in vuln.get("severity", []):
                stype = sev_entry.get("type", "")
                if "CVSS" in stype:
                    score_val = sev_entry.get("score")
                    if score_val is not None:
                        try:
                            cvss_score = float(score_val)
                        except (TypeError, ValueError):
                            pass
                    break
            db_spec = vuln.get("database_specific", {})
            if not severity:
                severity = db_spec.get("severity", "")

            try:
                published = datetime.fromisoformat(published_str.rstrip("Z")) if published_str else None
            except ValueError:
                published = None
            try:
                modified = datetime.fromisoformat(modified_str.rstrip("Z")) if modified_str else None
            except ValueError:
                modified = None

            try:
                con.execute(
                    """INSERT OR REPLACE INTO advisories
                           (id, source, aliases_json, summary, details, severity,
                            cvss_score, published, modified, raw_json)
                       VALUES (?, 'osv', ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        vuln_id,
                        json.dumps(aliases),
                        summary[:500],
                        details[:2000],
                        severity,
                        cvss_score,
                        published,
                        modified,
                        json.dumps(vuln),
                    ],
                )
            except Exception:
                pass

            # Store the package→advisory mapping from the query inputs
            if eco and pkg_name:
                try:
                    con.execute(
                        """INSERT OR IGNORE INTO package_vulns
                               (advisory_id, ecosystem, pkg_name, introduced, fixed)
                           VALUES (?, ?, ?, ?, '')""",
                        [vuln_id, eco, pkg_name, version],
                    )
                except Exception:
                    pass

            # Also parse any full 'affected' data if present (e.g. from future
            # enrichment or direct /vulns/{id} lookups)
            for affected in vuln.get("affected", []):
                apkg = affected.get("package", {})
                aeco = apkg.get("ecosystem", "")
                apkg_name = apkg.get("name", "")
                if not aeco or not apkg_name:
                    continue
                for rng in affected.get("ranges", []):
                    introduced = ""
                    fixed = ""
                    for event in rng.get("events", []):
                        if "introduced" in event:
                            introduced = str(event["introduced"])
                        if "fixed" in event:
                            fixed = str(event["fixed"])
                    try:
                        con.execute(
                            """INSERT OR IGNORE INTO package_vulns
                                   (advisory_id, ecosystem, pkg_name, introduced, fixed)
                               VALUES (?, ?, ?, ?, ?)""",
                            [vuln_id, aeco, apkg_name, introduced, fixed],
                        )
                    except Exception:
                        pass
                for ver in affected.get("versions", []):
                    try:
                        con.execute(
                            """INSERT OR IGNORE INTO package_vulns
                                   (advisory_id, ecosystem, pkg_name, introduced, fixed)
                               VALUES (?, ?, ?, ?, 'exact')""",
                            [vuln_id, aeco, apkg_name, ver],
                        )
                    except Exception:
                        pass
            stored += 1
    return stored


async def _fetch_osv_batch(queries: list[dict], log_cb=None) -> list[tuple[dict, list[dict]]]:
    """POST a batch of OSV queries and return list of (query, vulns) tuples."""
    import aiohttp

    _BATCH_SIZE = 1000
    all_pairs: list[tuple[dict, list[dict]]] = []

    for i in range(0, len(queries), _BATCH_SIZE):
        batch = queries[i:i + _BATCH_SIZE]
        payload = json.dumps({"queries": batch}).encode()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _OSV_BATCH_URL,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        results = body.get("results", [])
                        for query, result in zip(batch, results):
                            all_pairs.append((query, result.get("vulns", [])))
                    else:
                        text = await resp.text()
                        if log_cb:
                            log_cb(f"[dim red]Vuln:[/dim red] OSV returned HTTP {resp.status}: {text[:200]}")
        except Exception as exc:
            if log_cb:
                log_cb(f"[dim red]Vuln:[/dim red] OSV batch request failed: {exc}")

    return all_pairs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def refresh_kev(log_cb=None) -> int:
    """Sync the CISA KEV catalog into the local vuln cache. Returns count stored."""
    con = _open_cache()
    try:
        return _fetch_kev(con, log_cb=log_cb)
    finally:
        con.close()


async def query_vulns_for_packages(
    packages: list[dict],
    log_cb=None,
) -> dict[str, list[dict]]:
    """Query OSV for all packages in the SBOM list. Returns
    {advisory_id: advisory_dict} for every advisory that matched at least one
    package.

    Also stores results in the local cache for future offline use.
    Side-effect: writes to vuln.duckdb.
    """
    queries = _osv_queries_for_packages(packages)
    if not queries:
        return {}

    queryable = sum(
        1 for p in packages
        if _ECOSYSTEMS_FOR_SOURCE.get(p.get("source", ""), [])
    )
    if log_cb:
        log_cb(f"[dim]Vuln:[/dim] Querying OSV for {queryable} packages ({len(queries)} ecosystem variants)…")

    pairs = await _fetch_osv_batch(queries, log_cb=log_cb)

    con = _open_cache()
    try:
        stored = _store_osv_response(con, pairs)
    finally:
        con.close()

    if log_cb and stored > 0:
        log_cb(f"[dim]Vuln:[/dim] OSV: {stored} advisories cached")

    # Collate matching advisories from cache
    return match_packages_to_vulns(packages)


def match_packages_to_vulns(packages: list[dict]) -> dict[str, list[dict]]:
    """Look up each package in the local vuln cache.

    Returns {(source, name, version): [advisory_dict, ...]}.
    Purely a local DB read — no network calls.
    """
    if not packages:
        return {}

    con = _open_cache()
    try:
        results: dict[str, list[dict]] = {}
        for pkg in packages:
            source = pkg.get("source", "")
            ecosystems = _ECOSYSTEMS_FOR_SOURCE.get(source, [])
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if not name or not ecosystems:
                continue
            key = f"{source}:{name}:{version}"
            advisories: list[dict] = []
            for eco in ecosystems:
                rows = con.execute(
                    """SELECT DISTINCT a.id, a.source, a.aliases_json, a.summary,
                              a.severity, a.cvss_score, a.published
                       FROM package_vulns pv
                       JOIN advisories a ON a.id = pv.advisory_id
                       WHERE pv.ecosystem = ? AND pv.pkg_name = ?
                       ORDER BY a.published DESC NULLS LAST""",
                    [eco, name],
                ).fetchall()
                for row in rows:
                    adv_id, adv_source, aliases_json, summary, sev, cvss, pub = row
                    advisories.append({
                        "id": adv_id,
                        "source": adv_source,
                        "aliases": json.loads(aliases_json or "[]"),
                        "summary": summary,
                        "severity": sev,
                        "cvss_score": cvss,
                        "published": pub,
                    })
            if advisories:
                # Deduplicate by advisory id
                seen_ids: set[str] = set()
                unique = []
                for a in advisories:
                    if a["id"] not in seen_ids:
                        seen_ids.add(a["id"])
                        unique.append(a)
                results[key] = unique
        return results
    finally:
        con.close()


def vuln_summary(packages: list[dict]) -> dict[str, int]:
    """Return {severity: count} for all vulns matching this package list.
    Uses only the local cache — no network calls.
    """
    matches = match_packages_to_vulns(packages)
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    seen_ids: set[str] = set()
    for advisories in matches.values():
        for adv in advisories:
            if adv["id"] in seen_ids:
                continue
            seen_ids.add(adv["id"])
            sev = (adv.get("severity") or "Unknown").capitalize()
            if sev not in counts:
                sev = "Unknown"
            counts[sev] += 1
    return counts


def kev_ids() -> frozenset[str]:
    """Return the set of CVE IDs currently in the KEV catalog (local cache)."""
    try:
        con = _open_cache()
        try:
            rows = con.execute(
                "SELECT id FROM advisories WHERE source = 'kev'"
            ).fetchall()
            return frozenset(r[0] for r in rows)
        finally:
            con.close()
    except Exception:
        return frozenset()
