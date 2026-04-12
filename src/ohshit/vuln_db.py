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
        id              TEXT PRIMARY KEY,
        source          TEXT NOT NULL,       -- 'osv' or 'kev'
        aliases_json    TEXT NOT NULL DEFAULT '[]',
        summary         TEXT NOT NULL DEFAULT '',
        details         TEXT NOT NULL DEFAULT '',
        severity        TEXT NOT NULL DEFAULT '',
        cvss_score      REAL,
        published       TIMESTAMPTZ,
        modified        TIMESTAMPTZ,
        raw_json        TEXT NOT NULL DEFAULT '{}',
        epss_score      REAL,
        epss_percentile REAL,
        ransomware      TEXT NOT NULL DEFAULT ''
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

# Migrations for existing databases (idempotent ALTERs)
# DuckDB does not support NOT NULL or DEFAULT in ALTER TABLE ADD COLUMN,
# so these are nullable; code must treat NULL the same as empty/zero.
_MIGRATIONS = [
    "ALTER TABLE advisories ADD COLUMN IF NOT EXISTS epss_score REAL",
    "ALTER TABLE advisories ADD COLUMN IF NOT EXISTS epss_percentile REAL",
    "ALTER TABLE advisories ADD COLUMN IF NOT EXISTS ransomware TEXT",
]


def _open_cache() -> duckdb.DuckDBPyConnection:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(_VULN_DB_PATH))
    for stmt in _SCHEMA:
        con.execute(stmt)
    for stmt in _MIGRATIONS:
        try:
            con.execute(stmt)
        except Exception:
            pass  # column already exists
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

        ransomware = v.get("knownRansomwareCampaignUse", "")
        try:
            con.execute(
                """INSERT OR REPLACE INTO advisories
                       (id, source, aliases_json, summary, details, severity, published, raw_json, ransomware)
                   VALUES (?, 'kev', ?, ?, ?, 'Critical', ?, ?, ?)""",
                [
                    cve_id,
                    json.dumps([cve_id]),
                    summary,
                    f"Due date for remediation: {due_date}" if due_date else "",
                    published,
                    json.dumps(v),
                    ransomware,
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
# EPSS (Exploit Prediction Scoring System)
# ---------------------------------------------------------------------------

_EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_BATCH_SIZE = 100  # API accepts comma-separated CVE IDs

# Prefixes used by distro-specific OSV advisories that encode the CVE ID
_OSV_CVE_PREFIXES = (
    "DEBIAN-", "UBUNTU-CVE-", "RHSA-", "SUSE-CVE-", "ALAS-",
)


def _extract_cve_id(advisory_id: str) -> str | None:
    """Return the canonical CVE-XXXX-XXXXX form from an advisory ID, or None."""
    uid = advisory_id.upper()
    if uid.startswith("CVE-"):
        return advisory_id
    # DEBIAN-CVE-2022-1234 → CVE-2022-1234
    if uid.startswith("DEBIAN-CVE-"):
        return advisory_id[len("DEBIAN-"):]
    # UBUNTU-CVE-2022-1234 → CVE-2022-1234
    if uid.startswith("UBUNTU-CVE-"):
        return advisory_id[len("UBUNTU-"):]
    # SUSE-CVE-2022-1234-1 → CVE-2022-1234  (strip trailing -1)
    if uid.startswith("SUSE-CVE-"):
        candidate = advisory_id[len("SUSE-"):]
        # Remove trailing patch number if present
        parts = candidate.split("-")
        if len(parts) > 3 and parts[-1].isdigit():
            candidate = "-".join(parts[:-1])
        return candidate
    return None


async def fetch_epss(
    advisory_ids: list[str],
    log_cb=None,
) -> None:
    """Fetch EPSS scores from api.first.org and update the advisories table.

    Accepts any mix of advisory IDs (CVE-*, DEBIAN-CVE-*, GHSA-*, etc.).
    Derives canonical CVE IDs where possible, queries EPSS, then writes
    scores back to both the original advisory row and any alias matches.
    """
    import aiohttp

    # Build mapping: canonical_cve → set of original advisory IDs that map to it
    cve_to_adv: dict[str, set[str]] = {}
    for adv_id in advisory_ids:
        cve = _extract_cve_id(adv_id)
        if cve:
            cve_to_adv.setdefault(cve, set()).add(adv_id)
        # Also check if any alias is a CVE (passed through from match_packages_to_vulns)
        # — callers should pass aliases separately if needed

    cve_format = list(cve_to_adv.keys())
    if not cve_format:
        return

    if log_cb:
        log_cb(f"[dim]Vuln:[/dim] Fetching EPSS scores for {len(cve_format)} CVEs…")

    scores: dict[str, tuple[float, float]] = {}  # cve_id → (epss, percentile)

    try:
        async with aiohttp.ClientSession() as session:
            for i in range(0, len(cve_format), _EPSS_BATCH_SIZE):
                batch = cve_format[i:i + _EPSS_BATCH_SIZE]
                params = {"cve": ",".join(batch)}
                try:
                    async with session.get(
                        _EPSS_URL,
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.json()
                            for entry in body.get("data", []):
                                cve = entry.get("cve", "")
                                try:
                                    epss = float(entry.get("epss", 0))
                                    pct = float(entry.get("percentile", 0))
                                    scores[cve] = (epss, pct)
                                except (TypeError, ValueError):
                                    pass
                        else:
                            text = await resp.text()
                            if log_cb:
                                log_cb(f"[dim red]Vuln:[/dim red] EPSS returned HTTP {resp.status}: {text[:200]}")
                except Exception as exc:
                    if log_cb:
                        log_cb(f"[dim red]Vuln:[/dim red] EPSS batch request failed: {exc}")
    except Exception as exc:
        if log_cb:
            log_cb(f"[dim red]Vuln:[/dim red] EPSS session error: {exc}")
        return

    if not scores:
        return

    # Write scores to DB: match by original advisory ID, by CVE ID, and by alias
    con = _open_cache()
    try:
        for cve_id, (epss, pct) in scores.items():
            # Update rows whose id IS the CVE, or whose aliases contain it,
            # or whose id can be derived to this CVE (e.g. DEBIAN-CVE-*)
            original_adv_ids = cve_to_adv.get(cve_id, set())
            ids_to_update = original_adv_ids | {cve_id}
            for adv_id in ids_to_update:
                try:
                    con.execute(
                        "UPDATE advisories SET epss_score = ?, epss_percentile = ? WHERE id = ?",
                        [epss, pct, adv_id],
                    )
                except Exception:
                    pass
            # Also catch any rows that have this CVE in their aliases_json
            try:
                con.execute(
                    """UPDATE advisories SET epss_score = ?, epss_percentile = ?
                       WHERE epss_score IS NULL AND aliases_json LIKE ?""",
                    [epss, pct, f'%"{cve_id}"%'],
                )
            except Exception:
                pass
    finally:
        con.close()

    if log_cb:
        log_cb(f"[dim]Vuln:[/dim] EPSS: scores updated for {len(scores)} CVEs")

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

    # Fetch EPSS scores for all matched advisories
    matched = match_packages_to_vulns(packages)
    all_adv_ids: list[str] = []
    seen_ids: set[str] = set()
    for advisories in matched.values():
        for adv in advisories:
            adv_id = adv.get("id", "")
            if adv_id and adv_id not in seen_ids:
                seen_ids.add(adv_id)
                all_adv_ids.append(adv_id)
            for alias in adv.get("aliases", []):
                if alias and alias not in seen_ids:
                    seen_ids.add(alias)
                    all_adv_ids.append(alias)
    if all_adv_ids:
        await fetch_epss(all_adv_ids, log_cb=log_cb)

    # Re-read to pick up EPSS scores
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
        # Pre-load KEV index: id → ransomware, plus aliases → ransomware
        kev_by_cve: dict[str, str] = {}
        for row in con.execute(
            "SELECT id, aliases_json, ransomware FROM advisories WHERE source='kev'"
        ).fetchall():
            kev_id, aliases_json, ransomware = row
            kev_by_cve[kev_id] = ransomware or ""
            for alias in json.loads(aliases_json or "[]"):
                kev_by_cve[alias] = ransomware or ""

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
                              a.severity, a.cvss_score, a.published,
                              a.epss_score, a.epss_percentile, a.ransomware
                       FROM package_vulns pv
                       JOIN advisories a ON a.id = pv.advisory_id
                       WHERE pv.ecosystem = ? AND pv.pkg_name = ?
                       ORDER BY a.published DESC NULLS LAST""",
                    [eco, name],
                ).fetchall()
                for row in rows:
                    adv_id, adv_source, aliases_json, summary, sev, cvss, pub, epss, epss_pct, ransomware = row
                    aliases = json.loads(aliases_json or "[]")

                    # Cross-reference KEV: check the advisory ID, its aliases, and
                    # any CVE derived from a distro-prefixed ID (DEBIAN-CVE-*, etc.)
                    in_kev = adv_id in kev_by_cve or any(a in kev_by_cve for a in aliases)
                    if not in_kev:
                        derived_cve = _extract_cve_id(adv_id)
                        if derived_cve and derived_cve in kev_by_cve:
                            in_kev = True

                    # Determine effective ransomware status from KEV cross-ref
                    effective_ransomware = ransomware or ""
                    if not effective_ransomware:
                        for check_id in [adv_id] + aliases + ([_extract_cve_id(adv_id)] if _extract_cve_id(adv_id) else []):
                            if check_id and check_id in kev_by_cve:
                                effective_ransomware = kev_by_cve[check_id]
                                break

                    # For distro-prefixed OSV IDs with no severity, try to derive from KEV
                    effective_sev = sev
                    if not effective_sev and in_kev:
                        effective_sev = "Critical"

                    advisories.append({
                        "id": adv_id,
                        "source": "kev" if in_kev else adv_source,
                        "aliases": aliases,
                        "summary": summary,
                        "severity": effective_sev,
                        "cvss_score": cvss,
                        "published": pub,
                        "epss_score": epss,
                        "epss_percentile": epss_pct,
                        "ransomware": effective_ransomware,
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
