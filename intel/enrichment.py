"""
CVE enrichment engine.

For every CVE id found in our corpus, we pull three complementary signals:

1. CVSS v3 base score from NVD               -> intrinsic severity
2. EPSS exploit probability from FIRST       -> likelihood of exploitation
3. CISA KEV catalog membership               -> confirmed active exploitation

These three together are the SOC gold standard for vulnerability
prioritization.  None of them are available from RSS feeds alone, which is
exactly why this step is where the dashboard actually becomes *intelligence*
instead of aggregation.

All three APIs are free and do not require auth keys.  We cache results in
SQLite and honour a per-CVE freshness window so we don't hammer the upstream
services.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests

from .storage import connect


LOG = logging.getLogger("intel.enrichment")

# --- endpoints ---------------------------------------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# --- tuning ------------------------------------------------------------------
# NVD rate limits to ~5 req / 30 s without API key; we throttle defensively.
_NVD_SLEEP_BETWEEN_REQUESTS = 6.5
_DEFAULT_CACHE_TTL_DAYS = 7

# EPSS lets us batch CVEs with a comma-separated list; we use a conservative
# chunk size to keep URLs under common proxy limits.
_EPSS_CHUNK = 50

# In-process KEV cache so we don't fetch the (large) JSON file per CVE.
_KEV_CACHE: dict[str, dict] = {}
_KEV_LOADED_AT: float | None = None
_KEV_TTL_SECONDS = 60 * 60 * 6  # refresh KEV list up to 4x per day


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------


@dataclass
class CveEnrichment:
    cve_id: str
    cvss_v3_score: float | None
    cvss_v3_severity: str | None
    cvss_v3_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    in_kev: bool
    kev_date_added: str | None
    kev_due_date: str | None
    nvd_description: str | None
    last_fetched_at: str
    fetch_errors: list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["in_kev"] = bool(self.in_kev)
        return d


# ---------------------------------------------------------------------------
# KEV catalog loader
# ---------------------------------------------------------------------------


def _load_kev_catalog(force: bool = False) -> dict[str, dict]:
    """Download and cache the CISA Known Exploited Vulnerabilities catalog."""
    global _KEV_CACHE, _KEV_LOADED_AT
    now = time.time()
    if (
        not force
        and _KEV_CACHE
        and _KEV_LOADED_AT is not None
        and (now - _KEV_LOADED_AT) < _KEV_TTL_SECONDS
    ):
        return _KEV_CACHE

    try:
        resp = requests.get(KEV_URL, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        _KEV_CACHE = {
            (v.get("cveID") or "").upper(): v for v in vulns if v.get("cveID")
        }
        _KEV_LOADED_AT = now
        LOG.info("Loaded KEV catalog with %d entries", len(_KEV_CACHE))
    except Exception as exc:
        LOG.warning("KEV catalog fetch failed: %s", exc)
    return _KEV_CACHE


# ---------------------------------------------------------------------------
# NVD + EPSS helpers
# ---------------------------------------------------------------------------


def _fetch_cvss_from_nvd(cve_id: str) -> tuple[dict, str | None]:
    """Return (parsed_dict, error_or_none) for the given CVE."""
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=20)
        if resp.status_code == 404:
            return ({}, "nvd:not_found")
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return ({}, f"nvd:{exc}")

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return ({}, "nvd:empty")
    cve = (vulns[0] or {}).get("cve") or {}
    metrics = cve.get("metrics") or {}

    # prefer v3.1 then v3.0
    v3_blocks = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    v3_data = (v3_blocks[0] or {}).get("cvssData") or {} if v3_blocks else {}

    desc_items = cve.get("descriptions") or []
    description = ""
    for d in desc_items:
        if (d.get("lang") or "").lower() == "en":
            description = (d.get("value") or "").strip()
            break

    return (
        {
            "score": v3_data.get("baseScore"),
            "severity": v3_data.get("baseSeverity"),
            "vector": v3_data.get("vectorString"),
            "description": description,
        },
        None,
    )


def _fetch_epss_batch(cve_ids: list[str]) -> tuple[dict[str, dict], str | None]:
    if not cve_ids:
        return ({}, None)
    try:
        resp = requests.get(
            EPSS_API,
            params={"cve": ",".join(cve_ids)},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return ({}, f"epss:{exc}")

    out: dict[str, dict] = {}
    for item in data.get("data") or []:
        cve = (item.get("cve") or "").upper()
        if not cve:
            continue
        try:
            out[cve] = {
                "score": float(item.get("epss") or 0.0),
                "percentile": float(item.get("percentile") or 0.0),
            }
        except Exception:
            continue
    return (out, None)


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def _is_fresh(row: dict, ttl_days: int) -> bool:
    last = row.get("last_fetched_at") or ""
    if not last:
        return False
    try:
        dt = datetime.fromisoformat(last)
    except Exception:
        return False
    return datetime.now(timezone.utc) - dt < timedelta(days=ttl_days)


def get_cached_cve_enrichment(cve_id: str) -> CveEnrichment | None:
    cve_id = cve_id.strip().upper()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM cve_enrichment WHERE cve_id = ?", (cve_id,)
        ).fetchone()
    if not row:
        return None
    errors: list[str] = []
    try:
        errors = json.loads(row["fetch_errors"] or "[]")
    except Exception:
        errors = []
    return CveEnrichment(
        cve_id=row["cve_id"],
        cvss_v3_score=row["cvss_v3_score"],
        cvss_v3_severity=row["cvss_v3_severity"],
        cvss_v3_vector=row["cvss_v3_vector"],
        epss_score=row["epss_score"],
        epss_percentile=row["epss_percentile"],
        in_kev=bool(row["in_kev"]),
        kev_date_added=row["kev_date_added"],
        kev_due_date=row["kev_due_date"],
        nvd_description=row["nvd_description"],
        last_fetched_at=row["last_fetched_at"],
        fetch_errors=errors,
    )


def _store(enr: CveEnrichment) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO cve_enrichment (
                cve_id, cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                epss_score, epss_percentile,
                in_kev, kev_date_added, kev_due_date,
                nvd_description, last_fetched_at, fetch_errors
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss_v3_score=excluded.cvss_v3_score,
                cvss_v3_severity=excluded.cvss_v3_severity,
                cvss_v3_vector=excluded.cvss_v3_vector,
                epss_score=excluded.epss_score,
                epss_percentile=excluded.epss_percentile,
                in_kev=excluded.in_kev,
                kev_date_added=excluded.kev_date_added,
                kev_due_date=excluded.kev_due_date,
                nvd_description=excluded.nvd_description,
                last_fetched_at=excluded.last_fetched_at,
                fetch_errors=excluded.fetch_errors
            """,
            (
                enr.cve_id,
                enr.cvss_v3_score,
                enr.cvss_v3_severity,
                enr.cvss_v3_vector,
                enr.epss_score,
                enr.epss_percentile,
                1 if enr.in_kev else 0,
                enr.kev_date_added,
                enr.kev_due_date,
                enr.nvd_description,
                enr.last_fetched_at,
                json.dumps(enr.fetch_errors or []),
            ),
        )


def enrich_cves(
    cve_ids: Iterable[str],
    ttl_days: int = _DEFAULT_CACHE_TTL_DAYS,
    max_new_fetches: int = 25,
) -> dict[str, CveEnrichment]:
    """
    Return a {cve_id -> CveEnrichment} map.  Reuses cached entries that are
    within TTL; only the first `max_new_fetches` misses are fetched from NVD to
    keep request latency bounded for interactive endpoints.  Missing ones are
    still returned with partial (EPSS/KEV-only) data so the UI isn't empty.
    """
    ids = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    if not ids:
        return {}

    out: dict[str, CveEnrichment] = {}
    stale: list[str] = []
    for cve in ids:
        cached = get_cached_cve_enrichment(cve)
        if cached and _is_fresh(cached.to_dict(), ttl_days):
            out[cve] = cached
        else:
            stale.append(cve)

    if not stale:
        return out

    kev_map = _load_kev_catalog()

    # EPSS is cheap and batched: fetch for all stale ids at once.
    epss_all: dict[str, dict] = {}
    epss_errors: list[str] = []
    for i in range(0, len(stale), _EPSS_CHUNK):
        batch_map, err = _fetch_epss_batch(stale[i : i + _EPSS_CHUNK])
        epss_all.update(batch_map)
        if err:
            epss_errors.append(err)

    # NVD is per-CVE and rate-limited; enforce a hard cap per call.
    nvd_targets = stale[:max_new_fetches]
    nvd_results: dict[str, dict] = {}
    nvd_errors: dict[str, str] = {}
    for idx, cve in enumerate(nvd_targets):
        if idx > 0:
            time.sleep(_NVD_SLEEP_BETWEEN_REQUESTS)
        data, err = _fetch_cvss_from_nvd(cve)
        nvd_results[cve] = data
        if err:
            nvd_errors[cve] = err

    now_iso = datetime.now(timezone.utc).isoformat()

    for cve in stale:
        kev_entry = kev_map.get(cve)
        nvd_data = nvd_results.get(cve) or {}
        epss_entry = epss_all.get(cve) or {}

        errors: list[str] = []
        if cve in nvd_errors:
            errors.append(nvd_errors[cve])
        if cve not in nvd_results:
            # wasn't attempted this pass; partial enrichment only
            errors.append("nvd:deferred")
        errors.extend(epss_errors)

        enr = CveEnrichment(
            cve_id=cve,
            cvss_v3_score=nvd_data.get("score"),
            cvss_v3_severity=nvd_data.get("severity"),
            cvss_v3_vector=nvd_data.get("vector"),
            epss_score=epss_entry.get("score"),
            epss_percentile=epss_entry.get("percentile"),
            in_kev=bool(kev_entry),
            kev_date_added=(kev_entry or {}).get("dateAdded"),
            kev_due_date=(kev_entry or {}).get("dueDate"),
            nvd_description=nvd_data.get("description"),
            last_fetched_at=now_iso,
            fetch_errors=errors,
        )
        _store(enr)
        out[cve] = enr

    return out
