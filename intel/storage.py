"""
SQLite persistence layer for the threat intelligence engine.

The CSV files remain the source of truth for article text (that's how scrapers
write), but any *derived* intelligence (CVE enrichment, EPSS scores, KEV
membership, graph snapshots, cluster assignments) lives here so we can:

- avoid re-fetching NVD/EPSS/KEV data on every request
- keep a rolling time series for trend detection
- survive process restarts (the old in-memory caches did not)
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_DB_LOCK = threading.Lock()
_DEFAULT_DB_PATH = Path("intel_cache.sqlite3")


def get_db_path() -> Path:
    return _DEFAULT_DB_PATH


SCHEMA_STATEMENTS: list[str] = [
    # CVE enrichment cache.  Every CVE we've seen in our corpus gets an entry
    # here once NVD/EPSS/KEV have been queried.
    """
    CREATE TABLE IF NOT EXISTS cve_enrichment (
        cve_id            TEXT PRIMARY KEY,
        cvss_v3_score     REAL,
        cvss_v3_severity  TEXT,
        cvss_v3_vector    TEXT,
        epss_score        REAL,
        epss_percentile   REAL,
        in_kev            INTEGER NOT NULL DEFAULT 0,
        kev_date_added    TEXT,
        kev_due_date      TEXT,
        nvd_description   TEXT,
        last_fetched_at   TEXT NOT NULL,
        fetch_errors      TEXT
    )
    """,
    # Time series of IOC mention counts per UTC day.  Populated on demand by the
    # trending module; enables EWMA / z-score spike detection.
    """
    CREATE TABLE IF NOT EXISTS ioc_daily_counts (
        ioc_type   TEXT NOT NULL,
        ioc_value  TEXT NOT NULL,
        day_utc    TEXT NOT NULL,
        count      INTEGER NOT NULL,
        PRIMARY KEY (ioc_type, ioc_value, day_utc)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ioc_daily_type_day
    ON ioc_daily_counts(ioc_type, day_utc)
    """,
    # Article fingerprints for MinHash near-dup clustering.  Storing the
    # signature lets us skip recomputation when only a handful of new articles
    # arrive.
    """
    CREATE TABLE IF NOT EXISTS article_fingerprints (
        article_id   TEXT PRIMARY KEY,
        source_key   TEXT NOT NULL,
        url          TEXT,
        title        TEXT,
        published_at TEXT,
        signature    TEXT NOT NULL,
        fingerprinted_at TEXT NOT NULL
    )
    """,
]


def init_db(path: Path | None = None) -> None:
    """Create schema if it does not exist.  Safe to call multiple times."""
    db_path = path or get_db_path()
    with _DB_LOCK:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            for stmt in SCHEMA_STATEMENTS:
                conn.execute(stmt)
            conn.commit()


def persist_ioc_daily_counts(series: dict, path: Path | None = None) -> None:
    """
    Upsert IOC daily counts into the ioc_daily_counts table.

    series: dict[(ioc_type, ioc_value), dict[day_utc, count]]
    """
    if not series:
        return
    rows = []
    for (ioc_type, ioc_value), by_day in series.items():
        for day_utc, count in by_day.items():
            rows.append((ioc_type, ioc_value, day_utc, count))
    if not rows:
        return
    db_path = path or get_db_path()
    init_db(db_path)
    with _DB_LOCK:
        with sqlite3.connect(str(db_path)) as conn:
            conn.executemany(
                """
                INSERT INTO ioc_daily_counts (ioc_type, ioc_value, day_utc, count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ioc_type, ioc_value, day_utc)
                DO UPDATE SET count = excluded.count
                """,
                rows,
            )
            conn.commit()


def get_ioc_daily_counts(
    ioc_type: str | None = None,
    days: int = 7,
    path: Path | None = None,
) -> list[dict]:
    """
    Return daily counts for all IOCs (or a specific type) over the last N days.
    Used to drive sparklines on the executive dashboard.
    """
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    db_path = path or get_db_path()
    init_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if ioc_type:
            rows = conn.execute(
                "SELECT ioc_type, ioc_value, day_utc, count FROM ioc_daily_counts "
                "WHERE ioc_type = ? AND day_utc >= ? ORDER BY day_utc",
                (ioc_type, cutoff),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT ioc_type, ioc_value, day_utc, count FROM ioc_daily_counts "
                "WHERE day_utc >= ? ORDER BY day_utc",
                (cutoff,),
            ).fetchall()
    return [dict(r) for r in rows]


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    """Context manager that yields a configured sqlite3 connection."""
    db_path = path or get_db_path()
    init_db(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
