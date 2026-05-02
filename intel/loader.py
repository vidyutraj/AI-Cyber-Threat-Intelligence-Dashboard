"""
Article loader bridge.

The intel engine is deliberately decoupled from CSV layout.  This module is
the thin adapter that converts the scraper CSVs into the plain article dicts
the intel modules expect.
"""

from __future__ import annotations

import csv
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


def _parse_published_at(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).strip())
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _article_id(url: str, title: str, published_at: str, source: str) -> str:
    base = (url or "").strip() or f"{source}|{published_at}|{title}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


def load_articles_from_sources(
    sources: dict[str, dict],
    hours: int | None = None,
) -> list[dict]:
    """
    Flatten all configured source CSVs into one list of article dicts.
    """
    cutoff: datetime | None = None
    if hours is not None and hours > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    out: list[dict] = []
    for key, cfg in sources.items():
        path: Path = cfg.get("csv_path")
        if not path or not path.exists():
            continue
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pub = row.get("published_at") or ""
                dt = _parse_published_at(pub)
                if cutoff is not None and (dt is None or dt < cutoff):
                    continue
                art = {
                    "id": _article_id(
                        row.get("url") or "",
                        row.get("title") or "",
                        pub,
                        cfg.get("label", key),
                    ),
                    "source_key": key,
                    "source_label": cfg.get("label", key),
                    "url": row.get("url", "") or "",
                    "title": row.get("title", "") or "",
                    "published_at": pub,
                    "description": row.get("description", "") or "",
                    "full_text": row.get("full_text", "") or "",
                    "categories": row.get("categories", "") or "",
                    "cves": row.get("cves", "") or "",
                    "ips": row.get("ips", "") or "",
                    "ipv6": row.get("ipv6", "") or "",
                    "domains": row.get("domains", "") or "",
                    "hashes": row.get("hashes", "") or "",
                    "email": row.get("email", "") or "",
                    "malware_tools": row.get("malware_tools", "") or "",
                    "mitre_techniques": row.get("mitre_techniques", "") or "",
                }
                out.append(art)
    # Newest first
    out.sort(key=lambda x: x.get("published_at") or "", reverse=True)
    return out


def all_cve_ids(articles: Iterable[dict]) -> list[str]:
    ids: set[str] = set()
    for a in articles:
        raw = (a.get("cves") or "").strip()
        if not raw:
            continue
        for tok in (t.strip() for t in raw.split(",")):
            if tok:
                ids.add(tok.upper())
    return sorted(ids)


def source_breadth_by_cve(articles: Iterable[dict]) -> dict[str, int]:
    """How many distinct source labels mention each CVE."""
    by_cve: dict[str, set[str]] = {}
    for a in articles:
        raw = (a.get("cves") or "").strip()
        if not raw:
            continue
        src = a.get("source_label") or ""
        for tok in (t.strip().upper() for t in raw.split(",") if t.strip()):
            by_cve.setdefault(tok, set()).add(src)
    return {k: len(v) for k, v in by_cve.items()}
