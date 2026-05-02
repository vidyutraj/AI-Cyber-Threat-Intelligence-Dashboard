from pathlib import Path
from typing import Any, Dict, List

from datetime import datetime, timezone, timedelta
import os
import queue
import re
import json
import threading
import time
import hashlib

import csv
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS

from thn_rss_scraper import DEFAULT_FEED_URL, main as run_rss_scraper
from malwarebazaar_client import fetch_recent_malware_samples

from bleepingcomputer_scraper import scrape_bleepingcomputer
from darkreading_scraper import main as run_darkreading_scraper

from intel.api import create_intel_blueprint
from intel.storage import init_db as init_intel_db

# Supported RSS sources and their configuration
SOURCE_CONFIG: Dict[str, Dict[str, Any]] = {
    "thn": {
        "label": "The Hacker News",
        "feed_url": DEFAULT_FEED_URL,
        "csv_path": Path("thehackernews_rss_articles.csv"),
        "scraper": "rss",
    },
    "darkreading": {
        "label": "Dark Reading",
        "feed_url": "https://www.darkreading.com/vulnerabilities-threats",
        "csv_path": Path("darkreading_rss_articles.csv"),
        "scraper": "darkreading",
    },
    "krebs": {
        "label": "Krebs on Security",
        "feed_url": "https://krebsonsecurity.com/feed/",
        "csv_path": Path("krebs_rss_articles.csv"),
        "scraper": "rss",
    },
    "bleepingcomputer": {
        "label": "BleepingComputer",
        "feed_url": "https://www.bleepingcomputer.com/feed/",
        "csv_path": Path("bleepingcomputer_rss_articles.csv"),
        "scraper": "html",
    },
    "cisa": {
        "label": "CISA Advisories",
        "feed_url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "csv_path": Path("cisa_rss_articles.csv"),
        "scraper": "rss",
    },
}

DEFAULT_SOURCE = "thn"

# Track whether we've already warmed article CSVs this process
ARTICLE_WARMED: Dict[str, bool] = {key: False for key in SOURCE_CONFIG.keys()}

# CSV path for cached MalwareBazaar samples
MALWARE_CSV_PATH = Path("malwarebazaar_samples.csv")

# ── Background scraper ────────────────────────────────────────────────────────
# Decouples scraping latency from request handling.  Every source is refreshed
# on a background thread so `/articles` always returns immediately from CSV.

_SCRAPE_INTERVAL = int(os.getenv("SCRAPE_INTERVAL_SECONDS", "900"))  # 15 min

class _ScraperStatus:
    def __init__(self):
        self.last_scraped_at: float | None = None
        self.last_error: str | None = None
        self.running: bool = False
        self.article_count: int = 0

_scraper_status: Dict[str, _ScraperStatus] = {k: _ScraperStatus() for k in SOURCE_CONFIG}
_scraper_lock: Dict[str, threading.Lock] = {k: threading.Lock() for k in SOURCE_CONFIG}


def _run_scraper_for_source(source: str) -> None:
    """Run the appropriate scraper for a source, update status, notify SSE."""
    cfg = SOURCE_CONFIG[source]
    st = _scraper_status[source]
    if not _scraper_lock[source].acquire(blocking=False):
        return  # already running
    try:
        st.running = True
        st.last_error = None
        if cfg.get("scraper") == "darkreading":
            run_darkreading_scraper(
                ["--feed-url", cfg["feed_url"], "--output", str(cfg["csv_path"])]
            )
        elif cfg.get("scraper") == "html":
            scrape_bleepingcomputer(max_articles=50, output_path=str(cfg["csv_path"]))
        else:
            run_rss_scraper(
                ["--feed-url", cfg["feed_url"], "--output", str(cfg["csv_path"])]
            )
        ARTICLE_WARMED[source] = True
        st.last_scraped_at = time.time()
        # Count rows for freshness display
        csv_path: Path = cfg["csv_path"]
        if csv_path.exists():
            with csv_path.open("r", newline="", encoding="utf-8") as f:
                st.article_count = sum(1 for _ in csv.reader(f)) - 1  # minus header
        _sse_publish(source)
    except Exception as e:
        st.last_error = str(e)
    finally:
        st.running = False
        _scraper_lock[source].release()


def _background_scrape_loop(source: str) -> None:
    """Daemon loop: scrape immediately, then every SCRAPE_INTERVAL seconds."""
    _run_scraper_for_source(source)
    while True:
        time.sleep(_SCRAPE_INTERVAL)
        _run_scraper_for_source(source)


def _start_background_scrapers() -> None:
    for source in SOURCE_CONFIG:
        t = threading.Thread(
            target=_background_scrape_loop, args=(source,), daemon=True, name=f"scraper-{source}"
        )
        t.start()


# ── Server-Sent Events ────────────────────────────────────────────────────────

_sse_queues: Dict[str, List[queue.Queue]] = {k: [] for k in SOURCE_CONFIG}
_sse_lock = threading.Lock()


def _sse_publish(source: str) -> None:
    """Push an 'update' event to all listeners for a source."""
    with _sse_lock:
        for q in list(_sse_queues.get(source, [])):
            try:
                q.put_nowait("update")
            except queue.Full:
                pass


# ── Executive brief history (ARIA memory) ────────────────────────────────────

BRIEF_HISTORY: List[Dict[str, Any]] = []  # last 3 generated briefs
_BRIEF_HISTORY_MAX = 3


def _add_brief_to_history(brief: Dict[str, Any], meta: Dict[str, Any]) -> None:
    record = {
        "generated_at": meta.get("generated_at_utc"),
        "window_hours": meta.get("sources_analyzed"),
        "risk_level": brief.get("risk_level"),
        "urgency": brief.get("urgency"),
        "whats_happening": brief.get("whats_happening_today", ""),
        "dominant_themes": [t.get("theme") for t in (brief.get("dominant_themes") or [])],
        "top_risk": (brief.get("top_risks") or [{}])[0].get("threat", ""),
    }
    BRIEF_HISTORY.append(record)
    if len(BRIEF_HISTORY) > _BRIEF_HISTORY_MAX:
        BRIEF_HISTORY.pop(0)


app = Flask(__name__)
CORS(app)

# Initialise the intel SQLite cache and register the intel blueprint so the
# frontend can reach /api/intel/* endpoints for enrichment, graph, trends,
# and near-duplicate clustering.
init_intel_db()
app.register_blueprint(create_intel_blueprint(SOURCE_CONFIG))
_start_background_scrapers()


def load_csv(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Sort latest first by published_at (string ISO order works well enough)
    rows.sort(key=lambda r: r.get("published_at") or "", reverse=True)
    return rows


def load_malware_csv(path: Path, limit: int) -> List[Dict[str, Any]]:
    """
    Load cached MalwareBazaar samples from CSV, newest first.
    """
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Normalize types and convert tags back to a list
    norm_rows: List[Dict[str, Any]] = []
    for r in rows:
        tags_raw = r.get("tags", "") or ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        norm_rows.append(
            {
                "sha256_hash": r.get("sha256_hash", "") or "",
                "sha1_hash": r.get("sha1_hash", "") or "",
                "md5_hash": r.get("md5_hash", "") or "",
                "file_type": r.get("file_type", "") or "",
                "signature": r.get("signature", "") or "",
                "tags": tags,
                "first_seen": r.get("first_seen", "") or "",
                "reporter": r.get("reporter", "") or "",
                "file_name": r.get("file_name", "") or "",
                "file_size": r.get("file_size", "") or "",
            }
        )

    # Sort newest first by first_seen and enforce limit
    norm_rows.sort(key=lambda r: r.get("first_seen") or "", reverse=True)
    return norm_rows[:limit]


def write_malware_csv(path: Path, samples: List[Dict[str, Any]]) -> None:
    """
    Write MalwareBazaar samples to CSV for caching.
    Overwrites the existing file with the latest snapshot.
    """
    if not samples:
        # If there is nothing to write, don't touch the existing cache.
        return

    fieldnames = [
        "sha256_hash",
        "sha1_hash",
        "md5_hash",
        "file_type",
        "signature",
        "tags",
        "first_seen",
        "reporter",
        "file_name",
        "file_size",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in samples:
            tags = s.get("tags") or []
            if isinstance(tags, list):
                tags_str = ",".join(str(t).strip() for t in tags if str(t).strip())
            else:
                tags_str = str(tags)
            writer.writerow(
                {
                    "sha256_hash": s.get("sha256_hash", "") or "",
                    "sha1_hash": s.get("sha1_hash", "") or "",
                    "md5_hash": s.get("md5_hash", "") or "",
                    "file_type": s.get("file_type", "") or "",
                    "signature": s.get("signature", "") or "",
                    "tags": tags_str,
                    "first_seen": s.get("first_seen", "") or "",
                    "reporter": s.get("reporter", "") or "",
                    "file_name": s.get("file_name", "") or "",
                    "file_size": s.get("file_size", "") or "",
                }
            )


def iter_article_rows() -> List[Dict[str, Any]]:
    """
    Yield (source_key, label, row_dict) for every article in all known CSVs.
    """
    rows: List[Dict[str, Any]] = []
    for key, cfg in SOURCE_CONFIG.items():
        path: Path = cfg["csv_path"]
        if not path.exists():
            continue
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(
                    {
                        "source_key": key,
                        "source_label": cfg["label"],
                        "row": row,
                    }
                )
    return rows


def ensure_articles_warmed(source: str) -> None:
    """
    On first request for a given source after the server starts, run the
    RSS scraper once so the CSV is refreshed with the latest articles.
    Subsequent requests just read from the CSV until the user explicitly
    hits the /refresh endpoint.
    """
    if source not in SOURCE_CONFIG:
        return
    if ARTICLE_WARMED.get(source):
        return

    cfg = SOURCE_CONFIG[source]
    try:
        if cfg.get("scraper") == "darkreading":
            run_darkreading_scraper(
                ["--feed-url", cfg["feed_url"], "--output", str(cfg["csv_path"])]
            )
        elif cfg.get("scraper") == "html":
            scrape_bleepingcomputer(max_articles=50, output_path=str(cfg["csv_path"]))
        else:
            run_rss_scraper(
                ["--feed-url", cfg["feed_url"], "--output", str(cfg["csv_path"])]
            )
        ARTICLE_WARMED[source] = True
    except Exception:
        ARTICLE_WARMED[source] = False


@app.get("/api/feed/stream")
def feed_stream():
    """
    Server-Sent Events endpoint.  Clients subscribe per source and receive an
    'update' event whenever that source's CSV has been refreshed by the
    background scraper.  Keepalive comments are sent every 25 s so proxies
    don't time out the connection.
    """
    source = request.args.get("source", DEFAULT_SOURCE)
    if source not in SOURCE_CONFIG:
        source = DEFAULT_SOURCE

    client_q: queue.Queue = queue.Queue(maxsize=5)
    with _sse_lock:
        _sse_queues[source].append(client_q)

    def generate():
        yield "data: {\"event\": \"connected\"}\n\n"
        try:
            while True:
                try:
                    client_q.get(timeout=25)
                    yield f"data: {{\"event\": \"update\", \"source\": \"{source}\"}}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with _sse_lock:
                qs = _sse_queues.get(source, [])
                if client_q in qs:
                    qs.remove(client_q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/feed/sources")
def feed_sources():
    """Return freshness metadata for all configured sources."""
    result = {}
    for key, cfg in SOURCE_CONFIG.items():
        st = _scraper_status[key]
        csv_path: Path = cfg["csv_path"]
        # Find the most recent article published_at in the CSV
        latest_pub: str | None = None
        count = 0
        if csv_path.exists():
            with csv_path.open("r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    count += 1
                    pub = row.get("published_at") or ""
                    if pub and (latest_pub is None or pub > latest_pub):
                        latest_pub = pub
        result[key] = {
            "label": cfg["label"],
            "article_count": count,
            "latest_article_published_at": latest_pub,
            "last_scraped_at": st.last_scraped_at,
            "scraper_running": st.running,
            "last_error": st.last_error,
        }
    return jsonify(result)


@app.get("/articles")
def get_articles():
    """
    Return the current RSS-based articles from CSV (no refresh).

    Optional query parameter:
      - source: 'thn' (The Hacker News) or 'darkreading'
    """
    source = request.args.get("source", DEFAULT_SOURCE)
    if source not in SOURCE_CONFIG:
        source = DEFAULT_SOURCE

    cfg = SOURCE_CONFIG[source]
    articles = load_csv(cfg["csv_path"])
    return jsonify({"source": source, "articles": articles})


@app.post("/refresh")
def refresh_articles():
    """
    Re-run the RSS scraper to fetch the latest articles, then return them.
    This is triggered explicitly from the frontend (no auto-refresh loops).

    Optional query parameter:
      - source: 'thn' (The Hacker News) or 'darkreading'
    """
    source = request.args.get("source", DEFAULT_SOURCE)
    if source not in SOURCE_CONFIG:
        source = DEFAULT_SOURCE

    # Run the scrape in a background thread and return immediately with
    # current cached data — the SSE stream will notify the client when done.
    threading.Thread(
        target=_run_scraper_for_source, args=(source,), daemon=True
    ).start()

    cfg = SOURCE_CONFIG[source]
    articles = load_csv(cfg["csv_path"])
    return jsonify({"source": source, "articles": articles, "refreshing": True})


@app.get("/api/malware/recent")
def get_recent_malware_samples():
    """
    Return cached MalwareBazaar samples from CSV (no external API call).

    Optional query parameter:
      - limit: int (default 50, max 200)
    """
    try:
        limit_raw = request.args.get("limit", "50")
        limit = int(limit_raw)
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))

    # Load whatever is in the local cache first.
    samples = load_malware_csv(MALWARE_CSV_PATH, limit=limit)

    # If the cache is empty, missing, or only contains older data (not today),
    # automatically refresh once so the first visit of the day shows current
    # MalwareBazaar samples without requiring a manual refresh.
    today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def needs_refresh(current: List[Dict[str, Any]]) -> bool:
        if not current:
            return True
        first_seen = (current[0].get("first_seen") or "").strip()
        if not first_seen:
            return True
        date_part = first_seen.split(" ")[0]
        return date_part != today_utc

    if needs_refresh(samples):
        try:
            fresh = fetch_recent_malware_samples(limit=limit)
            if fresh:
                write_malware_csv(MALWARE_CSV_PATH, fresh)
                samples = fresh
        except Exception:
            # If the external API fails, just fall back to whatever we had.
            pass

    return jsonify({"samples": samples})


@app.get("/api/iocs/export")
def export_iocs_csv() -> Response:
    """
    Export all indicators of compromise (IOCs) from all RSS feeds and MalwareBazaar
    as a unified CSV for downstream tools (e.g., SIEM ingestion).

    Columns:
      - type: cve | ip | domain | email | hash | malware
      - value: the IOC string
      - source: logical source key (e.g. thn, darkreading, krebs, bleepingcomputer, malwarebazaar)
      - source_label: human readable source name
      - first_seen: publication or first_seen timestamp (string)
      - context: short context (article title or malware family)
      - article_url: URL to the article (if applicable)
      - article_title: title of the article (if applicable)
    """
    rows_out: List[Dict[str, str]] = []

    # Article-based IOCs from RSS / HTML feeds
    for item in iter_article_rows():
        source_key = item["source_key"]
        source_label = item["source_label"]
        row = item["row"]
        url = row.get("url", "") or ""
        title = row.get("title", "") or ""
        published_at = row.get("published_at", "") or ""

        def add_iocs(field_name: str, ioc_type: str) -> None:
            raw = row.get(field_name, "") or ""
            for token in (s.strip() for s in raw.split(",") if s.strip()):
                rows_out.append(
                    {
                        "type": ioc_type,
                        "value": token,
                        "source": source_key,
                        "source_label": source_label,
                        "first_seen": published_at,
                        "context": title,
                        "article_url": url,
                        "article_title": title,
                    }
                )

        add_iocs("cves", "cve")
        add_iocs("ips", "ip")
        add_iocs("ipv6", "ip")
        add_iocs("domains", "domain")
        add_iocs("email", "email")
        add_iocs("hashes", "hash")
        add_iocs("malware_tools", "malware")

    # MalwareBazaar samples as hash/malware indicators
    samples = load_malware_csv(MALWARE_CSV_PATH, limit=200)
    for s in samples:
        sha256 = s.get("sha256_hash", "") or ""
        first_seen = s.get("first_seen", "") or ""
        signature = s.get("signature", "") or ""
        tags = ", ".join(s.get("tags", []) or [])

        if sha256:
            rows_out.append(
                {
                    "type": "hash",
                    "value": sha256,
                    "source": "malwarebazaar",
                    "source_label": "MalwareBazaar",
                    "first_seen": first_seen,
                    "context": signature or tags,
                    "article_url": "",
                    "article_title": "",
                }
            )

        if signature:
            rows_out.append(
                {
                    "type": "malware",
                    "value": signature,
                    "source": "malwarebazaar",
                    "source_label": "MalwareBazaar",
                    "first_seen": first_seen,
                    "context": tags,
                    "article_url": "",
                    "article_title": "",
                }
            )

    # Build CSV response
    fieldnames = [
        "type",
        "value",
        "source",
        "source_label",
        "first_seen",
        "context",
        "article_url",
        "article_title",
    ]

    from io import StringIO

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows_out:
        writer.writerow(r)

    csv_data = buf.getvalue()
    buf.close()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="iocs_{today}.csv"'
        },
    )


@app.get("/api/iocs/related")
def get_related_iocs():
    """
    Given one or more IOC values, return related articles and malware samples that reference
    any of them.

    Query parameters:
      - values: comma-separated list of IOCs to search for (preferred)
      - value: single IOC string (legacy / convenience)
    """
    raw = (request.args.get("values") or request.args.get("value") or "").strip()
    values = [v.strip() for v in raw.split(",") if v.strip()]
    if not values:
        return (
            jsonify(
                {
                    "error": "Missing 'values' or 'value' query parameter",
                    "articles": [],
                    "malware_samples": [],
                }
            ),
            400,
        )

    value_set = {v.lower() for v in values}

    related_articles: List[Dict[str, Any]] = []
    for item in iter_article_rows():
        source_key = item["source_key"]
        source_label = item["source_label"]
        row = item["row"]

        def field_has_any(field_name: str) -> bool:
            raw = row.get(field_name, "") or ""
            for token in (s.strip() for s in raw.split(",") if s.strip()):
                if token.lower() in value_set:
                    return True
            return False

        if any(
            field_has_any(name)
            for name in ["cves", "ips", "ipv6", "domains", "email", "hashes", "malware_tools"]
        ):
            related_articles.append(
                {
                    "source": source_key,
                    "source_label": source_label,
                    "url": row.get("url", "") or "",
                    "title": row.get("title", "") or "",
                    "published_at": row.get("published_at", "") or "",
                    "cves": row.get("cves", "") or "",
                    "ips": row.get("ips", "") or "",
                    "domains": row.get("domains", "") or "",
                    "hashes": row.get("hashes", "") or "",
                    "email": row.get("email", "") or "",
                    "malware_tools": row.get("malware_tools", "") or "",
                }
            )

    related_samples: List[Dict[str, Any]] = []
    samples = load_malware_csv(MALWARE_CSV_PATH, limit=200)
    for s in samples:
        sha256 = (s.get("sha256_hash") or "").strip()
        signature = (s.get("signature") or "").strip()
        tags = [str(t).strip() for t in (s.get("tags") or []) if str(t).strip()]

        if sha256 and sha256.lower() in value_set:
            related_samples.append(s)
            continue

        if signature and signature.lower() in value_set:
            related_samples.append(s)
            continue

        if any(t.lower() in value_set for t in tags):
            related_samples.append(s)

    return jsonify(
        {
            "values": values,
            "articles": related_articles,
            "malware_samples": related_samples,
        }
    )


@app.post("/api/chat")
def chat_about_threats():
    """
    SOC analyst RAG chat endpoint.

    Retrieval: semantic KNN over the article corpus (SQLite-cached embeddings).
    Persona: Tier-2 SOC analyst with access to enriched CTI data.
    Output contract: structured markdown with clearly separated sections for
      threat summary, IOCs, CVE context, recommended actions, and confidence.
    """
    from openai import OpenAI
    from intel.embeddings import semantic_search, embed_articles
    from intel.loader import load_articles_from_sources

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return (
            jsonify({"error": "OPENAI_API_KEY is not configured on the server.", "message": None}),
            500,
        )

    payload = request.get_json(silent=True) or {}
    messages = payload.get("messages") or []
    if not isinstance(messages, list) or not messages:
        return jsonify({"error": "Missing messages", "message": None}), 400

    user_messages = [m for m in messages if m.get("role") == "user" and m.get("content")]
    query = user_messages[-1]["content"] if user_messages else ""

    # Semantic retrieval via the intel embeddings engine (persistent SQLite cache)
    articles = load_articles_from_sources(SOURCE_CONFIG, hours=24 * 60)
    embed_articles(articles, api_key=api_key)
    similar = semantic_search(query, articles, top_k=10, api_key=api_key)

    # Build a structured, information-rich context block
    context_lines: List[str] = []

    if similar:
        context_lines.append("## Semantically relevant threat articles (cosine KNN retrieval)")
        for idx, art in enumerate(similar, 1):
            # Pull the full article row for IOC fields
            full = next(
                (a for a in articles if a.get("id") == art.article_id),
                None,
            )
            cves = (full or {}).get("cves") or ""
            ips = (full or {}).get("ips") or ""
            domains = (full or {}).get("domains") or ""
            hashes = (full or {}).get("hashes") or ""
            malware = (full or {}).get("malware_tools") or ""
            mitre = (full or {}).get("mitre_techniques") or ""

            context_lines.append(
                f"\n[{idx}] [{art.source_label}] {art.title}\n"
                f"    Published: {art.published_at} | Similarity: {art.score:.3f}\n"
                f"    URL: {art.url or 'N/A'}\n"
                f"    CVEs: {cves or '—'}\n"
                f"    IPs/Domains: {ips or '—'} / {domains or '—'}\n"
                f"    Hashes: {hashes or '—'}\n"
                f"    Malware: {malware or '—'}\n"
                f"    MITRE: {mitre or '—'}"
            )

    # Enrich any CVEs mentioned with CVSS/EPSS/KEV so the analyst has
    # real prioritization data in context
    from intel.enrichment import enrich_cves
    mentioned_cves: set[str] = set()
    for art in similar:
        full = next((a for a in articles if a.get("id") == art.article_id), None)
        if full:
            for tok in (full.get("cves") or "").split(","):
                tok = tok.strip()
                if tok:
                    mentioned_cves.add(tok)

    if mentioned_cves:
        enrichment = enrich_cves(list(mentioned_cves), max_new_fetches=0)
        context_lines.append("\n## CVE enrichment data (NVD/EPSS/CISA KEV)")
        for cve_id, enr in enrichment.items():
            kev_flag = "⚠ IN CISA KEV (actively exploited)" if enr.in_kev else ""
            context_lines.append(
                f"  {cve_id}: CVSS {enr.cvss_v3_score or '?'} {enr.cvss_v3_severity or ''} | "
                f"EPSS {enr.epss_score:.3f} ({enr.epss_percentile:.0%} percentile) "
                f"| {kev_flag}"
                if (enr.epss_score is not None and enr.epss_percentile is not None)
                else f"  {cve_id}: CVSS {enr.cvss_v3_score or '?'} {enr.cvss_v3_severity or ''} {kev_flag}"
            )

    # Add recent malware samples for cross-referencing
    malware_samples = load_malware_csv(MALWARE_CSV_PATH, limit=15)
    if malware_samples:
        context_lines.append("\n## Recent MalwareBazaar samples (for hash cross-reference)")
        for s in malware_samples[:8]:
            context_lines.append(
                f"  {s.get('signature') or '?'} | SHA256: {s.get('sha256_hash') or 'N/A'} "
                f"| {s.get('file_type') or ''} | first_seen: {s.get('first_seen') or 'N/A'}"
            )

    # Inject brief history so ARIA can answer "is this worse than last week?"
    if BRIEF_HISTORY:
        context_lines.append("\n## Historical executive brief snapshots (for trend comparison)")
        for i, h in enumerate(reversed(BRIEF_HISTORY), 1):
            context_lines.append(
                f"  [{i} brief(s) ago | {h.get('generated_at', 'unknown')}] "
                f"Risk: {h.get('risk_level', '?')} | Urgency: {h.get('urgency', '?')} | "
                f"Themes: {', '.join(h.get('dominant_themes') or [])} | "
                f"Top risk: {h.get('top_risk', '?')}"
            )

    context_text = "\n".join(context_lines) if context_lines else "No relevant context found in the ingested corpus."

    system_prompt = """You are ARIA (Automated Risk Intelligence Analyst), a Tier-2 SOC analyst assistant embedded in a threat intelligence dashboard.

Your knowledge comes ONLY from the provided context — ingested threat feeds, CVE enrichment data, and malware samples. Never fabricate IOCs, CVE scores, or attribution.

When responding, always use this structured format (markdown):

**Threat Summary**
One paragraph describing what's happening, grounded in the context.

**Relevant IOCs**
| Type | Value | Source |
|------|-------|--------|
List any CVEs, IPs, domains, hashes, or malware families from context that are relevant.

**CVE Prioritization** (if CVEs are involved)
Rank the CVEs using CVSS + EPSS + KEV data from context. Explain why each matters.

**ATT&CK Techniques** (if available)
List the relevant MITRE techniques seen and what phase of the kill chain they represent.

**Recommended Actions**
Numbered, specific, actionable steps for the SOC team.

**Confidence**
State your confidence level (High / Medium / Low) and explain what information is missing or uncertain.

If the question cannot be answered from the provided context, say: "Insufficient context — this may be outside the ingested time window or sources."
"""

    client = OpenAI(api_key=api_key)
    chat_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": f"## Retrieved Context\n\n{context_text}"},
    ] + messages

    try:
        completion = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=chat_messages,
            temperature=0.2,   # lower temp = more factual, less hallucination
        )
        reply = completion.choices[0].message.content
    except Exception as e:
        return jsonify({"error": f"LLM call failed: {e}", "message": None}), 502

    return jsonify({"error": None, "message": {"role": "assistant", "content": reply}})


def _parse_published_at(published_at: str) -> datetime | None:
    """
    Parse CSV published_at timestamps into a datetime for time-window filtering.
    Returns None when parsing fails.
    """
    if not published_at:
        return None
    raw = str(published_at).strip()
    if not raw:
        return None
    # Examples in your CSVs include:
    # - 2026-03-10T21:51:00+05:30
    # - 2026-03-10T14:23:35-04:00
    # - 2026-03-10T21:51:00+05:30 (with timezone)
    # datetime.fromisoformat can parse both.
    try:
        dt = datetime.fromisoformat(raw)
        # Normalize naive datetimes (shouldn't happen often)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _split_csv_list(raw: str) -> List[str]:
    """
    Split CSV-stored lists (comma-separated) into normalized tokens.
    """
    if not raw:
        return []
    parts = [p.strip() for p in str(raw).split(",") if p and str(p).strip()]
    return parts


INCIDENT_BRIEF_CACHE: Dict[str, Dict[str, Any]] = {}


def _cache_key_incident_brief(hours: int) -> str:
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    return f"incident_brief:v1:model={model}:hours={hours}"


def _parse_llm_json(text: str) -> Dict[str, Any]:
    """
    Best-effort JSON parser for LLM outputs.
    Accepts plain JSON or JSON wrapped in markdown fences.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Empty LLM response")

    # Strip ```json ... ``` or ``` ... ``` wrappers if present.
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE).strip()
        raw = re.sub(r"\s*```$", "", raw).strip()

    # If there's extra text, try to extract the first JSON object.
    if not raw.startswith("{"):
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            raw = raw[start : end + 1].strip()

    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Parsed JSON was not an object")
    return parsed


@app.get("/api/incidents/summary")
def incident_summary():
    """
    Produce an "incident-style" summary for recent activity.

    Query params:
      - hours: time window in hours (default 24, max 168)

    Output is JSON suitable for sidebar display.
    """
    try:
        hours = int(request.args.get("hours", "24"))
    except Exception:
        hours = 24
    hours = max(1, min(hours, 168))

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)

    recent_articles: List[Dict[str, Any]] = []
    cve_counts: Dict[str, int] = {}
    ip_counts: Dict[str, int] = {}
    domain_counts: Dict[str, int] = {}
    hash_counts: Dict[str, int] = {}
    malware_counts: Dict[str, int] = {}

    # Collect recent articles and IOC frequency within the window.
    for item in iter_article_rows():
        row = item["row"]
        published_at_raw = row.get("published_at") or ""
        dt = _parse_published_at(published_at_raw)
        if dt is None:
            continue
        if dt < cutoff:
            continue

        recent_articles.append(
            {
                "source_key": item["source_key"],
                "source_label": item["source_label"],
                "url": row.get("url", "") or "",
                "title": row.get("title", "") or "",
                "published_at": published_at_raw,
                "description": row.get("description", "") or "",
            }
        )

        for cve in _split_csv_list(row.get("cves", "") or ""):
            cve_counts[cve] = cve_counts.get(cve, 0) + 1
        for ip in _split_csv_list(row.get("ips", "") or ""):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        for dom in _split_csv_list(row.get("domains", "") or ""):
            domain_counts[dom] = domain_counts.get(dom, 0) + 1
        for h in _split_csv_list(row.get("hashes", "") or ""):
            hash_counts[h] = hash_counts.get(h, 0) + 1
        for m in _split_csv_list(row.get("malware_tools", "") or ""):
            malware_counts[m] = malware_counts.get(m, 0) + 1

    # MalwareBazaar "recent" is based on first_seen YYYY-MM-DD HH:MM:SS.
    # We'll approximate by comparing the date prefix.
    samples = load_malware_csv(MALWARE_CSV_PATH, limit=200)
    today_cutoff_date = cutoff.strftime("%Y-%m-%d")
    recent_samples: List[Dict[str, Any]] = [
        s for s in samples if (s.get("first_seen") or "").startswith(today_cutoff_date)
    ]
    malware_family_counts: Dict[str, int] = {}
    for s in recent_samples:
        sig = (s.get("signature") or "").strip()
        if not sig:
            continue
        malware_family_counts[sig] = malware_family_counts.get(sig, 0) + 1
        if (s.get("sha256_hash") or "").strip():
            hash_counts[s.get("sha256_hash")] = hash_counts.get(s.get("sha256_hash"), 0) + 1

    def top_k(d: Dict[str, int], k: int) -> List[Dict[str, Any]]:
        items = sorted(d.items(), key=lambda x: x[1], reverse=True)[:k]
        return [{"value": v, "count": c} for v, c in items if v]

    # For the "incident narrative", we keep it deterministic (no LLM) for now.
    summary_lines: List[str] = []
    if recent_articles:
        summary_lines.append(
            f"{len(recent_articles)} new security stories in the last {hours}h across your feeds."
        )
    if recent_samples:
        summary_lines.append(
            f"{len(recent_samples)} recent MalwareBazaar samples (based on first_seen date) matched in the window."
        )

    if not summary_lines:
        summary_lines = [f"No incident-relevant items found in the last {hours} hours." ]

    # Enrich narrative with top IOCs.
    top_cves = top_k(cve_counts, 5)
    top_ips = top_k(ip_counts, 5)
    top_domains = top_k(domain_counts, 5)
    top_hashes = top_k(hash_counts, 5)

    if top_cves:
        summary_lines.append("Top CVEs seen: " + ", ".join([x["value"] for x in top_cves]))
    if top_ips:
        summary_lines.append("Top IPs seen: " + ", ".join([x["value"] for x in top_ips]))
    if top_domains:
        summary_lines.append("Top domains seen: " + ", ".join([x["value"] for x in top_domains]))
    if top_hashes:
        summary_lines.append("Top hashes seen: " + ", ".join([x["value"] for x in top_hashes]))

    top_malware = sorted(malware_family_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    if top_malware:
        summary_lines.append(
            "Most frequent malware signatures in cache: "
            + ", ".join([f"{name} ({cnt})" for name, cnt in top_malware])
        )

    # Return a compact, UI-friendly payload.
    return jsonify(
        {
            "window_hours": hours,
            "n_articles": len(recent_articles),
            "n_malware_samples": len(recent_samples),
            "n_cves": sum(cve_counts.values()),
            "n_ips": sum(ip_counts.values()),
            "n_domains": sum(domain_counts.values()),
            "n_hashes": sum(hash_counts.values()),
            "n_malware_signatures": sum(malware_family_counts.values()),
            "narrative": summary_lines,
            "top": {
                "cves": top_cves,
                "ips": top_ips,
                "domains": top_domains,
                "hashes": top_hashes,
                "malware_signatures": [
                    {"value": name, "count": cnt} for name, cnt in top_malware
                ],
            },
            # Light list for drill-down: most recent few
            "recent_articles": sorted(
                recent_articles, key=lambda x: x.get("published_at") or "", reverse=True
            )[:6],
        }
    )


@app.post("/api/incidents/brief")
def incident_brief():
    """
    Generate an executive-focused incident brief using OpenAI.

    Body JSON (optional):
      - hours: int (default 24, max 168)
      - force: bool (default false) bypasses cache

    Response:
      - { "cached": bool, "window_hours": int, "brief": { ... } }
    """
    from openai import OpenAI

    payload = request.get_json(silent=True) or {}
    try:
        hours = int(payload.get("hours", 24))
    except Exception:
        hours = 24
    hours = max(1, min(hours, 168))
    force = bool(payload.get("force", False))

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return (
            jsonify(
                {
                    "error": "OPENAI_API_KEY is not configured on the server.",
                    "cached": False,
                    "brief": None,
                }
            ),
            500,
        )

    cache_key = _cache_key_incident_brief(hours)
    cached = INCIDENT_BRIEF_CACHE.get(cache_key) or {}
    ttl_s = int(os.getenv("INCIDENT_BRIEF_TTL_SECONDS", "600") or "600")
    now_s = time.time()
    # Serve the last generated brief indefinitely until the user forces regeneration.
    # This keeps the executive view stable across page reloads; restarting the server clears cache.
    if not force and cached:
        meta = cached.get("meta") or {}
        created_at = float(cached.get("created_at", 0) or 0)
        # Always update cache age while keeping the same brief.
        if not meta:
            meta = {}
        meta = {
            **meta,
            "cache_ttl_seconds": ttl_s,
            "cache_age_seconds": max(0, int(now_s - created_at)),
        }
        return jsonify(
            {
                "error": None,
                "cached": True,
                "window_hours": hours,
                "brief": cached.get("brief"),
                "articles": cached.get("articles") or [],
                "clusters": cached.get("clusters") or [],
                "meta": meta,
            }
        )

    # Assemble incident window data (same source of truth as summary endpoint).
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    def make_article_id(url: str, title: str, published_at: str, source: str) -> str:
        base = (url or "").strip() or f"{source}|{published_at}|{title}"
        return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]

    CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    def extract_entities_from_text(text: str) -> Dict[str, List[str]]:
        cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(text or "")})
        return {"cves": cves}

    def infer_threat_tags(title: str, description: str) -> List[str]:
        t = f"{title} {description}".lower()
        tags: List[str] = []
        if any(k in t for k in ["ransomware", "double extortion", "encrypt", "locker"]):
            tags.append("ransomware")
        if any(k in t for k in ["actively exploited", "active exploitation", "in the wild", "exploited in the wild"]):
            tags.append("active_exploitation")
        if any(k in t for k in ["zero-day", "0-day", "0day"]):
            tags.append("zero_day")
        if any(k in t for k in ["supply chain", "dependency", "package", "npm", "pypi", "pip", "github", "repo"]):
            tags.append("software_supply_chain")
        if any(k in t for k in ["ai", "llm", "model", "prompt injection", "agent", "chatbot"]):
            tags.append("ai_systems")
        if any(k in t for k in ["phishing", "credential", "oauth", "sso", "mfa"]):
            tags.append("identity")
        if any(k in t for k in ["vpn", "firewall", "gateway", "edge device", "internet-facing"]):
            tags.append("edge_exposure")
        if any(k in t for k in ["malware", "trojan", "botnet", "loader"]):
            tags.append("malware")
        return sorted(set(tags))

    def cluster_key_for_article(article: Dict[str, Any]) -> str:
        ents = article.get("extracted_entities") or {}
        cves = ents.get("cves") or []
        if cves:
            return f"cve:{cves[0]}"
        tags = article.get("threat_tags") or []
        if tags:
            return f"tag:{tags[0]}"
        # fall back to normalized title bucket
        title = (article.get("title") or "").lower()
        title = re.sub(r"[^a-z0-9\s]+", " ", title)
        title = re.sub(r"\s+", " ", title).strip()
        return f"title:{title[:48]}"

    articles: List[Dict[str, Any]] = []
    by_cluster: Dict[str, List[Dict[str, Any]]] = {}

    for item in iter_article_rows():
        row = item["row"]
        published_at_raw = row.get("published_at") or ""
        dt = _parse_published_at(published_at_raw)
        if dt is None or dt < cutoff:
            continue

        title = (row.get("title") or "").strip()
        desc = (row.get("description") or "").strip()
        url = (row.get("url") or "").strip()
        source_label = item["source_label"]

        # Entity extraction from structured fields + free text
        structured_cves = _split_csv_list(row.get("cves", "") or "")
        text_ents = extract_entities_from_text(f"{title}\n{desc}\n{url}")
        cves = sorted({c.upper() for c in (structured_cves + (text_ents.get("cves") or [])) if c})

        threat_tags = infer_threat_tags(title, desc)
        article_id = make_article_id(url, title, published_at_raw, source_label)

        article_obj = {
            "id": article_id,
            "title": title[:240],
            "source": source_label,
            "timestamp": published_at_raw,
            "url": url,
            "extracted_entities": {
                "cves": cves[:12],
                # Keep room for future enrichment (vendors/industries/vectors/etc.)
                "threat_tags": threat_tags[:10],
            },
            "raw": {
                "description": desc[:600],
                "domains": (row.get("domains") or "")[:400],
                "ips": (row.get("ips") or "")[:400],
                "hashes": (row.get("hashes") or "")[:400],
                "malware_tools": (row.get("malware_tools") or "")[:400],
            },
        }

        articles.append(article_obj)

        ck = cluster_key_for_article(
            {
                "title": article_obj["title"],
                "extracted_entities": {"cves": cves},
                "threat_tags": threat_tags,
            }
        )
        by_cluster.setdefault(ck, []).append(article_obj)

    # Sort newest first
    articles.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    # Deduplicate within cluster by source (keep newest per source)
    clusters: List[Dict[str, Any]] = []
    cluster_id_map: Dict[str, str] = {}
    for ck, items in by_cluster.items():
        items_sorted = sorted(items, key=lambda x: x.get("timestamp") or "", reverse=True)
        seen_sources: set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for a in items_sorted:
            src = a.get("source") or ""
            if src in seen_sources:
                continue
            seen_sources.add(src)
            deduped.append(a)

        cid = hashlib.sha1(ck.encode("utf-8")).hexdigest()[:10]
        cluster_id_map[ck] = cid
        label = ck
        if ck.startswith("cve:"):
            label = ck.split(":", 1)[1]
        elif ck.startswith("tag:"):
            label = ck.split(":", 1)[1].replace("_", " ").title()

        first_ts = deduped[-1]["timestamp"] if deduped else ""
        last_ts = deduped[0]["timestamp"] if deduped else ""
        clusters.append(
            {
                "id": cid,
                "label": label,
                "source_ids": [a["id"] for a in deduped],
                "source_count": len(deduped),
                "timeline": {"first_seen": first_ts, "last_update": last_ts},
            }
        )

    # Sort clusters by coverage then recency
    clusters.sort(key=lambda c: (c.get("source_count") or 0, c.get("timeline", {}).get("last_update") or ""), reverse=True)

    # Malware samples from cache (use date prefix approximation like summary).
    samples = load_malware_csv(MALWARE_CSV_PATH, limit=200)
    cutoff_date = cutoff.strftime("%Y-%m-%d")
    recent_samples = [s for s in samples if (s.get("first_seen") or "").startswith(cutoff_date)]
    recent_samples.sort(key=lambda x: x.get("first_seen") or "", reverse=True)

    malware_family_counts: Dict[str, int] = {}
    for s in recent_samples:
        sig = (s.get("signature") or "").strip()
        if sig:
            malware_family_counts[sig] = malware_family_counts.get(sig, 0) + 1

    # Keep context compact to control cost/latency: use deduped clusters + top articles.
    cluster_context = clusters[:25]
    article_context = articles[:40]
    malware_context = [
        {
            "signature": (s.get("signature") or "").strip()[:80],
            "first_seen": (s.get("first_seen") or "").strip(),
            "file_type": (s.get("file_type") or "").strip(),
            "sha256_hash": (s.get("sha256_hash") or "").strip(),
            "tags": (s.get("tags") or [])[:10],
        }
        for s in recent_samples[:40]
    ]

    # ── Inject pre-computed CVE scores as ground truth ──────────────────────
    # The scoring engine (CVSS + EPSS + KEV + centrality + trend) is authoritative.
    # Inject its output so the LLM prioritizes CVEs by score, not by keyword frequency.
    ranked_cves_context: List[Dict[str, Any]] = []
    try:
        from intel.enrichment import enrich_cves
        from intel.scoring import rank_cves
        from intel.correlation import build_ioc_graph
        from intel.trending import compute_trending_iocs
        from intel.loader import load_articles_from_sources

        _intel_articles = load_articles_from_sources(SOURCE_CONFIG, hours=hours)
        _all_cve_ids: List[str] = []
        _source_breadth: Dict[str, int] = {}
        for _a in _intel_articles:
            for _c in (_a.get("cves") or "").split(","):
                _c = _c.strip().upper()
                if _c:
                    _all_cve_ids.append(_c)
                    _source_breadth[_c] = _source_breadth.get(_c, 0) + 1

        if _all_cve_ids:
            _enrichment = enrich_cves(list(set(_all_cve_ids)), max_new_fetches=0)
            _graph = build_ioc_graph(_intel_articles)
            _trends = compute_trending_iocs(_intel_articles)
            _ranked = rank_cves(_enrichment, _graph, _trends,
                                source_breadth=_source_breadth, top_n=10)
            for _r in _ranked:
                ranked_cves_context.append({
                    "cve_id": _r.cve_id,
                    "priority_score": _r.score,
                    "cvss": _r.cvss_v3_score,
                    "severity": _r.cvss_v3_severity,
                    "epss": _r.epss_score,
                    "in_kev": _r.in_kev,
                    "trend_z": _r.trend_z,
                    "source_breadth": _r.source_breadth,
                    "reasons": _r.reasons,
                })
    except Exception:
        pass  # never let scoring errors break the brief

    context_obj = {
        "window_hours": hours,
        "cutoff_utc_iso": cutoff.isoformat(),
        "counts": {"n_articles": len(articles), "n_malware_samples": len(recent_samples)},
        "priority_cves": ranked_cves_context,  # quantitative ground truth — use these first
        "clusters": cluster_context,
        "articles": article_context,
        "recent_malware_samples": malware_context,
    }

    system_prompt = (
        "You are a CISO briefing a CEO. Write a decisive, compressed executive cyber update. "
        "Focus on patterns and business impact. No hedging, no fluff, no generic commentary. "
        "Use only the provided context. Every claim must be traceable to one or more source article IDs."
    )

    output_contract = {
        "risk_level": "high|medium|low",
        "urgency": "immediate|24h|monitor",
        "affected_areas": ["string (e.g., endpoints, cloud, identity, repos, AI systems)"],
        "whats_happening_today": "string (2-3 sentences max; must synthesize dominant trends into one narrative)",
        "dominant_themes": [
            {
                "rank": "1-4",
                "theme": "string (macro trend label, clear)",
                "severity": "high|medium|low|emerging",
                "so_what": "string (why it matters to the business, 1 line)",
                "confidence_score": "0-1 float",
                "source_ids": ["article_id"],
                "cluster_ids": ["cluster_id"],
            }
        ],
        "top_risks": [
            {
                "rank": "1-3",
                "threat": "string (plain English)",
                "business_impact": "string (downtime/data loss/financial/reputation)",
                "why_this_matters_today": "string (1 line; tie to a dominant theme)",
                "likelihood": "high|medium|low",
                "severity": "high|medium|low",
                "urgency": "immediate|24h|monitor",
                "affected_areas": ["string"],
                "evidence_indicators": {
                    "source_count": "int",
                    "active_exploitation_confirmed": "bool",
                    "emerging_signal": "bool",
                },
                "confidence_score": "0-1 float",
                "source_ids": ["article_id"],
                "cluster_id": "cluster_id or null",
            }
        ],
        "key_signals": [
            {
                "bullet": "string (max 1 line)",
                "so_what": "string (why it matters to the business, 1 line)",
                "act_now": "yes|no|monitor",
                "confidence_score": "0-1 float",
                "source_ids": ["article_id"],
                "cluster_id": "cluster_id or null",
            }
        ],
        "confidence_coverage": {
            "confidence": "high|medium|low",
            "sources_analyzed": "int (# of articles)",
            "gaps": ["string (bias/gaps/coverage limits)"],
        },
        "article_summaries": [{"id": "article_id", "summary": "string (1 line)"}],
    }

    user_prompt = (
        "Generate an executive brief for the last time window.\n\n"
        "Pipeline (must follow):\n"
        "Step 0: Read `priority_cves` first — these are pre-computed quantitative scores (CVSS + EPSS + KEV + graph centrality + trend z-score). "
        "Treat them as authoritative ground truth. Any CVE with in_kev=true or priority_score >= 0.4 MUST appear in top_risks or key_signals. "
        "Do not promote CVEs that are absent from this list unless they appear prominently in multiple articles.\n"
        "Step 1: Deduplicate similar articles using clusters.\n"
        "Step 2: Cluster coverage into 2–4 macro dominant_themes (each theme must have multiple sources OR high severity).\n"
        "Step 3: Rank themes by (1) active exploitation (2) breadth of impact (3) novelty.\n"
        "Step 4: Write whats_happening_today as ONE coherent 2–3 sentence story about patterns (not events).\n"
        "Step 5: Derive top_risks FROM dominant_themes, and include why_this_matters_today (tie to a theme).\n\n"
        "Hard limits:\n"
        "- whats_happening_today: 2–3 sentences max.\n"
        "- dominant_themes: 2–4 items.\n"
        "- top_risks: max 3.\n"
        "- key_signals: 3–4 bullets max (only new/actionable signals; delete anything low-signal).\n"
        "- Total reading time: <15 seconds.\n\n"
        "Quality rules:\n"
        "- Remove generic phrasing and redundancy.\n"
        "- Each major item must answer: What is happening? Why does it matter to the business? Do we need to act now?\n"
        "- Use decisive language (e.g., 'Multiple sources confirm…').\n"
        "- Every theme/risk/signal must include source_ids (1+). If unsure, lower confidence_score.\n"
        "- If multiple sources cover the same event, include cluster_id(s) and multiple source_ids.\n\n"
        "Return VALID JSON only (no markdown).\n\n"
        "JSON shape:\n"
        f"{json.dumps(output_contract, ensure_ascii=False)}\n\n"
        "Context:\n"
        f"{json.dumps(context_obj, ensure_ascii=False)}"
    )

    client = OpenAI(api_key=api_key)
    try:
        completion = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=float(os.getenv("INCIDENT_BRIEF_TEMPERATURE", "0.4") or "0.4"),
        )
        text = (completion.choices[0].message.content or "").strip()
        brief = _parse_llm_json(text)
    except Exception as e:
        return (
            jsonify(
                {
                    "error": f"Failed to generate incident brief: {e}",
                    "cached": False,
                    "brief": None,
                }
            ),
            502,
        )

    # Freshness / coverage metadata for the UI (exec trust-building).
    per_source_counts: Dict[str, int] = {}
    newest_article_dt: datetime | None = None
    for a in articles:
        src = a.get("source") or ""
        per_source_counts[src] = per_source_counts.get(src, 0) + 1
        dt = _parse_published_at(a.get("timestamp") or "")
        if dt is not None and (newest_article_dt is None or dt > newest_article_dt):
            newest_article_dt = dt

    newest_malware_first_seen = (recent_samples[0].get("first_seen") or "") if recent_samples else ""

    meta = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cutoff_utc": cutoff.isoformat(),
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "cache_ttl_seconds": ttl_s,
        "cache_age_seconds": 0,
        "sources_analyzed": len(articles),
        "unique_sources": len([k for k in per_source_counts.keys() if k]),
        "per_source_counts": per_source_counts,
        "clusters_analyzed": len(clusters),
        "latest_article_utc": newest_article_dt.astimezone(timezone.utc).isoformat()
        if newest_article_dt is not None
        else None,
        "latest_malware_first_seen": newest_malware_first_seen or None,
    }

    # Persist to ARIA memory so future chats can compare across time.
    _add_brief_to_history(brief, meta)

    # Store computed artifacts so UI can drill down without reprocessing.
    INCIDENT_BRIEF_CACHE[cache_key] = {
        "created_at": now_s,
        "brief": brief,
        "articles": articles[:200],  # cap payload
        "clusters": clusters[:200],
        "meta": meta,
    }
    return jsonify(
        {
            "error": None,
            "cached": False,
            "window_hours": hours,
            "brief": brief,
            "articles": articles[:200],
            "clusters": clusters[:200],
            "meta": meta,
        }
    )


@app.post("/api/malware/refresh")
def refresh_malware_samples():
    """
    Refresh MalwareBazaar samples by calling the external API, cache them to CSV,
    and return the latest set to the caller.
    """
    try:
        limit_raw = request.args.get("limit", "200")
        limit = int(limit_raw)
    except Exception:
        limit = 200
    limit = max(1, min(limit, 200))

    try:
        samples = fetch_recent_malware_samples(limit=limit)
        write_malware_csv(MALWARE_CSV_PATH, samples)
        return jsonify({"samples": samples})
    except Exception:
        # Friendly error: don't crash the app if MalwareBazaar is down or rate-limiting.
        return (
            jsonify(
                {
                    "samples": [],
                    "error": "Failed to refresh MalwareBazaar samples. Please try again later.",
                }
            ),
            502,
        )


if __name__ == "__main__":
    # Simple dev server; in production you'd use a proper WSGI server
    app.run(host="0.0.0.0", port=8001, debug=True)

