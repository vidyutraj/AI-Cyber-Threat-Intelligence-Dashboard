"""
Flask blueprint exposing the intel engine over HTTP.

All endpoints live under /api/intel/* to keep them isolated from the existing
dashboard routes, and share a lightweight in-memory cache so hitting several
endpoints in one UI render doesn't re-scan CSVs each time.
"""

from __future__ import annotations

import time
from threading import Lock
from typing import Any

from flask import Blueprint, jsonify, request

from .actors import identify_actors
from .correlation import build_ioc_graph
from .dedup import cluster_articles_minhash
from .embeddings import embed_articles, semantic_search, get_embedding_stats
from .enrichment import enrich_cves, get_cached_cve_enrichment
from .ioc_scoring import score_iocs
from .killchain import analyze_kill_chains
from .loader import (
    all_cve_ids,
    load_articles_from_sources,
    source_breadth_by_cve,
)
from .scoring import rank_cves
from .trending import compute_trending_iocs


def create_intel_blueprint(sources: dict[str, dict]) -> Blueprint:
    bp = Blueprint("intel", __name__)

    _articles_cache: dict[int, tuple[float, list[dict]]] = {}
    _cache_lock = Lock()
    _ARTICLE_TTL_SECONDS = 60

    def _get_articles(hours: int) -> list[dict]:
        now = time.time()
        with _cache_lock:
            cached = _articles_cache.get(hours)
            if cached and now - cached[0] < _ARTICLE_TTL_SECONDS:
                return cached[1]
            fresh = load_articles_from_sources(sources, hours=hours)
            _articles_cache[hours] = (now, fresh)
            return fresh

    @bp.get("/api/intel/status")
    def status():
        emb_stats = get_embedding_stats()
        return jsonify(
            {
                "ok": True,
                "sources": list(sources.keys()),
                "embedding_stats": emb_stats,
                "endpoints": [
                    "/api/intel/overview",
                    "/api/intel/cves",
                    "/api/intel/cve/<id>",
                    "/api/intel/graph",
                    "/api/intel/clusters",
                    "/api/intel/trending",
                    "/api/intel/similar",
                    "/api/intel/killchain",
                ],
            }
        )

    @bp.get("/api/intel/similar")
    def get_similar():
        """
        Semantic similarity search over the article corpus.

        ?q=<query text>&top_k=<int>&hours=<int>

        Uses OpenAI text-embedding-3-small (cosine KNN) when the API key is
        available; falls back to TF-IDF cosine similarity otherwise.  The
        interface and result schema are identical in both modes.
        """
        import os
        query = (request.args.get("q") or "").strip()
        if not query:
            return jsonify({"error": "Missing ?q= parameter", "results": []}), 400
        try:
            top_k = int(request.args.get("top_k", "10"))
        except Exception:
            top_k = 10
        top_k = max(1, min(top_k, 25))
        try:
            hours = int(request.args.get("hours", "1440"))
        except Exception:
            hours = 1440
        hours = max(1, min(hours, 24 * 60))

        articles = _get_articles(hours)
        api_key = os.getenv("OPENAI_API_KEY")

        # Lazily embed any new articles (no-op if already cached)
        if api_key:
            embed_articles(articles, api_key=api_key)

        results = semantic_search(query, articles, top_k=top_k, api_key=api_key)
        mode = "openai_knn" if api_key else "tfidf_cosine"
        return jsonify(
            {
                "query": query,
                "mode": mode,
                "top_k": top_k,
                "results": [r.to_dict() for r in results],
            }
        )

    @bp.get("/api/intel/killchain")
    def get_killchain():
        """
        MITRE ATT&CK kill-chain analysis over the corpus.

        Returns per-tactic technique coverage and multi-stage campaign articles
        (articles whose techniques span >= 3 distinct ATT&CK tactics).
        """
        try:
            hours = int(request.args.get("hours", "1440"))
        except Exception:
            hours = 1440
        hours = max(1, min(hours, 24 * 60))

        articles = _get_articles(hours)
        result = analyze_kill_chains(articles, window_hours=hours)
        return jsonify(result.to_dict())

    @bp.get("/api/intel/cve/<cve_id>")
    def get_single_cve(cve_id: str):
        cached = get_cached_cve_enrichment(cve_id)
        if cached:
            return jsonify({"cve": cached.to_dict(), "cached": True})
        enriched = enrich_cves([cve_id], max_new_fetches=1)
        enr = enriched.get(cve_id.strip().upper())
        if not enr:
            return jsonify({"cve": None, "cached": False}), 404
        return jsonify({"cve": enr.to_dict(), "cached": False})

    @bp.get("/api/intel/cves")
    def list_cves():
        try:
            hours = int(request.args.get("hours", "168"))
        except Exception:
            hours = 168
        hours = max(1, min(hours, 24 * 60))
        try:
            max_new = int(request.args.get("max_new_fetches", "15"))
        except Exception:
            max_new = 15

        articles = _get_articles(hours)
        cves = all_cve_ids(articles)
        enrichment = enrich_cves(cves, max_new_fetches=max_new)
        breadth = source_breadth_by_cve(articles)
        trends = compute_trending_iocs(articles, lookback_days=min(30, max(hours // 24, 2)))
        graph = build_ioc_graph(articles, window_hours=hours, top_n=200)
        ranked = rank_cves(
            enrichment=enrichment,
            graph=graph,
            trends=trends,
            source_breadth=breadth,
            top_n=50,
        )
        return jsonify(
            {
                "window_hours": hours,
                "n_articles": len(articles),
                "n_cves": len(cves),
                "ranked": [r.to_dict() for r in ranked],
            }
        )

    @bp.get("/api/intel/graph")
    def get_graph():
        try:
            hours = int(request.args.get("hours", "168"))
        except Exception:
            hours = 168
        hours = max(1, min(hours, 24 * 60))
        try:
            top_n = int(request.args.get("top_n", "80"))
        except Exception:
            top_n = 80

        articles = _get_articles(hours)
        graph = build_ioc_graph(articles, window_hours=hours, top_n=top_n)
        return jsonify(graph.to_dict())

    @bp.get("/api/intel/clusters")
    def get_clusters():
        try:
            hours = int(request.args.get("hours", "72"))
        except Exception:
            hours = 72
        hours = max(1, min(hours, 24 * 60))
        try:
            min_size = int(request.args.get("min_size", "2"))
        except Exception:
            min_size = 2
        try:
            threshold = float(request.args.get("threshold", "0.30"))
        except Exception:
            threshold = 0.30

        articles = _get_articles(hours)
        result = cluster_articles_minhash(articles, jaccard_threshold=threshold)
        data = result.to_dict()
        # Filter: only return meaningful clusters (>= min_size members)
        data["clusters"] = [c for c in data["clusters"] if len(c["article_ids"]) >= min_size]
        data["window_hours"] = hours
        return jsonify(data)

    @bp.get("/api/intel/trending")
    def get_trending():
        try:
            lookback = int(request.args.get("lookback_days", "14"))
        except Exception:
            lookback = 14
        lookback = max(3, min(lookback, 60))
        try:
            z_threshold = float(request.args.get("z_threshold", "2.0"))
        except Exception:
            z_threshold = 2.0

        articles = _get_articles(lookback * 24)
        signals = compute_trending_iocs(
            articles,
            lookback_days=lookback,
            z_threshold=z_threshold,
        )
        return jsonify(
            {
                "lookback_days": lookback,
                "z_threshold": z_threshold,
                "signals": [s.to_dict() for s in signals],
            }
        )

    @bp.get("/api/intel/overview")
    def get_overview():
        """
        One-shot endpoint for the dashboard: returns ranked CVEs, trending
        signals, graph summary, and cluster counts so the UI can render a
        whole "Threat Intelligence" tab in one round trip.
        """
        try:
            hours = int(request.args.get("hours", "168"))
        except Exception:
            hours = 168
        hours = max(1, min(hours, 24 * 60))

        articles = _get_articles(hours)
        cves = all_cve_ids(articles)
        breadth = source_breadth_by_cve(articles)

        enrichment = enrich_cves(cves, max_new_fetches=15)
        trends = compute_trending_iocs(articles, lookback_days=min(30, max(hours // 24, 2)))
        graph = build_ioc_graph(articles, window_hours=hours, top_n=80)
        ranked = rank_cves(
            enrichment=enrichment,
            graph=graph,
            trends=trends,
            source_breadth=breadth,
            top_n=15,
        )
        clusters = cluster_articles_minhash(articles)

        # Compact "top hubs" summary from the graph.
        top_hubs: list[dict[str, Any]] = []
        for n in graph.nodes[:10]:
            top_hubs.append(
                {
                    "id": n.id,
                    "type": n.type,
                    "value": n.value,
                    "count": n.count,
                    "degree": n.degree,
                    "weighted_degree": n.weighted_degree,
                    "eigenvector": round(n.eigenvector, 4),
                    "community": n.community,
                    "sample_articles": n.sample_articles,
                }
            )

        # ── Sparklines: daily article/CVE/KEV counts for last 7 days ─────────
        from datetime import datetime, timedelta, timezone as _tz
        _today = datetime.now(_tz.utc)
        _days = [(_today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        _art_by_day: dict[str, int] = {d: 0 for d in _days}
        _cve_by_day: dict[str, int] = {d: 0 for d in _days}
        _kev_ids = {cve_id for cve_id, e in enrichment.items() if e.in_kev}
        _kev_by_day: dict[str, int] = {d: 0 for d in _days}
        for art in articles:
            pub = (art.get("published_at") or "")[:10]
            if pub in _art_by_day:
                _art_by_day[pub] += 1
                cves_raw = art.get("cves") or ""
                has_kev = False
                for cve in (t.strip().upper() for t in cves_raw.split(",") if t.strip()):
                    _cve_by_day[pub] = _cve_by_day.get(pub, 0) + 1
                    if cve in _kev_ids:
                        has_kev = True
                if has_kev:
                    _kev_by_day[pub] = _kev_by_day.get(pub, 0) + 1

        sparklines = {
            "days": _days,
            "articles": [_art_by_day[d] for d in _days],
            "cves": [_cve_by_day[d] for d in _days],
            "kev": [_kev_by_day[d] for d in _days],
        }

        return jsonify(
            {
                "window_hours": hours,
                "n_articles": len(articles),
                "n_cves_total": len(cves),
                "n_cves_enriched": sum(
                    1 for e in enrichment.values() if e.cvss_v3_score is not None
                ),
                "n_kev": sum(1 for e in enrichment.values() if e.in_kev),
                "ranked_cves": [r.to_dict() for r in ranked],
                "trending": [s.to_dict() for s in trends[:10]],
                "top_hubs": top_hubs,
                "n_clusters": len(
                    [c for c in clusters.clusters if len(c.article_ids) >= 2]
                ),
                "n_duplicates": clusters.duplicates,
                "sparklines": sparklines,
            }
        )

    @bp.get("/api/intel/iocs/scored")
    def get_scored_iocs():
        """
        Ranked IOC list with composite threat score.

        Each IOC is scored on: graph centrality, trend z-score,
        KEV co-occurrence, and source breadth.
        """
        try:
            hours = int(request.args.get("hours", "168"))
        except Exception:
            hours = 168
        hours = max(1, min(hours, 24 * 60))
        try:
            top_n = int(request.args.get("top_n", "50"))
        except Exception:
            top_n = 50
        top_n = max(1, min(top_n, 200))

        articles = _get_articles(hours)
        cves = all_cve_ids(articles)
        enrichment = enrich_cves(cves, max_new_fetches=10)
        kev_ids = {cve_id for cve_id, e in enrichment.items() if e.in_kev}
        trends = compute_trending_iocs(articles, lookback_days=max(hours // 24, 2))
        graph = build_ioc_graph(articles, window_hours=hours, top_n=300)
        scored = score_iocs(articles, graph, trends, kev_ids, top_n=top_n)
        return jsonify({
            "window_hours": hours,
            "n_articles": len(articles),
            "n_scored": len(scored),
            "iocs": [s.to_dict() for s in scored],
        })

    @bp.get("/api/intel/actors")
    def get_actors():
        """
        Threat actor profiles derived from article text matching against a
        curated alias dictionary (APT groups, ransomware operators, etc.).
        """
        try:
            hours = int(request.args.get("hours", "1440"))
        except Exception:
            hours = 1440
        hours = max(1, min(hours, 24 * 60))

        articles = _get_articles(hours)
        profiles = identify_actors(articles)
        return jsonify({
            "window_hours": hours,
            "n_articles": len(articles),
            "actors": [p.to_dict() for p in profiles],
        })

    @bp.get("/api/intel/stix")
    def get_stix():
        """
        Export IOCs and CVEs as a STIX 2.1 Bundle.

        Returns a Bundle containing:
          - Indicator objects for IPs, domains, hashes
          - Vulnerability objects for CVEs
          - Identity object for the feed platform
        """
        import uuid as _uuid

        try:
            hours = int(request.args.get("hours", "168"))
        except Exception:
            hours = 168
        hours = max(1, min(hours, 24 * 60))

        articles = _get_articles(hours)
        now_iso = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        identity_id = f"identity--{_uuid.uuid5(_uuid.NAMESPACE_DNS, 'cyberpulse.local')}"
        objects: list[dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": "CyberPulse Threat Intelligence Platform",
                "identity_class": "system",
            }
        ]

        seen_iocs: set[str] = set()
        seen_cves: set[str] = set()

        _ioc_fields = [
            ("ips",     "ip",     "ipv4-addr",   "ipv4-addr:value = '{v}'"),
            ("domains", "domain", "domain-name", "domain-name:value = '{v}'"),
            ("hashes",  "hash",   "file",        "file:hashes.SHA-256 = '{v}'"),
        ]

        for art in articles:
            pub = (art.get("published_at") or now_iso)[:19] + "Z"

            for field, ioc_type, stix_obj, pattern_tmpl in _ioc_fields:
                raw = (art.get(field) or "").strip()
                for token in (t.strip() for t in raw.split(",") if t.strip()):
                    key = f"{ioc_type}:{token}"
                    if key in seen_iocs:
                        continue
                    seen_iocs.add(key)
                    ind_id = f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_URL, key)}"
                    objects.append({
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": ind_id,
                        "created": pub,
                        "modified": pub,
                        "name": f"{ioc_type.upper()}: {token}",
                        "indicator_types": ["malicious-activity"],
                        "pattern": f"[{pattern_tmpl.format(v=token)}]",
                        "pattern_type": "stix",
                        "valid_from": pub,
                        "created_by_ref": identity_id,
                        "external_references": [
                            {"source_name": art.get("source_label") or "unknown",
                             "url": art.get("url") or ""}
                        ],
                    })

            # CVEs as Vulnerability objects
            cves_raw = (art.get("cves") or "").strip()
            for cve in (t.strip().upper() for t in cves_raw.split(",") if t.strip()):
                if cve in seen_cves:
                    continue
                seen_cves.add(cve)
                vuln_id = f"vulnerability--{_uuid.uuid5(_uuid.NAMESPACE_URL, cve)}"
                objects.append({
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": vuln_id,
                    "created": pub,
                    "modified": pub,
                    "name": cve,
                    "external_references": [
                        {"source_name": "cve", "external_id": cve,
                         "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
                    ],
                    "created_by_ref": identity_id,
                })

        bundle_id = f"bundle--{_uuid.uuid4()}"
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        from flask import Response as _Resp
        import json as _json
        return _Resp(
            _json.dumps(bundle, separators=(",", ":")),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="stix_{now_iso[:10]}.json"'},
        )

    return bp
