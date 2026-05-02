"""
IOC Threat Scoring
==================
Ranks every IOC in the corpus using a weighted composite of four signals:

  centrality   — eigenvector centrality in the IOC co-occurrence graph (how
                 connected this IOC is to other high-degree indicators)
  trend_z      — EWMA z-score spike; how unusually active this IOC is today
  kev_adjacent — co-occurs with at least one CISA KEV CVE (confirmed-exploited
                 vulnerability), which strongly elevates the IOC's priority
  breadth      — how many distinct sources mention this IOC

The formula mirrors rank_cves() in scoring.py and is fully auditable — every
scored IOC carries a `reasons` list explaining the score components.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable

from .correlation import GraphResult
from .trending import TrendSignal

# ── Weights ───────────────────────────────────────────────────────────────────

DEFAULT_WEIGHTS: dict[str, float] = {
    "centrality": 0.35,
    "trend":      0.25,
    "kev_adj":    0.25,
    "breadth":    0.15,
}

# Normalisation cap for z-scores (prevents a single outlier dominating)
_Z_CAP = 5.0
# Normalisation cap for source breadth
_BREADTH_CAP = 8


# ── Output type ───────────────────────────────────────────────────────────────

@dataclass
class ScoredIoc:
    ioc_type: str
    value: str
    score: float                # composite [0, 1]
    centrality: float           # eigenvector centrality from graph
    trend_z: float              # EWMA z-score (0 if not trending)
    kev_adjacent: bool          # True if co-occurs with a KEV CVE
    source_breadth: int         # number of distinct sources
    today_count: int            # mentions on the most recent day
    sample_articles: list[dict] # up to 3 article stubs

    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


# ── Helper ────────────────────────────────────────────────────────────────────

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _source_breadth_by_ioc(articles: Iterable[dict]) -> dict[tuple[str, str], int]:
    """
    Return {(ioc_type, value): distinct_source_count} across all articles.
    """
    by_ioc: dict[tuple[str, str], set[str]] = {}
    _fields = [
        ("cves",         "cve"),
        ("ips",          "ip"),
        ("ipv6",         "ip"),
        ("domains",      "domain"),
        ("hashes",       "hash"),
        ("malware_tools","malware"),
    ]
    for art in articles:
        src = art.get("source_label") or art.get("source_key") or ""
        for field, ioc_type in _fields:
            raw = (art.get(field) or "").strip()
            if not raw:
                continue
            for token in (t.strip() for t in raw.split(",") if t.strip()):
                key = (ioc_type, token)
                by_ioc.setdefault(key, set()).add(src)
    return {k: len(v) for k, v in by_ioc.items()}


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_iocs(
    articles: list[dict],
    graph: GraphResult,
    trends: list[TrendSignal],
    kev_cve_ids: set[str],
    top_n: int = 50,
    weights: dict[str, float] | None = None,
) -> list[ScoredIoc]:
    """
    Produce a ranked list of IOCs using multi-signal composite scoring.

    Parameters
    ----------
    articles    : article dicts from intel.loader
    graph       : IOC co-occurrence graph (provides centrality)
    trends      : trending signals (EWMA z-scores)
    kev_cve_ids : set of CVE IDs currently in CISA KEV
    top_n       : max results to return
    weights     : override DEFAULT_WEIGHTS
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}

    # ── index graph nodes by (type, value) ───────────────────────────────────
    graph_index: dict[tuple[str, str], float] = {}  # -> eigenvector
    for node in graph.nodes:
        graph_index[(node.type, node.value)] = node.eigenvector

    max_eig = max(graph_index.values(), default=1.0) or 1.0

    # ── index trending signals ────────────────────────────────────────────────
    trend_index: dict[tuple[str, str], TrendSignal] = {
        (s.ioc_type, s.value): s for s in trends
    }

    # ── find IOC → articles mapping for kev_adjacent and sample_articles ─────
    # article IDs that reference a KEV CVE
    kev_article_ids: set[str] = set()
    for art in articles:
        cves_raw = (art.get("cves") or "").strip()
        if not cves_raw:
            continue
        for cve in (t.strip().upper() for t in cves_raw.split(",") if t.strip()):
            if cve in kev_cve_ids:
                kev_article_ids.add(art.get("id") or "")
                break

    # ioc -> list of article ids
    ioc_to_articles: dict[tuple[str, str], list[dict]] = {}
    _fields = [
        ("cves",         "cve"),
        ("ips",          "ip"),
        ("ipv6",         "ip"),
        ("domains",      "domain"),
        ("hashes",       "hash"),
        ("malware_tools","malware"),
    ]
    for art in articles:
        stub = {
            "title": (art.get("title") or "")[:160],
            "source_label": art.get("source_label") or "",
            "published_at": art.get("published_at") or "",
            "url": art.get("url") or "",
        }
        for field, ioc_type in _fields:
            raw = (art.get(field) or "").strip()
            if not raw:
                continue
            for token in (t.strip() for t in raw.split(",") if t.strip()):
                key = (ioc_type, token)
                ioc_to_articles.setdefault(key, [])
                if len(ioc_to_articles[key]) < 3:
                    ioc_to_articles[key].append(stub)

    # ── source breadth ────────────────────────────────────────────────────────
    breadth_map = _source_breadth_by_ioc(articles)

    # ── collect all unique IOCs ───────────────────────────────────────────────
    all_iocs: set[tuple[str, str]] = (
        set(graph_index.keys())
        | set(trend_index.keys())
        | set(ioc_to_articles.keys())
    )
    # Exclude bare CVEs — those are handled by rank_cves() which is the CVE
    # scoring engine; mixing them here causes duplication in the UI.
    all_iocs = {(t, v) for t, v in all_iocs if t != "cve"}

    scored: list[ScoredIoc] = []
    for (ioc_type, value) in all_iocs:
        key = (ioc_type, value)

        eig = graph_index.get(key, 0.0)
        centrality_norm = _clip01(eig / max_eig)

        ts = trend_index.get(key)
        trend_z = ts.z_score if ts else 0.0
        trend_norm = _clip01(trend_z / _Z_CAP)
        today_count = ts.today_count if ts else 0

        breadth = breadth_map.get(key, 0)
        breadth_norm = _clip01(breadth / _BREADTH_CAP)

        # kev_adjacent: does this IOC appear in articles that also contain a KEV CVE?
        kev_adj = any(
            (a.get("id") or "") in kev_article_ids
            for a in ioc_to_articles.get(key, [])
        )

        composite = (
            w["centrality"] * centrality_norm
            + w["trend"]    * trend_norm
            + w["kev_adj"]  * (1.0 if kev_adj else 0.0)
            + w["breadth"]  * breadth_norm
        )

        reasons: list[str] = []
        if kev_adj:
            reasons.append("co-occurs with CISA KEV CVE (confirmed exploitation)")
        if trend_z >= 2.0:
            reasons.append(f"trending z={trend_z:.1f} (EWMA spike today)")
        if centrality_norm >= 0.5:
            reasons.append(f"high graph centrality ({eig:.4f})")
        if breadth >= 3:
            reasons.append(f"seen in {breadth} distinct sources")

        scored.append(
            ScoredIoc(
                ioc_type=ioc_type,
                value=value,
                score=round(composite, 4),
                centrality=round(eig, 4),
                trend_z=round(trend_z, 3),
                kev_adjacent=kev_adj,
                source_breadth=breadth,
                today_count=today_count,
                sample_articles=ioc_to_articles.get(key, [])[:3],
                reasons=reasons,
            )
        )

    scored.sort(key=lambda s: (s.score, s.trend_z), reverse=True)
    return scored[:top_n]
