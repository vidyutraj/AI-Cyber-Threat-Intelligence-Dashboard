"""
Composite CVE risk scoring.

Given the enriched CVE data, the IOC graph, and trend signals, we compute a
single priority score per CVE the user's SOC team should care about today.

score = w_cvss * cvss_norm
      + w_epss * epss
      + w_kev  * 1[in_kev]
      + w_cent * centrality_percentile
      + w_trend * trend_activity
      + w_cov  * source_breadth

The weights are explicit so the scoring is auditable and tunable; nothing is
hidden inside an LLM.  Every factor is in [0,1] so the final score lives in
[0,1] too.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable

from .correlation import GraphResult
from .enrichment import CveEnrichment
from .trending import TrendSignal


@dataclass
class RankedCve:
    cve_id: str
    score: float
    cvss_v3_score: float | None
    cvss_v3_severity: str | None
    epss_score: float | None
    epss_percentile: float | None
    in_kev: bool
    centrality: float
    graph_degree: int
    trend_z: float
    today_count: int
    source_breadth: int
    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


DEFAULT_WEIGHTS = {
    "cvss": 0.20,
    "epss": 0.20,
    "kev": 0.25,
    "centrality": 0.15,
    "trend": 0.15,
    "coverage": 0.05,
}


def _clip01(x: float) -> float:
    if x < 0:
        return 0.0
    if x > 1:
        return 1.0
    return x


def rank_cves(
    enrichment: dict[str, CveEnrichment],
    graph: GraphResult,
    trends: Iterable[TrendSignal],
    source_breadth: dict[str, int] | None = None,
    weights: dict[str, float] | None = None,
    top_n: int = 25,
) -> list[RankedCve]:
    """
    Combine per-CVE signals into a single ranked list.

    Parameters
    ----------
    enrichment      : {cve_id -> CveEnrichment}
    graph           : GraphResult (for centrality/degree)
    trends          : iterable of TrendSignal (we pick cve-type)
    source_breadth  : {cve_id -> # of distinct sources that mentioned it}
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    trends_by_id = {
        t.value.upper(): t for t in trends if t.ioc_type == "cve"
    }
    graph_by_id = {
        n.value.upper(): n for n in graph.nodes if n.type == "cve"
    }
    # Normalise centrality across the graph so the score factor is in [0,1].
    max_eig = max((n.eigenvector for n in graph.nodes), default=0.0) or 1.0
    source_breadth = source_breadth or {}

    # We union CVEs discovered via any signal so nothing is lost.
    all_ids = set(enrichment.keys()) | set(trends_by_id.keys()) | set(graph_by_id.keys())

    results: list[RankedCve] = []
    for cve_id in all_ids:
        enr = enrichment.get(cve_id)
        node = graph_by_id.get(cve_id)
        tr = trends_by_id.get(cve_id)
        breadth = source_breadth.get(cve_id, 0)

        cvss_norm = _clip01((enr.cvss_v3_score or 0.0) / 10.0) if enr else 0.0
        epss = _clip01(enr.epss_score) if enr and enr.epss_score is not None else 0.0
        in_kev = bool(enr and enr.in_kev)
        centrality = _clip01((node.eigenvector / max_eig) if node else 0.0)
        trend_activity = _clip01((tr.z_score / 5.0) if tr else 0.0)  # cap at z=5
        coverage = _clip01(min(breadth, 5) / 5.0)

        score = (
            w["cvss"] * cvss_norm
            + w["epss"] * epss
            + w["kev"] * (1.0 if in_kev else 0.0)
            + w["centrality"] * centrality
            + w["trend"] * trend_activity
            + w["coverage"] * coverage
        )

        reasons: list[str] = []
        if in_kev:
            reasons.append("Listed in CISA KEV (confirmed active exploitation)")
        if enr and enr.cvss_v3_score and enr.cvss_v3_score >= 9.0:
            reasons.append(f"Critical CVSS ({enr.cvss_v3_score})")
        elif enr and enr.cvss_v3_score and enr.cvss_v3_score >= 7.0:
            reasons.append(f"High CVSS ({enr.cvss_v3_score})")
        if enr and enr.epss_score is not None and enr.epss_score >= 0.5:
            reasons.append(f"EPSS {enr.epss_score:.2f} – elevated exploit probability")
        if tr and tr.z_score >= 3.0:
            reasons.append(f"Spike detected (z={tr.z_score:.1f})")
        elif tr and tr.z_score >= 2.0:
            reasons.append(f"Trending upward (z={tr.z_score:.1f})")
        if node and node.degree >= 5:
            reasons.append(f"High graph connectivity (degree={node.degree})")
        if breadth >= 3:
            reasons.append(f"Reported by {breadth} distinct sources")

        results.append(
            RankedCve(
                cve_id=cve_id,
                score=round(score, 4),
                cvss_v3_score=(enr.cvss_v3_score if enr else None),
                cvss_v3_severity=(enr.cvss_v3_severity if enr else None),
                epss_score=(enr.epss_score if enr else None),
                epss_percentile=(enr.epss_percentile if enr else None),
                in_kev=in_kev,
                centrality=round(centrality, 4),
                graph_degree=(node.degree if node else 0),
                trend_z=round(tr.z_score, 3) if tr else 0.0,
                today_count=(tr.today_count if tr else 0),
                source_breadth=breadth,
                reasons=reasons,
            )
        )

    results.sort(key=lambda r: r.score, reverse=True)
    return results[:top_n]
