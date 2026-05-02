"""
Threat Intelligence engine.

This package elevates the RSS dashboard from simple aggregation into an actual
intelligence pipeline:

- enrichment.py : pulls CVSS (NVD), EPSS (FIRST), KEV (CISA) for every CVE
- correlation.py: builds an IOC co-occurrence graph with centrality
- dedup.py      : MinHash+LSH near-duplicate article clustering
- trending.py   : EWMA + z-score spike detection for IOCs
- scoring.py    : composite risk score combining all signals
- storage.py    : sqlite caches shared across modules
- api.py        : Flask blueprint exposing everything over HTTP
"""

from .storage import get_db_path, init_db
from .enrichment import enrich_cves, get_cached_cve_enrichment
from .correlation import build_ioc_graph, GraphResult
from .dedup import cluster_articles_minhash, ClusterResult
from .trending import compute_trending_iocs, TrendSignal
from .scoring import rank_cves

__all__ = [
    "get_db_path",
    "init_db",
    "enrich_cves",
    "get_cached_cve_enrichment",
    "build_ioc_graph",
    "GraphResult",
    "cluster_articles_minhash",
    "ClusterResult",
    "compute_trending_iocs",
    "TrendSignal",
    "rank_cves",
]
