"""
IOC correlation graph.

We build a weighted undirected graph where nodes are indicators of compromise
(CVEs, IPs, domains, hashes, malware families, MITRE techniques) and edges
connect IOCs that co-occur inside the same article.  Edge weight is the
co-occurrence count across the time window.

We then compute:

- Degree centrality  : how many other IOCs this one touches
- Eigenvector        : iterative "important-IOC-connects-to-important-IOC"
                        (a PageRank-style influence score)
- Communities        : greedy label-propagation to surface clusters
                        (campaign / malware family / supply-chain topic)

This is the kind of analysis SOC / CTI teams actually do: we're not just
counting mentions, we're looking at the structure of how indicators relate.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable


# IOC types we ingest.  Order-independent.
IOC_TYPES = ("cve", "ip", "domain", "hash", "malware", "technique")


@dataclass
class GraphNode:
    id: str
    type: str
    value: str
    count: int = 0          # raw article mention count
    degree: int = 0         # number of unique neighbours
    weighted_degree: float = 0.0
    eigenvector: float = 0.0
    community: int = -1
    sample_articles: list[dict] = field(default_factory=list)


@dataclass
class GraphEdge:
    source: str
    target: str
    weight: float
    article_ids: list[str] = field(default_factory=list)


@dataclass
class GraphResult:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    n_articles: int
    window_hours: int

    def to_dict(self) -> dict:
        return {
            "n_articles": self.n_articles,
            "window_hours": self.window_hours,
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "value": n.value,
                    "count": n.count,
                    "degree": n.degree,
                    "weighted_degree": n.weighted_degree,
                    "eigenvector": n.eigenvector,
                    "community": n.community,
                    "sample_articles": n.sample_articles,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "weight": e.weight,
                    "article_ids": e.article_ids,
                }
                for e in self.edges
            ],
        }


def _ioc_id(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{value.strip().lower()}"


def _iter_article_iocs(article: dict) -> list[tuple[str, str]]:
    """Return [(type, value), ...] for every IOC present on the article."""
    out: list[tuple[str, str]] = []

    def _add(field: str, ioc_type: str) -> None:
        raw = (article.get(field) or "").strip()
        if not raw:
            return
        for token in (t.strip() for t in raw.split(",")):
            if token:
                out.append((ioc_type, token))

    _add("cves", "cve")
    _add("ips", "ip")
    _add("ipv6", "ip")
    _add("domains", "domain")
    _add("hashes", "hash")
    _add("malware_tools", "malware")
    _add("mitre_techniques", "technique")
    return out


# ---------------------------------------------------------------------------
# Graph algorithms (pure python, no numpy/networkx)
# ---------------------------------------------------------------------------


def _eigenvector_centrality(
    adjacency: dict[str, dict[str, float]],
    n_iter: int = 60,
    tol: float = 1e-5,
) -> dict[str, float]:
    """Power iteration on the (weighted) adjacency matrix."""
    if not adjacency:
        return {}
    nodes = list(adjacency.keys())
    # Initialise uniformly
    score = {n: 1.0 / len(nodes) for n in nodes}
    for _ in range(n_iter):
        new = {n: 0.0 for n in nodes}
        for u, neighbours in adjacency.items():
            s = score[u]
            for v, w in neighbours.items():
                new[v] += w * s
        # normalise
        norm = math.sqrt(sum(v * v for v in new.values())) or 1.0
        new = {n: v / norm for n, v in new.items()}
        # check convergence
        delta = sum(abs(new[n] - score[n]) for n in nodes)
        score = new
        if delta < tol:
            break
    return score


def _label_propagation_communities(
    adjacency: dict[str, dict[str, float]],
    n_iter: int = 20,
) -> dict[str, int]:
    """
    Greedy label-propagation community detection.  Each node adopts the
    most-weighted label among its neighbours.  Deterministic on ties by
    preferring the lower integer label.
    """
    if not adjacency:
        return {}
    # initial: every node its own community
    labels = {n: i for i, n in enumerate(adjacency.keys())}
    for _ in range(n_iter):
        changed = 0
        for n, neighbours in adjacency.items():
            if not neighbours:
                continue
            tally: dict[int, float] = defaultdict(float)
            for nb, w in neighbours.items():
                tally[labels[nb]] += w
            if not tally:
                continue
            best_label = min(
                tally.items(),
                key=lambda kv: (-kv[1], kv[0]),
            )[0]
            if labels[n] != best_label:
                labels[n] = best_label
                changed += 1
        if changed == 0:
            break
    # Compress label ids to 0..k-1
    remap: dict[int, int] = {}
    for lbl in labels.values():
        if lbl not in remap:
            remap[lbl] = len(remap)
    return {n: remap[lbl] for n, lbl in labels.items()}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def build_ioc_graph(
    articles: Iterable[dict],
    window_hours: int = 168,
    min_degree: int = 1,
    top_n: int | None = None,
) -> GraphResult:
    """
    Build the IOC co-occurrence graph from an iterable of article dicts.  Each
    article is expected to carry CSV-style string columns (cves, ips, etc.),
    which matches what our scrapers already produce.

    `min_degree` prunes isolated / noisy nodes to keep the UI graph readable.
    `top_n` optionally keeps only the top_n nodes by weighted degree.
    """
    articles_list = list(articles)
    node_counts: dict[str, int] = defaultdict(int)
    node_meta: dict[str, tuple[str, str]] = {}
    node_samples: dict[str, list[dict]] = defaultdict(list)
    edges: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"weight": 0.0, "article_ids": []}
    )

    for art in articles_list:
        iocs = _iter_article_iocs(art)
        if not iocs:
            continue
        # Dedupe within the article so a repeated CVE doesn't inflate edges
        unique_ids: list[str] = []
        seen: set[str] = set()
        for t, v in iocs:
            nid = _ioc_id(t, v)
            if nid in seen:
                continue
            seen.add(nid)
            unique_ids.append(nid)
            node_counts[nid] += 1
            node_meta.setdefault(nid, (t, v))

        article_id = (art.get("id") or art.get("url") or art.get("title") or "")[:80]
        article_stub = {
            "id": article_id,
            "title": (art.get("title") or "")[:180],
            "source_label": art.get("source_label") or "",
            "published_at": art.get("published_at") or "",
            "url": art.get("url") or "",
        }

        for nid in unique_ids:
            samples = node_samples[nid]
            if len(samples) < 3:
                samples.append(article_stub)

        # Co-occurrence edges
        for i in range(len(unique_ids)):
            for j in range(i + 1, len(unique_ids)):
                a, b = unique_ids[i], unique_ids[j]
                if a == b:
                    continue
                key = (a, b) if a < b else (b, a)
                edges[key]["weight"] += 1.0
                if article_id and len(edges[key]["article_ids"]) < 5:
                    edges[key]["article_ids"].append(article_id)

    # Build adjacency
    adjacency: dict[str, dict[str, float]] = defaultdict(dict)
    for (u, v), meta in edges.items():
        w = meta["weight"]
        adjacency[u][v] = w
        adjacency[v][u] = w
    for nid in node_counts:
        adjacency.setdefault(nid, {})

    # Metrics
    eig = _eigenvector_centrality(adjacency)
    communities = _label_propagation_communities(adjacency)

    nodes: list[GraphNode] = []
    for nid, cnt in node_counts.items():
        t, v = node_meta[nid]
        neigh = adjacency.get(nid) or {}
        degree = len(neigh)
        wdeg = sum(neigh.values())
        if degree < min_degree and cnt < 2:
            continue
        nodes.append(
            GraphNode(
                id=nid,
                type=t,
                value=v,
                count=cnt,
                degree=degree,
                weighted_degree=wdeg,
                eigenvector=eig.get(nid, 0.0),
                community=communities.get(nid, -1),
                sample_articles=node_samples.get(nid, []),
            )
        )

    # Sort by weighted degree * eigenvector (a pseudo "intel importance")
    nodes.sort(
        key=lambda n: (n.eigenvector * (n.weighted_degree + 1), n.count),
        reverse=True,
    )
    if top_n is not None and top_n > 0:
        keep_ids = {n.id for n in nodes[:top_n]}
        nodes = nodes[:top_n]
    else:
        keep_ids = {n.id for n in nodes}

    out_edges: list[GraphEdge] = []
    for (u, v), meta in edges.items():
        if u not in keep_ids or v not in keep_ids:
            continue
        out_edges.append(
            GraphEdge(
                source=u,
                target=v,
                weight=meta["weight"],
                article_ids=meta["article_ids"],
            )
        )
    out_edges.sort(key=lambda e: e.weight, reverse=True)

    return GraphResult(
        nodes=nodes,
        edges=out_edges,
        n_articles=len(articles_list),
        window_hours=window_hours,
    )
