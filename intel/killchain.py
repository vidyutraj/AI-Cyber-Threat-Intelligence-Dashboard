"""
MITRE ATT&CK kill-chain reconstruction.

The scrapers already extract MITRE technique IDs (T-codes) from articles.
This module maps every T-code to its parent tactic, then answers the
question a SOC analyst actually cares about:

  "What phases of the attack lifecycle are adversaries most active in right now,
   and which specific techniques are driving that activity?"

We also reconstruct per-article kill-chains: if an article mentions techniques
from Reconnaissance + Execution + Exfiltration it likely describes a complete
multi-stage campaign rather than a single-step event — that's a qualitatively
different kind of alert.

Design note: the full ATT&CK taxonomy is huge (>700 techniques).  We embed
the tactic-level mapping directly here so this works completely offline with
no API calls and no STIX bundle download (that's 40 MB and slow).  The
mapping covers all sub-techniques (T1xxx.yyy) by checking the parent prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# ATT&CK tactic taxonomy
# Each tuple: (tactic_id, short_name, display_label, order_in_kill_chain)
# Order reflects rough attacker progression; some tactics are concurrent.
# ---------------------------------------------------------------------------

TACTICS: list[tuple[str, str, str, int]] = [
    ("TA0043", "reconnaissance",         "Reconnaissance",         0),
    ("TA0042", "resource-development",   "Resource Development",   1),
    ("TA0001", "initial-access",         "Initial Access",         2),
    ("TA0002", "execution",              "Execution",              3),
    ("TA0003", "persistence",            "Persistence",            4),
    ("TA0004", "privilege-escalation",   "Privilege Escalation",   5),
    ("TA0005", "defense-evasion",        "Defense Evasion",        6),
    ("TA0006", "credential-access",      "Credential Access",      7),
    ("TA0007", "discovery",              "Discovery",              8),
    ("TA0008", "lateral-movement",       "Lateral Movement",       9),
    ("TA0009", "collection",             "Collection",             10),
    ("TA0011", "command-and-control",    "C2",                     11),
    ("TA0010", "exfiltration",           "Exfiltration",           12),
    ("TA0040", "impact",                 "Impact",                 13),
]

# Technique-prefix → tactic_id mapping.
# Sub-techniques (T1xxx.yyy) are matched by their parent T1xxx prefix first,
# then the exact sub-technique is also stored for drill-down display.
# Source: ATT&CK Enterprise v15 (technique → primary tactic).
# We list only the primary tactic for each technique; some techniques appear
# under multiple tactics but we pick the most operationally useful one.
_TECH_TO_TACTIC: dict[str, str] = {
    # TA0043 Reconnaissance
    "T1595": "TA0043", "T1592": "TA0043", "T1589": "TA0043",
    "T1590": "TA0043", "T1591": "TA0043", "T1598": "TA0043",
    "T1597": "TA0043", "T1596": "TA0043", "T1593": "TA0043",
    "T1594": "TA0043",
    # TA0042 Resource Development
    "T1583": "TA0042", "T1584": "TA0042", "T1585": "TA0042",
    "T1586": "TA0042", "T1587": "TA0042", "T1588": "TA0042",
    "T1608": "TA0042",
    # TA0001 Initial Access
    "T1189": "TA0001", "T1190": "TA0001", "T1191": "TA0001",
    "T1200": "TA0001", "T1566": "TA0001", "T1078": "TA0001",
    "T1195": "TA0001", "T1199": "TA0001", "T1133": "TA0001",
    # TA0002 Execution
    "T1059": "TA0002", "T1106": "TA0002", "T1129": "TA0002",
    "T1203": "TA0002", "T1204": "TA0002", "T1559": "TA0002",
    "T1047": "TA0002", "T1053": "TA0002", "T1569": "TA0002",
    "T1610": "TA0002", "T1612": "TA0002", "T1620": "TA0002",
    # TA0003 Persistence
    "T1037": "TA0003", "T1098": "TA0003", "T1136": "TA0003",
    "T1176": "TA0003", "T1197": "TA0003", "T1543": "TA0003",
    "T1546": "TA0003", "T1547": "TA0003", "T1556": "TA0003",
    "T1574": "TA0003", "T1505": "TA0003", "T1525": "TA0003",
    "T1601": "TA0003",
    # TA0004 Privilege Escalation
    "T1134": "TA0004", "T1484": "TA0004", "T1548": "TA0004",
    "T1055": "TA0004", "T1068": "TA0004", "T1611": "TA0004",
    # TA0005 Defense Evasion
    "T1036": "TA0005", "T1027": "TA0005", "T1070": "TA0005",
    "T1112": "TA0005", "T1140": "TA0005", "T1202": "TA0005",
    "T1205": "TA0005", "T1216": "TA0005", "T1218": "TA0005",
    "T1220": "TA0005", "T1221": "TA0005", "T1222": "TA0005",
    "T1497": "TA0005", "T1553": "TA0005", "T1562": "TA0005",
    "T1564": "TA0005", "T1600": "TA0005",
    # TA0006 Credential Access
    "T1003": "TA0006", "T1040": "TA0006", "T1056": "TA0006",
    "T1110": "TA0006", "T1111": "TA0006", "T1187": "TA0006",
    "T1212": "TA0006", "T1528": "TA0006", "T1539": "TA0006",
    "T1552": "TA0006", "T1555": "TA0006", "T1557": "TA0006",
    "T1558": "TA0006", "T1606": "TA0006",
    # TA0007 Discovery
    "T1007": "TA0007", "T1010": "TA0007", "T1012": "TA0007",
    "T1016": "TA0007", "T1018": "TA0007", "T1033": "TA0007",
    "T1046": "TA0007", "T1049": "TA0007", "T1057": "TA0007",
    "T1069": "TA0007", "T1082": "TA0007", "T1083": "TA0007",
    "T1087": "TA0007", "T1119": "TA0007", "T1120": "TA0007",
    "T1124": "TA0007", "T1135": "TA0007", "T1201": "TA0007",
    "T1217": "TA0007", "T1518": "TA0007", "T1526": "TA0007",
    "T1580": "TA0007", "T1613": "TA0007", "T1614": "TA0007",
    "T1615": "TA0007", "T1619": "TA0007", "T1622": "TA0007",
    # TA0008 Lateral Movement
    "T1210": "TA0008", "T1534": "TA0008", "T1021": "TA0008",
    "T1080": "TA0008", "T1091": "TA0008", "T1550": "TA0008",
    "T1563": "TA0008", "T1570": "TA0008", "T1072": "TA0008",
    # TA0009 Collection
    "T1005": "TA0009", "T1039": "TA0009", "T1025": "TA0009",
    "T1074": "TA0009", "T1114": "TA0009", "T1115": "TA0009",
    "T1123": "TA0009", "T1125": "TA0009", "T1185": "TA0009",
    "T1213": "TA0009", "T1530": "TA0009", "T1560": "TA0009",
    "T1602": "TA0009",
    # TA0011 C2
    "T1001": "TA0011", "T1008": "TA0011", "T1071": "TA0011",
    "T1092": "TA0011", "T1095": "TA0011", "T1102": "TA0011",
    "T1104": "TA0011", "T1105": "TA0011", "T1132": "TA0011",
    "T1568": "TA0011", "T1571": "TA0011", "T1572": "TA0011",
    "T1573": "TA0011",
    # TA0010 Exfiltration
    "T1011": "TA0010", "T1020": "TA0010", "T1022": "TA0010",
    "T1030": "TA0010", "T1041": "TA0010", "T1048": "TA0010",
    "T1052": "TA0010", "T1567": "TA0010",
    # TA0040 Impact
    "T1485": "TA0040", "T1486": "TA0040", "T1489": "TA0040",
    "T1490": "TA0040", "T1491": "TA0040", "T1495": "TA0040",
    "T1496": "TA0040", "T1498": "TA0040", "T1499": "TA0040",
    "T1529": "TA0040", "T1531": "TA0040", "T1561": "TA0040",
    "T1565": "TA0040",
    # Aliases seen in some sources
    "T1153": "TA0002",  # Source: old ATT&CK technique, maps to Execution
}

# Build reverse lookup and id maps
_TACTIC_ID_TO_INFO: dict[str, dict] = {
    tac_id: {
        "id": tac_id,
        "slug": slug,
        "label": label,
        "order": order,
    }
    for tac_id, slug, label, order in TACTICS
}


def technique_to_tactic(tech_id: str) -> str | None:
    """Map a T-code (e.g. 'T1053.002') to its parent tactic ID."""
    t = tech_id.strip().upper()
    # Exact match first
    if t in _TECH_TO_TACTIC:
        return _TECH_TO_TACTIC[t]
    # Sub-technique: try parent (T1xxx from T1xxx.yyy)
    if "." in t:
        parent = t.split(".")[0]
        if parent in _TECH_TO_TACTIC:
            return _TECH_TO_TACTIC[parent]
    return None


def _parse_techniques(raw: str) -> list[str]:
    if not raw:
        return []
    return [t.strip().upper() for t in raw.split(",") if t.strip()]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TacticCoverage:
    tactic_id: str
    tactic_label: str
    tactic_order: int
    technique_count: int
    article_count: int
    top_techniques: list[dict]   # [{id, count}, ...]
    sample_articles: list[dict]  # [{title, url, source, published_at}, ...]


@dataclass
class ArticleKillChain:
    article_id: str
    title: str
    url: str
    source_label: str
    published_at: str
    tactic_ids: list[str]
    tactic_labels: list[str]
    techniques: list[str]
    chain_length: int            # number of distinct tactics covered
    is_multi_stage: bool         # True if >= 3 tactics


@dataclass
class KillChainResult:
    tactic_coverage: list[TacticCoverage]
    multi_stage_articles: list[ArticleKillChain]
    total_articles_with_techniques: int
    total_techniques_seen: int
    window_hours: int

    def to_dict(self) -> dict:
        return {
            "window_hours": self.window_hours,
            "total_articles_with_techniques": self.total_articles_with_techniques,
            "total_techniques_seen": self.total_techniques_seen,
            "tactic_coverage": [
                {
                    "tactic_id": t.tactic_id,
                    "tactic_label": t.tactic_label,
                    "tactic_order": t.tactic_order,
                    "technique_count": t.technique_count,
                    "article_count": t.article_count,
                    "top_techniques": t.top_techniques,
                    "sample_articles": t.sample_articles,
                }
                for t in self.tactic_coverage
            ],
            "multi_stage_articles": [
                {
                    "article_id": a.article_id,
                    "title": a.title,
                    "url": a.url,
                    "source_label": a.source_label,
                    "published_at": a.published_at,
                    "tactic_ids": a.tactic_ids,
                    "tactic_labels": a.tactic_labels,
                    "techniques": a.techniques,
                    "chain_length": a.chain_length,
                    "is_multi_stage": a.is_multi_stage,
                }
                for a in self.multi_stage_articles
            ],
        }


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------


def analyze_kill_chains(
    articles: Iterable[dict],
    window_hours: int = 168,
) -> KillChainResult:
    """
    For every article in the corpus:
      1. Parse the mitre_techniques column
      2. Map each T-code to its ATT&CK tactic
      3. Accumulate per-tactic statistics
      4. Flag articles that cover >= 3 distinct tactics (multi-stage campaigns)
    """
    articles_list = list(articles)

    # Per-tactic accumulators
    tactic_tech_counts: dict[str, dict[str, int]] = {
        t[0]: {} for t in TACTICS
    }
    tactic_articles: dict[str, list[dict]] = {t[0]: [] for t in TACTICS}
    tactic_article_ids: dict[str, set[str]] = {t[0]: set() for t in TACTICS}

    article_chains: list[ArticleKillChain] = []
    total_with_tech = 0
    all_techniques_seen: set[str] = set()

    for art in articles_list:
        raw = art.get("mitre_techniques") or ""
        techs = _parse_techniques(raw)
        if not techs:
            continue

        total_with_tech += 1
        all_techniques_seen.update(techs)

        tactic_set: set[str] = set()
        for tech in techs:
            tac_id = technique_to_tactic(tech)
            if not tac_id:
                continue
            tactic_set.add(tac_id)
            tactic_tech_counts[tac_id][tech] = (
                tactic_tech_counts[tac_id].get(tech, 0) + 1
            )
            art_id = art.get("id") or art.get("url") or art.get("title") or ""
            if art_id not in tactic_article_ids[tac_id]:
                tactic_article_ids[tac_id].add(art_id)
                stub = {
                    "title": (art.get("title") or "")[:180],
                    "url": art.get("url") or "",
                    "source_label": art.get("source_label") or "",
                    "published_at": art.get("published_at") or "",
                }
                if len(tactic_articles[tac_id]) < 5:
                    tactic_articles[tac_id].append(stub)

        if not tactic_set:
            continue

        tactic_ids_sorted = sorted(
            tactic_set,
            key=lambda tid: _TACTIC_ID_TO_INFO.get(tid, {}).get("order", 99),
        )
        tactic_labels = [
            _TACTIC_ID_TO_INFO.get(tid, {}).get("label", tid)
            for tid in tactic_ids_sorted
        ]
        chain_len = len(tactic_ids_sorted)
        article_chains.append(
            ArticleKillChain(
                article_id=art.get("id") or art.get("url") or "",
                title=(art.get("title") or "")[:180],
                url=art.get("url") or "",
                source_label=art.get("source_label") or "",
                published_at=art.get("published_at") or "",
                tactic_ids=tactic_ids_sorted,
                tactic_labels=tactic_labels,
                techniques=techs,
                chain_length=chain_len,
                is_multi_stage=chain_len >= 3,
            )
        )

    # Build TacticCoverage objects for tactics that have data
    coverage: list[TacticCoverage] = []
    for tac_id, slug, label, order in TACTICS:
        tech_counts = tactic_tech_counts.get(tac_id, {})
        art_count = len(tactic_article_ids.get(tac_id, set()))
        if not tech_counts and not art_count:
            continue
        top_techs = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        coverage.append(
            TacticCoverage(
                tactic_id=tac_id,
                tactic_label=label,
                tactic_order=order,
                technique_count=len(tech_counts),
                article_count=art_count,
                top_techniques=[{"id": tid, "count": cnt} for tid, cnt in top_techs],
                sample_articles=tactic_articles.get(tac_id, [])[:5],
            )
        )
    coverage.sort(key=lambda t: t.tactic_order)

    # Multi-stage articles sorted by chain length desc
    multi_stage = sorted(
        [a for a in article_chains if a.is_multi_stage],
        key=lambda a: a.chain_length,
        reverse=True,
    )

    return KillChainResult(
        tactic_coverage=coverage,
        multi_stage_articles=multi_stage[:20],
        total_articles_with_techniques=total_with_tech,
        total_techniques_seen=len(all_techniques_seen),
        window_hours=window_hours,
    )
