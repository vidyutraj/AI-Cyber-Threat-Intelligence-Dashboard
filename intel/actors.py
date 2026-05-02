"""
Threat Actor Clustering
=======================
Maps articles to known threat actors via alias matching, then aggregates the
IOCs, CVEs, MITRE techniques, and source counts per actor.

The actor dictionary covers major nation-state APTs, ransomware groups, and
financially motivated threat actors that appear frequently in cyber news.
Aliases use the most common names across vendor naming conventions (Mandiant,
CrowdStrike, MSFT Threat Intelligence, MITRE ATT&CK).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

# ── Threat actor dictionary ───────────────────────────────────────────────────
# Format: actor_name -> { aliases, origin, motives, description }
THREAT_ACTORS: dict[str, dict] = {
    "APT29": {
        "aliases": ["APT29", "Cozy Bear", "NOBELIUM", "Midnight Blizzard",
                    "The Dukes", "SVR", "Yttrium"],
        "origin": "Russia",
        "motives": ["espionage", "intelligence_collection"],
        "description": "Russian SVR-linked group targeting governments & think tanks",
    },
    "APT28": {
        "aliases": ["APT28", "Fancy Bear", "SOFACY", "Strontium", "Forest Blizzard",
                    "Pawn Storm", "Sednit", "GRU"],
        "origin": "Russia",
        "motives": ["espionage", "information_operations"],
        "description": "Russian GRU-linked group targeting NATO, gov, elections",
    },
    "Sandworm": {
        "aliases": ["Sandworm", "Voodoo Bear", "Seashell Blizzard", "TeleBots",
                    "Electrum", "IRIDIUM"],
        "origin": "Russia",
        "motives": ["sabotage", "espionage"],
        "description": "Russian GRU Unit 74455; responsible for NotPetya and industrial attacks",
    },
    "Lazarus Group": {
        "aliases": ["Lazarus", "Lazarus Group", "Hidden Cobra", "ZINC", "Guardians of Peace",
                    "Diamond Sleet", "Labyrinth Chollima"],
        "origin": "North Korea",
        "motives": ["financial", "espionage"],
        "description": "North Korean state-sponsored group targeting crypto, banks, defense",
    },
    "Kimsuky": {
        "aliases": ["Kimsuky", "Velvet Chollima", "Black Banshee", "Thallium",
                    "APT43", "Emerald Sleet"],
        "origin": "North Korea",
        "motives": ["espionage", "intelligence_collection"],
        "description": "North Korean group targeting South Korea, nuclear policy researchers",
    },
    "APT41": {
        "aliases": ["APT41", "Double Dragon", "Winnti", "Barium", "Wicked Panda",
                    "Brass Typhoon"],
        "origin": "China",
        "motives": ["espionage", "financial", "supply_chain"],
        "description": "Chinese group blending state espionage with financially motivated attacks",
    },
    "Volt Typhoon": {
        "aliases": ["Volt Typhoon", "Bronze Silhouette", "Vanguard Panda", "Dev-0391",
                    "BRONZE SILHOUETTE"],
        "origin": "China",
        "motives": ["espionage", "critical_infrastructure", "pre_positioning"],
        "description": "Chinese group targeting US critical infrastructure for pre-positioning",
    },
    "Salt Typhoon": {
        "aliases": ["Salt Typhoon", "RedMike", "GhostEmperor", "FamousSparrow"],
        "origin": "China",
        "motives": ["espionage", "telecom"],
        "description": "Chinese group conducting telecom wiretapping campaigns",
    },
    "LockBit": {
        "aliases": ["LockBit", "LockBit 2.0", "LockBit 3.0", "LockBit Black",
                    "LockBit Green", "ABCD"],
        "origin": "Unknown",
        "motives": ["financial", "ransomware"],
        "description": "Prolific ransomware-as-a-service operation",
    },
    "BlackCat": {
        "aliases": ["BlackCat", "ALPHV", "Noberus"],
        "origin": "Unknown",
        "motives": ["financial", "ransomware"],
        "description": "Rust-based ransomware-as-a-service targeting enterprises",
    },
    "Cl0p": {
        "aliases": ["Cl0p", "Clop", "TA505", "FIN11", "GRACEFUL SPIDER"],
        "origin": "Russia",
        "motives": ["financial", "ransomware", "extortion"],
        "description": "Russian group exploiting zero-days for mass extortion campaigns",
    },
    "Scattered Spider": {
        "aliases": ["Scattered Spider", "UNC3944", "Oktapus", "Starfraud",
                    "Roasted 0ktapus", "Muddled Libra"],
        "origin": "Western",
        "motives": ["financial", "ransomware"],
        "description": "English-speaking group using social engineering and SIM-swapping",
    },
    "REvil": {
        "aliases": ["REvil", "Sodinokibi", "Gold Southfield", "Pinchy Spider"],
        "origin": "Russia",
        "motives": ["financial", "ransomware"],
        "description": "Russian RaaS group responsible for Kaseya and JBS attacks",
    },
    "Conti": {
        "aliases": ["Conti", "Wizard Spider", "Gold Ulrick"],
        "origin": "Russia",
        "motives": ["financial", "ransomware"],
        "description": "Russian cybercrime group; leaked internal playbooks in 2022",
    },
    "BlackBasta": {
        "aliases": ["Black Basta", "BlackBasta"],
        "origin": "Russia",
        "motives": ["financial", "ransomware"],
        "description": "Ransomware group believed to be a Conti successor",
    },
    "TA453": {
        "aliases": ["TA453", "Charming Kitten", "APT35", "Phosphorus",
                    "Ballistic Bobcat", "Mint Sandstorm"],
        "origin": "Iran",
        "motives": ["espionage", "phishing"],
        "description": "Iranian IRGC-linked group targeting journalists and researchers",
    },
    "MuddyWater": {
        "aliases": ["MuddyWater", "Mercury", "Static Kitten", "Mango Sandstorm", "TA450"],
        "origin": "Iran",
        "motives": ["espionage", "destructive"],
        "description": "Iranian group targeting government, telco, and energy sectors",
    },
}

# Pre-compile per-actor regex for fast matching
_ACTOR_PATTERNS: dict[str, re.Pattern] = {}
for _actor, _meta in THREAT_ACTORS.items():
    _terms = sorted(set(_meta["aliases"]), key=len, reverse=True)
    _pattern = "|".join(re.escape(t) for t in _terms)
    _ACTOR_PATTERNS[_actor] = re.compile(rf"\b(?:{_pattern})\b", re.IGNORECASE)


# ── Output types ──────────────────────────────────────────────────────────────

@dataclass
class ActorProfile:
    actor: str
    origin: str
    motives: list[str]
    description: str
    article_count: int
    source_breadth: int
    cves: list[str]
    iocs: dict[str, list[str]]   # {type: [values]}
    mitre_techniques: list[str]
    sample_articles: list[dict]  # up to 5 stubs

    def to_dict(self) -> dict:
        return asdict(self)


# ── Core function ─────────────────────────────────────────────────────────────

def identify_actors(articles: list[dict]) -> list[ActorProfile]:
    """
    Match articles to threat actors and build per-actor intelligence profiles.
    Returns actors sorted by article count (most mentioned first).
    """
    # actor -> {articles, sources, cves, iocs, techniques}
    matched: dict[str, dict] = {}

    for art in articles:
        text = " ".join([
            art.get("title") or "",
            art.get("description") or "",
            art.get("full_text") or "",
        ])
        matched_actors: list[str] = []
        for actor, pattern in _ACTOR_PATTERNS.items():
            if pattern.search(text):
                matched_actors.append(actor)

        for actor in matched_actors:
            if actor not in matched:
                matched[actor] = {
                    "articles": [],
                    "sources": set(),
                    "cves": set(),
                    "iocs": {"ip": set(), "domain": set(), "hash": set(), "malware": set()},
                    "techniques": set(),
                }
            entry = matched[actor]
            entry["articles"].append(art)
            entry["sources"].add(art.get("source_label") or art.get("source_key") or "")

            # Aggregate CVEs
            for cve in (t.strip().upper() for t in (art.get("cves") or "").split(",") if t.strip()):
                entry["cves"].add(cve)

            # Aggregate IOCs
            for field, itype in [("ips", "ip"), ("domains", "domain"),
                                   ("hashes", "hash"), ("malware_tools", "malware")]:
                for tok in (t.strip() for t in (art.get(field) or "").split(",") if t.strip()):
                    entry["iocs"][itype].add(tok)

            # Aggregate MITRE techniques
            for tech in (t.strip() for t in (art.get("mitre_techniques") or "").split(",") if t.strip()):
                entry["techniques"].add(tech)

    profiles: list[ActorProfile] = []
    for actor, data in matched.items():
        meta = THREAT_ACTORS.get(actor, {})
        arts = sorted(data["articles"], key=lambda a: a.get("published_at") or "", reverse=True)
        stubs = [
            {
                "title": (a.get("title") or "")[:180],
                "source_label": a.get("source_label") or "",
                "published_at": (a.get("published_at") or "")[:10],
                "url": a.get("url") or "",
            }
            for a in arts[:5]
        ]
        profiles.append(ActorProfile(
            actor=actor,
            origin=meta.get("origin", "Unknown"),
            motives=meta.get("motives", []),
            description=meta.get("description", ""),
            article_count=len(data["articles"]),
            source_breadth=len(data["sources"]),
            cves=sorted(data["cves"])[:20],
            iocs={k: sorted(v)[:15] for k, v in data["iocs"].items()},
            mitre_techniques=sorted(data["techniques"])[:20],
            sample_articles=stubs,
        ))

    profiles.sort(key=lambda p: p.article_count, reverse=True)
    return profiles
