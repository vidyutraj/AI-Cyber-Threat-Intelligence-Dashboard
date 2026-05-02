"""
Near-duplicate article clustering with MinHash + banded LSH.

Why this exists:
  The same breaking security story is often reported by 4+ outlets (THN,
  BleepingComputer, Dark Reading, Krebs).  Counting them as 4 separate items
  distorts every downstream metric (coverage, IOC frequency, "trending"
  detection).  We need a real near-duplicate detector.

Approach:
  1. For each article we build a set of word k-shingles from (title +
     description).
  2. A MinHash signature approximates Jaccard similarity between two articles
     with k*len hash functions.  We use ~128 hashes for a good accuracy/cost
     tradeoff.
  3. Locality Sensitive Hashing (LSH) with `b` bands of `r` rows lets us
     query candidate pairs in O(n) without all-pairs comparison.  Articles
     that share any band-bucket become candidates and we compute the real
     MinHash Jaccard to confirm.
  4. Connected components over the candidate graph = clusters.

This implementation is pure Python, no heavy dependencies; it's exactly the
kind of algorithm used in production newsroom dedup pipelines.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field


# --- configuration -----------------------------------------------------------
DEFAULT_NUM_PERM = 128        # number of MinHash permutations
DEFAULT_BANDS = 32            # LSH bands
DEFAULT_ROWS_PER_BAND = 4     # = NUM_PERM / BANDS
CHAR_NGRAM = 5                # character n-gram size for near-duplicate titles
WORD_SHINGLE_SIZE = 3         # word n-gram size for description text
JACCARD_THRESHOLD = 0.15      # confirmed near-duplicate threshold
                              # (calibrated for short news titles + entity signals)


_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _WORD_RE.findall(text or "")]


def _normalize(text: str) -> str:
    """Normalise text for char-gram hashing: lowercase, collapse whitespace."""
    return " ".join(_tokenize(text))


def _char_ngrams(text: str, k: int = CHAR_NGRAM) -> set[str]:
    norm = _normalize(text)
    if len(norm) <= k:
        return {norm}
    return {norm[i : i + k] for i in range(len(norm) - k + 1)}


def _word_shingles(text: str, k: int = WORD_SHINGLE_SIZE) -> set[str]:
    words = _tokenize(text)
    if len(words) < k:
        return set(words)
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def _build_feature_set(article: dict) -> set[str]:
    """
    Build the feature set that MinHash signs for an article.

    We combine three signal families because news dedup requires more than
    raw bag-of-words similarity:

    - Character 5-grams over the title (handles reword/paraphrase)
    - Word 3-gram shingles over title+description (captures phrasing)
    - Entity tokens (CVEs, malware, domains) prefixed to stay distinctive
    """
    title = article.get("title") or ""
    desc = article.get("description") or ""

    feats: set[str] = set()
    feats.update(f"c:{g}" for g in _char_ngrams(title))
    feats.update(f"w:{s}" for s in _word_shingles(f"{title} {desc}"))

    def _entities(field: str, prefix: str) -> None:
        raw = (article.get(field) or "").strip()
        if not raw:
            return
        for tok in (t.strip().lower() for t in raw.split(",")):
            if tok:
                feats.add(f"{prefix}:{tok}")

    _entities("cves", "cve")
    _entities("malware_tools", "mal")
    _entities("hashes", "h")
    _entities("domains", "dom")

    return feats


# Kept as a helper alias so the rest of the file (and any downstream users)
# don't need to care which feature set we're using.
def _shingles(text: str, k: int = WORD_SHINGLE_SIZE) -> set[str]:
    return _word_shingles(text, k=k)


# ---------------------------------------------------------------------------
# MinHash
# ---------------------------------------------------------------------------


_MERSENNE_PRIME = (1 << 61) - 1
_INIT_SIG = _MERSENNE_PRIME  # any value >= prime; the min over permutations updates from here


class MinHasher:
    """Seeded MinHash implementation using 2-universal hashing (ax+b mod p)."""

    def __init__(self, num_perm: int = DEFAULT_NUM_PERM, seed: int = 42) -> None:
        self.num_perm = num_perm
        rng = random.Random(seed)
        self._a = [rng.randint(1, _MERSENNE_PRIME - 1) for _ in range(num_perm)]
        self._b = [rng.randint(0, _MERSENNE_PRIME - 1) for _ in range(num_perm)]

    def signature(self, shingles: set[str]) -> list[int]:
        if not shingles:
            return [_INIT_SIG] * self.num_perm
        sig = [_INIT_SIG] * self.num_perm
        for sh in shingles:
            h = int(hashlib.blake2b(sh.encode("utf-8"), digest_size=8).hexdigest(), 16)
            h %= _MERSENNE_PRIME
            for i in range(self.num_perm):
                v = (self._a[i] * h + self._b[i]) % _MERSENNE_PRIME
                if v < sig[i]:
                    sig[i] = v
        return sig


def estimated_jaccard(sig_a: list[int], sig_b: list[int]) -> float:
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return matches / len(sig_a)


# ---------------------------------------------------------------------------
# LSH index
# ---------------------------------------------------------------------------


class LSHIndex:
    def __init__(
        self,
        num_perm: int = DEFAULT_NUM_PERM,
        bands: int = DEFAULT_BANDS,
        rows_per_band: int = DEFAULT_ROWS_PER_BAND,
    ) -> None:
        if bands * rows_per_band != num_perm:
            raise ValueError(
                f"bands*rows_per_band must equal num_perm ({bands*rows_per_band} != {num_perm})"
            )
        self.num_perm = num_perm
        self.bands = bands
        self.rows = rows_per_band
        self._buckets: dict[tuple[int, bytes], list[str]] = defaultdict(list)
        self._sigs: dict[str, list[int]] = {}

    def add(self, key: str, sig: list[int]) -> None:
        self._sigs[key] = sig
        for band_idx in range(self.bands):
            start = band_idx * self.rows
            chunk = bytes.fromhex(
                "".join(f"{(x & 0xFFFFFFFFFFFFFFFF):016x}" for x in sig[start : start + self.rows])
            )
            self._buckets[(band_idx, chunk)].append(key)

    def candidate_pairs(self) -> set[tuple[str, str]]:
        pairs: set[tuple[str, str]] = set()
        for keys in self._buckets.values():
            if len(keys) < 2:
                continue
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    a, b = keys[i], keys[j]
                    if a == b:
                        continue
                    pair = (a, b) if a < b else (b, a)
                    pairs.add(pair)
        return pairs


# ---------------------------------------------------------------------------
# Union-Find for clustering candidate pairs
# ---------------------------------------------------------------------------


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        if x not in self.parent:
            self.parent[x] = x

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: str, y: str) -> None:
        self.add(x)
        self.add(y)
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[rx] = ry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ArticleCluster:
    cluster_id: int
    article_ids: list[str]
    representative_id: str
    max_jaccard: float
    sources: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)


@dataclass
class ClusterResult:
    clusters: list[ArticleCluster]
    total_articles: int
    duplicates: int  # articles in multi-article clusters (coverage redundancy)

    def to_dict(self) -> dict:
        return {
            "total_articles": self.total_articles,
            "duplicates": self.duplicates,
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "representative_id": c.representative_id,
                    "article_ids": c.article_ids,
                    "sources": c.sources,
                    "titles": c.titles,
                    "max_jaccard": c.max_jaccard,
                }
                for c in self.clusters
            ],
        }


def cluster_articles_minhash(
    articles: list[dict],
    num_perm: int = DEFAULT_NUM_PERM,
    bands: int = DEFAULT_BANDS,
    rows_per_band: int = DEFAULT_ROWS_PER_BAND,
    jaccard_threshold: float = JACCARD_THRESHOLD,
) -> ClusterResult:
    if not articles:
        return ClusterResult(clusters=[], total_articles=0, duplicates=0)

    hasher = MinHasher(num_perm=num_perm)
    lsh = LSHIndex(num_perm=num_perm, bands=bands, rows_per_band=rows_per_band)

    sigs: dict[str, list[int]] = {}
    meta: dict[str, dict] = {}
    for art in articles:
        key = (art.get("id") or art.get("url") or art.get("title") or "").strip()
        if not key:
            continue
        title = (art.get("title") or "").strip()
        feats = _build_feature_set(art)
        if not feats:
            continue
        sig = hasher.signature(feats)
        sigs[key] = sig
        meta[key] = {
            "title": title[:200],
            "source": art.get("source_label") or art.get("source") or "",
        }
        lsh.add(key, sig)

    uf = _UnionFind()
    for key in sigs:
        uf.add(key)

    pair_jaccard: dict[tuple[str, str], float] = {}
    for a, b in lsh.candidate_pairs():
        j = estimated_jaccard(sigs[a], sigs[b])
        if j >= jaccard_threshold:
            uf.union(a, b)
            pair_jaccard[(a, b)] = j

    buckets: dict[str, list[str]] = defaultdict(list)
    for key in sigs:
        buckets[uf.find(key)].append(key)

    clusters: list[ArticleCluster] = []
    duplicates = 0
    for idx, (_, members) in enumerate(
        sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True)
    ):
        max_j = 0.0
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                key = (members[i], members[j]) if members[i] < members[j] else (
                    members[j],
                    members[i],
                )
                if key in pair_jaccard and pair_jaccard[key] > max_j:
                    max_j = pair_jaccard[key]
        if len(members) > 1:
            duplicates += len(members)
        clusters.append(
            ArticleCluster(
                cluster_id=idx,
                article_ids=sorted(members),
                representative_id=members[0],
                max_jaccard=round(max_j, 4),
                sources=sorted({meta[m]["source"] for m in members if meta[m]["source"]}),
                titles=[meta[m]["title"] for m in members[:4]],
            )
        )

    return ClusterResult(
        clusters=clusters,
        total_articles=len(sigs),
        duplicates=duplicates,
    )
