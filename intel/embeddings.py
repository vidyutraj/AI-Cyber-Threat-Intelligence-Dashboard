"""
Semantic embedding engine with SQLite-backed KNN search.

This turns the article corpus into a proper vector space.  Every article is
embedded once and the vector is persisted to SQLite so:

  - Embeddings survive server restarts (unlike the old in-memory dict)
  - New articles are embedded incrementally (no full re-embed on startup)
  - KNN search is cosine-similarity over the cached vectors — the same
    mathematical primitive used inside Pinecone / Weaviate, but without
    the external service

When OpenAI is available we use text-embedding-3-small (1536-d).  As a
zero-dependency fallback we provide a TF-IDF cosine engine so the endpoint
still works even without an API key.

The KNN retrieval path is:
  1.  Embed the query text                          (OpenAI or TF-IDF)
  2.  Load all cached article vectors from SQLite   (lazy, first-call only)
  3.  Compute cosine similarity to every vector     (pure Python, O(n))
  4.  Return top-k sorted by descending similarity  (k is typically 8-12)

For the corpora we're working with (100s of articles) this is instant.
Beyond ~100 k articles we'd switch to an HNSW index; the interface is
identical so swapping it out later costs nothing.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from .storage import connect

LOG = logging.getLogger("intel.embeddings")

_EMBEDDING_MODEL = "text-embedding-3-small"
_SCHEMA_STMT = """
CREATE TABLE IF NOT EXISTS article_embeddings (
    article_id    TEXT PRIMARY KEY,
    source_key    TEXT,
    source_label  TEXT,
    url           TEXT,
    title         TEXT,
    published_at  TEXT,
    text_snippet  TEXT,
    vector_json   TEXT NOT NULL,
    model         TEXT NOT NULL,
    embedded_at   TEXT NOT NULL
)
"""

# In-process cache: loaded once per process lifetime to avoid repeated
# SQLite reads on every search query.
_VECTOR_CACHE: list[tuple[list[float], dict]] | None = None
_TFIDF_ENGINE: "_TfIdfIndex | None" = None


# ---------------------------------------------------------------------------
# TF-IDF fallback (no API key needed)
# ---------------------------------------------------------------------------


class _TfIdfIndex:
    """
    Lightweight TF-IDF cosine similarity engine.  No numpy required.

    Backed by a vocabulary of the top-N document-frequency terms across the
    corpus, with IDF weighting.  Gives surprisingly good results for
    same-domain text (cybersecurity articles) because the vocabulary is
    narrow.
    """

    _STOP = frozenset(
        "a an the and or in of to is are was were be been being have has had "
        "do does did will would could should may might shall can cannot "
        "i we you he she they it its this that these those for with at from "
        "on by about into through during before after above below between "
        "out up down over under again further then once here there when where "
        "why how all both each few more most other some such no nor not only "
        "own same so than too very s t just don didn't doesn't wasn't".split()
    )
    _RE = re.compile(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*")

    def __init__(self, docs: list[tuple[dict, str]]) -> None:
        self._docs = docs  # [(meta, text), ...]
        n = len(docs)
        if n == 0:
            self._idf: dict[str, float] = {}
            self._doc_vecs: list[dict[str, float]] = []
            return

        # Term → document-frequency count
        df: dict[str, int] = {}
        tokenized: list[list[str]] = []
        for _, text in docs:
            tokens = self._tokenize(text)
            tokenized.append(tokens)
            for tok in set(tokens):
                df[tok] = df.get(tok, 0) + 1

        # IDF: log((N+1)/(df+1)) + 1  (smoothed)
        self._idf = {
            tok: math.log((n + 1) / (freq + 1)) + 1
            for tok, freq in df.items()
            if freq >= 2  # skip hapax legomena
        }

        # Normalised TF-IDF vectors per document
        self._doc_vecs = []
        for tokens in tokenized:
            vec = self._tfidf_vec(tokens)
            self._doc_vecs.append(vec)

    def _tokenize(self, text: str) -> list[str]:
        return [
            t
            for t in self._RE.findall(text.lower())
            if t not in self._STOP and len(t) > 1
        ]

    def _tfidf_vec(self, tokens: list[str]) -> dict[str, float]:
        tf: dict[str, int] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1
        vec: dict[str, float] = {}
        for tok, count in tf.items():
            if tok in self._idf:
                vec[tok] = (count / max(len(tokens), 1)) * self._idf[tok]
        # L2-normalise
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {k: v / norm for k, v in vec.items()}

    def _cosine(self, a: dict[str, float], b: dict[str, float]) -> float:
        shared = set(a) & set(b)
        return sum(a[k] * b[k] for k in shared)

    def query(self, text: str, top_k: int = 8) -> list[tuple[float, dict]]:
        tokens = self._tokenize(text)
        qvec = self._tfidf_vec(tokens)
        if not qvec:
            return []
        scored = [
            (self._cosine(qvec, dvec), meta)
            for (meta, _), dvec in zip(self._docs, self._doc_vecs)
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [(s, m) for s, m in scored if s > 0][:top_k]


# ---------------------------------------------------------------------------
# OpenAI helpers
# ---------------------------------------------------------------------------


def _cosine_sim(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


def _article_text(art: dict) -> str:
    return " ".join(
        filter(
            None,
            [
                art.get("title") or "",
                art.get("description") or "",
                art.get("categories") or "",
                art.get("cves") or "",
                art.get("malware_tools") or "",
                art.get("mitre_techniques") or "",
                art.get("domains") or "",
                art.get("ips") or "",
            ],
        )
    )[:4096]


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------


def _init_schema() -> None:
    with connect() as conn:
        conn.execute(_SCHEMA_STMT)


def _load_all_vectors() -> list[tuple[list[float], dict]]:
    _init_schema()
    with connect() as conn:
        rows = conn.execute(
            "SELECT article_id, source_key, source_label, url, title, "
            "published_at, text_snippet, vector_json FROM article_embeddings"
        ).fetchall()
    out: list[tuple[list[float], dict]] = []
    for row in rows:
        try:
            vec = json.loads(row["vector_json"])
        except Exception:
            continue
        meta = {
            "id": row["article_id"],
            "source_key": row["source_key"],
            "source_label": row["source_label"],
            "url": row["url"],
            "title": row["title"],
            "published_at": row["published_at"],
            "snippet": row["text_snippet"],
        }
        out.append((vec, meta))
    return out


def _store_vectors(rows: list[tuple[str, dict, list[float], str]]) -> None:
    """rows = [(article_id, meta_dict, vector, model_name)]"""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _init_schema()
    with connect() as conn:
        conn.executemany(
            """
            INSERT INTO article_embeddings
                (article_id, source_key, source_label, url, title,
                 published_at, text_snippet, vector_json, model, embedded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(article_id) DO NOTHING
            """,
            [
                (
                    article_id,
                    meta.get("source_key", ""),
                    meta.get("source_label", ""),
                    meta.get("url", ""),
                    meta.get("title", ""),
                    meta.get("published_at", ""),
                    _article_text(meta)[:512],
                    json.dumps(vec),
                    model,
                    now,
                )
                for article_id, meta, vec, model in rows
            ],
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class SimilarArticle:
    score: float
    article_id: str
    source_label: str
    title: str
    url: str
    published_at: str
    snippet: str

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 4),
            "id": self.article_id,
            "source_label": self.source_label,
            "title": self.title,
            "url": self.url,
            "published_at": self.published_at,
            "snippet": self.snippet,
        }


def embed_articles(
    articles: list[dict],
    api_key: str | None = None,
    model: str = _EMBEDDING_MODEL,
    batch_size: int = 64,
) -> int:
    """
    Embed any articles not already in the cache.  Returns the number of
    newly embedded articles.  Falls back to TF-IDF if no OpenAI key.
    """
    global _VECTOR_CACHE, _TFIDF_ENGINE

    _init_schema()

    # Find which articles are already cached
    existing_ids: set[str] = set()
    with connect() as conn:
        for row in conn.execute("SELECT article_id FROM article_embeddings"):
            existing_ids.add(row["article_id"])

    new_arts = [a for a in articles if a.get("id") and a["id"] not in existing_ids]
    if not new_arts:
        _VECTOR_CACHE = None  # invalidate so it reloads on next query
        return 0

    api_key = api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        LOG.info("No OpenAI key — TF-IDF fallback active, skipping vector storage")
        _TFIDF_ENGINE = None  # force rebuild
        return 0

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
    except ImportError:
        LOG.warning("openai package not available")
        return 0

    stored = 0
    for i in range(0, len(new_arts), batch_size):
        batch = new_arts[i : i + batch_size]
        texts = [_article_text(a) for a in batch]
        try:
            resp = client.embeddings.create(model=model, input=texts)
            rows_to_store = [
                (batch[j]["id"], batch[j], list(resp.data[j].embedding), model)
                for j in range(len(batch))
            ]
            _store_vectors(rows_to_store)
            stored += len(rows_to_store)
        except Exception as exc:
            LOG.warning("Embedding batch failed: %s", exc)

    _VECTOR_CACHE = None  # invalidate cache so next search reloads fresh
    return stored


def semantic_search(
    query: str,
    articles: list[dict],
    top_k: int = 10,
    api_key: str | None = None,
) -> list[SimilarArticle]:
    """
    Find the `top_k` articles most semantically similar to `query`.

    Tries OpenAI embeddings first; falls back to TF-IDF cosine similarity
    if no API key is configured.  The interface is identical either way.
    """
    global _VECTOR_CACHE, _TFIDF_ENGINE

    api_key = api_key or os.getenv("OPENAI_API_KEY")

    if api_key:
        return _openai_search(query, articles, top_k, api_key)
    else:
        return _tfidf_search(query, articles, top_k)


def _openai_search(
    query: str,
    articles: list[dict],
    top_k: int,
    api_key: str,
) -> list[SimilarArticle]:
    global _VECTOR_CACHE

    # Lazy-embed any uncached articles
    embed_articles(articles, api_key=api_key)

    # Reload vector cache if invalidated
    if _VECTOR_CACHE is None:
        _VECTOR_CACHE = _load_all_vectors()

    if not _VECTOR_CACHE:
        return _tfidf_search(query, articles, top_k)

    # Embed the query
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        resp = client.embeddings.create(model=_EMBEDDING_MODEL, input=[query])
        qvec = list(resp.data[0].embedding)
    except Exception as exc:
        LOG.warning("Query embedding failed, falling back to TF-IDF: %s", exc)
        return _tfidf_search(query, articles, top_k)

    scored: list[tuple[float, dict]] = []
    for vec, meta in _VECTOR_CACHE:
        sim = _cosine_sim(qvec, vec)
        if sim > 0.1:
            scored.append((sim, meta))
    scored.sort(key=lambda x: x[0], reverse=True)

    return [
        SimilarArticle(
            score=s,
            article_id=m["id"],
            source_label=m["source_label"],
            title=m["title"],
            url=m["url"],
            published_at=m["published_at"],
            snippet=m["snippet"],
        )
        for s, m in scored[:top_k]
    ]


def _tfidf_search(
    query: str,
    articles: list[dict],
    top_k: int,
) -> list[SimilarArticle]:
    global _TFIDF_ENGINE

    if _TFIDF_ENGINE is None:
        docs = [(a, _article_text(a)) for a in articles if a.get("title")]
        _TFIDF_ENGINE = _TfIdfIndex(docs)

    results = _TFIDF_ENGINE.query(query, top_k=top_k)
    return [
        SimilarArticle(
            score=s,
            article_id=(m.get("id") or ""),
            source_label=(m.get("source_label") or ""),
            title=(m.get("title") or ""),
            url=(m.get("url") or ""),
            published_at=(m.get("published_at") or ""),
            snippet=(_article_text(m)[:300]),
        )
        for s, m in results
    ]


def get_embedding_stats() -> dict[str, Any]:
    _init_schema()
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM article_embeddings").fetchone()[0]
        models = conn.execute(
            "SELECT model, COUNT(*) as n FROM article_embeddings GROUP BY model"
        ).fetchall()
    return {
        "total_cached": total,
        "by_model": [{"model": r["model"], "count": r["n"]} for r in models],
    }
