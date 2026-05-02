"""
IOC trend / anomaly detection.

We turn the corpus of articles into a per-IOC daily time series, then apply
Exponentially Weighted Moving Average (EWMA) baselines with a rolling
standard deviation to flag IOCs that are *spiking* relative to their recent
history.

This is a lightweight version of the detectors that surface in CTI platforms
as "emerging threats" — it answers "is this CVE unusually hot *right now*?",
not just "how often has it been mentioned?"
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


# --- tuning ------------------------------------------------------------------
# EWMA alpha: higher = more responsive, lower = smoother baseline.
_DEFAULT_ALPHA = 0.35
# Require at least this many days of history before we're willing to score a
# spike (otherwise the first day of data trivially "spikes").
_MIN_HISTORY_DAYS = 5
# z-score threshold to flag a spike
_DEFAULT_Z_THRESHOLD = 2.0
# Minimum count today to avoid trivial spikes (e.g. 1 mention vs baseline 0.1)
_MIN_TODAY_COUNT = 2


@dataclass
class TrendSignal:
    ioc_type: str
    value: str
    today_count: int
    baseline: float
    stddev: float
    z_score: float
    history: list[tuple[str, int]] = field(default_factory=list)  # [(day, count)]
    sample_articles: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "today_count": self.today_count,
            "baseline": round(self.baseline, 3),
            "stddev": round(self.stddev, 3),
            "z_score": round(self.z_score, 3),
            "history": [{"day": d, "count": c} for d, c in self.history],
            "sample_articles": self.sample_articles,
        }


def _parse_day(published_at: str) -> str | None:
    raw = (published_at or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _iter_ioc_mentions(article: dict) -> list[tuple[str, str]]:
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
    return out


def _ewma_and_stddev(values: list[int], alpha: float) -> tuple[float, float]:
    """Return (ewma_mean, sample_stddev) for the given series."""
    if not values:
        return (0.0, 0.0)
    mean = float(values[0])
    for v in values[1:]:
        mean = alpha * v + (1 - alpha) * mean
    if len(values) < 2:
        return (mean, 0.0)
    var = sum((v - mean) ** 2 for v in values) / max(1, len(values) - 1)
    return (mean, math.sqrt(var))


def compute_trending_iocs(
    articles: list[dict],
    lookback_days: int = 14,
    alpha: float = _DEFAULT_ALPHA,
    z_threshold: float = _DEFAULT_Z_THRESHOLD,
    top_n: int = 20,
) -> list[TrendSignal]:
    """
    For every IOC seen in the corpus, build a daily count series over the
    last `lookback_days`, compute an EWMA baseline + std-dev over the first
    N-1 days, and return the IOCs whose count on the most recent day exceeds
    baseline + z_threshold * stddev.  Always returns at most `top_n` signals
    ordered by z-score.
    """
    if not articles:
        return []

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime(
        "%Y-%m-%d"
    )

    # ioc -> day -> count
    series: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    # ioc -> sample article stubs (capped)
    samples: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for art in articles:
        day = _parse_day(art.get("published_at") or "")
        if not day or day < cutoff:
            continue
        mentions = _iter_ioc_mentions(art)
        if not mentions:
            continue
        stub = {
            "title": (art.get("title") or "")[:180],
            "source_label": art.get("source_label") or "",
            "published_at": art.get("published_at") or "",
            "url": art.get("url") or "",
        }
        for t, v in mentions:
            k = (t, v)
            series[k][day] += 1
            if len(samples[k]) < 4 and day == today:
                samples[k].append(stub)

    # Build candidate signals
    candidates: list[TrendSignal] = []
    for (t, v), by_day in series.items():
        # Normalise day-sequence over the full lookback window (include zeros)
        days_sorted = [
            (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
            for i in range(lookback_days)
        ][::-1]
        counts = [by_day.get(d, 0) for d in days_sorted]
        if len(counts) < _MIN_HISTORY_DAYS:
            continue

        history = counts[:-1]
        today_count = counts[-1]

        if today_count < _MIN_TODAY_COUNT:
            continue

        baseline, std = _ewma_and_stddev(history, alpha=alpha)
        # Guard against zero-variance baselines
        std_eff = std if std > 1e-6 else max(0.5, math.sqrt(max(baseline, 0.0)))
        z = (today_count - baseline) / std_eff if std_eff > 0 else 0.0

        if z < z_threshold:
            continue

        candidates.append(
            TrendSignal(
                ioc_type=t,
                value=v,
                today_count=today_count,
                baseline=baseline,
                stddev=std_eff,
                z_score=z,
                history=list(zip(days_sorted, counts)),
                sample_articles=samples.get((t, v), []),
            )
        )

    # Persist the computed series to SQLite so the ioc_daily_counts table stays
    # populated for sparklines and historical queries.
    try:
        from .storage import persist_ioc_daily_counts
        persist_ioc_daily_counts(dict(series))
    except Exception:
        pass  # never let persistence errors break the in-memory path

    candidates.sort(key=lambda s: (s.z_score, s.today_count), reverse=True)
    return candidates[:top_n]
