import argparse
import csv
import html
import re
import sys
from typing import Dict, List, Optional

from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

import requests


DEFAULT_FEED_URL = "https://feeds.feedburner.com/TheHackersNews"
DEFAULT_OUTPUT_CSV = "thehackernews_rss_articles.csv"

# External threat intelligence sources (phase 2 enrichment).
MITRE_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
# Caches for external vocabularies. These are populated lazily at runtime.
_MITRE_NAME_TO_ID: Dict[str, str] = {}


# User-Agent for RSS fetches; some sites (e.g. BleepingComputer) block default requests
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}


def fetch_feed_xml(url: str) -> str:
    resp = requests.get(url, timeout=20, headers=DEFAULT_HEADERS)
    resp.raise_for_status()
    return resp.text


def parse_pub_date(pub_date_raw: Optional[str]) -> str:
    if not pub_date_raw:
        return ""
    try:
        dt = parsedate_to_datetime(pub_date_raw)
        # Normalize to ISO 8601 string
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=None)
        return dt.isoformat()
    except Exception:
        return pub_date_raw


def _ensure_threat_feeds_loaded() -> None:
    """
    Load MITRE ATT&CK and malware vocabularies from external sources once per process.
    Falls back to a small hardcoded list if remote fetch fails.
    """
    global _MITRE_NAME_TO_ID

    if _MITRE_NAME_TO_ID:
        return

    # Load MITRE ATT&CK enterprise techniques
    try:
        resp = requests.get(MITRE_ENTERPRISE_ATTACK_URL, timeout=25)
        resp.raise_for_status()
        data = resp.json()
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            name = (obj.get("name") or "").strip()
            if not name:
                continue
            external_refs = obj.get("external_references") or []
            mitre_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    mitre_id = ref["external_id"]
                    break
            if not mitre_id:
                continue
            _MITRE_NAME_TO_ID[name.lower()] = mitre_id
    except Exception:
        # Fallback: leave mapping empty; regex-based MITRE ID extraction will still work.
        _MITRE_NAME_TO_ID = {}

    # We no longer load malware/tool vocabularies here; malware_tools is left empty.


def extract_indicators(text: str) -> Dict[str, List[str]]:
    """
    Best-effort extraction of common security indicators and entities from free text:
    - CVE IDs
    - IPv4 / IPv6 addresses
    - Domains
    - Email addresses
    - URLs
    - Hashes (MD5 / SHA1 / SHA256)
    - MITRE ATT&CK technique IDs (e.g. T1059, T1190.001)
    - Simple malware / tool names from a curated keyword list
    """
    if not text:
        return {
            "cves": [],
            "ips": [],
            "domains": [],
            "hashes": [],
            "emails": [],
            "urls": [],
            "ipv6": [],
            "mitre": [],
            "malware_tools": [],
        }

    # Ensure vocabularies are loaded exactly once per process.
    _ensure_threat_feeds_loaded()

    # Strip basic HTML tags and unescape entities
    cleaned = re.sub(r"<[^>]+>", " ", text)
    cleaned = html.unescape(cleaned)

    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"

    ipv4_pattern = (
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    )

    # Simple domain pattern (will include hostnames from URLs as well)
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    url_pattern = r"https?://[^\s'\"<>]+"

    # IPv6 – permissive pattern for typical forms (not exhaustively strict)
    ipv6_pattern = r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"

    # MITRE ATT&CK technique IDs: T#### or T####.### variants
    mitre_pattern = r"\bT\d{4}(?:\.\d{3})?\b"

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    cves = sorted(set(re.findall(cve_pattern, cleaned)))
    ips = sorted(set(re.findall(ipv4_pattern, cleaned)))
    ipv6s = sorted(set(re.findall(ipv6_pattern, cleaned)))

    # Domains, excluding ones that are actually IPs
    domains_all = set(re.findall(domain_pattern, cleaned))
    domains = sorted(d for d in domains_all if not re.fullmatch(ipv4_pattern, d))

    emails = sorted(set(re.findall(email_pattern, cleaned)))
    urls = sorted(set(re.findall(url_pattern, cleaned)))

    mitre_techniques = sorted(set(re.findall(mitre_pattern, cleaned)))

    lowered = cleaned.lower()

    # MITRE techniques from explicit IDs (e.g. T1053, T1053.002) and,
    # additionally, from technique names where we have a mapping from the
    # MITRE ATT&CK dataset. This is slightly more permissive but surfaces
    # techniques that are referenced by name only.
    mitre_from_ids = set(re.findall(mitre_pattern, cleaned))
    mitre_from_names = {
        tid for name, tid in _MITRE_NAME_TO_ID.items() if name in lowered
    }
    mitre_all = sorted(mitre_from_ids.union(mitre_from_names))

    # Malware / tools: intentionally left empty for now; this can be
    # reintroduced later with a more robust approach or external feeds.
    malware_tools_found: List[str] = []

    hashes = set(re.findall(md5_pattern, cleaned))
    hashes.update(re.findall(sha1_pattern, cleaned))
    hashes.update(re.findall(sha256_pattern, cleaned))
    hashes_sorted = sorted(hashes)

    return {
        "cves": cves,
        "ips": ips,
        "domains": domains,
        "hashes": hashes_sorted,
        "emails": emails,
        "urls": urls,
        "ipv6": ipv6s,
        "mitre": mitre_all,
        "malware_tools": malware_tools_found,
    }


def parse_feed_items(xml: str, feed_url: str, fetched_at: str) -> List[Dict[str, str]]:
    """
    Parse an RSS feed into a list of article dictionaries.
    No BeautifulSoup or HTML parsing is used here, only XML.
    """
    root = ET.fromstring(xml)

    # RSS structure: <rss><channel><item>...</item></channel></rss>
    channel = root.find("channel")
    if channel is None:
        # Some feeds use namespaces; fall back to a broader search
        channel = next((el for el in root.iter() if el.tag.endswith("channel")), None)
    if channel is None:
        return []

    items: List[Dict[str, str]] = []

    DC_NS = "http://purl.org/dc/elements/1.1/"

    for item in channel.findall("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date_raw = (item.findtext("pubDate") or "").strip()
        description = (item.findtext("description") or "").strip()

        # Author: standard RSS or Dublin Core creator, if present
        author = (item.findtext("author") or "").strip()
        if not author:
            dc_creator = item.find(f"{{{DC_NS}}}creator")
            if dc_creator is not None and dc_creator.text:
                author = dc_creator.text.strip()

        # Concatenate multiple <category> tags if present
        categories: List[str] = []
        for cat in item.findall("category"):
            text = (cat.text or "").strip()
            if text:
                categories.append(text)
        category_str = " / ".join(dict.fromkeys(categories)) if categories else ""

        # Treat the first category (if any) as a rough \"section\" label
        section = categories[0] if categories else ""

        # Use full article text if available (e.g., Krebs), otherwise fall back to description
        CONTENT_NS = "http://purl.org/rss/1.0/modules/content/"
        content_encoded = item.find(f"{{{CONTENT_NS}}}encoded")
        full_text = (content_encoded.text or "") if content_encoded is not None else ""

        # Include title and categories in the IOC extraction corpus
        ioc_corpus = " ".join(
            part
            for part in [title, full_text or description, category_str]
            if part
        )
        indicators = extract_indicators(ioc_corpus)

        parsed_link = urlparse(link) if link else None
        source_host = parsed_link.netloc.lower() if parsed_link and parsed_link.netloc else ""

        items.append(
            {
                "url": link,
                "title": title,
                "published_at": parse_pub_date(pub_date_raw),
                "description": description,
                "categories": category_str,
                "tags": "",
                "cves": ", ".join(indicators["cves"]),
                "ips": ", ".join(indicators["ips"]),
                "domains": ", ".join(indicators["domains"]),
                "hashes": ", ".join(indicators["hashes"]),
                "email": ", ".join(indicators["emails"]),
                "urls": ", ".join(indicators["urls"]),
                "ipv6": ", ".join(indicators["ipv6"]),
                "mitre_techniques": ", ".join(indicators["mitre"]),
                "malware_tools": ", ".join(indicators["malware_tools"]),
                "source": source_host,
                "feed_url": feed_url,
                "fetched_at": fetched_at,
                "full_text": full_text or description,
                "author": author,
                "section": section,
            }
        )

    # Some feeds use namespaced tags, handle those too
    if not items:
        items = []
        for item in channel:
            if not item.tag.endswith("item"):
                continue
            title = (item.findtext("./*[@tag='title']") or item.findtext("title") or "").strip()

    return items


def write_items_to_csv(items: List[Dict[str, str]], output_path: str) -> None:
    """
    Write RSS items to CSV, merging with any existing rows and deduplicating by URL.
    """
    fieldnames = [
        "url",
        "title",
        "published_at",
        "description",
        "categories",
        "tags",
        "cves",
        "ips",
        "domains",
        "hashes",
        "email",
        "urls",
        "ipv6",
        "mitre_techniques",
        "malware_tools",
        "source",
        "feed_url",
        "fetched_at",
        "full_text",
        "author",
        "section",
    ]

    existing_by_url: Dict[str, Dict[str, str]] = {}
    path = Path(output_path)
    if path.exists():
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url") or ""
                if url:
                    existing_by_url[url] = row

    for item in items:
        url = item.get("url", "")
        if not url:
            continue
        # Merge with any existing row, preferring newly scraped values
        existing = existing_by_url.get(url, {})
        merged = {**existing, **item}
        existing_by_url[url] = merged

    # Sort by published_at (latest first); fall back to unsorted if parsing fails
    def sort_key(row: Dict[str, str]) -> str:
        return row.get("published_at") or ""

    sorted_rows = sorted(
        existing_by_url.values(), key=sort_key, reverse=True
    )

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted_rows:
            # Filter to fieldnames only (existing CSVs may have extra columns)
            filtered = {k: row.get(k, "") for k in fieldnames}
            writer.writerow(filtered)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch latest articles from The Hacker News RSS feed and "
            "store them in a CSV file (without HTML scraping)."
        )
    )
    parser.add_argument(
        "--feed-url",
        default=DEFAULT_FEED_URL,
        help="RSS feed URL to read from (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_CSV,
        help="Path to output CSV file (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    print(f"Fetching RSS feed from {args.feed_url} ...")
    xml = fetch_feed_xml(args.feed_url)

    print("Parsing feed items...")
    fetched_at = datetime.utcnow().isoformat()
    items = parse_feed_items(xml, args.feed_url, fetched_at)
    print(f"Parsed {len(items)} items from feed.")

    print(f"Writing items to CSV at {args.output} (merging with existing rows if present)...")
    write_items_to_csv(items, args.output)

    print("Done. Sample:")
    for item in items[:5]:
        print(
            f"- {item['title']} | {item['published_at']} | "
            f"{item['categories']} | {item['url']}"
        )


if __name__ == "__main__":
    main(sys.argv[1:])

