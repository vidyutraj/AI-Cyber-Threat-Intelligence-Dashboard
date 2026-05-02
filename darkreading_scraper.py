import argparse
import html
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from thn_rss_scraper import DEFAULT_HEADERS, extract_indicators, write_items_to_csv

DEFAULT_FEED_URL = "https://www.darkreading.com/vulnerabilities-threats"
DEFAULT_OUTPUT_CSV = "darkreading_rss_articles.csv"
DEFAULT_MAX_PAGES = 5
DEFAULT_MAX_ARTICLES = 80
DEFAULT_TRANSPORT = "auto"

DARKREADING_MALWARE_TERMS: List[str] = [
    "ransomware",
    "botnet",
    "trojan",
    "worm",
    "dropper",
    "loader",
    "backdoor",
    "stealer",
    "infostealer",
    "spyware",
    "keylogger",
    "rootkit",
    "cryptominer",
    "phishing kit",
    "exploit kit",
    "cobalt strike",
    "metasploit",
    "mimikatz",
    "iran",
    "war"
]


try:
    from curl_cffi import requests as curl_requests  # type: ignore
except Exception:
    curl_requests = None


def _browser_headers() -> Dict[str, str]:
    headers = dict(DEFAULT_HEADERS)
    headers.update(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "Referer": "https://www.darkreading.com/",
        }
    )
    return headers


class WebFetcher:
    """
    Fetch pages with browser-like behavior to reduce bot-blocking 403 responses.
    """

    def __init__(self, transport: str = DEFAULT_TRANSPORT):
        self.transport = (transport or DEFAULT_TRANSPORT).strip().lower()
        self.session: Any = None
        self.kind = "requests"
        self._init_session()

    def _init_session(self) -> None:
        use_curl = self.transport == "curl" or (
            self.transport == "auto" and curl_requests is not None
        )
        if use_curl and curl_requests is not None:
            self.session = curl_requests.Session(impersonate="chrome124")
            self.kind = "curl_cffi"
        else:
            self.session = requests.Session()
            self.kind = "requests"
        self.session.headers.update(_browser_headers())

    def warmup(self) -> None:
        for seed in [
            "https://www.darkreading.com/",
            "https://www.darkreading.com/vulnerabilities-threats",
        ]:
            try:
                self.session.get(seed, timeout=25, allow_redirects=True)
            except Exception:
                pass

    def get_html(self, url: str) -> str:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                resp = self.session.get(url, timeout=30, allow_redirects=True)
                if resp.status_code in {401, 403, 429}:
                    if attempt == 1:
                        self.warmup()
                    if attempt < 3:
                        time.sleep(1.2 * attempt)
                        continue
                resp.raise_for_status()
                text = resp.text or ""
                if "Access Denied" in text[:1200] or "Forbidden" in text[:1200]:
                    raise requests.HTTPError(f"Blocked response for {url}")
                return text
            except Exception as e:
                last_error = e
                if attempt < 3:
                    time.sleep(1.2 * attempt)
                    continue
        if last_error is None:
            raise RuntimeError(f"Failed to fetch URL: {url}")
        raise last_error


def _clean_text(raw: str) -> str:
    text = html.unescape(raw or "")
    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _extract_darkreading_indicators(text: str) -> Dict[str, List[str]]:
    indicators = extract_indicators(text)
    lowered = (text or "").lower()

    found_terms: List[str] = []
    for term in DARKREADING_MALWARE_TERMS:
        pattern = r"\b" + re.escape(term).replace(r"\ ", r"\s+") + r"\b"
        if re.search(pattern, lowered):
            found_terms.append(term)

    existing = set(indicators.get("malware_tools") or [])
    indicators["malware_tools"] = sorted(existing.union(found_terms))
    return indicators


def extract_listing_article_urls(listing_html: str, listing_url: str) -> List[str]:
    """
    Extract candidate article URLs from a listing page.
    Keeps Dark Reading story URLs and filters out non-article routes.
    """
    hrefs = re.findall(r'href="([^"]+)"', listing_html, flags=re.IGNORECASE)
    urls: List[str] = []
    seen: set[str] = set()

    for href in hrefs:
        url = urljoin(listing_url, href).split("#")[0]
        parsed = urlparse(url)
        if parsed.netloc and "darkreading.com" not in parsed.netloc:
            continue
        path = parsed.path.rstrip("/")
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            continue
        # Strictly keep only stories under /vulnerabilities-threats/<slug>
        if parts[0] != "vulnerabilities-threats":
            continue
        if parts[0] in {"author", "resources", "videos", "latest-news"}:
            continue
        if parts[-1] in {"vulnerabilities-threats", "threat-intelligence", "application-security"}:
            continue
        if not re.search(r"[a-z0-9]-[a-z0-9]", parts[-1]):
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)

    return urls


def parse_darkreading_date(raw_text: str) -> str:
    if not raw_text:
        return ""
    raw = raw_text.strip()
    raw = re.sub(r"\s+", " ", raw)
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    return raw


def parse_article(article_url: str, page_html: str, feed_url: str, fetched_at: str) -> Dict[str, str]:
    title = ""
    m = re.search(r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"', page_html, flags=re.IGNORECASE)
    if m:
        title = html.unescape(m.group(1)).strip()
    if not title:
        h1 = re.search(r"<h1[^>]*>(.*?)</h1>", page_html, flags=re.IGNORECASE | re.DOTALL)
        title = _clean_text(h1.group(1)) if h1 else ""

    desc = ""
    m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', page_html, flags=re.IGNORECASE)
    if m:
        desc = html.unescape(m.group(1)).strip()
    if not desc:
        p = re.search(r"<p[^>]*>(.*?)</p>", page_html, flags=re.IGNORECASE | re.DOTALL)
        desc = _clean_text(p.group(1)) if p else ""

    published_raw = ""
    m = re.search(
        r'<meta[^>]+property="article:published_time"[^>]+content="([^"]+)"',
        page_html,
        flags=re.IGNORECASE,
    )
    if m:
        published_raw = m.group(1).strip()
    if not published_raw:
        m = re.search(
            r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}\b",
            page_html,
            flags=re.IGNORECASE,
        )
        published_raw = m.group(0) if m else ""

    author = ""
    m = re.search(r"/author/[^\"']+[^>]*>([^<]+)</a>", page_html, flags=re.IGNORECASE)
    if m:
        author = _clean_text(m.group(1))

    section = ""
    parsed = urlparse(article_url)
    parts = [p for p in parsed.path.split("/") if p]
    if parts:
        section = parts[0]

    categories = section.replace("-", " ").title() if section else ""

    article_block_match = re.search(
        r"<article\b[^>]*>(.*?)</article>",
        page_html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    article_html = article_block_match.group(1) if article_block_match else page_html
    full_text = _clean_text(article_html)
    if not full_text:
        full_text = desc

    ioc_corpus = " ".join(part for part in [title, desc, full_text, categories] if part)
    indicators = _extract_darkreading_indicators(ioc_corpus)

    source_host = parsed.netloc.lower() if parsed.netloc else "www.darkreading.com"

    return {
        "url": article_url,
        "title": title,
        "published_at": parse_darkreading_date(published_raw),
        "description": desc,
        "categories": categories,
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
        "full_text": full_text[:12000],
        "author": author,
        "section": section,
    }


def scrape_darkreading(
    base_url: str = DEFAULT_FEED_URL,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_articles: int = DEFAULT_MAX_ARTICLES,
    transport: str = DEFAULT_TRANSPORT,
) -> List[Dict[str, str]]:
    fetched_at = datetime.utcnow().isoformat()
    fetcher = WebFetcher(transport=transport)
    print(f"Using HTTP transport: {fetcher.kind}")
    fetcher.warmup()
    article_urls: List[str] = []
    seen_urls: set[str] = set()

    for page in range(1, max_pages + 1):
        page_url = base_url if page == 1 else f"{base_url}?page={page}"
        print(f"Fetching listing page: {page_url}")
        try:
            listing_html = fetcher.get_html(page_url)
        except Exception as e:
            print(f"  Failed to fetch listing page {page}: {e}")
            continue

        urls = extract_listing_article_urls(listing_html, page_url)
        for url in urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            article_urls.append(url)
            if len(article_urls) >= max_articles:
                break
        if len(article_urls) >= max_articles:
            break

    items: List[Dict[str, str]] = []
    for idx, url in enumerate(article_urls, start=1):
        try:
            article_html = fetcher.get_html(url)
            row = parse_article(url, article_html, base_url, fetched_at)
            if row.get("title"):
                items.append(row)
        except Exception as e:
            print(f"  Failed article {idx}/{len(article_urls)}: {url} | {e}")
            continue
        if idx % 10 == 0:
            print(f"  Parsed {idx}/{len(article_urls)} articles...")

    items.sort(key=lambda x: x.get("published_at") or "", reverse=True)
    return items


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scrape Dark Reading vulnerabilities/threats listing pages and article pages, "
            "then extract IOCs/CVEs into a CSV."
        )
    )
    parser.add_argument(
        "--feed-url",
        default=DEFAULT_FEED_URL,
        help="Base listing URL to scrape (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_CSV,
        help="Path to output CSV file (default: %(default)s)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Max listing pages to crawl (default: {DEFAULT_MAX_PAGES})",
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=DEFAULT_MAX_ARTICLES,
        help=f"Max article pages to parse (default: {DEFAULT_MAX_ARTICLES})",
    )
    parser.add_argument(
        "--transport",
        choices=["auto", "requests", "curl"],
        default=DEFAULT_TRANSPORT,
        help="HTTP transport mode (default: auto)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    print(
        f"Scraping Dark Reading from {args.feed_url} "
        f"(pages={args.max_pages}, max_articles={args.max_articles})..."
    )
    items = scrape_darkreading(
        base_url=args.feed_url,
        max_pages=max(1, args.max_pages),
        max_articles=max(1, args.max_articles),
        transport=args.transport,
    )
    print(f"Collected {len(items)} articles with indicator extraction.")
    print(f"Writing items to CSV at {args.output} (merge/dedupe by URL)...")
    write_items_to_csv(items, args.output)
    print("Done.")


if __name__ == "__main__":
    main(sys.argv[1:])
