"""
BleepingComputer scraper with pagination support.
Uses RSS for rich metadata (first ~15) and HTML scraping for additional articles (up to 50+).
Fetches each article page to extract tags from cz-news-tags-wrap.
"""

import argparse
import re
import sys
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from thn_rss_scraper import (
    DEFAULT_HEADERS,
    extract_indicators,
    fetch_feed_xml,
    parse_feed_items,
    write_items_to_csv,
)

BASE_URL = "https://www.bleepingcomputer.com"
RSS_FEED_URL = "https://www.bleepingcomputer.com/feed/"
DEFAULT_MAX_ARTICLES = 50
DEFAULT_OUTPUT_CSV = "bleepingcomputer_rss_articles.csv"


def is_article_url(href: str) -> bool:
    """Return True if href points to an article (not a category index)."""
    if not href or not href.startswith("https://www.bleepingcomputer.com/news/"):
        return False
    parsed = urlparse(href)
    path = parsed.path.rstrip("/")
    parts = [p for p in path.split("/") if p]
    # Article: /news/security/article-slug -> 3+ parts
    # Category: /news/security -> 2 parts
    return len(parts) >= 3 and parts[0] == "news"


def normalize_url(href: str) -> str:
    """Remove fragment (#comment_form etc) and ensure trailing slash for consistency."""
    parsed = urlparse(href)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return base.rstrip("/") + "/" if base.rstrip("/") else base


def fetch_page(url: str) -> str:
    resp = requests.get(url, timeout=20, headers=DEFAULT_HEADERS)
    resp.raise_for_status()
    return resp.text


def extract_article_tags(html: str) -> str:
    """
    Extract tag text from div.cz-news-tags-wrap li a elements.
    Returns comma-separated tag names (e.g. "Open Source, Security, Microsoft").
    """
    soup = BeautifulSoup(html, "html.parser")
    tags_wrap = soup.find("div", class_="cz-news-tags-wrap")
    if not tags_wrap:
        return ""
    tags: List[str] = []
    for li in tags_wrap.find_all("li"):
        a = li.find("a")
        if a:
            text = a.get_text(strip=True)
            if text:
                tags.append(text)
    return ", ".join(tags)


def parse_listing_page(html: str, page_url: str) -> List[Dict[str, str]]:
    """
    Parse a BleepingComputer listing page and extract article metadata.
    """
    soup = BeautifulSoup(html, "html.parser")
    items: List[Dict[str, str]] = []
    seen_urls: set[str] = set()

    # Find all article links - look for links in the main content
    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        full_url = urljoin(page_url, href) if href.startswith("/") else href

        if not is_article_url(full_url):
            continue

        url = normalize_url(full_url)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Get title from link text or nearest heading
        title = (a.get_text(strip=True) or "").strip()
        if not title and a.find_previous(["h2", "h3", "h4"]):
            title = a.find_previous(["h2", "h3", "h4"]).get_text(strip=True)

        # Try to find description - often in a sibling or parent paragraph
        description = ""
        for candidate in [a.find_next("p"), a.find_parent("div")]:
            if candidate:
                p = candidate.find("p") if candidate.name != "p" else candidate
                if p:
                    desc_text = p.get_text(strip=True)
                    if desc_text and len(desc_text) > 30 and desc_text != title:
                        description = desc_text[:500]
                        break

        # Try to find date - look for time/date patterns near the link
        published_at = ""
        parent = a.find_parent(["article", "div", "li"])
        if parent:
            text = parent.get_text()
            # Match "03:07 PM" and "March 09, 2026" style
            date_match = re.search(
                r"(\d{1,2}:\d{2}\s*(?:AM|PM))\s*[-•]?\s*(\w+\s+\d{1,2},\s+\d{4})",
                text,
            )
            if date_match:
                time_part, date_part = date_match.groups()
                try:
                    from datetime import datetime

                    dt_str = f"{date_part} {time_part}"
                    dt = datetime.strptime(dt_str, "%B %d, %Y %I:%M %p")
                    published_at = dt.strftime("%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    published_at = f"{date_part} {time_part}"

        # Categories from URL path (e.g. /news/security/ -> Security)
        path_parts = urlparse(url).path.strip("/").split("/")
        categories = path_parts[1].replace("-", " ").title() if len(path_parts) >= 2 else ""

        indicators = extract_indicators(description or title)

        items.append(
            {
                "url": url,
                "title": title or url.split("/")[-2].replace("-", " ").title(),
                "published_at": published_at,
                "description": description,
                "categories": categories,
                "tags": "",
                "cves": ", ".join(indicators["cves"]),
                "ips": ", ".join(indicators["ips"]),
                "domains": ", ".join(indicators["domains"]),
                "hashes": ", ".join(indicators["hashes"]),
            }
        )

    return items


def get_page_urls(max_articles: int) -> List[str]:
    """
    Build list of page URLs to fetch. Page 1 is base, page 2 is /page/2/, etc.
    ~15 articles per page, so for 50 we need ~4 pages.
    """
    urls = [BASE_URL]
    pages_needed = max(1, (max_articles + 14) // 15)
    for p in range(2, pages_needed + 1):
        urls.append(f"{BASE_URL}/page/{p}/")
    return urls


def scrape_bleepingcomputer(
    max_articles: int = DEFAULT_MAX_ARTICLES,
    output_path: str = DEFAULT_OUTPUT_CSV,
) -> List[Dict[str, str]]:
    """
    Scrape BleepingComputer: RSS for metadata + HTML pagination for more articles.
    """
    # 1. Fetch RSS for rich metadata (title, description, published_at, etc.)
    rss_by_url: Dict[str, Dict[str, str]] = {}
    try:
        print(f"Fetching RSS feed from {RSS_FEED_URL} ...")
        xml = fetch_feed_xml(RSS_FEED_URL)
        rss_items = parse_feed_items(xml)
        for item in rss_items:
            url = item.get("url", "")
            if url:
                url = normalize_url(url)
                rss_by_url[url] = item
        print(f"  Got {len(rss_by_url)} items from RSS.")
    except Exception as e:
        print(f"  RSS fetch failed: {e}")

    # 2. Scrape HTML pages for additional article URLs
    page_urls = get_page_urls(max_articles)
    all_items: List[Dict[str, str]] = []
    seen: set[str] = set()

    for page_url in page_urls:
        if len(all_items) >= max_articles:
            break
        print(f"Fetching {page_url} ...")
        html = fetch_page(page_url)
        items = parse_listing_page(html, page_url)
        for item in items:
            url = item.get("url", "")
            if url and url not in seen:
                seen.add(url)
                # Prefer RSS metadata when available
                if url in rss_by_url:
                    all_items.append(rss_by_url[url])
                else:
                    all_items.append(item)
                if len(all_items) >= max_articles:
                    break

    # Sort by published_at (RSS items have it; HTML-only may not)
    all_items.sort(
        key=lambda x: x.get("published_at") or "",
        reverse=True,
    )

    # 3. Fetch each article page to extract tags from cz-news-tags-wrap
    print("Fetching article pages for tags...")
    for i, item in enumerate(all_items):
        url = item.get("url", "")
        if not url:
            continue
        try:
            html = fetch_page(url)
            item["tags"] = extract_article_tags(html)
            if (i + 1) % 10 == 0:
                print(f"  Fetched tags for {i + 1}/{len(all_items)} articles...")
        except Exception as e:
            item["tags"] = ""
        time.sleep(0.3)  # Be polite to the server

    write_items_to_csv(all_items, output_path)
    return all_items


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scrape BleepingComputer article listings from paginated HTML pages."
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=DEFAULT_MAX_ARTICLES,
        help=f"Maximum number of articles to fetch (default: {DEFAULT_MAX_ARTICLES})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_CSV,
        help=f"Output CSV path (default: {DEFAULT_OUTPUT_CSV})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    print(f"Scraping up to {args.max_articles} articles from BleepingComputer...")
    items = scrape_bleepingcomputer(
        max_articles=args.max_articles,
        output_path=args.output,
    )
    print(f"Collected {len(items)} articles. Sample:")
    for item in items[:5]:
        print(f"  - {item['title']} | {item['published_at']} | {item['url']}")


if __name__ == "__main__":
    main(sys.argv[1:])
