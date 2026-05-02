"""
Pre-warm every heavy endpoint so the demo loads instantly.

Run this ~2-5 minutes before you present:
    python demo_warmup.py

It hits the backend on localhost:8001 and prints status for each step.
"""

import sys
import time
import json
import urllib.request
import urllib.error

BASE = "http://localhost:8001"

STEPS = [
    ("GET",  "/api/feed/sources",               None,               "Feed source freshness"),
    ("GET",  "/api/intel/status",               None,               "Intel engine status"),
    ("GET",  "/api/intel/overview?hours=168",   None,               "Executive overview (7d)"),
    ("GET",  "/api/intel/overview?hours=24",    None,               "Executive overview (24h)"),
    ("GET",  "/api/intel/cves?hours=168",        None,               "CVE enrichment (7d)"),
    ("GET",  "/api/intel/iocs?hours=168",        None,               "IOC extraction (7d)"),
    ("GET",  "/api/intel/iocs/scored?hours=168", None,               "IOC scoring (7d)"),
    ("GET",  "/api/intel/graph?hours=168",       None,               "IOC correlation graph (7d)"),
    ("GET",  "/api/intel/trending?hours=168",    None,               "Trending IOCs (7d)"),
    ("GET",  "/api/intel/killchain?hours=168",   None,               "Kill chain analysis (7d)"),
    ("GET",  "/api/intel/actors?hours=720",      None,               "Threat actor profiles (30d)"),
    ("GET",  "/api/intel/duplicates?hours=168",  None,               "Deduplication clusters (7d)"),
    ("POST", "/api/incidents/brief",             {"hours": 168},     "Executive brief (7d) ← slow"),
    ("GET",  "/api/articles?source=krebs",       None,               "Krebs articles"),
    ("GET",  "/api/articles?source=hackernews",  None,               "Hacker News articles"),
    ("GET",  "/api/articles?source=bleepingcomputer", None,          "BleepingComputer articles"),
]

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def req(method, path, body=None, timeout=60):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    rq = urllib.request.Request(url, data=data, method=method,
                                headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(rq, timeout=timeout) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception as e:
        return None, str(e)

def main():
    print(f"\n{BOLD}CyberPulse Demo Warmup{RESET}")
    print("=" * 55)
    print(f"Backend: {BASE}\n")

    ok = err = 0
    for method, path, body, label in STEPS:
        t0 = time.time()
        status, size = req(method, path, body)
        elapsed = time.time() - t0
        if status and 200 <= status < 400:
            print(f"  {GREEN}✓{RESET} {label:<42} {status}  {elapsed:.1f}s")
            ok += 1
        else:
            print(f"  {RED}✗{RESET} {label:<42} {status or 'ERR'} {elapsed:.1f}s  {YELLOW}({size}){RESET}")
            err += 1

    print("\n" + "=" * 55)
    if err == 0:
        print(f"  {GREEN}{BOLD}All {ok} endpoints warmed successfully.{RESET}")
        print(f"  Demo is ready. Good luck!\n")
    else:
        print(f"  {GREEN}{ok} OK{RESET}  {RED}{err} failed{RESET}")
        print(f"  {YELLOW}Check that the backend is running: python server.py{RESET}\n")

    return 0 if err == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
