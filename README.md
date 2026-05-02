# Threat Intelligence Dashboard

A full-stack **cyber threat intelligence** workspace: it ingests public security feeds, extracts IOCs and CVEs, enriches them (NVD, EPSS, CISA KEV), scores and clusters stories, and exposes everything through a **React** UI with an **optional OpenAI** layer for executive briefs, semantic search embeddings, and a RAG chat assistant.

**Repository:** [github.com/vidyutraj/AI-Cyber-Threat-Intelligence-Dashboard](https://github.com/vidyutraj/AI-Cyber-Threat-Intelligence-Dashboard)

---

## Why this exists

CVE and threat feeds are noisy. This project turns **raw articles** into **ranked CVEs**, **trending IOCs**, **correlation graphs**, **near-duplicate story clusters**, **MITRE ATT&CK coverage**, **STIX export**, and a **single place to read and query** the signal.

---

## Features

| Area | What you get |
|------|----------------|
| **Feeds** | Background scraping to CSV, freshness per source, SSE “new articles” hints |
| **Intel core** | CVE scoring, IOC graph + communities, trending IOCs, deduplication, kill chain, actor hints |
| **Executive view** | AI-generated brief with KPIs (when `OPENAI_API_KEY` is set) |
| **Analyst UI** | Tabbed dashboard: overview, graph, kill chain, actors, semantic search |
| **Malware** | MalwareBazaar sample list (optional API key) |
| **Chat (ARIA)** | RAG over your corpus + enrichment context (requires OpenAI) |
| **Export** | STIX 2.1 bundle, IOC CSV |

---

## Tech stack

- **Backend:** Python 3.11+, Flask, SQLite cache (`intel_cache.sqlite3`)
- **Frontend:** React 19, Vite 7, D3 (IOC graph)
- **AI (optional):** OpenAI API (chat, brief, embeddings)

---

## Architecture (high level)

```
RSS / HTML scrape  ──►  per-source CSV  ──►  IOC / CVE extraction
        │                                           │
        ▼                                           ▼
Background workers        intel_cache.sqlite3  ◄──  NVD / EPSS / KEV enrichment
(per source)                   │                    Embeddings (OpenAI, optional)
        │                      │                    MinHash near-dupes, IOC trends
        ▼                      ▼
SSE updates              Flask API (/api/*, /articles, …)
                               │
                               ▼
                        React app (Vite dev proxy → :8001)
```

---

## Data sources (built-in)

| Key | Source | Notes |
|-----|--------|--------|
| `thn` | [The Hacker News](https://thehackernews.com/) | RSS |
| `krebs` | [Krebs on Security](https://krebsonsecurity.com/) | RSS |
| `cisa` | [CISA advisories](https://www.cisa.gov/) | RSS |
| `bleepingcomputer` | [BleepingComputer](https://www.bleepingcomputer.com/) | RSS + HTML pagination |
| `darkreading` | [Dark Reading](https://www.darkreading.com/) | HTML (`curl_cffi`) |
| Malware | [MalwareBazaar](https://bazaar.abuse.ch/) | JSON API (optional key) |

Article bodies are scanned for CVEs, IPs, domains, hashes, and MITRE technique references. **Respect each site’s terms and rate limits**; this project is intended for **local or controlled** use.

---

## Repository layout

```
├── server.py              # Flask app, scrapers, SSE, AI routes
├── intel/                 # Scoring, graph, embeddings, STIX, API blueprint
├── *_scraper.py          # Source-specific collectors
├── demo_warmup.py        # Optional cache warm-up before demos
├── start.sh              # Backend :8001 + frontend :5173
├── .env.example          # Copy to .env — never commit .env
└── frontend/             # React UI (see frontend/README.md)
```

---

## Quick start

### Prerequisites

- Python **3.11+**
- Node.js **18+**
- **OpenAI API key** — required for executive brief, chat, and embedding-based semantic search (other tabs still work with reduced AI features)

### 1. Clone and configure

```bash
git clone https://github.com/vidyutraj/AI-Cyber-Threat-Intelligence-Dashboard.git
cd AI-Cyber-Threat-Intelligence-Dashboard

cp .env.example .env
# Edit .env and set at least OPENAI_API_KEY if you want AI features.
```

### 2. Run everything

```bash
chmod +x start.sh
./start.sh
```

- **Frontend:** [http://localhost:5173](http://localhost:5173)
- **Backend:** [http://localhost:8001](http://localhost:8001)

The Vite dev server proxies `/api`, `/articles`, and `/refresh` to the backend (`frontend/vite.config.js`).

### 3. Manual run (alternative)

```bash
# Terminal 1 — API
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
set -a && source .env && set +a   # or export vars your own way
python server.py

# Terminal 2 — UI
cd frontend && npm install && npm run dev
```

### 4. Optional: warm caches before a demo

```bash
source .venv/bin/activate
python demo_warmup.py
```

---

## Configuration

All variables are documented in [`.env.example`](.env.example). Common ones:

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | For AI features | Chat, brief, embeddings |
| `OPENAI_MODEL` | No | Default `gpt-4o-mini` |
| `MALWAREBAZAAR_API_KEY` | No | MalwareBazaar auth |
| `SCRAPE_INTERVAL_SECONDS` | No | Default `900` (15 min) |
| `VITE_API_BASE` | No | Set if the UI calls a **remote** API (empty = same-origin / proxy) |

---

## API overview

The server exposes feed metadata, paginated articles, SSE streams, intelligence aggregates, malware helpers, and AI endpoints. Full route list lives in `server.py` and `intel/api.py`; highlights:

- **Feed:** `/api/feed/sources`, `/api/feed/stream`, `/articles`, `/refresh`
- **Intel:** `/api/intel/overview`, `/api/intel/graph`, `/api/intel/trending`, `/api/intel/clusters`, `/api/intel/killchain`, `/api/intel/actors`, `/api/intel/similar`, `/api/intel/stix`, …
- **AI:** `/api/incidents/brief`, `/api/chat`
- **Malware:** `/api/malware/recent`, `/api/malware/refresh`

---

## Intelligence modules (`intel/`)

| Module | Role |
|--------|------|
| `loader.py` | Normalize articles from CSVs with time windows |
| `storage.py` | SQLite cache for enrichment, embeddings, MinHash, IOC counts |
| `enrichment.py` | NVD, EPSS, KEV |
| `scoring.py` | Composite CVE priority score |
| `correlation.py` | IOC graph, centrality, communities |
| `trending.py` | EWMA / z-score spikes on IOC mentions |
| `dedup.py` | MinHash + LSH clustering |
| `embeddings.py` | OpenAI vectors + cosine KNN (with TF-IDF fallback) |
| `killchain.py` | MITRE ATT&CK mapping |
| `actors.py` | Actor alias matching |
| `ioc_scoring.py` | IOC composite scores |
| `api.py` | Flask blueprint for `/api/intel/*` |

---

## UI tabs (at a glance)

- **Executive** — Threat level banner, KPIs, AI situation summary (with API key)
- **Threat intelligence** — Overview, IOC graph, kill chain, actors, semantic search; STIX / IOC export
- **Feed** — Per-source articles, search/filter, freshness, live update indicator
- **Malware** — Recent samples from MalwareBazaar
- **ARIA** — Floating RAG chat

---

## Security and responsible use

- **Never commit `.env`** or real API keys. Use `.env.example` only as a template.
- Scraping and third-party APIs can be **rate-limited** or **blocked**. Run responsibly.
- Enrichment calls **public** services (e.g. NVD, EPSS); review their acceptable use policies.
- This software is provided **as-is**; see [LICENSE](LICENSE).

---

## License

[MIT](LICENSE)
