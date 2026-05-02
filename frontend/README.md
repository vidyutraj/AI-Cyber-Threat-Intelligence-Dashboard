# Frontend (React + Vite)

This directory is the web UI for the **Threat Intelligence Dashboard**. The Flask API lives in the repository root (`server.py`).

For setup, environment variables, architecture, and API documentation, see the [root README](../README.md).

**Local dev** (from repo root, with the backend running on port 8001):

```bash
cd frontend
npm install
npm run dev
```

Vite proxies `/api`, `/articles`, and `/refresh` to `http://localhost:8001` — see `vite.config.js`.
