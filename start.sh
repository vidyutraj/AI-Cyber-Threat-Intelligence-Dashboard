#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
#  Threat Intelligence Dashboard — one-command local starter
#  Usage: ./start.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
FRONTEND="$ROOT/frontend"

GREEN="\033[92m"; BOLD="\033[1m"; RESET="\033[0m"

echo -e "${BOLD}Threat Intelligence Dashboard${RESET}"
echo "──────────────────────────────────────────"

# ── Python virtual env ─────────────────────────────────────────────────────
if [[ ! -f "$VENV/bin/activate" ]]; then
  echo "Creating virtual environment…"
  python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"

echo "Installing Python dependencies…"
pip install -q -r "$ROOT/requirements.txt"

# ── Backend ────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}▶ Starting Flask backend on :8001${RESET}"
cd "$ROOT"
if [[ -f "$ROOT/.env" ]]; then
  set -o allexport; source "$ROOT/.env"; set +o allexport
fi
python server.py &
BACKEND_PID=$!

# Wait for backend to be ready
echo -n "  Waiting for backend"
for i in $(seq 1 30); do
  if curl -sf http://localhost:8001/api/intel/status > /dev/null 2>&1; then
    echo -e "  ${GREEN}ready${RESET}"
    break
  fi
  echo -n "."
  sleep 1
done

# ── Frontend ───────────────────────────────────────────────────────────────
echo -e "\n${GREEN}▶ Starting Vite frontend on :5173${RESET}"
cd "$FRONTEND"
npm install --silent
npm run dev &
FRONTEND_PID=$!

echo ""
echo "──────────────────────────────────────────"
echo -e "${BOLD}Servers are running${RESET}"
echo -e "  Frontend:  http://localhost:5173"
echo -e "  Backend:   http://localhost:8001"
echo ""
echo "  Run warm-up: cd $ROOT && python demo_warmup.py"
echo ""
echo "Press Ctrl+C to stop both servers."
echo "──────────────────────────────────────────"

# ── Cleanup on exit ────────────────────────────────────────────────────────
trap "echo ''; echo 'Stopping servers…'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait
