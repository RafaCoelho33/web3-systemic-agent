#!/usr/bin/env bash
set -e

echo "=================================================================="
echo " Web3 Condition-Action Trigger Agent - Public API Launcher"
echo "=================================================================="
echo ""

CLOUDFLARED_BIN=""

find_cloudflared() {
    if command -v cloudflared >/dev/null 2>&1; then
        echo "cloudflared"
        return 0
    fi
    for candidate in \
        "/c/Program Files (x86)/cloudflared/cloudflared.exe" \
        "/c/Program Files/cloudflared/cloudflared.exe" \
        "$LOCALAPPDATA/Microsoft/WinGet/Links/cloudflared.exe" \
        "$HOME/AppData/Local/Microsoft/WinGet/Links/cloudflared.exe" \
        "/usr/local/bin/cloudflared" \
        "/usr/bin/cloudflared"
    do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

CLOUDFLARED_BIN="$(find_cloudflared || true)"

if [ -z "$CLOUDFLARED_BIN" ]; then
    echo "[!] cloudflared not found in PATH or standard install paths."
    echo "[*] Attempting installation via winget..."
    winget install --id Cloudflare.cloudflared --accept-source-agreements --accept-package-agreements || true
    CLOUDFLARED_BIN="$(find_cloudflared || true)"
fi

if [ -z "$CLOUDFLARED_BIN" ]; then
    echo "[ERROR] cloudflared could not be found or installed."
    echo "Please download and install it manually from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    exit 1
fi

echo "[*] Using Cloudflare executable: $CLOUDFLARED_BIN"

# Graceful cleanup on SIGINT / SIGTERM / EXIT
cleanup() {
    echo ""
    echo "[*] Shutting down FastAPI uvicorn server..."
    if [ -n "$UVICORN_PID" ]; then
        kill "$UVICORN_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "[*] Starting FastAPI uvicorn server in background..."
export PUBLIC_EVALUATE_ONLY=true
python -m uvicorn api:app --host 0.0.0.0 --port 8000 &
UVICORN_PID=$!

echo "[*] Waiting for API server to become ready on http://127.0.0.1:8000..."
READY=0
for i in {1..20}; do
    if curl -s http://127.0.0.1:8000/ >/dev/null 2>&1 || python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/')" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ $READY -eq 1 ]; then
    echo "[*] FastAPI server is ready and responding!"
else
    echo "[!] Warning: Server did not respond within 20s, attempting tunnel anyway..."
fi

echo ""
echo "=================================================================="
echo " Starting Cloudflare Public Tunnel for http://localhost:8000"
echo " Look for your public https://*.trycloudflare.com URL below:"
echo "=================================================================="
echo ""

"$CLOUDFLARED_BIN" tunnel --url http://localhost:8000
