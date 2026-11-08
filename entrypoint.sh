#!/usr/bin/env bash
# attack-surface entrypoint
#
# Modes:
#   1. CLI passthrough (default when args are given):
#        docker run <img> serve --port 8443
#        docker run <img> -d example.com --redteam
#        docker run <img> watch -d example.com --every 3600
#      → runs attack_surface.py with the given arguments.
#
#   2. Service mode (no args): starts the red-team RPC daemons
#      (msfrpcd + sliver-server) and keeps the container alive.
#      Security defaults:
#        - msfrpcd: SSL ON, bind ${MSF_BIND:-127.0.0.1}, random password
#          (or $MSF_RPC_PASS), written to ~/.attack_surface/msfrpcd.env
#        - sliver:  bind ${SLIVER_BIND:-127.0.0.1}, port ${SLIVER_PORT:-50051}
#      Override binds via env when the services must be reachable
#      from outside the container (e.g. compose publishes 127.0.0.1:PORT).
set -u

APP_DIR="${ATTACK_SURFACE_APP:-/home/attack/attack-surface}"
cd "$APP_DIR" || exit 1

# ---------------------------------------------------------------- passthrough
if [ "$#" -gt 0 ]; then
    # `python3 attack_surface.py ...` style (docker exec / direct) or bare flags
    case "$1" in
        *.py)
            exec "$@"
            ;;
        *)
            exec python3 attack_surface.py "$@"
            ;;
    esac
fi

# ---------------------------------------------------------------- service mode
echo "[entrypoint] service mode: msfrpcd + sliver-server"

STATE_DIR="${ATTACK_SURFACE_STATE:-$HOME/.attack_surface}"
mkdir -p "$STATE_DIR"

MSF_BIND="${MSF_BIND:-127.0.0.1}"
MSF_PORT="${MSF_PORT:-55553}"
MSF_USER="${MSF_USER:-msf}"
# msfrpcd -S disables SSL; we want SSL ON → do not pass -S
if [ -z "${MSF_RPC_PASS:-}" ]; then
    MSF_RPC_PASS="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
fi

SLIVER_BIND="${SLIVER_BIND:-127.0.0.1}"
SLIVER_PORT="${SLIVER_PORT:-50051}"

# Persist credentials for the Python RPC clients (config.load reads this file)
{
    echo "MSF_USER=$MSF_USER"
    echo "MSF_RPC_PASS=$MSF_RPC_PASS"
    echo "MSF_HOST=$MSF_BIND"
    echo "MSF_PORT=$MSF_PORT"
    echo "SLIVER_HOST=$SLIVER_BIND"
    echo "SLIVER_PORT=$SLIVER_PORT"
} > "$STATE_DIR/msfrpcd.env"
chmod 600 "$STATE_DIR/msfrpcd.env"
echo "[entrypoint] credentials written to $STATE_DIR/msfrpcd.env"

# --- Metasploit RPC (SSL on, loopback by default) ---
if command -v msfrpcd >/dev/null 2>&1; then
    msfrpcd -U "$MSF_USER" -P "$MSF_RPC_PASS" -p "$MSF_PORT" -a "$MSF_BIND" -n &
    echo "[entrypoint] msfrpcd: user=$MSF_USER bind=$MSF_BIND port=$MSF_PORT (SSL on)"
else
    echo "[entrypoint] msfrpcd not found — skipping Metasploit RPC"
fi

# --- Sliver C2 server (loopback by default) ---
SLIVER_BIN=""
if command -v sliver-server >/dev/null 2>&1; then
    SLIVER_BIN="sliver-server"
elif command -v sliver >/dev/null 2>&1; then
    SLIVER_BIN="sliver"
fi
if [ -n "$SLIVER_BIN" ]; then
    if [ "$SLIVER_BIN" = "sliver-server" ]; then
        "$SLIVER_BIN" daemon -l "$SLIVER_BIND" -p "$SLIVER_PORT" >/dev/null 2>&1 &
    else
        "$SLIVER_BIN" server --lhost "$SLIVER_BIND" --lport "$SLIVER_PORT" >/dev/null 2>&1 &
    fi
    echo "[entrypoint] sliver: bind=$SLIVER_BIND port=$SLIVER_PORT"
else
    echo "[entrypoint] sliver not found — skipping C2 server (install at image build)"
fi

# Keep the container alive without burning CPU
exec tail -f /dev/null
