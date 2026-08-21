#!/usr/bin/env bash
# =============================================================================
# Hermes Collab Mesh — Peer Onboarding (plug-and-play, security-first)
#
# Purpose : 1-command setup on a SECOND Hermes VPS so it can join the mesh
#           (plug-and-play while keeping trust boundaries).
# Usage   :  sudo bash setup-mesh-peer.sh --mesh-key <HEX32> [--partner <URL>]
#
# Security invariants (non-negotiable):
#   * MESH_KEY is the SHARED trust secret -> must be identical on every node.
#   * collab data only; personal paths (.env, ~/.hermes, keys) stay 403 by design.
#   * Relay exposes ONLY /api/relay via cloudflared tunnel, never a raw VPS IP.
#   * join handshake still enforced: code + TTL; wrong/expired -> rejected.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}[+]${NC} $*"; }
warn(){ echo -e "${YLW}[!]${NC} $*"; }
err(){  echo -e "${RED}[x]${NC} $*" >&2; }

REPO_URL="https://github.com/github-owner/Hermes-K2-Monitor.git"
APP_DIR="${HERMES_MESH_DIR:-/opt/hermes-k2-monitor}"
GATEWAY_PORT="${K2_HTTP_PORT:-8766}"

usage(){ echo "Usage: $0 --mesh-key <hex32> [--partner <url>] [--dir <path>]"; exit 1; }

MESH_KEY=""
PARTNERS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mesh-key) MESH_KEY="$2"; shift 2 ;;
    --partner)  PARTNERS="${PARTNERS:+$PARTNERS,}$2"; shift 2 ;;
    --dir)      APP_DIR="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -z "$MESH_KEY" ] && { err "MESH_KEY wajib (sama dengan node lain)"; usage; }

# --- 0. sanity: root? python3? git? -----------------------------------------
[[ $EUID -eq 0 ]] || { err "jalankan sebagai root"; exit 1; }
command -v python3 >/dev/null || { err "python3 tidak ada"; exit 1; }
command -v git >/dev/null || { err "git tidak ada"; exit 1; }
[[ ${#MESH_KEY} -ge 32 ]] || { warn "MESH_KEY pendek (<32 hex). Pakai yang sama di semua node & >=32."; }

# --- 1. clone repo ----------------------------------------------------------
if [[ -d "$APP_DIR/.git" ]]; then
  info "repo sudah ada, pull ulang"
  git -C "$APP_DIR" pull --quiet
else
  info "clone repo ke $APP_DIR"
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi
cd "$APP_DIR"

# --- 2. python deps ---------------------------------------------------------
info "install dependensi backend"
python3 -m pip install --quiet --upgrade aiohttp websockets psutil cryptography \
  || warn "pip install sebagian gagal (cek error)"

# --- 3. tulis mesh key + env (mode 600, gak masuk git) ----------------------
CONF_DIR="$APP_DIR/collab/.auth"
mkdir -p "$CONF_DIR"
ENV_FILE="$APP_DIR/.env.mesh"
umask 077
cat > "$ENV_FILE" <<EOF
MESH_KEY=$MESH_KEY
COLLAB_DIR=$APP_DIR/collab
K2_BIND_HOST=127.0.0.1
K2_HTTP_PORT=$GATEWAY_PORT
EOF
[[ -n "$PARTNERS" ]] && echo "COLLAB_PARTNER_URLS=$PARTNERS" >> "$ENV_FILE"
chmod 600 "$ENV_FILE"
info "env mesh ditulis ke $ENV_FILE (600)"

# --- 4. gateway keep-alive (setsid daemon + cron) ---------------------------
KEEPALIVE="$APP_DIR/scripts/mesh-gateway.sh"
cat > "$KEEPALIVE" <<'KEEPER'
#!/usr/bin/env bash
# self-heal mesh gateway keeper
APP_DIR="${HERMES_MESH_DIR:-$(dirname "$(cd "$(dirname "$0")" && pwd)")}"
PIDFILE="$APP_DIR/.mesh.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
  touch "$APP_DIR/collab/.auth/.alive"   # heartbeat
  exit 0
fi
cd "$APP_DIR"
set -a; . ./.env.mesh 2>/dev/null; set +a
setsid /usr/local/bin/python3 server.py >> "$APP_DIR/.mesh.log" 2>&1 &
echo $! > "$PIDFILE"
KEEPER
chmod +x "$KEEPALIVE"
bash "$KEEPALIVE" || true

# instal cron (catatan: jangan hapus cron existing)
CRON_LINE="* * * * * bash $KEEPALIVE"
( crontab -l 2>/dev/null | grep -vF "$KEEPALIVE" ; echo "$CRON_LINE" ) | crontab -
info "gateway daemon + cron keep-alive aktif (port $GATEWAY_PORT, localhost)"

# --- 5. (opsional) cloudflared tunnel expose /api/relay ---------------------
if command -v cloudflared >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  warn "cloudflared ada -> expose relay manual via: cloudflared tunnel --url http://127.0.0.1:$GATEWAY_PORT"
  warn "Arahkan subdomain, set COLLAB_PARTNER_URLS ke https://<subdomain>. Lakukan manual biar anonim & terkontrol."
fi

# --- 6. verifikasi ----------------------------------------------------------
sleep 2
if curl -sf -o /dev/null "http://127.0.0.1:$GATEWAY_PORT/api/state"; then
  info "✅ Gateway UP — mesin ini siap jadi node mesh"
  info "   1) Ajakan dari node lain: POST /api/auth/invite lalu join pakai CONN_CODE"
  info "   2) Atau kasih node lain code lu: invite -> kirim code"
else
  err "Gateway belum response. Cek .mesh.log"
fi
info "Selesai. MESH_KEY sama di semua node = kunci trust bersama."
