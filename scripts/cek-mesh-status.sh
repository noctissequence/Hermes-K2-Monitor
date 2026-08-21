#!/usr/bin/env bash
# cek-mesh-status.sh — verifikasi status mesh Hermes K2 Monitor.
# Menampilkan: gateway up/turun, node terdaftar, mesh status, konfig partner.
# Path default dari setup-mesh-peer.sh; override via HERMES_MESH_DIR atau APP_DIR env.
set -u
BASE="${BASE:-http://127.0.0.1:8766}"
APP_DIR="${HERMES_MESH_DIR:-${APP_DIR:-/opt/hermes-k2-monitor}}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env.mesh}"

pass(){ echo -e "  [OK]   $*"; }
warn(){ echo -e "  [! ]   $*"; }
fail(){ echo -e "  [X]   $*"; }

src() { command -v python3 >/dev/null 2>&1 && /usr/local/bin/python3 -c "$1" 2>/dev/null || echo "?"; }

echo "=== Gateway ==="
if curl -sf -o /dev/null "$BASE/api/state"; then
  pass "HTTP gateway UP ($BASE)"
else
  fail "HTTP gateway DOWN ($BASE) — jalankan: cd $APP_DIR && bash scripts/mesh-gateway.sh"
fi

echo "=== State / Mesh ==="
STATE=$(curl -sf "$BASE/api/state" 2>/dev/null)
if [ -n "$STATE" ]; then
  AGENTS=$(echo "$STATE" | /usr/local/bin/python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('agents',{})))" 2>/dev/null)
  MSH=$(echo "$STATE" | /usr/local/bin/python3 -c "import sys,json;d=json.load(sys.stdin).get('collab',{});print(d.get('mesh_status','?'))" 2>/dev/null)
  NODES=$(echo "$STATE" | /usr/local/bin/python3 -c "import sys,json;d=json.load(sys.stdin).get('collab',{});print(len(d.get('nodes',{})))" 2>/dev/null)
  pass "agents terdeteksi: ${AGENTS:-?}"
  echo "  mesh_status = ${MSH:-?} | node terdaftar = ${NODES:-?} (harus ada node partner)"
else
  warn "state kosong — cek gateway"
fi

echo "=== Konfigurasi partner ==="
if [ -f "$ENV_FILE" ]; then
  p_url=$(grep -cE "^COLLAB_PARTNER_URLS=" "$ENV_FILE")
  p_id=$(grep -cE "^COLLAB_LOCAL_NODE_ID=" "$ENV_FILE")
  p_tok=$(grep -cE "^COLLAB_LOCAL_NODE_TOKEN=" "$ENV_FILE")
  pass "COLLAB_PARTNER_URLS : $([ "$p_url" -ge 1 ] && echo set || echo KOSONG)"
  pass "COLLAB_LOCAL_NODE_ID: $([ "$p_id" -ge 1 ] && echo set || echo KOSONG)"
  pass "COLLAB_LOCAL_NODE_TOKEN: $([ "$p_tok" -ge 1 ] && echo set || echo KOSONG)"
  [ "$p_tok" -le 0 ] && warn "NODE_TOKEN belum di-set — mesh tidak forward ke partner."
else
  warn "file env tidak ditemukan: $ENV_FILE"
fi

echo "Selesai."
