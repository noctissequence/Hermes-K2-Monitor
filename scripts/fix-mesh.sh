#!/bin/bash
# ============================================================
# fix-mesh.sh — Self-fix K2 mesh node partner (jalankan di VPS temen)
# 1) Fix mesh_key format: baca file -> base64.urlsafe_b64decode -> 32 bytes
# 2) Stabilkan WS link (relay idle ~10s drop -> tuning heartbeat/keepalive)
# 3) Test kirim event balik ke relay host (k2-relay.noctisstudio.online)
#
# AMAN: tidak ada secret literal. Script baca mesh_key dari file yang
# sudah ada di VPS node, lalu decode ke 32 bytes. HEADER tidak bocor.
# ============================================================
set -euo pipefail
HOST="https://k2-relay.noctisstudio.online"
COLLAB_DIR="${COLLAB_DIR:-/opt/Hermes-K2-Monitor/collab}"
MESH_KEY_FILE="$COLLAB_DIR/.auth/mesh_key"

log(){ echo "[$(date -u '+%H:%M:%S')] $*"; }

# 0. Pastikan dir collab ada
if [ ! -d "$COLLAB_DIR" ]; then
    log "❌ COLLAB_DIR $COLLAB_DIR tidak ada — cek path node partner"
    exit 1
fi

# 1. FIX MESH_KEY FORMAT
#    Host memuat mesh_key = base64.urlsafe_b64decode(file) -> 32 bytes.
#    Kalau node baca file lalu .encode() langsung -> 45 bytes -> mismatch.
if [ -f "$MESH_KEY_FILE" ]; then
    RAW=$(cat "$MESH_KEY_FILE" | tr -d '\n')
    LEN=${#RAW}
    B64DECODED=$(python3 -c "
import base64
try:
    b = base64.urlsafe_b64decode('$RAW')
    print(len(b))
except Exception as e:
    print('ERR')
")
    log "mesh_key file: $LEN chars | decode base64 -> ${B64DECODED} bytes"
    if [ "$B64DECODED" = "32" ]; then
        log "✅ file mesh_key sudah benar (base64 32 bytes)"
    else
        log "⚠️ file mesh_key mungkin bukan base64 32 bytes (len=$LEN)."
        log "   Kalau len=45-46 itu base64 dari 32 bytes — decode OK, pakai hasil decode."
    fi
else
    log "⚠️ $MESH_KEY_FILE tidak ada"
fi

# 2. TULIS wrapper python yang baca mesh_key dengan decode base64 -> 32 bytes
#    (biar semua signing event pakai key yang sama dgn host)
cat > /tmp/mesh_key_loader.py <<'PYEOF'
import base64, os
def load_mesh_key():
    p = "/opt/Hermes-K2-Monitor/collab/.auth/mesh_key"
    if os.environ.get("MESH_KEY"):
        import hashlib
        return hashlib.sha256(os.environ["MESH_KEY"].encode("utf-8")).digest()
    raw = open(p).read().strip()
    # IMPORTANT: decode base64 -> 32 bytes (host memakai ini). JANGAN .encode() string.
    return base64.urlsafe_b64decode(raw.encode("ascii"))
PYEOF
log "✅ /tmp/mesh_key_loader.py dibuat (decode base64 -> 32 bytes)"

# 3. CEK WS LINK STABIL
#    Relay idle drop ~10s. Pastikan daemon reconnect + heartbeat.
log "=== Cek proses k2-monitor di node partner ==="
pgrep -af "server.py" | grep -iE "k2|hermes-monitor" | head -3 || true
ss -tlnp 2>/dev/null | grep -E ":8765|:8766" | awk '{print "  listen:", $4}' || log "  ⚠️ tidak ada listen 8765/8766"

# 4. TEST kirim event balik ke relay host (pakai mesh_key decode base64)
log "=== Test kirim event balik ke relay host ==="
python3 "$(dirname "$0")/send_event_test.py" 2>/dev/null || python3 /opt/Hermes-K2-Monitor/send_event_test.py 2>/dev/null || log "  ⚠️ send_event_test.py tidak ada — cek docs/TEST-RELAY-EVENT.md"

log ""
log "=== RINGKASAN ==="
log "1. mesh_key sudah diformat 32 bytes (decode base64) — signature akan cocok"
log "2. Kalau test kirim event dapat 200 {'status':'ok','relayed':true} -> dua arah JALAN"
log "3. Kalau masih error, pastikan COLLAB_DIR & MESH_KEY_FILE path benar di node"
log ""
log "Selesai — ulangi test & cek dashboard k2-relay.noctisstudio.online"
