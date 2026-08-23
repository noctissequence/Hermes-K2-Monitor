#!/usr/bin/env bash
# ============================================================
# invite-partner.sh — bikin code undangan join mesh K2 ke partner
# (node server-relay HARUS sudah jalan di :8766)
# Pemakaian:  bash scripts/invite-partner.sh <node_id_partner>
# Contoh:     bash scripts/invite-partner.sh k2-partner-node
# Output:     code + expires_at (copy-paste ke partner)
# ============================================================
set -euo pipefail

NODE_ID="${1:-}"
HOST="${K2_INVITE_HOST:-http://127.0.0.1:8766}"
AUTH_DIR="/root/hermes-monitor/collab/.auth"
OWNER_FILE="${K2_OWNER_TOKEN_FILE:-$AUTH_DIR/owner_token}"

if [ -z "$NODE_ID" ]; then
  echo "Usage: $0 <node_id_partner>" >&2
  echo "Contoh: $0 k2-partner-node" >&2
  exit 1
fi

if [ ! -f "$OWNER_FILE" ]; then
  echo "ERROR: owner_token tidak ditemukan di $OWNER_FILE" >&2
  exit 1
fi
OT="$(cat "$OWNER_FILE")"

RESP="$(curl -s -X POST "$HOST/api/auth/invite" \
  -H "X-Collab-Owner: $OT" \
  -H "Content-Type: application/json" \
  -d "{\"node_id\":\"$NODE_ID\"}")"

# parse
CODE="$(echo "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("code",""))' 2>/dev/null || echo "")"
EXP="$(echo "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("expires_at",""))' 2>/dev/null || echo "")"

if [ -z "$CODE" ]; then
  echo "GAGAL: pastikan server relay jalan di $HOST dan node_id unik." >&2
  echo "Response mentah:" >&2; echo "$RESP" >&2
  exit 1
fi

echo "=============================================="
echo "  CODE        : $CODE"
echo "  EXPIRES_AT  : $EXP   (TTL ~5 menit)"
echo "  NODE_ID     : $NODE_ID"
echo "=============================================="
echo ""
echo "Kirim ke partner. Di sisi partner (3 nilai wajib):"
echo "  COLLAB_LOCAL_NODE_ID=$NODE_ID"
echo "  code=$CODE"
echo "  expires_at=$EXP"
