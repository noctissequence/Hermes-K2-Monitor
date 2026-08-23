# Quickstart — Bergabung sebagai Partner Node (K2 Collab Mesh)

Panduan ini buat kamu (partner) yang menerima ajakan dari node host (Noctis)
buat gabung ke mesh dan saling remate task secara real-time antar VPS.

Prerequisite: kamu punya VPS (Debian/Ubuntu), akses root, dan internet.
Durasi setup: ~10 menit.

---

## 1. Isi yang kamu butuh dari host (Noctis)

Untuk bisa connect, kamu perlu dapat **dari host**:
- **MESH_KEY** — 32-byte hex (sama persis di semua node; ini kunci trust bersama)
- **HOST_RELAY_URL** — endpoint relay host, misal `https://k2-relay.fluxscout.xyz`
- **OWNER_TOKEN** tiap node (nanti otomatis dibuat) — bukan buat kamu, internal.
- (Opsional) **JUMLAH** — biasanya host yang bikin ajakan node_id kamu.

Minta ini via chat private, JANGAN di channel publik.

## 2. Clone + install (di VPS kamu)

```bash
apt update && apt install -y python3-pip git 2>/dev/null || sudo apt update
git clone https://github.com/noctissequence/Hermes-K2-Monitor.git
cd Hermes-K2-Monitor
pip install websockets aiohttp psutil cryptography
```

## 3. Set mesh key (WAJIB sama dengan host)

```bash
mkdir -p collab/.auth
# tulis MESH_KEY dari host (tanpa newline):
printf '%s' '<MESH_KEY_DARI_HOST>' > collab/.auth/mesh_key
chmod 600 collab/.auth/mesh_key
```

Catatan: kalau host sudah pakai env `MESH_KEY`, kamu juga bisa set lewat env.
Yang penting NILAINYA SAMA di kedua node.

## 4. Jalankan server node kamu

```bash
# buat .env.mesh agar relay + WS link tahu partner & identitas lokal
cat > .env.mesh <<'EOF'
COLLAB_PARTNER_URLS=<HOST_RELAY_URL>        # ganti: URL relay host
COLLAB_LOCAL_NODE_ID=<node_id_kamu>          # misal: node-saya
COLLAB_LOCAL_NODE_TOKEN=<akan-diisi-step-5>
K2_PUNCH_UDP_PORT=0     # punch UDP nonaktif (kita relay-only, sesuai desain)
EOF
chmod 600 .env.mesh
# jalankan (baca env)
set -a; . ./.env.mesh; set +a
python3 server.py
```

Kalau mau jadi daemon self-heal, pakai keeper:
```bash
bash scripts/setup-mesh-peer.sh --mesh-key "$(cat collab/.auth/mesh_key)" \
  --partner "<HOST_RELAY_URL>" --punch-port 0
```
(section ini walau namanya setup-mesh-peer, fungsinya yang penting: tulis .env.mesh
+ daemon kan, BUKAN punch — kita relay-only.)

## 5. Registrasi silang (node kamu vs node host) — PENTING

Agar host bisa kirim event ke kamu (dan kamu ke host), kedua node harus
**saling terdaftar**. Alur:

**A. Host bikin ajakan buat kamu** (host lakukan di dashboard/server-nya):
```bash
curl -X POST http://127.0.0.1:8766/api/auth/invite \
  -H "X-Collab-Owner: <OWNER_TOKEN_HOST>" \
  -H "Content-Type: application/json" \
  -d '{"node_id":"<node_id_kamu>"}'
# → dapat {code, expires_at}
```
Host kirim `code` ini ke kamu (TTL 300s, sekali pakai).

**B. Kamu join ke mesh host** (di VPS kamu, server kamu sudah jalan):
```bash
curl -X POST <HOST_RELAY_URL>/api/auth/join \
  -H "Content-Type: application/json" \
  -d '{"node_id":"<node_id_kamu>","code":"<CODE_DARI_HOST>","expires_at":"<EXPIRES_DARI_HOST>"}'
# → dapat {token, certificate, ...}
```
Ini menandatangani node kamu ke mesh host. Token ini DIPAKAI untuk WS link di step 4
(`COLLAB_LOCAL_NODE_TOKEN`).

## 6. Link WS persisten (real-time)

Setelah step 5, update `.env.mesh`:
```bash
COLLAB_LOCAL_NODE_TOKEN=<token_dari_join_kamu>
```
Restart server. Sekarang node kamu **dial WS ke host** (`/ws/relay`) → event
mengalir real-time. Kalau WS putus, otomatis fallback ke HTTP relay.

## 7. Verifikasi

```bash
# 1. server up
curl -s -o /dev/null -w "node HTTP: %{http_code}\n" http://127.0.0.1:8766/

# 2. lihat peer aktif + status lane (perlu token node kamu)
curl -s -H "Authorization: Bearer <node_token_kamu>" \
  http://127.0.0.1:8766/api/mesh/peers
# → {"peers":[...], "punch_enabled":false}

# 3. cek log WS link
tail -20 /var/log/k2-monitor.log 2>/dev/null | grep -i wsrelay
# atau di foreground tsb lihat "wsrelay link established to <host>"
```

## Troubleshooting umum

- **`auth rejected` di WS** → `COLLAB_LOCAL_NODE_TOKEN` salah / node belum join /
  token expired. Ulangi step 5-B lalu update `.env.mesh`.
- **Tidak ada event mengalir** → pastikan `COLLAB_PARTNER_URLS` benar dan node
  kamu terdaftar di host (step 5). Cek log `wsrelay link established`.
- **Relay HTTP fallback** → normal kalau WS belum live; event tetap nyampe lewat
  POST (best-effort).

## Security catatan (harus dipahami)

- **Jangan pernah** commit `.env.mesh`, `collab/.auth/*`, atau token ke git.
- MESH_KEY dipegang semua node = kunci trust. Kompromi satu node = bisa baca
  seluruh mesh; jangan bagikan ke siapapun di luar mesh.
- Kamu berhak akses `collab/` (shared vault) SAJA, bukan file personal host.
- Token node rotating (24h). Kalau kompromis, host bisa revoke via
  `/api/mesh/revoke`.

---

`K2_PUNCH_UDP_PORT=0` karena desain K2 memakai relay + persistent WebSocket,
BUKAN P2P UDP (menjaga anonymity — IP node tidak pernah di-expose ke peer).
