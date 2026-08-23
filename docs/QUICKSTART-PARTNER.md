# 🚀 QUICKSTART — Bergabung ke Mesh K2 (Partner/Coba)

> Dibuat untuk test malam ini. Ikutin urutan, sat set ~10 menit.
> Req: VPS (Debian/Ubuntu) + akses root + internet.

---

## 0. Yang kamu butuh dari host (isi manual dari chat private)

- **`MESH_KEY`** — kunci trust mesh (rahasia, SAMA di semua node)
- **`CODE`** + **`EXPIRES_AT`** — kode undangan join (berubah-ubah, minta fresh ke host)
- **`RELAY_URL`** = **`https://k2-relay.noctisstudio.online`** (sudah terisi di bawah)

---

## 1. Clone + install

```bash
apt update && apt install -y git python3-pip 2>/dev/null || sudo apt-get install -y git python3-pip
git clone https://github.com/noctissequence/Hermes-K2-Monitor.git
cd Hermes-K2-Monitor
pip install websockets aiohttp psutil cryptography
```

## 2. Set mesh key (sekali, rahasia)

```bash
mkdir -p collab/.auth
printf '%s' '<MESH_KEY_DARI_HOST>' > collab/.auth/mesh_key
chmod 600 collab/.auth/mesh_key
```

## 3. Buat file env mesh

```bash
umask 077
cat > .env.mesh <<'EOF'
COLLAB_DIR=$(pwd)/collab
K2_BIND_HOST=127.0.0.1
K2_HTTP_PORT=8766
COLLAB_LOCAL_NODE_ID=k2-partner-node
COLLAB_LOCAL_NODE_TOKEN=<TOKEN_DARI_JOIN_STEP_5>
COLLAB_PARTNER_URLS=https://k2-relay.noctisstudio.online
K2_PUNCH_UDP_PORT=0
EOF
```

> `K2_PUNCH_UDP_PORT=0` = punch UDP nonaktif (mesh pake relay + WS persisten,
> IP node tidak pernah di-expose — desain anonymity).

## 4. Jalankan server node kamu

```bash
# biar env ke-load
set -a; . ./.env.mesh; set +a
python3 server.py
```

Cek jalan:
```bash
curl -s -o /dev/null -w "node HTTP: %{http_code}\n" http://127.0.0.1:8766/
# → 200
```

## 5. Join ke node HOST (dapat token)

Server node kamu PUNCA tetap jalan di terminal lain (jalankan ini di terminal kedua).

```bash
# minta CODE + EXPIRES_AT fresh dari host dulu (TTL ~5 menit)
curl -X POST https://k2-relay.noctisstudio.online/api/auth/join \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "k2-partner-node",
    "code": "<CODE_DARI_HOST>",
    "expires_at": "<EXPIRES_AT_DARI_HOST>"
  }'
```

Hasilnya berisi `{ "token": ..., ... }` (dan `certificate`). Salin token itu.

## 6. Sambungkan token ke WS link

Edit `.env.mesh` → isi `COLLAB_LOCAL_NODE_TOKEN=<token dari step 5>`, lalu restart:

```bash
kill $(pgrep -f "server.py" | head -1) 2>/dev/null
set -a; . ./.env.mesh; set +a
python3 server.py
```

Sekarang node kamu **dial WS ke host** → event ngucur real-time.

> Ada jalur balik juga: host bisa connect ke kamu kalau kamu expose relay kamu
> (tunnel CF / IP). Tapi untuk uji pertama, cukup arah "kamu ke host" sudah
> membuktikan WS link + real-time.

## 7. Verifikasi

```bash
# (a) server up
curl -s -o /dev/null -w "http: %{http_code}\n" http://127.0.0.1:8766/

# (b) peer aktif + status (pakai token node kamu)
curl -s -H "Authorization: Bearer <TOKEN_DARI_JOIN>" \
  http://127.0.0.1:8766/api/mesh/peers
# → {"peers":[...], "punch_enabled":false}

# (c) log WS link ke host
tail -20 /var/log/k2-monitor.log 2>/dev/null | grep -iE "wsrelay|link established"
# → "wsrelay link established to https://k2-relay.noctisstudio.online"
```

Kalau cuma lihat itu di log → **WS link BERHASIL**, kamu resmi connect ke mesh host.

---

## Troubleshooting

| Gejala | Penyebab & fix |
|---|---|
| `auth rejected` di WS | `COLLAB_LOCAL_NODE_TOKEN` salah / expired. Ulangi step 5, update token, restart |
| `/api/mesh/peers` 403 | token salah / belum join. Pastikan token dari `join` benar |
| Tidak ada event | `COLLAB_PARTNER_URLS` benar? Code join masih valid? Cek log wsrelay |
| Port 8766 gak ngedenger | server belum start / port kepake. `K2_HTTP_PORT` beda? |
| `code invalid` di join | code expired (TTL 5 mnt) atau sudah dipakai. Minta code fresh |

## 🛑 JANGAN PERNAH

- Commit `.env.mesh`, `collab/.auth/*`, atau token ke git
- Share `MESH_KEY` ke orang di luar mesh (satu kunci = akses penuh mesh)
- Ganti `K2_PUNCH_UDP_PORT` ke angka (mesh ini relay-only, bukan P2P UDP)

---

## Security note

- Mesh pake relay + WS persisten, **alpha anonymity**: IP node tidak pernah
  di-expose ke peer. Host cuma di-expose lewat subdomain tunnel (mask IP).
- Token node rotating 24h. Kalau kompromis, host bisa revoke via `/api/mesh/revoke`.
- Semua event di-verify (HMAC + nonce + timestamp + node cert) sebelum masuk ledger.
