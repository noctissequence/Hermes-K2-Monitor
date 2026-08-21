# Connect Mesh — Panduan Peer (untuk VPS kedua / teman)

Ikuti urutan ini di VPS yang mau bergabung jadi node mesh. Ganti GANDA `<...>`
dengan nilai yang diisi sendiri / dikirim oleh pengundang.

> Semua command dijalankan sebagai root. Repositori ini kamu clone dari mana
> punyamu berada — ganti `<REPO_URL>` di bawah dengan URL git yang kamu pakai.

## 0. Prasyarat
- VPS Linux (Debian/Ubuntu) dengan Python 3.11+.
- `git`, `pip3`, `curl` terpasang.
- Untuk relay 2 arah: akun Cloudflare + `cloudflared` (Bagian 4).

---

## 1. Clone & install

```bash
git clone <REPO_URL> /opt/hk2
cd /opt/hk2
pip3 install --upgrade aiohttp websockets psutil cryptography
```

## 2. Setup peer (1 command)

Onboarding sekaligus: clone deps, tulis `MESH_KEY`, daemon + cron keep-alive.
**`MESH_KEY` harus PERSIS sama** dengan node lain — itu kunci trust bersama mesh.

```bash
sudo bash scripts/setup-mesh-peer.sh \
  --mesh-key "<MESH_KEY_RAHASIA_SAMA>" \
  --repo-url "<REPO_URL>"
```

Verifikasi gateway up:

```bash
curl -s http://127.0.0.1:8766/api/state | head -c 120
# -> JSON {"agents":{...}...}
```

## 3. Join mesh (2 arah — wajib)

Mesh bersifat **2 arah**: kamu join ke node lain, dan node lain join ke kamu.

### 3a. Kamu join ke node lain
Dapat dari pengundang: `code` + `expires_at`. Jalankan:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"node_id":"<NODE_ID_KAMU>","conn_code":"<CONN_CODE>","expires_at":"<EXPIRES_AT>"}' \
  http://<IP_ATAU_TUNNEL_PARTNER>:8766/api/auth/join
```

Simpan `token` hasilnya → dipakai jadi `COLLAB_LOCAL_NODE_TOKEN` (Bagian 5).

### 3b. Node lain join ke kamu
Buat undangan (butuh `owner_token` kamu):

```bash
curl -X POST -H "X-Collab-Owner: <OWNER_TOKEN_KAMU>" -H "Content-Type: application/json" \
  -d '{"node_id":"<NODE_ID_PARTNER>"}' \
  http://127.0.0.1:8766/api/auth/invite
```

Kirim `code` + `expires_at` ke partner; partner jalankan 3a di VPS-nya.

---

## 4. Expose relay via Cloudflare Tunnel (jangan IP mentah)

Agar event bisa di-forward silang, ekspos `/api/relay` lewat tunnel (anonim + HTTPS):

```bash
cloudflared tunnel --url http://127.0.0.1:8766
```

Buat subdomain, misal `https://relay-kamu.example.com`. Catat URL-nya.

---

## 5. Set partner config (dua sisi)

Tulis `.env.mesh` (mode 600, TIDAK masuk git):

```bash
# File: /opt/hk2/.env.mesh
MESH_KEY=<MESH_KEY_RAHASIA_SAMA>
COLLAB_DIR=/opt/hk2/collab
K2_BIND_HOST=127.0.0.1
K2_HTTP_PORT=8766

# alamat tunnel relay partner (pisah koma kalau lebih dari satu)
COLLAB_PARTNER_URLS=https://relay-partner.example.com

# identitas node kamu yang SUDAH JOIN ke partner
COLLAB_LOCAL_NODE_ID=<NODE_ID_KAMU>
COLLAB_LOCAL_NODE_TOKEN=<TOKEN_HASIL_JOIN>
```

Restart gateway:

```bash
cd /opt/hk2 && bash scripts/mesh-gateway.sh || true
```

## 6. Cek status

```bash
bash scripts/cek-mesh-status.sh
```

Menampilkan: gateway UP, node terdaftar, mesh status, env partner.

---

## Keamanan (baca dulu)
- **`MESH_KEY` = rahasia bersama.** Jangan share di chat publik / repo.
- **Closed mesh:** whitelist path hanya izinkan `collab/{task_id}/`. Path personal
  (`.env`, `~/.hermes`, private key, dll) otomatis `403`.
- Relay **verifikasi HMAC + nonce + timestamp** — pesan tamper / stale / replay ditolak.
- Ekspos via **CF tunnel** biar IP VPS tidak terekspos sebagai endpoint publik.
- Jangan kirim `MESH_KEY` / `owner_token` lewat pesan yang bisa dibaca pihak lain.
