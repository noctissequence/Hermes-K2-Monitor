# 🔧 Panduan Fix — WS Relay Masih "Auth Rejected"

> Masalah: JOIN K2 mesh **sukses** (`k2-partner-node` sudah terdaftar di server host),
> tapi **daemon k2-monitor masih auth-rejected** saat buka WS link ke relay.
>
> **Penting:** server relay host **SUDAH TERVERIFIKASI BAIK**. `k2-partner-node`
> sudah masuk trusted list, dan server menolak token salah dengan benar (1008).
> Jadi masalahnya **di sisi daemon kamu**, bukan di server host.

---

## Kenapa kemungkinan besar terjadi (urut dari paling mungkin)

1. **`COLLAB_LOCAL_NODE_ID` di daemon ≠ `k2-partner-node`**
   Server host menolak jika node_id di frame auth tidak cocok dengan yang
   terdaftar (`claimed != peer_node_id`). Kalau daemon kamu masih `mesh-local`
   atau value lain, koneksi ditolak.

2. **Patch manual yang mengubah logika auth WS**
   Kalau waktu menyetup kamu men-patch sendiri `collab/wsrelay.py`
   (misal fix "no running event loop") dan mengubah cara auth frame dikirim,
   server host tidak menerimanya. **Pakai kode resmi terbaru.**

3. **Token/URL benar tapi race di relay** — kemungkinan kecil; sudah dicek
   dari sisi host tidak ada rate-limit residual terhadap node kamu.

---

## Langkah fix (jalankan di VPS kamu, `/opt/Hermes-K2-Monitor`)

### 1. Git pull — pakai kode resmi terbaru

```bash
cd /opt/Hermes-K2-Monitor
git fetch --all
git pull origin main
git log --oneline -1
# pastikan sampai commit: fee42bf (fix "no running event loop")
```

> ⚠️ Kalau kamu punya perubahan lokal, simpan dulu dengan `git stash`,
> lalu `git pull`, lalu `git stash pop` dan resolve konflik jika ada.

### 2. Pastikan `COLLAB_LOCAL_NODE_ID` = `k2-partner-node`

```bash
grep COLLAB_LOCAL_NODE_ID .env.mesh
```

Kalau belum `k2-partner-node`, ganti:

```bash
sed -i 's/COLLAB_LOCAL_NODE_ID=.*/COLLAB_LOCAL_NODE_ID=k2-partner-node/' .env.mesh
grep COLLAB_LOCAL_NODE_ID .env.mesh   # harus: k2-partner-node
```

### 3. Pastikan token masih valid

```bash
grep COLLAB_LOCAL_NODE_TOKEN .env.mesh | wc -c   # > 0 berarti ada
# Token valid 24 jam (expires 2026-08-24 16:13 UTC). Kalau mendekati expired,
# minta host generate ulang / re-register.
```

### 4. Restart service

```bash
# kalau systemd:
systemctl restart k2-monitor
# atau cara yang kamu pakai untuk service k2-monitor
```

### 5. Cek log setelah restart

```bash
sleep 5
tail -40 /var/log/k2-monitor.log | grep -iE "wsrelay|auth|reject|link established|node_id"
```

**Yang diharapkan:** baris seperti
```
wsrelay link established to https://k2-relay.noctisstudio.online
```
Kalau itu muncul → **WS link BERHASIL**, kamu resmi terhubung.

---

## Kalau masih reject — kirim log ini ke host

```bash
tail -60 /var/log/k2-monitor.log | grep -iE "auth|reject|unauthorized|wsrelay|node_id|close|1008"
```

Plus:
```bash
grep -E "COLLAB_LOCAL_NODE_ID|COLLAB_PARTNER_URLS|COLLAB_LOCAL_NODE_TOKEN" .env.mesh | sed 's/TOKEN=.*/TOKEN=<redacted>/'
```

Host akan diagnosa dari baris log itu.

---

## Ringkasan

- ✅ Join sukses, token aman 24 jam
- ❌ Blocker cuma 1: daemon WS link reject
- 🎯 Root cause hampir pasti `COLLAB_LOCAL_NODE_ID` salah **atau** pakai patch
  manual yang beda dari kode resmi
- ✅ Fix: `git pull` → pastikan node_id = `k2-partner-node` → restart → cek log

> Kirim log yang diminta ke host kalau masih reject, biar diagnosa lanjutan.
