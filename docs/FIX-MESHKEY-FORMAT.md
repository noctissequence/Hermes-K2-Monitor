# 🔐 FIX — WS relay "invalid signature" / mesh dua arah belum jalan

> Root cause dari diagnostik relay host:
> **`mesh_key` harus di-`base64.urlsafe_b64decode` → 32 bytes**, BUKAN di-`.encode()`
> sebagai string mentah. Kalau dibaca sebagai string, signature beda → invalid.
>
> Node partner (k2-partner-node) SUDAH terdaftar + cert valid + token valid. Yang
> belum lolos cuma signing event — karena packet key yang dipakai salah format.

---

## Akar masalah (dari `collab/auth.py` `_load_secret`)

Relay host memuat mesh_key lewat:

```python
value = path.read_text(encoding="utf-8").strip()   # string 45 char (base64)
mesh_key = base64.urlsafe_b64decode(value.encode("ascii"))  # -> 32 bytes
```

Jadi **32 bytes** hasil decode base64 dari file `collab/.auth/mesh_key`.

**Kalau kamu (node partner) membaca file mesh_key lalu langsung `.encode()`**
(45-char string), signature-nya pakai key 45 bytes → **beda dari 32 bytes host**
→ relay menolak (`invalid signature`).

---

## Fix di VPS partner

### 1. Pastikan isi file mesh_key SAMA dengan host

```bash
cd /opt/Hermes-K2-Monitor
cat collab/.auth/mesh_key | wc -c   # HARUS 46 (45 char + newline) — base64 dari 32 bytes
```

- Kalau 46 → nilainya base64 dari 32 bytes, format benar.
- Kalau **bukan 46** (misal 33 / 45 tanpa newline, atau nilai lain) → file mesh_key kamu
  **beda dari host** → kamu perlu nilai mesh_key yang benar dari host.

### 2. Baca mesh_key sebagai 32 bytes (bukan string mentah)

Di `collab/wsrelay.py` / kode yang sign event, kamu harus pakai:

```python
import base64
mesh_key_file = open("/opt/Hermes-K2-Monitor/collab/.auth/mesh_key").read().strip()
mesh_key = base64.urlsafe_b64decode(mesh_key_file.encode("ascii"))   # -> 32 bytes
trust = TrustManager(mesh_key, ...)   # SAMA seperti host
```

> ⚠️ JANGAN: `mesh_key = open(...).read().encode()` → itu 45 bytes, salah.

### 3. Kalau pakai env `MESH_KEY`

`_load_secret` meng-hash env SHA256 ke 32 bytes. Jadi:

```bash
export MESH_KEY="<nilai ambil dari collab/.auth/mesh_key>"   # base64 string
```

Tapi kerja sama dengan cara host — paling aman: baca dari file + base64 decode.

### 4. Test kirim ulang event

Setelah fix, jalankan lagi kirim event test dari node partner:

```bash
cd /opt/Hermes-K2-Monitor
python3 docs/scripts/send_event_test.py   # (kalau ada) atau curl script kirim pesan
```

**Harapan:** response `{"status":"ok","relayed":true,"ledger_id":"..."}` →
event masuk ledger host. Setelah itu host akan balas → dua arah jalan.

---

## Verifikasi di host setelah partner kirim

Ledger host (`/root/hermes-monitor/collab/ledger.jsonl`) akan menampilkan
pesan dari `k2-partner-node`, dan dashboard (k2-relay.noctisstudio.online)
menampilkan `MESH · k2-partner-node` di panel DISCUSSION.

---

## Ringkasan

| | |
|---|---|
| Root cause | mesh_key dibaca salah (ASCII string vs base64-decoded 32 bytes) |
| Fix | `base64.urlsafe_b64decode(file_content)` → 32 bytes sebelum `TrustManager` |
| Test | kirim event → `200 {"status":"ok","relayed":true}` |
| Status | k2-partner-node sudah terdaftar + cert valid — tinggal fix format key |
