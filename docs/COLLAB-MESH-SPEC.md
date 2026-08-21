# Hermes Collab Mesh — Technical Spec (for build)

> **Proyek**: Extend Hermes K2 Monitor jadi trusted multi-VPS collaboration mesh.
> **Mode**: TAMBAH + REVISI, JANGAN rombak. UIUX existing dipertahankan 100%.
> **Prioritas build utama**: Security > Anonymity > Trust > Shared-file > Join-code.

---

## 0. HARD RULE — UIUX JANGAN DIROMBAK

- Struktur visual existing (dark cyberpunk terminal, panel `agent-card`, `task-col` PENDING/WORKING/DONE, `discussion-body`, `.dsk`/`.mob`, SVG icon Yerin diamond / Merlin hexagon, zero-CDN, mono font stack) **DI•PERTAHANKAN apa adanya**.
- Perubahan = **tambah panel/div baru** + **revisi elemen yang kurang sesuai**. Bukan hapus/ganti layout existing.
- Semua CSS baru ikut `:root` var yang ada (`--bg`, `--green`, `--blue`, `--mono`, dst).
- **No emoji**, pakai inline SVG (VIEW 24x24, stroke 1.2-1.5).
- **Zero external CDN** — system font stack, no Google Fonts/jsDelivr.
- Mobile responsive via `.dsk`/`.mob` toggle (pattern existing, jangan ubah).
- File tetap: `server.py` (aiohttp :8766 + websockets :8765) + `frontend/index.html`.

---

## 1. VISI ARSITEKTUR (ringkas)

**Dashboard K2 Monitor = satu-satunya AUTH GATE & RELAY antar node.**
Untuk collab, agent WAJIB lewat dashboard → auto-anonim + auto-auth. Tidak ada jalur lain (no raw VPS IP, no SSH antar node, no backdoor).

```
VPS-A (yerin) ── Dashboard-A ──HTTPS/CF-tunnel──► Dashboard-B ── VPS-B (merlin)
                 │ collab vault                    │ collab vault
                 │ /shared/collab/                 │ /shared/collab/ (mirror)
```

- Antara node: komunikasi cuma **HTTPS POST ke CF-tunnel domain partner** (IP VPS tidak pernah exposed, egress WARP).
- Setiap node punya `collab/` vault (shared source-of-truth) + mirror lokal.

---

## 2. PRIORITAS (urut build)

1. **SECURITY** — Hermes antar node TIDAK BISA saling intip file personal / key. Isolation ketat.
2. **ANONYMITY** — masuk dashboard = otomatis tersamarkan. Identity node tidak ke-expose ke peer lain.
3. **TRUST** — message relay TIDAK bisa dibobol/diakali pihak ke-3 (no celah). Signed + nonce + TTL + rotating key.
4. **SHARED FILE** — collab ledger khusus di dashboard monitor (`/shared/collab/`), mirror lokal per node.
5. **JOIN CODE** — sebelum connect, agent harus present join-code + TTL. Salah/expired = TOLAK.

---

## 3. MODUL TAMBAH (dalam server.py / file baru di repo)

### 3.1 Collab Vault (P4 — shared file)
- Dir: `/root/hermes-monitor/collab/` (relatif repo, biar ikut git. Atau configurable via env `COLLAB_DIR`).
- Format **ledger append-only** `collab/ledger.jsonl` — tiap entri:
  ```json
  {"id":"uuid","ts":"ISO","node":"yerin-a","op":"message|task|join|file_update","payload":{...},"sig":"..."}
  ```
- `collab/state.json` — snapshot terbaru (messages + task state + nodes registered). Di-update tiap ada event.
- `collab/tasks/` — subfolder `pending/processing/done/` untuk task kolaborasi (BUKAN task lokal hermes-shared/tasks, DIPISAH).
- **Mirror**: `collab/mirror/` nx diisi snapshot dari node lain (cache/backup). Kalau link putus, state terakhir tetap ada.
- K2 Monitor **wajib tampilkan** collab ledger sebagai view/panel baru (lihat §5).

### 3.2 Join Handshake (P5 — code + TTL)
- Endpoint `POST /api/auth/join` — body: `{node_id, conn_code, expires_at}`.
- Validasi: conn_code cocok dengan `join_codes/` store + `expires_at > now` + `node_id` belum terdaftar. Gagal = `403 {error:"invalid or expired code"}`.
- Dashboard generate join-code: `POST /api/auth/invite` → return `{code, expires_at, node_id}`. Code TTL default 300s, single-use.
- Store (plaintext gak boleh): `collab/.auth/join_codes.enc` — di-encrypt symmetric dengan mesh key.
- Setelah join sukses, node dapat **rotating token** (bukan code sekali-pakai) untuk komunikasi lanjutan.

### 3.3 Trust / Message Signing (P3)
- Setiap message relay: `{node_id, op, payload, nonce, ts, sig}`.
- `sig = HMAC_SHA256(mesh_key, node_id|op|canonical(payload)|nonce|ts)`.
- Verify di penerima:
  1. `|now - ts| <= 30s` (anti-replay lama)
  2. `nonce` belum pernah dipakai (anti-replay dobel) — cek state nonce file
  3. `sig` valid (hanya node dgn mesh_key yang tau)
  4. `op` diizinkan sesuai role (collab-only: message/task/file_update/broadcast — **SELALU tolak** request key/env/path personal)
- **Rotating key**: mesh_key berputar via simple ratchet tiap N menit (misal 15m) atau tiap X event. Configurable.
- **Nonce store**: `collab/.auth/nonces` — kapasitas terbatas (rolling delete lama).

### 3.4 Anonymity Relay (P2)
- `POST /api/relay` — terima message signed dari node, verify, tulis ke ledger + broadcast ke webhook partner.
- Response: `{status:"ok", relayed:true, ledger_id}"` atau `{status:"rejected", reason}`.
- Node identity di log = **node_id semi-acak** (misal `n7f2a9`), bukan hostname/IP/email. Mapping node_id→real identity cuma di state internal dashboard, TIDAK dikirim ke peer.
- **No PII**: payload tidak boleh berisi IP internal, hostname server, path absolut, email, API key.

### 3.5 Collab Sandbox / Isolation (P1 — SECURITY)
- Batasi agent collab TIDAK bisa akses file personal:
  - Akses file collab HANYA via API endpoint (`/api/collab/file`), bukan path langsung di sistem remote.
  - Endpoint **whitelist path**: hanya izinkan `collab/{task_id}/` — path lain (`/root/.env`, `.hermes`, `config.yaml`, `keys`) = `403 forbidden`.
  - Simpan **akses scope** di state: collab agent role punya `read/write` cuma di `collab/`, deny else.
- (Implementasi hard sandbox = namespace/kernel — di scope lanjut. P0 ini: whitelist-path API + deny by default.)

---

## 4. API SUMMARY (semua di aiohttp `server.py`, auth wajib)

| Method | Endpoint | Auth | Fungsi |
|---|---|---|---|
| GET | `/api/state` | existing | snapshot existing (+ tambah `collab`) |
| POST | `/api/auth/invite` | dashboard-owner | buat join-code + TTL |
| POST | `/api/auth/join` | conn_code | node daftar ke mesh |
| POST | `/api/relay` | HMAC sig | kirim/terima message signed |
| POST | `/api/collab/file` | HMAC + whitelist | read/write file collab (whitelist path) |
| POST | `/api/collab/task` | HMAC | buat/claim/selesaikan task kolaborasi |
| GET | `/api/collab/ledger` | HMAC | ambil ledger (buat sinkronisasi) |
| POST | `/api/mesh/revoke` | dashboard-owner | kill-switch node/mesh |
| WS | `/ws` (8765) | existing | realtime existing (+ broadcast event collab) |

Semua route baru WAJIB HMAC verify (kecuali join invite = dashboard-owner). Auth gagal → `403`, bukan 401 kosong.

---

## 5. UI TAMBAHAN (frontend, TIDAK rombak)

**A. Collab Panel** (desktop `.dsk` + mobile `.mob`):
- Panel baru "COLLAB MESH": status mesh (CONNECTED / PARTITIONED), daftar node terdaftar (node_id semi-acak), shared file list (dari `collab/`), task kolaborasi (reuse task-col style).
- Style ikut pattern existing (panel-head dengan `.stat`, padding sama, border `--line`).

**B. Auth / Invite View**:
- Tombol/aksi "Invite Node" → POST `/api/auth/invite` → tampil join-code + countdown TTL (timer).
- Form "Join Mesh" → input node_id + conn_code + submit → POST `/api/auth/join`.
- Status join sukses/gagal feedback (tidak toast global berlebihan, ikut pola debug-session).

**C. Trust Indicator**:
- Setiap entry collab ledger di dashboard tampil indikator signature valid/terverifikasi (dot hijau) vs invalid/tampered (dot merah) — langsung visual "no-celah".

**TIDAK DIHAPUS**: PENDING/WORKING/DONE task-col, discussion chat, agent-card Yerin/Merlin, metrics, clock.

---

## 6. DATA MODEL (state.json)

```json
{
  "nodes": {
    "n7f2a9": {"status":"active","joined_at":"...","last_seen":"...","role":"collab","ttl":0}
  },
  "tasks": {"pending":[],"processing":[],"done":[]},
  "messages": [],
  "mesh_key_rotations": 0,
  "last_sync": "..."
}
```

---

## 7. TEST / VERIFY (wajib setelah build)

1. `bash -n` / `python3 -m py_compile` server.py → no error.
2. Server jalan, `curl /api/state` → `collab` field ada, UI lama masih render (Yerin/Merlin/task/discussion).
3. Join handshake: invite → code TTL → join dengan code benar = `200`; code salah/expired = `403`.
4. Relay: kirim message signed → verify → ledger ada entri baru + broadcast.
5. Trust: kirim message dengan sig diubah (tamper) → `403 rejected` + audit log mencatat.
6. Collab file: akses `collab/taskid/x.json` = `200`; akses `/root/.env` atau `../../etx` = `403` (path traversal blocked).
7. UI: collab panel render, no console error, no CDN external, mobile toggle jalan.

---

## 8. NON-GOALS (gak dikerjakan di scope ini)
- Shared FS mount antar VPS (NFS/sshfs) — sengaja TIDAK.
- External queue broker (Redis/NATS/Kafka) — tetap file-based + webhook.
- Hard kernel sandbox (namespace/seccomp/LXD) — P1 lanjut.
- Frontend rombak total / redesign.

---

## 9. OVERKILL LAYER (tambah progresif, urut dampak)

> "Simple tapi overkill": mekanisme inti tetap webhook+file, tapi tiap lapis hardened.

1. **Node identity cert (P1)** — tiap node punya cert ditandatangani pusat (mesh CA). Node palsu/pintu didekteksi: cert gak valid → selalu rejected walau signature pass. Mapping node_id↔public key di `.auth/nodes.enc`.
2. **Kill-switch remote (P1)** — `POST /api/mesh/revoke` oleh dashboard-owner: revoked node_id masuk blacklist (state on-disk, persist restart). Satu klik hapus node dari mesh; node yang di-revoke otomatis dibuang semua session/keys.
3. **Audit hash-chain (tamper-evident, P1)** — tiap baris ledger `collab/.auth/audit.jsonl` punya `prev_hash = sha256(prev_line)`. Ubah/inject baris lama → rantai hash putus → dashboard tampil "AUDIT TAMPERED" dot merah. Mencegah node/pihak-3 menutupi jejak.
4. **Forward-secrecy key ratchet (P2)** — mesh_key bukan statis: turunan sesi `session_key = HKDF(mesh_key, node_id+nonce)`. Rotasi per N event; compromise key lama tidak bocorin pesan lama.
5. **Traffic padding / timing disguise (P2)** — overhead request dummy (random interval) supaya pola trafik tidak bocorkan kapan collab aktif (anti-meta data leak).
6. **QoS circuit breaker (P2)** — link yang selalu gagal/rate-limit → auto-isolate (stop propagate), dashboard status node = "UNHEALTHY" sampai manual clear. Cegah satu node nakal menjatuhkan mesh (byzantine-tolerant).

**Implementasi berurutan**: (1)(2)(3) di fase auth/trust — karena langsung menutup celah bobol. (4)(5)(6) fase relay/operasional — hardening lanjutan.
