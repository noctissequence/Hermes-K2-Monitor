# Hermes K2 Monitor — Security Testing Guide

Dokumen ini menjelaskan cara menjalankan skrip test untuk memverifikasi modul `trust`, `auth`, audit hash-chain, node certificate, dan kill-switch persistence.

## 1. Jalankan dari repository

```bash
cd /home/ubuntu/Hermes-K2-Monitor
python3 -m py_compile server.py collab/*.py tests/test_collab_core.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Output sehat harus berakhir dengan pola berikut:

```text
Ran 17 tests in ...s
OK
```

Peringatan deprecation dari library `websockets` tidak dianggap kegagalan test selama proses berakhir dengan `OK` dan exit code `0`.

## 2. Jalankan test tertentu

Gunakan nama test berikut untuk mengisolasi skenario keamanan tertentu:

| Perintah | Yang diverifikasi |
|---|---|
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_invite_join_single_use_and_bad_code -v` | Owner invite, TTL, code salah, dan single-use join code. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_signed_relay_and_replay_rejected -v` | HMAC valid, tamper signature/payload, dan replay nonce. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_trust_rejects_stale_and_sensitive_payloads -v` | Timestamp lebih tua dari 30 detik dan payload berisi API key/secret. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_file_whitelist_allows_collab_and_denies_personal_paths -v` | Akses `collab/{task_id}/` versus traversal/personal path. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_audit_tamper_is_detected_and_new_events_fail_closed -v` | Mutasi `ledger.jsonl`, deteksi chain putus, dan penolakan event baru. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_certificate_integrity_and_revoke_persist_after_restart -v` | Certificate signature, revoke, restart, serta invalidasi token lama. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_encrypted_auth_store_tamper_fails_closed -v` | Store token terenkripsi yang dirusak tidak boleh mengautentikasi node. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_auth_boundary_and_expired_invite_rejected -v` | Owner boundary, node ID invalid, dan join code expired. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_trust_operation_and_path_edge_cases -v` | Operation di luar allowlist, future timestamp, Windows traversal, NUL byte, symlink escape, dan file oversize. |
| `python3 -m unittest tests.test_collab_core.CollabCoreHTTPTests.test_certificate_expiry_and_audit_reorder_are_detected -v` | Certificate expired/field tamper dan audit line reorder. |

## 3. Skenario trust secara manual

Pertama, buat test module instance melalui suite. Untuk pemeriksaan langsung terhadap envelope HMAC, pola payload-nya adalah:

```python
signed = mesh_trust.sign(
    "n-demo",
    "message",
    {"text": "hello"},
    nonce="unique-once-only",
)
verified, reason, node_id = mesh_trust.verify(signed)
assert verified is True
```

Kemudian jalankan verifikasi kedua dengan envelope yang sama. Hasilnya harus `verified == False` dan `reason == "replayed nonce"`. Jika `payload`, `op`, `node_id`, `nonce`, atau `ts` diubah setelah signing, hasilnya harus false dengan alasan signature atau policy failure.

Payload berikut harus ditolak sebelum dikirim ke relay:

```python
{"api_key": "do-not-send"}
{"email": "person@example.invalid"}
{"internal_ip": "10.0.0.1"}
{"path": "~/.env"}
```

Timestamp envelope lebih tua dari 30 detik juga harus ditolak sebagai `stale timestamp`.

## 4. Skenario auth secara manual

Gunakan alur berikut untuk menguji lifecycle node:

1. Owner memanggil `POST /api/auth/invite` dengan header `X-Collab-Owner`.
2. Node memanggil `POST /api/auth/join` memakai `node_id` dan `conn_code` yang diterima.
3. Simpan token hasil join hanya untuk sesi test; jangan masukkan token ke Git atau log.
4. Gunakan `Authorization: Bearer <token>` untuk route node.
5. Panggil `POST /api/mesh/revoke` sebagai owner.
6. Ulangi request dengan token lama; hasil yang diharapkan adalah `403`.
7. Restart object `CollabVault` dan `MeshAuth` dengan directory yang sama; token lama tetap harus ditolak dan node berstatus `revoked`.

Join code salah, expired, sudah dipakai, atau `node_id` yang sudah terdaftar harus menghasilkan `403`.

## 5. Skenario audit hash-chain

Jangan menjalankan skenario mutasi pada vault production. Gunakan temporary directory seperti yang dilakukan test suite. Alurnya:

```python
vault.append_event("n-demo", "message", {"text": "original"}, "sig")
assert vault.verify_audit_chain() is True

# Simulasikan tamper pada ledger.jsonl.
# Setelah satu karakter payload diubah:
assert vault.verify_audit_chain() is False
```

Setelah chain putus, `append_event`, file write, dan task mutation harus fail closed. API mutation mengembalikan HTTP `503` dengan alasan `audit chain tampered`. Operator harus menyelidiki dan memulihkan data secara terkontrol; jangan menghapus audit line untuk membuat test kembali hijau.

## 6. Skenario certificate dan kill-switch

Saat join sukses, response mengandung certificate Ed25519 yang ditandatangani mesh CA. Certificate valid harus lolos `identity.verify(node_id, certificate)`. Mengubah `node_id`, public key, expiry, atau signature harus membuat verifikasi false.

Revoke menulis status revoked pada `state.json`, memasukkan node ke encrypted `revoked_nodes.enc`, mencabut certificate, dan menonaktifkan token yang terkait. Untuk menguji persistence, buat object vault/auth baru dengan `COLLAB_DIR`, `MESH_KEY`, dan store yang sama. Node tetap harus revoked setelah object lama dibuang.

## 7. Isolasi data test

Suite memakai `tempfile.TemporaryDirectory()` dan environment berikut:

```text
COLLAB_DIR=<temporary-directory>
MESH_KEY=test-mesh-key-for-hermes-collab
COLLAB_OWNER_TOKEN=owner-test-token
```

Dengan demikian test tidak menyentuh `collab/` production di repository. Jangan memakai `COLLAB_DIR` production ketika melakukan test tamper, revoke, atau store corruption.

## 8. Coverage boundary and operational follow-up

The suite covers the security invariants implemented in this phase, including same-origin realtime activity delivery and the two-step owner kill-switch flow, but no finite test suite can prove that every possible attack is impossible.
 The following attack classes remain operational follow-up work rather than silently being reported as covered: sustained flooding beyond the configured local limiter, distributed rate-limit coordination across hosts, webhook replay across a partner link, traffic metadata leakage, CA key compromise, backup/restore tampering, filesystem permission drift under a different service account, and recovery tooling for a deliberately broken audit chain. These require deployment-level tests, load testing, or an explicit recovery runbook. The current implementation fails closed for detected integrity failures; it does not yet provide automatic audit-chain repair or a circuit breaker.

## 9. Live smoke test

With the server already running on HTTP port `8766`, execute the committed client from the repository root:

```bash
export MESH_KEY='the-same-mesh-key-used-by-server'
export COLLAB_OWNER_TOKEN='the-owner-token-used-by-server'
python3 scripts/live_smoke.py --base http://127.0.0.1:8766 --node-id n-live-smoke
```

The client checks `/api/state`, creates an invite, joins a temporary node, posts one signed relay event, and then reads `/api/collab/ledger` using a signed query envelope. Expected output includes `PASS /api/state status=200`, `PASS /api/relay status=200`, and `PASS /api/collab/ledger status=200` with at least one ledger entry and `audit.verified=True`. Use a temporary `COLLAB_DIR` for destructive or isolated smoke runs.

## 10. Rate limiting and concurrent stress

The server applies a SQLite-backed sliding-window limiter to sensitive routes. The default is 60 requests per 60 seconds per route and node/IP bucket. For a deterministic local test, start the server with a low limit:

```bash
export K2_RATE_LIMIT=8
export K2_RATE_WINDOW_SECONDS=60
python3 server.py
```

In another shell, run the multiprocessing harness:

```bash
python3 scripts/stress_concurrent.py \
  --base http://127.0.0.1:8766 \
  --workers 4 \
  --requests-per-worker 25 \
  --expect-429
```

The expected JSON report contains a `status_counts` entry for `429`, a positive `rate_limited` count, and latency statistics. The harness uses spawned processes and unique HMAC nonces; it fails on transport errors, unexpected server errors, or the absence of `429` when `--expect-429` is supplied. The SQLite limiter test separately verifies that concurrent writers cannot exceed the configured allowance.

## 11. Audit-chain and node-identity anomaly scan

The scanner is read-only and should be run against a copy or controlled maintenance view of the vault:

```bash
python3 scripts/audit_identity_scan.py \
  --collab-dir ./collab \
  --mesh-key "$MESH_KEY"
```

Exit code `0` means the audit chain, ledger-to-state node mapping, certificates, and persistent revoked-node registry passed the checks. Exit code `1` reports anomalies and never attempts repair. Exit code `2` means the scanner itself could not load the vault/auth state. High-signal anomalies include a broken or count-mismatched chain, unknown ledger node, revoked node appearing in the ledger, missing/expired/invalid certificate, or a revoked state missing from the persistent kill-switch store.

## 12. Code-quality audit

The repository can be checked with the same static-analysis tools used during review:

```bash
ruff check server.py collab scripts tests
bandit -q -r server.py collab scripts tests -f txt
python3 -m py_compile server.py collab/*.py tests/*.py scripts/*.py
```

Ruff is expected to pass. Bandit findings must be reviewed by severity and context; the server's long-lived loop and websocket boundary deliberately log and contain unexpected exceptions, while deployment-level concerns such as load shedding and key compromise remain separate operational controls.

## 10. Live attack simulation and browser validation

To generate disposable realtime events against a temporary preview, start the server with a deliberately low relay limit and use the committed simulator:

```bash
K2_RATE_LIMIT=3 K2_RATE_WINDOW_SECONDS=60 python3 server.py
python3 scripts/live_attack_sim.py \
  --base http://127.0.0.1:8766 \
  --owner "$COLLAB_OWNER_TOKEN" \
  --mesh-key "$MESH_KEY" \
  --node-id n-ui-attack \
  --attempts 6
```

The simulator must report a `tamper_status` of `403`, at least one `429` in `relay_statuses`, and no transport failure. The dashboard should then show `NODE TAMPERING`, `429 RATE LIMIT`, `AUDIT`, and `NODE IDENTITY` events in the same-origin WebSocket feed.

The owner kill-switch UI is verified in two stages. First, enter the owner token, select the disposable active node, and prepare a challenge. A wrong exact phrase or wrong `CONFIRM MESH REVOKE` value must produce `mesh confirmation mismatch` while the node remains active. A fresh challenge with the exact phrase and mesh confirmation must change the node card to `REVOKED`, persist the kill-switch, and emit a `KILL-SWITCH · <node_id> · revoked` activity event.

For responsive validation, render at 390px width and verify that the agent cards stack, the task board uses one column without duplicate `ALL TASKS`, discussion follows the board, and no horizontal overflow is present. The SYSTEM, TODAY, and COLLAB MESH sections remain reachable by vertical scroll.
