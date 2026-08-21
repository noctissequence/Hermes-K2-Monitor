# Manus AI — Build Prompt: Hermes Collab Mesh

Goal: Extend Hermes K2 Monitor (aiohttp+websockets+vanilla HTML dashboard) into a trusted multi-VPS collaboration mesh — security-first, anonymous, tamper-proof. You will receive the full spec separately. Follow it exactly.

## HARD RULES (violating these = rework from zero, punishable)

1. **DO NOT redesign the existing UI/UX.** The dark cyberpunk terminal dashboard (`.panel`, `agent-card` Yerin diamond + Merlin hexagon, `task-col` PENDING/WORKING/DONE, `discussion-body`, `.dsk`/`.mob` toggle, metrics, clock) is KEPT 100%. You only ADD new panels/divs and REVISE elements that don't fit. Never delete or re-layout existing structure.
2. Zero external CDN. Zero emoji (inline SVG only). System font stack. Mobile via `.dsk`/`.mob`.
3. Existing files stay: `server.py` (aiohttp :8766 + websockets :8765) + `frontend/index.html`. Add modules, don't move/rename.
4. Security first, in this order: (1) isolation/no-intel, (2) anonymity, (3) trust/no-breach, (4) shared-file, (5) join-code.

## What to build (all inside this repo)

- **Collab vault**: `/collab/` ledger (append-only `ledger.jsonl`), `state.json` snapshot, `tasks/{pending,processing,done}`, `mirror/` per-node cache. Collab tasks are SEPARATE from `~/hermes-shared/tasks`.
- **Join handshake** (`/api/auth/invite` + `/api/auth/join`): owner generates join-code with TTL (default 300s, single-use, encrypted store), node presents code to join. Wrong/expired = `403`. After join → rotating token.
- **Trust/message signing**: every relay message `{node_id, op, payload, nonce, ts, sig}` with `sig = HMAC_SHA256`. Verify: ts ±30s, nonce not replayed, sig valid, op in whitelist (ALWAYS deny key/env/personal-path ops).
- **Anonymity relay** (`/api/relay`): verify signed message → append to ledger → broadcast. Node identity = semi-random `node_id`, no PII in payload.
- **Collab file API** (`/api/collab/file`): whitelist paths only `collab/{task_id}/`, anything else (`/root/.env`, `../../`, `.hermes`, `keys`) = `403`. Path traversal blocked.
- **Mesh ops** (`/api/collab/task`, `/api/collab/ledger`, `/api/mesh/revoke`).
- **Overkill P1**: node identity cert, kill-switch revoke, audit hash-chain (prev_hash per line).

## UI to ADD (don't break existing)
- "COLLAB MESH" panel: mesh status (CONNECTED/PARTITIONED), registered nodes (semi-random ids), shared-file list, collab tasks (reuse task-col style). Use existing `:root` vars and `.panel-head`/`.panel-body` pattern.
- "Invite Node" action (POST invite → show code + TTL countdown) and "Join Mesh" form (node_id + code).
- Trust indicator on each ledger entry: green dot = sig verified, red dot = tampered.

## Build order
1. Backend auth/mesh/trust (invite/join/relay/signing/nonce) — the core. 
2. Collab vault + file/task API (whitelist).
3. Overkill P1 (cert/revoke/audit hash-chain).
4. Frontend collab panel + invite/join UI + trust dots (additive only).
5. Verification per spec section 7.

## Must NOT do
- No NFS/sshfs shared mount. No Redis/NATS/Kafka. No full redesign. No moving existing files.

Deliver: working code diff vs existing repo, run the test list, report pass/fail per test, and confirm existing UI still renders unchanged.
