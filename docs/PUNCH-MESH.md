# K2 Punch — P2P NAT-Punch Mesh (auto-connect)

Adds an automatic peer-to-peer UDP lane between mesh nodes, on top of the
existing HTTPS relay. Nodes discover each other via the authenticated relay,
exchange punch signals, and establish a low-latency UDP path. If NAT blocks
UDP, the existing HTTPS relay stays the data path — connectivity never
degrades.

## Anonymity-by-design (unchanged)

- No new controller/lighthouse ever sees a node's origin IP.
- Peers exchange their public endpoint ONLY with each other, over the already
  authenticated relay (HMAC + Ed25519 + rotating token).
- The UDP lane is MAC-authenticated (derived from mesh_key + both node ids +
  fresh nonce). A packet that does not carry a valid MAC is dropped.

## New in this build

- `collab/punch.py` — discovery, signalling, UDP NAT-punch, credential MAC.
- `op="punch"` added to `ALLOWED_OPS` in `collab/trust.py` (signalling rides the
  relay; consumed locally, not persisted to the ledger).
- `GET /api/mesh/peers` (signed node) — list active peers + lane status.
- `K2_PUNCH_UDP_PORT` (default 8767) — enable UDP punch on this port.
- Auto-discovery sweep in `_punch_auto_loop()` — emits intent to active peers
  without a lane, every 15s.

## Enable

```bash
# both nodes:
export K2_PUNCH_UDP_PORT=8767
python3 server.py
```

`setup-mesh-peer.sh` writes `K2_PUNCH_UDP_PORT` (default 8767) into `.env.mesh`
automatically. The `k2-monitor-keep-alive.sh` supervisor also enables it.

## Verify

```bash
# with a registered node token:
curl -H "Authorization: Bearer <node-token>" http://127.0.0.1:8766/api/mesh/peers
# → {"peers":[{node_id,status,lane:true/false}], "punch_enabled":true}
```

`lane: true` means a MAC-authenticated UDP path is established to that peer.
