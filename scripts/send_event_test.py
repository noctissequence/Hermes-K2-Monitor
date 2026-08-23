#!/usr/bin/env python3
"""Test kirim event dari node partner ke relay host (K2 mesh).
STANDALONE — tidak butuh import module repo. Pakai HMAC + SHA256 + nonce.
Membaca mesh_key dengan decode base64 -> 32 bytes (SAMA seperti host).
Jalankan di VPS node partner.
"""
import sys, json, base64, secrets, hashlib, hmac, time, urllib.request, urllib.error

COLLAB_DIR = "/opt/Hermes-K2-Monitor/collab"
NODE_ID = "k2-partner-node"
HOST = "https://k2-relay.noctisstudio.online/api/relay"

def load_mesh_key():
    p = f"{COLLAB_DIR}/.auth/mesh_key"
    raw = open(p).read().strip()
    # decode base64 -> 32 bytes (host memakai ini). JANGAN .encode() string mentah.
    return base64.urlsafe_b64decode(raw.encode("ascii"))

def load_token():
    for env in [f"{COLLAB_DIR}/../.env.mesh", "/opt/Hermes-K2-Monitor/.env.mesh"]:
        try:
            for line in open(env):
                if line.startswith("COLLAB_LOCAL_NODE_TOKEN="):
                    return line.split("=", 1)[1].strip()
        except FileNotFoundError:
            continue
    return ""

def canonical_json(v):
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def main():
    mesh_key = load_mesh_key()
    token = load_token()
    if not token:
        print("GAGAL: COLLAB_LOCAL_NODE_TOKEN kosong — cek .env.mesh")
        return 1
    nonce = secrets.token_hex(16)
    payload = {"from": NODE_ID, "to": "n96ebaa",
               "text": "Halo Yerin! Ini partner (temen) — mesh dua arah jalan!"}
    body = {"node_id": NODE_ID, "op": "message", "payload": payload,
            "nonce": nonce, "ts": time.time()}
    # signing material: node_id + op + canonical(payload) + nonce + ts
    msg = f"{body['node_id']}|{body['op']}|{canonical_json(payload)}|{nonce}|{body['ts']}"
    body["sig"] = hmac.new(mesh_key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    req = urllib.request.Request(HOST, data=json.dumps(body).encode(), headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    }, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=20)
        print("STATUS", r.status, r.read().decode()[:250])
        return 0
    except urllib.error.HTTPError as e:
        print("HTTP", e.code, e.read().decode()[:300])
        return 1
    except Exception as e:
        print("ERR", repr(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
