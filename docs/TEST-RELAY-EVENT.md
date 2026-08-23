# 📨 Tes Kirim Event via Relay (Uji Duksi Mesh)

> Dipakai dari VPS node partner (temen) untuk mengirim 1 signed event ke relay
> host (`https://k2-relay.noctisstudio.online`). Setelah berhasil, event masuk
> ledger host — bukti duksi mesh end-to-end.

## Jalankan di VPS partner (temen)

```bash
cd /opt/Hermes-K2-Monitor
cat > /tmp/k2_send_event.py <<'EOF'
import sys, json, urllib.request, urllib.error
sys.path.insert(0, '/opt/Hermes-K2-Monitor')
from collab.trust import TrustManager
from collab.vault import CollabVault
from collab.auth import MeshAuth

V = CollabVault('/opt/Hermes-K2-Monitor/collab')
auth = MeshAuth(V.auth_dir, V)
trust = TrustManager(auth.mesh_key, V.auth_dir)
node_id = 'k2-partner-node'

tok = ''
for line in open('/opt/Hermes-K2-Monitor/.env.mesh'):
    if line.startswith('COLLAB_LOCAL_NODE_TOKEN='):
        tok = line.split('=',1)[1].strip()

env = trust.sign(node_id, 'message', {
    'from': node_id, 'text': 'hello mesh test dari partner', 'ts_note': 'duksi'})
body = json.dumps(env).encode()
req = urllib.request.Request('https://k2-relay.noctisstudio.online/api/relay',
    data=body, headers={'Authorization':'Bearer '+tok,'Content-Type':'application/json'}, method='POST')
try:
    r = urllib.request.urlopen(req, timeout=20)
    print('STATUS', r.status, r.read().decode()[:200])
except urllib.error.HTTPError as e:
    print('HTTP', e.code, e.read().decode()[:300])
except Exception as e:
    print('ERR', repr(e))
EOF
python3 /tmp/k2_send_event.py
```

**Hasil yang diharapkan:**
```
STATUS 200 {"status": "ok", "relayed": true, "ledger_id": "..."}
```

## Verifikasi di sisi HOST (Bos)

Setelah temen kirim, host cek bahwa event masuk ledger:

```bash
# kalau ada endpoint view / atau cek file state:
# di /root/hermes-monitor, cek messages di collab/state.json atau ledger
grep -c "hello mesh test" /root/hermes-monitor/collab/state.json 2>/dev/null
# atau tail log relay
tail -5 /var/log/k2-monitor.log | grep -iE "collab_event|relay|message"
```

Kalau `STATUS 200` dari partner = **duksi mesh BERHASIL** — event terverifikasi,
masuk ledger, dan broadcast ke host. Ini bukti mesh jalan penuh, bukan cuma
koneksi.

---

> Catatan: op `message`, `task`, `file_update`, `broadcast`, `join` diizinkan.
> Semua event di-verify (HMAC + nonce + timestamp + node cert) sebelum diterima.
