#!/usr/bin/env bash
# Boot a real gre-hub against a throwaway database with one seeded connection, then serve.
#
# This exists because the Hub UI is otherwise only exercised with a DOM stub, and a stub
# cannot catch a global-scope collision, a CSS problem, or a handler that is wired to the
# wrong element. `scripts/ui-browser-test.js` drives this with a real browser.
#
#   bash scripts/boot-hub-for-ui.sh 4123          # then in another shell:
#   UI_BASE=http://127.0.0.1:4123 npm run test:ui
#
# Nothing here touches a real server: the seeded hosts are TEST-NET addresses (RFC 5737),
# so every remote operation fails on connect, which is what the run is meant to show.
set -u
HUB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$(mktemp -d)"
PORT="${1:-4123}"
PASSWD="${HUB_UI_PASSWORD:-uitest-pass-1}"

echo "DATA=$DATA"
echo "PORT=$PORT"
echo "PASSWORD=$PASSWD"

cd "$HUB_DIR" || exit 1
HUB_DATA_DIR="$DATA" PORT="$PORT" HUB_HOST=127.0.0.1 node server/index.js > "$DATA/hub.log" 2>&1 &
HUB_PID=$!
echo "HUB_PID=$HUB_PID"

for _ in $(seq 1 60); do
    grep -q 'listening' "$DATA/hub.log" 2>/dev/null && break
    sleep 0.5
done
if ! grep -q 'listening' "$DATA/hub.log"; then
    echo "HUB FAILED TO START"
    cat "$DATA/hub.log"
    exit 1
fi
echo "hub is up"

node - "$DATA" "$PORT" "$PASSWD" <<'EOS'
const dataDir = process.argv[2];
const port = process.argv[3];
const password = process.argv[4];
const base = `http://127.0.0.1:${port}`;

(async () => {
  let cookie = '';
  const call = async (p, { method = 'GET', body } = {}) => {
    const headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (cookie) headers.Cookie = cookie;
    const res = await fetch(base + p, {
      method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual',
    });
    const sc = res.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0];
    return { status: res.status };
  };

  const setup = await call('/api/setup', { method: 'POST', body: { password } });
  if (setup.status !== 200) { console.error('setup failed', setup.status); process.exit(1); }

  const { openDb } = require('./server/db');
  const crypto = require('./server/crypto');
  const db = openDb(dataDir);
  const key = crypto.loadKey(dataDir);
  const enc = (v) => crypto.encrypt(key, v);
  const now = Date.now();

  const server = (name, host) => Number(db.prepare(
    `INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,password_enc,key_installed,created_at)
     VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(name, host, 22, 'root', 'password', enc('pw'), enc('pw'), 0, now).lastInsertRowid);

  // RFC 5737 documentation addresses: real enough to attempt a connection, guaranteed
  // not to belong to anyone, so nothing outside this machine is ever contacted.
  const iranId = server('IR01', '198.51.100.20');
  const foreignId = server('Hetz02', '203.0.113.10');
  db.prepare('INSERT INTO xui_panels (name,base_url,username,auth_type,password_enc,created_at) VALUES (?,?,?,?,?,?)')
    .run('panel', 'https://panel.example:2053', 'admin', 'password', enc('tok'), now);

  const endpoint = JSON.stringify({
    iran_ip: '198.51.100.20', foreign_ip: '203.0.113.10', subnet_base: '10.200', idx: 1, key: 1001,
  });
  const id = Number(db.prepare(
    `INSERT INTO gre_routes
       (name,iran_server_id,foreign_server_id,panel_id,port,protocol,method,client_email,status,created_at,updated_at,
        peer_name,iran_ip,foreign_ip,tcp_ports,udp_ports,mss_clamp,iran_endpoint,connection_state)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run('de1', iranId, foreignId, 1, 3001, 'tcp,udp', 'shadowsocks', 'de1@test', 'ACTIVE', now, now,
    'de1', '198.51.100.20', '203.0.113.10', '3001', '3001', 1, endpoint, 'MATCHED').lastInsertRowid);
  db.close();
  console.log('CONNECTION_ID=' + id);
})();
EOS

echo "ready — drive it with: UI_BASE=http://127.0.0.1:$PORT npm run test:ui"
wait "$HUB_PID"
