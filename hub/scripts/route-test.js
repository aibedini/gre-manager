'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');
const { RouteOrchestrator, inboundPayload, portEvidence, peerName } = require('../server/route-orchestrator');
const { parseShadowsocksLink } = require('../server/xui');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-route-test-'));
const db = openDb(dataDir);
const key = cryptoUtil.loadKey(dataDir);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });
}

async function main() {
  assert.equal(portEvidence('tcp LISTEN 0 10 0.0.0.0:3049\n', 3049).length, 1);
  assert.equal(portEvidence('tcp LISTEN 0 10 0.0.0.0:3050\n', 3049).length, 0);
  assert(peerName('Very-Long-Route-Name').length <= 11);

  const legacy = inboundPayload({
    remark: 'GRE-test', port: 3049, method: 'chacha20-ietf-poly1305',
    inboundPassword: 'inbound-secret', clientPassword: 'client-secret', email: 'navid',
    externalProxy: { host: '37.202.247.77', port: 3049 },
  });
  const legacyStream = JSON.parse(legacy.streamSettings);
  const legacySettings = JSON.parse(legacy.settings);
  assert.equal(legacyStream.externalProxy[0].dest, '37.202.247.77');
  assert.equal(legacySettings.clients[0].password, 'client-secret');
  assert.notEqual(legacySettings.password, legacySettings.clients[0].password);

  const iranId = Number(db.prepare(`INSERT INTO servers
    (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)`)
    .run('iran', '37.202.247.77', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw1'), Date.now()).lastInsertRowid);
  const foreignId = Number(db.prepare(`INSERT INTO servers
    (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)`)
    .run('foreign', '46.8.228.7', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw2'), Date.now()).lastInsertRowid);
  const panelId = Number(db.prepare(`INSERT INTO xui_panels
    (name,base_url,username,password_enc,created_at) VALUES (?,?,?,?,?)`)
    .run('panel', 'https://panel.example', 'admin', cryptoUtil.encrypt(key, 'panel-pass'), Date.now()).lastInsertRowid);

  let clientPassword = '';
  let inboundCreated = false;
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || 'GET' });
    if (url.endsWith('/login')) return json({ success: true }, 200, { 'set-cookie': 'session=test; Path=/; HttpOnly' });
    if (url.endsWith('/panel/api/inbounds/list')) return json({ success: true, obj: inboundCreated ? [{ id: 123, port: 3049 }] : [] });
    if (url.endsWith('/docs/openapi.json')) return json({ paths: { '/panel/api/hosts/add': { post: {} } } });
    if (url.endsWith('/panel/api/inbounds/add')) {
      const body = JSON.parse(opts.body);
      const settings = JSON.parse(body.settings);
      clientPassword = settings.clients[0].password;
      inboundCreated = true;
      assert.notEqual(settings.password, clientPassword);
      assert.equal(JSON.parse(body.streamSettings).externalProxy, undefined);
      return json({ success: true, obj: { id: 123 } });
    }
    if (url.endsWith('/panel/api/hosts/add')) {
      const body = JSON.parse(opts.body);
      assert.deepEqual(body.inboundIds, [123]);
      assert.equal(body.hosts[0], '37.202.247.77');
      return json({ success: true, obj: { id: 9 } });
    }
    if (url.includes('/panel/api/clients/links/')) {
      const auth = Buffer.from(`chacha20-ietf-poly1305:${clientPassword}`).toString('base64');
      return json({ success: true, obj: [`ss://${auth}@37.202.247.77:3049#GRE-test`] });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const commands = [];
  const sshExec = async (server, secret, command) => {
    commands.push({ server: server.name, command });
    if (command.includes('ss -H')) return {
      rc: 0,
      stdout: inboundCreated
        ? (server.name === 'iran' ? '-A PREROUTING -p tcp --dport 3049\n-A PREROUTING -p udp --dport 3049\n' : 'tcp LISTEN 0 10 0.0.0.0:3049\nudp UNCONN 0 0 0.0.0.0:3049\n')
        : '',
      stderr: '',
    };
    if (command.startsWith('gre iran peer add')) return { rc: 0, stdout: 'ok', stderr: '' };
    if (command.startsWith('ip link show')) return { rc: 0, stdout: 'state UP', stderr: '' };
    if (command.startsWith('timeout 8 bash')) return { rc: 0, stdout: '', stderr: '' };
    throw new Error(`unexpected ssh command: ${command}`);
  };
  const orchestrator = new RouteOrchestrator({ db, cryptKey: key, sshOptsFor: () => ({}), fetchImpl, sshExec });
  const route = await orchestrator.create({
    name: 'IR05-DE02', iranServerId: iranId, foreignServerId: foreignId,
    panelId, port: 3049, start: 3000, end: 3999, clientName: 'navid',
  });
  assert.equal(route.status, 'ACTIVE');
  assert.equal(route.capability, 'managed_hosts');
  assert.equal(parseShadowsocksLink(route.link).password, clientPassword);
  assert.equal(db.prepare('SELECT status FROM port_allocations').get().status, 'ACTIVE');
  assert(commands.some((x) => x.command.includes("--tcp-ports '3049'") && x.command.includes("--udp-ports '3049'")));
  assert(calls.some((x) => x.url.endsWith('/panel/api/hosts/add')));
  console.log('route orchestrator tests passed');
}

main().finally(() => {
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
