'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');
const { RouteOrchestrator, inboundPayload, portEvidence, peerName } = require('../server/route-orchestrator');
const { XuiClient, parseShadowsocksLink, buildShadowsocksLink } = require('../server/xui');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-route-test-'));
const db = openDb(dataDir);
const key = cryptoUtil.loadKey(dataDir);
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });

async function main() {
  assert.equal(portEvidence('tcp LISTEN 0 10 0.0.0.0:3049\n', 3049).length, 1);
  assert.equal(portEvidence('tcp LISTEN 0 10 0.0.0.0:3050\n', 3049).length, 0);
  assert(peerName('Very-Long-Route-Name').length <= 11);
  assert.equal(parseShadowsocksLink(buildShadowsocksLink({ method: 'chacha20-ietf-poly1305', password: 'secret', host: '1.2.3.4', port: 3049 })).password, 'secret');

  const cookieCalls = [];
  const cookieClient = new XuiClient({ baseUrl: 'https://cookie.example', username: 'admin', password: 'secret', fetchImpl: async (url, opts = {}) => {
    cookieCalls.push({ url, opts });
    if (url.endsWith('/csrf-token')) return json({ success: true, obj: 'csrf-123' }, 200, { 'set-cookie': 'pre=one; Path=/' });
    if (url.endsWith('/login')) return json({ success: true }, 200, { 'set-cookie': '3x-ui=session; Path=/' });
    assert.equal(opts.headers['x-csrf-token'], 'csrf-123');
    return json({ success: true, obj: [] });
  } });
  await cookieClient.listInbounds();
  assert.equal(cookieCalls.length, 3);

  const clientsClient = new XuiClient({ baseUrl: 'https://clients.example', authType: 'token', token: 'token', fetchImpl: async () => json({ success: true, obj: [
    { id: 8, remark: 'SS-main', protocol: 'shadowsocks', settings: JSON.stringify({ clients: [{ email: 'navid' }, { email: 'navid' }, { email: 'sara' }] }) },
  ] }) });
  assert.deepEqual((await clientsClient.listClients()).map((item) => item.email), ['navid', 'sara']);

  const legacy = inboundPayload({ remark: 'GRE-test', port: 3049, method: 'chacha20-ietf-poly1305', inboundPassword: 'inbound-secret', clientPassword: 'client-secret', email: 'navid', externalProxy: { host: '37.202.247.77', port: 3049 } });
  assert.equal(JSON.parse(legacy.streamSettings).externalProxy[0].dest, '37.202.247.77');
  assert.equal(JSON.parse(legacy.settings).clients[0].password, 'client-secret');

  const iranId = Number(db.prepare('INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)').run('iran', '37.202.247.77', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw1'), Date.now()).lastInsertRowid);
  const foreignId = Number(db.prepare('INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)').run('foreign', '46.8.228.7', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw2'), Date.now()).lastInsertRowid);
  const panelId = Number(db.prepare('INSERT INTO xui_panels (name,base_url,username,auth_type,password_enc,created_at) VALUES (?,?,?,?,?,?)').run('panel', 'https://panel.example', '', 'token', cryptoUtil.encrypt(key, 'panel-token'), Date.now()).lastInsertRowid);
  let clientPassword = '';
  let inboundCreated = false;
  const fetchImpl = async (url, opts = {}) => {
    assert.equal(opts.headers.authorization, 'Bearer panel-token');
    if (url.endsWith('/panel/api/inbounds/list')) return json({ success: true, obj: inboundCreated ? [{ id: 123, port: 3049 }] : [] });
    if (url.endsWith('/panel/api/hosts/list')) return json({ success: true, obj: [] });
    if (url.endsWith('/panel/api/inbounds/add')) {
      const settings = JSON.parse(JSON.parse(opts.body).settings);
      clientPassword = settings.clients[0].password;
      inboundCreated = true;
      assert.notEqual(settings.password, clientPassword);
      return json({ success: true, obj: { id: 123 } });
    }
    if (url.endsWith('/panel/api/hosts/add')) return json({ success: true, obj: { groupId: 'host-group-9' } });
    if (url.includes('/panel/api/clients/links/')) {
      const auth = Buffer.from(`chacha20-ietf-poly1305:${clientPassword}`).toString('base64');
      return json({ success: true, obj: [`ss://${auth}@37.202.247.77:3049#GRE-test`] });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const commands = [];
  const sshExec = async (server, secret, command) => {
    commands.push({ server: server.name, command });
    if (command.includes('ss -H')) return { rc: 0, stdout: inboundCreated ? (server.name === 'iran' ? '-A PREROUTING -p tcp --dport 3049\n-A PREROUTING -p udp --dport 3049\n' : 'tcp LISTEN 0 10 0.0.0.0:3049\nudp UNCONN 0 0 0.0.0.0:3049\n') : '' };
    if (command === 'gre iran peer suggest --json' || command.startsWith('gre node suggest')) return { rc: 0, stdout: JSON.stringify({ name: 'ir01', subnet_base: '10.200', idx: 1, key: 1001 }) };
    if (command.startsWith('ping ') || command.startsWith('gre ') || command.startsWith('ip link') || command.startsWith('timeout 8')) return { rc: 0, stdout: 'UP' };
    throw new Error(`unexpected SSH command ${command}`);
  };
  const orchestrator = new RouteOrchestrator({ db, cryptKey: key, sshOptsFor: () => ({}), fetchImpl, sshExec });
  const route = await orchestrator.create({ name: 'IR05-DE02', iranServerId: iranId, foreignServerId: foreignId, panelId, port: 3049, start: 3000, end: 3999, clientName: 'navid' });
  assert.equal(route.status, 'ACTIVE');
  assert.equal(route.capability, 'managed_hosts');
  assert.equal(parseShadowsocksLink(route.link).password, clientPassword);
  assert.equal(route.outbound.settings.servers[0].password, clientPassword);
  assert.match(route.qr_data_url, /^data:image\/png;base64,/);
  const nodeIndex = commands.findIndex((item) => item.command.startsWith('gre node add'));
  const peerIndex = commands.findIndex((item) => item.command.startsWith('gre iran peer add'));
  assert(nodeIndex >= 0 && peerIndex > nodeIndex);
  assert(commands[peerIndex].command.includes("--tcp-ports '3049'") && commands[peerIndex].command.includes("--udp-ports '3049'"));
  assert(route.events.some((event) => event.stage === 'foreign_node_add'));
  assert(route.events.some((event) => event.stage === 'iran_peer_add'));
  assert(!JSON.stringify(route.events).includes(clientPassword));
  console.log('route orchestrator tests passed');
}

main().finally(() => { db.close(); fs.rmSync(dataDir, { recursive: true, force: true }); }).catch((err) => { console.error(err); process.exit(1); });
