'use strict';

// SSH provisioning safety.
//
// The design rule this suite exists to defend:
//
//   Installing the Hub key must never break, remove or replace a server's
//   existing SSH access. The Hub key is an ADDITIONAL authentication method, so if
//   a server was reachable with root/password before provisioning the same
//   password must still work afterwards — for the Hub and for PuTTY alike.
//
// Two v2.15.2 behaviours violated it: provisioning cleared servers.password_enc
// unless the operator ticked a box that defaulted to OFF, and nothing verified
// that the password path still worked afterwards. Both are covered here, at the
// module level and over real HTTP (via the hub's HUB_TEST_SSH_MODULE hook).
//
// Run with: node scripts/provision-safety-test.js

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

const { assert, makeHarness, check, checkAsync, report } = require('./_harness');
const provision = require('../server/provision');
const ssh = require('../server/ssh');
const { decrypt, encrypt } = require('../server/crypto');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASSWORD = 'shape-test-pass-1';
// The harness seeds both of its servers with secret_enc = encrypt('pw1'/'pw2'), so
// the fallback in a module-level fixture must be that same string.
const HARNESS_PASSWORD = 'pw1';
const MODULE_SECRET = 'PRIVATE KEY MATERIAL';

// Ask the OS for a free port and release it immediately. A random high port can
// land in a range Windows refuses (EACCES), which surfaced as a flaky
// "server exited early" in this suite.
const net = require('net');
async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// ---------------------------------------------------------------------------
// Boot the real hub with the test SSH transport wired in. This exercises the
// actual auth middleware, the actual routes and the actual provisioning stages.
// ---------------------------------------------------------------------------
async function bootHub(scenario) {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-ssh-'));
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server', 'index.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      HUB_HOST: '127.0.0.1',
      HUB_DATA_DIR: dataDir,
      HUB_TEST_SSH_MODULE: path.join(__dirname, '_fake-ssh.js'),
      HUB_TEST_SSH_SCENARIO: scenario,
      HUB_TEST_SSH_DEBUG: process.env.HUB_TEST_SSH_DEBUG || '',
      HUB_TEST_SSH_PASSWORD: 'root-secret',
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  const base = `http://127.0.0.1:${port}`;
  let buf = '';
  child.stdout.on('data', (d) => { buf += d; });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (buf.includes('gre-hub listening')) break;
    if (child.exitCode !== null) throw new Error(`server exited early (${child.exitCode})\n${buf}`);
    await sleep(100);
  }

  const client = {
    cookie: '', csrf: '',
    async call(pathname, { method = 'GET', body, raw = false } = {}) {
      const headers = {};
      if (body) headers['Content-Type'] = 'application/json';
      if (client.cookie) headers.Cookie = client.cookie;
      if (method !== 'GET' && client.csrf) headers['x-csrf-token'] = client.csrf;
      const res = await fetch(base + pathname, {
        method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual',
      });
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) client.cookie = setCookie.split(';')[0];
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = raw ? text : null; }
      if (data && data.csrf) client.csrf = data.csrf;
      return { status: res.status, data, text };
    },
  };

  let sharedDb = null;
  return {
    base, dataDir, client,
    // One long-lived handle. Opening and closing the SQLite file repeatedly while
    // the hub holds it caused intermittent "database is locked".
    db() {
      if (!sharedDb) {
        const { openDb } = require('../server/db');
        sharedDb = openDb(dataDir);
      }
      return sharedDb;
    },
    // Wait until the asynchronous auto-provisioning has settled.
    async waitForProvision(id, { keyInstalled = true, timeoutMs = 15000 } = {}) {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const row = this.db().prepare('SELECT * FROM servers WHERE id = ?').get(id);
        if (row && (keyInstalled ? row.key_installed === 1 : true)) return row;
        await sleep(120);
      }
      return this.db().prepare('SELECT * FROM servers WHERE id = ?').get(id);
    },
    async close() {
      if (sharedDb) { try { sharedDb.close(); } catch { /* already closed */ } sharedDb = null; }
      child.kill();
      await sleep(120);
      try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    },
  };
}

function makeAuditLog() {
  const events = [];
  const audit = (serverId, serverName, action, params, rc, output) => {
    events.push({ action, rc, output, params });
  };
  audit.events = events;
  audit.has = (action) => events.some((e) => e.action === action);
  return audit;
}

// A fake transport for the module-level stage tests.
//
// `password` defaults to the harness's own primary credential, because on a
// password server the primary secret and the fallback ARE the same string — a
// fixture that gave them different values would not model a real server.
function makeFakeServer(opts = {}) {
  const state = {
    password: opts.password === undefined ? HARNESS_PASSWORD : opts.password,
    authorizedKeys: opts.authorizedKeys || [
      'ssh-ed25519 AAAAOPERATORKEY operator@laptop',
      'ssh-rsa AAAAVENDORKEY vendor@backup',
    ],
    installed: [],
    passwordAuthWorks: opts.passwordAuthWorks !== false,
    keyAuthWorks: opts.keyAuthWorks !== false,
  };

  const stdoutFor = (command) => {
    for (const marker of [provision.PRE_MARKER, provision.KEY_MARKER, provision.POST_MARKER, 'key-installed', 'key-removed']) {
      if (command.includes(marker)) return `${marker}\n`;
    }
    return 'ok\n';
  };

  const exec = async (server, secret, command, opts = {}) => {
    // The generated public key is embedded in a multi-line, quoted printf
    // argument, so extract it by its own comment instead of matching the whole
    // command. This mirrors what the remote shell actually appends.
    const hubKeyLine = (command.match(/ssh-(?:ed25519|rsa) [^\s']+ gre-hub-\d+/) || [])[0];
    if (process.env.HUB_DEBUG_FAKE && command.includes('authorized_keys')) {
      console.error(`[fake-install] matched=${!!hubKeyLine} keysBefore=${state.authorizedKeys.length} cmdHasPrintf=${command.includes('printf')}`);
    }
    if (hubKeyLine && command.includes('authorized_keys')) {
      const comment = (hubKeyLine.match(/gre-hub-\d+/) || [])[0];
      if (comment) state.authorizedKeys = state.authorizedKeys.filter((k) => !k.includes(comment));
      state.authorizedKeys.push(hubKeyLine);
      state.installed.push(hubKeyLine);
    }
    // A pure removal (the key-delete path) deletes only our own line. An install
    // also carries this grep token — to drop a stale line before appending — so the
    // removal must be modelled only for the command that actually is a removal.
    const removeMatch = command.match(/grep -vF '([^']+)'/);
    if (removeMatch && !command.includes('printf')) {
      state.authorizedKeys = state.authorizedKeys.filter((k) => !k.includes(removeMatch[1]));
    }

    const mode = opts.authMode || (server.auth_type === 'key' ? 'key' : 'password');
    const fail = () => ({ rc: -1, stdout: '', stderr: 'ssh error: All configured authentication methods failed', error_class: 'auth' });

    if (mode === 'password') {
      if (!state.passwordAuthWorks || secret !== state.password) return fail();
      return { rc: 0, stdout: stdoutFor(command), stderr: '' };
    }
    // Key mode succeeds once our line is present in authorized_keys — reading the
    // recorded file rather than a separate list keeps the fixture honest.
    const hasHubKey = state.authorizedKeys.some((k) => k.includes('gre-hub-'));
    const isPrivateKey = /BEGIN (OPENSSH|RSA|EC) PRIVATE KEY/.test(String(secret));
    if (process.env.HUB_DEBUG_FAKE) {
      console.error(`[fake] mode=${mode} privateKey=${isPrivateKey} hubKey=${hasHubKey} keys=${state.authorizedKeys.length} cmd=${command.slice(0, 30)}`);
    }
    if (state.keyAuthWorks && isPrivateKey && hasHubKey) {
      return { rc: 0, stdout: stdoutFor(command), stderr: '' };
    }
    return fail();
  };

  return { state, exec, stdoutFor };
}

const rowFor = (h, overrides = {}) => ({
  ...h.db.prepare('SELECT * FROM servers WHERE id = ?').get(h.iranId),
  host_key_fp: 'SHA256:pinned',
  ...overrides,
});

const pinnedOpts = () => ({ hostKey: { expected: 'SHA256:pinned' } });

async function main() {
  console.log('MODULE LEVEL — the four provisioning stages:');

  console.log('\nTEST 1 — provisioning preserves the encrypted password fallback:');
  await checkAsync('the password survives a successful key install', async () => {
    const h = makeHarness();
    try {
      const audit = makeAuditLog();
      const fake = makeFakeServer();
      h.db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(encrypt(h.key, HARNESS_PASSWORD), h.iranId);
      const row = rowFor(h);

      const result = await provision.provision(h.db, h.dataDir, h.key, row, pinnedOpts, audit, fake);

      assert.equal(result.ok, true, `expected success: ${JSON.stringify(result)}`);
      assert.equal(result.password_retained, true, 'the password must be reported as retained');
      const after = h.db.prepare('SELECT * FROM servers WHERE id = ?').get(h.iranId);
      assert.equal(after.auth_type, 'key');
      assert.equal(after.key_installed, 1);
      assert(after.password_enc, 'the fallback password must still be stored');
      assert.equal(decrypt(h.key, after.password_enc), HARNESS_PASSWORD);
      assert(after.password_verified_at, 'and marked verified');
      assert(after.key_verified_at, 'with the key verified too');
      assert(after.secret_enc, 'the private key must be the primary secret');
      assert.notEqual(after.secret_enc, after.password_enc, 'the two credentials must not share a column');
    } finally { h.cleanup(); }
  });

  console.log('\nTEST 2/14/15 — the install is additive and touches nothing else:');
  await checkAsync('every pre-existing authorized_keys line is preserved', async () => {
    const h = makeHarness();
    try {
      const fake = makeFakeServer();
      h.db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(encrypt(h.key, HARNESS_PASSWORD), h.iranId);
      await provision.provision(h.db, h.dataDir, h.key, rowFor(h), pinnedOpts, makeAuditLog(), fake);
      assert(fake.state.authorizedKeys.some((k) => k.includes('operator@laptop')),
        `operator key lost: ${JSON.stringify(fake.state.authorizedKeys)}`);
      assert(fake.state.authorizedKeys.some((k) => k.includes('vendor@backup')),
        `vendor key lost: ${JSON.stringify(fake.state.authorizedKeys)}`);
      assert(fake.state.authorizedKeys.some((k) => k.includes('gre-hub-')), 'hub key present');
    } finally { h.cleanup(); }
  });

  check('the install command cannot change login policy', () => {
    const cmd = provision.installCommand('ssh-ed25519 AAAAHUB gre-hub-3', 3);
    for (const token of ['sshd_config', 'PasswordAuthentication', 'PermitRootLogin', 'AuthenticationMethods',
      'KbdInteractiveAuthentication', 'UsePAM', 'passwd', 'usermod', 'chpasswd', 'chage',
      '/etc/shadow', '/etc/passwd', 'pam.d', 'systemctl restart ssh', '/etc/']) {
      assert(!cmd.includes(token), `the install command must not reference ${token}`);
    }
    assert(/~\/\.ssh/.test(cmd), 'it operates on ~/.ssh');
    assert(/grep -vF 'gre-hub-3'/.test(cmd), 'it removes only its own previous line');
    assert(/authorized_keys/.test(cmd), 'and writes authorized_keys');
  });

  check('the removal command deletes only the hub line', () => {
    const cmd = provision.removeCommand(9);
    assert(/grep -vF 'gre-hub-9'/.test(cmd), 'removal is scoped to our own comment');
    assert(!cmd.includes('sshd_config') && !cmd.includes('passwd'), 'no policy file touched');
  });

  console.log('\nTEST 3/4 — auth_type flips only after the key is proven:');
  await checkAsync('a successful verify switches the primary method and records every stage', async () => {
    const h = makeHarness();
    try {
      const audit = makeAuditLog();
      const fake = makeFakeServer();
      h.db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(encrypt(h.key, HARNESS_PASSWORD), h.iranId);
      await provision.provision(h.db, h.dataDir, h.key, rowFor(h), pinnedOpts, audit, fake);
      assert.equal(h.db.prepare('SELECT auth_type FROM servers WHERE id = ?').get(h.iranId).auth_type, 'key');
      for (const action of ['ssh_password_precheck_pass', 'ssh_key_installed', 'ssh_key_verify_pass', 'ssh_password_postcheck_pass']) {
        assert(audit.has(action), `missing audit event ${action}`);
      }
    } finally { h.cleanup(); }
  });

  console.log('\nTEST 16 — pre PASS + key PASS + post FAIL is not a success:');
  await checkAsync('a password that stops working after install yields NEEDS_REVIEW', async () => {
    const h = makeHarness();
    try {
      const audit = makeAuditLog();
      const crypto = require('../server/crypto');
      h.db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(crypto.encrypt(h.key, HARNESS_PASSWORD), h.iranId);
      const fake = makeFakeServer();
      let postChecks = 0;
      const scripted = {
        exec: async (server, secret, command, opts = {}) => {
          if (command.includes(provision.POST_MARKER) && opts.authMode === 'password') {
            postChecks += 1;
            return { rc: -1, stdout: '', stderr: 'ssh error: All configured authentication methods failed', error_class: 'auth' };
          }
          return fake.exec(server, secret, command, opts);
        },
      };
      const result = await provision.provision(h.db, h.dataDir, h.key, rowFor(h), pinnedOpts, audit, scripted);

      assert.equal(result.ok, false, 'this must NOT be reported as success');
      assert.equal(result.status, 'NEEDS_REVIEW');
      assert(/no longer verified/i.test(result.detail), result.detail);
      assert.equal(result.password_retained, true);
      assert(audit.has('ssh_password_postcheck_fail'), 'the failure must be audited');
      assert.equal(postChecks, 1, 'the post-check must have actually run');
      const after = h.db.prepare('SELECT * FROM servers WHERE id = ?').get(h.iranId);
      assert(after.password_enc, 'the stored password must survive a failed post-check');
      assert.equal(after.key_installed, 1, 'the key stays installed, because it does work');
    } finally { h.cleanup(); }
  });

  console.log('\nTEST 5/6/7 — fallback policy:');
  check('only an authentication failure is classified as retryable', () => {
    const cases = [
      ['connect ETIMEDOUT 10.0.0.1:22', 'transport'],
      ['connect ECONNREFUSED 10.0.0.1:22', 'transport'],
      ['connect EHOSTUNREACH 10.0.0.1:22', 'transport'],
      ['no route to host', 'transport'],
      ['Handshake failed', 'transport'],
      ['All configured authentication methods failed', 'auth'],
      ['Received host key mismatch', 'hostkey'],
    ];
    for (const [message, want] of cases) {
      assert.equal(ssh.classifyConnectionError(new Error(message), null), want, `${message} should be ${want}`);
    }
    assert.equal(ssh.classifyConnectionError(new Error('All configured authentication methods failed'), { mismatch: 'SHA256:x' }),
      'hostkey', 'a host key mismatch outranks an auth failure');
  });

  check('a forced auth mode refuses to let the other method rescue it', () => {
    // The verification stages must be real: forcing a mode also disables fallback.
    assert.equal(ssh.resolveAuthMode({ auth_type: 'key' }, { authMode: 'password' }), 'password');
    assert.equal(ssh.resolveAuthMode({ auth_type: 'password' }, { authMode: 'key' }), 'key');
    assert.equal(ssh.resolveAuthMode({ auth_type: 'key' }, {}), 'key');
    assert.equal(ssh.resolveAuthMode({ auth_type: 'password' }, {}), 'password');
  });

  console.log('\nTEST 8/9 — the last verified access method is protected:');
  await checkAsync('removing the key with no verified password is BLOCKED', async () => {
    const h = makeHarness();
    try {
      const audit = makeAuditLog();
      const fake = makeFakeServer({ passwordAuthWorks: false });
      h.db.prepare('UPDATE servers SET auth_type=?, secret_enc=?, key_installed=1, password_enc=? WHERE id=?')
        .run('key', encrypt(h.key, MODULE_SECRET), encrypt(h.key, 'stale-password'), h.iranId);
      const before = h.db.prepare('SELECT * FROM servers WHERE id = ?').get(h.iranId);

      const result = await provision.removeKey(h.db, h.dataDir, h.key, rowFor(h), pinnedOpts, audit, fake);

      assert.equal(result.ok, false, 'removal must be refused');
      assert.equal(result.status, 'BLOCKED');
      assert(/Cannot remove the last verified SSH access method/.test(result.error), result.error);
      assert(audit.has('key_delete_blocked'), 'the refusal must be audited');
      const after = h.db.prepare('SELECT * FROM servers WHERE id = ?').get(h.iranId);
      assert.equal(after.key_installed, 1, 'the key must still be installed');
      assert.equal(after.secret_enc, before.secret_enc, 'the key material must be untouched');
      assert(!audit.has('key_delete'), 'no delete event may be recorded');
    } finally { h.cleanup(); }
  });

  await checkAsync('removing the key with a verified password is allowed', async () => {
    const h = makeHarness();
    try {
      const audit = makeAuditLog();
      const fake = makeFakeServer();
      h.db.prepare('UPDATE servers SET auth_type=?, secret_enc=?, key_installed=1, password_enc=? WHERE id=?')
        .run('key', encrypt(h.key, MODULE_SECRET), encrypt(h.key, HARNESS_PASSWORD), h.iranId);

      const result = await provision.removeKey(h.db, h.dataDir, h.key, rowFor(h), pinnedOpts, audit, fake);

      assert.equal(result.ok, true, `expected allowed: ${JSON.stringify(result)}`);
      const after = h.db.prepare('SELECT * FROM servers WHERE id = ?').get(h.iranId);
      assert.equal(after.auth_type, 'password');
      assert.equal(after.key_installed, 0);
      assert.equal(decrypt(h.key, after.secret_enc), HARNESS_PASSWORD, 'the verified password becomes primary');
    } finally { h.cleanup(); }
  });

  await checkAsync('a server with no password at all cannot lose its key', async () => {
    const h = makeHarness();
    try {
      const fake = makeFakeServer();
      h.db.prepare('UPDATE servers SET auth_type=?, secret_enc=?, key_installed=1, password_enc=NULL WHERE id=?')
        .run('key', encrypt(h.key, MODULE_SECRET), h.iranId);
      const result = await provision.removeKey(h.db, h.dataDir, h.key, rowFor(h), pinnedOpts, makeAuditLog(), fake);
      assert.equal(result.status, 'BLOCKED');
      assert.equal(h.db.prepare('SELECT key_installed FROM servers WHERE id = ?').get(h.iranId).key_installed, 1);
    } finally { h.cleanup(); }
  });

  console.log('\nREPO AUDIT — no source file changes login policy (spec 4/5/23):');
  check('nothing in the repository can run passwd/usermod/chpasswd or edit sshd_config', () => {
    const roots = [path.join(__dirname, '..', '..'), path.join(__dirname, '..', 'server'),
      path.join(__dirname, '..', 'public'), path.join(__dirname, '..', 'scripts')];
    const files = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name === 'data' || entry.name === '.git'
          || entry.name === '.tools' || entry.name === 'dist') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (/\.(js|sh)$/.test(entry.name)) files.push(full);
      }
    };
    for (const r of roots) if (fs.existsSync(r)) walk(r);

    const forbidden = [
      { re: /(?:^|[\s'"`;&|(])(?:sudo\s+)?passwd(?:\s|$)/m, why: 'passwd invocation' },
      { re: /usermod\s+[^\n]*-p\b/, why: 'usermod -p' },
      { re: /chpasswd/, why: 'chpasswd' },
      { re: /sshd_config/, why: 'sshd_config' },
      { re: /PasswordAuthentication/, why: 'PasswordAuthentication' },
      { re: /PermitRootLogin/, why: 'PermitRootLogin' },
      { re: /AuthenticationMethods/, why: 'AuthenticationMethods' },
      { re: /UsePAM/, why: 'UsePAM' },
    ];
    for (const file of files) {
      // Strip comments before scanning: this file set legitimately NAMES the
      // forbidden tokens (that is the point of the audit), and provision.js
      // explains in prose why it must never run them.
      const text = fs.readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:])\/\/.*$/gm, '$1')
        .replace(/(^|\s)#.*$/gm, '$1');
      if (path.basename(file) === 'provision-safety-test.js') continue;
      for (const { re, why } of forbidden) {
        const hit = text.match(re);
        assert(!hit, `${path.relative(path.join(__dirname, '..'), file)} contains ${why}: ${hit && hit[0]}`);
      }
    }
    assert(files.length > 20, `expected to scan the repo, only saw ${files.length} files`);
  });

  console.log('\nHTTP LEVEL — real hub, real routes, scripted SSH transport:');

  console.log('\nTEST 1b — adding a server keeps the password and succeeds end to end:');
  await checkAsync('a fresh server ends up with both a verified key and a verified password', async () => {
    const hub = await bootHub('happy');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200, `setup failed: ${r.status}`);
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 'fresh', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      assert.equal(r.status, 201, `add server failed: ${JSON.stringify(r.data)}`);
      const id = r.data.id;
      assert(r.data.ssh_auth, 'the response must already carry ssh_auth');
      assert.equal(r.data.ssh_auth.password_fallback, 'stored', 'the password is stored from the start');
      assert(!JSON.stringify(r.data).includes('root-secret'), 'the password must not be echoed back');

      // Provisioning runs asynchronously.
      const deadline = Date.now() + 15000;
      let row = null;
      while (Date.now() < deadline) {
        row = hub.db().prepare('SELECT * FROM servers WHERE id = ?').get(id);
        if (row && row.key_installed === 1) break;
        await sleep(150);
      }
      assert(row, 'the server row must exist');
      assert.equal(row.key_installed, 1, 'the key should have been installed');
      assert.equal(row.auth_type, 'key');
      assert(row.password_enc, 'the password fallback must still be stored');
      assert.equal(decrypt(require('../server/crypto').loadKey(hub.dataDir), row.password_enc), 'root-secret');
      assert(row.key_verified_at, 'the key must be marked verified');
      assert(row.password_verified_at, 'the password must be marked verified');

      // And the API agrees.
      const one = await hub.client.call(`/api/servers/${id}`);
      assert.equal(one.data.ssh_auth.primary, 'key');
      assert.equal(one.data.ssh_auth.key, 'verified');
      assert.equal(one.data.ssh_auth.password_fallback, 'stored');
      assert.equal(one.data.has_fallback_password, true);
    } finally { await hub.close(); }
  });

  console.log('\nTEST 16b — the same flow reports NEEDS_REVIEW when the password breaks:');
  await checkAsync('post-check failure is visible over the API, not silently successful', async () => {
    const hub = await bootHub('postcheck_fail');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200);
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 'broken', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      const id = r.data.id;

      const deadline = Date.now() + 15000;
      let events = [];
      while (Date.now() < deadline) {
        const list = await hub.client.call('/api/actions?kind=auth');
        events = Array.isArray(list.data) ? list.data : [];
        if (events.some((e) => e.action === 'ssh_password_postcheck_fail')) break;
        await sleep(150);
      }
      assert(events.some((e) => e.action === 'ssh_password_postcheck_fail'),
        `expected a postcheck failure event, saw: ${events.map((e) => e.action).join(', ')}`);
      const failEvent = events.find((e) => e.action === 'ssh_password_postcheck_fail');
      assert(/no longer verif/i.test(failEvent.output), failEvent.output);
      assert(!/no longer verif.*password=/i.test(failEvent.output), 'the audit message must not carry the password');

      const db = hub.db();
      const row = db.prepare('SELECT * FROM servers WHERE id = ?').get(id);
      assert(row.password_enc, 'the password must be kept even when the post-check fails');
      assert.equal(row.key_installed, 1, 'the key stays, because it genuinely works');
    } finally { await hub.close(); }
  });

  console.log('\nTEST 11/12b — the fallback-password API refuses bad input and accepts good:');
  await checkAsync('an unverifiable password is rejected and a working one is stored', async () => {
    const hub = await bootHub('happy');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200);
      // A server that is NOT auto-provisioned: delete the key state so the row
      // stays a password server, then exercise the fallback endpoints.
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 't', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      const id = r.data.id;
      await sleep(600);

      const bad = await hub.client.call(`/api/servers/${id}/fallback-password`, {
        method: 'PUT', body: { password: 'definitely-wrong' },
      });
      assert.equal(bad.status, 400, `expected 400 for a wrong password, got ${bad.status} ${JSON.stringify(bad.data)}`);

      const good = await hub.client.call(`/api/servers/${id}/fallback-password`, {
        method: 'PUT', body: { password: 'root-secret' },
      });
      assert.equal(good.status, 200, `expected 200, got ${good.status} ${JSON.stringify(good.data)}`);
      assert.equal(good.data.server.ssh_auth.password_fallback, 'stored');
      assert(good.data.server.ssh_auth.password_verified_at, 'a verified password must be timestamped');
      assert(!JSON.stringify(good.data).includes('root-secret'), 'the password must never be returned');

      const missing = await hub.client.call(`/api/servers/${id}/fallback-password`, { method: 'PUT', body: {} });
      assert.equal(missing.status, 400, 'a missing password must be rejected');
    } finally { await hub.close(); }
  });

  console.log('\nTEST 12c — deleting the fallback clears only the hub copy:');
  await checkAsync('DELETE removes the stored password and says the server is unchanged', async () => {
    const hub = await bootHub('happy');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200);
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 'd', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      const id = r.data.id;
      await sleep(600);

      const del = await hub.client.call(`/api/servers/${id}/fallback-password`, { method: 'DELETE' });
      assert.equal(del.status, 200, JSON.stringify(del.data));
      assert(/unchanged/i.test(del.data.note), 'the response must be explicit that the server was not modified');
      assert.equal(del.data.server.ssh_auth.password_fallback, 'not_stored');
      const db = hub.db();
      const row = hub.db().prepare('SELECT password_enc, password_verified_at FROM servers WHERE id = ?').get(id);
      assert.equal(row.password_enc, null);
      assert.equal(row.password_verified_at, null);
    } finally { await hub.close(); }
  });

  console.log('\nTEST 13b — Edit Server on a key server stores the fallback, not the key:');
  await checkAsync('the primary private key is byte-identical afterwards', async () => {
    const hub = await bootHub('happy');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200);
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 'e', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      const id = r.data.id;
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        const db = hub.db();
        const row = hub.db().prepare('SELECT key_installed FROM servers WHERE id = ?').get(id);
        if (row && row.key_installed === 1) break;
        await sleep(150);
      }

      const before = hub.db().prepare('SELECT secret_enc FROM servers WHERE id = ?').get(id).secret_enc;

      // A wrong password must be refused rather than stored.
      const bad = await hub.client.call(`/api/servers/${id}`, { method: 'PUT', body: { secret: 'not-the-password' } });
      assert.equal(bad.status, 400, `expected 400, got ${bad.status}`);

      // The real password is stored as the fallback.
      const ok = await hub.client.call(`/api/servers/${id}`, { method: 'PUT', body: { secret: 'root-secret' } });
      assert.equal(ok.status, 200, JSON.stringify(ok.data));

      const after = hub.db().prepare('SELECT secret_enc, password_enc, auth_type, key_installed FROM servers WHERE id = ?').get(id);
      assert.equal(after.secret_enc, before, 'the PRIMARY private key must be untouched');
      assert.equal(after.auth_type, 'key', 'the primary method must remain the key');
      assert.equal(after.key_installed, 1);
      assert(after.password_enc, 'the password must be stored as the fallback');
      assert.equal(decrypt(require('../server/crypto').loadKey(hub.dataDir), after.password_enc), 'root-secret');
    } finally { await hub.close(); }
  });

  console.log('\nTEST 17b — no secret appears in any API response:');
  await checkAsync('password and key material stay out of everything the UI can see', async () => {
    const hub = await bootHub('happy');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200);
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 's', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      const id = r.data.id;
      await sleep(800);

      const list = await hub.client.call('/api/servers');
      const one = await hub.client.call(`/api/servers/${id}`);
      const events = await hub.client.call('/api/actions?kind=auth');
      const payload = `${JSON.stringify(list.data)}${JSON.stringify(one.data)}${JSON.stringify(events.data)}`;

      assert(!payload.includes('root-secret'), 'the plaintext password leaked into a response');
      assert(!payload.includes('secret_enc'), 'the encrypted secret column leaked');
      assert(!/BEGIN (OPENSSH|RSA|EC) PRIVATE KEY/.test(payload), 'private key material leaked');
      assert(!/ssh-ed25519 AAA/.test(payload), 'a public key body leaked into the API');
      // The key comment is fine and useful; the key body is not.
      assert(payload.includes('gre-hub-') || payload.includes('"key"'), 'the key state should be reported');
    } finally { await hub.close(); }
  });

  console.log('\nTEST 10b — a key server with no stored password reports NOT STORED:');
  await checkAsync('the API never invents a fallback it does not have', async () => {
    const hub = await bootHub('happy');
    try {
      let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
      assert.equal(r.status, 200);
      r = await hub.client.call('/api/servers', {
        method: 'POST', body: { name: 'n', host: '127.0.0.1', ssh_port: 22, username: 'root', password: 'root-secret' },
      });
      const id = r.data.id;
      await sleep(800);
      // Simulate the legacy state: a key with no stored password.
      hub.db().prepare('UPDATE servers SET password_enc = NULL, password_verified_at = NULL WHERE id = ?').run(id);

      const one = await hub.client.call(`/api/servers/${id}`);
      assert.equal(one.data.ssh_auth.password_fallback, 'not_stored');
      assert.equal(one.data.ssh_auth.primary, 'key');
      assert.equal(one.data.has_fallback_password, false);
      assert.equal(one.data.ssh_auth.password_verified_at, null);
    } finally { await hub.close(); }
  });

  report('ssh provisioning safety tests');
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
