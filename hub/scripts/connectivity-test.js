'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openDb } = require('../server/db');
const connectivity = require('../server/connectivity');
const actions = require('../server/actions');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-connectivity-test-'));
const db = openDb(dataDir);

function addServer(name, host) {
  return db.prepare(`
    INSERT INTO servers (name, host, ssh_port, username, auth_type, secret_enc, created_at)
    VALUES (?, ?, 22, 'root', 'password', 'test-secret', ?)
  `).run(name, host, Date.now()).lastInsertRowid;
}

async function main() {
  const iranId = addServer('iran-a', '37.202.247.77');
  const foreignId = addServer('foreign-a', '46.8.228.7');
  const iran = db.prepare('SELECT * FROM servers WHERE id = ?').get(iranId);
  const foreign = db.prepare('SELECT * FROM servers WHERE id = ?').get(foreignId);

  assert.equal(connectivity.isIPv4('37.202.247.77'), true);
  assert.equal(connectivity.isIPv4('37.202.247.77; touch /tmp/no'), false);
  assert.doesNotThrow(() => actions.buildAction('peer_add', { name: 'aparshetz01', foreign_ip: foreign.host }));
  assert.throws(() => actions.buildAction('peer_add', { name: 'abcdefghijkl', foreign_ip: foreign.host }), /1-11/);
  assert.throws(() => actions.buildAction('peer_add', { name: 'bad.name', foreign_ip: foreign.host }), /1-11/);
  assert.throws(() => connectivity.resolvePair(db, iran, 'peer_add', { foreign_ip: '46.8.228.7;id' }), /invalid public IPv4/);
  assert.throws(() => connectivity.resolvePair(db, iran, 'peer_add', { foreign_ip: '1.1.1.1' }), /registered in Hub/);

  const pair = connectivity.resolvePair(db, iran, 'setup_iran', { foreign_ip: foreign.host });
  const commands = [];
  const passed = await connectivity.checkPair(pair, {
    getSecret: () => 'secret', sshOptsFor: () => ({}),
    exec: async (server, secret, command) => {
      commands.push({ server: server.name, command });
      return { rc: 0, stdout: '2 received', stderr: '' };
    },
  });
  assert.equal(passed.ok, true);
  assert.deepEqual(commands, [
    { server: 'iran-a', command: 'ping -4 -c 2 -W 2 46.8.228.7' },
    { server: 'foreign-a', command: 'ping -4 -c 2 -W 2 37.202.247.77' },
  ]);
  connectivity.persistPair(db, passed);
  let saved = db.prepare('SELECT * FROM connectivity_checks').get();
  assert.equal(saved.iran_to_foreign, 1);
  assert.equal(saved.foreign_to_iran, 1);

  const failed = await connectivity.checkPair(pair, {
    getSecret: () => 'secret', sshOptsFor: () => ({}),
    exec: async (server) => server.id === iranId
      ? { rc: 1, stdout: '', stderr: '100% packet loss' }
      : { rc: 0, stdout: 'reachable', stderr: '' },
  });
  assert.equal(failed.ok, false);
  assert.equal(failed.iran_to_foreign.reachable, false);
  assert.equal(failed.foreign_to_iran.reachable, true);
  connectivity.persistPair(db, failed);
  saved = db.prepare('SELECT * FROM connectivity_checks').get();
  assert.equal(saved.iran_to_foreign, 0);
  assert.equal(saved.foreign_to_iran, 1);

  let calls = 0;
  const mismatch = await connectivity.checkPair(pair, {
    getSecret: () => 'secret', sshOptsFor: () => ({}),
    exec: async () => {
      calls++;
      return { rc: -1, stdout: '', stderr: 'mismatch', hostkey_mismatch: true, presented_fp: 'SHA256:new' };
    },
  });
  assert.equal(mismatch.hostkey_mismatch, true);
  assert.equal(calls, 1);

  db.prepare('DELETE FROM servers WHERE id = ?').run(foreignId);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM connectivity_checks').get().n, 0);
  console.log('connectivity tests passed');
}

main().finally(() => {
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
