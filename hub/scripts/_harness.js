'use strict';
// _harness.js — shared fixtures for the hub test scripts: a temp SQLite data
// dir, an IRAN/FOREIGN server pair, a 3x-ui panel row, a scripted SSH
// transport and small assertion helpers.

require('./_sqlite');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');
const { RouteOrchestrator } = require('../server/route-orchestrator');

function makeHarness() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-test-'));
  const db = openDb(dataDir);
  const key = cryptoUtil.loadKey(dataDir);

  const insert = (sql, ...params) => Number(db.prepare(sql).run(...params).lastInsertRowid);
  const iranId = insert(
    'INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
    'iran', '37.202.247.77', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw1'), Date.now()
  );
  const foreignId = insert(
    'INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
    'foreign', '46.8.228.7', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw2'), Date.now()
  );
  const panelId = insert(
    'INSERT INTO xui_panels (name,base_url,username,auth_type,password_enc,created_at) VALUES (?,?,?,?,?,?)',
    'panel', 'https://panel.example', '', 'token', cryptoUtil.encrypt(key, 'panel-token'), Date.now()
  );

  return {
    dataDir,
    db,
    key,
    iranId,
    foreignId,
    panelId,
    insert,
    cleanup() {
      try { db.close(); } catch { /* already closed */ }
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/**
 * Scripted SSH transport. `getState()` lets the script react to provisioning
 * progress (for example, listeners only exist once the inbound was created).
 * `failCommandTest(command)` makes any matching remote command fail, which is
 * how leftover-resource scenarios are modelled.
 */
function makeSshMock({ getState = () => ({}), log = [], failCommandTest = null } = {}) {
  // The route picks an auto port; evidence must quote the port the peer was
  // actually created for, exactly like the remote gre/ss output would.
  let activePort = null;
  // Track whether a GRE link exists, so reconcile sees a peer disappear after
  // a successful rollback the same way the real system would.
  let greExists = false;
  const sshExec = async (server, secret, command, opts = {}) => {
    const entry = { server: server.name, command, opts };
    log.push(entry);
    const state = getState() || {};
    const inboundCreated = !!state.inboundCreated;

    const portMatch = command.match(/--tcp-ports\s+'(\d+)'/);
    if (portMatch) activePort = Number(portMatch[1]);

    // Remote mutations change the modelled GRE state.
    if (/^gre (foreign-setup|iran-setup)\b/.test(command) || /^gre node add\b/.test(command) || /^gre iran peer add\b/.test(command)) {
      greExists = true;
    }
    if (/^gre node remove\b/.test(command) || /^gre iran peer remove\b/.test(command) || /^gre purge\b/.test(command)) {
      greExists = false;
    }

    if (command.includes('ss -H')) {
      if (!inboundCreated || !activePort) return { rc: 0, stdout: '' };
      return server.name === 'iran'
        ? { rc: 0, stdout: `-A PREROUTING -p tcp --dport ${activePort}\n-A PREROUTING -p udp --dport ${activePort}\n` }
        : { rc: 0, stdout: `tcp LISTEN 0 10 0.0.0.0:${activePort}\nudp UNCONN 0 0 0.0.0.0:${activePort}\n` };
    }
    if (command === 'gre iran peer suggest --json' || command.startsWith('gre node suggest')) {
      return { rc: 0, stdout: JSON.stringify({ name: 'ir01', subnet_base: '10.200', idx: 1, key: 1001 }) };
    }
    if (command.startsWith('ping ') || command.startsWith('gre ') || command.startsWith('ip link') || command.startsWith('timeout 8')) {
      const shouldFail = failCommandTest || state.failCommandTest;
      if (shouldFail && shouldFail(command)) {
        return { rc: 1, stdout: '', stderr: 'simulated failure' };
      }
      // Reconcile asks whether the GRE link is up. `state.greUp === false`
      // models a peer that exists but is not forwarding.
      if (command.startsWith('ip link')) {
        if (state.greUp === false) return { rc: 1, stdout: '', stderr: '' };
        if (state.greEnabled === true && !greExists) return { rc: 1, stdout: '', stderr: '' };
      }
      return { rc: 0, stdout: 'UP' };
    }
    if (command.includes('api.ipify.org') || command.includes('ifconfig.me')) {
      return { rc: 0, stdout: server.name === 'iran' ? '37.202.247.77' : '46.8.228.7' };
    }
    throw new Error(`unexpected SSH command on ${server.name}: ${command}`);
  };
  return { sshExec, log, greExists: () => greExists };
}

function makeOrchestrator(harness, { fetchImpl, sshExec, runTimeoutMs } = {}) {
  return new RouteOrchestrator({
    db: harness.db,
    cryptKey: harness.key,
    sshOptsFor: () => ({}),
    fetchImpl,
    sshExec,
    runTimeoutMs,
  });
}

// --- assertions ---------------------------------------------------------

let passed = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ok    ${name}`);
  } catch (err) {
    failures.push({ name, err });
    console.log(`  FAIL  ${name}: ${err.message}`);
  }
}

async function checkAsync(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok    ${name}`);
  } catch (err) {
    failures.push({ name, err });
    console.log(`  FAIL  ${name}: ${err.message}`);
  }
}

async function rejects(name, fn, matcher) {
  try {
    await fn();
    failures.push({ name, err: new Error('expected a rejection but the call resolved') });
    console.log(`  FAIL  ${name}: expected a rejection`);
  } catch (err) {
    try {
      if (matcher) matcher(err);
      passed += 1;
      console.log(`  ok    ${name}`);
    } catch (assertErr) {
      failures.push({ name, err: assertErr });
      console.log(`  FAIL  ${name}: ${assertErr.message}`);
    }
  }
}

function report(label) {
  console.log(`\n${label}: ${passed} passed, ${failures.length} failed`);
  if (failures.length) {
    for (const failure of failures) {
      console.error(`\n--- ${failure.name} ---\n${failure.err && failure.err.stack || failure.err}`);
    }
    process.exit(1);
  }
}

function eventsToText(events) {
  return events.map((event) => `${event.status} ${event.stage} ${event.detail}`).join('\n');
}

module.exports = {
  assert,
  makeHarness,
  makeSshMock,
  makeOrchestrator,
  check,
  checkAsync,
  rejects,
  report,
  eventsToText,
};
