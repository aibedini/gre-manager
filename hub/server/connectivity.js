'use strict';

const net = require('net');
const ssh = require('./ssh');

const PREFLIGHT_ACTIONS = new Set(['setup_iran', 'peer_add', 'node_add']);

function isIPv4(value) {
  return typeof value === 'string' && net.isIP(value.trim()) === 4;
}

function findUniqueServerByHost(db, host) {
  if (!isIPv4(host)) throw new Error(`invalid public IPv4 address: ${host || '(empty)'}`);
  const rows = db.prepare('SELECT * FROM servers WHERE host = ?').all(host.trim());
  if (rows.length !== 1) {
    throw new Error(`Both endpoints must be registered in Hub with unique public IPv4 addresses; found ${rows.length} servers for ${host}.`);
  }
  return rows[0];
}

function resolvePair(db, current, action, params = {}) {
  if (!PREFLIGHT_ACTIONS.has(action)) return null;
  if (!isIPv4(current.host)) {
    throw new Error(`Both endpoints must use registered public IPv4 addresses; ${current.name} has host ${current.host}.`);
  }

  if (action === 'node_add') {
    const iran = findUniqueServerByHost(db, String(params.ip || ''));
    return { iran, foreign: current, iranIp: iran.host, foreignIp: current.host };
  }

  const foreign = findUniqueServerByHost(db, String(params.foreign_ip || ''));
  const iranIp = params.iran_ip ? String(params.iran_ip).trim() : current.host;
  if (!isIPv4(iranIp)) throw new Error('iran_ip must be a valid public IPv4 address');
  return { iran: current, foreign, iranIp, foreignIp: foreign.host };
}

function directionResult(source, destinationIp, result) {
  const detail = (result.stderr || result.stdout || `ping exited ${result.rc}`).trim().slice(0, 1000);
  return {
    source_id: source.id,
    source_name: source.name,
    source_ip: source.host,
    destination_ip: destinationIp,
    reachable: result.rc === 0,
    rc: result.rc,
    detail,
  };
}

async function checkPair(pair, { getSecret, sshOptsFor, exec = ssh.exec } = {}) {
  if (!pair || typeof getSecret !== 'function' || typeof sshOptsFor !== 'function') {
    throw new Error('connectivity checker requires a pair and SSH dependency helpers');
  }
  if (!isIPv4(pair.iranIp) || !isIPv4(pair.foreignIp)) throw new Error('connectivity endpoints must be valid IPv4 addresses');

  const run = async (source, destinationIp) => {
    const result = await exec(
      source,
      getSecret(source),
      `ping -4 -c 2 -W 2 ${destinationIp}`,
      { timeoutMs: 15000, ...sshOptsFor(source) }
    );
    return { raw: result, public: directionResult(source, destinationIp, result) };
  };

  const iranToForeign = await run(pair.iran, pair.foreignIp);
  if (iranToForeign.raw.hostkey_mismatch) {
    return { hostkey_mismatch: true, server: pair.iran, presented_fp: iranToForeign.raw.presented_fp };
  }
  const foreignToIran = await run(pair.foreign, pair.iranIp);
  if (foreignToIran.raw.hostkey_mismatch) {
    return { hostkey_mismatch: true, server: pair.foreign, presented_fp: foreignToIran.raw.presented_fp };
  }

  const checkedAt = Date.now();
  return {
    ok: iranToForeign.public.reachable && foreignToIran.public.reachable,
    iran: { id: pair.iran.id, name: pair.iran.name, ip: pair.iranIp },
    foreign: { id: pair.foreign.id, name: pair.foreign.name, ip: pair.foreignIp },
    iran_to_foreign: iranToForeign.public,
    foreign_to_iran: foreignToIran.public,
    checked_at: checkedAt,
  };
}

function persistPair(db, result) {
  db.prepare(`
    INSERT INTO connectivity_checks
      (iran_server_id, foreign_server_id, iran_ip, foreign_ip, iran_to_foreign, foreign_to_iran,
       iran_to_foreign_detail, foreign_to_iran_detail, checked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(iran_server_id, foreign_server_id) DO UPDATE SET
      iran_ip = excluded.iran_ip,
      foreign_ip = excluded.foreign_ip,
      iran_to_foreign = excluded.iran_to_foreign,
      foreign_to_iran = excluded.foreign_to_iran,
      iran_to_foreign_detail = excluded.iran_to_foreign_detail,
      foreign_to_iran_detail = excluded.foreign_to_iran_detail,
      checked_at = excluded.checked_at
  `).run(
    result.iran.id, result.foreign.id, result.iran.ip, result.foreign.ip,
    result.iran_to_foreign.reachable ? 1 : 0,
    result.foreign_to_iran.reachable ? 1 : 0,
    result.iran_to_foreign.detail,
    result.foreign_to_iran.detail,
    result.checked_at
  );
}

module.exports = { PREFLIGHT_ACTIONS, isIPv4, findUniqueServerByHost, resolvePair, checkPair, persistPair };
