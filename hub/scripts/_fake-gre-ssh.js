'use strict';
// _fake-gre-ssh.js — a scripted, STATEFUL fake of the `gre` CLI surface the Hub
// drives during a connection edit or migration.
//
// Unlike the provisioning fake, this one has to hold real state: a peer_edit on
// one server must be visible to the next `peer list --json` on that same server, or
// the Hub's verification step would be meaningless and a make-before-break test
// would pass for the wrong reason.
//
// Faults are injected through HUB_TEST_GRE_FAULT (a JSON file, re-read on every
// call so one process can drive several scenarios):
//   { "fail": { "<server name>": ["peer_edit", "doctor"] },
//     "ping_fail": ["<server name>"],
//     "unreachable": ["<server name>"] }
//
// Loaded via HUB_TEST_SSH_MODULE.

const fs = require('fs');

const FAULT_FILE = process.env.HUB_TEST_GRE_FAULT || '';
let faultCache = { loadedAt: 0, faults: {} };

function faults() {
  if (!FAULT_FILE) return {};
  const now = Date.now();
  if (now - faultCache.loadedAt < 80) return faultCache.faults;
  faultCache = { loadedAt: now, faults: {} };
  try {
    faultCache.faults = JSON.parse(fs.readFileSync(FAULT_FILE, 'utf8'));
  } catch { faultCache.faults = {}; }
  return faultCache.faults;
}

// Per-server state, keyed by host so it survives across requests.
const state = new Map();

// Optional initial state, so a test can present servers that ALREADY carry the
// connection being edited. Without this, an edit would be applied to a host that
// never had the peer, and the test would prove nothing about editing.
//
// This is loaded LAZILY rather than at require time: the hub requires its
// transport override while starting up, which is before a test has had a chance to
// write the seed. Reading on first use (and re-reading when the file changes) makes
// the seed reliable regardless of that ordering.
const SEED_FILE = process.env.HUB_TEST_GRE_SEED || '';
let seedStamp = 0;
let seedLoaded = false;

function loadSeed(force) {
  if (!SEED_FILE) return;
  let stat;
  try { stat = fs.statSync(SEED_FILE); } catch { return; }
  if (!force && seedLoaded && stat.mtimeMs === seedStamp) return;
  seedStamp = stat.mtimeMs;
  seedLoaded = true;
  let seed;
  try { seed = JSON.parse(fs.readFileSync(SEED_FILE, 'utf8')); } catch { return; }
  for (const [host, value] of Object.entries(seed)) {
    const existing = state.get(host) || { peers: [], nodes: [], events: [] };
    // An explicitly seeded host replaces its list; anything a test already did
    // through the API is preserved for hosts the seed does not mention.
    state.set(host, {
      peers: value.peers || existing.peers,
      nodes: value.nodes || existing.nodes,
      events: existing.events,
    });
  }
}

function forServer(server) {
  loadSeed(false);
  const key = server.host || server.name;
  if (!state.has(key)) state.set(key, { peers: [], nodes: [], events: [] });
  return state.get(key);
}

function parseArgs(command) {
  const tokens = command.match(/'[^']*'|\S+/g) || [];
  const out = { _: [] };
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.startsWith('--')) {
      const name = t.slice(2);
      const next = tokens[i + 1];
      if (next && !next.startsWith('--')) { out[name] = next.replace(/^'|'$/g, ''); i += 1; } else { out[name] = true; }
    } else {
      out._.push(t.replace(/^'|'$/g, ''));
    }
  }
  return out;
}

function faulted(server, verb) {
  const f = faults();
  const list = (f.fail && f.fail[server.name]) || [];
  if (list.includes(verb)) return true;
  if ((f.unreachable || []).includes(server.name)) return true;
  return false;
}

function fail(verb, server) {
  return { rc: 1, stdout: '', stderr: `injected failure: ${verb} on ${server.name}` };
}

// `gre iran peer list --json` / `gre node list --json` are what the Hub verifies
// against, so the output shape has to match the real CLI's.
function listJson(entries, kind) {
  return JSON.stringify(entries.map((e) => (kind === 'peer'
    ? {
      name: e.name, iran_ip: e.iran_ip, foreign_ip: e.foreign_ip,
      subnet_base: e.subnet_base, idx: Number(e.idx), key: Number(e.key),
      tun: `gre-${e.name}`, tcp_ports: e.tcp_ports || '', udp_ports: e.udp_ports || '',
    }
    : {
      name: e.name, iran_ip: e.iran_ip, subnet_base: e.subnet_base,
      idx: Number(e.idx), key: Number(e.key), tun: `gre-${e.name}`,
    })));
}

const exec = async (server, secret, command, opts = {}) => {
  const st = forServer(server);
  const ok = (stdout) => ({ rc: 0, stdout, stderr: '' });

  if (faulted(server, 'any')) return fail('any', server);

  // --- read-only verbs the Hub verifies with -------------------------------
  if (/gre iran peer list --json/.test(command)) {
    if (faulted(server, 'peer_list_json')) return fail('peer_list_json', server);
    return ok(listJson(st.peers, 'peer'));
  }
  if (/gre node list --json/.test(command)) {
    if (faulted(server, 'node_list_json')) return fail('node_list_json', server);
    return ok(listJson(st.nodes, 'node'));
  }
  if (/gre status --json/.test(command)) {
    if (faulted(server, 'status_json')) return fail('status_json', server);
    return ok(JSON.stringify({ roles: st.peers.length ? ['IRAN'] : (st.nodes.length ? ['FOREIGN'] : []), tunnels_up: st.peers.length + st.nodes.length }));
  }
  if (/gre doctor/.test(command)) {
    if (faulted(server, 'doctor')) return { rc: 2, stdout: 'FAIL something is wrong', stderr: '' };
    return ok('PASS all checks');
  }
  if (/ping -c/.test(command)) {
    if ((faults().ping_fail || []).includes(server.name)) return { rc: 1, stdout: '', stderr: 'ping: unreachable' };
    return ok('2 packets transmitted, 2 received');
  }

  // --- mutating verbs ------------------------------------------------------
  let m = command.match(/gre iran peer add (.*)$/);
  if (m) {
    if (faulted(server, 'peer_add')) return fail('peer_add', server);
    const a = parseArgs(m[1]);
    st.peers.push({
      name: a.name, iran_ip: a['iran-ip'] || '', foreign_ip: a['foreign-ip'],
      subnet_base: a['subnet-base'], idx: a.idx, key: a.key,
      tcp_ports: a['tcp-ports'] || '', udp_ports: a['udp-ports'] || '',
    });
    return ok("Foreign peer added.\n");
  }
  m = command.match(/gre iran peer edit (.*)$/);
  if (m) {
    if (faulted(server, 'peer_edit')) return fail('peer_edit', server);
    const a = parseArgs(m[1]);
    const peer = st.peers.find((p) => p.name === a.name);
    if (!peer) return { rc: 1, stdout: '', stderr: `Peer '${a.name}' does not exist.` };
    // A rename rewrites the entry under the new name, exactly as the CLI does.
    if (a['new-name']) peer.name = a['new-name'];
    for (const [flag, field] of [['foreign-ip', 'foreign_ip'], ['iran-ip', 'iran_ip'], ['subnet-base', 'subnet_base'], ['idx', 'idx'], ['key', 'key'], ['tcp-ports', 'tcp_ports'], ['udp-ports', 'udp_ports']]) {
      if (a[flag] !== undefined) peer[field] = a[flag];
    }
    return ok(`Connection '${peer.name}' updated (A: rule-only update).\n`);
  }
  m = command.match(/gre iran peer remove (.*)$/);
  if (m) {
    if (faulted(server, 'peer_remove')) return fail('peer_remove', server);
    const a = parseArgs(m[1]);
    const before = st.peers.length;
    st.peers = st.peers.filter((p) => p.name !== a.name);
    if (st.peers.length === before) return { rc: 1, stdout: '', stderr: `Peer '${a.name}' does not exist.` };
    return ok(`Peer '${a.name}' removed.\n`);
  }
  m = command.match(/gre node add (.*)$/);
  if (m) {
    if (faulted(server, 'node_add')) return fail('node_add', server);
    const a = parseArgs(m[1]);
    st.nodes.push({ name: a.name, iran_ip: a.ip, subnet_base: a['subnet-base'], idx: a.idx, key: a.key });
    return ok('Node added.\n');
  }
  m = command.match(/gre node edit (.*)$/);
  if (m) {
    if (faulted(server, 'node_edit')) return fail('node_edit', server);
    const a = parseArgs(m[1]);
    const node = st.nodes.find((n) => n.name === a.name);
    if (!node) return { rc: 1, stdout: '', stderr: `Node '${a.name}' does not exist.` };
    if (a['new-name']) node.name = a['new-name'];
    for (const [flag, field] of [['ip', 'iran_ip'], ['subnet-base', 'subnet_base'], ['idx', 'idx'], ['key', 'key']]) {
      if (a[flag] !== undefined) node[field] = a[flag];
    }
    return ok(`Node '${node.name}' updated (B: tunnel recreation required).\n`);
  }
  m = command.match(/gre node remove (.*)$/);
  if (m) {
    if (faulted(server, 'node_remove')) return fail('node_remove', server);
    const a = parseArgs(m[1]);
    const before = st.nodes.length;
    st.nodes = st.nodes.filter((n) => n.name !== a.name);
    if (st.nodes.length === before) return { rc: 1, stdout: '', stderr: `Node '${a.name}' does not exist.` };
    return ok(`Node '${a.name}' removed.\n`);
  }

  // Anything else the Hub asks for (installer probes, suggestions) is a no-op
  // success: this fake exists to model the connection verbs, not the whole CLI.
  return ok('ok\n');
};

module.exports = exec;
module.exports.exec = exec;
module.exports.state = state;
module.exports.reset = () => state.clear();
