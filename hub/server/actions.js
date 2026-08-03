'use strict';
// actions.js — allowlisted remote actions executed over SSH and recorded
// in the action_log table. All mutating gre commands get --yes.

const ssh = require('./ssh');

// Shell-safe single-quote wrapping.
function q(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function optStr(flag, value) {
  return value === undefined || value === null || value === '' ? '' : ` ${flag} ${q(value)}`;
}

function optInt(flag, value) {
  if (value === undefined || value === null || value === '') return '';
  const n = Number(value);
  if (!Number.isInteger(n)) throw new Error(`${flag} must be an integer`);
  return ` ${flag} ${n}`;
}

// Fields that must never be written to the action log.
const SENSITIVE_PARAMS = new Set(['key', 'secret', 'password']);

// Each builder receives the params object and returns the remote command.
// Throwing means the params were invalid (returned to the caller as 400).
const BUILDERS = {
  install_gre: () =>
    'curl -fsSL https://raw.githubusercontent.com/aibedini/gre-manager/main/install.sh | bash',
  update: () => 'gre update --yes',
  doctor: () => 'gre doctor',
  // restart_all is not a CLI subcommand; --stop + --apply is exactly what it does.
  restart_all: () => 'gre --stop && gre --apply',
  watchdog_enable: () => 'gre watchdog enable',
  watchdog_disable: () => 'gre watchdog disable',
  watchdog_interval: (p) => {
    const n = Number(p.interval);
    if (!Number.isInteger(n) || n < 1 || n > 60) throw new Error('interval must be an integer 1-60');
    return `gre watchdog interval ${n}`;
  },
  node_add: (p) => {
    if (!p.name || !p.ip) throw new Error('node_add requires name and ip');
    return (
      `gre node add --name ${q(p.name)} --ip ${q(p.ip)}` +
      optInt('--idx', p.idx) +
      optStr('--key', p.key) +
      optStr('--subnet-base', p.subnet_base) +
      ' --yes'
    );
  },
  node_remove: (p) => {
    if (!p.name) throw new Error('node_remove requires name');
    return `gre node remove --name ${q(p.name)} --yes`;
  },
  peer_add: (p) => {
    if (!p.name || !p.foreign_ip) throw new Error('peer_add requires name and foreign_ip');
    return (
      `gre iran peer add --name ${q(p.name)} --foreign-ip ${q(p.foreign_ip)}` +
      optStr('--iran-ip', p.iran_ip) +
      optStr('--subnet-base', p.subnet_base) +
      optInt('--idx', p.idx) +
      optStr('--key', p.key) +
      optStr('--tcp-ports', p.tcp_ports) +
      optStr('--udp-ports', p.udp_ports) +
      ' --yes'
    );
  },
  peer_remove: (p) => {
    if (!p.name) throw new Error('peer_remove requires name');
    return `gre iran peer remove --name ${q(p.name)} --yes`;
  },
  peer_apply: (p) => {
    if (!p.name) throw new Error('peer_apply requires name');
    return `gre iran peer apply --name ${q(p.name)}`;
  },
  export: (p) => `gre export${p.path ? ` ${q(p.path)}` : ''} --yes`,
  purge: (p) => {
    if (p.confirm !== 'PURGE') throw new Error('purge requires confirm: "PURGE"');
    return 'gre purge --yes';
  },
};

const ACTION_NAMES = Object.keys(BUILDERS);

function sanitizeParams(params) {
  const out = {};
  for (const [k, v] of Object.entries(params || {})) {
    out[k] = SENSITIVE_PARAMS.has(k) ? '***' : v;
  }
  return out;
}

// Run one action; returns { rc, stdout, stderr, command } and logs it.
async function runAction(db, server, secret, action, params, sshOpts = {}) {
  const builder = BUILDERS[action];
  if (!builder) throw new Error(`unknown action: ${action}`);
  const command = builder(params || {});
  const result = await ssh.exec(server, secret, command, { timeoutMs: 300000, ...sshOpts });

  const output = [result.stdout, result.stderr].filter(Boolean).join('\n').slice(0, 20000);
  db.prepare(
    "INSERT INTO action_log (kind, server_id, server_name, action, params, rc, output, created_at) VALUES ('action', ?, ?, ?, ?, ?, ?, ?)"
  ).run(server.id, server.name, action, JSON.stringify(sanitizeParams(params)), result.rc, output, Date.now());

  return { ...result, command };
}

module.exports = { runAction, ACTION_NAMES, sanitizeParams };
