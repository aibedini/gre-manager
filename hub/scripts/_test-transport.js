'use strict';
// _test-fixtures.js — transport modules used ONLY by the end-to-end hub test.
//
//   HUB_TEST_SSH_MODULE=<abs path>   exports an sshExec(server, secret, cmd, opts)
//   HUB_TEST_FETCH_MODULE=<abs path> exports a fetch(url, opts) that serves one
//                                    fake 3x-ui panel per configured URL
//
// Behaviour is driven by HUB_TEST_SCENARIO, a JSON file whose shape is:
//   {
//     "panels": { "<base_url>": { "clientModel": "...", "hostsApi": true, "clients": [...], "linkDelayMs": 0 } },
//     "faults": ["managed_host", "xdg"],
//     "hostsProbeStatus": 404
//   }

const { makeMockPanel } = require('./_xui-mock');

function readScenario() {
  if (!process.env.HUB_TEST_SCENARIO) return { panels: {} };
  // eslint-disable-next-line global-require, import/no-dynamic-require
  return require(process.env.HUB_TEST_SCENARIO);
}

// --- shared panel registry ------------------------------------------------
const scenario = readScenario();
const panels = new Map();
for (const [baseUrl, spec] of Object.entries(scenario.panels || {})) {
  panels.set(String(baseUrl).replace(/\/$/, ''), makeMockPanel(spec));
}

const faults = new Set();
// Faults and panel specs are re-read while the process runs so a single test
// process can drive several scenarios without a restart. Panel STATE is always
// preserved (the fake 3x-ui panel is only built once per base URL).
let lastLoad = 0;
let lastMtime = 0;

function reloadScenario() {
  const now = Date.now();
  if (now - lastLoad < 100) return;
  lastLoad = now;
  let stat;
  try { stat = require('fs').statSync(process.env.HUB_TEST_SCENARIO); } catch { return; }
  const mtime = stat.mtimeMs;
  if (mtime === lastMtime) return;
  lastMtime = mtime;
  let next;
  try { next = JSON.parse(require('fs').readFileSync(process.env.HUB_TEST_SCENARIO, 'utf8')); } catch { return; }
  faults.clear();
  for (const fault of next.faults || []) faults.add(fault);
  for (const [baseUrl, spec] of Object.entries(next.panels || {})) {
    const key = String(baseUrl).replace(/\/$/, '');
    const existing = panels.get(key);
    if (!existing) {
      panels.set(key, makeMockPanel(spec));
      continue;
    }
    // Apply capability toggles in place while keeping accumulated state.
    existing.hostsApiEnabled = !!spec.hostsApi;
  }
}

// The route's port is learned from the peer-add command; remember it so later
// listener probes quote the same port even if the command is re-issued.
let activePort = null;

function portOf(panel) {
  if (activePort) return activePort;
  const inbound = panel && panel.state.inbounds[panel.state.inbounds.length - 1];
  return inbound ? inbound.port : null;
}

if (process.env.HUB_TEST_TRANSPORT_DEBUG === '1') {
  console.log(`[test-transport] panels=${[...panels.keys()].join(',')} faults=${[...faults].join(',')}`);
}

async function sshExec(server, secret, command, opts = {}) {
  reloadScenario();
  const panel = [...panels.values()][0];
  const inboundCreated = panel ? panel.state.inbounds.length > 0 : false;
  const portMatch = command.match(/--tcp-ports\s+'(\d+)'/);
  if (portMatch) activePort = Number(portMatch[1]);
  const port = portMatch ? Number(portMatch[1]) : Number(portOf(panel)) || 3049;

  if (command.includes('ss -H')) {
    if (!inboundCreated) return { rc: 0, stdout: '' };
    const out = server.name === 'iran'
      ? `-A PREROUTING -p tcp --dport ${port}\n-A PREROUTING -p udp --dport ${port}\n`
      : `tcp LISTEN 0 10 0.0.0.0:${port}\nudp UNCONN 0 0 0.0.0.0:${port}\n`;
    if (process.env.HUB_TEST_TRANSPORT_DEBUG === '1') {
      console.log(`[test-transport] probe ${server.name} port=${port} inbounds=${panel ? panel.state.inbounds.length : 'n/a'}`);
    }
    return { rc: 0, stdout: out };
  }
  if (command === 'gre iran peer suggest --json' || command.startsWith('gre node suggest')) {
    return { rc: 0, stdout: JSON.stringify({ name: 'ir01', subnet_base: '10.200', idx: 1, key: 1001 }) };
  }
  if (command.startsWith('ping ') || command.startsWith('gre ') || command.startsWith('ip link') || command.startsWith('timeout 8')) {
    if (process.env.HUB_TEST_TRANSPORT_DEBUG === '1') {
      console.log(`[test-transport] ssh ${server.name} (inbounds=${panel ? panel.state.inbounds.length : 'n/a'}): ${command}`);
    }
    return { rc: 0, stdout: 'UP' };
  }
  if (command.includes('api.ipify.org') || command.includes('ifconfig.me')) {
    return { rc: 0, stdout: server.name === 'iran' ? '37.202.247.77' : '46.8.228.7' };
  }
  return { rc: 0, stdout: '' };
}

async function fetchImpl(url, opts = {}) {
  reloadScenario();
  const target = String(url);
  const pathname = new URL(target).pathname;
  for (const [baseUrl, panel] of panels) {
    if (!target.startsWith(baseUrl)) continue;
    if (faults.has('managed_host') && pathname.endsWith('/panel/api/hosts/add')) {
      throw new Error('simulated managed-host failure');
    }
    return panel.fetchImpl(target, opts);
  }
  if (pathname.endsWith('/csrf-token')) {
    return new Response(JSON.stringify({ success: false }), { status: 404, headers: { 'content-type': 'application/json' } });
  }
  if (pathname.endsWith('/login')) {
    return new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': '3x-ui=s; Path=/' } });
  }
  throw new Error(`no fake panel configured for ${target}`);
}

module.exports = { fetchImpl, sshExec, panels };

