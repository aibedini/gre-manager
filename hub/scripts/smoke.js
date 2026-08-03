'use strict';
// smoke.js — boot gre-hub on a random port against a temp data dir and
// assert the core auth flow: setup → login → me → bad-login rate limiting.
// Run with: node scripts/smoke.js

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const PORT = 42000 + Math.floor(Math.random() * 20000);
const BASE = `http://127.0.0.1:${PORT}`;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-smoke-'));
const PASSWORD = 'smoke-test-password';

let passed = 0;
let failed = 0;

function check(name, cond, extra = '') {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

// fetch wrapper that keeps the session cookie like a browser would.
let cookie = '';
async function call(pathname, { method = 'GET', body, useCookie = true } = {}) {
  const res = await fetch(BASE + pathname, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(useCookie && cookie ? { Cookie: cookie } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  let data = null;
  const text = await res.text();
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForServer(child, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let buf = '';
  child.stdout.on('data', (d) => { buf += d; });
  while (Date.now() < deadline) {
    if (buf.includes('gre-hub listening')) return;
    if (child.exitCode !== null) throw new Error(`server exited early with code ${child.exitCode}\n${buf}`);
    await sleep(100);
  }
  throw new Error(`server did not start in time.\n${buf}`);
}

async function main() {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server', 'index.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HUB_HOST: '127.0.0.1',
      HUB_DATA_DIR: DATA_DIR,
      HUB_LOCK_SECONDS: '1', // shorten the rate-limit lock for the test
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  try {
    console.log(`booting gre-hub on ${BASE} (data: ${DATA_DIR})`);
    await waitForServer(child);

    console.log('static + setup:');
    const index = await call('/', { useCookie: false });
    check('GET / serves index.html', index.status === 200 && String(index.data).includes('gre-hub'));
    const vendor = await fetch(`${BASE}/vendor/xterm/lib/xterm.js`);
    check('GET /vendor/xterm/lib/xterm.js', vendor.status === 200);

    let r = await call('/api/setup', { useCookie: false });
    check('GET /api/setup → needs_setup true', r.status === 200 && r.data.needs_setup === true);

    r = await call('/api/setup', { method: 'POST', body: { password: 'short' }, useCookie: false });
    check('POST /api/setup rejects short password', r.status === 400);

    r = await call('/api/setup', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    check('POST /api/setup creates password + session', r.status === 200 && r.data.ok === true && cookie.length > 0);

    r = await call('/api/setup', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    check('POST /api/setup twice → 409', r.status === 409);

    console.log('session:');
    r = await call('/api/me');
    check('GET /api/me with session → 200', r.status === 200 && r.data.ok === true);

    r = await call('/api/me', { useCookie: false });
    check('GET /api/me without session → 401', r.status === 401);

    r = await call('/api/servers');
    check('GET /api/servers → empty list', r.status === 200 && Array.isArray(r.data) && r.data.length === 0);

    r = await call('/api/logout', { method: 'POST' });
    check('POST /api/logout', r.status === 200);
    const deadCookie = cookie;
    r = await call('/api/me');
    check('session invalid after logout → 401', r.status === 401);

    console.log('rate limiting (5 fails → lock):');
    for (let i = 1; i <= 5; i++) {
      r = await call('/api/login', { method: 'POST', body: { password: 'wrong-password' }, useCookie: false });
      if (r.status !== 401) break;
    }
    check('5 wrong logins → 401 each', r.status === 401);
    r = await call('/api/login', { method: 'POST', body: { password: 'wrong-password' }, useCookie: false });
    check('6th attempt → 429 locked', r.status === 429);
    r = await call('/api/login', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    check('correct password still locked → 429', r.status === 429);

    await sleep(1200); // HUB_LOCK_SECONDS=1
    cookie = deadCookie; // will be overwritten by the fresh login below
    r = await call('/api/login', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    check('login works after lock expires', r.status === 200 && r.data.ok === true);
    r = await call('/api/me');
    check('GET /api/me after re-login → 200', r.status === 200);
  } finally {
    child.kill('SIGTERM');
    await sleep(300);
    if (child.exitCode === null) child.kill('SIGKILL');
    fs.rmSync(DATA_DIR, { recursive: true, force: true });
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error('smoke test error:', err);
  process.exit(1);
});
