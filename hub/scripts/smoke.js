'use strict';
// smoke.js — boot gre-hub on a random port against a temp data dir and assert:
//   static + security headers, unknown-route 404, setup/login/me,
//   CSRF enforcement, rate limiting, TOTP 2FA (enable, login, recovery codes),
//   password policy + change, session invalidation, logout-all, body limit.
// Run with: node scripts/smoke.js

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const totp = require('../server/totp');

const PORT = 42000 + Math.floor(Math.random() * 20000);
const BASE = `http://127.0.0.1:${PORT}`;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-smoke-'));
const P1 = 'smoke-test-pass-1';
const P2 = 'smoke-test-pass-2';

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

// Minimal browser-like client: cookie jar + CSRF header handling.
function makeClient() {
  const c = {
    cookie: '',
    csrf: '',
    async call(pathname, { method = 'GET', body, useCookie = true, useCsrf = true } = {}) {
      const headers = {};
      if (body) headers['Content-Type'] = 'application/json';
      if (useCookie && c.cookie) headers.Cookie = c.cookie;
      if (useCsrf && method !== 'GET' && c.csrf) headers['x-csrf-token'] = c.csrf;
      const res = await fetch(BASE + pathname, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        redirect: 'manual',
      });
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) c.cookie = setCookie.split(';')[0];
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = text; }
      if (data && data.csrf) c.csrf = data.csrf;
      return { status: res.status, data, headers: res.headers };
    },
  };
  return c;
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

    const anon = makeClient();

    console.log('static + security headers:');
    let r = await anon.call('/', { useCookie: false });
    check('GET / serves index.html', r.status === 200 && String(r.data).includes('gre-hub'));
    check('CSP header present', (r.headers.get('content-security-policy') || '').includes("default-src 'self'"));
    check('X-Frame-Options DENY', r.headers.get('x-frame-options') === 'DENY');
    check('X-Content-Type-Options nosniff', r.headers.get('x-content-type-options') === 'nosniff');
    check('Referrer-Policy no-referrer', r.headers.get('referrer-policy') === 'no-referrer');
    check('Permissions-Policy present', (r.headers.get('permissions-policy') || '').includes('camera=()'));
    check('X-Powered-By removed', !r.headers.get('x-powered-by'));
    check('no HSTS without HUB_SECURE', !r.headers.get('strict-transport-security'));
    const vendor = await fetch(`${BASE}/vendor/xterm/lib/xterm.js`);
    check('GET /vendor/xterm/lib/xterm.js', vendor.status === 200);

    console.log('setup (password policy):');
    r = await anon.call('/api/setup', { useCookie: false });
    check('GET /api/setup → needs_setup true', r.status === 200 && r.data.needs_setup === true);

    r = await anon.call('/api/setup', { method: 'POST', body: { password: 'short-pass!' }, useCookie: false }); // exactly 11 chars
    check('POST /api/setup rejects 11-char password', r.status === 400);

    r = await anon.call('/api/setup', { method: 'POST', body: { password: P1 }, useCookie: false });
    check('POST /api/setup creates password + session + csrf', r.status === 200 && r.data.ok === true && anon.cookie.length > 0 && !!r.data.csrf);

    r = await anon.call('/api/setup', { method: 'POST', body: { password: P1 }, useCookie: false });
    check('POST /api/setup twice → 409', r.status === 409);

    console.log('session + CSRF:');
    r = await anon.call('/api/me');
    check('GET /api/me with session → 200 (+csrf)', r.status === 200 && r.data.ok === true && !!r.data.csrf);

    r = await anon.call('/api/me', { useCookie: false });
    check('GET /api/me without session → 401', r.status === 401);

    r = await anon.call('/api/servers');
    check('GET /api/servers → empty list', r.status === 200 && Array.isArray(r.data) && r.data.length === 0);

    r = await anon.call('/api/definitely-not-a-route');
    check('unknown /api route → 404 JSON', r.status === 404 && r.data && r.data.error === 'not found');

    r = await anon.call('/api/logout', { method: 'POST', useCsrf: false });
    check('mutating call without CSRF token → 403', r.status === 403);

    r = await anon.call('/api/logout', { method: 'POST' });
    check('POST /api/logout with CSRF → 200', r.status === 200);
    r = await anon.call('/api/me');
    check('session invalid after logout → 401', r.status === 401);

    console.log('rate limiting (5 fails → lock):');
    for (let i = 1; i <= 5; i++) {
      r = await anon.call('/api/login', { method: 'POST', body: { password: 'wrong-password-1' }, useCookie: false });
      if (r.status !== 401) break;
    }
    check('5 wrong logins → 401 each', r.status === 401);
    r = await anon.call('/api/login', { method: 'POST', body: { password: 'wrong-password-1' }, useCookie: false });
    check('6th attempt → 429 locked', r.status === 429);
    r = await anon.call('/api/login', { method: 'POST', body: { password: P1 }, useCookie: false });
    check('correct password still locked → 429', r.status === 429);
    await sleep(1200); // HUB_LOCK_SECONDS=1
    r = await anon.call('/api/login', { method: 'POST', body: { password: P1 }, useCookie: false });
    check('login works after lock expires', r.status === 200 && r.data.ok === true);

    console.log('TOTP 2FA:');
    r = await anon.call('/api/2fa/setup', { method: 'POST' });
    check('POST /api/2fa/setup → secret + uri', r.status === 200 && !!r.data.secret && r.data.uri.startsWith('otpauth://'));
    const secretBytes = totp.base32Decode(r.data.secret);
    const validCode = () => totp.totp(secretBytes);

    r = await anon.call('/api/2fa/enable', { method: 'POST', body: { code: '000000' } });
    check('enable with wrong code → 400', r.status === 400);

    r = await anon.call('/api/2fa/enable', { method: 'POST', body: { code: validCode() } });
    check('enable with valid code → 10 recovery codes', r.status === 200 && Array.isArray(r.data.recovery_codes) && r.data.recovery_codes.length === 10);
    const recovery = r.data.recovery_codes;

    r = await anon.call('/api/me');
    check('/api/me shows totp_enabled', r.status === 200 && r.data.totp_enabled === true);

    await anon.call('/api/logout', { method: 'POST' });

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1 }, useCookie: false });
    check('login without code → 401 requires_2fa', r.status === 401 && r.data.requires_2fa === true);

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1, code: '000000' }, useCookie: false });
    check('login with wrong code → 401', r.status === 401);

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1, code: validCode() }, useCookie: false });
    check('login with valid TOTP → 200', r.status === 200);
    await anon.call('/api/logout', { method: 'POST' });

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1, code: recovery[0] }, useCookie: false });
    check('login with recovery code → 200', r.status === 200);
    await anon.call('/api/logout', { method: 'POST' });

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1, code: recovery[0] }, useCookie: false });
    check('same recovery code twice → 401 (single-use)', r.status === 401);

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1, code: validCode() }, useCookie: false });
    check('login again with TOTP → 200', r.status === 200);

    console.log('password change + session invalidation:');
    const other = makeClient();
    r = await other.call('/api/login', { method: 'POST', body: { password: P1, code: validCode() }, useCookie: false });
    check('second session login → 200', r.status === 200);

    r = await anon.call('/api/password', { method: 'POST', body: { current: 'wrong-current-pw', next: P2 } });
    check('password change, wrong current → 400', r.status === 400);
    r = await anon.call('/api/password', { method: 'POST', body: { current: P1, next: 'short' } });
    check('password change, short next → 400', r.status === 400);
    r = await anon.call('/api/password', { method: 'POST', body: { current: P1, next: P2 } });
    check('password change ok → 200', r.status === 200);

    r = await other.call('/api/me');
    check('other session invalidated by password change → 401', r.status === 401);
    r = await anon.call('/api/me');
    check('current session survives password change → 200', r.status === 200);

    r = await anon.call('/api/login', { method: 'POST', body: { password: P1, code: validCode() }, useCookie: false });
    check('old password rejected → 401', r.status === 401);

    console.log('logout-all:');
    const third = makeClient();
    r = await third.call('/api/login', { method: 'POST', body: { password: P2, code: validCode() }, useCookie: false });
    check('third session login (new pw + TOTP) → 200', r.status === 200);
    r = await third.call('/api/logout-all', { method: 'POST' });
    check('POST /api/logout-all → 200', r.status === 200);
    r = await anon.call('/api/me');
    check('first session killed by logout-all → 401', r.status === 401);
    r = await third.call('/api/me');
    check('calling session survives logout-all → 200', r.status === 200);

    console.log('2FA disable + misc:');
    r = await third.call('/api/2fa/disable', { method: 'POST', body: { password: 'wrong-password-2', code: validCode() } });
    check('2FA disable, wrong password → 400', r.status === 400);
    r = await third.call('/api/2fa/disable', { method: 'POST', body: { password: P2, code: validCode() } });
    check('2FA disable with password + code → 200', r.status === 200);
    r = await third.call('/api/login', { method: 'POST', body: { password: P2 }, useCookie: false });
    check('login without code works after disable → 200', r.status === 200);

    const bigBody = { password: 'x'.repeat(150 * 1024) };
    const bigRes = await fetch(`${BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bigBody),
    });
    check('oversized JSON body → 413', bigRes.status === 413);
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
