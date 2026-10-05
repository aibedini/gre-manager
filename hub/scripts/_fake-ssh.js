'use strict';
// Test-only SSH transport for the hub's end-to-end provisioning tests.
//
// Loaded via HUB_TEST_SSH_MODULE. It behaves like a real server with a password
// and a set of authorized keys, so the four provisioning stages can be exercised
// over the real HTTP surface without a network.
//
// Scenario is chosen with HUB_TEST_SSH_SCENARIO:
//   happy           password works, key installs cleanly, both paths verify
//   postcheck_fail  the password stops working only after the key is installed
//   no_password     the password never works
//   auth_fail       key auth fails, the fallback password works (auto mode only)

const fs = require('fs');
const path = require('path');
const os = require('os');

const SCENARIO = process.env.HUB_TEST_SSH_SCENARIO || 'happy';
const LOG = path.join(os.tmpdir(), `gre-hub-fake-ssh-${process.pid}.log`);

const state = {
  password: process.env.HUB_TEST_SSH_PASSWORD || 'root-secret',
  authorizedKeys: [],
  installed: [],
  calls: [],
  passwordChecked: 0,
};

function log(entry) {
  state.calls.push(entry);
  // stderr is inherited from the test runner, so this is visible without guessing
  // at a temp path.
  if (process.env.HUB_TEST_SSH_DEBUG === '1') {
    try { process.stderr.write(`[fake-ssh] ${JSON.stringify(entry)}\n`); } catch { /* best effort */ }
  }
  try { fs.appendFileSync(LOG, `${JSON.stringify(entry)}\n`); } catch { /* best effort */ }
}

function stdoutFor(command) {
  for (const marker of ['hub-password-pre-ok', 'hub-key-ok', 'hub-password-post-ok', 'key-installed', 'key-removed']) {
    if (command.includes(marker)) return `${marker}\n`;
  }
  return 'ok\n';
}

function looksLikePrivateKey(secret) {
  return /BEGIN (OPENSSH|RSA|EC) PRIVATE KEY/.test(String(secret));
}

const exec = async (server, secret, command, opts = {}) => {
  const mode = opts.authMode || (server.auth_type === 'key' ? 'key' : 'password');
  const isPre = command.includes('hub-password-pre-ok');
  const isPost = command.includes('hub-password-post-ok');
  log({ mode, isPre, isPost, disabled: opts.disableFallback === true, command: command.slice(0, 60) });
  const fail = (cls, message) => ({ rc: -1, stdout: '', stderr: `ssh error: ${message}`, error_class: cls });

  // The generated public key arrives inside a multi-line, quoted printf argument,
  // so extract it by its own comment.
  const hubKeyLine = (command.match(/ssh-(?:ed25519|rsa) [^\s']+ gre-hub-\d+/) || [])[0];
  if (hubKeyLine && command.includes('authorized_keys')) {
    const comment = (hubKeyLine.match(/gre-hub-\d+/) || [])[0];
    if (comment) state.authorizedKeys = state.authorizedKeys.filter((k) => !k.includes(comment));
    state.authorizedKeys.push(hubKeyLine);
    state.installed.push(hubKeyLine);
  } else {
    // A pure removal deletes only our own line. An install command also carries the
    // removal token (to drop a stale line first), so it must not be modelled here.
    const removeMatch = command.match(/grep -vF '(gre-hub-\d+)'/);
    if (removeMatch) state.authorizedKeys = state.authorizedKeys.filter((k) => !k.includes(removeMatch[1]));
  }

  if (mode === 'password') {
    if (isPre) state.passwordChecked += 1;
    const works = SCENARIO === 'no_password' ? false
      : (SCENARIO === 'postcheck_fail' && isPost) ? false
        : secret === state.password;
    if (!works) {
      // Record WHY, without the secret itself: enough to debug a test, useless to
      // an attacker reading a log.
      log({ reject: 'password', gotLength: String(secret || '').length, expectedLength: state.password.length, matches: false });
      return fail('auth', 'All configured authentication methods failed');
    }
    return { rc: 0, stdout: stdoutFor(command), stderr: '' };
  }

  // Key mode: the Hub's freshly generated key is only valid once its public half
  // has been installed. A request with no installed key line at all (a password
  // string passed to key mode) fails, which is the honest behaviour.
  const installedBody = (state.installed[0] || '').split(/\s+/)[1];
  const secretBody = looksLikePrivateKey(secret) ? installedBody : null;
  const keyWorks = SCENARIO !== 'auth_fail' && !!secretBody && !!installedBody;
  if (keyWorks) return { rc: 0, stdout: stdoutFor(command), stderr: '' };

  // A real transport offers the fallback only when allowed to, and only for auth.
  const mayFallback = opts.disableFallback !== true && opts.authMode === undefined && opts.fallbackPassword;
  if (mayFallback && secret === state.password) {
    return { rc: 0, stdout: stdoutFor(command), stderr: '', fallback_used: true, auth_method: 'password' };
  }
  return fail('auth', 'All configured authentication methods failed');
};

// The module IS the exec function (matching _test-ssh-module.js). The state and
// helpers hang off it so a caller can inspect what happened.
module.exports = exec;
module.exports.exec = exec;
module.exports.state = state;
module.exports.LOG = () => LOG;
module.exports.reset = () => { state.authorizedKeys = []; state.installed = []; };
