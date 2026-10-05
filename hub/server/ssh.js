'use strict';
// ssh.js — ssh2 helpers: run a remote command, open an interactive shell.
//
// Security features:
// - Host key pinning (TOFU): callers pass opts.hostKey = { expected, onNew }.
//   `expected` null + onNew → trust-on-first-use (onNew(fp) is called and the
//   connection proceeds). A non-null expected that does not match aborts the
//   connection and the result carries hostkey_mismatch + presented_fp.
// - tryKeyboard fallback for keyboard-interactive-only servers.
// - Password fallback: if key auth fails and opts.fallbackPassword exists,
//   the connection is retried once with the password.

const { Client } = require('ssh2');

const AUTH_FAIL_RE = /authentication|auth methods failed|permission denied/i;

// Why the connection failed, which decides whether retrying with a different
// credential could possibly help.
//
// This matters for safety, not just tidiness: retrying with the stored password
// after a host key mismatch would be a way to bypass host key pinning, and
// retrying after a network timeout just doubles the wait for no reason.
const TRANSPORT_FAIL_RE = /econnrefused|connection refused|econnreset|ehostunreach|enetunreach|etimedout|timeout|timed out|no route to host|socket hang up|connection lost|enotfound|getaddrinfo|network|kex|handshake/i;
const HOSTKEY_FAIL_RE = /host key|hostkey|host verification|verification failed/i;

function classifyConnectionError(err, hk) {
  if (hk && hk.mismatch) return 'hostkey';
  const message = String((err && err.message) || err || '');
  if (HOSTKEY_FAIL_RE.test(message)) return 'hostkey';
  // Authentication is checked FIRST: "All configured authentication methods
  // failed" also contains no transport wording, but a genuine auth failure is the
  // only case where another credential is worth trying.
  if (AUTH_FAIL_RE.test(message)) return 'auth';
  if (TRANSPORT_FAIL_RE.test(message)) return 'transport';
  return 'transport';
}

// The effective authentication mode for a call.
//
// 'auto' keeps the historical behaviour (whatever the row's auth_type says).
// 'key' and 'password' force one method, which is what makes the provisioning
// verification stages real: testing the password while key auth could still
// succeed underneath proves nothing.
function resolveAuthMode(server, opts) {
  const mode = opts.authMode || 'auto';
  if (mode === 'key' || mode === 'password') return mode;
  return server.auth_type === 'key' ? 'key' : 'password';
}

function connectConfig(server, secret, opts) {
  const cfg = {
    host: server.host,
    port: server.ssh_port,
    username: server.username,
    readyTimeout: 15000,
    keepaliveInterval: 10000,
    tryKeyboard: true,
    hostHash: 'sha256',
  };
  const authType = opts.effectiveAuthType || server.auth_type;
  if (authType === 'key') {
    cfg.privateKey = secret;
    if (opts.passphrase) cfg.passphrase = opts.passphrase;
  } else {
    cfg.password = secret;
  }

  const hk = opts.hostKey;
  if (hk) {
    cfg.hostVerifier = (hashedKey) => {
      const fp = `SHA256:${hashedKey}`;
      if (!hk.expected) {
        if (hk.onNew) hk.onNew(fp); // TOFU: pin on first sight
        return true;
      }
      if (hk.expected === fp) return true;
      hk.mismatch = fp; // surfaced to the caller
      return false;
    };
  }
  return cfg;
}

function wireKeyboardInteractive(conn, password) {
  if (!password) return;
  conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
    finish(prompts.map(() => password));
  });
}

// Run a command, resolve with { rc, stdout, stderr } plus, when relevant,
// { hostkey_mismatch: true, presented_fp } or
// { fallback_used: true, primary_error: 'auth', auth_method: 'password' }.
function exec(server, secret, command, opts = {}) {
  const { timeoutMs = 120000 } = opts;
  const mode = resolveAuthMode(server, opts);
  // A caller verifying the password must not be rescued by the key, and vice
  // versa, so `disableFallback` is implied whenever a specific mode is forced.
  const explicitMode = opts.authMode === 'key' || opts.authMode === 'password';
  const fallbackAllowed = opts.disableFallback !== true && !explicitMode && mode === 'key';

  const attempt = (authSecret, authType, fallbackPassword, usedFallback) =>
    new Promise((resolve) => {
      const conn = new Client();
      const hk = opts.hostKey ? { ...opts.hostKey } : null;
      let settled = false;
      const done = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { conn.end(); } catch { /* already gone */ }
        if (hk && hk.mismatch) {
          result.hostkey_mismatch = true;
          result.presented_fp = hk.mismatch;
        }
        if (usedFallback) {
          result.fallback_used = true;
          result.auth_method = 'password';
          // Only announce it once the fallback actually carried a command through.
          if (result.rc === 0 && typeof opts.onFallbackUsed === 'function') {
            try { opts.onFallbackUsed(); } catch { /* auditing must never break a call */ }
          }
        } else if (result.rc === 0) {
          result.auth_method = authType;
        }
        resolve(result);
      };
      const timer = setTimeout(() => {
        done({ rc: -1, stdout: '', stderr: `command timed out after ${timeoutMs}ms`, timed_out: true, error_class: 'timeout' });
      }, timeoutMs);

      const srv = { ...server, auth_type: authType };
      conn
        .on('ready', () => {
          conn.exec(command, (err, stream) => {
            if (err) return done({ rc: -1, stdout: '', stderr: `exec failed: ${err.message}`, error_class: 'remote' });
            let stdout = '';
            let stderr = '';
            stream
              .on('close', (code) => done({ rc: code ?? 0, stdout, stderr }))
              .on('data', (d) => { stdout += d.toString(); });
            stream.stderr.on('data', (d) => { stderr += d.toString(); });
          });
        })
        .on('error', (err) => {
          const kind = classifyConnectionError(err, hk);
          // Retry with the stored password ONLY for a genuine authentication
          // failure. Never for a host key mismatch (that would bypass pinning)
          // and never for a transport problem (the password cannot help).
          if (fallbackPassword && authType === 'key' && kind === 'auth' && !settled) {
            clearTimeout(timer);
            settled = true;
            try { conn.end(); } catch { /* already gone */ }
            resolve(attempt(fallbackPassword, 'password', null, true));
            return;
          }          done({
            rc: -1,
            stdout: '',
            stderr: `ssh error: ${err.message}`,
            error_class: kind,
            primary_error: kind,
          });
        })
        .connect(connectConfig(srv, authSecret, { ...opts, hostKey: hk, effectiveAuthType: authType }));
      // Keyboard-interactive only ever answers with the password actually in use.
      wireKeyboardInteractive(conn, authType === 'password' ? authSecret : null);
    });

  if (!secret && !fallbackAllowed) {
    return Promise.resolve({
      rc: -1,
      stdout: '',
      stderr: 'no credentials stored — set a password or reinstall the SSH key',
      error_class: 'nocreds',
    });
  }
  return attempt(secret, mode, fallbackAllowed ? (opts.fallbackPassword || null) : null, false);
}

// Open an interactive PTY shell. Callbacks receive data/close/error events.
function openShell(server, secret, { cols = 80, rows = 24 }, { onData, onClose, onError }, opts = {}) {
  const conn = new Client();
  const hk = opts.hostKey ? { ...opts.hostKey } : null;
  let stream = null;

  conn
    .on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols, rows }, (err, s) => {
        if (err) {
          onError(err);
          conn.end();
          return;
        }
        stream = s;
        s.on('data', (d) => onData(d));
        s.on('close', () => {
          conn.end();
          onClose();
        });
      });
    })
    .on('error', (err) => {
      if (hk && hk.mismatch) {
        err.hostkey_mismatch = true;
        err.presented_fp = hk.mismatch;
      }
      onError(err);
    })
    .on('close', () => onClose())
    .connect(connectConfig(server, secret, { ...opts, hostKey: hk }));
  wireKeyboardInteractive(conn, (opts.authMode ? resolveAuthMode(server, opts) : server.auth_type) === 'password' ? secret : null);

  return {
    write(data) { if (stream) stream.write(data); },
    resize(c, r) { if (stream && stream.setWindow) stream.setWindow(r, c, 0, 0); },
    close() { try { conn.end(); } catch { /* already closed */ } },
  };
}

module.exports = {
  exec,
  openShell,
  classifyConnectionError,
  resolveAuthMode,
  AUTH_FAIL_RE,
  TRANSPORT_FAIL_RE,
};
