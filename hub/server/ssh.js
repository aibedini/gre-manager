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

const AUTH_FAIL_RE = /authentication|auth methods failed/i;

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
  if (server.auth_type === 'key') {
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
// { hostkey_mismatch: true, presented_fp } or { hostkey_pinned: fp }.
function exec(server, secret, command, opts = {}) {
  const { timeoutMs = 120000 } = opts;
  const attempt = (authSecret, authType, fallbackPassword) =>
    new Promise((resolve) => {
      const conn = new Client();
      const hk = opts.hostKey ? { ...opts.hostKey } : null;
      let settled = false;
      const done = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        conn.end();
        if (hk && hk.mismatch) {
          result.hostkey_mismatch = true;
          result.presented_fp = hk.mismatch;
        }
        resolve(result);
      };
      const timer = setTimeout(() => {
        done({ rc: -1, stdout: '', stderr: `command timed out after ${timeoutMs}ms` });
      }, timeoutMs);

      const srv = { ...server, auth_type: authType };
      conn
        .on('ready', () => {
          conn.exec(command, (err, stream) => {
            if (err) return done({ rc: -1, stdout: '', stderr: `exec failed: ${err.message}` });
            let stdout = '';
            let stderr = '';
            stream
              .on('close', (code) => done({ rc: code ?? 0, stdout, stderr }))
              .on('data', (d) => { stdout += d.toString(); });
            stream.stderr.on('data', (d) => { stderr += d.toString(); });
          });
        })
        .on('error', (err) => {
          // Key auth failed but we hold a fallback password → retry with it.
          if (
            fallbackPassword &&
            authType === 'key' &&
            AUTH_FAIL_RE.test(err.message) &&
            !(hk && hk.mismatch)
          ) {
            clearTimeout(timer);
            settled = true;
            conn.end();
            resolve(attempt(fallbackPassword, 'password', null));
            return;
          }
          done({ rc: -1, stdout: '', stderr: `ssh error: ${err.message}` });
        })
        .connect(connectConfig(srv, authSecret, { ...opts, hostKey: hk }));
      wireKeyboardInteractive(conn, authType === 'password' ? authSecret : fallbackPassword);
    });

  if (!secret && !(opts.fallbackPassword && server.auth_type === 'key')) {
    return Promise.resolve({
      rc: -1,
      stdout: '',
      stderr: 'no credentials stored — set a password or reinstall the SSH key',
    });
  }
  return attempt(secret, server.auth_type, opts.fallbackPassword || null);
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
  wireKeyboardInteractive(conn, server.auth_type === 'password' ? secret : opts.fallbackPassword);

  return {
    write(data) { if (stream) stream.write(data); },
    resize(c, r) { if (stream && stream.setWindow) stream.setWindow(r, c, 0, 0); },
    close() { try { conn.end(); } catch { /* already closed */ } },
  };
}

module.exports = { exec, openShell };
