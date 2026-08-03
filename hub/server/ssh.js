'use strict';
// ssh.js — ssh2 helpers: run a remote command, open an interactive shell.

const { Client } = require('ssh2');

function connectConfig(server, secret) {
  const cfg = {
    host: server.host,
    port: server.ssh_port,
    username: server.username,
    readyTimeout: 15000,
    keepaliveInterval: 10000,
  };
  if (server.auth_type === 'key') {
    cfg.privateKey = secret;
    if (server.passphrase) cfg.passphrase = server.passphrase;
  } else {
    cfg.password = secret;
  }
  return cfg;
}

// Run a command, resolve with { rc, stdout, stderr }.
function exec(server, secret, command, { timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const conn = new Client();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      conn.end();
      resolve(result);
    };
    const timer = setTimeout(() => {
      done({ rc: -1, stdout: '', stderr: `command timed out after ${timeoutMs}ms` });
    }, timeoutMs);

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
      .on('error', (err) => done({ rc: -1, stdout: '', stderr: `ssh error: ${err.message}` }))
      .connect(connectConfig(server, secret));
  });
}

// Open an interactive PTY shell. Callbacks receive data/close events.
function openShell(server, secret, { cols = 80, rows = 24 }, { onData, onClose, onError }) {
  const conn = new Client();
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
    .on('error', (err) => onError(err))
    .on('close', () => onClose())
    .connect(connectConfig(server, secret));

  return {
    write(data) { if (stream) stream.write(data); },
    resize(c, r) { if (stream && stream.setWindow) stream.setWindow(r, c, 0, 0); },
    close() { try { conn.end(); } catch { /* already closed */ } },
  };
}

module.exports = { exec, openShell };
