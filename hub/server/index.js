'use strict';
// index.js — gre-hub entry point: HTTP API + static frontend + WS terminal.

const path = require('path');
const http = require('http');
const express = require('express');
const { WebSocketServer } = require('ws');

const { openDb } = require('./db');
const cryptoUtil = require('./crypto');
const ssh = require('./ssh');
const { createRouter, consumeTicket, makeSshOpts } = require('./routes');

const PORT = Number(process.env.PORT || 3939);
const HOST = process.env.HUB_HOST || '127.0.0.1';
const DATA_DIR = process.env.HUB_DATA_DIR || path.join(__dirname, '..', 'data');
const SECURE = process.env.HUB_SECURE === '1';

const db = openDb(DATA_DIR);
const cryptKey = cryptoUtil.loadKey(DATA_DIR);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// Security headers on every response.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

app.use('/api', createRouter(db, cryptKey, DATA_DIR));

// Unknown API routes → JSON 404 (never the HTML handler).
app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

// Static frontend; xterm.js is served straight from node_modules (no CDN, no build).
const root = path.join(__dirname, '..');
app.use(express.static(path.join(root, 'public')));
app.use('/vendor/xterm', express.static(path.join(root, 'node_modules', '@xterm', 'xterm')));
app.use('/vendor/xterm-fit', express.static(path.join(root, 'node_modules', '@xterm', 'addon-fit')));

// Error handler: no stack traces leak to clients.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'request body too large' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON body' });
  res.status(500).json({ error: 'internal error' });
});

const server = http.createServer(app);

// --- WebSocket SSH terminal --------------------------------------------
const wss = new WebSocketServer({ noServer: true });
const sshOptsFor = makeSshOpts(db, cryptKey);

server.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    socket.destroy();
    return;
  }
  if (url.pathname !== '/ws/terminal') {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, url));
});

wss.on('connection', (ws, req, url) => {
  const serverId = consumeTicket(url.searchParams.get('ticket') || '');
  const row = serverId && db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId);
  if (!row) {
    ws.send('\r\n\x1b[31mInvalid or expired terminal ticket.\x1b[0m\r\n');
    ws.close();
    return;
  }

  let shell = null;
  let closed = false;
  const closeAll = () => {
    if (closed) return;
    closed = true;
    if (shell) shell.close();
    try { ws.close(); } catch { /* already closed */ }
  };

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!shell) {
      // First message must be the init frame with terminal dimensions.
      if (msg.type === 'init') {
        shell = ssh.openShell(
          row,
          row.secret_enc ? cryptoUtil.decrypt(cryptKey, row.secret_enc) : '',
          { cols: msg.cols || 80, rows: msg.rows || 24 },
          {
            onData: (d) => { if (ws.readyState === ws.OPEN) ws.send(d.toString('utf8')); },
            onClose: closeAll,
            onError: (err) => {
              if (ws.readyState === ws.OPEN) {
                const text = err.hostkey_mismatch
                  ? `HOST KEY MISMATCH — presented ${err.presented_fp}. Accept the new key from the Overview tab if this is expected.`
                  : `SSH error: ${err.message}`;
                ws.send(`\r\n\x1b[31m${text}\x1b[0m\r\n`);
              }
              closeAll();
            },
          },
          sshOptsFor(row)
        );
      }
      return;
    }
    if (msg.type === 'data') shell.write(msg.data);
    else if (msg.type === 'resize') shell.resize(msg.cols, msg.rows);
  });

  ws.on('close', closeAll);
  ws.on('error', closeAll);
});

server.listen(PORT, HOST, () => {
  console.log(`gre-hub listening on http://${HOST}:${PORT}  (data: ${DATA_DIR})`);
});

// Graceful shutdown so `node scripts/smoke.js` and Ctrl+C exit cleanly.
function shutdown() {
  wss.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
