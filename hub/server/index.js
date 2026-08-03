'use strict';
// index.js — gre-hub entry point: HTTP API + static frontend + WS terminal.

const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const { WebSocketServer } = require('ws');

const { openDb } = require('./db');
const cryptoUtil = require('./crypto');
const ssh = require('./ssh');
const { createRouter, consumeTicket } = require('./routes');

const PORT = Number(process.env.PORT || 3939);
const HOST = process.env.HUB_HOST || '127.0.0.1';
const DATA_DIR = process.env.HUB_DATA_DIR || path.join(__dirname, '..', 'data');

const db = openDb(DATA_DIR);
const cryptKey = cryptoUtil.loadKey(DATA_DIR);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));

app.use('/api', createRouter(db, cryptKey));

// Static frontend; xterm.js is served straight from node_modules (no CDN, no build).
const root = path.join(__dirname, '..');
app.use(express.static(path.join(root, 'public')));
app.use('/vendor/xterm', express.static(path.join(root, 'node_modules', '@xterm', 'xterm')));
app.use('/vendor/xterm-fit', express.static(path.join(root, 'node_modules', '@xterm', 'addon-fit')));

const server = http.createServer(app);

// --- WebSocket SSH terminal --------------------------------------------
const wss = new WebSocketServer({ noServer: true });

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
          cryptoUtil.decrypt(cryptKey, row.secret_enc),
          { cols: msg.cols || 80, rows: msg.rows || 24 },
          {
            onData: (d) => { if (ws.readyState === ws.OPEN) ws.send(d.toString('utf8')); },
            onClose: closeAll,
            onError: (err) => {
              if (ws.readyState === ws.OPEN) ws.send(`\r\n\x1b[31mSSH error: ${err.message}\x1b[0m\r\n`);
              closeAll();
            },
          }
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
