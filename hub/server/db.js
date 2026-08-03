'use strict';
// db.js — SQLite schema, migrations, and the audit helper.

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'hub.db'));
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      csrf       TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      last_seen  INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS servers (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT NOT NULL UNIQUE,
      host          TEXT NOT NULL,
      ssh_port      INTEGER NOT NULL DEFAULT 22,
      username      TEXT NOT NULL DEFAULT 'root',
      auth_type     TEXT NOT NULL CHECK (auth_type IN ('password','key')),
      secret_enc    TEXT NOT NULL,
      password_enc  TEXT,
      key_installed INTEGER NOT NULL DEFAULT 0,
      host_key_fp   TEXT,
      created_at    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS snapshots (
      server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
      json      TEXT NOT NULL,
      taken_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS action_log (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      kind        TEXT NOT NULL DEFAULT 'action',
      server_id   INTEGER REFERENCES servers(id) ON DELETE SET NULL,
      server_name TEXT NOT NULL,
      action      TEXT NOT NULL,
      params      TEXT,
      rc          INTEGER,
      output      TEXT,
      created_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS recovery_codes (
      hash       TEXT PRIMARY KEY,
      used_at    INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_action_log_created ON action_log(created_at DESC);
  `);

  // Migrations for v1 databases.
  ensureColumn(db, 'servers', 'password_enc', 'password_enc TEXT');
  ensureColumn(db, 'servers', 'key_installed', 'key_installed INTEGER NOT NULL DEFAULT 0');
  ensureColumn(db, 'servers', 'host_key_fp', 'host_key_fp TEXT');
  ensureColumn(db, 'sessions', 'csrf', "csrf TEXT NOT NULL DEFAULT ''");
  ensureColumn(db, 'sessions', 'last_seen', 'last_seen INTEGER NOT NULL DEFAULT 0');
  ensureColumn(db, 'action_log', 'kind', "kind TEXT NOT NULL DEFAULT 'action'");

  return db;
}

function ensureColumn(db, table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
  }
}

// Audit events share the action_log table with kind='auth' (hub-level events,
// server_name='hub') or kind='action' (remote command runs).
function audit(db, { kind = 'auth', serverId = null, serverName = 'hub', action, params = null, rc = 0, output = '' }) {
  db.prepare(
    'INSERT INTO action_log (kind, server_id, server_name, action, params, rc, output, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(kind, serverId, serverName, action, params ? JSON.stringify(params) : null, rc, String(output).slice(0, 20000), Date.now());
}

module.exports = { openDb, audit };
