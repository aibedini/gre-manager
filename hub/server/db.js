'use strict';
// db.js — SQLite schema and shared statement helpers.

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
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS servers (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT NOT NULL UNIQUE,
      host       TEXT NOT NULL,
      ssh_port   INTEGER NOT NULL DEFAULT 22,
      username   TEXT NOT NULL DEFAULT 'root',
      auth_type  TEXT NOT NULL CHECK (auth_type IN ('password','key')),
      secret_enc TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS snapshots (
      server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
      json      TEXT NOT NULL,
      taken_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS action_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id  INTEGER REFERENCES servers(id) ON DELETE SET NULL,
      server_name TEXT NOT NULL,
      action     TEXT NOT NULL,
      params     TEXT,
      rc         INTEGER,
      output     TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_action_log_created ON action_log(created_at DESC);
  `);
  return db;
}

module.exports = { openDb };
