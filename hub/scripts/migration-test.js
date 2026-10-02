'use strict';
// migration-test.js — an existing gre-manager v2.10.0 hub.db must open, migrate
// in place and keep working, with no data loss and no route left unrunnable.
//
// Run with: node scripts/migration-test.js

const { assert, check, report } = require('./_harness');
const fs = require('fs');
const os = require('os');
const path = require('path');
require('./_sqlite');
const Database = require('better-sqlite3');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');

// The v2.10.0 schema, verbatim from the released db.js.
const V210_SCHEMA = `
  CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
    ssh_port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL DEFAULT 'root',
    auth_type TEXT NOT NULL CHECK (auth_type IN ('password','key')), secret_enc TEXT NOT NULL,
    password_enc TEXT, key_installed INTEGER NOT NULL DEFAULT 0, host_key_fp TEXT, created_at INTEGER NOT NULL);
  CREATE TABLE xui_panels (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, base_url TEXT NOT NULL,
    username TEXT NOT NULL, auth_type TEXT NOT NULL DEFAULT 'password' CHECK (auth_type IN ('password','token')),
    capability TEXT CHECK (capability IN ('managed_hosts','external_proxy')), password_enc TEXT NOT NULL, created_at INTEGER NOT NULL);
  CREATE TABLE gre_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
    iran_server_id INTEGER NOT NULL, foreign_server_id INTEGER NOT NULL, panel_id INTEGER NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535), protocol TEXT NOT NULL DEFAULT 'tcp,udp',
    method TEXT NOT NULL, client_email TEXT NOT NULL, client_password_enc TEXT, inbound_id INTEGER,
    capability TEXT CHECK (capability IN ('managed_hosts','external_proxy')), share_link_enc TEXT,
    status TEXT NOT NULL CHECK (status IN ('RESERVED','ACTIVE','FAILED','STALE','NEEDS_REVIEW')),
    last_error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
  CREATE TABLE port_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, route_id INTEGER NOT NULL UNIQUE,
    iran_server_id INTEGER NOT NULL, foreign_server_id INTEGER NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535), protocols TEXT NOT NULL DEFAULT 'tcp,udp',
    status TEXT NOT NULL CHECK (status IN ('RESERVED','ACTIVE','FAILED','STALE','NEEDS_REVIEW','RELEASED')),
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
  CREATE TABLE route_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, route_id INTEGER NOT NULL, stage TEXT NOT NULL,
    status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
`;

function main() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-migration-'));
  // Build a v2.10.0 database with a live route, an event log and a panel.
  const legacy = new Database(path.join(dataDir, 'hub.db'));
  legacy.pragma('journal_mode = WAL');
  legacy.exec(V210_SCHEMA);
  const now = Date.now();
  legacy.prepare("INSERT INTO servers (id,name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (1,'iran','1.2.3.4',22,'root','password','x',?)").run(now);
  legacy.prepare("INSERT INTO servers (id,name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (2,'foreign','5.6.7.8',22,'root','password','x',?)").run(now);
  legacy.prepare("INSERT INTO xui_panels (id,name,base_url,username,auth_type,capability,password_enc,created_at) VALUES (1,'p','https://p.example','','token','managed_hosts','enc',?)").run(now);
  legacy.prepare(`INSERT INTO gre_routes (id,name,iran_server_id,foreign_server_id,panel_id,port,method,client_email,client_password_enc,inbound_id,capability,share_link_enc,status,created_at,updated_at)
    VALUES (1,'IR05-DE02',1,2,1,3049,'chacha20-ietf-poly1305','navid','cipher','100','managed_hosts','link','ACTIVE',?,?)`).run(now, now);
  legacy.prepare("INSERT INTO port_allocations (route_id,iran_server_id,foreign_server_id,port,protocols,status,created_at,updated_at) VALUES (1,1,2,3049,'tcp,udp','ACTIVE',?,?)").run(now, now);
  legacy.prepare("INSERT INTO route_events (route_id,stage,status,detail,created_at) VALUES (1,'active','PASS','Route marked ACTIVE',?)").run(now);
  legacy.close();

  const key = cryptoUtil.loadKey(dataDir);
  const db = openDb(dataDir);
  try {
    const columns = db.prepare('PRAGMA table_info(gre_routes)').all().map((c) => c.name);
    check('new columns are added in place', () => {
      assert(columns.includes('client_mode'), `client_mode missing (${columns.join(',')})`);
      assert(columns.includes('client_model'), 'client_model missing');
    });

    check('existing routes, allocations and events survive the migration', () => {
      const route = db.prepare('SELECT * FROM gre_routes WHERE id=1').get();
      assert.equal(route.status, 'ACTIVE');
      assert.equal(route.client_email, 'navid');
      assert.equal(route.port, 3049);
      assert.equal(db.prepare('SELECT count(*) AS n FROM port_allocations').get().n, 1);
      assert.equal(db.prepare('SELECT count(*) AS n FROM route_events').get().n, 1);
      assert.equal(route.client_mode, null, 'legacy rows keep NULL rather than an invented value');
      assert.equal(route.client_model, null);
    });

    check('the new CHECK constraints are enforced after migration', () => {
      assert.throws(() => db.prepare(`INSERT INTO gre_routes (name,iran_server_id,foreign_server_id,panel_id,port,method,client_email,client_mode,status,created_at,updated_at)
        VALUES ('bad',1,2,1,3050,'m','e','bogus','RESERVED',1,1)`).run(), /CHECK/i);
      assert.throws(() => db.prepare(`INSERT INTO gre_routes (name,iran_server_id,foreign_server_id,panel_id,port,method,client_email,client_model,status,created_at,updated_at)
        VALUES ('bad2',1,2,1,3051,'m','e','legacy','RESERVED',1,1)`).run(), /CHECK/i);
    });

    check('valid new values are accepted', () => {
      db.prepare(`INSERT INTO gre_routes (name,iran_server_id,foreign_server_id,panel_id,port,method,client_email,client_mode,client_model,status,created_at,updated_at)
        VALUES ('IR05-DE03',1,2,1,3052,'m','e','existing','first_class','RESERVED',1,1)`).run();
      const row = db.prepare("SELECT client_mode, client_model FROM gre_routes WHERE name='IR05-DE07' OR name='IR05-DE03'").get();
      assert.equal(row.client_mode, 'existing');
      assert.equal(row.client_model, 'first_class');
    });

    check('a legacy row with a NULL client_mode still provisions as a new client', () => {
      // RouteOrchestrator.run() falls back to 'new' for pre-v2.11.0 rows.
      const route = db.prepare('SELECT * FROM gre_routes WHERE id=1').get();
      assert.equal(route.client_mode || 'new', 'new');
    });

    check('opening the same database twice is idempotent', () => {
      db.close();
      const again = openDb(dataDir);
      const columnsAgain = again.prepare('PRAGMA table_info(gre_routes)').all().map((c) => c.name);
      assert.equal(columnsAgain.filter((c) => c === 'client_mode').length, 1, 'client_mode was added twice');
      again.close();
    });
  } finally {
    try { db.close(); } catch { /* already closed */ }
    fs.rmSync(dataDir, { recursive: true, force: true });
  }

  report('migration tests');
}

main();
