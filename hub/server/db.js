'use strict';
// db.js — SQLite schema, migrations, and the audit helper.

const path = require('path');
const fs = require('fs');
// Install the node:sqlite fallback before better-sqlite3 is loaded, so the hub
// still opens its database on machines where the native build is unavailable.
// It is optional: a trimmed runtime package simply uses the real driver.
try { require('../scripts/_sqlite'); } catch { /* test hook not shipped */ }
const Database = require('better-sqlite3');

function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'hub.db'));
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

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
    CREATE TABLE IF NOT EXISTS connectivity_checks (
      id                        INTEGER PRIMARY KEY AUTOINCREMENT,
      iran_server_id            INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      foreign_server_id         INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      iran_ip                   TEXT NOT NULL,
      foreign_ip                TEXT NOT NULL,
      iran_to_foreign           INTEGER NOT NULL,
      foreign_to_iran           INTEGER NOT NULL,
      iran_to_foreign_detail    TEXT NOT NULL DEFAULT '',
      foreign_to_iran_detail    TEXT NOT NULL DEFAULT '',
      checked_at                INTEGER NOT NULL,
      UNIQUE (iran_server_id, foreign_server_id)
    );
    CREATE TABLE IF NOT EXISTS xui_panels (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL UNIQUE,
      base_url    TEXT NOT NULL,
      username    TEXT NOT NULL,
      auth_type   TEXT NOT NULL DEFAULT 'password' CHECK (auth_type IN ('password','token')),
      capability  TEXT CHECK (capability IN ('managed_hosts','external_proxy')),
      password_enc TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      -- v2.12.0 diagnostics. Capability detection stays API-driven; these
      -- columns exist so the UI can show what was detected, when, and whether
      -- the last probe failed.
      panel_version        TEXT,
      panel_version_source TEXT,
      client_model         TEXT CHECK (client_model IN ('first_class','embedded')),
      host_mode            TEXT CHECK (host_mode IN ('managed_hosts','external_proxy')),
      last_probe_at        INTEGER,
      last_probe_error     TEXT
    );
    CREATE TABLE IF NOT EXISTS gre_routes (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      name              TEXT NOT NULL UNIQUE,
      iran_server_id    INTEGER NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
      foreign_server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
      panel_id          INTEGER NOT NULL REFERENCES xui_panels(id) ON DELETE RESTRICT,
      port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
      protocol          TEXT NOT NULL DEFAULT 'tcp,udp',
      method            TEXT NOT NULL,
      client_email      TEXT NOT NULL,
      client_mode       TEXT CHECK (client_mode IN ('existing','new')),
      client_model      TEXT CHECK (client_model IN ('first_class','embedded')),
      client_password_enc TEXT,
      inbound_id        INTEGER,
      capability        TEXT CHECK (capability IN ('managed_hosts','external_proxy')),
      share_link_enc    TEXT,
      status            TEXT NOT NULL CHECK (status IN ('RESERVED','ACTIVE','FAILED','STALE','NEEDS_REVIEW')),
      last_error        TEXT,
      created_at        INTEGER NOT NULL,
      updated_at        INTEGER NOT NULL,
      -- v2.12.0 ownership metadata: enough to reconcile, retry, edit and
      -- safely delete exactly the resources this route created.
      peer_name             TEXT,
      host_group_id         TEXT,
      client_created_by_route INTEGER,
      client_attached_by_route INTEGER,
      rollback_state        TEXT CHECK (rollback_state IN ('NONE','PARTIAL','CLEAN','FAILED')),
      attempt_no            INTEGER NOT NULL DEFAULT 1,
      deleted_at            INTEGER,
      current_stage         TEXT,
      panel_version_snapshot TEXT,
      host_mode             TEXT CHECK (host_mode IN ('managed_hosts','external_proxy'))
    );
    CREATE TABLE IF NOT EXISTS port_allocations (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      route_id          INTEGER NOT NULL UNIQUE REFERENCES gre_routes(id) ON DELETE CASCADE,
      iran_server_id    INTEGER NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
      foreign_server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
      port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
      protocols         TEXT NOT NULL DEFAULT 'tcp,udp',
      status            TEXT NOT NULL CHECK (status IN ('RESERVED','ACTIVE','FAILED','STALE','NEEDS_REVIEW','RELEASED')),
      created_at        INTEGER NOT NULL,
      updated_at        INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS route_events (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      route_id   INTEGER NOT NULL REFERENCES gre_routes(id) ON DELETE CASCADE,
      stage      TEXT NOT NULL,
      status     TEXT NOT NULL,
      detail     TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      -- v2.12.0: which provisioning attempt produced this row, so a retried
      -- route keeps every previous attempt in the same persistent log.
      attempt_no INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS idx_action_log_created ON action_log(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_connectivity_iran ON connectivity_checks(iran_server_id);
    CREATE INDEX IF NOT EXISTS idx_connectivity_foreign ON connectivity_checks(foreign_server_id);
    CREATE INDEX IF NOT EXISTS idx_routes_pair ON gre_routes(iran_server_id, foreign_server_id);
    CREATE INDEX IF NOT EXISTS idx_ports_status ON port_allocations(status);
    CREATE INDEX IF NOT EXISTS idx_route_events_route ON route_events(route_id, id);
    -- Transport health and discovery health are TWO SEPARATE facts and must not
    -- share a row: a successful lightweight health probe ten seconds after a
    -- failed full discovery used to erase the discovery failure, so the UI said
    -- HEALTHY while topology was still unreadable.
    CREATE TABLE IF NOT EXISTS server_probe_state (
      server_id     INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
      ok            INTEGER NOT NULL,
      checked_at    INTEGER NOT NULL,
      duration_ms   INTEGER,
      error_class   TEXT,
      error_message TEXT,
      kind          TEXT NOT NULL DEFAULT 'full'
    );
    CREATE INDEX IF NOT EXISTS idx_probe_checked ON server_probe_state(checked_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_live_iran
      ON port_allocations(iran_server_id, port) WHERE status != 'RELEASED';
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_live_foreign
      ON port_allocations(foreign_server_id, port) WHERE status != 'RELEASED';
  `);

  // Migrations for v1 databases.
  ensureColumn(db, 'servers', 'password_enc', 'password_enc TEXT');
  ensureColumn(db, 'servers', 'key_installed', 'key_installed INTEGER NOT NULL DEFAULT 0');
  // SSH access verification state. A credential being STORED is not the same as it
  // being VERIFIED, and the last-access-method rule depends on the difference:
  // "no verified password" is what blocks removing the Hub key.
  ensureColumn(db, 'servers', 'password_verified_at', 'password_verified_at INTEGER');
  ensureColumn(db, 'servers', 'key_verified_at', 'key_verified_at INTEGER');
  ensureColumn(db, 'servers', 'fallback_last_used_at', 'fallback_last_used_at INTEGER');
  ensureColumn(db, 'servers', 'host_key_fp', 'host_key_fp TEXT');
  ensureColumn(db, 'sessions', 'csrf', "csrf TEXT NOT NULL DEFAULT ''");
  ensureColumn(db, 'sessions', 'last_seen', 'last_seen INTEGER NOT NULL DEFAULT 0');
  ensureColumn(db, 'action_log', 'kind', "kind TEXT NOT NULL DEFAULT 'action'");
  ensureColumn(db, 'xui_panels', 'auth_type', "auth_type TEXT NOT NULL DEFAULT 'password'");
  ensureColumn(db, 'xui_panels', 'capability', 'capability TEXT');
  // v2.11.0: distinguish "reuse an existing 3x-ui client" from "create a new
  // one", and remember which of the two client data models the panel had.
  // ALTER TABLE ADD COLUMN accepts a CHECK constraint in SQLite, so existing
  // v2.10.0 databases get the same guarantees as fresh ones.
  ensureColumn(db, 'gre_routes', 'client_mode', "client_mode TEXT CHECK (client_mode IN ('existing','new'))");
  ensureColumn(db, 'gre_routes', 'client_model', "client_model TEXT CHECK (client_model IN ('first_class','embedded'))");
  // v2.12.0: panel diagnostics + route ownership metadata. Same ALTER TABLE
  // path, so an existing v2.10.0/v2.11.0 hub.db migrates in place and keeps
  // every route, allocation and event row.
  ensureColumn(db, 'xui_panels', 'panel_version', 'panel_version TEXT');
  ensureColumn(db, 'xui_panels', 'panel_version_source', 'panel_version_source TEXT');
  ensureColumn(db, 'xui_panels', 'client_model', "client_model TEXT CHECK (client_model IN ('first_class','embedded'))");
  ensureColumn(db, 'xui_panels', 'host_mode', "host_mode TEXT CHECK (host_mode IN ('managed_hosts','external_proxy'))");
  ensureColumn(db, 'xui_panels', 'last_probe_at', 'last_probe_at INTEGER');
  ensureColumn(db, 'xui_panels', 'last_probe_error', 'last_probe_error TEXT');

  ensureColumn(db, 'gre_routes', 'peer_name', 'peer_name TEXT');
  ensureColumn(db, 'gre_routes', 'host_group_id', 'host_group_id TEXT');
  ensureColumn(db, 'gre_routes', 'client_created_by_route', 'client_created_by_route INTEGER');
  ensureColumn(db, 'gre_routes', 'client_attached_by_route', 'client_attached_by_route INTEGER');
  ensureColumn(db, 'gre_routes', 'rollback_state', "rollback_state TEXT CHECK (rollback_state IN ('NONE','PARTIAL','CLEAN','FAILED'))");
  ensureColumn(db, 'gre_routes', 'attempt_no', 'attempt_no INTEGER NOT NULL DEFAULT 1');
  ensureColumn(db, 'gre_routes', 'deleted_at', 'deleted_at INTEGER');
  ensureColumn(db, 'gre_routes', 'current_stage', 'current_stage TEXT');
  ensureColumn(db, 'gre_routes', 'panel_version_snapshot', 'panel_version_snapshot TEXT');
  ensureColumn(db, 'gre_routes', 'host_mode', "host_mode TEXT CHECK (host_mode IN ('managed_hosts','external_proxy'))");
  // Persistent, encrypted client configuration so an ACTIVE route can always be
  // copied again — after a browser refresh, and after the hub restarts. The
  // in-memory routeResults cache is a convenience, never the source of truth.
  ensureColumn(db, 'gre_routes', 'outbound_enc', 'outbound_enc TEXT');
  ensureColumn(db, 'gre_routes', 'config_updated_at', 'config_updated_at INTEGER');
  // Safe, non-secret summary of the last runtime validation (component -> PASS/WARN/FAIL).
  ensureColumn(db, 'gre_routes', 'runtime_checks', 'runtime_checks TEXT');
  // Public IRAN endpoint the client config points at. Stored so a config can be
  // reconstructed without re-detecting public IPs over SSH.
  ensureColumn(db, 'gre_routes', 'iran_endpoint', 'iran_endpoint TEXT');
  ensureColumn(db, 'route_events', 'attempt_no', 'attempt_no INTEGER NOT NULL DEFAULT 1');

  // ---------------------------------------------------------------- connections
  //
  // A GRE connection already IS a gre_routes row: it carries both server ids, the
  // peer name, the tunnel parameters and the port pair. Rather than introduce a
  // second model that would drift from that one, the connection view is a
  // projection of these rows and the extra state lives in the columns below.
  //
  // connection_uuid is the STABLE identity: it survives a rename and a server
  // migration, which the name-derived pair fingerprint cannot. It is assigned on
  // first look (see connections.js) so an existing installation needs no migration.
  ensureColumn(db, 'gre_routes', 'connection_uuid', 'connection_uuid TEXT');
  ensureColumn(db, 'gre_routes', 'connection_state', 'connection_state TEXT');
  ensureColumn(db, 'gre_routes', 'last_verified_at', 'last_verified_at INTEGER');
  ensureColumn(db, 'gre_routes', 'tcp_ports', 'tcp_ports TEXT');
  ensureColumn(db, 'gre_routes', 'udp_ports', 'udp_ports TEXT');
  ensureColumn(db, 'gre_routes', 'mss_clamp', 'mss_clamp INTEGER');
  ensureColumn(db, 'gre_routes', 'iran_ip', 'iran_ip TEXT');
  ensureColumn(db, 'gre_routes', 'foreign_ip', 'foreign_ip TEXT');

  try {
    db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_gre_routes_uuid ON gre_routes(connection_uuid) WHERE connection_uuid IS NOT NULL').run();
  } catch { /* already present */ }

  // The transaction journal. It records what an edit WOULD change and what it did
  // change, so a failed or interrupted migration can be explained and recovered.
  // No credential material ever goes in here: the requested state holds addresses,
  // ports and tunnel parameters only.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS edit_operations (
        operation_id      TEXT PRIMARY KEY,
        connection_uuid   TEXT NOT NULL,
        route_id          INTEGER,
        kind              TEXT NOT NULL,
        old_state_json    TEXT,
        requested_state_json TEXT,
        plan_json         TEXT,
        status            TEXT NOT NULL,
        current_stage     TEXT,
        rollback_state    TEXT,
        detail            TEXT,
        created_at        INTEGER NOT NULL,
        started_at        INTEGER,
        completed_at      INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_edit_ops_conn ON edit_operations(connection_uuid, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_edit_ops_status ON edit_operations(status);
    `);
  } catch { /* already present */ }

  // Split transport health from discovery health on the probe table. Additive:
  // the legacy ok/checked_at/error_* columns are kept and are migrated into the
  // `discovery_*` set once, so an existing row is not lost.
  ensureColumn(db, 'server_probe_state', 'health_ok', 'health_ok INTEGER');
  ensureColumn(db, 'server_probe_state', 'health_checked_at', 'health_checked_at INTEGER');
  ensureColumn(db, 'server_probe_state', 'health_duration_ms', 'health_duration_ms INTEGER');
  ensureColumn(db, 'server_probe_state', 'health_error_class', 'health_error_class TEXT');
  ensureColumn(db, 'server_probe_state', 'health_error_message', 'health_error_message TEXT');
  ensureColumn(db, 'server_probe_state', 'discovery_ok', 'discovery_ok INTEGER');
  ensureColumn(db, 'server_probe_state', 'discovery_checked_at', 'discovery_checked_at INTEGER');
  ensureColumn(db, 'server_probe_state', 'discovery_duration_ms', 'discovery_duration_ms INTEGER');
  ensureColumn(db, 'server_probe_state', 'discovery_error_class', 'discovery_error_class TEXT');
  ensureColumn(db, 'server_probe_state', 'discovery_error_message', 'discovery_error_message TEXT');
  // One-time carry-over of a pre-split row. Guarded so it cannot overwrite a row
  // that has already been migrated, and never destructive: the legacy columns
  // stay in place.
  try {
    db.prepare(`
      UPDATE server_probe_state
         SET discovery_ok = ok,
             discovery_checked_at = checked_at,
             discovery_duration_ms = duration_ms,
             discovery_error_class = error_class,
             discovery_error_message = error_message
       WHERE discovery_checked_at IS NULL AND checked_at IS NOT NULL
    `).run();
  } catch { /* pre-split table absent or already migrated */ }

  db.pragma(`user_version = ${SCHEMA_VERSION}`);
  return db;
}

// Bumped whenever the schema changes, so GET /api/meta can tell an operator
// which schema a running hub actually migrated to.
const SCHEMA_VERSION = 2;

function schemaVersion(db) {
  const row = db.prepare('PRAGMA user_version').get();
  const value = row ? Object.values(row)[0] : 0;
  return Number(value) || 0;
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

module.exports = { openDb, audit, schemaVersion, SCHEMA_VERSION };
