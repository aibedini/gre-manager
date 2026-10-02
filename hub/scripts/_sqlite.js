'use strict';
// _sqlite.js — portability shim.
//
// Production and CI run Linux where `better-sqlite3` installs from a prebuilt
// binary. On a Windows dev box without a Windows SDK the native build fails,
// which must not stop the hub's own test suite from running. So: use
// better-sqlite3 when it loads, otherwise fall back to Node's built-in
// node:sqlite behind the same tiny API surface (prepare/run/get/all/exec/
// transaction/pragma).
//
// Requiring this module installs the fallback on the module loader, so every
// existing `require('better-sqlite3')` in server/db.js and the test scripts
// keeps working unchanged.

let nativeError = null;
let nativeAvailable = false;
try {
  // eslint-disable-next-line global-require
  const NativeDatabase = require('better-sqlite3');
  // Requiring the package only loads its JS; the native addon is resolved on
  // first construction, which is where a missing/broken build actually throws.
  const probe = new NativeDatabase(':memory:');
  probe.close();
  nativeAvailable = true;
} catch (err) {
  nativeError = err;
}

function toPlain(row) {
  if (!row || typeof row !== 'object') return row;
  return { ...row };
}

class Statement {
  constructor(statement) {
    this.statement = statement;
  }

  run(...params) {
    const info = this.statement.run(...params);
    return {
      changes: Number(info.changes),
      lastInsertRowid: typeof info.lastInsertRowid === 'bigint' ? Number(info.lastInsertRowid) : Number(info.lastInsertRowid),
    };
  }

  get(...params) {
    const row = this.statement.get(...params);
    return row === undefined ? undefined : toPlain(row);
  }

  all(...params) {
    return this.statement.all(...params).map(toPlain);
  }

  iterate(...params) {
    return this.all(...params)[Symbol.iterator]();
  }
}

class SqliteShim {
  constructor(filename) {
    // eslint-disable-next-line global-require
    const { DatabaseSync } = require('node:sqlite');
    this.inner = new DatabaseSync(filename);
  }

  prepare(sql) {
    return new Statement(this.inner.prepare(sql));
  }

  exec(sql) {
    this.inner.exec(sql);
    return this;
  }

  pragma(statement) {
    const text = String(statement);
    if (text.includes('=')) {
      // Setting form, e.g. "journal_mode = WAL" / "foreign_keys = ON".
      const [key, value] = text.split('=', 2).map((part) => part.trim());
      this.inner.exec(`PRAGMA ${key} = ${value}`);
      return this;
    }
    return this.inner.prepare(`PRAGMA ${text}`).all().map(toPlain);
  }

  transaction(fn) {
    const wrapped = (...args) => {
      this.inner.exec('BEGIN');
      try {
        const value = fn(...args);
        this.inner.exec('COMMIT');
        return value;
      } catch (err) {
        try { this.inner.exec('ROLLBACK'); } catch { /* already rolled back */ }
        throw err;
      }
    };
    wrapped.default = wrapped;
    wrapped.deferred = wrapped;
    wrapped.immediate = wrapped;
    wrapped.exclusive = wrapped;
    return wrapped;
  }

  close() {
    this.inner.close();
  }
}

function patchModuleLoader() {
  if (nativeAvailable) return;
  // eslint-disable-next-line global-require
  const Module = require('module');
  const original = Module._load;
  if (original.__greSqlitePatched) return;
  const patched = function patchedLoad(request, parent, isMain) {
    if (request === 'better-sqlite3') return SqliteShim;
    return original.call(this, request, parent, isMain);
  };
  patched.__greSqlitePatched = true;
  Module._load = patched;
}

patchModuleLoader();

module.exports = {
  available: nativeAvailable,
  nativeError,
  SqliteShim,
  engine: nativeAvailable ? 'better-sqlite3' : 'node:sqlite',
};
