'use strict';
// auth.js — single-user password auth, DB-backed sessions, CSRF tokens,
// login rate limiting.
//
// Sessions: 1-hour idle timeout (sliding — last_seen is refreshed on every
// authenticated request) with a 12-hour absolute cap from creation.
// Each session carries a CSRF token (rotates on login) that mutating API
// calls must echo in the x-csrf-token header.

const crypto = require('crypto');
const { scryptHash, scryptVerify } = require('./crypto');

const IDLE_TTL_MS = 60 * 60 * 1000; // 1 hour sliding
const ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours hard cap
const MAX_FAILS = 5;
const LOCK_MS = Number(process.env.HUB_LOCK_SECONDS || 60) * 1000;
const COOKIE_NAME = 'hub_session';
const MIN_PASSWORD_LENGTH = 12;

// In-memory rate limiting is fine for a single-user hub.
const fails = new Map(); // ip -> { count, lockedUntil }

function isLocked(ip) {
  const rec = fails.get(ip);
  return !!(rec && rec.lockedUntil && rec.lockedUntil > Date.now());
}

// Returns true when this failure triggered a fresh lockout (for auditing).
function recordFail(ip) {
  const rec = fails.get(ip) || { count: 0, lockedUntil: 0 };
  rec.count += 1;
  if (rec.count >= MAX_FAILS) {
    rec.lockedUntil = Date.now() + LOCK_MS;
    rec.count = 0;
    fails.set(ip, rec);
    return true;
  }
  fails.set(ip, rec);
  return false;
}

function clearFails(ip) {
  fails.delete(ip);
}

function hasPassword(db) {
  return !!db.prepare('SELECT value FROM settings WHERE key = ?').get('password_hash');
}

function setPassword(db, password) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run('password_hash', scryptHash(password));
}

function checkPassword(db, password) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('password_hash');
  return !!row && scryptVerify(password, row.value);
}

function createSession(db) {
  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, csrf, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(token, csrf, now, now, now + ABSOLUTE_TTL_MS);
  return { token, csrf, expiresAt: now + ABSOLUTE_TTL_MS };
}

function destroySession(db, token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function destroyOtherSessions(db, token) {
  db.prepare('DELETE FROM sessions WHERE token != ?').run(token || '');
}

// Validates token + absolute cap + idle timeout; slides last_seen forward.
function getSession(db, token) {
  if (!token) return null;
  const row = db.prepare('SELECT token, csrf, created_at, last_seen, expires_at FROM sessions WHERE token = ?').get(token);
  if (!row) return null;
  const now = Date.now();
  if (row.expires_at < now || (row.last_seen && now - row.last_seen > IDLE_TTL_MS)) {
    destroySession(db, token);
    return null;
  }
  db.prepare('UPDATE sessions SET last_seen = ? WHERE token = ?').run(now, token);
  return row;
}

// Minimal cookie parsing (avoids an extra dependency).
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function sessionCookie(token, expiresAt, secure) {
  const maxAge = Math.floor((expiresAt - Date.now()) / 1000);
  const securePart = secure ? '; Secure' : '';
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${securePart}`;
}

function clearCookie(secure) {
  return `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure ? '; Secure' : ''}`;
}

// Express middleware: attaches the session or 401s. Mutating methods must
// also present the session's CSRF token in x-csrf-token.
function requireAuth(db) {
  return (req, res, next) => {
    const token = parseCookies(req)[COOKIE_NAME];
    const session = getSession(db, token);
    if (!session) return res.status(401).json({ error: 'not authenticated' });
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
      const presented = req.headers['x-csrf-token'];
      if (!presented || presented !== session.csrf) {
        return res.status(403).json({ error: 'missing or invalid CSRF token' });
      }
    }
    req.sessionToken = token;
    req.session = session;
    next();
  };
}

module.exports = {
  COOKIE_NAME,
  MIN_PASSWORD_LENGTH,
  isLocked,
  recordFail,
  clearFails,
  hasPassword,
  setPassword,
  checkPassword,
  createSession,
  destroySession,
  destroyOtherSessions,
  parseCookies,
  sessionCookie,
  clearCookie,
  requireAuth,
};
