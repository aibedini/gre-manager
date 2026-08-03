'use strict';
// auth.js — single-user password auth, DB-backed sessions, login rate limiting.

const crypto = require('crypto');
const { scryptHash, scryptVerify } = require('./crypto');

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_FAILS = 5;
const LOCK_MS = Number(process.env.HUB_LOCK_SECONDS || 60) * 1000;
const COOKIE_NAME = 'hub_session';

// In-memory rate limiting is fine for a single-user hub.
const fails = new Map(); // ip -> { count, lockedUntil }

function isLocked(ip) {
  const rec = fails.get(ip);
  return !!(rec && rec.lockedUntil && rec.lockedUntil > Date.now());
}

function recordFail(ip) {
  const rec = fails.get(ip) || { count: 0, lockedUntil: 0 };
  rec.count += 1;
  if (rec.count >= MAX_FAILS) {
    rec.lockedUntil = Date.now() + LOCK_MS;
    rec.count = 0;
  }
  fails.set(ip, rec);
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
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)')
    .run(token, now, now + SESSION_TTL_MS);
  return { token, expiresAt: now + SESSION_TTL_MS };
}

function destroySession(db, token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function getSession(db, token) {
  if (!token) return null;
  const row = db.prepare('SELECT token, expires_at FROM sessions WHERE token = ?').get(token);
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    destroySession(db, token);
    return null;
  }
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

function sessionCookie(token, expiresAt) {
  const maxAge = Math.floor((expiresAt - Date.now()) / 1000);
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function clearCookie() {
  return `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

// Express middleware: everything under /api except login/setup requires a session.
function requireAuth(db) {
  return (req, res, next) => {
    const token = parseCookies(req)[COOKIE_NAME];
    const session = getSession(db, token);
    if (!session) return res.status(401).json({ error: 'not authenticated' });
    req.sessionToken = token;
    next();
  };
}

module.exports = {
  COOKIE_NAME,
  isLocked,
  recordFail,
  clearFails,
  hasPassword,
  setPassword,
  checkPassword,
  createSession,
  destroySession,
  parseCookies,
  sessionCookie,
  clearCookie,
  requireAuth,
};
