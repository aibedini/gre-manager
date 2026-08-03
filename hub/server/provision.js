'use strict';
// provision.js — automatic per-server SSH key provisioning.
//
// Flow (see routes.js for the API entry points):
//   1. ssh-keygen -t ed25519 -f data/keys/server-<id> -N "" -C "gre-hub-<id>"
//      (private key mode 600, keys dir mode 700). ssh-keygen is required —
//      a clean error is raised when it is missing.
//   2. The public key line is appended to the server's ~/.ssh/authorized_keys
//      (dir 700 / file 600, de-duplicated on the "gre-hub-<id>" comment),
//      using whatever auth currently works (existing key or one-time password).
//   3. A key-only connection is verified; then the server row flips to
//      auth_type='key'. The private key's canonical copy is stored AES-256-GCM
//      encrypted in servers.secret_enc (same scheme as v1 passwords); the
//      data/keys/ files are kept (mode 600) as the ssh-keygen artifact.
//   4. The password is wiped unless the user opted to keep it as a fallback
//      (then it stays encrypted in servers.password_enc and ssh.js retries
//      with it when key auth fails).

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const ssh = require('./ssh');
const { encrypt, decrypt } = require('./crypto');

const KEY_COMMENT = (id) => `gre-hub-${id}`;

function keysDir(dataDir) {
  const dir = path.join(dataDir, 'keys');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function keygen(dataDir, serverId) {
  const dir = keysDir(dataDir);
  const keyPath = path.join(dir, `server-${serverId}`);
  for (const p of [keyPath, `${keyPath}.pub`]) {
    if (fs.existsSync(p)) fs.rmSync(p);
  }
  return new Promise((resolve, reject) => {
    execFile(
      'ssh-keygen',
      ['-t', 'ed25519', '-f', keyPath, '-N', '', '-C', KEY_COMMENT(serverId), '-q'],
      (err) => {
        if (err) {
          if (err.code === 'ENOENT') {
            return reject(new Error('ssh-keygen not found on this machine — install OpenSSH client tools'));
          }
          return reject(new Error(`ssh-keygen failed: ${err.message}`));
        }
        try { fs.chmodSync(keyPath, 0o600); } catch { /* windows: best effort */ }
        resolve({
          keyPath,
          privateKey: fs.readFileSync(keyPath, 'utf8'),
          publicKey: fs.readFileSync(`${keyPath}.pub`, 'utf8').trim(),
        });
      }
    );
  });
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

// Remote install: ensure ~/.ssh and authorized_keys exist with the right
// permissions, then append our key line unless the comment is already there.
function installCommand(publicKey, serverId) {
  const comment = KEY_COMMENT(serverId);
  return [
    'mkdir -p ~/.ssh && chmod 700 ~/.ssh',
    'touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
    `grep -qF ${shellQuote(comment)} ~/.ssh/authorized_keys || echo ${shellQuote(publicKey)} >> ~/.ssh/authorized_keys`,
    'echo key-installed',
  ].join(' && ');
}

// Remote removal: delete the line carrying our comment (best effort).
function removeCommand(serverId) {
  return `sed -i '/${KEY_COMMENT(serverId)}/d' ~/.ssh/authorized_keys 2>/dev/null; echo key-removed`;
}

// sshOptsFor(server) is supplied by routes.js so host-key TOFU and fallback
// passwords stay in one place.
async function provision(db, dataDir, cryptKey, server, sshOptsFor, audit) {
  const { keyPath, privateKey, publicKey } = await keygen(dataDir, server.id);

  // Current working credentials: the installed key, else the stored password.
  if (!server.secret_enc) {
    throw new Error('no working credentials — set the server password first');
  }
  const secret = decrypt(cryptKey, server.secret_enc);

  const install = await ssh.exec(server, secret, installCommand(publicKey, server.id), {
    timeoutMs: 30000,
    ...sshOptsFor(server),
  });
  if (install.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: install.presented_fp };
  if (install.rc !== 0 || !install.stdout.includes('key-installed')) {
    throw new Error(`failed to install public key: ${install.stderr || install.stdout || `rc=${install.rc}`}`);
  }

  // Verify key-only auth before switching.
  const keyServer = { ...server, auth_type: 'key' };
  const verify = await ssh.exec(keyServer, privateKey, 'echo hub-key-ok', {
    timeoutMs: 20000,
    ...sshOptsFor(keyServer),
  });
  if (verify.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: verify.presented_fp };
  if (verify.rc !== 0 || !verify.stdout.includes('hub-key-ok')) {
    throw new Error(`key installed but key auth failed: ${verify.stderr || `rc=${verify.rc}`}`);
  }

  db.prepare('UPDATE servers SET auth_type = ?, secret_enc = ?, key_installed = 1 WHERE id = ?')
    .run('key', encrypt(cryptKey, privateKey), server.id);
  if (audit) {
    audit(server.id, server.name, 'key_provision', { key: KEY_COMMENT(server.id), path: keyPath }, 0, 'ed25519 key installed and verified');
  }
  return { ok: true, comment: KEY_COMMENT(server.id) };
}

// After successful provisioning: wipe the one-time password, or keep it as
// an encrypted fallback when the user asked for that.
function handlePasswordAfterProvision(db, cryptKey, serverId, password, keepFallback) {
  if (keepFallback && password) {
    db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(encrypt(cryptKey, password), serverId);
  } else {
    db.prepare('UPDATE servers SET password_enc = NULL WHERE id = ?').run(serverId);
  }
}

async function removeKey(db, dataDir, cryptKey, server, sshOptsFor, audit) {
  // Best effort: delete the remote line while the key still works.
  if (server.secret_enc) {
    try {
      const secret = decrypt(cryptKey, server.secret_enc);
      await ssh.exec(server, secret, removeCommand(server.id), {
        timeoutMs: 20000,
        ...sshOptsFor(server),
      });
    } catch { /* best effort */ }
  }
  // Local cleanup: key files + DB. The kept fallback password (if any) becomes
  // the primary secret again; otherwise "password required" state.
  const keyPath = path.join(keysDir(dataDir), `server-${server.id}`);
  for (const p of [keyPath, `${keyPath}.pub`]) {
    if (fs.existsSync(p)) fs.rmSync(p);
  }
  const fallback = server.password_enc || '';
  db.prepare('UPDATE servers SET auth_type = ?, secret_enc = ?, password_enc = NULL, key_installed = 0 WHERE id = ?')
    .run('password', fallback, server.id);
  if (audit) {
    audit(server.id, server.name, 'key_delete', {}, 0, 'hub key removed locally and remotely (best effort)');
  }
  return { ok: true, password_required: !fallback };
}

module.exports = { provision, removeKey, handlePasswordAfterProvision, KEY_COMMENT, keysDir };
