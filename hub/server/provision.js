'use strict';
// provision.js — automatic per-server SSH key provisioning.
//
// DESIGN RULE, and the reason this file is shaped the way it is:
//
//   Installing the Hub key must NEVER break, remove or replace a server's
//   existing SSH access. The Hub key is an ADDITIONAL authentication method. If a
//   server was reachable with root/password before provisioning, the same password
//   must still work afterwards — including for PuTTY and MobaXterm sessions that
//   have nothing to do with this Hub.
//
// Two consequences that are enforced here:
//   * No normal provisioning path ever clears servers.password_enc. Only an
//     explicit operator action may do that.
//   * Provisioning writes ONLY ~/.ssh and ~/.ssh/authorized_keys. It never edits
//     sshd_config, never touches PasswordAuthentication / PermitRootLogin /
//     AuthenticationMethods, and never runs passwd / usermod / chpasswd. The Hub
//     manages the credentials it owns; it does not manage the server's login policy.
//
// Verification is four stages, so the claim "both paths still work" is measured
// rather than assumed:
//   A  password-only auth with the CURRENT stored credential (abort if it fails)
//   B  append the public key to authorized_keys (additive; nothing is deleted)
//   C  KEY-ONLY auth with the new private key, password fallback disabled
//   D  PASSWORD-ONLY auth again with the original password, key auth not used
//
// If D fails while A and C passed, provisioning is NOT a success: it returns
// NEEDS_REVIEW and leaves every credential in place, because the operator has to
// decide what to do. It never "fixes" the remote password.

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const ssh = require('./ssh');
const { encrypt, decrypt } = require('./crypto');

const KEY_COMMENT = (id) => `gre-hub-${id}`;

// Markers used by the verification stages.
const PRE_MARKER = 'hub-password-pre-ok';
const KEY_MARKER = 'hub-key-ok';
const POST_MARKER = 'hub-password-post-ok';

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
// permissions, then refresh OUR key line.
//
// Strictly additive and strictly scoped: the only line ever removed is a previous
// line carrying our own `gre-hub-<id>` comment (so a rotated key does not leave a
// stale entry behind). Every other key — the operator's own, other tools' — is
// preserved byte-for-byte. Nothing here reads or writes any file outside ~/.ssh.
function installCommand(publicKey, serverId) {
  const comment = KEY_COMMENT(serverId);
  const line = `${publicKey}`;
  return [
    'mkdir -p ~/.ssh && chmod 700 ~/.ssh',
    'touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
    // Drop only our own previous line, if any.
    `if [ -f ~/.ssh/authorized_keys ]; then grep -vF ${shellQuote(comment)} ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.gre-hub.tmp || true; mv ~/.ssh/authorized_keys.gre-hub.tmp ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; fi`,
    `printf '%s\\n' ${shellQuote(line)} >> ~/.ssh/authorized_keys`,
    'echo key-installed',
  ].join(' && ');
}

// Remote removal: delete only the line carrying our comment.
function removeCommand(serverId) {
  const comment = KEY_COMMENT(serverId);
  return [
    `if [ -f ~/.ssh/authorized_keys ]; then grep -vF ${shellQuote(comment)} ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.gre-hub.tmp || true; mv ~/.ssh/authorized_keys.gre-hub.tmp ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; fi`,
    'echo key-removed',
  ].join('; ');
}

// --- verification stages -------------------------------------------------
//
// Each stage runs through the injected `sshImpl` so tests can drive the exact
// sequence without a network. They are also exported individually so a test can
// assert what a stage does on its own.

// STAGE A: does the CURRENT credential still authenticate over password-only auth?
async function verifyPasswordStage(server, password, sshOptsFor, sshImpl, marker) {
  const result = await sshImpl.exec(server, password, `echo ${marker}`, {
    timeoutMs: 20000,
    authMode: 'password',
    disableFallback: true,
    ...sshOptsFor(server),
  });
  if (result.hostkey_mismatch) return { ok: false, hostkey_mismatch: true, presented_fp: result.presented_fp };
  return {
    ok: result.rc === 0 && String(result.stdout).includes(marker),
    rc: result.rc,
    detail: result.stderr || result.stdout || `rc=${result.rc}`,
    error_class: result.error_class || null,
  };
}

// STAGE C: does KEY-ONLY auth work? The fallback password is deliberately withheld
// and the mode forced, so a password that happens to still work cannot mask a key
// that does not.
async function verifyKeyStage(server, privateKey, sshOptsFor, sshImpl) {
  const keyServer = { ...server, auth_type: 'key' };
  const result = await sshImpl.exec(keyServer, privateKey, `echo ${KEY_MARKER}`, {
    timeoutMs: 20000,
    authMode: 'key',
    disableFallback: true,
    ...sshOptsFor(keyServer),
  });
  if (result.hostkey_mismatch) return { ok: false, hostkey_mismatch: true, presented_fp: result.presented_fp };
  return {
    ok: result.rc === 0 && String(result.stdout).includes(KEY_MARKER),
    rc: result.rc,
    detail: result.stderr || result.stdout || `rc=${result.rc}`,
    error_class: result.error_class || null,
  };
}

async function installKeyRemote(server, password, publicKey, sshOptsFor, sshImpl) {
  const result = await sshImpl.exec(server, password, installCommand(publicKey, server.id), {
    timeoutMs: 30000,
    authMode: 'password',
    disableFallback: true,
    ...sshOptsFor(server),
  });
  if (result.hostkey_mismatch) return { ok: false, hostkey_mismatch: true, presented_fp: result.presented_fp };
  const ok = result.rc === 0 && String(result.stdout).includes('key-installed');
  return { ok, detail: result.stderr || result.stdout || `rc=${result.rc}` };
}

// sshOptsFor(server) is supplied by routes.js so host-key TOFU and fallback
// passwords stay in one place.
//
// `sshImpl` defaults to the real transport and exists so the four stages can be
// tested end-to-end without a server. It is NOT reachable from HTTP input.
async function provision(db, dataDir, cryptKey, server, sshOptsFor, audit, sshImpl = ssh) {
  if (!server.secret_enc) {
    throw new Error('no working credentials — set the server password first');
  }
  const secret = decrypt(cryptKey, server.secret_enc);
  const isKeyServer = server.auth_type === 'key' && server.key_installed;

  // The credential we are about to prove still works, and the password we will
  // keep as the fallback. On a fresh password server both are the same string; on
  // an existing key server the "current" credential is the private key and the
  // fallback password comes from password_enc.
  const currentPassword = isKeyServer
    ? (server.password_enc ? decrypt(cryptKey, server.password_enc) : null)
    : secret;

  // STAGE A — the current password path must already work. Provisioning a key on
  // top of a password that does not work would be building on sand, and would also
  // make STAGE D meaningless.
  if (currentPassword) {
    const pre = await verifyPasswordStage(server, currentPassword, sshOptsFor, sshImpl, PRE_MARKER);
    if (pre.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: pre.presented_fp };
    if (!pre.ok) {
      if (audit) audit(server.id, server.name, 'ssh_password_precheck_fail', null, 1, 'the current password does not authenticate');
      throw new Error('the current password no longer authenticates — refusing to provision a key on top of it');
    }
    if (audit) audit(server.id, server.name, 'ssh_password_precheck_pass', null, 0, 'password auth verified before key install');
  } else if (!isKeyServer) {
    throw new Error('no password available to verify — set the server password first');
  }

  // STAGE B — install, additively.
  const { keyPath, privateKey, publicKey } = await keygen(dataDir, server.id);
  // On a key server the install runs over the existing key; otherwise the password.
  const bootstrapSecret = isKeyServer ? secret : currentPassword;
  const bootstrapServer = isKeyServer ? server : { ...server, auth_type: 'password' };
  const install = await installKeyRemote(bootstrapServer, bootstrapSecret, publicKey, sshOptsFor, sshImpl);
  if (install.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: install.presented_fp };
  if (!install.ok) {
    if (audit) audit(server.id, server.name, 'ssh_key_verify_fail', null, 1, `key install failed: ${install.detail}`);
    throw new Error(`failed to install public key: ${install.detail}`);
  }
  if (audit) audit(server.id, server.name, 'ssh_key_installed', { key: KEY_COMMENT(server.id), path: keyPath }, 0, 'public key appended to authorized_keys');

  // STAGE C — key-only auth must work before we trust it.
  const keyCheck = await verifyKeyStage(server, privateKey, sshOptsFor, sshImpl);
  if (keyCheck.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: keyCheck.presented_fp };
  if (!keyCheck.ok) {
    if (audit) audit(server.id, server.name, 'ssh_key_verify_fail', null, 1, 'key installed but key-only auth failed');
    throw new Error(`key installed but key-only auth failed: ${keyCheck.detail}`);
  }
  if (audit) audit(server.id, server.name, 'ssh_key_verify_pass', null, 0, 'key-only authentication verified');

  // The key demonstrably works, so the row can switch its PRIMARY method. The
  // password, if we hold one, is preserved — that is the whole point.
  db.prepare('UPDATE servers SET auth_type = ?, secret_enc = ?, key_installed = 1, key_verified_at = ? WHERE id = ?')
    .run('key', encrypt(cryptKey, privateKey), Date.now(), server.id);
  if (currentPassword) {
    db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?')
      .run(encrypt(cryptKey, currentPassword), server.id);
  }

  // STAGE D — the original password path must STILL work. This is the check whose
  // absence allowed a key install to quietly be the last access method standing.
  if (currentPassword) {
    const post = await verifyPasswordStage(server, currentPassword, sshOptsFor, sshImpl, POST_MARKER);
    if (post.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: post.presented_fp };
    if (!post.ok) {
      if (audit) {
        audit(server.id, server.name, 'ssh_password_postcheck_fail', null, 1,
          'key installed, but the original password path no longer verifies');
      }
      // Nothing is rolled back and nothing remote is touched: the key works, the
      // password is still stored, and a human has to look.
      return {
        ok: false,
        status: 'NEEDS_REVIEW',
        needs_review: true,
        comment: KEY_COMMENT(server.id),
        detail: 'Key installed successfully, but the original password path no longer verified.',
        password_retained: true,
      };
    }
    db.prepare('UPDATE servers SET password_verified_at = ? WHERE id = ?').run(Date.now(), server.id);
    if (audit) audit(server.id, server.name, 'ssh_password_postcheck_pass', null, 0, 'password auth re-verified after key install');
  }

  return {
    ok: true,
    comment: KEY_COMMENT(server.id),
    key_verified: true,
    password_verified: !!currentPassword,
    password_retained: !!currentPassword,
  };
}

// Kept for backward compatibility with callers that used to wipe the password.
// It NO LONGER deletes anything unless the caller explicitly asks for removal:
// provisioning must never clear the fallback on its own.
function handlePasswordAfterProvision(db, cryptKey, serverId, password, keepFallback) {
  if (password && (keepFallback === undefined || keepFallback)) {
    db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(encrypt(cryptKey, password), serverId);
    db.prepare('UPDATE servers SET password_verified_at = ? WHERE id = ?').run(Date.now(), serverId);
  }
}

// The ONLY code path that may drop the stored fallback password. Called from an
// explicit, confirm-gated operator action — never from provisioning.
function removeFallbackPassword(db, serverId) {
  db.prepare('UPDATE servers SET password_enc = NULL, password_verified_at = NULL WHERE id = ?').run(serverId);
  return { ok: true };
}

// Can this server still be reached if the given method is taken away?
//
// The rule: at least one VERIFIED access method must survive any operation.
// "Verified" means we have a credential AND we have proved it works; a stored but
// unverified password does not count as a safety net.
function remainingAccessAfterRemovingKey(server, passwordVerifiedOk) {
  return { password: !!passwordVerifiedOk };
}

async function removeKey(db, dataDir, cryptKey, server, sshOptsFor, audit, sshImpl = ssh) {
  // Safety gate: removing the Hub key leaves the operator with whatever password
  // access exists. Prove it works BEFORE we take the key away, because afterwards
  // there may be no way back in.
  const storedPassword = server.password_enc ? decrypt(cryptKey, server.password_enc) : null;
  let passwordVerified = false;
  if (storedPassword) {
    const check = await verifyPasswordStage(server, storedPassword, sshOptsFor, sshImpl, PRE_MARKER);
    if (check.hostkey_mismatch) return { hostkey_mismatch: true, presented_fp: check.presented_fp };
    passwordVerified = check.ok;
  }

  if (!passwordVerified) {
    if (audit) {
      audit(server.id, server.name, 'key_delete_blocked', null, 1,
        'refused: no verified password fallback would remain');
    }
    return {
      ok: false,
      status: 'BLOCKED',
      error: 'Cannot remove the last verified SSH access method.',
      detail: storedPassword
        ? 'The stored fallback password did not authenticate, so removing the Hub key could lock you out.'
        : 'No fallback password is stored, so the Hub key is the only verified access method.',
    };
  }

  // Best effort: delete the remote line while the key still works.
  if (server.secret_enc) {
    try {
      const secret = decrypt(cryptKey, server.secret_enc);
      await sshImpl.exec(server, secret, removeCommand(server.id), {
        timeoutMs: 20000,
        authMode: 'key',
        disableFallback: true,
        ...sshOptsFor(server),
      });
    } catch { /* best effort: the safety gate above is what matters */ }
  }
  // Local cleanup: key files + DB. The verified fallback password becomes the
  // primary secret again.
  const keyPath = path.join(keysDir(dataDir), `server-${server.id}`);
  for (const p of [keyPath, `${keyPath}.pub`]) {
    if (fs.existsSync(p)) fs.rmSync(p);
  }
  db.prepare('UPDATE servers SET auth_type = ?, secret_enc = ?, password_enc = NULL, key_installed = 0 WHERE id = ?')
    .run('password', server.password_enc, server.id);
  if (audit) {
    audit(server.id, server.name, 'key_delete', {}, 0, 'hub key removed locally and remotely (best effort)');
  }
  return { ok: true, password_required: false, password_verified: true };
}

module.exports = {
  provision,
  removeKey,
  handlePasswordAfterProvision,
  removeFallbackPassword,
  verifyPasswordStage,
  verifyKeyStage,
  installKeyRemote,
  remainingAccessAfterRemovingKey,
  installCommand,
  removeCommand,
  KEY_COMMENT,
  keysDir,
  PRE_MARKER,
  KEY_MARKER,
  POST_MARKER,
};
