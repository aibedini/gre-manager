# gre-hub

Minimal web dashboard and central SSH hub for [gre-manager](https://github.com/aibedini/gre-manager)
servers. One place to see every IRAN/FOREIGN server, probe its tunnel state, run
manager actions, and open a browser SSH terminal.

## Quick start

```bash
cd hub
npm install
npm start          # listens on http://127.0.0.1:3939
```

Open http://127.0.0.1:3939 — on first run you create the hub password (min 12
chars), then add your servers with host, SSH port, username and password.

**The password is used only once.** On first successful connect the hub:

1. generates a dedicated ed25519 keypair (`ssh-keygen`, comment `gre-hub-<id>`,
   stored under `data/keys/` mode 600),
2. appends the public key to the server's `~/.ssh/authorized_keys`
   (700/600 permissions, de-duplicated),
3. verifies key-only auth, switches the server to key auth, and wipes the
   stored password — unless you checked "keep password as fallback"
   (then it stays AES-256-GCM encrypted and is used only if key auth fails).

The private key's canonical copy is stored AES-256-GCM encrypted in the hub
database (same scheme as all secrets); the `data/keys/` files are kept as the
ssh-keygen artifacts. Per server you can reinstall the key (e.g. after it was
removed remotely) or remove it entirely (remote `authorized_keys` line deleted
best-effort, local key destroyed, server falls back to "password required").

Configuration via environment variables:

| Variable          | Default       | Purpose                                        |
| ----------------- | ------------- | ---------------------------------------------- |
| `PORT`            | `3939`        | HTTP port                                      |
| `HUB_HOST`        | `127.0.0.1`   | Bind address (`0.0.0.0` to expose on LAN)      |
| `HUB_DATA_DIR`    | `hub/data`    | SQLite DB + encryption key + SSH keys          |
| `HUB_SECURE`      | off           | `1` = HSTS header + `Secure` session cookie (use behind HTTPS) |
| `HUB_LOCK_SECONDS`| `60`          | Login lockout after 5 failed attempts          |

## What it does

- **Discovery** — over SSH, probes each server for: gre-manager presence and
  version, `gre status --json` (roles, service, watchdog, tunnels up, nodes/peers
  with reachability), all GRE interfaces, tunnels **not** managed by the manager
  (not listed in `/etc/multi-gre` `TUN=` fields), and legacy vatanhost artifacts
  (`vatan-m2`, nat rules referencing `132.168.30.`, broad MASQUERADE, INPUT icmp
  DROP). Snapshots are stored in SQLite; server cards show role, version,
  tunnels, watchdog, peer names with reachability dots, LEGACY/UNMANAGED
  warnings, and a per-card Discover button.
- **Actions** — allowlisted, non-interactive (`--yes`) commands executed over SSH
  with captured output: install, update, doctor, restart all, watchdog control,
  first-time role setup (`setup_foreign` → `gre foreign-setup`, needs gre >=
  2.6.0; `setup_iran` → `gre iran-setup`, creates the first peer — both refuse
  when the server is already configured), node add/remove (FOREIGN), peer
  add/remove/apply (IRAN), export, and purge (requires typing `PURGE`). When a
  remote gre is too old for an action, the hub appends a hint to run the
  `update` action first. The Node-add, Peer-add, and Configure-as-IRAN forms use
  editable dropdowns: role-matched IRAN/FOREIGN IPs come from servers already
  registered in the hub, while ten rolling free-value suggestions come from
  `gre node suggest` or `gre iran peer suggest --count 10` (requires remote gre
  >= 2.8.0). Changing the subnet refreshes its index/key pool. Every run is
  recorded in the action log (params with secrets masked).
- **Terminal** — full SSH shell in the browser (xterm.js), bridged over a
  WebSocket authenticated by a short-lived one-time ticket.

## Security model

- **Hub password**: min 12 chars, scrypt hash. Changeable in Settings (requires
  the current password, signs out all other sessions).
- **Sessions**: random 32-byte tokens, HttpOnly SameSite=Lax cookie, 1-hour idle
  timeout (sliding) with a 12-hour absolute cap. "Log out all other sessions"
  button in Settings.
- **CSRF**: every session carries a token (rotated on login) that mutating API
  calls must send as `x-csrf-token`.
- **Optional TOTP 2FA** (RFC 6238, HMAC-SHA1/30s/6 digits, ±1 window, no
  external deps): enable in Settings — the secret and otpauth:// URI are shown
  for manual entry into any authenticator, one valid code activates it, and 10
  single-use recovery codes are issued (shown once, stored as SHA-256 hashes).
  Login becomes password → code. Disable requires password + code.
- **Rate limiting**: 5 failed logins → 60s lock (per IP).
- **SSH host key pinning (TOFU)**: the server's host key fingerprint (SHA256) is
  pinned on first connect; a later mismatch refuses the connection and requires
  an explicit, audited "accept new host key" action.
- **Security headers** on all responses: strict CSP (self-only, no CDN),
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`,
  restrictive `Permissions-Policy`, no `X-Powered-By`. With `HUB_SECURE=1` also
  HSTS and a `Secure` cookie.
- **Audit log**: auth events (logins, lockouts, setup, password change, 2FA
  on/off, recovery-code use, key provision/delete, host-key accept) and remote
  actions share one log, filterable by type in the UI.
- JSON bodies capped at 100kb; unknown `/api` routes 404; no stack traces in
  responses.

## Production checklist

1. **TLS** — never expose the plain-HTTP hub. Either put it behind Caddy/nginx
   with HTTPS and set `HUB_SECURE=1`, or keep it on `127.0.0.1` and reach it
   through an SSH tunnel: `ssh -L 3939:127.0.0.1:3939 you@hub-host`.
2. **Keep the default bind** (`127.0.0.1`); if you must bind wider, firewall
   the port (`ufw allow from <your-ip> to any port 3939`).
3. **Enable TOTP 2FA** in Settings and store the recovery codes offline.
4. **Use a long, unique hub password** — it guards root on every server.
5. **SSH keys only**: let the hub provision its per-server keys, don't keep
   password fallbacks unless you need them, and disable SSH password auth on
   the servers themselves (`PasswordAuthentication no`) once keys work.
6. **Protect `data/`** — it contains the DB, the AES key (`secret.key`) and
   the hub's private SSH keys. Back it up; don't commit it.

## Development

```bash
node scripts/smoke.js   # boots on a random port, 49 assertions
```

No build step: `public/` is plain HTML/JS/CSS; xterm.js is served from
`node_modules`. Stack: Express, better-sqlite3, ssh2, ws.
