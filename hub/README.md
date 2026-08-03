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

Open http://127.0.0.1:3939 — on first run you create the hub password, then add
your servers (host, SSH port, username, password or private key).

Configuration via environment variables:

| Variable          | Default       | Purpose                                  |
| ----------------- | ------------- | ---------------------------------------- |
| `PORT`            | `3939`        | HTTP port                                |
| `HUB_HOST`        | `127.0.0.1`   | Bind address (`0.0.0.0` to expose on LAN) |
| `HUB_DATA_DIR`    | `hub/data`    | SQLite DB + encryption key location      |
| `HUB_LOCK_SECONDS`| `60`          | Login lockout after 5 failed attempts    |

## What it does

- **Discovery** — over SSH, probes each server for: gre-manager presence and
  version, `gre status --json` (roles, service, watchdog, tunnels up, nodes/peers
  with reachability), all GRE interfaces, tunnels **not** managed by the manager
  (not listed in `/etc/multi-gre` `TUN=` fields), and legacy vatanhost artifacts
  (`vatan-m2`, nat rules referencing `132.168.30.`, broad MASQUERADE, INPUT icmp
  DROP). Snapshots are stored in SQLite and shown as badges on each server card.
- **Actions** — allowlisted, non-interactive (`--yes`) commands executed over SSH
  with captured output: install, update, doctor, restart all, watchdog control,
  node add/remove (FOREIGN), peer add/remove/apply (IRAN), export, and purge
  (requires typing `PURGE`). Every run is recorded in the action log (params with
  secrets masked).
- **Terminal** — full SSH shell in the browser (xterm.js), bridged over a
  WebSocket authenticated by a short-lived one-time ticket.

## Security notes

- **Use a strong hub password.** It is the single credential guarding SSH access
  to all your servers. Stored as a scrypt hash; sessions are random 32-byte
  tokens in HttpOnly cookies (7-day TTL); 5 failed logins lock for 60s.
- **Do not expose the hub without TLS.** By default it binds to `127.0.0.1` —
  keep it that way and put it behind a reverse proxy with HTTPS, or reach it
  through an SSH tunnel: `ssh -L 3939:127.0.0.1:3939 you@hub-host`.
- **Prefer SSH keys** for server credentials. Secrets are stored AES-256-GCM
  encrypted with a key in `data/secret.key` (mode 600); back it up and protect
  the `data/` directory.
- The hub runs commands as the SSH user you configure (usually `root`) — anyone
  with the hub password has root on every registered server.

## Development

```bash
node scripts/smoke.js   # boots on a random port, asserts auth flow
```

No build step: `public/` is plain HTML/JS/CSS; xterm.js is served from
`node_modules`. Stack: Express, better-sqlite3, ssh2, ws.
