# gre-manager v2.12.1 — deployment & real-panel verification runbook

This is the exact sequence for PHASE 0/1/2/19 of the v2.12.1 brief: prove what is
running now, deploy the release, and reproduce the `navid` flow against a real
3x-ui panel. Run it on the machine that hosts the gre-hub dashboard and keep the
output of each step.

**Install v2.12.1, not v2.12.1.** The v2.12.1 `gre-hub.tar.gz` shipped without
`hub/.npmrc`, so on a host whose npm refuses dependency install scripts by
default the hub installed "successfully" and then could not start (no native
`better-sqlite3` binding). v2.12.1 contains every v2.12.1 change plus that fix.

Set these once (`REL` is used by the download commands below):

```bash
REL=v2.12.1
HUB_DIR=/opt/gre-hub
HUB_URL=http://127.0.0.1:3939          # change if PORT was overridden
PANEL=NetlenTRNew1                     # the saved 3x-ui panel to test with
CLIENT=navid                           # the EXISTING client
```

---

## PHASE 0 — prove what is running BEFORE you change anything

```bash
sudo systemctl status gre-hub --no-pager | head -20
sudo systemctl show gre-hub -p ExecMainPID -p ActiveEnterTimestamp
sudo journalctl -u gre-hub -n 200 --no-pager | head -40
stat -c '%y  %s  %n' $HUB_DIR/public/app.js $HUB_DIR/server/xui.js \
                     $HUB_DIR/server/route-orchestrator.js $HUB_DIR/package.json
cat $HUB_DIR/VERSION       2>/dev/null || echo "NO hub/VERSION (pre-2.12.0 deployment)"
cat $HUB_DIR/build-info.json 2>/dev/null || echo "NO build-info.json (pre-2.12.0 deployment)"
curl -s $HUB_URL/api/meta || echo "GET /api/meta unavailable (pre-2.12.0 deployment)"
```

Hashes of the deployed runtime vs. the release:

```bash
sha256sum $HUB_DIR/public/app.js $HUB_DIR/server/xui.js \
          $HUB_DIR/server/route-orchestrator.js $HUB_DIR/server/routes.js \
          $HUB_DIR/server/db.js $HUB_DIR/server/index.js

TMP=$(mktemp -d); cd "$TMP"
curl -fsSLO https://github.com/aibedini/gre-manager/releases/download/$REL/gre-hub.tar.gz
curl -fsSLO https://github.com/aibedini/gre-manager/releases/download/$REL/gre-hub.tar.gz.sha256
sha256sum -c gre-hub.tar.gz.sha256
tar xzf gre-hub.tar.gz
cat hub/VERSION hub/build-info.json

for f in public/app.js server/xui.js server/route-orchestrator.js server/routes.js server/db.js server/index.js; do
  d=$(sha256sum "$HUB_DIR/$f" 2>/dev/null | cut -c1-12)
  r=$(sha256sum "$TMP/hub/$f" 2>/dev/null | cut -c1-12)
  printf '%-32s deployed=%s  v2.12.1=%s  %s\n' "$f" "${d:-missing}" "${r:-missing}" \
    "$([ "$d" = "$r" ] && echo MATCH || echo DIFFERENT)"
done
```

### Interpreting the diff (this answers the "why is the runtime inconsistent?" question)

| Observation | Diagnosis |
| --- | --- |
| `hub/VERSION` or `build-info.json` missing | **(A) stale `/opt/gre-hub`** — pre-2.12.0 files, so the old `client_name` collapse and the old hub-update code are what run |
| Files DIFFERENT and the service started before the files changed | **(B) stale service process** (old code still in memory) *plus* (A) |
| Files MATCH but the browser still shows old behaviour | **(C) stale browser assets** — hard-refresh (Ctrl/Cmd+Shift+R) |
| Files MATCH, no cache issue, still wrong | **(D) wrong release artifact** — the tarball/assets do not match the tag |
| Some files MATCH, others DIFFERENT | **(E) mixed files** from different releases, typically a partially applied update |

The three UI symptoms in the report map onto this: `capability: "detected on next
save"` and `client model: unknown` only exist in the **pre-2.12.0** frontend/DB
schema, and `Duplicate email: navid` can only happen on the **pre-2.11.0**
orchestrator. Seeing all of them together is the signature of **(A)** — a stale
`/opt/gre-hub` that was never updated to v2.11.0 either — not of a defect in the
released code.

---

## PHASE 1 — deploy v2.12.1 and prove it

Back up first. Never delete `hub.db`, `master.key` or the SSH keys:

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sudo tar czf /root/gre-hub-data-$STAMP.tar.gz -C $HUB_DIR data
sudo cp /etc/systemd/system/gre-hub.service /root/gre-hub.service.$STAMP 2>/dev/null || true
ls -la /root/gre-hub-data-$STAMP.tar.gz
ls -la /etc/systemd/system/gre-hub.service.d/ 2>/dev/null || true
```

Deploy through the tested updater:

```bash
sudo gre update            # CLI + hub to exactly the same release
# or, hub only:
sudo gre hub update
```

If the installed CLI predates `gre hub update`, install the released CLI first
and then use it:

```bash
sudo curl -fsSL -o /usr/local/sbin/gre \
  https://github.com/aibedini/gre-manager/releases/download/$REL/gre
curl -fsSL -o /tmp/gre.sha256 \
  https://github.com/aibedini/gre-manager/releases/download/$REL/gre.sha256
# verify /usr/local/sbin/gre against it (the checksum line names `gre`)
(cd /usr/local/sbin && sudo sha256sum -c /tmp/gre.sha256)
sudo chmod +x /usr/local/sbin/gre
sudo gre hub update
```

Verify:

```bash
sudo systemctl is-active gre-hub
sudo journalctl -u gre-hub -n 100 --no-pager | head -30
curl -s $HUB_URL/api/meta | python3 -m json.tool
cat $HUB_DIR/VERSION; cat $HUB_DIR/build-info.json
sudo gre hub status
```

Expected journal line (the hash is the release commit — take it from
`hub/build-info.json` in the tarball you downloaded, or from the release page):

```
gre-hub build: v2.12.1 · <shortsha> · version source: build-info.json
```

Expected `/api/meta`: `"version": "2.12.1"`, the same `"commit"` as
`hub/build-info.json`, `"schemaVersion": 2`, `"mixed": false`.

The UI top bar must read `v2.12.1 · <shortsha>` after a hard refresh, and
Settings → Application must show the same values. If the service does not come
up, the updater has already rolled the previous build back — capture
`journalctl -u gre-hub -n 200 --no-pager` before retrying.

---

## PHASE 2 / 19 — reproduce `navid` against the real panel

### 2a. Panel diagnostics

```bash
PANEL_ID=$(curl -s $HUB_URL/api/xui-panels \
  | python3 -c "import sys,json;print([p['id'] for p in json.load(sys.stdin) if p['name']=='$PANEL'][0])")
curl -s -X POST $HUB_URL/api/xui-panels/$PANEL_ID/probe | python3 -m json.tool
```

Expect a real `panel_version` (e.g. `3.8.x`), `client_model: first_class` if
`GET /panel/api/clients/list` returns 200, a `host_mode`, and no `error`.
`client_model` is never derived from the version number.

### 2b. Confirmed request contract

DevTools → Network → Create route → the `POST /api/gre-routes` payload must
contain:

```json
{ "client_mode": "existing", "client_email": "navid" }
```

and must NOT contain `client_name`.

### 2c. Expected timeline

```
panel_probe            RUNNING → PASS   3x-ui vX.Y.Z; client=first_class; hosts=...
client_preflight       PASS             client 'navid' exists on the panel (first_class)
port_reserved          PASS             TCP+UDP port NNNN reserved
public_ip / connectivity
gre_pairing / foreign_node_add / iran_peer_add
inbound_add            RUNNING → PASS   Shadowsocks inbound NNN
client_attach          RUNNING → PASS   Attached existing client navid to inbound NNN
managed_host_add or external_proxy
link_fetch             RUNNING → PASS   Panel link received
link_validate          PASS
runtime_validation     RUNNING → PASS
active                 PASS
```

### 2d. Prove no duplicate client was created

```bash
curl -s -H "Authorization: Bearer <PANEL_TOKEN>" \
  https://<panel>/panel/api/clients/get/navid | python3 -m json.tool
# "inboundIds" MUST contain the new inbound NNN, and navid must NOT have been re-created
```

The new inbound's decoded `settings.clients` MUST be `[]`. There must be no
`Duplicate email: navid` anywhere in the timeline. If it still appears, capture
`GET $HUB_URL/api/gre-routes/<ROUTE_ID>/events` plus the panel-side body of
`POST /panel/api/inbounds/add` with the password redacted — and do not work
around it.

### 2e. Reconcile

Click **Reconcile** on the row. The modal must list every component with `PASS`,
including `client_attachment = ATTACHED`, and print
`All expected components are present.`

### 2f. Delete the TEST route, prove navid survives

The delete dialog must state `3x-ui client "navid" — WILL NOT BE DELETED`.

```bash
curl -s -H "Authorization: Bearer <PANEL_TOKEN>" \
  https://<panel>/panel/api/clients/get/navid | python3 -m json.tool
# navid MUST still exist, with the route's inbound removed from inboundIds
```

Never delete a production route for testing.

---

## What to send back

1. The Phase 0 comparison table (deployed vs. v2.12.1 hashes) and `/api/meta`.
2. `systemctl is-active gre-hub` plus the first 30 journal lines.
3. The Phase 2c timeline text, including any FAIL row.
4. `GET /panel/api/clients/get/navid` before and after the test-route deletion.
5. Whether the produced configuration actually connects.
