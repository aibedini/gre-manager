# gre-manager v2.12.0 — deployment & real-panel verification runbook

This is the exact sequence for PHASE 0/1/2/19 of the v2.12.0 brief. Run it on the
machine that hosts the gre-hub dashboard. Copy/paste block by block and keep the
output: every step prints the evidence needed to prove what is actually running.

Set these once:

```bash
HUB_DIR=/opt/gre-hub
HUB_URL=http://127.0.0.1:3939          # change if PORT was overridden
PANEL=NetlenTRNew1                     # the saved 3x-ui panel to test with
CLIENT=navid                           # the EXISTING client
```

---

## PHASE 0 — prove what is running BEFORE you change anything

```bash
set -x
sudo systemctl status gre-hub --no-pager | head -20
sudo journalctl -u gre-hub -n 200 --no-pager | head -40
stat -c '%y  %s  %n' $HUB_DIR/public/app.js $HUB_DIR/server/xui.js \
                     $HUB_DIR/server/route-orchestrator.js $HUB_DIR/package.json 2>&1
cat $HUB_DIR/VERSION 2>/dev/null || echo "NO hub/VERSION (pre-2.12.0 deployment)"
cat $HUB_DIR/build-info.json 2>/dev/null || echo "NO build-info.json (pre-2.12.0 deployment)"
set +x
```

Hashes of the deployed runtime vs. the release vs. git main:

```bash
sha256sum $HUB_DIR/public/app.js $HUB_DIR/server/xui.js \
          $HUB_DIR/server/route-orchestrator.js $HUB_DIR/server/routes.js \
          $HUB_DIR/server/db.js $HUB_DIR/server/index.js 2>&1
```

Then compare against the same files extracted from the official v2.12.0 tarball:

```bash
TMP=$(mktemp -d)
cd "$TMP"
curl -fsSLO https://github.com/aibedini/gre-manager/releases/download/v2.12.0/gre-hub.tar.gz
curl -fsSLO https://github.com/aibedini/gre-manager/releases/download/v2.12.0/gre-hub.tar.gz.sha256
sha256sum -c gre-hub.tar.gz.sha256
tar xzf gre-hub.tar.gz
sha256sum hub/public/app.js hub/server/xui.js hub/server/route-orchestrator.js \
          hub/server/routes.js hub/server/db.js hub/server/index.js
cat hub/VERSION hub/build-info.json
echo "release tarball extracted at $TMP"
```

Build the comparison table:

```bash
for f in public/app.js server/xui.js server/route-orchestrator.js server/routes.js server/db.js server/index.js; do
  d=$(sha256sum "$HUB_DIR/$f" 2>/dev/null | cut -c1-12)
  r=$(sha256sum "$TMP/hub/$f" 2>/dev/null | cut -c1-12)
  m=$([ "$d" = "$r" ] && echo MATCH || echo DIFFERENT)
  printf '%-32s deployed=%s  v2.12.0=%s  %s\n' "$f" "${d:-missing}" "${r:-missing}" "$m"
done
```

**Interpretation**

| Symptom | Cause |
| --- | --- |
| `hub/VERSION` or `build-info.json` missing | (A) stale `/opt/gre-hub` — pre-2.12.0 files |
| files DIFFERENT but the service started long ago | (B) stale service process (old code in memory) plus (A) |
| files MATCH but the UI still shows old behaviour | (C) stale browser cache — hard-refresh (Ctrl/Cmd+Shift+R) |
| some files MATCH, others DIFFERENT | (E) mixed files from different releases |
| files and process both current, UI still wrong | (C) or a wrong release artifact (D) |

Also record what the service process actually loaded:

```bash
sudo systemctl show gre-hub -p ExecMainPID -p ActiveEnterTimestamp
sudo ls -l /proc/$(systemctl show -p ExecMainPID --value gre-hub)/cwd
```

---

## PHASE 1 — deploy v2.12.0 and prove it

Back up first (never delete these):

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sudo tar czf /root/gre-hub-data-$STAMP.tar.gz -C $HUB_DIR data
sudo cp /etc/systemd/system/gre-hub.service /root/gre-hub.service.$STAMP 2>/dev/null || true
sudo ls -la /root/gre-hub-data-$STAMP.tar.gz
ls -la /etc/systemd/system/gre-hub.service.d/ 2>/dev/null || true
```

Deploy through the updater (this is the path being shipped and tested):

```bash
sudo gre update            # CLI + hub to the same release
# or, hub only:
sudo gre hub update
```

If the installed CLI is too old to know `gre hub update`, install the released
CLI asset first and then use it:

```bash
sudo curl -fsSL -o /usr/local/sbin/gre \
  https://github.com/aibedini/gre-manager/releases/download/v2.12.0/gre
sudo curl -fsSL -o /tmp/gre.sha256 \
  https://github.com/aibedini/gre-manager/releases/download/v2.12.0/gre.sha256
# verify it names the `gre` file, then check it from /usr/local/sbin
(cd /usr/local/sbin && sudo sha256sum -c /tmp/gre.sha256)
sudo chmod +x /usr/local/sbin/gre
sudo gre hub update
```

Verify:

```bash
sudo systemctl daemon-reload
sudo systemctl restart gre-hub
sudo systemctl is-active gre-hub
sudo journalctl -u gre-hub -n 100 --no-pager | head -30
curl -s $HUB_URL/api/meta | python3 -m json.tool
cat $HUB_DIR/VERSION; cat $HUB_DIR/build-info.json
```

Expected in the journal:

```
gre-hub build: v2.12.0 · <shortsha> · version source: build-info.json
```

Expected from `/api/meta`: `"version": "2.12.0"`, `"commit"`, `"builtAt"`,
`"schemaVersion": 2`, and `"mixed": false`.

The UI top bar must read `v2.12.0 · <shortsha>` (hard-refresh the browser), and
Settings → Application must show the same values.

If the service does not come up, the updater has already restored the previous
build; check `journalctl -u gre-hub -n 200 --no-pager` and report it before
retrying.

---

## PHASE 2 / 19 — reproduce `navid` against the real panel

### 2a. Confirm what the hub believes about the panel

```bash
# force a fresh probe and read back the diagnostics
PANEL_ID=$(curl -s $HUB_URL/api/xui-panels | python3 -c "import sys,json;print([p['id'] for p in json.load(sys.stdin) if p['name']=='$PANEL'][0])")
curl -s -X POST $HUB_URL/api/xui-panels/$PANEL_ID/probe | python3 -m json.tool
```

Expect `panel_version` to be the real panel version (e.g. `3.8.x`),
`client_model: first_class`, `host_mode` either value, and no `error`.
Remember: `client_model` comes from `GET /panel/api/clients/list` returning 200,
never from the version number.

### 2b. Confirm the frontend sends the explicit contract

In the browser: DevTools → Network → **Create route** → click the
`/api/gre-routes` request → Payload. It MUST contain:

```json
{ "client_mode": "existing", "client_email": "navid", "...": "..." }
```

and MUST NOT contain `client_name`.

### 2c. Watch the timeline

The dialog turns into a live timeline. The expected order:

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

### 2d. Prove the inbound embedded NO client, and navid was attached

On the 3x-ui panel (or over its API), for inbound `NNN` from the timeline:

```bash
# decode the new inbound's settings.clients — for first_class + existing it MUST be []
curl -s -H "Authorization: Bearer <PANEL_TOKEN>" \
  https://<panel>/panel/api/clients/get/navid | python3 -m json.tool
# expect "inboundIds" to contain NNN
```

`settings.clients` for the new inbound must be `[]`; the only client
relationship is the attachment. `navid` must NOT have been re-created and there
must be no `Duplicate email: navid` anywhere in the timeline.

If `Duplicate email: navid` still appears, capture the exact request and report
it — do not work around it:

```bash
curl -s $HUB_URL/api/gre-routes/<ROUTE_ID>/events | python3 -m json.tool
```

and on the panel side, the decoded body of `POST /panel/api/inbounds/add`
(method, network, clients) with the password redacted. `clients` MUST be `[]`.

### 2e. Reconcile the new route

Click **Reconcile** on the route row. The modal must list every component with
`PASS`, including `client_attachment` = `ATTACHED`, and print
`All expected components are present.`

### 2f. Delete the TEST route and prove navid survives

Click **Delete** → the preview must state that
`3x-ui client "navid" — WILL NOT BE DELETED`.

After deleting:

```bash
curl -s -H "Authorization: Bearer <PANEL_TOKEN>" \
  https://<panel>/panel/api/clients/get/navid | python3 -m json.tool
# navid MUST still exist, with the route's inbound removed from inboundIds
```

Confirm in the 3x-ui UI that `navid` still exists. Do not delete a production
route for testing.

---

## What to send back

1. The Phase 0 comparison table (deployed vs. v2.12.0 hashes).
2. `curl -s $HUB_URL/api/meta` output.
3. `systemctl is-active gre-hub` and the first 30 journal lines.
4. The Phase 2c timeline text (all rows, including any FAIL).
5. `GET /panel/api/clients/get/navid` before and after the test-route deletion.
6. Whether the route's final configuration actually connects.

With those six items every claim in the release notes can be confirmed against
the real deployment instead of only against the test doubles.
