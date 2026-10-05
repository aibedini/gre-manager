# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.15.2] - 2026-10-05

### Fixed

- **The per-server API exposed probe health only under a nested `probe` key.**
  v2.15.1 returned `probe: { health, discovery }` but not the top-level `health`
  and `discovery` fields the interface is specified in terms of, so any client
  reading the documented shape saw both axes as *unknown* for every server — the
  same class of silent misreport this series of fixes exists to remove. The two
  endpoints now return the axes under **all three** keys:

  ```json
  {
    "snapshot": { "roles": ["FOREIGN"], "manager": { "version": "2.8.2" } },
    "health":    { "ok": true,  "checked_at": 0, "duration_ms": 1200, "error_class": null, "error": null, "reason": null },
    "discovery": { "ok": false, "checked_at": 0, "duration_ms": 15000, "error_class": "timeout",
                   "error": "gre status --json timed out after 15s", "reason": "SSH timeout" },
    "probe":     { "health": { }, "discovery": { } }
  }
  ```

  `health` and `discovery` are top-level for the current client, and the nested
  `probe` object carries the same values so a browser holding a cached v2.15.1
  `app.js` keeps working. Exposing only one of them silently blinds whoever is on
  the other side, which is exactly what happened here.
- `POST /api/servers/:id/discover` and `POST /api/servers/:id/health` now carry the
  same top-level `health`/`discovery` keys as the list endpoints, so the drawer
  updates both axes from the discover response itself instead of waiting for the
  next full reload. All probe responses go through one projection helper, so they
  cannot drift out of shape again.
- The server card tooltip showed the generic error class ("SSH timeout") where the
  specific cause was available. It now prefers `error` — the recorded cause such as
  `gre status --json timed out after 15s` — and falls back to the class label.

### Tests

- New `scripts/api-shape-test.js` (31 assertions). It boots a real gre-hub against
  a temp data dir, seeds a server whose last known topology is FOREIGN with
  transport healthy and discovery timed out, and asserts over HTTP that
  `GET /api/servers` and `GET /api/servers/:id` return the identical shape, that
  both carry the top-level axes as well as the nested ones, that the last known
  FOREIGN topology survives the failure, that the version is still reported, that
  `NO MANAGER` is not claimed, and that a server with no probe state reports `null`
  axes rather than `false` ones. It also asserts the rendered UI state is
  `group=foreign ssh=healthy discovery=failed`, and that no secret material appears
  in either payload. Verified in reverse: restoring the nested-only shape makes the
  suite fail on the missing top-level keys.

## [2.15.1] - 2026-10-05

### Fixed

- **The Server drawer rendered a blank Overview.** `renderOverview()` referenced an
  undefined `server` identifier while its local is `s`, so the function threw
  `ReferenceError: server is not defined` *before* assigning `el.innerHTML`. The
  whole Overview disappeared and every handler below it — including **Run
  discovery** — was never bound, because `innerHTML` was still empty when the
  bindings ran. The line now reads `s.probe`, and the function audits clean.
- **The drawer's Discover handler was incompatible with the v2.15 response
  envelope.** It still did `s.snapshot = <response>`, so a *failure* envelope would
  have been stored as the server's topology. Both the card and the drawer now go
  through one shared implementation (`hub/public/discovery-response.js`): a failure
  verdict never becomes a snapshot, a success adopts `data.snapshot`, and
  `state.servers` is kept in step.
- **`gre status --json` exit status was discarded**, so a status command that timed
  out, crashed or printed nothing still left every marker in place and the outer
  SSH session exiting 0 — and `classifyProbeResult()` then accepted it as a
  successful discovery with `roles: []`. That is how a server could show
  `v2.8.2` + healthy with no topology behind it. The probe now captures the status
  subcommand's exit code and its stderr into their own markers (stdout and stderr
  are captured into separate files first, so an interleaved stream cannot corrupt
  the JSON), sanitises the stderr, and classifies the outcome exactly:
  `status_rc=124` → `timeout`, non-zero → `remote` with the panel's own reason,
  empty or unparseable output → `malformed`. **A manager that is installed but
  whose state cannot be read is now an incomplete discovery that does not overwrite
  the authoritative snapshot**, rather than an authoritative empty one.
- **Transport health and discovery health shared one row**, so a lightweight health
  ping ten seconds after a failed discovery erased the discovery failure and the UI
  reported `HEALTHY` while topology was still unreadable. They are now separate
  columns (`health_*` and `discovery_*`) with an additive, non-destructive
  migration; a pre-split row is carried over into `discovery_*` once.
- **Health and full discovery could open two SSH sessions to the same server**,
  because the queue keyed full discovery on the server id and health on
  `health:<id>`. Both now key on the server id, full discovery takes priority, and a
  health probe for a server already being discovered is skipped rather than queued
  behind it.

### Added

- **Version/schema-compatible role extraction.** `gre status --json` has changed
  shape across the releases in production, so `extractRoles()` detects what is
  present instead of switching on a version number:
  `roles: [...]`, `role: "IRAN"|"both"|"dual"`, `mode: "iran"|"foreign"`,
  `node_role`, `is_iran`/`is_foreign`, and topology evidence (`iran_peers[]`,
  `nodes[]`, `foreign_ip`, `subnet_base`). The evidence used is recorded on the
  snapshot as `role_evidence`.
- `GET /api/servers` and `GET /api/servers/:id` now return the same shape:
  `snapshot` (last known good) plus `probe: { health: {...}, discovery: {...} }`.
  The drawer previously used a different shape than the card.
- The health summary reports topology, transport health and discovery health as
  three separate counts, so a header can no longer imply that reachable means
  healthy means correctly configured.
- `hub/public/discovery-response.js`, loaded before `app.js` and required directly
  by the tests, so the card and the drawer cannot drift apart again.

### Changed

- Server cards show `SSH HEALTHY` / `SSH UNREACHABLE` and
  `DISCOVERY OK` / `DISCOVERY FAILED` as two separate badges, plus
  `NEEDS DISCOVERY` when the transport is fine but no successful discovery has read
  the roles yet. The health dot now reflects reachability and marks
  "reachable but topology unread" as attention-needed rather than an outage.
- A server with no snapshot shows **TOPOLOGY UNKNOWN** with the reason, instead of a
  bare `UNKNOWN`. `NO MANAGER` is only ever shown when a full discovery genuinely
  completed and found `gre` absent.

### Tests

- New `scripts/overview-test.js` (20 assertions) which **executes the real
  `renderOverview()`** against a minimal DOM shim and asserts that the toolbar,
  the SSH section, the probe banner and the failure reason all render, and that the
  panel is never left empty. It also covers the discovery response matrix, the
  `gre status` outcomes, older status schemas, the health/discovery separation, the
  single-SSH-operation guarantee, and role recovery after a successful
  rediscovery. The execution check was verified in reverse: reintroducing the
  original `server.probe` line makes this suite fail with exactly
  `server is not defined`.
- `scripts/discovery-semantics-test.js` grew to 22 assertions with the new
  status-outcome cases.
- An early attempt at a generic "undefined identifier" audit was **discarded**: it
  flagged English prose inside rendered HTML ("probe this server.") and missed the
  real bug because `server` legitimately appears as a parameter name elsewhere in
  the file. Executing the function is the reliable check.

## [2.15.0] - 2026-10-03

### Fixed

- **A transient SSH/probe failure could erase a server's topology and drop it into
  UNCONFIGURED.** Production showed many servers suddenly leaving the IRAN/FOREIGN
  groups while `PROBE FAILED` badges appeared, with auto refresh running every 10
  seconds. The chain was: `discovery.discover()` returned an error-shaped snapshot
  with `roles: []`, `POST /api/servers/:id/discover` called `saveSnapshot()`
  unconditionally, and the frontend's `roleGroup()` derived UNCONFIGURED from the
  now-empty roles. A hub that could not reach a server concluded that the server
  had no role — an availability failure silently became a topology fact.

  Availability and topology are now separate axes, and only the second can change a
  server's group:
  - A new `server_probe_state` table records probe health (`ok`, `checked_at`,
    `duration_ms`, `error_class`, `error_message`, `kind`). It is additive: the
    existing `snapshots` blob is never rewritten by a failure, and no existing row
    is touched.
  - `discovery.classifyProbeResult()` classifies an outcome as SUCCESS or as one of
    `timeout`, `auth`, `refused`, `hostkey`, `transport`, `malformed`, `remote`,
    `nocreds`. Only SUCCESS may replace the authoritative snapshot, and
    `runFullDiscovery()` is the single call site that writes it — a failure path has
    no way to reach it.
  - **A completed probe that finds no manager is still a SUCCESS**, and may
    legitimately produce empty roles. "The manager is not installed" and "the hub
    could not reach the server" are now different answers.
  - A truncated probe (a timeout mid-script that emitted one section) is classified
    `malformed` instead of being parsed into an empty-role state.
  - `GET /api/servers` returns `snapshot` (last known good, or null only if no
    discovery ever succeeded) alongside `probe { ok, checked_at, reason, error,
    error_class, stale_for_ms, kind }`.
  - Probe error messages are sanitised before storage or display: passwords,
    `user:pass@host` forms, tokens, bearer headers, share links and PEM blocks are
    redacted.

### Added

- **Bounded discovery concurrency with per-server coalescing**
  (`hub/server/discovery-queue.js`). Every automated probe now goes through one
  queue with `HUB_DISCOVERY_CONCURRENCY` (default 4, clamped to 32), and a second
  request for a server already being discovered joins that run instead of opening
  another SSH session. Previously auto refresh fired a full discovery at every
  server at once, so 30 servers meant 30 concurrent sessions every 10 seconds — a
  thundering herd that manufactured the very transient failures that wiped topology.
- **Two-level auto refresh.** A lightweight availability probe
  (`POST /api/servers/:id/health`, and `POST /api/servers/health` for all of them)
  runs on a 15s cadence; full discovery is reserved for the Discover button,
  post-action refreshes, a 6-minute cadence, and the recovery path. The lightweight
  probe runs `echo hub-health-ok` and collects no topology, so it is cheap enough to
  run often.
- **`GET /api/servers/health-summary`** reporting topology and probe health
  separately, plus staleness and live queue state:
  `{ total, authoritative: { iran, foreign, dual, unconfigured }, probe: { healthy,
  failed, unknown }, stale_snapshots, discovery: { in_flight, queued, concurrency,
  peak }, concurrency }`. No secrets.
- **`POST /api/servers/rediscover-unconfigured`**: a bounded recovery path for the
  servers already stuck at UNCONFIGURED. It re-probes only candidates whose
  snapshot looks like a failed probe or a confirmed absence, through the same
  bounded queue, and never infers a role from a name or an IP — only a real
  successful discovery restores one.
- **`hub/public/server-topology.js`**, loaded before `app.js` and required directly
  by the tests, so the rule that decides a server's group has exactly one
  implementation rather than two copies that can drift apart again.

### Changed

- Server cards show topology and probe health separately: the group badges come from
  the authoritative snapshot while a distinct line shows `HEALTHY` / `PROBE FAILED`
  / `PROBE UNKNOWN`, when the snapshot was last verified, a `SNAPSHOT STALE` marker
  once it is older than 6 hours, and the sanitised failure reason as a tooltip.
  The health dot follows probe availability.
- The server drawer shows a probe-failure banner **above** the last known good
  data instead of replacing it, and says explicitly that the topology below is the
  last verified state. A server that has never been discovered successfully is
  reported as having an unknown role.
- Auto-refresh status now reads `health 15s · full <age>` so the two cadences are
  visible.

### Tests

- New `scripts/discovery-semantics-test.js` (17 assertions): every failure class is
  a failure and never a state; a truncated or empty probe is `malformed` rather than
  "no manager"; a completed probe with no manager is still a SUCCESS; a
  `status_json` parse error keeps the probe successful; error sanitisation;
  retryability policy per class (a pinned host key is never retried into
  acceptance); and the legacy `discover()` snapshot shape is preserved.
- New `scripts/topology-test.js` (12 assertions) covering the ten required cases
  plus the acceptance simulation: **27 servers, round 1 all healthy (6 IRAN /
  21 FOREIGN), round 2 with 17 transient SSH failures, final grouping stays 6 IRAN
  / 21 FOREIGN with 17 failed probes and zero UNCONFIGURED**; concurrency never
  exceeds the bound; a repeated request opens one session; stale-but-good snapshots
  keep their role; and `HUB_DISCOVERY_CONCURRENCY` parsing and clamping.

## [2.14.0] - 2026-10-03

Three production issues solved together, plus the client picker rework that was
started in the same branch.

### Fixed

- **`runtime_validation` could hang for 45 seconds and then fail with no usable
  detail.** In production a fully successful route —
  `client_preflight`, `port_check`, both connectivity checks, `gre_pairing`,
  `foreign_node_add`, `iran_peer_add`, `inbound_add`, `client_attach`,
  `managed_host_add`, `link_fetch` and `link_validate` all PASS — died at
  `runtime_validation` with `The operation was aborted due to timeout`, and the
  rollback then removed a working tunnel. The cause was a single opaque promise
  that called the heavyweight `/panel/api/inbounds/list` inventory (which
  serializes every inbound's full settings blob) while sequentially chaining
  several SSH reads, so one slow subsystem consumed the whole request budget.
  It is now a set of small, independently timed checks:

  | Stage | What it proves | Timeout |
  | --- | --- | --- |
  | `runtime_gre_iran` | IRAN `gre-<peer>` link exists and is UP | 10s |
  | `runtime_gre_foreign` | FOREIGN `gre-<peer>` link exists and is UP | 10s |
  | `runtime_iran_tcp_rule` | IRAN forwarding rule for the port | 10s |
  | `runtime_iran_udp_rule` | IRAN UDP forwarding rule for the port | 10s |
  | `runtime_foreign_tcp_listener` | something listens on `:port` | 10s |
  | `runtime_foreign_udp_listener` | UDP listener on `:port` | 10s |
  | `runtime_xui_inbound` | inbound detail for the route's inbound id | 10s |
  | `runtime_xui_client` | the client appears in that inbound's `settings.clients[]` | 0s |
  | `runtime_managed_host` | managed host present (metadata-only) | 10s |
  | `runtime_e2e_tcp` | TCP connect to the IRAN public endpoint | 5s |
  | `runtime_validation` | summary of all of the above | — |

  Each emits its own `RUNNING` then `PASS`/`FAIL`, all independent checks run in
  parallel via `allSettled` so one slow probe cannot cancel a sibling, and the
  failure names the exact component:
  `Runtime validation failed at IRAN TCP forwarding rule: no IRAN forwarding rule
  for 3001`. The old opaque timeout string is gone.
- **Runtime validation no longer touches any heavyweight panel endpoint.** The
  only panel read is `GET /panel/api/inbounds/get/<inboundId>`; client membership
  is answered from that same response, so `/inbounds/list`, `/clients/list`,
  `/clients/links` and a post-attach `/clients/get` are all avoided.
- **Duplicate pre-provision work removed.** `run()` re-detected public IPs and
  re-ran bidirectional ping reachability even though the live preflight had just
  proved both. Those `public_ip`/`connectivity` stages are gone; the preflight
  owns public-path availability and runtime owns GRE/forwarding/listener/inbound.
- **Delete is now idempotent.** Production hit a 409 on a route whose rollback had
  already removed everything: Delete re-issued the removals, the GRE CLI answered
  `Peer 'ir01' does not exist`, and the whole delete failed. Deletion's desired end
  state is "resource absent", so each component is inspected first and an
  already-absent resource is reported `ALREADY_ABSENT` as a **success**. A delete
  that races and returns "not found" is tolerated the same way; only a genuine
  error is a failure. The response is structured:
  `{ ok, deleted, components: [{ name, previous, result, detail }], failures }`.
  The globally existing client is still never deleted — only this route's
  attachment is removed, and a route-created client that other inbounds still use
  is detached and explicitly preserved.
- **`rollback` no longer logs `[object Object]`.** Panel helpers return envelopes,
  and interpolating one produced `client navid attachment removed: [object Object]`.
  Results are now described safely, rollback steps report the exact stage
  (`rollback_client_detach`, `rollback_inbound`, `rollback_iran_peer`,
  `rollback_foreign_node`), and a resource that is already gone is a PASS.
- **The route configuration is permanently retrievable.** `link_fetch` used to
  produce a share link that only lived in the process-memory `routeResults` map,
  so Copy Config stopped working after a hub restart. The effective configuration
  is now persisted **encrypted** on the route row (`share_link_enc`,
  `outbound_enc`, `config_updated_at`, plus `iran_endpoint`) and revealed through
  a dedicated authenticated endpoint. An ACTIVE route from an earlier release that
  has an encrypted credential but no stored link is reconstructed locally from
  method + credential + IRAN endpoint + port and then persisted — no 3x-ui call and
  never an invented credential. A FAILED route exposes nothing, and only an ACTIVE
  route may reveal a configuration.

### Added

- `GET /api/gre-routes/:id/config` (ACTIVE only, `Cache-Control: no-store`):
  returns `{ route_id, name, status, link, outbound, endpoint: { host, port } }`.
  Never included in the route list, never in the timeline, never in logs, and the
  reveal is audited as `route_config_reveal` with the route id and name only —
  never the secret.
- A **Config** action on every ACTIVE route row, with Reveal, Copy config,
  Copy JSON and Show QR. Copying never contacts 3x-ui, never re-creates the client
  and never changes the password. Non-ACTIVE routes show a disabled action with
  "No active configuration — provisioning did not complete."
- Shared read-only inspection primitives (`hub/server/route-inspection.js`),
  now the single implementation of "what does the world actually look like":
  `inspectGreInterface`, `inspectForwarding`, `inspectListeners`, `inspectInbound`,
  `clientInInbound`, `inspectClientAttachment`, `inspectManagedHost`,
  `inspectPortAllocation`, `probeTcpConnect`. Runtime validation, reconcile and
  delete all use them, so the same question can no longer get two different
  answers depending on which code path asks. Reconcile's own `grep -q` GRE probe
  was replaced by the shared one.
- A persisted, secret-free per-component validation summary
  (`gre_routes.runtime_checks`), e.g.
  `{"gre_iran":"PASS","xui_inbound":"PASS","e2e_tcp":"PASS",...}`, so the UI and
  Reconcile can show what was actually verified.

### Changed

- The 202 create response now includes the panel's cached `client_model`
  (and `panel_client_model`/`panel_version`), so the timeline header reads
  `First-class / multi-inbound` from the first render instead of `unknown` — the
  hub already knows the value from its last probe.
- The client picker no longer downloads the panel inventory. It seeds one page
  (`?paged=1&pageSize=20`), searches through the panel's paged endpoint with a
  250 ms debounce, aborts a superseded request, and drops an out-of-order
  response. Opening Create Route renders the cached panel model immediately,
  starts the client page and the port check **in parallel**, and never blocks the
  form.
- `listFirstClassClients()` no longer calls `/panel/api/inbounds/list`; inbound
  remarks come from the lightweight metadata projection, and the paged path does
  not fetch them at all.
- The event secret scrubber now covers share links (`ss://`, `vmess://`,
  `vless://`, `trojan://`), `password`/`passwd`/`secret`/`privateKey` in prose and
  JSON, `Authorization: Bearer`, cookies, CSRF tokens, session tokens and PEM
  private-key blocks — while deliberately preserving route name, client email,
  inbound id, IP, port, stage and panel version.

### Tests

- New `scripts/v214-test.js` (12 assertions): every runtime sub-stage exists and
  announces RUNNING then PASS; runtime validation issues no heavyweight panel
  call; a missing forwarding rule and an unreachable endpoint each fail at their
  own named stage with a `RuntimeValidationError`; the persisted summary is
  per-component and secret-free; a cleanly rolled-back route deletes successfully
  with `ALREADY_ABSENT` components; a route-exclusive client may be deleted while
  a shared one is preserved; an ACTIVE route exposes a valid config pointing at
  the IRAN endpoint; **the config survives a hub restart with identical output and
  zero panel calls**; a FAILED route exposes no config; and the inspection
  primitives recognise already-absent errors while every check keeps its own
  bounded timeout.
- New `scripts/redaction-test.js` (18 assertions): 15 secret shapes are proven to
  be scrubbed, operational facts are proven to survive, `event()` is proven to
  sanitise on the way in, and empty/non-string input cannot throw.
- `_harness.js` needed three small extensions to model the new probes: an
  end-to-end TCP branch, a `MISSING` answer for a removed GRE peer, and a DOWN
  link instead of a non-zero rc so a not-UP tunnel is distinguishable from a
  broken probe.

## [2.13.5] - 2026-10-03

### Fixed

- **The post-attach credential read could also block until the 45s timeout.**
  v2.13.4 correctly removed the slow `/panel/api/clients/links/:email`
  enumeration, but its replacement — a post-attach
  `GET /panel/api/clients/get/:email` — proved to be just as slow on a real
  3x-ui v3.7.0 panel. Route provisioning failed at the last step with:
  `3x-ui could not read the first-class client 'navid' after attachment:
  The operation was aborted due to timeout`, after `client_preflight`,
  `inbound_add`, `client_attach` and `managed_host_add` had all already passed.
  The client-detail endpoint builds attachment, traffic and tunnel metadata, so
  asking for it again while the panel is busy is the wrong source for a
  credential we have already read once.

### Changed

- For an existing first-class client, the credential is now captured during the
  **already-successful pre-mutation `client_preflight`** read of
  `GET /panel/api/clients/get/:email`. It is held in memory on the reused
  `XuiClient` instance (a non-enumerable symbol-keyed map, never persisted) and
  consumed exactly once by `link_fetch` after `client_attach`.
- Normal live route provisioning therefore performs **no credential-related
  3x-ui request at all after `client_attach`**: zero post-attach
  `/panel/api/clients/get/:email` and zero `/panel/api/clients/links/:email`.
  `link_fetch` completes immediately instead of waiting on the panel.
- The cache is one-shot and time-bounded (2 minutes): a stale entry from an
  earlier attempt can never donate a password, and each preflight read clears any
  previous value before storing a new one.
- If the preflight credential is unavailable (legacy preflight mode, or an empty
  global password), the **only** fallback is
  `GET /panel/api/inbounds/get/<new inbound id>`, extracting the password from
  `settings.clients[]` for exactly the inbound this route just created. That read
  is bounded to one inbound. It still never falls back to `/clients/get` or
  `/clients/links` after attach.
- The fallback validates that the inbound is Shadowsocks and that the attached
  client's method matches the route before accepting its password, so a wrong or
  partial read fails loudly instead of producing a link that cannot connect.
- A route that created its own client still rebuilds the link from the credential
  it owns, with no panel round trip.
- Embedded/legacy panels are unchanged and keep the per-inbound panel-link path,
  because there the credential source already is the inbound settings object.
- No credential and no complete `ss://` link is ever written to `route_events`;
  the persisted timeline carries only the source-neutral wording.
- The existing global client is never recreated, never deleted and its password
  is never changed: this path only reads and reuses what the panel already has.

### Tests

- `scripts/credential-fastpath-test.js` grew to 31 assertions and now pins the
  whole matrix: exactly one `/clients/get` read (the preflight one), **zero**
  post-attach panel requests when the preflight credential was captured, the
  real password preserved byte-for-byte into the rebuilt link, the
  `/panel/api/inbounds/get/:id` fallback issuing exactly one bounded read and no
  `/clients/get`, a missing credential failing loudly instead of hanging, the
  route-owned and embedded paths unchanged, and the timeline wording.
- `scripts/_xui-mock.js` models the single-inbound detail endpoint so the
  fallback is exercised against a realistic panel rather than a stub that cannot
  answer it.

## [2.13.4] - 2026-10-03

### Fixed

- **`link_fetch` could hang until it timed out when reusing an existing
  first-class 3x-ui client**, failing the route with
  `3x-ui did not return a Shadowsocks link for the existing client 'navid' ...
  The operation was aborted due to timeout`. 3x-ui v3.1+ stores first-class
  client credentials in a global client row, and
  `GET /panel/api/clients/links/:email` expands links across **every** inbound
  that client is attached to. On a panel where the client is attached to many
  inbounds — the normal situation for a long-lived identity such as `navid` —
  that enumeration is slow enough to exhaust the request budget, and the previous
  code retried it twice with 500ms/1500ms backoff before giving up.
- Route provisioning no longer calls `/panel/api/clients/links/:email` for an
  existing first-class client. It reads the authoritative record from
  `GET /panel/api/clients/get/:email` instead, which is a single cheap lookup and
  contains the exact password 3x-ui copied into the newly created Shadowsocks
  inbound during attach. Embedded/legacy panels keep using the original
  panel-issued link path, because there the credential source really is the
  inbound settings object.
- A route that created its own client still rebuilds the link from the credential
  it owns, with no panel round trip at all.
- If a first-class client record has no password, provisioning now fails
  immediately with an explicit message instead of falling through to the slow
  link enumeration and timing out.
- The `link_fetch` / `link_validate` timeline text is source-neutral, so it no
  longer claims a panel-issued link was fetched when the credential actually came
  from the first-class client record:
  - `RUNNING link_fetch` → `Resolving Shadowsocks credential and share link for navid`
  - `PASS link_fetch` → `Client credential resolved; share link ready`
  - `PASS link_validate` → `Endpoint, method and client credential validated`

### Tests

- New `scripts/credential-fastpath-test.js` (21 assertions) pins the behaviour:
  exactly one `/clients/get` call, **zero** `/clients/links` calls, the slow
  legacy resolver bypassed, the existing password preserved byte-for-byte into
  the rebuilt link, the link method/host/port matching the new route, the
  embedded and legacy paths unchanged, and the new timeline wording.

## [2.13.3] - 2026-10-03

### Fixed

- Auto Route now prefers the fast `/panel/api/inbounds/list/slim` inventory on
  3x-ui v3.7 panels where `/panel/api/inbounds/options` exists but can stall.
- A timeout from one lightweight inbound-port endpoint now advances to the next
  compatible endpoint instead of failing the entire route immediately.
- Provisioning still stops safely when every lightweight and legacy inventory
  endpoint fails, preserving collision protection before GRE changes begin.

## [2.13.2] - 2026-10-03

### Fixed

- **A successful `npm ci` is no longer treated as proof of a working hub.** The
  hub cannot start without a compiled `better-sqlite3` binding, and npm reports a
  fully successful install even when it silently skipped that build — whether it
  does so depends on the npm version and on `allow-scripts` / `ignore-scripts`
  settings the installer does not control. The updater now loads
  `better-sqlite3` in the staged directory before swapping it in, attempts
  `npm rebuild` and a toolchain install on failure, and if the driver still
  cannot load it **refuses the deployment and leaves the working installation
  untouched**, with the exact repair commands. Previously this surfaced as an
  opaque `Could not locate the bindings file` crash after the service had already
  been replaced.

## [2.13.1] - 2026-10-03

### Fixed

- Auto Route `port_check` no longer uses the heavyweight 3x-ui full inbound list
  on modern panels, which could spend tens of seconds serializing traffic and
  client payloads and made the port safety scan exceed its timeout on panels with
  a large client population.
- Use `/panel/api/inbounds/options` first.
- Fall back to `/panel/api/inbounds/list/slim` where supported.
- Full `/panel/api/inbounds/list` is legacy fallback only.
- Split port safety diagnostics into:
  `port_check_iran`, `port_check_foreign`, `port_check_xui`.
- 3x-ui inbound-port query has a bounded timeout
  (`HUB_PORT_XUI_TIMEOUT_MS`, default 12s), separate from the 20s host inventory
  timeout (`HUB_PORT_SSH_TIMEOUT_MS`), and the previous client timeout is restored
  afterwards so the provisioning run keeps its own budget.
- Exact failing subsystem is now shown in the route timeline.
- No GRE mutation may start if any port safety check fails.

## [2.13.0] - 2026-10-03

Adds the live Auto Route preflight timeline contributed upstream in
`4cd1ba7`, on top of everything in v2.12.2.

### Added

- **Route creation now answers before any network work happens.** The old
  synchronous preflight probed 3x-ui and both servers *before* the request
  returned, so the Create Route dialog could only show a static `Creating…`
  until everything finished. `prepare()` now validates, reserves the port
  locally and returns the route id immediately; every slow step then runs as a
  persisted timeline stage that the modal streams live:
  - `panel_probe` — 3x-ui capability probe, with the panel version, now on a 45s
    timeout (`HUB_XUI_TIMEOUT_MS`) because slow panels previously surfaced as an
    opaque browser `AbortError`
  - `client_preflight` — the selected client is validated against the panel
  - `port_check` — full remote safety scan of the reserved port
    (listeners/nftables/iptables/Docker/3x-ui/registry); if it turns out to be
    occupied the reservation is moved to a free port instead of failing
  - `public_ip_preflight` — resolves both public IPv4 addresses
  - `connectivity_iran_to_foreign` / `connectivity_foreign_to_iran` — explicit
    **per-direction** reachability checks, replacing the single combined check
    that could not say which side was blocked
  - `connectivity_preflight` — persisted summary of both directions
- Failures now name the stage and the timeout, e.g.
  `3x-ui client preflight timed out after 45s: The operation was aborted`, and
  each preflight stage emits `RUNNING` before its `PASS`/`FAIL`.
- The in-flight 3x-ui client is reused for a short window so the background
  provisioning run inherits the capability result and timeout from the probe.

### Changed

- Client-selection validation now happens **after** the route row is reserved
  rather than before the request returns. A bad selection therefore no longer
  comes back as an immediate `409`; it is accepted as `202` and then fails at
  `client_preflight` on the timeline. The guarantee that matters is unchanged and
  is now covered by a test: the failure happens **before** any inbound, GRE node
  or GRE peer is created, so no remote mutation is made for a mistake in the
  client picker. The Create Route dialog surfaces it as `Failed at
  client_preflight`.
- Legacy mode is still available with `HUB_ROUTE_PREFLIGHT_MODE=legacy` for the
  synchronous integration fixture; production defaults to live preflight.

### Tests

- The upstream `live-preflight-test.js` (22 assertions) covers the new stages
  against a stub class.
- The HTTP events suite now runs in **both** modes: live (production default)
  with 26 assertions and legacy with 24, including the assertion that a rejected
  client selection reaches no `foreign_node_add`, `iran_peer_add`,
  `inbound_add`, `client_attach`, `client_create` or `managed_host_add` stage.
  The upstream commit had removed this suite from `npm test` entirely; both modes
  are wired back in.

## [2.12.2] - 2026-10-02

### Fixed

- The provisioning timeline no longer drops the `Attempt #1` header. Attempt
  separators are tracked across incremental renders in a module-level counter
  that was never reset per modal, so opening a route at attempt 1 after viewing
  one at attempt 2 silently omitted the separator. Both entry points (the create
  dialog and the row's Timeline action) now reset it, and the create/retry path
  seeds it so a retried route shows its attempt boundaries correctly.

Everything below (the updater rewrite, build identity, panel diagnostics, the
provisioning timeline, reconcile and the route lifecycle controls) plus the
native-module install policy first shipped in v2.12.1 with no other functional
changes here.

## [2.12.1] - 2026-10-02

### Fixed

- **A fresh v2.12.0 hub installation could not start.** `better-sqlite3` is a
  native module, and recent npm versions (11+) refuse to run dependency install
  scripts unless the package explicitly allows them — silently. `npm ci`
  reported success, installed no compiled binding, and the hub then exited at
  startup with `Could not locate the bindings file`, so its database could never
  be opened. The v2.12.0 `gre-hub.tar.gz` shipped no install policy at all.
  The package now ships `hub/.npmrc` with `allow-scripts=true`, which is the
  documented npm setting for this.
- The installer no longer passes `--allow-scripts` on the npm command line: npm
  11 rejects it for project-scoped installs with `EALLOWSCRIPTS`, which would
  have converted a silent failure into a hard one.

### Changed

- `hub_npm_ci` warns when the installed package has no `.npmrc` (so an older
  package cannot fail silently), installs a build toolchain and retries, and as
  a last resort installs with `--ignore-scripts` and then rebuilds the native
  modules explicitly instead of leaving the hub unable to open its database.
- The release job now asserts that `gre-hub.tar.gz` contains `hub/.npmrc` with
  `allow-scripts=true`, plus `hub/server/version.js`, `routes.js`, `db.js` and
  the public assets, so an uninstallable package can never be published again.
- Regression tests on both layers: `scripts/version-test.js` checks the packaged
  file and that no `.gitignore` excludes it, and `tests/run.sh` builds a tarball
  the way the release job does and asserts its contents.
- The CLI fixture version in `tests/run.sh` is now derived from the script
  instead of hardcoded, so a version bump can no longer silently turn that
  regression test into a no-op.

Everything below (the updater rewrite, build identity, panel diagnostics, the
provisioning timeline, reconcile and the route lifecycle controls) first shipped
in v2.12.0 with no functional changes here.

## [2.12.0] - 2026-10-02

> **Do not install this release's `gre-hub.tar.gz`.** It ships without
> `hub/.npmrc`, so on a host whose npm refuses dependency install scripts by
> default the hub installs "successfully" and then cannot start. Use v2.12.1,
> which contains every change below plus the fix.

### Fixed

- `gre update` and hub installation can no longer leave the CLI and gre-hub on
  different releases. Hub installation used to try `v${VERSION}/gre-hub.tar.gz`
  **before** asking GitHub for the latest release, so an outdated installed CLI
  could reinstall a hub package matching its own old version even when a newer
  release existed — and the last fallback was the raw `main` tarball, which
  bypassed checksum verification entirely. The updater now resolves the release
  tag first, verifies `gre-hub.tar.gz.sha256` (and refuses a checksum file that
  does not name the tarball), and never falls back to `main` or
  `raw.githubusercontent.com`.
- Hub deployment is now atomic and self-recovering: the package is staged and
  its dependencies installed in a temporary directory, the previous build is
  snapshotted, the service is restarted, the running version is verified through
  `/api/meta`, and a hub that fails to start or reports the wrong version is
  rolled back automatically. `/opt/gre-hub/data` (`hub.db`, `master.key`, SSH
  keys) is never touched by the swap.
- Reconcile no longer marks a cleanly rolled back `FAILED` route as
  `NEEDS_REVIEW`. Its expected state is "everything this route owned is gone", so
  absence is success: the response now reports `cleanup_complete: true` and an
  empty `leftovers` list, and only genuine surviving resources escalate a route.
  Reconcile also never judges or destroys a `STALE` route: it performs read-only
  discovery and says so.
- The installed Hub version can no longer disagree with the released one
  silently: `VERSION`, `gre-manager.sh`, `hub/package.json`,
  `hub/package-lock.json` and `hub/VERSION` are asserted equal in CI and in the
  release job, and the release tag itself must match.

### Added

- `gre hub update` — always installs the newest stable release, independent of
  the CLI's own version. `gre hub install [TAG]` still works and an explicit tag
  remains the way to pin a release. `gre hub status` now prints both the
  installed and the running hub version and warns when they disagree. Every
  update ends with an unambiguous summary:
  `gre-manager: vX.Y.Z` / `gre-hub: vX.Y.Z` / `release: vX.Y.Z`.
- `GET /api/meta` (no session required) and a permanent build stamp in the UI
  top bar (`gre-hub v2.12.0 · abcdef1`, with a tooltip listing every version
  source and whether they agree) plus an Application panel in Settings showing
  version, version source, build commit, build time, release tag, Node and DB
  schema. The startup log line also names the running build, so a stale
  deployment is visible in `journalctl` immediately.
- The release workflow now ships `hub/VERSION` and `hub/build-info.json`
  (version, full commit, short commit, UTC build time, tag) inside
  `gre-hub.tar.gz`, verifies both are present and consistent, and strips test-only
  files from the runtime package. `GET /api/meta` resolves the version in a
  documented order: `build-info.json` → `hub/VERSION` → `../VERSION` →
  `package.json`, and flags a mixed deployment when sources disagree.
- Exact 3x-ui version detection as **diagnostic metadata only**
  (`XuiClient.detectPanelVersion()`): `/panel/api/server/getPanelUpdateInfo`
  first, then a conservative scan of the authenticated panel HTML. It never
  reports the Xray-core version as the panel version and resolves to `null` when
  ambiguous. Capability detection remains API-driven (`/clients/list`,
  `/hosts/list`) and never consults a version number.
- Panel diagnostics are persisted in `xui_panels` (`panel_version`,
  `panel_version_source`, `client_model`, `host_mode`, `last_probe_at`,
  `last_probe_error`) with `POST /api/xui-panels/:id/probe` for a manual refresh
  and an automatic background refresh when metadata is older than 10 minutes.
  The panel table shows `3x-ui vX.Y.Z`, the client model, the host model and when
  it was last checked — and keeps showing the last known-good values (with the
  error alongside) when a probe fails, instead of reverting to
  "detected on next save".
- The Create Route dialog shows the selected panel's 3x-ui version, client model
  and host model before anything is created, with explicit helper copy for
  existing versus new clients and for the legacy embedded model.
- Every mutable or slow provisioning step now emits `RUNNING` before its
  `PASS`/`FAIL` (`panel_probe`, `public_ip`, `connectivity`, `gre_pairing`,
  `foreign_node_add`, `iran_peer_add`, `inbound_add`, `client_attach`,
  `client_create`, `managed_host_add`, `link_fetch`, `runtime_validation`), the
  route records its `current_stage`, and a failure reports the exact step:
  `Failed at inbound_add: Duplicate email: navid`. The timeline's failure card
  now shows **Failed at / Reason / Attempt** instead of one generic `failed`.
- Component-level Reconcile with a proper result modal. An `ACTIVE` route is
  checked component by component (registry, IRAN peer and forwarding, FOREIGN
  listeners, GRE link state, inbound presence/port/protocol, client existence and
  attachment, managed host or `externalProxy`) and rendered as a
  Component / Expected / Actual / Result / Detail table.
- `PATCH /api/gre-routes/:id` edits a route's **desired specification** without
  provisioning anything. Servers, panel, port, method and client are refused
  while a route is `ACTIVE` (with the locked fields named in the response); a
  rename is always allowed.
- `POST /api/gre-routes/:id/retry` re-runs provisioning for a route that is not
  `ACTIVE`. It reconciles first and refuses to start when the previous attempt
  left resources behind, increments `attempt_no`, and preserves every earlier
  event — `route_events.attempt_no` plus attempt separators in the timeline keep
  each run distinguishable.
- `GET /api/gre-routes/:id/delete-preview` and `DELETE /api/gre-routes/:id`.
  Delete removes only the resources the route owns, in a safe order (client
  relationship → managed host → inbound → IRAN peer → FOREIGN node → port
  allocation), then soft-deletes the row (`deleted_at`) while keeping the event
  history. A pre-existing client is only ever detached — never deleted globally —
  and a route-created client is preserved (detached instead) when another inbound
  still uses it. The preview dialog states plainly what will be removed and that
  the existing client **WILL NOT BE DELETED**. Any cleanup failure leaves the
  route visible as `NEEDS_REVIEW` with the exact failures recorded.
- Ownership metadata is persisted so those operations are possible after a
  restart: `peer_name`, `host_group_id`, `client_created_by_route`,
  `client_attached_by_route`, `rollback_state`, `attempt_no`, `deleted_at`,
  `current_stage`, `panel_version_snapshot` and `host_mode`.

### Changed

- `gre_routes` and `xui_panels` gained the columns above and `route_events`
  gained `attempt_no`; existing v2.10.0/v2.11.0 databases migrate in place with
  `ALTER TABLE … CHECK (…)`, keeping every route, allocation and event row.
- The smoke/CI pipeline now runs the hub suite, and CI asserts that all five
  version sources agree.

## [2.11.0] - 2026-10-02

### Fixed

- Auto routes no longer re-creates a 3x-ui client the panel already owns. The
  route form now sends an explicit `client_mode` (`existing` / `new`) instead of
  collapsing both cases into one `client_name` string, and an existing
  first-class client is **attached** to the new inbound instead of being embedded
  in `settings.clients`, which is what produced `Duplicate email: navid` on
  3x-ui v3.1.0 and newer.
- 3x-ui client-model detection is a capability probe, never a version guess:
  `GET /panel/api/clients/list` decides `first_class` (HTTP 200) versus
  `embedded` (404/405). 3x-ui v3.0.2 still uses the legacy inbound-centric
  model, so a `major >= 3` test would be wrong; 401/403, 5xx and timeouts are
  surfaced as auth/panel failures instead of silently classifying the panel as
  legacy. Host mode (`managed_hosts` / `external_proxy`) remains an independent
  axis and is stored and logged separately as `client=…; hosts=…`.
- The share link for a reused client is taken from the panel-issued `ss://` link
  and validated against the expected endpoint, port and cipher, so the real
  existing credential is preserved. A credential is only ever rebuilt locally
  for a client that this route itself created; otherwise provisioning fails
  clearly instead of returning a link that cannot authenticate.
- Rollback is ownership-scoped: a pre-existing client is detached from the newly
  created inbound only, a route-created client is deleted explicitly, and an
  existing client is never deleted globally. One failing rollback stage no
  longer prevents the remaining cleanup stages from running.

### Added

- `POST /api/gre-routes` is now an async job: it validates the request, runs the
  read-only client preflight, reserves the port and the route row, then answers
  **202** with `{ route_id, status: "RESERVED" }` while provisioning continues in
  the hub. Client-selection mistakes and capacity problems are therefore
  rejected before any IRAN/FOREIGN mutation.
- Live provisioning timeline in the web UI: the create dialog turns into a
  step-by-step log streamed from `GET /api/gre-routes/:id/events?after_id=…`, with
  per-stage rows (`port_reserved`, `client_model_detected`, `client_preflight`,
  `inbound_add`, `client_attach`/`client_create`, `link_validate`,
  `runtime_validation`, `active`, …), PASS/INFO/FAIL/rollback styling, a failure
  summary above the log and no duplicate rows.
- `GET /api/gre-routes/:id` returns the safe status of a single route, and the
  events endpoint supports `after_id` for incremental reads plus `wait=1` for a
  long poll. Every route row now has a **Timeline** action that reopens the
  complete persistent log, including after a browser refresh or a hub restart.
- Interrupted provisioning is now surfaced instead of ignored: on startup a route
  that is still `RESERVED` past the provisioning window is marked `STALE` with an
  explanatory event. Remote state is never destroyed automatically.
- Optional test-transport hooks (`HUB_TEST_FETCH_MODULE`, `HUB_TEST_SSH_MODULE`)
  so the real HTTP surface, router and orchestrator can be exercised offline, and
  a `node:sqlite` fallback so the hub's own test suite also runs where the native
  `better-sqlite3` build is unavailable.

### Changed

- `gre_routes` gained `client_mode` and `client_model` columns. Existing v2.10.0
  databases are migrated in place with `ALTER TABLE … CHECK (…)`, keeping all
  routes, allocations and event history; legacy rows keep NULL and behave as
  before.
- `inboundPayload()` no longer invents a client: it accepts an explicit `clients`
  array, so the data-model decision lives in one place in the orchestrator
  instead of leaking into the generic inbound builder.
- CI now syntax-checks the hub scripts and runs the full hub test suite.

## [2.10.0] - 2026-10-02

### Added

- Auto routes now load existing client names from 3x-ui and support creating a
  new client name directly from the route workflow.
- Port recommendation now runs automatically and reports every occupied port
  found in the selected range across Linux, firewall, Docker, 3x-ui and the
  persistent GRE allocation registry.
- Route creation now provisions the matching FOREIGN node and IRAN peer with
  one collision-checked GRE identity, and rolls both sides back on failure.
- Persistent secret-safe route event logs are returned to the web UI for every
  provisioning and rollback stage.
- Successful routes now provide a Shadowsocks QR code, share link and complete
  Xray outbound JSON.

## [2.9.2] - 2026-10-02

### Fixed

- `gre update` now syncs and restarts an installed gre-hub even when the CLI is
  already on the latest version, fixing partially updated installations.
- Auto routes now lists saved 3x-ui panels with URL, authentication mode,
  detected capability and safe deletion controls.
- Panel verification uses one authoritative Managed Hosts probe and parallel
  read-only checks, removing slow sequential OpenAPI timeouts.

## [2.9.1] - 2026-10-02

### Fixed

- 3x-ui adapter now supports admin Bearer tokens, 3.x CSRF-protected session
  login, legacy 2.x cookie login, Managed Hosts endpoint variants and manual
  Shadowsocks-link fallback where the client-links endpoint is unavailable.
- Panel credentials are verified against the remote API before being saved.
- `gre update` now updates and restarts an installed gre-hub from the matching
  release while preserving its database and encryption keys.

## [2.9.0] - 2026-10-01

### Added

- gre-hub automatic GRE + 3x-ui route orchestration with capability-based
  Managed Hosts / legacy `externalProxy` support.
- Persistent TCP+UDP port allocation registry with listener, nftables,
  iptables, Docker and 3x-ui collision checks.
- Transactional route creation, generated Shadowsocks client-link validation,
  rollback and runtime reconciliation with `NEEDS_REVIEW` state.
- Auto routes dashboard for panel registration, port recommendation, route
  creation and health reconciliation.

## [2.8.2] - 2026-08-05

### Added
- gre-hub blocks Configure-as-IRAN, Peer-add, and Node-add until bounded public
  ICMP checks pass in both directions. Latest pair results are persisted and
  shown direction-by-direction on both server cards.
- Server cards are grouped into IRAN, FOREIGN, dual-role, and unconfigured
  sections and discovery refreshes every 10 seconds while the page is visible.

### Fixed
- Peer and node names may now use all 11 characters available after the
  `gre-` prefix within Linux's 15-character network-interface limit.

## [2.8.1] - 2026-08-04

### Changed
- gre-hub action forms now use role-filtered native selects for server IPs and
  live-discovered native selects for Node-remove, Peer-remove, and Peer-apply.
  Subnet base remains editable with free-value suggestions; Peer-add TCP/UDP
  ports are randomized from collision-free pools and kept distinct when the
  returned pools permit it.

## [2.8.0] - 2026-08-04

### Added
- `gre iran peer suggest` now accepts `--count N` and `--base A.B`, returning
  rolling pools of up to 20 collision-free names, subnet bases, indexes, GRE
  keys, and TCP/UDP ports while preserving the original single-value JSON shape.
- `gre node suggest` provides the equivalent name/subnet/index/key pools using
  FOREIGN-side node allocations.
- gre-hub Node-add, Peer-add, and Configure-as-IRAN forms now use editable
  datalist comboboxes. IP choices come from role-matched servers already in the
  hub; resource choices load ten free values and refresh indexes/keys when the
  selected subnet base changes.

### Security
- The suggestion endpoint validates suggestion type, count, and subnet base
  before building its remote command.
- `gre update` now installs only checksum-verified pinned releases, aborts cleanly
  when release assets are unavailable, and refuses version downgrades. This
  removes the previous network-dependent fallback to the unverified `main` branch.

## [2.7.1] - 2026-08-03

### Added
- gre-hub: **Suggest auto-fill button** in the Peer-add and Configure-as-IRAN
  forms (`POST /api/servers/:id/suggest-peer` driving
  `gre iran peer suggest --json`; requires remote gre >= 2.7.0).

## [2.7.0] - 2026-08-03

### Added
- **`gre iran peer suggest [--json]`** — prints collision-free suggested values
  for a new foreign peer: generic free name, next subnet base, index, GRE key,
  and free TCP/UDP ports (skipping ports/ranges used by other peers and local
  listeners). Powers the "Suggest" auto-fill button in gre-hub's
  Peer-add / Configure-as-IRAN forms.

## [2.6.1] - 2026-08-03

### Fixed
- gre-hub release package now includes the "Configure as FOREIGN / IRAN"
  actions (added after v2.6.0 was tagged); reinstalling the hub with
  `gre hub install` upgrades an existing installation in place (dashboard
  data is preserved).

## [2.6.0] - 2026-08-03

### Added
- **`gre foreign-setup` — non-interactive FOREIGN setup** (mirrors `iran-setup`
  for the foreign side): `gre foreign-setup [--foreign-ip IP] [--gre-whitelist
  on|off] [--icmp-drop on|off] [--downtime MIN] [--yes]` writes the foreign
  config, applies watchdog settings and installs the systemd service; refuses
  when already configured and points to `gre node add`. This also powers the
  new "Configure as FOREIGN / Configure as IRAN" actions in gre-hub.

## [2.5.0] - 2026-08-03

### Added
- **Smart defaults in the interactive peer-add wizard**: the TCP/UDP port
  prompts now suggest a port that collides with nothing — skipping every port
  and range already used by other peers (per protocol) and any locally
  listened-on port, starting from 3001. Subnet base, index and GRE key were
  already auto-suggested (next free in pool); now all four values can be
  accepted with Enter end-to-end. Test added: full wizard run asserts the
  suggested base/ports are the expected non-colliding ones.

## [2.4.0] - 2026-08-03

### Added
- **`gre hub domain` — one-command web exposure with free HTTPS**: asks for the
  domain (menu option 14 → 5, or `gre hub domain [DOMAIN]`), sanity-checks DNS
  against the server's IP, auto-installs Caddy (official static binary,
  amd64/arm64) when missing, writes the reverse-proxy site into
  `/etc/caddy/sites/gre-hub.caddy` (non-destructive import into the main
  Caddyfile), enables `HUB_SECURE=1` via a systemd drop-in (Secure cookies +
  HSTS), and starts everything. `gre hub unexpose` (menu option 6) cleanly
  reverts to localhost-only. `gre hub install` now also offers the domain
  setup at the end. Port 80/443 conflicts are detected before touching anything.

## [2.3.0] - 2026-08-03

### Added
- **`gre hub` — one-command gre-hub installation** (menu option 14, CLI
  `gre hub install|status|start|stop|restart|uninstall`): installs Node.js 22
  automatically when missing (NodeSource, apt/dnf/yum), downloads the pinned
  `gre-hub.tar.gz` release asset (with latest-release and main-tarball
  fallbacks), runs `npm install` (auto-installs build tools and retries on
  failure), creates and starts the `gre-hub.service` systemd unit, and prints
  local + SSH-tunnel access instructions. Works on any server that already
  has any gre-manager version installed.
- Release workflow now also publishes `gre-hub.tar.gz` (+ sha256) with every tag.

## [2.2.3] - 2026-08-03

### Fixed
- **`gre update` resilience**: the GitHub releases API and release-asset
  downloads are flaky from some networks (intermittent throttling), which made
  updates silently fall back to the unchecksummed main branch. Both steps now
  retry once with a short pause, print a distinct message for API vs. asset
  failure, and only fall back after retries are exhausted. Timeouts added to
  all update curl calls.

## [2.2.2] - 2026-08-03

### Fixed
- **False "unmanaged GRE tunnel" warnings in doctor** (and three similar latent
  spots): `producer | grep -q …` under `set -o pipefail` is a footgun — when
  `grep -q` exits on an early match, the producer dies of SIGPIPE and pipefail
  flips the pipeline to failure. With 2+ managed tunnels this made
  `gre doctor` wrongly report a managed tunnel as unmanaged (and warn it was
  blocked by the whitelist when it was not). All four sites
  (`unmanaged_gre_tunnels`, `port_in_use`, `subnet_route_conflict`, the
  IRAN_IP interface check in doctor) now use herestrings instead of pipes.
- Regression test added: 2 managed tunnels → doctor must not warn.

## [2.2.1] - 2026-08-02

### Added
- **Doctor: GRE-filtering diagnosis on failed tunnel pings** — when a tunnel
  peer does not answer ping, doctor now explains the likely cause (far side
  down vs. GRE proto 47 filtered, often one-way) and prints the exact
  two-sided `tcpdump -n proto 47` test, including the reminder that plain ICMP
  ping can still work while proto 47 is blocked.

## [2.2.0] - 2026-08-02

### Added
- **Current-nodes list before adding**: menu option 2 (FOREIGN) now prints the
  existing Iran nodes (name, IP, subnet, key) before the add-node prompts, so
  you always see what is already configured before adding the next one. The
  Iran-side peers menu already listed peers before add/remove/apply.

## [2.1.0] - 2026-08-02

### Added
- **Coexistence with other GRE tunnels**: during FOREIGN setup, if GRE tunnels
  not managed by gre-manager already exist, enabling the GRE whitelist now
  prints an explicit warning that those tunnels will be blocked.
- **Doctor coexistence check**: `gre doctor` detects unmanaged GRE tunnels —
  reports them as WARN (and warns they are blocked when the GRE whitelist is
  active), so gre-manager never silently kills or fights another tool's tunnel.
- **Pairing fingerprint in status**: `gre status` prints an identical
  `pair: IRAN_IP <-> FOREIGN_IP · SUBNET.IDX.0/30 · key N` line on both sides
  of a tunnel, so operators can visually confirm which Iran node is linked to
  which foreign peer (matching names on both sides is recommended but not
  required — the link is established by IP + subnet base + index + key).

## [2.0.1] - 2026-08-02

### Fixed
- **Installer progress bars**: the "Downloading gre-manager" bar jumped from
  40% to the next step without completing and the "Latest release" line was
  printed mid-bar; every stage now completes its own bar to 100% in order
  (download → checksum → install).
- **Menu clarity**: menu option 1 was renamed from the confusing
  "Foreigns connected to this Iran" to "Configure this server as IRAN
  (add / manage foreign peers)", and a fresh server now shows a
  `Start here → IRAN? press 1 · FOREIGN? press 2` hint under the status line.

## [2.0.0] - 2026-08-01

### Added
- **Multi-foreign support (IRAN side)** — one Iran server can now connect to
  **multiple foreign servers** at once. Each foreign is an independent peer
  with its own tunnel, `/30` subnet, GRE key, forwarded ports and health
  state. Peer configs live in `/etc/multi-gre/foreigns/<name>.conf`;
  `/etc/multi-gre/iran.conf` becomes a manifest (`SCHEMA_VERSION=2`).
- **Per-peer subnets** — tunnel addresses become `<subnet-base>.<idx>.1/.2`
  with an automatic pool of `10.200`–`10.254` (first peer and migrated legacy
  configs keep `10.200`). Duplicate `(SUBNET_BASE, IDX)` pairs, peer names and
  tunnel names are rejected before anything is written or applied.
- **New Iran CLI**:
  - `gre iran peer list [--json]`
  - `gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP]
    [--subnet-base A.B] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST]
    [--udp-ports LIST] [--mss-clamp on|off] [--yes]` (re-running with
    identical values is idempotent; different values are rejected)
  - `gre iran peer remove --name NAME [--yes]` (touches only that peer)
  - `gre iran peer apply --name NAME`
- **Port splitting between foreigns** — every (protocol, port) tuple belongs
  to exactly one peer; overlaps (including range overlaps like `80:90` vs
  `85`) are rejected with an error naming the conflicting peer. TCP and UDP
  are independent (the same port number may go to different peers on
  different protocols). No shared-port failover/load-balancing yet (v2.1+).
- **Foreign-side `--subnet-base`** — `gre node add` and `gre iran-setup`
  accept `--subnet-base`; node confs store `SUBNET_BASE` (default `10.200`
  when absent) and the pairing output prints the full `gre iran peer add`
  command for the Iran side.
- **Automatic v1→v2 migration** — a legacy v1 `iran.conf` is converted to an
  equivalent peer (`SUBNET_BASE=10.200`) plus manifest on the first
  operational command; the original is kept as `iran.conf.v1.bak` (mode 0600)
  for rollback. Migration is atomic and idempotent; an inconsistent mixed
  old+new layout aborts instead of silently overwriting.
- **JSON schema v2** — `gre status --json` now reports `"schema_version": 2`
  and an `iran_peers[]` array (name, foreign IP, subnet base, idx, key,
  tunnel, ports, reachability). A deprecated legacy `iran` field is still
  emitted for single-peer setups; new consumers must read `iran_peers`.
- **Per-peer watchdog & doctor** — the watchdog pings every peer and
  re-applies only dead ones (log lines name the peer, tunnel and foreign IP);
  doctor checks every peer and reports duplicate subnet/tunnel and port
  overlaps as FAIL.
- **Test suite + CI** — new bash test harness (`tests/run.sh`, stubbed
  `ip`/`iptables`/`systemctl`/`ping`/… with redirected config roots, runs on
  Linux and Git Bash) covering migration, idempotency, port/subnet collision
  rejection, peer isolation, watchdog, doctor, JSON, export/import and
  foreign-side regression; CI runs it on every push/PR.

### Changed
- **Menu option 1** is now a peers flow — "Foreigns connected to this Iran
  (add / manage peers)" with list/add/remove; the banner shows
  `IRAN (peers: N/M up)`. Peer iptables rules carry per-peer comments
  (`multi-gre-iran-<name>-*`) so exact removal is possible; `gre purge`
  patterns match the new comments.
- `gre iran-setup` stays for backward compatibility: it creates the first
  peer on an empty server and refuses to overwrite on multi-peer servers
  (pointing to `gre iran peer add`). Accepts `--subnet-base`.
- `gre node remove` now tells the user to remove the matching peer on the
  Iran side instead of uninstalling.
- Export/import handle both v1 and v2 layouts (v1 archives migrate on
  import); ambiguous mixed archives are rejected.

## [1.5.0] - 2026-08-01

### Added
- **`gre purge` — scorched-earth cleanup** (menu option 13, CLI `gre purge [--yes]`):
  removes EVERYTHING GRE-related from the server, including artifacts left by
  older gre-manager versions or other tools:
  - every GRE/GRETAP tunnel, even ones not present in the config (`vatan-m2`,
    hand-made tunnels, old `gre-*` interfaces)
  - every iptables rule in `filter`/`nat`/`mangle` mentioning multi-gre, GRE
    interfaces, proto 47, `10.200.0.0/16` or `132.168.30.0/30`, plus the legacy
    vatanhost broad rules (unscoped MASQUERADE, broad ICMP DROP)
  - all systemd units (`multi-gre.service`, `multi-gre-watchdog.*`)
  - `/etc/multi-gre`, the sysctl file, audit log, bash completion, and the
    `gre` / `multi-gre-manager` commands themselves
  - requires an explicit confirmation (or `--yes`) with a full warning about
    what will be touched

## [1.4.0] - 2026-08-01

### Added
- **Downtime tolerance question during setup**: the installer now asks how many
  minutes of tunnel downtime are acceptable and derives the watchdog check
  interval from the answer (interval = tolerance / 2, min 1 min; `0` disables
  auto-heal). Stored in `/etc/multi-gre/global.conf`.
- **Watchdog settings menu** (menu option 7): view state, change the downtime
  tolerance, enable or disable the watchdog at any time — cancellable whenever
  the user wants. CLI: `gre watchdog interval <1-60>` plus the existing
  `enable|disable|status`.
- **WARP-Manager-inspired menu UX**: grouped sections (Tunnels / Monitoring /
  Maintenance), live state indicators (`● ON` / `○ OFF`) for tunnels and the
  watchdog directly in the menu, node counter, new interactive submenus for
  Watchdog and Backup/restore, and Ctrl+C now returns to the menu instead of
  killing the program.
- **Installer progress bars** (`install.sh`), styled step-by-step output.
- `gre iran-setup --downtime MIN` flag for non-interactive setups.

### Changed
- Doctor and Backup/restore are now reachable from the interactive menu
  (options 8 and 9).

## [1.3.0] - 2026-07-31

### Added
- **CI (GitHub Actions)**: ShellCheck (`-S warning`), `bash -n`, smoke tests and a
  version-consistency check (VERSION file == script == CHANGELOG) on every push/PR.
- **Pinned, verifiable installs**: `install.sh` now downloads the latest GitHub
  *release* asset and verifies its SHA-256 checksum before installing
  (`GRE_EDGE=1` opts into the bleeding-edge main branch).
- **Verifiable self-update**: `gre update` prefers the latest release asset and
  verifies `gre.sha256`; refuses to install on checksum mismatch; falls back to
  the main branch (with a warning) only when release assets are unavailable.
- **Release automation**: pushing a `v*` tag builds `gre` + `gre.sha256` and
  publishes the GitHub release automatically.
- **bash completion** for `gre` (`completion/gre.bash`, installed to
  `/etc/bash_completion.d/` by the installer when available).

## [1.2.0] - 2026-07-31

### Added
- **Non-interactive CLI** for automation/Ansible:
  - `gre node list [--json]` — list configured Iran nodes (foreign side).
  - `gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]` —
    non-interactive equivalent of the menu's add-node flow; defaults
    `idx = next free`, `key = 1000 + idx`, keeps the GRE whitelist rule
    ordering intact and prints the values to enter on the Iran server.
  - `gre node remove --name NAME [--yes]` — deletes the tunnel, its whitelist
    ACCEPT rule and the node config.
  - `gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N]
    [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST]
    [--mss-clamp on|off] [--yes]` — full non-interactive Iran setup;
    auto-detects the public IP/WAN interface when omitted. A TCP list covering
    port 22 aborts unless `--yes` is passed.
  - All mutating CLI commands ask for confirmation unless `--yes` is passed;
    unknown flags error out with usage.
- **JSON status**: `gre status --json` / `gre --status --json` prints pure-bash
  JSON (no jq needed): version, roles, service/watchdog state, tunnel count,
  per-node reachability and the Iran-side config.
- **`gre doctor`**: diagnostics with PASS/WARN/FAIL per check and a non-zero
  exit code on any FAIL — required binaries, `ip_forward`, WAN interface and
  Iran IP assignment, tunnel existence + peer ping, NAT DNAT rules, GRE
  whitelist rules, systemd service/watchdog state, and local port conflicts.
- **Backup/restore**: `gre export [path]` writes a mode-600 tar.gz of
  `/etc/multi-gre` (default `./gre-backup-<timestamp>.tar.gz`);
  `gre import <file> [--yes]` verifies the archive (gzip tar, must contain
  `etc/multi-gre`, no absolute/`..` paths), stops tunnels, restores, and
  re-applies everything.
- **Port-conflict warning**: the interactive Iran setup now warns (non-fatally)
  when a forwarded port is already listened on by a local service.

## [1.1.0] - 2026-07-31

### Added
- **Watchdog**: `multi-gre-watchdog.timer` checks every tunnel every minute
  (existence + ICMP reachability of the tunnel peer) and re-applies dead
  tunnels automatically; actions are logged to the systemd journal
  (`journalctl -t gre-watchdog`). Manage with `gre watchdog enable|disable|status`.
- **Firewall hardening (FOREIGN)**: optional GRE (proto 47) whitelist — only
  known Iran node IPs may establish GRE to the foreign server; all other GRE
  traffic is dropped. Per-node ACCEPT rules carry iptables comments
  (`multi-gre-node-<name>`) and are kept correctly ordered before the block rule.
- **TCP MSS clamping (IRAN)**: optional `TCPMSS --clamp-mss-to-pmtu` on the
  tunnel interface (mangle/POSTROUTING) to prevent broken-PMTU stalls.
- **Audit log**: node add/remove, setups, restarts, cleanup, updates and
  uninstalls are appended to `/var/log/gre-manager.log` with timestamp and user.
- Config files under `/etc/multi-gre/` are now created with mode `0600`.
- Watchdog state shown in the menu banner and in `gre --status`.

### Changed
- ICMP drop on FOREIGN now keeps tunnel subnets (`10.200.0.0/16`) pingable so
  the watchdog and `gre --status` health checks keep working; old v1.0.0
  un-commented ICMP DROP rules are migrated automatically on re-apply.

## [1.0.0] - 2026-07-31

### Added
- Interactive `gre` command: menu-driven management of multiple GRE tunnels
  (many IRAN servers -> one FOREIGN server).
- Per-node isolation: each Iran node gets its own tunnel (`gre-<name>`),
  `/30` subnet (`10.200.<idx>.0/30`) and GRE key (`1000 + idx`).
- IRAN side setup: DNAT of selected TCP/UDP ports (multiport, ranges
  supported) from the public IP into the tunnel, plus SNAT on the tunnel.
  Port 22 (SSH) is never forwarded silently — an explicit confirmation is
  required.
- FOREIGN side setup: add/remove Iran nodes, automatic free tunnel-index
  allocation, optional inbound ICMP drop.
- systemd integration: `multi-gre.service` (oneshot) re-applies all tunnels
  and NAT rules after reboot; `gre --apply` / `gre --stop` are the service
  entry points.
- Idempotent iptables handling: rules are only added when missing and only
  removed when present (safe to re-run any action).
- Legacy cleanup: removes everything the original `vatanhost/gre` script
  created (`vatan-m2`, `132.168.30.0/30`, its broad NAT rules, ICMP drop).
- Self-update: `gre update` pulls the latest version from GitHub (with
  version comparison and a syntax check before replacing the binary).
- CLI: `gre --status`, `gre --version`, `gre --help`.
- One-line installer: `install.sh` installs the `gre` command to
  `/usr/local/sbin/gre`.

[1.0.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.0.0
[1.1.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.1.0
[1.2.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.2.0
[1.3.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.3.0
[1.4.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.4.0
[1.5.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.5.0
[2.0.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.0.0
[2.0.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.0.1
[2.1.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.1.0
[2.2.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.0
[2.2.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.1
[2.2.2]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.2
[2.2.3]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.3
[2.3.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.3.0
[2.4.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.4.0
[2.5.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.5.0
[2.6.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.6.0
[2.6.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.6.1
[2.7.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.7.0
[2.7.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.7.1
