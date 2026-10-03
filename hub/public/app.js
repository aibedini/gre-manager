'use strict';
/* gre-hub frontend — vanilla JS SPA, no build step. */

// ---------- helpers -------------------------------------------------------

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

const state = {
  servers: [],
  routes: [],
  panels: [],
  current: null,      // server object open in the drawer
  csrf: '',
  totpEnabled: false,
  logKind: '',
  meta: null,         // GET /api/meta (running build identity)
  autoRefreshTimer: null,
  autoRefreshRunning: false,
  lastRefreshAt: null,
  routesPoll: null,   // live provisioning timeline poller
  routesPollGeneration: 0, // invalidates an in-flight poll after the modal closes
};

async function api(path, { method = 'GET', body, ok = null, signal = null } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && state.csrf) headers['x-csrf-token'] = state.csrf;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: signal || undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !path.startsWith('/api/login')) {
    showAuth(false);
    throw new Error('not authenticated');
  }
  const accepted = ok && ok.includes(res.status);
  if (!res.ok && !accepted) {
    const err = new Error((data && data.error) || `request failed (${res.status})`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

function timeAgo(isoOrMs) {
  if (!isoOrMs) return 'never';
  const t = typeof isoOrMs === 'number' ? isoOrMs : Date.parse(isoOrMs);
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ---------- modal ---------------------------------------------------------

function openModal(html, { wide = false } = {}) {
  const wrap = $('#modal-wrap');
  const modal = $('#modal');
  modal.classList.toggle('wide', wide);
  modal.innerHTML = html;
  wrap.classList.add('open');
  const first = modal.querySelector('input, select, textarea, button.btn');
  if (first) first.focus();
}

function closeModal() {
  $('#modal-wrap').classList.remove('open');
  $('#modal').innerHTML = '';
}

$('#modal-wrap').addEventListener('click', (e) => {
  if (e.target.id === 'modal-wrap') closeModal();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

// ---------- host key mismatch ----------------------------------------------

function showHostKeyMismatch(server, data) {
  openModal(`
    <h2>Host key mismatch</h2>
    <p class="sub"><strong>${esc(server.name)}</strong> presented a different SSH host key than the one pinned.
    This can mean a man-in-the-middle attack — or a legitimate server reinstall.</p>
    <dl class="kv" style="margin-bottom:8px">
      <dt>Pinned</dt><dd>${esc(data.expected_fp || '(none)')}</dd>
      <dt>Presented</dt><dd>${esc(data.presented_fp || '(unknown)')}</dd>
    </dl>
    <div class="foot">
      <button class="btn btn-ghost" id="hk-cancel">Cancel</button>
      <button class="btn btn-danger" id="hk-accept">Accept new key (logged)</button>
    </div>`);
  $('#hk-cancel').addEventListener('click', closeModal);
  $('#hk-accept').addEventListener('click', async () => {
    if (!confirm(`Really accept the new host key for ${server.name}?\n\n${data.presented_fp}\n\nOnly proceed if you know why the key changed.`)) return;
    try {
      await api(`/api/servers/${server.id}/host-key/accept`, { method: 'POST', body: { fingerprint: data.presented_fp } });
      server.host_key_fp = data.presented_fp;
      closeModal();
      toast('New host key accepted and pinned');
    } catch (err) { toast(err.message, true); }
  });
}

function handleHostKeyError(server, err) {
  if (err.data && err.data.hostkey_mismatch) {
    showHostKeyMismatch(server, err.data);
    return true;
  }
  return false;
}

// ---------- auth ----------------------------------------------------------

let authMode = 'login'; // 'login' | 'setup'
let authNeed2fa = false;

function showAuth(needsSetup) {
  stopAutoRefresh();
  authMode = needsSetup ? 'setup' : 'login';
  authNeed2fa = false;
  state.csrf = '';
  $('#view-main').classList.add('hidden');
  closeDrawer();
  $('#view-auth').classList.remove('hidden');
  $('#auth-title').textContent = needsSetup ? 'Create hub password' : 'gre-hub';
  $('#auth-sub').textContent = needsSetup
    ? 'First run — set the password for this hub.'
    : 'Sign in to continue.';
  $('#auth-confirm-wrap').classList.toggle('hidden', !needsSetup);
  $('#auth-2fa-wrap').classList.add('hidden');
  $('#auth-submit').textContent = needsSetup ? 'Create password' : 'Sign in';
  $('#auth-error').textContent = '';
  $('#auth-password').value = '';
  $('#auth-confirm').value = '';
  $('#auth-2fa').value = '';
  $('#auth-password').focus();
}

$('#auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('#auth-password').value;
  const errEl = $('#auth-error');
  errEl.textContent = '';
  try {
    if (authMode === 'setup') {
      if (password !== $('#auth-confirm').value) {
        errEl.textContent = 'Passwords do not match.';
        return;
      }
      const r = await api('/api/setup', { method: 'POST', body: { password } });
      state.csrf = r.csrf;
    } else {
      const body = { password };
      if (authNeed2fa) body.code = $('#auth-2fa').value.trim();
      const r = await api('/api/login', { method: 'POST', body });
      state.csrf = r.csrf;
    }
    enterMain();
  } catch (err) {
    if (authMode === 'login' && err.data && err.data.requires_2fa) {
      if (!authNeed2fa) {
        authNeed2fa = true;
        $('#auth-2fa-wrap').classList.remove('hidden');
        $('#auth-2fa').focus();
        errEl.textContent = 'Two-factor authentication is enabled — enter your code.';
      } else {
        errEl.textContent = err.message;
      }
      return;
    }
    errEl.textContent = err.message;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
  showAuth(false);
});

// ---------- navigation ----------------------------------------------------

$$('.nav button[data-page]').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('.nav button[data-page]').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const page = btn.dataset.page;
    $('#page-servers').classList.toggle('hidden', page !== 'servers');
    $('#page-routes').classList.toggle('hidden', page !== 'routes');
    $('#page-log').classList.toggle('hidden', page !== 'log');
    $('#page-settings').classList.toggle('hidden', page !== 'settings');
    if (page === 'log') loadLog();
    if (page === 'routes') loadRoutes();
    if (page === 'settings') renderSettings();
  });
});

// ---------- build identity -------------------------------------------------

// The running build is shown permanently in the top bar so a stale deployment
// is visible at a glance instead of being inferred from odd behaviour.
function renderBuildStamp() {
  const el = $('#brand-version');
  if (!el) return;
  const meta = state.meta;
  if (!meta || !meta.version) { el.textContent = ''; return; }
  const short = meta.shortCommit || meta.commit || null;
  el.textContent = `v${meta.version}${short ? ` · ${short}` : ''}`;
  const details = [
    `version: ${meta.version} (${meta.versionSource})`,
    short ? `commit: ${short}` : 'commit: unknown',
    meta.builtAt ? `built: ${meta.builtAt}` : 'built: unknown',
    `node: ${meta.node}`,
    meta.schemaVersion !== null && meta.schemaVersion !== undefined ? `db schema: ${meta.schemaVersion}` : null,
    meta.mixed ? 'WARNING: version sources disagree (mixed deployment)' : null,
  ].filter(Boolean).join('\n');
  el.title = details;
  el.classList.toggle('stale', !!meta.mixed || !short);
}

async function loadMeta() {
  try {
    state.meta = await api('/api/meta');
  } catch {
    state.meta = null;
  }
  renderBuildStamp();
}

async function enterMain() {
  $('#view-auth').classList.add('hidden');
  $('#view-main').classList.remove('hidden');
  try {
    const me = await api('/api/me');
    state.csrf = me.csrf;
    state.totpEnabled = me.totp_enabled;
  } catch { /* csrf already set from login */ }
  await loadMeta();
  await loadServers();
  startAutoRefresh();
}

// ---------- servers grid --------------------------------------------------

function roleInfo(snap) {
  const roles = (snap && snap.roles) || [];
  if (roles.includes('IRAN') && roles.includes('FOREIGN')) return { label: 'both', cls: 'blue' };
  if (roles.includes('IRAN')) return { label: 'iran', cls: 'blue' };
  if (roles.includes('FOREIGN')) return { label: 'foreign', cls: 'blue' };
  return { label: 'unknown', cls: 'gray' };
}

function peerList(snap) {
  const st = snap && snap.status;
  if (!st) return null;
  if (Array.isArray(st.nodes)) return st.nodes;
  if (Array.isArray(st.iran_peers)) return st.iran_peers;
  return null;
}

function watchdogOn(snap) {
  const wd = snap && (snap.watchdog || (snap.status && snap.status.watchdog));
  if (!wd) return null;
  if (typeof wd === 'object') return wd.enabled === true || wd.enabled === 1;
  return String(wd) === 'enabled';
}

function badgesFor(server) {
  const snap = server.snapshot;
  const out = [];
  if (server.key_installed) out.push(['green', 'ssh key']);
  else out.push(['gray', server.has_secret ? 'password' : 'password required']);
  if (!snap) {
    out.push(['gray', 'not discovered']);
    return out;
  }
  if (snap.error) {
    out.push(['red', 'probe failed']);
    return out;
  }
  if (!snap.manager || !snap.manager.installed) {
    out.push(['yellow', 'no manager']);
  } else {
    const role = roleInfo(snap);
    out.push([role.cls, role.label]);
    if (snap.manager.version) out.push(['gray', `v${snap.manager.version}`]);
    if (snap.tunnels_up !== null && snap.tunnels_up !== undefined) {
      out.push([snap.tunnels_up > 0 ? 'green' : 'gray', `${snap.tunnels_up} up`]);
    }
    const wd = watchdogOn(snap);
    if (wd !== null) out.push([wd ? 'green' : 'gray', wd ? 'watchdog' : 'no watchdog']);
  }
  if (snap.legacy && snap.legacy.present) out.push(['red', 'legacy']);
  if (snap.unmanaged_tunnels && snap.unmanaged_tunnels.length) {
    out.push(['yellow', `${snap.unmanaged_tunnels.length} unmanaged`]);
  }
  return out;
}

function healthDot(server) {
  const snap = server.snapshot;
  if ((server.connectivity || []).some((pair) =>
    !pair.iran_to_foreign.reachable || !pair.foreign_to_iran.reachable)) return 'err';
  if (!server.has_secret && !server.key_installed) return 'err';
  if (!snap) return 'unknown';
  if (snap.error) return 'err';
  if (!snap.manager || !snap.manager.installed) return 'warn';
  const peers = peerList(snap);
  if (peers) {
    if (peers.some((n) => n.reachable === false)) return 'warn';
    if (peers.length && peers.every((n) => n.reachable === true)) return 'ok';
  }
  return 'ok';
}

function peerNamesHtml(snap) {
  const peers = peerList(snap);
  if (!peers || !peers.length) return '';
  const items = peers.map((p) => {
    const cls = p.reachable === true ? 'ok' : p.reachable === false ? 'err' : 'unknown';
    return `<span class="peer-chip"><span class="dot ${cls}"></span>${esc(p.name)}</span>`;
  }).join('');
  return `<div class="peer-chips">${items}</div>`;
}

function connectivityHtml(server) {
  const pairs = Array.isArray(server.connectivity) ? server.connectivity : [];
  if (!pairs.length) return '';
  return `<div class="public-paths">${pairs.map((pair) => {
    const other = server.id === pair.iran.id ? pair.foreign : pair.iran;
    const blocked = !pair.iran_to_foreign.reachable || !pair.foreign_to_iran.reachable;
    const line = (from, to, result) => `<div class="public-path-line ${result.reachable ? 'pass' : 'fail'}">
      <span class="route">${esc(from)} -&gt; ${esc(to)}</span>
      <span class="state">${result.reachable ? 'REACHABLE' : 'BLOCKED'}</span>
    </div>`;
    return `<div class="public-path-pair">
      <div class="public-path-peer">Public path with ${esc(other.name)} · checked ${timeAgo(pair.checked_at)}</div>
      ${line(pair.iran.ip, pair.foreign.ip, pair.iran_to_foreign)}
      ${line(pair.foreign.ip, pair.iran.ip, pair.foreign_to_iran)}
      ${blocked ? '<div class="public-path-blocked">Public path blocked</div>' : ''}
    </div>`;
  }).join('')}</div>`;
}

function roleGroup(server) {
  const roles = ((server.snapshot && server.snapshot.roles) || []).map((role) => String(role).toUpperCase());
  if (roles.includes('IRAN') && roles.includes('FOREIGN')) return 'dual';
  if (roles.includes('IRAN')) return 'iran';
  if (roles.includes('FOREIGN')) return 'foreign';
  return 'unconfigured';
}

function renderServers() {
  const grid = $('#servers-grid');
  $('#servers-count').textContent =
    state.servers.length === 0 ? 'No servers yet.' : `${state.servers.length} server${state.servers.length === 1 ? '' : 's'}`;
  if (!state.servers.length) {
    grid.innerHTML = '<div class="empty">Add your first server to start managing GRE tunnels.</div>';
    return;
  }
  const renderCard = (s, i) => {
    const badges = badgesFor(s)
      .map(([cls, label]) => `<span class="badge ${cls}">${esc(label)}</span>`)
      .join('');
    const snap = s.snapshot;
    const peers = peerList(snap);
    const peerLine = peers
      ? `<div class="card-peers-title muted">${peers.length} ${snap.status.nodes ? 'iran node' : 'foreign peer'}${peers.length === 1 ? '' : 's'}</div>${peerNamesHtml(snap)}`
      : '';
    return `
      <div class="card" style="--i:${i}" data-id="${s.id}">
        <div class="card-top">
          <div>
            <div class="card-name">${esc(s.name)}</div>
            <div class="card-host">${esc(s.username)}@${esc(s.host)}:${s.ssh_port}</div>
          </div>
          <span><span class="dot ${healthDot(s)}"></span></span>
        </div>
        <div class="card-badges">${badges}</div>
        ${peerLine}
        ${connectivityHtml(s)}
        <div class="card-foot">
          <span>${snap ? `discovered ${timeAgo(snap.taken_at)}` : 'never discovered'}</span>
          <button class="btn btn-ghost btn-sm btn-card-discover" data-id="${s.id}">Discover</button>
        </div>
      </div>`;
  };
  const groups = [
    ['iran', 'IRAN'],
    ['foreign', 'FOREIGN'],
    ['dual', 'DUAL ROLE'],
    ['unconfigured', 'UNCONFIGURED'],
  ];
  let cardIndex = 0;
  grid.innerHTML = groups.map(([key, label]) => {
    const servers = state.servers.filter((server) => roleGroup(server) === key);
    if (!servers.length && !['iran', 'foreign'].includes(key)) return '';
    return `<section class="server-group ${key}">
      <div class="server-group-head"><span>${label}</span><span class="server-group-count">${servers.length}</span></div>
      <div class="grid">${servers.length ? servers.map((server) => renderCard(server, cardIndex++)).join('') : '<div class="empty">No servers in this group.</div>'}</div>
    </section>`;
  }).join('');
  $$('.card', grid).forEach((card) => {
    card.addEventListener('click', () => openDrawer(Number(card.dataset.id)));
  });
  $$('.btn-card-discover', grid).forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const server = state.servers.find((s) => s.id === Number(btn.dataset.id));
      btn.disabled = true;
      btn.textContent = '…';
      try {
        const snap = await api(`/api/servers/${server.id}/discover`, { method: 'POST' });
        server.snapshot = snap;
        toast(`Discovery complete: ${server.name}`);
      } catch (err) {
        if (!handleHostKeyError(server, err)) toast(err.message, true);
      }
      loadServers();
    });
  });
}

async function loadServers() {
  try {
    state.servers = await api('/api/servers');
    renderServers();
    if (state.current) {
      const fresh = state.servers.find((s) => s.id === state.current.id);
      if (fresh) { state.current = fresh; renderOverview(); }
    }
  } catch (err) {
    if (err.message !== 'not authenticated') toast(err.message, true);
  }
}

function updateAutoRefreshStatus() {
  const el = $('#auto-refresh-status');
  if (!el) return;
  if (state.autoRefreshRunning) el.textContent = 'Auto refresh: refreshing…';
  else if (document.hidden) el.textContent = 'Auto refresh: paused';
  else el.textContent = `Auto refresh: 10s · last ${state.lastRefreshAt ? timeAgo(state.lastRefreshAt) : 'pending'}`;
}

async function refreshAllServers() {
  if (state.autoRefreshRunning || document.hidden || $('#view-main').classList.contains('hidden')) return;
  state.autoRefreshRunning = true;
  updateAutoRefreshStatus();
  try {
    await Promise.allSettled(state.servers.map((server) =>
      api(`/api/servers/${server.id}/discover`, { method: 'POST' })
    ));
    await loadServers();
    state.lastRefreshAt = Date.now();
  } finally {
    state.autoRefreshRunning = false;
    updateAutoRefreshStatus();
  }
}

function startAutoRefresh() {
  stopAutoRefresh(false);
  state.lastRefreshAt = Date.now();
  state.autoRefreshTimer = setInterval(() => {
    updateAutoRefreshStatus();
    if (!document.hidden && Date.now() - state.lastRefreshAt >= 10000) refreshAllServers();
  }, 1000);
  updateAutoRefreshStatus();
}

function stopAutoRefresh(reset = true) {
  if (state.autoRefreshTimer) clearInterval(state.autoRefreshTimer);
  state.autoRefreshTimer = null;
  state.autoRefreshRunning = false;
  if (reset) state.lastRefreshAt = null;
  updateAutoRefreshStatus();
}

document.addEventListener('visibilitychange', () => {
  updateAutoRefreshStatus();
  if (!document.hidden && state.autoRefreshTimer && Date.now() - state.lastRefreshAt >= 10000) refreshAllServers();
});

// ---------- add / edit / delete server ------------------------------------

function serverFormHtml(server) {
  const s = server || {};
  const isKey = server && server.key_installed;
  return `
    <h2>${server ? 'Edit server' : 'Add server'}</h2>
    <p class="sub">${server
      ? 'Credentials stay AES-256-GCM encrypted.'
      : 'A dedicated ed25519 SSH key will be created and installed automatically; the password is used only once.'}</p>
    <form id="server-form">
      <div class="form-row">
        <div class="field"><label>Name</label><input name="name" required value="${esc(s.name || '')}" placeholder="iran-1" /></div>
        <div class="field"><label>Host</label><input name="host" required value="${esc(s.host || '')}" placeholder="203.0.113.10" /></div>
      </div>
      <div class="form-row">
        <div class="field"><label>SSH port</label><input name="ssh_port" type="number" value="${s.ssh_port || 22}" /></div>
        <div class="field"><label>Username</label><input name="username" value="${esc(s.username || 'root')}" /></div>
      </div>
      <div class="field">
        <label>${server ? (isKey ? 'Fallback password (optional)' : 'Password') : 'SSH password'}</label>
        <input name="secret" type="password" ${!server && !isKey ? 'required' : ''}
          placeholder="${server ? 'Leave empty to keep current' : 'Used once to install the hub key'}" />
        ${isKey ? '<div class="hint">This server authenticates with the hub SSH key; a password here is stored only as a fallback.</div>' : ''}
      </div>
      ${!server ? `
      <div class="field" style="display:flex; gap:8px; align-items:center">
        <input type="checkbox" id="keep-fallback" name="keep_fallback" style="width:auto" />
        <label for="keep-fallback" style="margin:0; color:var(--text)">Keep password as fallback after key install</label>
      </div>` : ''}
      <div class="form-error" id="server-form-error"></div>
      <div class="foot">
        ${server ? '<button type="button" class="btn btn-danger" id="btn-delete-server">Delete</button>' : ''}
        <div style="flex:1"></div>
        <button type="button" class="btn btn-ghost" id="btn-cancel-server">Cancel</button>
        <button type="submit" class="btn">${server ? 'Save' : 'Add server'}</button>
      </div>
    </form>`;
}

function openServerForm(server) {
  openModal(serverFormHtml(server));
  const form = $('#server-form');
  $('#btn-cancel-server').addEventListener('click', closeModal);
  const delBtn = $('#btn-delete-server');
  if (delBtn) {
    delBtn.addEventListener('click', async () => {
      if (!confirm(`Delete server "${server.name}" from the hub? (Nothing changes on the server itself.)`)) return;
      try {
        await api(`/api/servers/${server.id}`, { method: 'DELETE' });
        closeModal();
        closeDrawer();
        toast('Server deleted');
        loadServers();
      } catch (err) { toast(err.message, true); }
    });
  }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = {
      name: form.name.value.trim(),
      host: form.host.value.trim(),
      ssh_port: Number(form.ssh_port.value) || 22,
      username: form.username.value.trim() || 'root',
    };
    if (server) {
      if (form.secret.value) body.secret = form.secret.value;
    } else {
      body.password = form.secret.value;
      body.keep_fallback = form.keep_fallback.checked;
    }
    try {
      if (server) {
        await api(`/api/servers/${server.id}`, { method: 'PUT', body });
        toast('Server updated');
      } else {
        await api('/api/servers', { method: 'POST', body });
        toast('Server added — installing SSH key and discovering');
      }
      closeModal();
      loadServers();
    } catch (err) {
      $('#server-form-error').textContent = err.message;
    }
  });
}

$('#btn-add-server').addEventListener('click', () => openServerForm(null));

// ---------- drawer --------------------------------------------------------

function openDrawer(id) {
  const server = state.servers.find((s) => s.id === id);
  if (!server) return;
  state.current = server;
  $('#drawer-name').textContent = server.name;
  $('#drawer-meta').textContent = `${server.username}@${server.host}:${server.ssh_port}`;
  $('#overlay').classList.add('open');
  $('#drawer').classList.add('open');
  switchTab('overview');
}

function closeDrawer() {
  $('#overlay').classList.remove('open');
  $('#drawer').classList.remove('open');
  state.current = null;
  destroyTerminal();
}

$('#overlay').addEventListener('click', closeDrawer);
$('#drawer-close').addEventListener('click', closeDrawer);

$$('.drawer-tabs button').forEach((btn) => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function switchTab(tab) {
  $$('.drawer-tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  $('#tab-overview').classList.toggle('hidden', tab !== 'overview');
  $('#tab-actions').classList.toggle('hidden', tab !== 'actions');
  $('#tab-terminal').classList.toggle('hidden', tab !== 'terminal');
  if (tab === 'overview') renderOverview();
  if (tab === 'actions') renderActions();
  if (tab === 'terminal') initTerminal();
  else destroyTerminal();
}

// ---------- overview tab --------------------------------------------------

function reachBadge(v) {
  if (v === true) return '<span class="badge green">up</span>';
  if (v === false) return '<span class="badge red">down</span>';
  return '<span class="badge gray">?</span>';
}

function peersTable(rows, kind) {
  if (!rows || !rows.length) return '';
  const head = kind === 'nodes'
    ? '<th>Name</th><th>Iran IP</th><th>Idx</th><th>Tunnel</th><th>Subnet</th><th>State</th>'
    : '<th>Name</th><th>Foreign IP</th><th>Idx</th><th>Tunnel</th><th>Subnet</th><th>TCP</th><th>UDP</th><th>State</th>';
  const body = rows.map((n) => kind === 'nodes'
    ? `<tr><td>${esc(n.name)}</td><td>${esc(n.iran_ip)}</td><td>${esc(n.idx)}</td><td>${esc(n.tun)}</td><td>${esc(n.subnet_base)}</td><td>${reachBadge(n.reachable)}</td></tr>`
    : `<tr><td>${esc(n.name)}</td><td>${esc(n.foreign_ip)}</td><td>${esc(n.idx)}</td><td>${esc(n.tun)}</td><td>${esc(n.subnet_base)}</td><td>${esc(n.tcp_ports || '')}</td><td>${esc(n.udp_ports || '')}</td><td>${reachBadge(n.reachable)}</td></tr>`
  ).join('');
  return `<table class="data"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function renderOverview() {
  const el = $('#tab-overview');
  const s = state.current;
  if (!s) return;
  const snap = s.snapshot;

  const toolbar = `
    <div style="display:flex; gap:8px; margin-bottom:28px; flex-wrap:wrap">
      <button class="btn btn-ghost btn-sm" id="ov-discover">Run discovery</button>
      <button class="btn btn-ghost btn-sm" id="ov-test">Test connection</button>
      <button class="btn btn-ghost btn-sm" id="ov-edit">Edit server</button>
    </div>`;

  const sshSection = `
    <div class="section"><h3>SSH access</h3>
      <dl class="kv">
        <dt>Auth</dt><dd>${s.key_installed ? 'hub ed25519 key' : 'password'}</dd>
        <dt>Hub key</dt><dd>${s.key_installed ? `installed (gre-hub-${s.id})` : (s.has_secret ? 'not installed' : 'not installed — password required')}</dd>
        <dt>Fallback password</dt><dd>${s.has_fallback_password ? 'stored (encrypted)' : 'none'}</dd>
        <dt>Host key</dt><dd>${s.host_key_fp ? esc(s.host_key_fp) : 'not pinned yet (TOFU on first connect)'}</dd>
      </dl>
      <div style="display:flex; gap:8px; margin-top:14px; flex-wrap:wrap">
        ${s.key_installed
          ? '<button class="btn btn-ghost btn-sm" id="ov-key-reinstall">Reinstall key</button><button class="btn btn-danger btn-sm" id="ov-key-delete">Remove hub key</button>'
          : '<button class="btn btn-ghost btn-sm" id="ov-key-reinstall">Install hub key</button>'}
      </div>
    </div>`;

  let body = '';
  if (!snap) {
    body = '<div class="empty">No discovery data yet. Run discovery to probe this server.</div>';
  } else if (snap.error) {
    body = `
      <div class="section"><h3>Probe failed</h3>
      <div class="output-pane">${esc(snap.error)}</div></div>
      <div class="muted" style="font-size:12px">Last attempt ${timeAgo(snap.taken_at)}</div>`;
  } else {
    const st = snap.status || {};
    const svc = st.service || snap.service || {};
    const wd = st.watchdog || snap.watchdog || {};
    const wdText = wd === null || wd === undefined ? '—'
      : typeof wd === 'object'
        ? `${wd.enabled ? 'enabled' : 'disabled'}${wd.interval_min ? `, every ${wd.interval_min}m` : ''}`
        : String(wd);
    const svcText = typeof svc === 'object'
      ? `${svc.active !== undefined ? (svc.active ? 'active' : 'inactive') : ''}${svc.enabled !== undefined ? (svc.enabled ? ', enabled' : ', disabled') : ''}`.replace(/^, /, '') || '—'
      : String(svc || '—');

    const legacy = snap.legacy || {};
    const legacyHtml = legacy.present ? `
      <div class="section"><h3>Legacy vatanhost artifacts <span class="badge red" style="margin-left:8px">warning</span></h3>
        <dl class="kv">
          <dt>vatan-m2 tunnel</dt><dd>${legacy.vatan_m2 ? 'present' : 'absent'}</dd>
          <dt>nat rules w/ 132.168.30.</dt><dd>${legacy.nat_132_168_30_rules}</dd>
          <dt>broad MASQUERADE rules</dt><dd>${legacy.broad_masquerade_rules}</dd>
          <dt>INPUT icmp DROP rules</dt><dd>${legacy.input_icmp_drop_rules}</dd>
        </dl>
      </div>` : '';

    const unmanagedHtml = (snap.unmanaged_tunnels && snap.unmanaged_tunnels.length) ? `
      <div class="section"><h3>Unmanaged GRE tunnels <span class="badge yellow" style="margin-left:8px">not in manager config</span></h3>
        <div>${snap.unmanaged_tunnels.map((t) => `<span class="badge yellow">${esc(t)}</span>`).join(' ')}</div>
      </div>` : '';

    body = `
      <div class="section"><h3>Manager</h3>
        <dl class="kv">
          <dt>Installed</dt><dd>${snap.manager.installed ? 'yes' : 'no'}</dd>
          <dt>Version</dt><dd>${esc(snap.manager.version || '—')}</dd>
          <dt>Roles</dt><dd>${(snap.roles || []).join(', ') || 'none'}</dd>
          <dt>Service</dt><dd>${esc(svcText)}</dd>
          <dt>Watchdog</dt><dd>${esc(wdText)}</dd>
          <dt>Tunnels up</dt><dd>${snap.tunnels_up ?? '—'}</dd>
          <dt>All GRE interfaces</dt><dd>${(snap.gre_tunnels || []).join(', ') || 'none'}</dd>
          <dt>Discovered</dt><dd>${timeAgo(snap.taken_at)}</dd>
        </dl>
      </div>
      ${st.nodes ? `<div class="section"><h3>Iran nodes (${st.nodes.length})</h3>${peersTable(st.nodes, 'nodes') || '<div class="empty">None</div>'}</div>` : ''}
      ${st.iran_peers ? `<div class="section"><h3>Foreign peers (${st.iran_peers.length})</h3>${peersTable(st.iran_peers, 'peers') || '<div class="empty">None</div>'}</div>` : ''}
      ${unmanagedHtml}
      ${legacyHtml}
      <div class="section"><h3>Raw snapshot</h3>
        <details><summary class="muted" style="cursor:pointer; font-size:12px">Full JSON</summary>
          <div class="output-pane" style="margin-top:10px; max-height:300px">${esc(JSON.stringify(snap, null, 2))}</div>
        </details>
      </div>`;
  }

  el.innerHTML = toolbar + sshSection + body;

  $('#ov-discover').addEventListener('click', async () => {
    const btn = $('#ov-discover');
    btn.disabled = true; btn.textContent = 'Discovering…';
    try {
      const snap = await api(`/api/servers/${s.id}/discover`, { method: 'POST' });
      s.snapshot = snap;
      renderOverview();
      loadServers();
      toast('Discovery complete');
    } catch (err) {
      if (!handleHostKeyError(s, err)) toast(err.message, true);
      btn.disabled = false; btn.textContent = 'Run discovery';
    }
  });
  $('#ov-test').addEventListener('click', async () => {
    const btn = $('#ov-test');
    btn.disabled = true; btn.textContent = 'Testing…';
    try {
      const r = await api(`/api/servers/${s.id}/test`, { method: 'POST' });
      toast(r.ok ? 'Connection OK' : `Connection failed: ${r.stderr || `rc=${r.rc}`}`, !r.ok);
    } catch (err) {
      if (!handleHostKeyError(s, err)) toast(err.message, true);
    }
    btn.disabled = false; btn.textContent = 'Test connection';
  });
  $('#ov-edit').addEventListener('click', () => openServerForm(s));

  const reinstallBtn = $('#ov-key-reinstall');
  if (reinstallBtn) {
    reinstallBtn.addEventListener('click', async () => {
      if (!s.has_secret && !s.key_installed) {
        toast('Set a password first (Edit server) so the hub can connect once to install the key', true);
        return;
      }
      reinstallBtn.disabled = true;
      reinstallBtn.textContent = 'Working…';
      try {
        await api(`/api/servers/${s.id}/key/reinstall`, { method: 'POST' });
        toast('SSH key installed and verified');
        loadServers();
      } catch (err) {
        if (!handleHostKeyError(s, err)) toast(err.message, true);
      }
      reinstallBtn.disabled = false;
      reinstallBtn.textContent = s.key_installed ? 'Reinstall key' : 'Install hub key';
    });
  }
  const deleteKeyBtn = $('#ov-key-delete');
  if (deleteKeyBtn) {
    deleteKeyBtn.addEventListener('click', async () => {
      if (!confirm(`Remove the hub SSH key from ${s.name}?\n\nThe gre-hub-${s.id} line is deleted from authorized_keys and the local key is destroyed.`)) return;
      if (!confirm('Second confirmation: the hub will need a password to connect afterwards. Continue?')) return;
      try {
        const r = await api(`/api/servers/${s.id}/key/delete`, { method: 'POST' });
        toast(r.password_required ? 'Key removed — password required on next connect' : 'Key removed — fallback password restored');
        loadServers();
      } catch (err) { toast(err.message, true); }
    });
  }
}

// ---------- actions tab ---------------------------------------------------

const SIMPLE_ACTIONS = [
  { id: 'install_gre', label: 'Install gre-manager', desc: 'Run the official installer via curl' },
  { id: 'update', label: 'Update', desc: 'Self-update to the latest version' },
  { id: 'doctor', label: 'Doctor', desc: 'Run diagnostics (PASS/WARN/FAIL)' },
  { id: 'restart_all', label: 'Restart all tunnels', desc: 'gre --stop && gre --apply', confirm: 'Restart all tunnels on this server? Brief downtime expected.' },
  { id: 'watchdog_enable', label: 'Watchdog: enable', desc: 'Auto-heal dead tunnels' },
  { id: 'watchdog_disable', label: 'Watchdog: disable', desc: 'Stop the watchdog timer' },
  { id: 'export', label: 'Export backup', desc: 'Back up /etc/multi-gre to a tarball' },
];

const FORM_ACTIONS = [
  { id: 'setup_foreign', label: 'Configure as FOREIGN', desc: 'First-time FOREIGN setup (requires gre >= 2.6.0)', fields: [
    { name: 'foreign_ip', label: 'Foreign IP (optional)', ipRole: 'FOREIGN', includeCurrent: true, blankLabel: 'Auto-detect (default)' },
    { name: 'gre_whitelist', label: 'GRE whitelist', type: 'select', options: [['', 'default (on)'], ['on', 'on'], ['off', 'off']] },
    { name: 'icmp_drop', label: 'ICMP drop', type: 'select', options: [['', 'default (off)'], ['on', 'on'], ['off', 'off']] },
    { name: 'downtime', label: 'Downtime tolerance, minutes (default 2)', type: 'number' },
  ] },
  { id: 'setup_iran', label: 'Configure as IRAN', desc: 'First-time IRAN setup — creates the first foreign peer', suggest: true, suggestionKind: 'peer', fields: [
    { name: 'foreign_ip', label: 'Foreign IP', required: true, ipRole: 'FOREIGN', blankLabel: 'Select a FOREIGN server…' },
    { name: 'name', label: 'Peer name (optional)', maxLength: 11 },
    { name: 'idx', label: 'Index (optional)', type: 'number' },
    { name: 'key', label: 'GRE key (optional)' },
    { name: 'subnet_base', label: 'Subnet base, e.g. 10.9 (optional)' },
    { name: 'tcp_ports', label: 'TCP ports list (optional)' },
    { name: 'udp_ports', label: 'UDP ports list (optional)' },
    { name: 'downtime', label: 'Downtime tolerance, minutes (default 2)', type: 'number' },
  ] },
  { id: 'watchdog_interval', label: 'Watchdog: interval', desc: 'Set check interval (1-60 min)', fields: [
    { name: 'interval', label: 'Interval (minutes)', type: 'number', required: true },
  ] },
  { id: 'node_add', label: 'Node: add', desc: 'Add an Iran node (FOREIGN side)', suggest: true, suggestionKind: 'node', fields: [
    { name: 'name', label: 'Name', required: true, maxLength: 11 },
    { name: 'ip', label: 'Iran IP', required: true, ipRole: 'IRAN', blankLabel: 'Select an IRAN server…' },
    { name: 'idx', label: 'Index (optional)', type: 'number' },
    { name: 'key', label: 'GRE key (optional)' },
    { name: 'subnet_base', label: 'Subnet base, e.g. 10.9 (optional)' },
  ] },
  { id: 'node_remove', label: 'Node: remove', desc: 'Remove an Iran node (FOREIGN side)', fields: [
    { name: 'name', label: 'Name', required: true, statusResource: 'nodes', blankLabel: 'Select an Iran node…' },
  ] },
  { id: 'peer_add', label: 'Peer: add', desc: 'Connect to a foreign server (IRAN side)', suggest: true, suggestionKind: 'peer', fields: [
    { name: 'name', label: 'Name', required: true, maxLength: 11 },
    { name: 'foreign_ip', label: 'Foreign IP', required: true, ipRole: 'FOREIGN', blankLabel: 'Select a FOREIGN server…' },
    { name: 'iran_ip', label: 'Iran IP (optional)', ipRole: 'IRAN', includeCurrent: true, blankLabel: 'Default (current server)' },
    { name: 'subnet_base', label: 'Subnet base (optional)' },
    { name: 'idx', label: 'Index (optional)', type: 'number' },
    { name: 'key', label: 'GRE key (optional)' },
    { name: 'tcp_ports', label: 'TCP ports list (optional)' },
    { name: 'udp_ports', label: 'UDP ports list (optional)' },
  ] },
  { id: 'peer_remove', label: 'Peer: remove', desc: 'Remove one foreign peer (IRAN side)', fields: [
    { name: 'name', label: 'Name', required: true, statusResource: 'iran_peers', blankLabel: 'Select a foreign peer…' },
  ] },
  { id: 'peer_apply', label: 'Peer: apply', desc: 'Re-apply one peer tunnel + rules', fields: [
    { name: 'name', label: 'Name', required: true, statusResource: 'iran_peers', blankLabel: 'Select a foreign peer…' },
  ] },
];

function renderActions() {
  const grid = $('#action-grid');
  const all = [
    ...SIMPLE_ACTIONS.map((a) => ({ ...a, kind: 'simple' })),
    ...FORM_ACTIONS.map((a) => ({ ...a, kind: 'form' })),
    { id: 'purge', kind: 'purge', label: 'Purge everything', desc: 'Remove ALL GRE artifacts from this server' },
  ];
  grid.innerHTML = all.map((a) => `
    <button class="action-btn ${a.kind === 'purge' ? 'danger' : ''}" data-kind="${a.kind}" data-id="${a.id}">
      ${esc(a.label)}<span class="desc">${esc(a.desc)}</span>
    </button>`).join('');
  $$('.action-btn', grid).forEach((btn) => {
    btn.addEventListener('click', () => {
      const def = all.find((a) => a.id === btn.dataset.id);
      if (def.kind === 'simple') runSimpleAction(def);
      else if (def.kind === 'form') openActionForm(def);
      else openPurgeConfirm();
    });
  });
}

function setActionOutput(text, running = false) {
  const pane = $('#action-output');
  pane.textContent = text;
  pane.style.opacity = running ? '0.55' : '1';
}

const CONNECTIVITY_ACTIONS = new Set(['setup_iran', 'peer_add', 'node_add']);

function connectivityPanelHtml(data) {
  const direction = (from, to, result) => `<div class="direction"><span>${esc(from)} -&gt; ${esc(to)}</span><span>${result.reachable ? 'REACHABLE' : 'BLOCKED'}</span></div>`;
  return `<strong>${data.ok ? 'Both public paths are reachable' : 'Public path blocked · no configuration was created'}</strong>
    ${direction(data.iran.ip, data.foreign.ip, data.iran_to_foreign)}
    ${direction(data.foreign.ip, data.iran.ip, data.foreign_to_iran)}
    ${data.ok ? '' : '<div style="margin-top:8px">Fix network routing, ICMP policy, or firewall rules before trying setup again.</div>'}`;
}

async function executeAction(action, params = {}, { inline = false } = {}) {
  const s = state.current;
  if (!s) return false;
  const panel = inline ? $('#action-connectivity') : null;
  if (panel) {
    panel.className = 'connectivity-panel checking';
    panel.innerHTML = '<strong>Checking both directions…</strong>';
  }
  setActionOutput(`$ ${action} ${JSON.stringify(params)}\nrunning…`, true);
  try {
    const r = await api(`/api/servers/${s.id}/action`, { method: 'POST', body: { action, params } });
    const out = [r.stdout, r.stderr].filter(Boolean).join('\n').trim();
    const hintLine = r.hint ? `\n\nHint: ${r.hint}` : '';
    const preflightLine = r.preflight
      ? `Public preflight: IRAN -> FOREIGN ${r.preflight.iran_to_foreign.reachable ? 'PASS' : 'FAIL'}; FOREIGN -> IRAN ${r.preflight.foreign_to_iran.reachable ? 'PASS' : 'FAIL'}\n\n`
      : '';
    setActionOutput(`${preflightLine}$ ${r.command}\n(exit ${r.rc})\n\n${out || '(no output)'}${hintLine}`);
    loadServers(); // snapshot may have been refreshed
    return true;
  } catch (err) {
    if (handleHostKeyError(s, err)) {
      setActionOutput(`$ ${action}\n\nAborted: host key mismatch — see the warning dialog.`);
      return false;
    }
    if (err.data && err.data.connectivity_failed) {
      if (panel) {
        panel.className = 'connectivity-panel';
        panel.innerHTML = connectivityPanelHtml(err.data);
      }
      setActionOutput(`$ ${action}\n\nBLOCKED: ${err.message}`);
      loadServers();
      return false;
    }
    setActionOutput(`$ ${action}\n\nError: ${err.message}`);
    if (inline) $('#action-form-error').textContent = err.message;
    return false;
  }
}

function runSimpleAction(def) {
  if (def.confirm && !confirm(def.confirm)) return;
  executeAction(def.id);
}

function roleServerOptions(role, includeCurrent = false) {
  const seen = new Set();
  return state.servers
    .filter((server) => includeCurrent || server.id !== (state.current && state.current.id))
    .filter((server) => ((server.snapshot && server.snapshot.roles) || [])
      .some((value) => String(value).toUpperCase() === role))
    .filter((server) => isIPv4Host(server.host))
    .filter((server) => !seen.has(server.host) && seen.add(server.host))
    .map((server) => ({ value: server.host, label: server.name }));
}

function isIPv4Host(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function statusResourceNames(snapshot, resource) {
  const values = snapshot && snapshot.status && snapshot.status[resource];
  if (!Array.isArray(values)) return [];
  return [...new Set(values
    .map((item) => (typeof item === 'string' ? item : item && item.name))
    .map((name) => String(name || '').trim())
    .filter(Boolean))];
}

function selectOptions(items) {
  return items.map((item) => `<option value="${esc(item.value)}">${esc(item.label)} — ${esc(item.value)}</option>`).join('');
}

function randomPoolValue(values, excluded = new Set()) {
  const clean = [...new Set((Array.isArray(values) ? values : [values])
    .filter((value) => value !== undefined && value !== null && value !== '')
    .map(String))];
  const preferred = clean.filter((value) => !excluded.has(value));
  const pool = preferred.length ? preferred : clean;
  return pool.length ? pool[Math.floor(Math.random() * pool.length)] : '';
}

function openActionForm(def) {
  const fields = def.fields.map((f) => {
    if (f.type === 'select') {
      const opts = (f.options || []).map(([v, label]) => `<option value="${esc(v)}">${esc(label)}</option>`).join('');
      return `
    <div class="field">
      <label>${esc(f.label)}</label>
      <select name="${f.name}" ${f.required ? 'required' : ''}>${opts}</select>
    </div>`;
    }
    if (f.ipRole) {
      const options = roleServerOptions(f.ipRole, f.includeCurrent);
      const hint = options.length
        ? `${options.length} ${f.ipRole} server${options.length === 1 ? '' : 's'} available from Hub discovery.`
        : `No discovered ${f.ipRole} servers are currently available in this Hub.`;
      return `
    <div class="field">
      <label>${esc(f.label)}</label>
      <select name="${f.name}" ${f.required ? 'required' : ''}>
        <option value="">${esc(f.blankLabel || 'Select a server…')}</option>
        ${selectOptions(options)}
      </select>
      <span class="hint">${esc(hint)}</span>
    </div>`;
    }
    if (f.statusResource) {
      const names = statusResourceNames(state.current && state.current.snapshot, f.statusResource);
      const options = names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join('');
      return `
    <div class="field">
      <label>${esc(f.label)}</label>
      <select name="${f.name}" ${f.required ? 'required' : ''} data-status-resource="${esc(f.statusResource)}">
        <option value="">${esc(f.blankLabel || 'Select a resource…')}</option>
        ${options}
      </select>
      <span class="hint" id="${def.id}-${f.name}-status">${names.length ? `${names.length} cached option${names.length === 1 ? '' : 's'}; refreshing discovery…` : 'Loading current server resources…'}</span>
    </div>`;
    }
    const listId = def.suggest && f.name === 'subnet_base' ? `${def.id}-${f.name}-suggestions` : '';
    return `
    <div class="field">
      <label>${esc(f.label)}</label>
      <input name="${f.name}" ${f.required ? 'required' : ''} type="${f.type || 'text'}" ${f.maxLength ? `maxlength="${f.maxLength}"` : ''} ${listId ? `list="${listId}"` : ''} autocomplete="off" />
      ${listId ? `<datalist id="${listId}"></datalist><span class="hint">Choose a free suggested base or type a valid A.B value.</span>` : ''}
    </div>`;
  }).join('');
  openModal(`
    <h2>${esc(def.label)}</h2>
    <p class="sub">${esc(def.desc)}</p>
    <form id="action-form">
      ${fields}
      ${CONNECTIVITY_ACTIONS.has(def.id) ? '<div id="action-connectivity" class="hidden"></div>' : ''}
      <div class="form-error" id="action-form-error"></div>
      <div class="foot">
        ${def.suggest ? '<button type="button" class="btn btn-ghost" id="btn-suggest" title="Reload 10 collision-free values from the server (gre >= 2.8.0)">Refresh values</button>' : ''}
        <button type="button" class="btn btn-ghost" id="btn-cancel-action">Cancel</button>
        <button type="submit" class="btn">Run</button>
      </div>
    </form>`);
  $('#btn-cancel-action').addEventListener('click', closeModal);
  const resourceFields = def.fields.filter((f) => f.statusResource);
  if (resourceFields.length) {
    const refreshResources = async () => {
      const server = state.current;
      try {
        const snapshot = await api(`/api/servers/${server.id}/discover`, { method: 'POST' });
        if (snapshot.error) throw new Error(snapshot.error);
        server.snapshot = snapshot;
        const listed = state.servers.find((item) => item.id === server.id);
        if (listed) listed.snapshot = snapshot;
        for (const field of resourceFields) {
          const select = $(`#action-form [name="${field.name}"]`);
          const hint = $(`#${def.id}-${field.name}-status`);
          if (!select || !hint) continue;
          const names = statusResourceNames(snapshot, field.statusResource);
          const previous = select.value;
          select.innerHTML = `<option value="">${esc(field.blankLabel || 'Select a resource…')}</option>${names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join('')}`;
          if (names.includes(previous)) select.value = previous;
          hint.textContent = names.length
            ? `${names.length} current option${names.length === 1 ? '' : 's'} from live discovery.`
            : `No configured ${field.statusResource === 'nodes' ? 'Iran nodes' : 'foreign peers'} found on this server.`;
        }
      } catch (err) {
        for (const field of resourceFields) {
          const hint = $(`#${def.id}-${field.name}-status`);
          if (hint) hint.textContent = `Discovery failed: ${err.message}. Cached options are shown when available.`;
        }
      }
    };
    refreshResources();
  }
  const suggestBtn = $('#btn-suggest');
  if (suggestBtn) {
    const SUGGEST_MAP = { name: 'name', subnet_base: 'subnet_base', idx: 'idx', key: 'key', tcp_port: 'tcp_ports', udp_port: 'udp_ports' };
    const loadSuggestions = async ({ fillEmpty = false, refreshPorts = false, base = '' } = {}) => {
      const form = $('#action-form');
      const errEl = $('#action-form-error');
      errEl.textContent = '';
      suggestBtn.disabled = true;
      suggestBtn.textContent = 'Loading values…';
      try {
        const s = state.current;
        const data = await api(`/api/servers/${s.id}/suggest-peer`, {
          method: 'POST',
          body: { kind: def.suggestionKind || 'peer', count: 10, ...(base ? { base } : {}) },
        });
        let filled = 0;
        for (const [src, dest] of Object.entries(SUGGEST_MAP)) {
          if (!form[dest]) continue;
          const values = Array.isArray(data[src]) ? data[src] : [data[src]];
          const clean = values.filter((value) => value !== undefined && value !== null && value !== '');
          const list = $(`#${def.id}-${dest}-suggestions`);
          if (list) list.innerHTML = clean.map((value) => `<option value="${esc(value)}"></option>`).join('');
          if (fillEmpty && !['tcp_ports', 'udp_ports'].includes(dest) && !form[dest].value && clean.length) {
            form[dest].value = randomPoolValue(clean);
            filled++;
          }
        }
        if (refreshPorts) {
          const tcp = form.tcp_ports ? randomPoolValue(data.tcp_port) : '';
          const udp = form.udp_ports ? randomPoolValue(data.udp_port, new Set(tcp ? [tcp] : [])) : '';
          if (form.tcp_ports && tcp) { form.tcp_ports.value = tcp; filled++; }
          if (form.udp_ports && udp) { form.udp_ports.value = udp; filled++; }
        }
        if (fillEmpty) toast(filled ? `Loaded 10-value pools and filled ${filled} fields` : 'Suggestion lists refreshed');
      } catch (err) {
        errEl.textContent = err.message;
      }
      suggestBtn.disabled = false;
      suggestBtn.textContent = 'Refresh values';
    };
    suggestBtn.addEventListener('click', () => loadSuggestions({ fillEmpty: true, refreshPorts: true, base: $('#action-form').subnet_base?.value.trim() || '' }));
    const baseInput = $('#action-form').subnet_base;
    if (baseInput) baseInput.addEventListener('change', () => loadSuggestions({ base: baseInput.value.trim() }));
    loadSuggestions({ refreshPorts: true });
  }
  $('#action-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const params = {};
    for (const f of def.fields) {
      const v = form[f.name].value.trim();
      if (v !== '') params[f.name] = f.type === 'number' ? Number(v) : v;
    }
    if (!CONNECTIVITY_ACTIONS.has(def.id)) {
      closeModal();
      executeAction(def.id, params);
      return;
    }
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    submit.textContent = 'Checking…';
    $('#action-form-error').textContent = '';
    const ok = await executeAction(def.id, params, { inline: true });
    if (ok) closeModal();
    else if ($('#action-form')) {
      submit.disabled = false;
      submit.textContent = 'Run';
    }
  });
}

function openPurgeConfirm() {
  openModal(`
    <h2>Purge server</h2>
    <p class="sub">This removes <strong>every</strong> GRE-related artifact from
    <strong>${esc(state.current.name)}</strong>: tunnels, iptables rules, systemd units and configs.
    This cannot be undone.</p>
    <form id="purge-form">
      <div class="field">
        <label>Type <kbd>PURGE</kbd> to confirm</label>
        <input name="confirm" autocomplete="off" required />
      </div>
      <div class="form-error" id="purge-error"></div>
      <div class="foot">
        <button type="button" class="btn btn-ghost" id="btn-cancel-purge">Cancel</button>
        <button type="submit" class="btn btn-danger">Purge everything</button>
      </div>
    </form>`);
  $('#btn-cancel-purge').addEventListener('click', closeModal);
  $('#purge-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const val = e.target.confirm.value.trim();
    if (val !== 'PURGE') {
      $('#purge-error').textContent = 'Type PURGE exactly to proceed.';
      return;
    }
    closeModal();
    executeAction('purge', { confirm: 'PURGE' });
  });
}

// ---------- terminal tab --------------------------------------------------

const termState = { term: null, fit: null, ws: null, serverId: null, resizeObserver: null };

function destroyTerminal() {
  if (termState.ws) { try { termState.ws.close(); } catch { /* noop */ } }
  if (termState.resizeObserver) termState.resizeObserver.disconnect();
  if (termState.term) { termState.term.dispose(); }
  termState.term = null;
  termState.fit = null;
  termState.ws = null;
  termState.serverId = null;
  termState.resizeObserver = null;
  const bar = $('#term-status');
  if (bar) bar.textContent = 'Disconnected';
}

async function initTerminal() {
  const s = state.current;
  if (!s) return;
  if (termState.serverId === s.id && termState.ws && termState.ws.readyState === WebSocket.OPEN) return;
  destroyTerminal();
  connectTerminal(s);
}

async function connectTerminal(s) {
  const status = $('#term-status');
  status.textContent = 'Connecting…';
  termState.serverId = s.id;

  const container = $('#terminal-container');
  container.innerHTML = '';
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: "'SF Mono', 'JetBrains Mono', Consolas, monospace",
    fontSize: 13,
    theme: { background: '#0c0c0b', foreground: '#d6d3cb' },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(container);
  fit.fit();
  termState.term = term;
  termState.fit = fit;

  termState.resizeObserver = new ResizeObserver(() => {
    try { fit.fit(); } catch { /* hidden */ }
  });
  termState.resizeObserver.observe(container);

  let ticket;
  try {
    ({ ticket } = await api(`/api/servers/${s.id}/terminal-ticket`, { method: 'POST' }));
  } catch (err) {
    status.textContent = `Ticket failed: ${err.message}`;
    return;
  }

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/terminal?ticket=${encodeURIComponent(ticket)}`);
  termState.ws = ws;

  const sendSize = () => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    }
  };

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'init', cols: term.cols, rows: term.rows }));
    status.textContent = `Connected to ${s.name}`;
  };
  ws.onmessage = (e) => term.write(e.data);
  ws.onclose = () => { status.textContent = 'Disconnected'; };
  ws.onerror = () => { status.textContent = 'Connection error'; };

  term.onData((d) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'data', data: d }));
  });
  term.onResize(sendSize);
}

$('#btn-term-reconnect').addEventListener('click', () => {
  if (state.current) { destroyTerminal(); connectTerminal(state.current); }
});

// ---------- automatic GRE + 3x-ui routes ---------------------------------

function panelsHtml() {
  return `
    <div class="section">
      <h3>Saved 3x-ui panels</h3>
      ${state.panels.length ? `
        <table class="data">
          <thead><tr><th>Name</th><th>URL</th><th>3x-ui</th><th>Client model</th><th>Host model</th><th>Checked</th><th></th></tr></thead>
          <tbody>${state.panels.map((panel) => `
            <tr>
              <td><strong>${esc(panel.name)}</strong><div class="muted">${esc(panel.auth_type === 'token' ? 'API token' : 'Username + password')}</div></td>
              <td>${esc(panel.base_url)}</td>
              <td>${panel.panel_version ? `<span class="badge blue">v${esc(panel.panel_version)}</span>` : '<span class="badge gray">unknown</span>'}
                  ${panel.last_probe_error ? `<div class="muted" title="${esc(panel.last_probe_error)}">probe failed</div>` : ''}</td>
              <td>${esc(clientModelLabel(panel.client_model))}</td>              <td>${esc(hostModelLabel(panel.host_mode))}</td>
              <td class="muted">${panel.last_probe_at ? timeAgo(panel.last_probe_at) : 'never'}</td>
              <td class="row-actions">
                <button class="btn btn-ghost btn-sm btn-probe-panel" data-id="${panel.id}">Probe</button>
                <button class="btn btn-danger btn-sm btn-delete-panel" data-id="${panel.id}">Delete</button>
              </td>
            </tr>`).join('')}</tbody>
        </table>` : '<div class="empty">No 3x-ui panel saved yet.</div>'}
    </div>`;
}

function bindPanelActions(wrap) {
  $$('.btn-delete-panel', wrap).forEach((btn) => btn.addEventListener('click', async () => {
    if (!confirm('Delete this saved panel? Routes using it prevent deletion.')) return;
    btn.disabled = true;
    try {
      await api(`/api/xui-panels/${btn.dataset.id}`, { method: 'DELETE' });
      toast('Panel deleted');
      await loadRoutes();
    } catch (err) { toast(err.message, true); btn.disabled = false; }
  }));
  $$('.btn-probe-panel', wrap).forEach((btn) => btn.addEventListener('click', async () => {
    btn.disabled = true; btn.textContent = 'Probing…';
    try {
      const result = await api(`/api/xui-panels/${btn.dataset.id}/probe`, { method: 'POST' });
      const panel = result.probe && result.probe.panel;
      toast(panel ? `Panel: ${panel.panel_version ? `v${panel.panel_version}` : 'version unknown'} · ${clientModelLabel(panel.client_model)}` : 'Panel probed');
      await loadRoutes();
    } catch (err) { toast(err.message, true); btn.disabled = false; btn.textContent = 'Probe'; }
  }));
}

async function loadRoutes() {
  const wrap = $('#routes-body');
  try {
    [state.routes, state.panels] = await Promise.all([api('/api/gre-routes'), api('/api/xui-panels')]);
    if (!state.routes.length) {
      wrap.innerHTML = panelsHtml() + `<div class="empty">No automatic routes yet. ${state.panels.length ? 'Create the first route.' : 'Add a 3x-ui panel first.'}</div>`;
      bindPanelActions(wrap);
      return;
    }
    wrap.innerHTML = panelsHtml() + `
      <table class="data">
        <thead><tr><th>Route</th><th>IRAN endpoint</th><th>FOREIGN</th><th>Panel</th><th>Mode</th><th>Status</th><th>Created</th><th></th></tr></thead>
        <tbody>${state.routes.map((r) => `
          <tr>
            <td><strong>${esc(r.name)}</strong><div class="muted">${esc(r.method)}</div>${Number(r.attempt_no) > 1 ? `<div class="muted">attempt #${Number(r.attempt_no)}</div>` : ''}</td>
            <td>${esc(r.iran_host)}:${esc(r.port)}<div class="muted">TCP + UDP</div></td>
            <td>${esc(r.foreign_name)}</td>
            <td>${esc(r.panel_name)}<div class="muted">${esc(r.panel_version ? `3x-ui v${r.panel_version}` : 'version unknown')}</div><div class="muted">${esc(clientModelLabel(r.client_model))}</div></td>
            <td>${esc(hostModelLabel(r.host_mode || r.capability) || 'pending')}</td>
            <td><span class="badge ${routeStatusClass(r.status)}">${esc(r.status)}</span>${r.current_stage ? `<div class="muted">at ${esc(r.current_stage)}</div>` : ''}${r.last_error ? `<div class="muted">${esc(routeErrorText(r.last_error))}</div>` : ''}</td>
            <td>${timeAgo(r.created_at)}</td>
            <td class="row-actions">
              <button class="btn btn-ghost btn-sm btn-timeline" data-id="${r.id}" data-name="${esc(r.name)}">Timeline</button>
              ${r.status === 'ACTIVE'
                ? `<button class="btn btn-ghost btn-sm btn-config" data-id="${r.id}">Config</button>`
                : `<button class="btn btn-ghost btn-sm" disabled title="No active configuration — provisioning did not complete.">Config</button>`}
              <button class="btn btn-ghost btn-sm btn-reconcile" data-id="${r.id}">Reconcile</button>
              <button class="btn btn-ghost btn-sm btn-edit-route" data-id="${r.id}">Edit</button>
              ${r.status === 'ACTIVE' ? '' : `<button class="btn btn-ghost btn-sm btn-retry-route" data-id="${r.id}">Retry</button>`}
              <button class="btn btn-danger btn-sm btn-delete-route" data-id="${r.id}">Delete</button>
            </td>
          </tr>`).join('')}</tbody>
      </table>`;
    $$('.btn-timeline', wrap).forEach((btn) => btn.addEventListener('click', () => {
      openRouteTimeline({ id: Number(btn.dataset.id), name: btn.dataset.name });
    }));
    $$('.btn-config', wrap).forEach((btn) => btn.addEventListener('click', () => {
      openRouteConfigModal(Number(btn.dataset.id));
    }));
    $$('.btn-reconcile', wrap).forEach((btn) => btn.addEventListener('click', () => {
      openReconcileModal(Number(btn.dataset.id), btn);
    }));
    $$('.btn-edit-route', wrap).forEach((btn) => btn.addEventListener('click', () => {
      openEditRouteModal(Number(btn.dataset.id));
    }));
    $$('.btn-retry-route', wrap).forEach((btn) => btn.addEventListener('click', async () => {
      const route = state.routes.find((r) => Number(r.id) === Number(btn.dataset.id));
      if (!confirm(`Retry provisioning for ${route ? route.name : `route ${btn.dataset.id}`}?\n\nReconcile runs first; a retry is refused if the previous attempt left resources behind.`)) return;
      btn.disabled = true; btn.textContent = 'Retrying…';
      try {
        const result = await api(`/api/gre-routes/${btn.dataset.id}/retry`, { method: 'POST' });
        toast(`Attempt #${result.attempt_no} started`);
        startProvisioningTimeline({
          route_id: Number(btn.dataset.id),
          name: route ? route.name : '',
          port: route ? route.port : null,
          status: 'RESERVED',
          client_email: route ? route.client_email : null,
          client_mode: route ? route.client_mode : null,
          client_model: route ? route.client_model : null,
        });
      } catch (err) { toast(err.message, true); btn.disabled = false; btn.textContent = 'Retry'; }
    }));
    $$('.btn-delete-route', wrap).forEach((btn) => btn.addEventListener('click', () => {
      openDeleteRouteModal(Number(btn.dataset.id));
    }));
    bindPanelActions(wrap);
  } catch (err) { wrap.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
}

// last_error may be a JSON blob (reconcile detail) or a plain message.
function routeErrorText(value) {
  const text = String(value || '');
  if (!text.startsWith('{')) return text;
  try {
    const parsed = JSON.parse(text);
    if (parsed.summary) return parsed.summary;
    if (parsed.deleteFailures) return `delete incomplete: ${parsed.deleteFailures.map((f) => f.name).join(', ')}`;
  } catch { /* fall through */ }
  return text.slice(0, 200);
}

$('#btn-add-panel').addEventListener('click', () => {
  openModal(`
    <h2>Add 3x-ui panel</h2>
    <p class="sub">3.x automation should use an admin API token. Legacy 2.x panels use username and password. Credentials are encrypted at rest.</p>
    <form id="panel-form">
      <div class="field"><label>Name</label><input name="name" required maxlength="80" /></div>
      <div class="field"><label>Panel URL</label><input name="base_url" type="url" required placeholder="https://panel.example.com:2053/path" /></div>
      <div class="field"><label>Authentication</label><select name="auth_type"><option value="token">API token — 3.x (recommended)</option><option value="password">Username + password — legacy 2.x</option></select></div>
      <div class="field" id="panel-token-wrap"><label>Admin API token</label><input name="token" type="password" required autocomplete="off" /><div class="hint">3x-ui: Settings → Security → API Token. Use an admin-scope token.</div></div>
      <div id="panel-password-wrap" class="hidden">
        <div class="field"><label>Username</label><input name="username" autocomplete="username" /></div>
        <div class="field"><label>Password</label><input name="password" type="password" autocomplete="current-password" /></div>
      </div>
      <div class="form-error" id="panel-error"></div>
      <div class="foot"><button type="button" class="btn btn-ghost modal-cancel">Cancel</button><button class="btn">Save panel</button></div>
    </form>`);
  $('.modal-cancel').addEventListener('click', closeModal);
  const panelForm = $('#panel-form');
  const syncPanelAuth = () => {
    const tokenMode = panelForm.auth_type.value === 'token';
    $('#panel-token-wrap').classList.toggle('hidden', !tokenMode);
    $('#panel-password-wrap').classList.toggle('hidden', tokenMode);
    panelForm.token.required = tokenMode;
    panelForm.username.required = !tokenMode;
    panelForm.password.required = !tokenMode;
  };
  panelForm.auth_type.addEventListener('change', syncPanelAuth);
  syncPanelAuth();
  $('#panel-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    try {
      const saved = await api('/api/xui-panels', { method: 'POST', body: {
        name: form.name.value.trim(), base_url: form.base_url.value.trim(),
        auth_type: form.auth_type.value, username: form.username.value.trim(),
        password: form.password.value, token: form.token.value,
      } });
      closeModal();
      await loadRoutes();
      // The detected client model is the thing users actually need to know
      // about their panel; surface it without making them read API versions.
      let model = null;
      try {
        const probe = await api(`/api/xui-panels/${saved.id}/clients`);
        model = probe && probe.client_model;
      } catch { /* detection is best effort here */ }
      toast(`3x-ui panel saved${model ? ` — ${clientModelLabel(model)}` : ''}`);
    } catch (err) { $('#panel-error').textContent = err.message; }
  });
});

$('#btn-add-route').addEventListener('click', async () => {
  try {
    state.panels = await api('/api/xui-panels');
    if (!state.servers.length) await loadServers();
    if (!state.panels.length) { toast('Add a 3x-ui panel first', true); return; }
  } catch (err) { toast(err.message, true); return; }
  const roleHas = (server, role) => ((server.snapshot && server.snapshot.roles) || []).map((x) => String(x).toUpperCase()).includes(role);
  const iranServers = state.servers.filter((s) => roleHas(s, 'IRAN'));
  const foreignServers = state.servers.filter((s) => roleHas(s, 'FOREIGN'));
  if (!iranServers.length || !foreignServers.length) { toast('Discover at least one IRAN and one FOREIGN server first', true); return; }
  const options = (rows) => rows.map((x) => `<option value="${x.id}">${esc(x.name)} — ${esc(x.host)}</option>`).join('');
  openModal(`
    <h2>Create automatic route</h2>
    <p class="sub">The selected port is checked against listeners, nftables, iptables, Docker, 3x-ui and the permanent registry before it is reserved. Nothing is changed on either server until the client selection has been validated.</p>
    <form id="route-form">
      <div class="field"><label>Route name</label><input name="name" required maxlength="40" placeholder="IR05-DE02" /></div>
      <div class="field"><label>IRAN server</label><select name="iran_server_id">${options(iranServers)}</select></div>
      <div class="field"><label>FOREIGN server</label><select name="foreign_server_id">${options(foreignServers)}</select></div>
      <div class="field"><label>3x-ui panel</label><select name="panel_id">${state.panels.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join('')}</select>
        <div class="hint" id="panel-info"></div>
      </div>
      <div class="field">
        <label>3x-ui client</label>
        <select name="client_mode" id="client-mode">
          <option value="new">Add new client...</option>
          <option value="existing">Attach an existing client</option>
        </select>
        <div class="hint" id="client-model"></div>
        <div class="hint" id="client-choice-hint"></div>
      </div>
      <div class="field hidden" id="existing-client-wrap">
        <label>Search existing client</label>
        <input name="client_search" id="client-search" list="client-options" autocomplete="off"
               spellcheck="false" placeholder="Type a name, e.g. navid" />
        <datalist id="client-options"></datalist>
        <div class="hint" id="client-load"></div>
      </div>
      <div class="field" id="new-client-wrap"><label>New client name</label><input name="client_name" required maxlength="80" placeholder="navid" /><div class="hint">Creates a new 3x-ui client for this route.</div></div>
      <div class="field"><label>Preferred port (optional)</label><input name="port" type="number" min="1024" max="65535" placeholder="auto: 3000–3999" /></div>
      <div id="port-result" class="hint">A safe TCP+UDP port will be selected before any changes are made.</div>
      <div class="form-error" id="route-error"></div>
      <div class="foot"><button type="button" class="btn btn-ghost modal-cancel">Cancel</button><button type="button" class="btn btn-ghost" id="btn-check-port">Check port</button><button class="btn" id="btn-create-route">Create route</button></div>
    </form>`);
  $('.modal-cancel').addEventListener('click', closeModal);
  const form = $('#route-form');
  let clientModel = null;
  const CLIENT_PAGE_SIZE = 20;
  const CLIENT_SEARCH_DEBOUNCE_MS = 250;
  // Cached results keyed by search term, so re-typing a prefix is instant and we
  // never re-query the panel for the same page of a live dialog.
  const clientPageCache = new Map();
  // Labels currently offered by the datalist, plus the last label the user picked.
  // This lets the dialog reject a typed-but-nonexistent client before submitting.
  let clientOptions = [];
  let pickedClient = '';
  const isNewClient = () => form.client_mode.value === 'new';
  const clientHint = () => {
    if (isNewClient()) return 'Creates a new 3x-ui client for this route.';
    return clientModel === 'embedded'
      ? 'Client credentials are stored inside each inbound; the real credential of the selected client is reused.'
      : 'Will be attached to the new inbound; the client will not be recreated.';
  };
  const typedClientValue = () => String(form.client_search.value || '').trim();
  const selectedEmail = () => {
    const typed = typedClientValue();
    if (pickedClient && typed === pickedClient) return pickedClient.split(/\s+—\s+/)[0].trim();
    // Fall back to the "email — attachment" prefix, then to the raw text.
    return typed.split(/\s+—\s+/)[0].trim();
  };
  const syncClient = () => {
    const isNew = isNewClient();
    $('#new-client-wrap').classList.toggle('hidden', !isNew);
    $('#existing-client-wrap').classList.toggle('hidden', isNew);
    form.client_name.required = isNew;
    const hint = $('#new-client-wrap .hint');
    if (hint) hint.textContent = clientHint();
    // Helper copy for the currently selected intent, shown next to the select.
    const fieldHint = $('#client-choice-hint');
    if (fieldHint) fieldHint.textContent = isNew ? '' : clientHint();
    renderPanelInfo();
  };
  // Everything we know about the selected panel, before anything is created.
  const renderPanelInfo = () => {
    const box = $('#panel-info');
    if (!box) return;
    const panel = state.panels.find((p) => String(p.id) === String(form.panel_id.value)) || {};
    const isNew = isNewClient();
    const rows = [
      `Panel: ${panel.name || '—'}`,
      `3x-ui: ${panel.panel_version ? `v${panel.panel_version}` : 'version unknown'}`,
      `Client model: ${clientModelLabel(panel.client_model || clientModel)}`,
      `Host model: ${hostModelLabel(panel.host_mode)}`,
    ];
    if (!isNew) {
      rows.push(panel.client_model === 'embedded' || clientModel === 'embedded'
        ? 'Legacy embedded client model: the selected client\'s real credential is reused from its inbound.'
        : 'Existing client will be attached to the new inbound. It will not be recreated.');
    }
    box.innerHTML = rows.map((line) => esc(line)).join('<br>');
    // The model comes from the hub's stored panel probe, so this is known before
    // the dialog finishes opening — no "Detecting…" round trip.
    const model = $('#client-model');
    if (model) {
      const resolved = panel.client_model || clientModel;
      if (resolved === 'first_class') model.textContent = '3x-ui client model: First-class / multi-inbound';
      else if (resolved === 'embedded') model.textContent = '3x-ui client model: Legacy embedded';
      else model.textContent = '3x-ui client model: unknown (probe the panel)';
    }
  };
  const clientOptionLabel = (client) => {
    const ids = Array.isArray(client.inbound_ids) ? client.inbound_ids : [];
    const where = client.inbound_remark
      || (ids.length ? `inbound ${ids[0]}${ids.length > 1 ? ` +${ids.length - 1}` : ''}` : 'not attached yet');
    return `${client.email} — ${where}`;
  };
  // One page of clients, never the whole inventory. `search` goes to the panel so
  // a busy panel with thousands of clients stays responsive. A superseded search
  // is aborted so a slow response cannot land after a newer one.
  let clientFetchController = null;
  const fetchClientPage = async (search = '', { abortPrevious = false } = {}) => {
    const key = search.trim().toLowerCase();
    if (clientPageCache.has(key)) return clientPageCache.get(key);
    if (abortPrevious && clientFetchController) {
      try { clientFetchController.abort(); } catch { /* already finished */ }
    }
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    if (abortPrevious) clientFetchController = controller;
    const qs = new URLSearchParams({ paged: '1', page: '1', pageSize: String(CLIENT_PAGE_SIZE) });
    if (key) qs.set('search', key);
    let payload;
    try {
      payload = await api(`/api/xui-panels/${form.panel_id.value}/clients?${qs.toString()}`,
        controller ? { signal: controller.signal } : undefined);
    } catch (err) {
      if (err && (err.name === 'AbortError' || /abort/i.test(err.message))) return null;
      throw err;
    }
    const result = {
      clients: (payload && payload.clients) || [],
      total: payload && payload.total,
      paged: !!(payload && payload.paged),
    };
    if (!search.trim()) clientModel = (payload && payload.client_model) || clientModel;
    clientPageCache.set(key, result);
    return result;
  };
  const renderClientOptions = (clients, { searching = false, total = null } = {}) => {
    const list = $('#client-options');
    clientOptions = clients.map((client) => clientOptionLabel(client));
    list.innerHTML = clientOptions.map((label) => `<option value="${esc(label)}"></option>`).join('');
    const shown = clients.length;
    let text;
    if (!shown) text = searching ? 'No matching client.' : 'No client found; create a new one instead.';
    else if (searching) text = `${shown} match(es)${Number.isFinite(total) ? ` of ${total}` : ''} — keep typing to narrow.`;
    else text = `Showing the first ${shown}${Number.isFinite(total) ? ` of ${total}` : ''} client(s) — type to search.`;
    $('#client-load').textContent = text;
    // A slow response must not wipe what the user already committed to.
    if (pickedClient && !clientOptions.includes(pickedClient)) {
      form.client_search.value = '';
      pickedClient = '';
    }
  };
  // Seed the picker with one page. Never blocks the dialog.
  const loadInitialClients = async () => {
    try {
      const result = await fetchClientPage('');
      if (!result) return;
      renderClientOptions(result.clients, { total: result.total });
    } catch (err) {
      $('#client-load').textContent = err.message;
    }
  };
  // Debounced paged search. Two guards against a stale result winning: the
  // in-flight request is aborted, and a sequence number drops any response that
  // still arrives out of order.
  let searchTimer = null;
  let searchSeq = 0;
  const onClientSearchInput = () => {
    clearTimeout(searchTimer);
    // Track an exact datalist pick (datalist selection fires `input`).
    pickedClient = clientOptions.includes(typedClientValue()) ? typedClientValue() : '';
    const term = typedClientValue();
    if (!term) { loadInitialClients(); return; }
    $('#client-load').textContent = 'Searching…';
    searchTimer = setTimeout(async () => {
      const seq = ++searchSeq;
      try {
        const result = await fetchClientPage(term, { abortPrevious: true });
        if (!result || seq !== searchSeq) return;
        renderClientOptions(result.clients, { searching: true, total: result.total });
      } catch (err) {
        if (seq === searchSeq) $('#client-load').textContent = err.message;
      }
    }, CLIENT_SEARCH_DEBOUNCE_MS);
  };
  const body = () => {
    const isNew = isNewClient();
    return {
      name: form.name.value.trim(),
      iran_server_id: Number(form.iran_server_id.value),
      foreign_server_id: Number(form.foreign_server_id.value),
      panel_id: Number(form.panel_id.value),
      client_mode: isNew ? 'new' : 'existing',
      client_email: isNew ? form.client_name.value.trim() : selectedEmail(),
      port: form.port.value ? Number(form.port.value) : undefined,
      range_start: 3000, range_end: 3999,
    };
  };
  const checkPort = async () => {
    const btn = $('#btn-check-port'); btn.disabled = true; btn.textContent = 'Checking…';
    try {
      const r = await api('/api/gre-routes/recommend-port', { method: 'POST', body: body() });
      form.port.value = r.port;
      const occupied = r.occupied_ports && r.occupied_ports.length ? r.occupied_ports.join(', ') : 'none in scanned candidates';
      $('#port-result').innerHTML = `<span class="badge green">Suggested: ${r.port} FREE</span> TCP: ${esc(r.tcp)} / UDP: ${esc(r.udp)} / 3x-ui: ${esc(r.xui)} / GRE: ${esc(r.gre)}<br><strong>Occupied:</strong> ${esc(occupied)}`;
    } catch (err) { $('#route-error').textContent = err.message; }
    finally { btn.disabled = false; btn.textContent = 'Check port'; }
  };
  $('#btn-check-port').addEventListener('click', checkPort);
  form.client_mode.addEventListener('change', syncClient);
  form.client_search.addEventListener('input', onClientSearchInput);
  form.panel_id.addEventListener('change', async () => {
    clientModel = null;
    clientPageCache.clear();
    searchSeq++;
    form.client_search.value = '';
    renderPanelInfo();
    // Independent work: neither waits for the other.
    await Promise.all([loadInitialClients(), checkPort()]);
  });
  form.iran_server_id.addEventListener('change', checkPort);
  form.foreign_server_id.addEventListener('change', checkPort);
  syncClient();
  // The port check and the first client page are independent requests: run them
  // together so the dialog is usable as soon as either finishes.
  await Promise.all([loadInitialClients(), checkPort()]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#btn-create-route'); btn.disabled = true; btn.textContent = 'Creating…';
    $('#route-error').textContent = '';
    const payload = body();
    // An existing client must have come from the panel listing; a typo would
    // otherwise fail later with a confusing panel-side error.
    if (payload.client_mode === 'existing') {
      const typed = typedClientValue();
      const known = clientOptions.includes(typed) || (pickedClient && typed === pickedClient);
      if (!typed) {
        $('#route-error').textContent = 'Select an existing client or switch to "Add new client...".';
        btn.disabled = false; btn.textContent = 'Create route';
        return;
      }
      if (!known) {
        $('#route-error').textContent = `"${typed}" is not one of the listed clients. Pick one from the suggestions.`;
        btn.disabled = false; btn.textContent = 'Create route';
        return;
      }
    }
    try {
      // 202 + route_id comes back as soon as validation, client preflight,
      // port reservation and the route row are done. The rest runs in the
      // hub and is streamed through route_events.
      const created = await api('/api/gre-routes', { method: 'POST', body: payload, ok: [202] });
      loadRoutes();
      startProvisioningTimeline(created);
    } catch (err) {
      $('#route-error').textContent = err.message;
      btn.disabled = false; btn.textContent = 'Create route';
    }
  });
});

// ---------- reconcile modal ----------------------------------------------

function componentRow(component) {
  const cls = component.status === 'PASS' ? 'green' : 'red';
  return `<tr>
    <td><strong>${esc(component.name)}</strong></td>
    <td class="mono">${esc(component.expected)}</td>
    <td class="mono">${esc(component.actual)}</td>
    <td><span class="badge ${cls}">${esc(component.status)}</span></td>
    <td class="muted">${esc(component.detail || '')}</td>
  </tr>`;
}

// Persistent route configuration.
//
// The config comes from the hub's encrypted route row (GET /gre-routes/:id/config),
// so it is still available after a browser refresh and after the hub restarts.
// Copying never contacts 3x-ui, never re-creates the client and never changes the
// password.
async function openRouteConfigModal(routeId) {
  let config;
  try {
    config = await api(`/api/gre-routes/${routeId}/config`);
  } catch (err) {
    toast(err.message, true);
    return;
  }
  const link = String(config.link || '');
  const masked = link ? `${link.slice(0, 12)}${'•'.repeat(Math.max(8, Math.min(24, link.length - 12)))}` : '';
  const outboundJson = config.outbound ? JSON.stringify(config.outbound, null, 2) : '';
  openModal(`
    <h2>Configuration — ${esc(config.name || `route ${routeId}`)}</h2>
    <p class="sub">Endpoint <strong>${esc(config.endpoint?.host || '—')}:${esc(config.endpoint?.port ?? '—')}</strong>
      · method <strong>${esc(config.method || '—')}</strong>
      · client <strong>${esc(config.client_email || '—')}</strong></p>

    <div class="field">
      <label>Shadowsocks config</label>
      <div class="hint" id="cfg-link">${esc(masked)}</div>
      <div class="foot" style="justify-content:flex-start">
        <button type="button" class="btn btn-sm" id="btn-reveal-config">Reveal</button>
        <button type="button" class="btn btn-sm" id="btn-copy-config">Copy config</button>
        <button type="button" class="btn btn-ghost btn-sm" id="btn-copy-outbound">Copy JSON</button>
        <button type="button" class="btn btn-ghost btn-sm" id="btn-show-qr">Show QR</button>
      </div>
    </div>

    <div class="field hidden" id="cfg-qr-wrap"><div id="cfg-qr"></div></div>

    <div class="field">
      <label>Outbound JSON</label>
      <pre class="cfg-out" id="cfg-outbound">${esc(outboundJson)}</pre>
    </div>

    <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);

  $('.modal-cancel').addEventListener('click', closeModal);

  const copy = async (text, label) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for a non-secure origin, where the async clipboard API is absent.
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      toast(`${label} copied`);
    } catch (err) {
      toast(`Copy failed: ${err.message}`, true);
    }
  };

  $('#btn-reveal-config').addEventListener('click', () => {
    $('#cfg-link').textContent = link;
    toast('Configuration revealed');
  });
  $('#btn-copy-config').addEventListener('click', () => copy(link, 'Config'));
  $('#btn-copy-outbound').addEventListener('click', () => copy(outboundJson, 'Outbound JSON'));
  $('#btn-show-qr').addEventListener('click', async () => {
    const wrap = $('#cfg-qr-wrap');
    if (!wrap) return;
    if (!wrap.classList.contains('hidden')) { wrap.classList.add('hidden'); return; }
    try {
      const payload = await api(`/api/gre-routes/${routeId}?result=1`);
      if (payload.qr_data_url) {
        $('#cfg-qr').innerHTML = `<img alt="Shadowsocks QR" src="${esc(payload.qr_data_url)}" width="240" height="240" />`;
      } else {
        $('#cfg-qr').textContent = 'QR code unavailable.';
      }
    } catch (err) {
      $('#cfg-qr').textContent = err.message;
    }
    wrap.classList.remove('hidden');
  });
}

async function openReconcileModal(routeId, button = null) {
  if (button) { button.disabled = true; button.textContent = 'Checking…'; }
  let result;
  try {
    result = await api(`/api/gre-routes/${routeId}/reconcile`, { method: 'POST' });
  } catch (err) {
    toast(err.message, true);
    if (button) { button.disabled = false; button.textContent = 'Reconcile'; }
    return;
  }
  const summaryClass = result.healthy ? 'green' : 'red';
  openModal(`
    <h2>Reconcile ${esc(result.name || `route ${routeId}`)}</h2>
    <p class="sub">Desired state: <strong>${esc(result.desiredState)}</strong> · current: <strong>${esc(result.status)}</strong>
      ${Number(result.attemptNo) > 1 ? `· attempt #${Number(result.attemptNo)}` : ''}</p>
    <div class="tl-summary ${result.healthy ? 'ok' : ''}" style="background:var(--${summaryClass}-bg); border-color:var(--${summaryClass}-fg); color:var(--${summaryClass}-fg)">
      <span class="badge ${summaryClass}">${result.healthy ? 'HEALTHY' : 'ACTION NEEDED'}</span>
      <span>${esc(result.summary || '')}</span>
    </div>
    ${result.failedStage ? `<div class="hint" style="margin-bottom:10px">Last provisioning stage reached: <strong>${esc(result.failedStage)}</strong></div>` : ''}
    ${result.probeError ? `<div class="form-error">probe error: ${esc(result.probeError)}</div>` : ''}
    ${(result.notes || []).length ? `<div class="hint">${result.notes.map((n) => esc(n)).join('<br>')}</div>` : ''}
    <table class="data">
      <thead><tr><th>Component</th><th>Expected</th><th>Actual</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>${(result.components || []).map(componentRow).join('')}</tbody>
    </table>
    <div class="foot"><button class="btn modal-cancel">Close</button></div>`);
  $('.modal-cancel').addEventListener('click', () => { closeModal(); loadRoutes(); });
}

// ---------- edit route modal ----------------------------------------------

async function openEditRouteModal(routeId) {
  const route = await api(`/api/gre-routes/${routeId}`).catch(() => null);
  if (!route) { toast('Route not found', true); return; }
  const isActive = route.status === 'ACTIVE';
  const roleHas = (server, role) => ((server.snapshot && server.snapshot.roles) || []).map((x) => String(x).toUpperCase()).includes(role);
  if (!state.servers.length) await loadServers();
  const iranServers = state.servers.filter((s) => roleHas(s, 'IRAN'));
  const foreignServers = state.servers.filter((s) => roleHas(s, 'FOREIGN'));
  if (!state.panels.length) state.panels = await api('/api/xui-panels');
  const options = (rows, selected) => rows.map((x) => `<option value="${x.id}"${Number(x.id) === Number(selected) ? ' selected' : ''}>${esc(x.name)} — ${esc(x.host)}</option>`).join('');
  const disabled = isActive ? ' disabled' : '';

  openModal(`
    <h2>Edit ${esc(route.name)}</h2>
    <p class="sub">Editing changes the route's intended specification only — it never provisions.
      ${isActive ? '<strong>This route is ACTIVE, so infrastructure fields are locked.</strong>' : 'Retry afterwards to apply the new specification.'}</p>
    <form id="edit-route-form">
      <div class="field"><label>Route name</label><input name="name" required maxlength="40" value="${esc(route.name)}" /></div>
      <div class="field"><label>IRAN server</label><select name="iran_server_id"${disabled}>${options(iranServers, route.iran_server_id)}</select></div>
      <div class="field"><label>FOREIGN server</label><select name="foreign_server_id"${disabled}>${options(foreignServers, route.foreign_server_id)}</select></div>
      <div class="field"><label>3x-ui panel</label><select name="panel_id"${disabled}>${state.panels.map((p) => `<option value="${p.id}"${Number(p.id) === Number(route.panel_id) ? ' selected' : ''}>${esc(p.name)}</option>`).join('')}</select></div>
      <div class="field"><label>3x-ui client</label><select name="client_mode"${disabled}>
        <option value="existing"${route.client_mode === 'existing' ? ' selected' : ''}>Existing client</option>
        <option value="new"${route.client_mode === 'new' ? ' selected' : ''}>New client</option>
      </select><div class="hint">Changing this re-runs the read-only client preflight when you save.</div></div>
      <div class="field"><label>Client email</label><input name="client_email" maxlength="80" value="${esc(route.client_email || '')}"${disabled} /></div>
      <div class="form-row">
        <div class="field"><label>Preferred port</label><input name="port" type="number" min="1024" max="65535" value="${esc(route.port)}"${disabled} /></div>
        <div class="field"><label>Method</label><select name="method"${disabled}>
          ${['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm'].map((m) => `<option value="${m}"${m === route.method ? ' selected' : ''}>${m}</option>`).join('')}
        </select></div>
      </div>
      <div class="form-error" id="edit-route-error"></div>
      <div class="foot"><button type="button" class="btn btn-ghost modal-cancel">Cancel</button><button class="btn">Save specification</button></div>
    </form>`);
  $('.modal-cancel').addEventListener('click', closeModal);
  $('#edit-route-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const body = { name: form.name.value.trim() };
    if (!isActive) {
      Object.assign(body, {
        iran_server_id: Number(form.iran_server_id.value),
        foreign_server_id: Number(form.foreign_server_id.value),
        panel_id: Number(form.panel_id.value),
        client_mode: form.client_mode.value,
        client_email: form.client_email.value.trim(),
        port: Number(form.port.value),
        method: form.method.value,
      });
    }
    try {
      await api(`/api/gre-routes/${routeId}`, { method: 'PATCH', body });
      closeModal();
      await loadRoutes();
      toast('Route specification updated (nothing was provisioned)');
    } catch (err) {
      const locked = err.data && err.data.fields ? ` (locked: ${err.data.fields.join(', ')})` : '';
      $('#edit-route-error').textContent = err.message + locked;
    }
  });
}

// ---------- delete route modal --------------------------------------------

async function openDeleteRouteModal(routeId) {
  let preview;
  try {
    preview = await api(`/api/gre-routes/${routeId}/delete-preview`);
  } catch (err) { toast(err.message, true); return; }

  openModal(`
    <h2>Delete ${esc(preview.name)}?</h2>
    <p class="sub">${esc(preview.warning)}</p>
    <div class="section" style="margin-bottom:18px">
      <h3>Will remove</h3>
      <ul class="plain-list">${preview.removes.map((item) => `<li>${esc(item)}</li>`).join('')}</ul>
    </div>
    <div class="section" style="margin-bottom:18px">
      <h3>Will preserve</h3>
      <ul class="plain-list">${preview.preserves.map((item) => `<li><strong>${esc(item)}</strong></li>`).join('')}</ul>
    </div>
    <div class="form-error" id="delete-route-error"></div>
    <div class="foot">
      <button type="button" class="btn btn-ghost modal-cancel">Cancel</button>
      <button class="btn btn-danger" id="btn-confirm-delete-route">Delete route</button>
    </div>`);
  $('.modal-cancel').addEventListener('click', closeModal);
  $('#btn-confirm-delete-route').addEventListener('click', async () => {
    const btn = $('#btn-confirm-delete-route');
    btn.disabled = true; btn.textContent = 'Deleting…';
    try {
      const result = await api(`/api/gre-routes/${routeId}`, { method: 'DELETE' });
      closeModal();
      await loadRoutes();
      toast(`${result.name} deleted${result.removed.length ? ` — removed ${result.removed.join(', ')}` : ''}`);
    } catch (err) {
      const data = err.data || {};
      const failures = (data.failures || []).map((f) => `${f.name}: ${f.error}`).join('; ');
      $('#delete-route-error').textContent = `${err.message}${failures ? ` — ${failures}` : ''}`;
      btn.disabled = false; btn.textContent = 'Delete route';
      loadRoutes();
    }
  });
}

// ---------- live provisioning timeline ------------------------------------

const TERMINAL_STATUSES = ['ACTIVE', 'FAILED', 'STALE', 'NEEDS_REVIEW'];
const POLL_INTERVAL_MS = 900;

function routeStatusClass(status) {
  if (status === 'ACTIVE') return 'green';
  if (status === 'FAILED') return 'red';
  if (status === 'RESERVED') return 'blue';
  if (status === 'STALE' || status === 'NEEDS_REVIEW') return 'yellow';
  return 'gray';
}

function clientModelLabel(model) {
  if (model === 'first_class') return 'First-class / multi-inbound';
  if (model === 'embedded') return 'Legacy embedded';
  return 'unknown';
}

function hostModelLabel(mode) {
  if (mode === 'managed_hosts') return 'Managed hosts';
  if (mode === 'external_proxy') return 'Legacy externalProxy';
  return 'unknown';
}

function eventKind(event) {
  if (event.status === 'FAIL') return { cls: 'red', icon: '✗', color: 'var(--red-fg)' };
  if (event.status === 'RUNNING') return { cls: 'blue', icon: '●', color: 'var(--blue-fg)' };
  if (event.status === 'INFO') return { cls: 'blue', icon: '›', color: 'var(--blue-fg)' };
  if (event.status === 'WARN') return { cls: 'yellow', icon: '!', color: 'var(--yellow-fg)' };
  if (/^rollback_/.test(String(event.stage || ''))) return { cls: 'yellow', icon: '↩', color: 'var(--yellow-fg)' };
  return { cls: 'green', icon: '✓', color: 'var(--green-fg)' };
}

function eventRowHtml(event) {
  const kind = eventKind(event);
  const when = new Date(Number(event.created_at) || Date.now()).toLocaleTimeString();
  return `<div class="tl-row ${kind.cls}" data-event-id="${Number(event.id)}" data-attempt="${Number(event.attempt_no) || 1}">
    <span class="tl-time">${esc(when)}</span>
    <span class="tl-icon" style="color:${kind.color}">${kind.icon}</span>
    <span class="tl-stage"><strong>${esc(event.stage)}</strong><span class="tl-detail">${esc(event.detail || '')}</span></span>
  </div>`;
}

// A retried route accumulates several attempts in one log. Mark the boundaries
// so "which run failed" is never ambiguous.
let timelineAttemptSeen = 1;

function attemptSeparatorHtml(attempt) {
  return `<div class="tl-attempt" data-attempt-sep="${attempt}">Attempt #${attempt}</div>`;
}

function timelineShellHtml(header) {
  return `<h2 id="tl-title">Creating route</h2>
    <div class="tl-head">${header}</div>
    <div class="tl-summary hidden" id="tl-summary"></div>
    <div class="tl-scroll" id="tl-scroll"><div class="tl-empty">Waiting for the first provisioning step…</div></div>
    <div class="tl-result hidden" id="tl-result"></div>
    <div class="foot">
      <button class="btn btn-ghost" id="tl-refresh">Refresh log</button>
      <button class="btn modal-cancel">Close</button>
    </div>`;
}

function headerFor(route) {
  return `
    <span class="tl-chip"><strong>${esc(route.name || '(route)')}</strong></span>
    <span class="tl-chip">port ${esc(route.port ?? '—')}</span>
    <span class="tl-chip">${esc(route.client_mode === 'existing' ? `existing client ${route.client_email || ''}` : `new client ${route.client_email || ''}`)}</span>
    <span class="tl-chip">${esc(clientModelLabel(route.client_model))}</span>
    ${Number(route.attempt_no) > 1 ? `<span class="tl-chip">attempt #${Number(route.attempt_no)}</span>` : ''}
    <span class="badge gray" id="tl-status">${esc(route.status || 'RESERVED')}</span>`;
}

function renderTimelineEvents(routeId, events) {
  const scroll = $('#tl-scroll');
  if (!scroll) return 0;
  const empty = $('.tl-empty', scroll);
  if (empty) empty.remove();
  let lastId = 0;
  for (const event of events) {
    const id = Number(event.id) || 0;
    if (id && $(`.tl-row[data-event-id="${id}"]`, scroll)) { lastId = Math.max(lastId, id); continue; }
    const attempt = Number(event.attempt_no) || 1;
    if (attempt !== timelineAttemptSeen) {
      scroll.insertAdjacentHTML('beforeend', attemptSeparatorHtml(attempt));
      timelineAttemptSeen = attempt;
    }
    scroll.insertAdjacentHTML('beforeend', eventRowHtml(event));
    lastId = Math.max(lastId, id);
  }
  return lastId;
}

function timelineNearBottom() {
  const scroll = $('#tl-scroll');
  if (!scroll) return true;
  return scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 60;
}

function stopProvisioningTimeline() {
  // Bumping the generation also neutralises a poll request that is already in
  // flight, so closing the modal cannot leave a polling loop behind.
  state.routesPollGeneration += 1;
  if (state.routesPoll) {
    clearTimeout(state.routesPoll.timer);
    state.routesPoll = null;
  }
}

function renderFailureSummary(route) {
  const box = $('#tl-summary');
  if (!box) return;
  const raw = String(route.last_error || '');
  // A reconcile run stores structured JSON in last_error; the live run stores a
  // plain message. Show whichever we have without ever dumping raw JSON.
  let reason = raw;
  let stage = route.current_stage || null;
  if (raw.startsWith('{')) {
    try {
      const parsed = JSON.parse(raw);
      reason = parsed.summary || reason;
      stage = stage || parsed.failedStage || null;
    } catch { /* keep the raw text */ }
  }
  const failedMatch = !stage && raw.match(/^Failed at ([a-z_]+):/i);
  if (failedMatch) { stage = failedMatch[1]; reason = raw.slice(failedMatch[0].length).trim(); }
  box.className = 'tl-summary';
  box.innerHTML = `<div class="tl-failure">
    <div class="row"><span class="label">Failed at</span><span><strong>${esc(stage || 'unknown stage')}</strong></span></div>
    <div class="row"><span class="label">Reason</span><span>${esc(reason)}</span></div>
    ${Number(route.attempt_no) > 1 ? `<div class="row"><span class="label">Attempt</span><span>#${Number(route.attempt_no)}</span></div>` : ''}
  </div>`;
}

async function openRouteTimeline(route) {
  stopProvisioningTimeline();
  // Attempt separators are tracked across incremental renders, so the counter
  // has to start fresh for each modal. Otherwise opening a route at attempt 1
  // after viewing one at attempt 2 silently drops the "Attempt #1" header.
  timelineAttemptSeen = 1;
  const detail = await api(`/api/gre-routes/${route.id}`).catch(() => route);
  const merged = { ...route, ...detail };
  openModal(timelineShellHtml(headerFor(merged)));
  $('.modal-cancel').addEventListener('click', () => { stopProvisioningTimeline(); closeModal(); });
  $('#tl-refresh').addEventListener('click', () => refreshTimeline(merged.id));
  await refreshTimeline(merged.id, merged);
}

async function refreshTimeline(routeId, known = null) {
  try {
    const [events, route] = await Promise.all([
      api(`/api/gre-routes/${routeId}/events`),
      known ? Promise.resolve(known) : api(`/api/gre-routes/${routeId}`),
    ]);
    renderTimelineEvents(routeId, events);
    const badge = $('#tl-status');
    if (badge && route && route.status) {
      badge.textContent = route.status;
      badge.className = `badge ${routeStatusClass(route.status)}`;
    }
    if (route && route.status === 'FAILED') renderFailureSummary(route);
    return route;
  } catch (err) {
    toast(err.message, true);
    return null;
  }
}

function startProvisioningTimeline(created) {
  stopProvisioningTimeline();
  timelineAttemptSeen = 1;
  const initial = {
    id: created.route_id,
    name: created.name,
    port: created.port,
    status: created.status || 'RESERVED',
    client_email: created.client_email,
    client_mode: created.client_mode,
    client_model: created.client_model,
    last_error: null,
  };
  openModal(timelineShellHtml(headerFor(initial)));
  $('.modal-cancel').addEventListener('click', () => { stopProvisioningTimeline(); closeModal(); });
  $('#tl-refresh').addEventListener('click', () => refreshTimeline(created.route_id));

  let lastEventId = 0;
  let finished = false;
  const generation = state.routesPollGeneration;
  const stillCurrent = () => !finished && state.routesPollGeneration === generation;
  const finish = (route, result) => {
    finished = true;
    stopProvisioningTimeline();
    const badge = $('#tl-status');
    if (badge) { badge.textContent = route.status; badge.className = `badge ${routeStatusClass(route.status)}`; }
    const box = $('#tl-result');
    if (!box) return;
    if (route.status === 'ACTIVE' && result && result.link) {
      box.className = 'tl-result';
      const outbound = result.outbound
        ? `<h3>Xray outbound JSON</h3><pre class="output-pane" style="max-height:none; user-select:all">${esc(JSON.stringify(result.outbound, null, 2))}</pre>`
        : '';
      const qr = result.qr_data_url
        ? `<div style="text-align:center; margin-top:14px"><img src="${esc(result.qr_data_url)}" alt="Shadowsocks QR code" width="240" height="240"></div>`
        : '';
      box.innerHTML = `
        <h3>Shadowsocks link</h3>
        <div class="output-pane" style="max-height:none; user-select:all">${esc(result.link)}</div>
        ${outbound}${qr}`;
    } else if (route.status === 'ACTIVE') {
      box.className = 'tl-result';
      box.innerHTML = '<div class="muted">Route is ACTIVE. Use <strong>Timeline</strong> on the route row, or <strong>Reveal</strong> later, to retrieve the share link.</div>';
    } else if (route.status !== 'ACTIVE') {
      renderFailureSummary(route);
    }
    loadRoutes();
  };

  const tick = async () => {
    if (!stillCurrent()) return;
    // wait=1 makes the hub hold this request until the provisioning run that
    // this browser started has settled, so we never render a half-written row.
    const route = await (async () => {
      try {
        return await api(`/api/gre-routes/${created.route_id}?wait=1`);
      } catch { return null; }
    })();
    let events = [];
    try {
      events = await api(`/api/gre-routes/${created.route_id}/events?after_id=${lastEventId}`);
    } catch { /* keep polling */ }
    // The modal may have been closed while those two requests were in flight.
    if (!stillCurrent()) return;
    if (events.length) {
      const stick = timelineNearBottom();
      const newest = renderTimelineEvents(created.route_id, events);
      if (newest > lastEventId) lastEventId = newest;
      if (stick) {
        const scroll = $('#tl-scroll');
        if (scroll) scroll.scrollTop = scroll.scrollHeight;
      }
    }
    if (route) {
      const badge = $('#tl-status');
      if (badge && route.status) { badge.textContent = route.status; badge.className = `badge ${routeStatusClass(route.status)}`; }
      if (route.status === 'FAILED') renderFailureSummary(route);
    }
    if (route && TERMINAL_STATUSES.includes(route.status)) {
      let result = null;
      if (route.status === 'ACTIVE') {
        // The share link and credential live AES-encrypted in the hub; the
        // completed result (link, QR, outbound) is fetched for this one route
        // through the explicit result path.
        try {
          result = await api(`/api/gre-routes/${created.route_id}?result=1`);
          if (!stillCurrent()) return;
        } catch { result = null; }
      }
      finish(route, result);
      return;
    }
    if (!stillCurrent()) return;
    state.routesPoll = { timer: setTimeout(tick, POLL_INTERVAL_MS) };
  };

  // The reserve/preflight events already exist, so pull them immediately.
  tick();
}

// ---------- action log page ----------------------------------------------

$$('#log-filter button').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('#log-filter button').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    state.logKind = btn.dataset.kind;
    loadLog();
  });
});

async function loadLog() {
  const wrap = $('#log-table-wrap');
  try {
    const rows = await api(`/api/actions${state.logKind ? `?kind=${state.logKind}` : ''}`);
    if (!rows.length) {
      wrap.innerHTML = '<div class="empty">No events recorded yet.</div>';
      return;
    }
    wrap.innerHTML = `
      <table class="data">
        <thead><tr><th>When</th><th>Type</th><th>Server</th><th>Event</th><th>Params</th><th>Exit</th><th>Details</th></tr></thead>
        <tbody>${rows.map((r) => `
          <tr>
            <td>${timeAgo(r.created_at)}</td>
            <td><span class="badge ${r.kind === 'auth' ? 'blue' : 'gray'}">${esc(r.kind)}</span></td>
            <td>${esc(r.server_name)}</td>
            <td>${esc(r.action)}</td>
            <td>${esc(r.params || '')}</td>
            <td>${r.rc === 0 ? '<span class="badge green">0</span>' : `<span class="badge red">${esc(r.rc)}</span>`}</td>
            <td class="muted">${esc((r.output || '').slice(0, 120))}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  } catch (err) {
    toast(err.message, true);
  }
}

$('#btn-refresh-log').addEventListener('click', loadLog);

// ---------- settings page --------------------------------------------------

function renderSettings() {
  const el = $('#settings-body');
  const meta = state.meta || {};
  const metaRow = (label, value) => `<dt>${esc(label)}</dt><dd>${esc(value === null || value === undefined || value === '' ? 'unknown' : value)}</dd>`;
  el.innerHTML = `
    <div class="section">
      <h3>Application</h3>
      <p class="muted" style="font-size:13px; margin-bottom:14px">Exactly which gre-hub build this server is running. If the version here differs from the release you installed, the deployment is stale.</p>
      <dl class="kv" style="margin-bottom:12px">
        ${metaRow('Version', meta.version ? `v${meta.version}` : null)}
        ${metaRow('Version source', meta.versionSource)}
        ${metaRow('Build commit', meta.shortCommit || meta.commit)}
        ${metaRow('Built at', meta.builtAt)}
        ${metaRow('Release tag', meta.tag)}
        ${metaRow('Node', meta.node)}
        ${metaRow('DB schema', meta.schemaVersion)}
        ${metaRow('Uptime', typeof meta.uptimeSeconds === 'number' ? `${Math.floor(meta.uptimeSeconds / 60)}m ${meta.uptimeSeconds % 60}s` : null)}
      </dl>
      ${meta.mixed ? '<p class="badge yellow" style="display:inline-block; margin-bottom:10px">version sources disagree — mixed deployment</p>' : ''}
      <button class="btn btn-ghost btn-sm" id="btn-refresh-meta">Refresh</button>
    </div>
    <div class="section">
      <h3>Change hub password</h3>
      <form id="pw-form">
        <div class="field"><label>Current password</label><input type="password" name="current" required autocomplete="current-password" /></div>
        <div class="field"><label>New password (min 12 chars)</label><input type="password" name="next" required autocomplete="new-password" /></div>
        <div class="field"><label>Confirm new password</label><input type="password" name="confirm" required autocomplete="new-password" /></div>
        <div class="form-error" id="pw-error"></div>
        <button type="submit" class="btn">Change password</button>
        <div class="hint" style="margin-top:8px">All other sessions are signed out.</div>
      </form>
    </div>
    <div class="section">
      <h3>Two-factor authentication</h3>
      <p class="muted" style="font-size:13px; margin-bottom:14px">
        Status: ${state.totpEnabled
          ? '<span class="badge green">enabled</span>'
          : '<span class="badge gray">disabled</span>'}
      </p>
      ${state.totpEnabled
        ? '<button class="btn btn-danger btn-sm" id="btn-2fa-disable">Disable 2FA</button>'
        : '<button class="btn btn-ghost btn-sm" id="btn-2fa-enable">Enable TOTP 2FA</button>'}
    </div>
    <div class="section">
      <h3>Sessions</h3>
      <p class="muted" style="font-size:13px; margin-bottom:14px">Sessions expire after 1 hour idle and 12 hours maximum. Sign out everywhere except this browser:</p>
      <button class="btn btn-ghost btn-sm" id="btn-logout-all">Log out all other sessions</button>
    </div>`;

  $('#btn-refresh-meta').addEventListener('click', async () => {
    await loadMeta();
    renderSettings();
  });

  $('#pw-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = $('#pw-error');
    errEl.textContent = '';
    if (form.next.value !== form.confirm.value) {
      errEl.textContent = 'New passwords do not match.';
      return;
    }
    try {
      await api('/api/password', { method: 'POST', body: { current: form.current.value, next: form.next.value } });
      form.reset();
      toast('Password changed — other sessions signed out');
    } catch (err) { errEl.textContent = err.message; }
  });

  $('#btn-logout-all').addEventListener('click', async () => {
    try {
      await api('/api/logout-all', { method: 'POST' });
      toast('All other sessions signed out');
    } catch (err) { toast(err.message, true); }
  });

  const enableBtn = $('#btn-2fa-enable');
  if (enableBtn) enableBtn.addEventListener('click', open2faEnable);
  const disableBtn = $('#btn-2fa-disable');
  if (disableBtn) disableBtn.addEventListener('click', open2faDisable);
}

async function open2faEnable() {
  let setup;
  try {
    setup = await api('/api/2fa/setup', { method: 'POST' });
  } catch (err) { toast(err.message, true); return; }
  openModal(`
    <h2>Enable two-factor authentication</h2>
    <p class="sub">Add this key to any TOTP authenticator (Aegis, Bitwarden, 1Password, …), then enter the 6-digit code.</p>
    <div class="field">
      <label>Manual entry key</label>
      <div class="output-pane" style="max-height:none; user-select:all">${esc(setup.secret)}</div>
    </div>
    <div class="field">
      <label>otpauth URI</label>
      <div class="output-pane" style="max-height:80px; user-select:all; font-size:11px">${esc(setup.uri)}</div>
    </div>
    <form id="2fa-enable-form">
      <div class="field"><label>Code from authenticator</label><input name="code" required inputmode="numeric" autocomplete="one-time-code" placeholder="123456" /></div>
      <div class="form-error" id="2fa-enable-error"></div>
      <div class="foot">
        <button type="button" class="btn btn-ghost" id="btn-cancel-2fa">Cancel</button>
        <button type="submit" class="btn">Activate 2FA</button>
      </div>
    </form>`);
  $('#btn-cancel-2fa').addEventListener('click', closeModal);
  $('#2fa-enable-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const r = await api('/api/2fa/enable', { method: 'POST', body: { code: e.target.code.value.trim() } });
      state.totpEnabled = true;
      showRecoveryCodes(r.recovery_codes);
    } catch (err) {
      $('#2fa-enable-error').textContent = err.message;
    }
  });
}

function showRecoveryCodes(codes) {
  openModal(`
    <h2>Recovery codes</h2>
    <p class="sub">Each code works once, together with your password. Store them somewhere safe — they are shown only now.</p>
    <div class="output-pane" style="max-height:none; user-select:all">${codes.map(esc).join('\n')}</div>
    <div class="foot">
      <button class="btn" id="btn-codes-saved">I saved these codes</button>
    </div>`);
  $('#btn-codes-saved').addEventListener('click', () => {
    closeModal();
    renderSettings();
    toast('Two-factor authentication enabled');
  });
}

function open2faDisable() {
  openModal(`
    <h2>Disable two-factor authentication</h2>
    <p class="sub">Confirm with your hub password and a current code (or recovery code).</p>
    <form id="2fa-disable-form">
      <div class="field"><label>Password</label><input type="password" name="password" required autocomplete="current-password" /></div>
      <div class="field"><label>Two-factor code</label><input name="code" required inputmode="numeric" autocomplete="one-time-code" /></div>
      <div class="form-error" id="2fa-disable-error"></div>
      <div class="foot">
        <button type="button" class="btn btn-ghost" id="btn-cancel-2fad">Cancel</button>
        <button type="submit" class="btn btn-danger">Disable 2FA</button>
      </div>
    </form>`);
  $('#btn-cancel-2fad').addEventListener('click', closeModal);
  $('#2fa-disable-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/2fa/disable', { method: 'POST', body: { password: e.target.password.value, code: e.target.code.value.trim() } });
      state.totpEnabled = false;
      closeModal();
      renderSettings();
      toast('Two-factor authentication disabled');
    } catch (err) {
      $('#2fa-disable-error').textContent = err.message;
    }
  });
}

// ---------- boot ----------------------------------------------------------

(async function boot() {
  try {
    const { needs_setup } = await api('/api/setup');
    if (needs_setup) {
      showAuth(true);
      return;
    }
    try {
      const me = await api('/api/me');
      state.csrf = me.csrf;
      state.totpEnabled = me.totp_enabled;
      enterMain();
    } catch {
      showAuth(false);
    }
  } catch (err) {
    document.body.innerHTML = `<div class="auth-wrap"><div class="auth-box"><h1>gre-hub</h1><p class="sub">Failed to reach the API: ${esc(err.message)}</p></div></div>`;
  }
})();
