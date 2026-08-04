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
  current: null,      // server object open in the drawer
  csrf: '',
  totpEnabled: false,
  logKind: '',
};

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && state.csrf) headers['x-csrf-token'] = state.csrf;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !path.startsWith('/api/login')) {
    showAuth(false);
    throw new Error('not authenticated');
  }
  if (!res.ok) {
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
    $('#page-log').classList.toggle('hidden', page !== 'log');
    $('#page-settings').classList.toggle('hidden', page !== 'settings');
    if (page === 'log') loadLog();
    if (page === 'settings') renderSettings();
  });
});

async function enterMain() {
  $('#view-auth').classList.add('hidden');
  $('#view-main').classList.remove('hidden');
  try {
    const me = await api('/api/me');
    state.csrf = me.csrf;
    state.totpEnabled = me.totp_enabled;
  } catch { /* csrf already set from login */ }
  loadServers();
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

function renderServers() {
  const grid = $('#servers-grid');
  $('#servers-count').textContent =
    state.servers.length === 0 ? 'No servers yet.' : `${state.servers.length} server${state.servers.length === 1 ? '' : 's'}`;
  if (!state.servers.length) {
    grid.innerHTML = '<div class="empty">Add your first server to start managing GRE tunnels.</div>';
    return;
  }
  grid.innerHTML = state.servers.map((s, i) => {
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
        <div class="card-foot">
          <span>${snap ? `discovered ${timeAgo(snap.taken_at)}` : 'never discovered'}</span>
          <button class="btn btn-ghost btn-sm btn-card-discover" data-id="${s.id}">Discover</button>
        </div>
      </div>`;
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
    { name: 'foreign_ip', label: 'Foreign IP (optional)' },
    { name: 'gre_whitelist', label: 'GRE whitelist', type: 'select', options: [['', 'default (on)'], ['on', 'on'], ['off', 'off']] },
    { name: 'icmp_drop', label: 'ICMP drop', type: 'select', options: [['', 'default (off)'], ['on', 'on'], ['off', 'off']] },
    { name: 'downtime', label: 'Downtime tolerance, minutes (default 2)', type: 'number' },
  ] },
  { id: 'setup_iran', label: 'Configure as IRAN', desc: 'First-time IRAN setup — creates the first foreign peer', suggest: true, suggestionKind: 'peer', fields: [
    { name: 'foreign_ip', label: 'Foreign IP', required: true, ipRole: 'FOREIGN' },
    { name: 'name', label: 'Peer name (optional)' },
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
    { name: 'name', label: 'Name', required: true },
    { name: 'ip', label: 'Iran IP', required: true, ipRole: 'IRAN' },
    { name: 'idx', label: 'Index (optional)', type: 'number' },
    { name: 'key', label: 'GRE key (optional)' },
    { name: 'subnet_base', label: 'Subnet base, e.g. 10.9 (optional)' },
  ] },
  { id: 'node_remove', label: 'Node: remove', desc: 'Remove an Iran node (FOREIGN side)', fields: [
    { name: 'name', label: 'Name', required: true },
  ] },
  { id: 'peer_add', label: 'Peer: add', desc: 'Connect to a foreign server (IRAN side)', suggest: true, suggestionKind: 'peer', fields: [
    { name: 'name', label: 'Name', required: true },
    { name: 'foreign_ip', label: 'Foreign IP', required: true, ipRole: 'FOREIGN' },
    { name: 'iran_ip', label: 'Iran IP (optional)', ipRole: 'IRAN', includeCurrent: true },
    { name: 'subnet_base', label: 'Subnet base (optional)' },
    { name: 'idx', label: 'Index (optional)', type: 'number' },
    { name: 'key', label: 'GRE key (optional)' },
    { name: 'tcp_ports', label: 'TCP ports list (optional)' },
    { name: 'udp_ports', label: 'UDP ports list (optional)' },
  ] },
  { id: 'peer_remove', label: 'Peer: remove', desc: 'Remove one foreign peer (IRAN side)', fields: [
    { name: 'name', label: 'Name', required: true },
  ] },
  { id: 'peer_apply', label: 'Peer: apply', desc: 'Re-apply one peer tunnel + rules', fields: [
    { name: 'name', label: 'Name', required: true },
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

async function executeAction(action, params = {}) {
  const s = state.current;
  if (!s) return;
  setActionOutput(`$ ${action} ${JSON.stringify(params)}\nrunning…`, true);
  try {
    const r = await api(`/api/servers/${s.id}/action`, { method: 'POST', body: { action, params } });
    const out = [r.stdout, r.stderr].filter(Boolean).join('\n').trim();
    const hintLine = r.hint ? `\n\nHint: ${r.hint}` : '';
    setActionOutput(`$ ${r.command}\n(exit ${r.rc})\n\n${out || '(no output)'}${hintLine}`);
    loadServers(); // snapshot may have been refreshed
  } catch (err) {
    if (handleHostKeyError(s, err)) {
      setActionOutput(`$ ${action}\n\nAborted: host key mismatch — see the warning dialog.`);
      return;
    }
    setActionOutput(`$ ${action}\n\nError: ${err.message}`);
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
    .filter((server) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(server.host || ''))
    .filter((server) => !seen.has(server.host) && seen.add(server.host))
    .map((server) => ({ value: server.host, label: server.name }));
}

function openActionForm(def) {
  const suggestFields = new Set(['name', 'subnet_base', 'idx', 'key', 'tcp_ports', 'udp_ports']);
  const fields = def.fields.map((f) => {
    if (f.type === 'select') {
      const opts = (f.options || []).map(([v, label]) => `<option value="${esc(v)}">${esc(label)}</option>`).join('');
      return `
    <div class="field">
      <label>${esc(f.label)}</label>
      <select name="${f.name}" ${f.required ? 'required' : ''}>${opts}</select>
    </div>`;
    }
    const listId = f.ipRole
      ? `${def.id}-${f.name}-servers`
      : (def.suggest && suggestFields.has(f.name) ? `${def.id}-${f.name}-suggestions` : '');
    const options = f.ipRole
      ? roleServerOptions(f.ipRole, f.includeCurrent).map((item) => `<option value="${esc(item.value)}">${esc(item.label)}</option>`).join('')
      : '';
    return `
    <div class="field">
      <label>${esc(f.label)}</label>
      <input name="${f.name}" ${f.required ? 'required' : ''} type="${f.type || 'text'}" ${listId ? `list="${listId}"` : ''} autocomplete="off" />
      ${listId ? `<datalist id="${listId}">${options}</datalist>` : ''}
      ${f.ipRole ? `<span class="hint">Choose a ${f.ipRole} server from this hub, or type another IP.</span>` : ''}
    </div>`;
  }).join('');
  openModal(`
    <h2>${esc(def.label)}</h2>
    <p class="sub">${esc(def.desc)}</p>
    <form id="action-form">
      ${fields}
      <div class="form-error" id="action-form-error"></div>
      <div class="foot">
        ${def.suggest ? '<button type="button" class="btn btn-ghost" id="btn-suggest" title="Reload 10 collision-free values from the server (gre >= 2.8.0)">Refresh values</button>' : ''}
        <button type="button" class="btn btn-ghost" id="btn-cancel-action">Cancel</button>
        <button type="submit" class="btn">Run</button>
      </div>
    </form>`);
  $('#btn-cancel-action').addEventListener('click', closeModal);
  const suggestBtn = $('#btn-suggest');
  if (suggestBtn) {
    const SUGGEST_MAP = { name: 'name', subnet_base: 'subnet_base', idx: 'idx', key: 'key', tcp_port: 'tcp_ports', udp_port: 'udp_ports' };
    const loadSuggestions = async ({ fillEmpty = false, base = '' } = {}) => {
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
          if (fillEmpty && !form[dest].value && clean.length) { form[dest].value = clean[0]; filled++; }
        }
        if (fillEmpty) toast(filled ? `Loaded 10-value pools and filled ${filled} fields` : 'Suggestion lists refreshed');
      } catch (err) {
        errEl.textContent = err.message;
      }
      suggestBtn.disabled = false;
      suggestBtn.textContent = 'Refresh values';
    };
    suggestBtn.addEventListener('click', () => loadSuggestions({ fillEmpty: true, base: $('#action-form').subnet_base?.value.trim() || '' }));
    const baseInput = $('#action-form').subnet_base;
    if (baseInput) baseInput.addEventListener('change', () => loadSuggestions({ base: baseInput.value.trim() }));
    loadSuggestions();
  }
  $('#action-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const form = e.target;
    const params = {};
    for (const f of def.fields) {
      const v = form[f.name].value.trim();
      if (v !== '') params[f.name] = f.type === 'number' ? Number(v) : v;
    }
    closeModal();
    executeAction(def.id, params);
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
  el.innerHTML = `
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
