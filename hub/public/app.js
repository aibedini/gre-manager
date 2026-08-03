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

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !path.startsWith('/api/login')) {
    showAuth(false);
    throw new Error('not authenticated');
  }
  if (!res.ok) throw new Error((data && data.error) || `request failed (${res.status})`);
  return data;
}

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
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

// ---------- auth ----------------------------------------------------------

let authMode = 'login'; // 'login' | 'setup'

function showAuth(needsSetup) {
  authMode = needsSetup ? 'setup' : 'login';
  $('#view-main').classList.add('hidden');
  closeDrawer();
  $('#view-auth').classList.remove('hidden');
  $('#auth-title').textContent = needsSetup ? 'Create hub password' : 'gre-hub';
  $('#auth-sub').textContent = needsSetup
    ? 'First run — set the password for this hub.'
    : 'Sign in to continue.';
  $('#auth-confirm-wrap').classList.toggle('hidden', !needsSetup);
  $('#auth-submit').textContent = needsSetup ? 'Create password' : 'Sign in';
  $('#auth-error').textContent = '';
  $('#auth-password').value = '';
  $('#auth-confirm').value = '';
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
      await api('/api/setup', { method: 'POST', body: { password } });
    } else {
      await api('/api/login', { method: 'POST', body: { password } });
    }
    enterMain();
  } catch (err) {
    errEl.textContent = err.message;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
  showAuth(false);
});

// ---------- navigation ----------------------------------------------------

$$('.nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('.nav button').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const page = btn.dataset.page;
    $('#page-servers').classList.toggle('hidden', page !== 'servers');
    $('#page-log').classList.toggle('hidden', page !== 'log');
    if (page === 'log') loadLog();
  });
});

function enterMain() {
  $('#view-auth').classList.add('hidden');
  $('#view-main').classList.remove('hidden');
  loadServers();
}

// ---------- state ---------------------------------------------------------

const state = {
  servers: [],
  current: null, // server object open in the drawer
};

// ---------- servers grid --------------------------------------------------

function badgesFor(server) {
  const snap = server.snapshot;
  const out = [];
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
    const roles = snap.roles || [];
    let role = 'none';
    if (roles.includes('IRAN') && roles.includes('FOREIGN')) role = 'both';
    else if (roles.includes('IRAN')) role = 'iran';
    else if (roles.includes('FOREIGN')) role = 'foreign';
    out.push([role === 'none' ? 'gray' : 'blue', role]);
    if (snap.manager.version) out.push(['gray', `v${snap.manager.version}`]);
    if (snap.tunnels_up !== null && snap.tunnels_up !== undefined) {
      out.push([snap.tunnels_up > 0 ? 'green' : 'gray', `${snap.tunnels_up} up`]);
    }
    const peers = countPeers(snap);
    if (peers !== null) out.push(['gray', `${peers} peer${peers === 1 ? '' : 's'}`]);
    if (snap.watchdog) {
      const on = snap.watchdog.enabled === true || snap.watchdog.enabled === 1 || snap.watchdog === 'enabled';
      out.push([on ? 'green' : 'gray', on ? 'watchdog' : 'no watchdog']);
    }
  }
  if (snap.legacy && snap.legacy.present) out.push(['red', 'legacy']);
  if (snap.unmanaged_tunnels && snap.unmanaged_tunnels.length) {
    out.push(['yellow', `${snap.unmanaged_tunnels.length} unmanaged`]);
  }
  return out;
}

function countPeers(snap) {
  const st = snap.status;
  if (!st) return null;
  if (Array.isArray(st.nodes)) return st.nodes.length;
  if (Array.isArray(st.iran_peers)) return st.iran_peers.length;
  return null;
}

function healthDot(server) {
  const snap = server.snapshot;
  if (!snap) return 'unknown';
  if (snap.error) return 'err';
  if (!snap.manager || !snap.manager.installed) return 'warn';
  const st = snap.status;
  if (!st) return 'unknown';
  const lists = [st.nodes, st.iran_peers].filter(Array.isArray);
  if (lists.length) {
    const all = lists.flat();
    if (all.some((n) => n.reachable === false)) return 'warn';
    if (all.length && all.every((n) => n.reachable === true)) return 'ok';
  }
  return 'ok';
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
        <div class="card-foot">
          <span>${snap ? `discovered ${timeAgo(snap.taken_at)}` : 'never discovered'}</span>
          <span class="muted">Open &rarr;</span>
        </div>
      </div>`;
  }).join('');
  $$('.card', grid).forEach((card) => {
    card.addEventListener('click', () => openDrawer(Number(card.dataset.id)));
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
    toast(err.message, true);
  }
}

// ---------- add / edit / delete server ------------------------------------

function serverFormHtml(server) {
  const s = server || {};
  return `
    <h2>${server ? 'Edit server' : 'Add server'}</h2>
    <p class="sub">Credentials are stored AES-256-GCM encrypted.</p>
    <form id="server-form">
      <div class="form-row">
        <div class="field"><label>Name</label><input name="name" required value="${esc(s.name || '')}" placeholder="iran-1" /></div>
        <div class="field"><label>Host</label><input name="host" required value="${esc(s.host || '')}" placeholder="203.0.113.10" /></div>
      </div>
      <div class="form-row">
        <div class="field"><label>SSH port</label><input name="ssh_port" type="number" value="${s.ssh_port || 22}" /></div>
        <div class="field"><label>Username</label><input name="username" value="${esc(s.username || 'root')}" /></div>
        <div class="field"><label>Auth</label>
          <select name="auth_type">
            <option value="password" ${s.auth_type === 'password' ? 'selected' : ''}>Password</option>
            <option value="key" ${s.auth_type === 'key' ? 'selected' : ''}>Private key</option>
          </select>
        </div>
      </div>
      <div class="field" id="secret-field">
        <label>${s.auth_type === 'key' ? 'Private key (PEM)' : 'Password / key'}</label>
        <textarea name="secret" ${server ? '' : 'required'} placeholder="${server ? 'Leave empty to keep the existing secret' : 'Password or PEM private key'}"></textarea>
        <div class="hint">For key auth, paste the full PEM including BEGIN/END lines.</div>
      </div>
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
  form.auth_type.addEventListener('change', () => {
    $('#secret-field label').textContent =
      form.auth_type.value === 'key' ? 'Private key (PEM)' : 'Password / key';
  });
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
      auth_type: form.auth_type.value,
    };
    if (form.secret.value) body.secret = form.secret.value;
    try {
      if (server) {
        await api(`/api/servers/${server.id}`, { method: 'PUT', body });
        toast('Server updated');
      } else {
        await api('/api/servers', { method: 'POST', body });
        toast('Server added — discovery running');
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
    <div style="display:flex; gap:8px; margin-bottom:28px">
      <button class="btn btn-ghost btn-sm" id="ov-discover">Run discovery</button>
      <button class="btn btn-ghost btn-sm" id="ov-test">Test connection</button>
      <button class="btn btn-ghost btn-sm" id="ov-edit">Edit server</button>
    </div>`;

  if (!snap) {
    el.innerHTML = toolbar + '<div class="empty">No discovery data yet. Run discovery to probe this server.</div>';
  } else if (snap.error) {
    el.innerHTML = toolbar + `
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

    el.innerHTML = toolbar + `
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
      ${legacyHtml}`;
  }

  $('#ov-discover').addEventListener('click', async () => {
    const btn = $('#ov-discover');
    btn.disabled = true; btn.textContent = 'Discovering…';
    try {
      const snap = await api(`/api/servers/${s.id}/discover`, { method: 'POST' });
      s.snapshot = snap;
      renderOverview();
      loadServers();
      toast('Discovery complete');
    } catch (err) { toast(err.message, true); btn.disabled = false; btn.textContent = 'Run discovery'; }
  });
  $('#ov-test').addEventListener('click', async () => {
    const btn = $('#ov-test');
    btn.disabled = true; btn.textContent = 'Testing…';
    try {
      const r = await api(`/api/servers/${s.id}/test`, { method: 'POST' });
      toast(r.ok ? 'Connection OK' : `Connection failed: ${r.stderr || `rc=${r.rc}`}`, !r.ok);
    } catch (err) { toast(err.message, true); }
    btn.disabled = false; btn.textContent = 'Test connection';
  });
  $('#ov-edit').addEventListener('click', () => openServerForm(s));
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
  { id: 'watchdog_interval', label: 'Watchdog: interval', desc: 'Set check interval (1-60 min)', fields: [
    { name: 'interval', label: 'Interval (minutes)', type: 'number', required: true },
  ] },
  { id: 'node_add', label: 'Node: add', desc: 'Add an Iran node (FOREIGN side)', fields: [
    { name: 'name', label: 'Name', required: true },
    { name: 'ip', label: 'Iran IP', required: true },
    { name: 'idx', label: 'Index (optional)', type: 'number' },
    { name: 'key', label: 'GRE key (optional)' },
    { name: 'subnet_base', label: 'Subnet base, e.g. 10.9 (optional)' },
  ] },
  { id: 'node_remove', label: 'Node: remove', desc: 'Remove an Iran node (FOREIGN side)', fields: [
    { name: 'name', label: 'Name', required: true },
  ] },
  { id: 'peer_add', label: 'Peer: add', desc: 'Connect to a foreign server (IRAN side)', fields: [
    { name: 'name', label: 'Name', required: true },
    { name: 'foreign_ip', label: 'Foreign IP', required: true },
    { name: 'iran_ip', label: 'Iran IP (optional)' },
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
    setActionOutput(`$ ${r.command}\n(exit ${r.rc})\n\n${out || '(no output)'}`);
    loadServers(); // snapshot may have been refreshed
  } catch (err) {
    setActionOutput(`$ ${action}\n\nError: ${err.message}`);
  }
}

function runSimpleAction(def) {
  if (def.confirm && !confirm(def.confirm)) return;
  executeAction(def.id);
}

function openActionForm(def) {
  const fields = def.fields.map((f) => `
    <div class="field">
      <label>${esc(f.label)}</label>
      <input name="${f.name}" ${f.required ? 'required' : ''} type="${f.type || 'text'}" />
    </div>`).join('');
  openModal(`
    <h2>${esc(def.label)}</h2>
    <p class="sub">${esc(def.desc)}</p>
    <form id="action-form">
      ${fields}
      <div class="form-error" id="action-form-error"></div>
      <div class="foot">
        <button type="button" class="btn btn-ghost" id="btn-cancel-action">Cancel</button>
        <button type="submit" class="btn">Run</button>
      </div>
    </form>`);
  $('#btn-cancel-action').addEventListener('click', closeModal);
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

async function loadLog() {
  const wrap = $('#log-table-wrap');
  try {
    const rows = await api('/api/actions');
    if (!rows.length) {
      wrap.innerHTML = '<div class="empty">No actions recorded yet.</div>';
      return;
    }
    wrap.innerHTML = `
      <table class="data">
        <thead><tr><th>When</th><th>Server</th><th>Action</th><th>Params</th><th>Exit</th></tr></thead>
        <tbody>${rows.map((r) => `
          <tr>
            <td>${timeAgo(r.created_at)}</td>
            <td>${esc(r.server_name)}</td>
            <td>${esc(r.action)}</td>
            <td>${esc(r.params || '')}</td>
            <td>${r.rc === 0 ? '<span class="badge green">0</span>' : `<span class="badge red">${esc(r.rc)}</span>`}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  } catch (err) {
    toast(err.message, true);
  }
}

$('#btn-refresh-log').addEventListener('click', loadLog);

// ---------- boot ----------------------------------------------------------

(async function boot() {
  try {
    const { needs_setup } = await api('/api/setup');
    if (needs_setup) {
      showAuth(true);
      return;
    }
    try {
      await api('/api/me');
      enterMain();
    } catch {
      showAuth(false);
    }
  } catch (err) {
    document.body.innerHTML = `<div class="auth-wrap"><div class="auth-box"><h1>gre-hub</h1><p class="sub">Failed to reach the API: ${esc(err.message)}</p></div></div>`;
  }
})();
