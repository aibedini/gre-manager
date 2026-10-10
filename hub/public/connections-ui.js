// ===========================================================================
// connections.js — the Connections page: table, edit wizard, review, timeline.
//
// A connection is shown as a PAIR. Both endpoints and both states are always
// visible: showing only one side is what forced an operator to hold two configs in
// their head, and it is the failure mode this page exists to remove.
//
// Published under window.ConnectionsUI rather than as bare globals, so app.js can
// reference it defensively: a bare `loadConnections()` would throw at load time if
// this script were ever missing, blanking every page instead of one.
// ===========================================================================

async function loadConnections() {
  try {
    [state.connections, state.servers] = await Promise.all([
      api('/api/gre-connections'),
      api('/api/servers'),
    ]);
    state.connectionsError = null;
  } catch (err) {
    state.connectionsError = err.message;
    state.connections = [];
  }
  renderConnections();
}

function connectionStateBadge(value) {
  switch (value) {
    case 'UP': return '<span class="badge green">UP</span>';
    case 'DOWN': return '<span class="badge red">DOWN</span>';
    case 'MISSING': return '<span class="badge gray">MISSING</span>';
    case 'MIGRATING': return '<span class="badge yellow">MIGRATING</span>';
    default: return '<span class="badge gray">UNKNOWN</span>';
  }
}

// ----------------------------------------------------------------- MTU columns
//
// Two sources on purpose. The list endpoint already carries a JOURNAL-ONLY MTU summary,
// so every row shows what the Hub last knew without an SSH round trip per row. Live
// diagnostics land in state.connMtu once the operator asks for them. A value that only
// exists in the journal is rendered muted with a title, never presented as verified.

function mtuState() {
  if (!state.connMtu) state.connMtu = {};
  if (!state.connMtuBusy) state.connMtuBusy = {};
  if (!state.connMtuError) state.connMtuError = {};
  return state.connMtu;
}

const MTU_TEST_CLASS = {
  SUCCEEDED: 'green', ROLLED_BACK: 'yellow', ROLLBACK_FAILED: 'red', INTERRUPTED: 'red', REJECTED: 'gray', RUNNING: 'blue',
};

const mtuText = (value) => (value === null || value === undefined || value === '' ? '—' : String(value));

// Journal-only values are styled as unverified so a stale number never reads like a
// live measurement.
function mtuCell(value, live, title = '') {
  const known = value !== null && value !== undefined && value !== '';
  const cls = known ? (live ? 'conn-mtu-live' : 'muted') : 'muted';
  const tip = title || (known && !live ? 'the last value the Hub recorded, not a live reading' : '');
  return `<span class="${cls}"${tip ? ` title="${esc(tip)}"` : ''}>${esc(known ? String(value) : '—')}</span>`;
}

function mtuDriftBadge(drift, extra = '') {
  if (!drift) return '<span class="muted">—</span>';
  const reasons = (drift.reasons || []).join('; ');
  if (!drift.detected) return '<span class="badge green" title="the two sides and the stored configuration agree">in sync</span>';
  return `<span class="badge red" title="${esc(reasons || extra)}">DRIFT</span>`;
}

function mtuTestBadge(last) {
  if (!last) return '<span class="muted">—</span>';
  const cls = MTU_TEST_CLASS[last.status] || 'gray';
  const when = last.at ? timeAgo(last.at) : '';
  return `<span class="badge ${cls}" title="${esc(`${last.status}${last.stage ? ` at ${last.stage}` : ''} ${last.detail || ''}`.trim())}">${esc(last.status)}</span>`
    + (when ? `<div class="muted conn-mtu-when">${esc(when)}</div>` : '');
}

// Merge the journal summary and the live diagnostics into the one shape the table and
// the detail panel both read.
function mtuRowView(c) {
  const live = mtuState()[c.id] || null;
  const stored = c.mtu || {};
  const rec = live && live.recommendation ? live.recommendation : null;
  const side = (name) => (rec && rec.sides && rec.sides[name]) || {};
  const iran = side('iran');
  const foreign = side('foreign');
  return {
    live,
    stored,
    rec,
    error: state.connMtuError[c.id] || null,
    busy: !!state.connMtuBusy[c.id],
    iranNic: iran.ok ? iran.nic_mtu : null,
    foreignNic: foreign.ok ? foreign.nic_mtu : null,
    iranGre: iran.ok ? iran.gre_mtu : stored.iran_gre_mtu,
    foreignGre: foreign.ok ? foreign.gre_mtu : stored.foreign_gre_mtu,
    underlay: rec ? rec.underlay_mtu : stored.underlay_mtu,
    overhead: rec ? rec.encapsulation_overhead : stored.encapsulation_overhead,
    recommended: rec ? rec.recommended_gre_mtu : stored.recommended_gre_mtu,
    mss: iran.ok ? (iran.mss_clamp && iran.mss_clamp.enabled ? 'on' : 'off') : stored.mss_clamp,
    usingStored: !live,
    drift: live ? live.combined.drift : stored.drift,
    lastTest: stored.last_test || null,
    lastVerified: stored.last_verified_at || null,
  };
}

function connectionById(id) {
  return (state.connections || []).find((x) => Number(x.id) === Number(id)) || null;
}

// Load the LIVE diagnostics for one connection. Read-only on the server side, so it is
// safe to call while an operator is still deciding.
async function analyzeMtu(id, { silent = false } = {}) {
  mtuState();
  state.connMtuBusy[id] = true;
  if (!silent) renderConnections();
  try {
    state.connMtu[id] = await api(`/api/gre-connections/${id}/mtu`);
    delete state.connMtuError[id];
    return state.connMtu[id];
  } catch (err) {
    state.connMtuError[id] = err.message;
    if (!silent) toast(`MTU analysis failed: ${err.message}`, true);
    return null;
  } finally {
    state.connMtuBusy[id] = false;
    renderConnections();
  }
}

function renderConnections() {
  const wrap = $('#connections-body');
  if (!wrap) return;

  if (state.connectionsError) {
    wrap.innerHTML = `<div class="empty">Could not load connections: ${esc(state.connectionsError)}</div>`;
    return;
  }
  const all = state.connections || [];
  const filter = String(state.connFilter || '').toLowerCase();
  const rows = filter
    ? all.filter((c) => [c.name, c.iran_server, c.foreign_server, c.iran_ip, c.foreign_ip, c.iran_tunnel]
      .some((v) => String(v || '').toLowerCase().includes(filter)))
    : all;

  if (!all.length) {
    wrap.innerHTML = '<div class="empty">No connections yet. They appear here once a GRE route is provisioned.</div>';
    return;
  }

  const body = rows.map((c) => {
    const m = mtuRowView(c);
    const live = !m.usingStored;
    return `
    <tr data-id="${c.id}" class="conn-row${c.busy ? ' busy' : ''}">
      <td>
        <div class="conn-name">${esc(c.name || '—')}${c.busy ? ' <span class="badge yellow">BUSY</span>' : ''}</div>
        <div class="muted" style="font-size:11px">${esc(c.connection_id ? `${c.connection_id.slice(0, 8)}…` : 'unassigned')}</div>
      </td>
      <td>${esc(c.iran_server || '—')}<div class="muted" style="font-size:11px">${esc(c.iran_ip || '')}</div></td>
      <td>${esc(c.foreign_server || '—')}<div class="muted" style="font-size:11px">${esc(c.foreign_ip || '')}</div></td>
      <td>${esc(c.iran_tunnel || '—')}</td>
      <td>${esc(c.subnet_base ? `${c.subnet_base}.${c.idx == null ? '?' : c.idx}.0/30` : '—')}</td>
      <td>${esc(c.key == null ? '—' : String(c.key))}</td>
      <td>${esc(c.tcp_ports || '—')}</td>
      <td>${esc(c.udp_ports || '—')}</td>
      <td>${connectionStateBadge(c.iran_state)}</td>
      <td>${connectionStateBadge(c.foreign_state)}</td>
      <td class="muted">${c.last_verified_at ? esc(timeAgo(c.last_verified_at)) : 'never'}</td>
      <td>${mtuCell(m.iranNic, live)}</td>
      <td>${mtuCell(m.foreignNic, live)}</td>
      <td>${mtuCell(m.iranGre, live)}</td>
      <td>${mtuCell(m.foreignGre, live)}</td>
      <td>${mtuCell(m.underlay, live, live ? 'verified underlay path capacity' : 'no live probe yet')}</td>
      <td>${mtuCell(m.overhead, live)}</td>
      <td>${mtuCell(m.recommended, live)}</td>
      <td>${esc(mtuText(m.mss))}${m.busy ? ' <span class="badge blue">…</span>' : ''}</td>
      <td>${mtuTestBadge(m.lastTest)}</td>
      <td class="muted">${m.lastVerified ? esc(timeAgo(m.lastVerified)) : 'never'}</td>
      <td>${mtuDriftBadge(m.drift, m.error || '')}</td>
      <td class="conn-actions conn-mtu-actions">
        <button class="btn btn-ghost btn-sm btn-mtu-analyze" data-id="${c.id}">Analyze MTU</button>
        <button class="btn btn-ghost btn-sm btn-mtu-details" data-id="${c.id}">View Detailed Results</button>
        <button class="btn btn-ghost btn-sm btn-mtu-recommend" data-id="${c.id}">Recommend MTU</button>
        <button class="btn btn-ghost btn-sm btn-mtu-apply" data-id="${c.id}">Apply MTU</button>
        <button class="btn btn-ghost btn-sm btn-mtu-restore" data-id="${c.id}">Restore Previous MTU</button>
        <button class="btn btn-ghost btn-sm btn-mtu-nic" data-id="${c.id}">Advanced NIC Settings</button>
        <button class="btn btn-ghost btn-sm btn-conn-edit" data-id="${c.id}">Edit</button>
        <button class="btn btn-ghost btn-sm btn-conn-timeline" data-id="${c.id}">Timeline</button>
      </td>
    </tr>`;
  }).join('');

  wrap.innerHTML = `
    <div class="conn-table-wrap">
      <table class="conn-table">
        <thead><tr>
          <th>Name</th><th>Iran Server</th><th>Foreign Server</th><th>Tunnel</th>
          <th>Subnet</th><th>Key</th><th>TCP</th><th>UDP</th>
          <th>Iran State</th><th>Foreign State</th><th>Last Verified</th>
          <th title="Iran NIC MTU">Iran NIC MTU</th>
          <th title="Foreign NIC MTU">Foreign NIC MTU</th>
          <th title="Iran GRE MTU">Iran GRE MTU</th>
          <th title="Foreign GRE MTU">Foreign GRE MTU</th>
          <th title="Verified underlay PMTU">Underlay PMTU</th>
          <th title="Estimated GRE overhead">GRE Overhead</th>
          <th title="Recommended MTU">Recommended</th>
          <th title="TCP MSS clamp status">TCP MSS Clamp</th>
          <th title="Latest MTU test result">Latest MTU Test</th>
          <th title="Last successful MTU verification">MTU Verified</th>
          <th title="Drift between the two sides or the stored configuration">MTU Drift</th>
          <th></th>
        </tr></thead>
        <tbody>${body || '<tr><td colspan="23" class="muted" style="padding:14px">No connection matches that filter.</td></tr>'}</tbody>
      </table>
    </div>`;

  $$('.btn-conn-edit', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openConnectionEdit(Number(btn.dataset.id)));
  });
  $$('.btn-conn-timeline', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openConnectionTimeline(Number(btn.dataset.id)));
  });
  $$('.btn-mtu-analyze', wrap).forEach((btn) => {
    btn.addEventListener('click', () => analyzeMtu(Number(btn.dataset.id)).then(() => toast('MTU diagnostics read from both sides')));
  });
  $$('.btn-mtu-details', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openMtuDetails(Number(btn.dataset.id)));
  });
  $$('.btn-mtu-recommend', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openMtuRecommend(Number(btn.dataset.id)));
  });
  $$('.btn-mtu-apply', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openMtuApply(Number(btn.dataset.id)));
  });
  $$('.btn-mtu-restore', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openMtuRestore(Number(btn.dataset.id)));
  });
  $$('.btn-mtu-nic', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openMtuNic(Number(btn.dataset.id)));
  });
}

// ------------------------------------------------------------------ the wizard
//
// The same fields as Create, every one prefilled from the current state. An
// untouched field is never sent, so "leave it alone" is the default rather than
// something the operator has to express.

function serverOptions(servers, selectedId) {
  return servers.map((s) => `<option value="${s.id}"${Number(s.id) === Number(selectedId) ? ' selected' : ''}>${esc(s.name)} — ${esc(s.host)}</option>`).join('');
}

function openConnectionEdit(id) {
  const c = (state.connections || []).find((x) => Number(x.id) === Number(id));
  if (!c) { toast('that connection is no longer loaded; refresh first', true); return; }
  const servers = state.servers || [];

  openModal(`
    <h2>Edit connection</h2>
    <p class="sub">${esc(c.name)} — every field is prefilled. Change only what you mean to change; the rest is left alone.</p>
    <form id="conn-form">
      <div class="form-row">
        <div class="field"><label>Iran server</label><select name="iran_server_id">${serverOptions(servers, c.iran_server_id)}</select></div>
        <div class="field"><label>Foreign server</label><select name="foreign_server_id">${serverOptions(servers, c.foreign_server_id)}</select></div>
      </div>
      <div class="field"><label>Connection name</label><input name="name" value="${esc(c.name || '')}" maxlength="11" /></div>
      <div class="form-row">
        <div class="field"><label>Iran IP</label><input name="iran_ip" value="${esc(c.iran_ip || '')}" /></div>
        <div class="field"><label>Foreign IP</label><input name="foreign_ip" value="${esc(c.foreign_ip || '')}" /></div>
      </div>
      <div class="form-row">
        <div class="field"><label>Subnet base</label><input name="subnet_base" value="${esc(c.subnet_base || '')}" placeholder="10.212" /></div>
        <div class="field"><label>Index</label><input name="idx" value="${c.idx == null ? '' : esc(String(c.idx))}" /></div>
        <div class="field"><label>GRE key</label><input name="key" value="${c.key == null ? '' : esc(String(c.key))}" /></div>
      </div>
      <div class="form-row">
        <div class="field"><label>TCP ports</label><input name="tcp_ports" value="${esc(c.tcp_ports || '')}" placeholder="3001 or 3001,3002" /></div>
        <div class="field"><label>UDP ports</label><input name="udp_ports" value="${esc(c.udp_ports || '')}" placeholder="3001" /></div>
        <div class="field"><label>MSS clamp</label><select name="mss_clamp">
          <option value=""${c.mss_clamp == null ? ' selected' : ''}>leave unchanged</option>
          <option value="on"${Number(c.mss_clamp) === 1 ? ' selected' : ''}>on</option>
          <option value="off"${Number(c.mss_clamp) === 0 ? ' selected' : ''}>off</option>
        </select></div>
      </div>
      <div class="form-error" id="conn-error"></div>
      <div class="foot">
        <button type="button" class="btn btn-ghost modal-cancel">Cancel</button>
        <button class="btn" id="conn-review">Review change</button>
      </div>
    </form>`);

  $('#conn-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const err = $('#conn-error');
    err.textContent = '';
    // Only fields that actually differ from the current value are sent. A
    // prefilled field the operator did not touch must not look like an edit.
    const body = {};
    const text = (name) => form[name].value.trim();
    if (text('name') && text('name') !== String(c.name || '')) body.name = text('name');
    if (Number(form.iran_server_id.value) !== Number(c.iran_server_id)) body.iran_server_id = Number(form.iran_server_id.value);
    if (Number(form.foreign_server_id.value) !== Number(c.foreign_server_id)) body.foreign_server_id = Number(form.foreign_server_id.value);
    if (text('iran_ip') && text('iran_ip') !== String(c.iran_ip || '')) body.iran_ip = text('iran_ip');
    if (text('foreign_ip') && text('foreign_ip') !== String(c.foreign_ip || '')) body.foreign_ip = text('foreign_ip');
    if (text('subnet_base') && text('subnet_base') !== String(c.subnet_base || '')) body.subnet_base = text('subnet_base');
    if (text('idx') && text('idx') !== String(c.idx == null ? '' : c.idx)) body.idx = Number(text('idx'));
    if (text('key') && text('key') !== String(c.key == null ? '' : c.key)) body.key = Number(text('key'));
    if (text('tcp_ports') !== String(c.tcp_ports || '')) body.tcp_ports = text('tcp_ports');
    if (text('udp_ports') !== String(c.udp_ports || '')) body.udp_ports = text('udp_ports');
    if (form.mss_clamp.value) {
      const want = form.mss_clamp.value === 'on' ? 1 : 0;
      if (Number(c.mss_clamp) !== want) body.mss_clamp = form.mss_clamp.value;
    }

    if (!Object.keys(body).length) {
      err.textContent = 'Nothing has changed.';
      return;
    }

    const btn = $('#conn-review');
    btn.disabled = true; btn.textContent = 'Planning…';
    try {
      const plan = await api(`/api/gre-connections/${c.id}/plan-edit`, { method: 'POST', body });
      closeModal();
      openConnectionReview(c, body, plan);
    } catch (e2) {
      err.textContent = e2.message;
    }
    btn.disabled = false; btn.textContent = 'Review change';
  });
}

// ------------------------------------------------------------------- review
//
// CURRENT and NEW side by side, the impact list, and the preflight results. The
// operator sees what will happen before anything is applied.

function openConnectionReview(c, body, plan) {
  const newVal = (field, fallback) => (Object.prototype.hasOwnProperty.call(body, field) ? String(body[field]) : String(fallback == null ? '—' : fallback));
  const currentVal = (field, fallback) => String(fallback == null ? '—' : fallback);

  const rows = [
    ['Iran server', currentVal('iran_server_id', c.iran_server), newVal('iran_server_id', c.iran_server)],
    ['Foreign server', currentVal('foreign_server_id', c.foreign_server), newVal('foreign_server_id', c.foreign_server)],
    ['Name', currentVal('name', c.name), newVal('name', c.name)],
    ['Iran IP', currentVal('iran_ip', c.iran_ip), newVal('iran_ip', c.iran_ip)],
    ['Foreign IP', currentVal('foreign_ip', c.foreign_ip), newVal('foreign_ip', c.foreign_ip)],
    ['Subnet base', currentVal('subnet_base', c.subnet_base), newVal('subnet_base', c.subnet_base)],
    ['Index', currentVal('idx', c.idx), newVal('idx', c.idx)],
    ['GRE key', currentVal('key', c.key), newVal('key', c.key)],
    ['TCP ports', currentVal('tcp_ports', c.tcp_ports), newVal('tcp_ports', c.tcp_ports)],
    ['UDP ports', currentVal('udp_ports', c.udp_ports), newVal('udp_ports', c.udp_ports)],
    ['MSS clamp', Number(c.mss_clamp) === 1 ? 'on' : 'off', newVal('mss_clamp', Number(c.mss_clamp) === 1 ? 'on' : 'off')],
  ];

  const changed = new Set((plan.changes || []).map((ch) => ch.field));
  const fieldKey = {
    'Iran server': 'iran_server_id', 'Foreign server': 'foreign_server_id', Name: 'name',
    'Iran IP': 'iran_ip', 'Foreign IP': 'foreign_ip', 'Subnet base': 'subnet_base',
    Index: 'idx', 'GRE key': 'key', 'TCP ports': 'tcp_ports', 'UDP ports': 'udp_ports', 'MSS clamp': 'mss_clamp',
  };

  const diffRows = rows.map(([label, before, after]) => {
    const key = fieldKey[label];
    const isChanged = changed.has(key);
    return `<tr class="${isChanged ? 'changed' : ''}">
      <td>${esc(label)}</td>
      <td>${esc(before)}</td>
      <td>${isChanged ? `→ ${esc(after)}` : '<span class="muted">unchanged</span>'}</td>
    </tr>`;
  }).join('');

  const preflight = (plan.preflight || []).map((p) => `
    <li class="${p.ok ? 'ok' : 'bad'}">${p.ok ? '✓' : '✗'} ${esc(p.name)}${p.detail ? ` <span class="muted">${esc(p.detail)}</span>` : ''}</li>`).join('');

  const impact = (plan.impact || []).map((i) => `<li>${esc(i)}</li>`).join('');

  openModal(`
    <h2>Review ${plan.class === 'C' ? 'migration' : 'change'}</h2>
    <p class="sub">Class ${esc(plan.class || '—')} — ${esc(plan.class_label || '')}</p>

    <div class="review-grid">
      <table class="review-table">
        <thead><tr><th>Field</th><th>Current</th><th>New</th></tr></thead>
        <tbody>${diffRows}</tbody>
      </table>
    </div>

    <div class="section"><h3>Impact</h3><ul class="impact-list">${impact}</ul></div>
    <div class="section"><h3>Preflight</h3><ul class="preflight-list">${preflight}</ul></div>
    <div class="muted" style="font-size:12px">${esc(plan.estimated_disruption || '')}</div>
    ${plan.can_apply ? '' : `<div class="form-error">${esc(plan.blocked_reason || 'this change cannot be applied')}</div>`}

    <div class="foot">
      <button type="button" class="btn btn-ghost modal-cancel">Cancel</button>
      <button class="btn" id="conn-apply" ${plan.can_apply ? '' : 'disabled'}>${plan.class === 'C' ? 'Apply migration' : 'Apply change'}</button>
    </div>`);

  const applyBtn = $('#conn-apply');
  if (applyBtn && plan.can_apply) {
    applyBtn.addEventListener('click', async () => {
      applyBtn.disabled = true;
      applyBtn.textContent = plan.class === 'C' ? 'Migrating…' : 'Applying…';
      closeModal();
      openConnectionTimeline(c.id, true);
      try {
        const result = await api(`/api/gre-connections/${c.id}`, { method: 'PUT', body });
        toast(result.migrated
          ? `Migrated: ${result.migrated.from.foreign} → ${result.migrated.to.foreign}`
          : 'Connection updated');
        await loadConnections();
      } catch (err) {
        // A failed or rolled-back operation must say which, and how to recover.
        if (err.body && err.body.rollback === 'FAILED' && err.body.manual_recovery) {
          openManualRecovery(err.body);
        } else {
          toast(`${err.message}${err.body && err.body.rollback === 'CLEAN' ? ' (the previous configuration was restored)' : ''}`, true);
        }
        await loadConnections();
      }
    });
  }
}

function openManualRecovery(payload) {
  openModal(`
    <h2>Rollback failed — manual recovery needed</h2>
    <p class="sub">The Hub could not restore the previous configuration. The connection may be in an unknown state.</p>
    <pre class="recovery-steps">${esc(payload.manual_recovery)}</pre>
    <div class="section"><h3>What went wrong</h3><div class="output-pane">${esc(payload.error || '')}</div></div>
    <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);
}

// ------------------------------------------------------------------ timeline
//
// Live-updating stage list. Same event source the route timeline uses, so a
// migration and a provisioning run read the same way.

async function openConnectionTimeline(id, live = false) {
  const c = (state.connections || []).find((x) => Number(x.id) === Number(id)) || { name: `connection ${id}` };
  openModal(`
    <h2>Timeline — ${esc(c.name)}</h2>
    <p class="sub">Every stage of the last operation on this connection.</p>
    <div id="conn-timeline" class="timeline"><div class="muted">Loading…</div></div>
    <div class="section"><h3>Operations</h3><div id="conn-ops" class="muted">Loading…</div></div>
    <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);

  let afterId = 0;
  let stopped = false;
  const render = (events) => {
    const el = $('#conn-timeline');
    if (!el) { stopped = true; return; }
    if (!events.length) { el.innerHTML = '<div class="muted">No stages recorded yet.</div>'; return; }
    el.innerHTML = events.map((e) => `
      <div class="timeline-row ${esc(String(e.status || '').toLowerCase())}">
        <span class="timeline-stage">${esc(e.stage)}</span>
        <span class="badge ${e.status === 'PASS' ? 'green' : e.status === 'FAIL' ? 'red' : e.status === 'WARN' ? 'yellow' : 'gray'}">${esc(e.status)}</span>
        <span class="muted">${esc(e.detail || '')}</span>
        <span class="muted timeline-time">${esc(new Date(e.created_at).toLocaleTimeString())}</span>
      </div>`).join('');
  };

  const tick = async () => {
    if (stopped) return;
    try {
      const events = await api(`/api/gre-connections/${id}/events?after_id=${afterId}`);
      if (Array.isArray(events) && events.length) {
        afterId = events[events.length - 1].id;
        render(events);
      }
      const detail = await api(`/api/gre-connections/${id}`);
      const ops = $('#conn-ops');
      if (ops) {
        ops.innerHTML = (detail.recent_operations || []).length
          ? detail.recent_operations.map((o) => `<div class="op-row">
               <span class="badge ${o.status === 'SUCCEEDED' ? 'green' : o.status === 'ROLLED_BACK' ? 'yellow' : o.status === 'ROLLBACK_FAILED' ? 'red' : 'gray'}">${esc(o.status)}</span>
               <span>${esc(o.kind)}</span>
               <span class="muted">${esc(o.current_stage || '')}</span>
               <span class="muted">${esc(timeAgo(o.created_at))}</span>
             </div>`).join('')
          : '<div class="muted">No operations recorded for this connection yet.</div>';
      }
    } catch { /* keep the last good render */ }
    if (!stopped && live) setTimeout(tick, 1500);
  };
  await tick();
}

// ------------------------------------------------------------------ MTU actions

function mtuProbeText(probe) {
  if (!probe) return '—';
  if (probe.state !== 'PASS') return probe.state;
  return probe.max_ok === null || probe.max_ok === undefined ? 'PASS' : `PASS ${probe.max_ok} B`;
}

function mtuConfidenceBadge(confidence) {
  const cls = confidence === 'high' ? 'green' : confidence === 'medium' ? 'yellow' : confidence === 'low' ? 'yellow' : 'gray';
  return `<span class="badge ${cls}">${esc(String(confidence || 'unknown').toUpperCase())} confidence</span>`;
}

// "View Detailed Results": the per-side breakdown, rendered into the panel the
// Connections page owns so the numbers stay on the page they belong to.
async function openMtuDetails(id) {
  const c = connectionById(id);
  if (!c) { toast('that connection is no longer loaded; refresh first', true); return; }
  const host = $('#connections-mtu');
  const tbody = $('#conn-mtu-body');
  if (!host || !tbody) { openMtuDetailsModal(c); return; }
  host.classList.remove('hidden');
  $('#conn-mtu-title').textContent = `MTU analysis — ${c.name}`;
  tbody.innerHTML = '<tr><td colspan="11" class="muted">Reading both sides…</td></tr>';
  const diag = await analyzeMtu(id, { silent: true });
  if (!diag) {
    tbody.innerHTML = `<tr><td colspan="11" class="muted">${esc(state.connMtuError[id] || 'the analysis failed')}</td></tr>`;
    return;
  }
  renderMtuDetail(c, diag, tbody, $('#conn-mtu-verdict'), $('#conn-mtu-checks'));
}

function mtuDetailRow(key, c, diag) {
  const rec = (diag && diag.recommendation) || {};
  const view = (rec.sides && rec.sides[key]) || {};
  const stored = c.mtu || {};
  const greMtu = view.ok ? view.gre_mtu : (key === 'iran' ? stored.iran_gre_mtu : stored.foreign_gre_mtu);
  const mss = view.ok ? (view.mss_clamp && view.mss_clamp.enabled ? 'on' : 'off') : stored.mss_clamp;
  const outer = view.outer_probe;
  const inner = view.inner_probe;
  const probe = outer && outer.state === 'PASS'
    ? mtuProbeText(outer)
    : `${mtuProbeText(outer)}<div class="muted conn-mtu-when">inner ${esc(mtuProbeText(inner))}</div>`;
  return `<tr>
    <td>${esc(view.label || key)}${view.ok ? '' : ' <span class="badge red">UNREADABLE</span>'}${view.error ? `<div class="muted conn-mtu-when">${esc(view.error)}</div>` : ''}</td>
    <td>${esc(view.server || '—')}</td>
    <td>${esc(mtuText(view.ok ? view.nic_mtu : null))}</td>
    <td>${esc(mtuText(greMtu))}</td>
    <td>${probe}</td>
    <td>${esc(mtuText(view.overhead))}</td>
    <td>${esc(mtuText(rec.recommended_gre_mtu))}</td>
    <td>${esc(mtuText(mss))}</td>
    <td>${mtuTestBadge(stored.last_test)}</td>
    <td class="muted">${stored.last_verified_at ? esc(timeAgo(stored.last_verified_at)) : 'never'}</td>
    <td>${mtuDriftBadge(diag && diag.combined && diag.combined.drift)}</td>
  </tr>`;
}

function mtuVerdictHtml(diag) {
  const rec = (diag && diag.recommendation) || {};
  return `
    <div class="mtu-verdict-line">
      ${mtuConfidenceBadge(rec.confidence)}
      <span>Recommended MTU: <strong>${esc(mtuText(rec.recommended_gre_mtu))}</strong>${rec.recommended_gre_mtu ? ' B' : ''}</span>
      <span>Underlay PMTU: <strong>${esc(mtuText(rec.underlay_mtu))}</strong>${rec.underlay_mtu ? ' B' : ''}</span>
      <span>Overhead: <strong>${esc(mtuText(rec.encapsulation_overhead))}</strong>${rec.encapsulation_overhead ? ' B' : ''}</span>
      ${rec.asymmetric ? '<span class="badge yellow" title="the two underlay paths disagree">ASYMMETRIC</span>' : ''}
    </div>
    <div class="muted">${esc(rec.reason || '')}</div>
    <div class="${rec.safe_to_apply ? 'muted' : 'mtu-not-safe'}">${rec.safe_to_apply
      ? 'Safe to apply: both ends can be verified after the change.'
      : 'Not safe to apply: the evidence is inconclusive, so the Hub refuses to change the MTU.'}</div>`;
}

function mtuChecksHtml(key, label, diag) {
  const data = (diag && diag[key] && diag[key].data) || {};
  const list = Array.isArray(data.checks) ? data.checks : [];
  return `<div class="mtu-check-col">
    <h4>${esc(label)} checks</h4>
    ${list.length
      ? `<ul class="preflight-list">${list.map((ch) => `<li class="${ch.status === 'PASS' ? 'ok' : ch.status === 'FAIL' ? 'bad' : ''}">${esc(`${ch.status} ${ch.id}`)} <span class="muted">${esc(ch.detail || '')}</span></li>`).join('')}</ul>`
      : '<div class="muted">no checks reported</div>'}
  </div>`;
}

function renderMtuDetail(c, diag, tbody, verdictEl, checksEl) {
  tbody.innerHTML = mtuDetailRow('iran', c, diag) + mtuDetailRow('foreign', c, diag);
  if (verdictEl) verdictEl.innerHTML = mtuVerdictHtml(diag);
  if (checksEl) checksEl.innerHTML = `<div class="mtu-check-grid">${mtuChecksHtml('iran', 'Iran', diag)}${mtuChecksHtml('foreign', 'Foreign', diag)}</div>`;
}

// Fallback for a page that does not carry the MTU panel.
async function openMtuDetailsModal(c) {
  openModal(`<h2>MTU analysis — ${esc(c.name)}</h2><p class="sub">Reading both sides…</p>`);
  const diag = await analyzeMtu(c.id, { silent: true });
  if (!diag) {
    openModal(`<h2>MTU analysis — ${esc(c.name)}</h2>
      <div class="form-error">${esc(state.connMtuError[c.id] || 'the analysis failed')}</div>
      <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);
    return;
  }
  const rec = (diag && diag.recommendation) || {};
  const view = (key) => (rec.sides && rec.sides[key]) || {};
  openModal(`
    <h2>MTU analysis — ${esc(c.name)}</h2>
    <p class="sub">What each side reports, and what the Hub recommends.</p>
    <div class="review-grid">
      <table class="review-table">
        <thead><tr><th>Side</th><th>NIC MTU</th><th>GRE MTU</th><th>Underlay probe</th><th>Inner probe</th><th>Overhead</th><th>MSS clamp</th></tr></thead>
        <tbody>${['iran', 'foreign'].map((k) => {
          const v = view(k);
          return `<tr>
            <td>${esc(v.label || k)}${v.ok ? '' : ' <span class="badge red">UNREADABLE</span>'}</td>
            <td>${esc(mtuText(v.nic_mtu))}</td>
            <td>${esc(mtuText(v.gre_mtu))}</td>
            <td>${esc(mtuProbeText(v.outer_probe))}</td>
            <td>${esc(mtuProbeText(v.inner_probe))}</td>
            <td>${esc(mtuText(v.overhead))}</td>
            <td>${esc(v.mss_clamp && v.mss_clamp.enabled ? 'on' : 'off')}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    </div>
    <div class="mtu-verdict">${mtuVerdictHtml(diag)}</div>
    <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`, { wide: true });
}

async function openMtuRecommend(id) {
  const c = connectionById(id);
  if (!c) { toast('that connection is no longer loaded; refresh first', true); return; }
  openModal(`<h2>Recommend MTU — ${esc(c.name)}</h2><p class="sub">Reading both sides…</p>`);
  const diag = await analyzeMtu(id, { silent: true });
  if (!diag) {
    openModal(`<h2>Recommend MTU — ${esc(c.name)}</h2>
      <div class="form-error">${esc(state.connMtuError[id] || 'the analysis failed')}</div>
      <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);
    return;
  }
  const rec = diag.recommendation || {};
  const sideRows = ['iran', 'foreign'].map((k) => {
    const v = (rec.sides && rec.sides[k]) || {};
    return `<tr>
      <td>${esc(v.label || k)}</td>
      <td>${esc(mtuText(v.nic_mtu))}</td>
      <td>${esc(v.capacity === null || v.capacity === undefined ? '—' : `${v.capacity} B`)}</td>
      <td>${esc(v.capacity_source || '—')}</td>
      <td>${esc(v.measured ? 'measured' : 'not measured')}</td>
    </tr>`;
  }).join('');

  openModal(`
    <h2>Recommend MTU — ${esc(c.name)}</h2>
    <p class="sub">Sized from the LOWER of the two verified underlay paths, never an average.</p>
    <div class="mtu-verdict">${mtuVerdictHtml(diag)}</div>
    <div class="review-grid">
      <table class="review-table">
        <thead><tr><th>Side</th><th>NIC MTU</th><th>Path capacity</th><th>Evidence</th><th>Probe</th></tr></thead>
        <tbody>${sideRows}</tbody>
      </table>
    </div>
    <div class="section"><h3>Why this value</h3><div class="output-pane">${esc(rec.reason || '')}${rec.margin_reason ? `\n${esc(rec.margin_reason)}` : ''}</div></div>
    <div class="foot">
      <button type="button" class="btn btn-ghost modal-cancel">Close</button>
      <button class="btn" id="mtu-recommend-apply" ${rec.safe_to_apply && rec.recommended_gre_mtu ? '' : 'disabled'}>Apply ${esc(mtuText(rec.recommended_gre_mtu))}${rec.recommended_gre_mtu ? ' B' : ''}</button>
    </div>`);

  const btn = $('#mtu-recommend-apply');
  if (btn && rec.safe_to_apply && rec.recommended_gre_mtu) {
    btn.addEventListener('click', () => { closeModal(); openMtuApply(id, rec.recommended_gre_mtu); });
  }
}

// The confirmation screen. Every fact an operator needs BEFORE the click is on it:
// both current values, the recommendation, what will change, the estimated risk, the
// verification checks that will run, and the conditions under which the Hub rolls back.
async function openMtuApply(id, presetTarget = null) {
  const c = connectionById(id);
  if (!c) { toast('that connection is no longer loaded; refresh first', true); return; }
  openModal(`<h2>Apply MTU — ${esc(c.name)}</h2><p class="sub">Reading both sides…</p>`);
  const diag = await analyzeMtu(id, { silent: true });
  const rec = diag ? (diag.recommendation || {}) : {};
  const preset = presetTarget === null || presetTarget === undefined ? rec.recommended_gre_mtu : presetTarget;
  const plan = diag
    ? await api(`/api/gre-connections/${id}/mtu/plan`, { method: 'POST', body: { mtu: preset || 0 } }).catch(() => null)
    : null;

  if (!plan) {
    openModal(`<h2>Apply MTU — ${esc(c.name)}</h2>
      <div class="form-error">${esc(state.connMtuError[id] || 'the diagnostics could not be read, so no plan can be shown')}</div>
      <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);
    return;
  }

  const riskClass = plan.risk.level === 'high' ? 'bad' : plan.risk.level === 'medium' ? '' : 'ok';
  openModal(`
    <h2>Apply MTU — ${esc(c.name)}</h2>
    <p class="sub">This changes the interface MTU only. The GRE interface is NOT recreated, so the peer, key, addressing and rules stay as they are.</p>

    <div class="review-grid">
      <table class="review-table">
        <thead><tr><th>Field</th><th>Current</th><th>New</th></tr></thead>
        <tbody>
          <tr><td>Current Iran GRE MTU</td><td>${esc(mtuText(plan.current.iran))}</td><td>${esc(mtuText(plan.target))}</td></tr>
          <tr><td>Current Foreign GRE MTU</td><td>${esc(mtuText(plan.current.foreign))}</td><td>${esc(mtuText(plan.target))}</td></tr>
          <tr><td>Recommended MTU</td><td colspan="2">${esc(mtuText(plan.recommended_mtu))}${plan.recommended_mtu ? ' B' : ''} — ${mtuConfidenceBadge(plan.confidence)}</td></tr>
          <tr><td>Underlay PMTU / overhead</td><td colspan="2">${esc(mtuText(plan.underlay_mtu))} B − ${esc(mtuText(plan.encapsulation_overhead))} B</td></tr>
          <tr><td>Minimum legal MTU</td><td colspan="2">${esc(mtuText(plan.min_legal_mtu))} B</td></tr>
        </tbody>
      </table>
    </div>

    <div class="section"><h3>What will change</h3><ul class="impact-list">${(plan.what_changes || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>
    <div class="section"><h3>Estimated risk — ${esc(plan.risk.level)}</h3><ul class="impact-list">${(plan.risk.reasons || []).map((x) => `<li class="${riskClass}">${esc(x)}</li>`).join('')}</ul></div>
    <div class="section"><h3>Verification checks</h3><ul class="preflight-list">${(plan.verification_checks || []).map((x) => `<li class="ok">${esc(x.description || x.id)}</li>`).join('')}</ul></div>
    <div class="section"><h3>Rollback conditions</h3><ul class="impact-list">${(plan.rollback_conditions || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>

    <div class="field"><label for="mtu-target">MTU to apply</label><input id="mtu-target" inputmode="numeric" value="${esc(plan.target === null ? '' : String(plan.target))}" /></div>
    <div class="form-error" id="mtu-error">${plan.can_apply ? '' : esc(plan.blocked_reason || 'this change cannot be applied')}</div>
    <div class="foot">
      <button type="button" class="btn btn-ghost modal-cancel">Cancel</button>
      <button class="btn" id="mtu-confirm">I understand — apply the MTU change</button>
    </div>`);

  const confirm = $('#mtu-confirm');
  if (!confirm) return;
  confirm.addEventListener('click', async () => {
    const err = $('#mtu-error');
    const target = Number($('#mtu-target').value);
    err.textContent = '';
    if (!Number.isInteger(target)) { err.textContent = 'the MTU must be a whole number'; return; }
    confirm.disabled = true;
    confirm.textContent = 'Applying…';
    closeModal();
    openConnectionTimeline(c.id, true);
    try {
      const result = await api(`/api/gre-connections/${c.id}/mtu`, { method: 'PUT', body: { mtu: target, confirm: true } });
      toast(`MTU ${target} applied to both sides and verified (reachability ${result.connectivity.state})`);
      await loadConnections();
      await analyzeMtu(c.id, { silent: true });
    } catch (e) {
      // A failed or rolled-back change must say which, and how to recover.
      if (e.data && e.data.rollback === 'FAILED' && e.data.manual_recovery) {
        openManualRecovery({ error: e.message, manual_recovery: e.data.manual_recovery });
      } else {
        toast(`${e.message}${e.data && e.data.rollback === 'CLEAN' ? ' (the previous MTU was restored)' : ''}`, true);
      }
      await loadConnections();
    }
  });
}

async function openMtuRestore(id) {
  const c = connectionById(id);
  if (!c) { toast('that connection is no longer loaded; refresh first', true); return; }
  openModal(`<h2>Restore previous MTU — ${esc(c.name)}</h2><p class="sub">Loading the MTU operations…</p>`);
  const detail = await api(`/api/gre-connections/${id}`).catch(() => null);
  const ops = ((detail && detail.recent_operations) || []).filter((o) => o.kind === 'MTU_CHANGE');
  const rows = ops.map((o) => {
    const canRestore = ['SUCCEEDED', 'ROLLBACK_FAILED', 'INTERRUPTED'].includes(o.status);
    return `<tr>
      <td>${esc(timeAgo(o.created_at))}</td>
      <td><span class="badge ${MTU_TEST_CLASS[o.status] || 'gray'}">${esc(o.status)}</span></td>
      <td class="muted">${esc(o.current_stage || '')}</td>
      <td class="muted">${esc(String(o.operation_id).slice(0, 8))}…</td>
      <td><button class="btn btn-ghost btn-sm mtu-restore-op" data-op="${esc(o.operation_id)}" ${canRestore ? '' : 'disabled'}>Restore Previous MTU</button></td>
    </tr>`;
  }).join('');

  openModal(`
    <h2>Restore previous MTU — ${esc(c.name)}</h2>
    <p class="sub">A restore re-applies the MTU that operation recorded before it changed anything, through the same verified transaction.</p>
    ${ops.length
      ? `<div class="review-grid"><table class="review-table">
           <thead><tr><th>When</th><th>Status</th><th>Stage</th><th>Operation</th><th></th></tr></thead>
           <tbody>${rows}</tbody>
         </table></div>`
      : '<div class="empty">No MTU operation has been run on this connection yet.</div>'}
    <div class="form-error" id="mtu-restore-error"></div>
    <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);

  $$('.mtu-restore-op').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const err = $('#mtu-restore-error');
      err.textContent = '';
      btn.disabled = true;
      btn.textContent = 'Restoring…';
      try {
        const result = await api(`/api/gre-connections/${c.id}/mtu/restore`, { method: 'POST', body: { operation_id: btn.dataset.op } });
        closeModal();
        toast(`Previous MTU restored (${result.applied.iran_mtu} / ${result.applied.foreign_mtu} B) and verified`);
        await loadConnections();
        await analyzeMtu(c.id, { silent: true });
      } catch (e) {
        if (e.data && e.data.rollback === 'FAILED' && e.data.manual_recovery) {
          openManualRecovery({ error: e.message, manual_recovery: e.data.manual_recovery });
        } else {
          err.textContent = e.message;
        }
        btn.disabled = false;
        btn.textContent = 'Restore Previous MTU';
      }
    });
  });
}

// Advanced NIC Settings: the read-only WAN NIC risk analysis for both sides.
async function openMtuNic(id) {
  const c = connectionById(id);
  if (!c) { toast('that connection is no longer loaded; refresh first', true); return; }
  openModal(`<h2>Advanced NIC settings — ${esc(c.name)}</h2><p class="sub">Reading the WAN interfaces on both sides…</p>`);
  let data;
  try {
    data = await api(`/api/gre-connections/${id}/mtu/nic`);
  } catch (err) {
    openModal(`<h2>Advanced NIC settings — ${esc(c.name)}</h2>
      <div class="form-error">${esc(err.message)}</div>
      <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`);
    return;
  }
  const side = (key, label) => {
    const s = data[key] || {};
    const d = s.data || {};
    const nics = Array.isArray(d.nics) ? d.nics : [];
    const checks = Array.isArray(d.checks) ? d.checks : [];
    const risk = (data.combined && data.combined.risk_by_side && data.combined.risk_by_side[key]) || (d.risk || null);
    return `<div class="section">
      <h3>${esc(label)} — ${s.ok ? `<span class="badge ${risk === 'high' ? 'red' : risk === 'medium' ? 'yellow' : 'green'}">${esc(String(risk || 'unknown').toUpperCase())} RISK</span>` : '<span class="badge red">UNREADABLE</span>'}</h3>
      ${s.ok ? '' : `<div class="form-error">${esc(s.error || 'could not be read')}</div>`}
      ${nics.length ? `<table class="review-table"><thead><tr><th>Interface</th><th>Role</th><th>MTU</th><th>Up</th><th>Risk</th><th>Notes</th></tr></thead>
        <tbody>${nics.map((n) => `<tr><td>${esc(n.iface || '—')}</td><td>${esc(n.role || (n.wan ? 'wan' : '—'))}</td><td>${esc(mtuText(n.mtu))}</td><td>${n.up === false ? 'no' : 'yes'}</td><td>${esc(String(n.risk || '—'))}</td><td class="muted">${esc((n.notes || []).join('; '))}</td></tr>`).join('')}</tbody></table>` : '<div class="muted">no NIC data reported</div>'}
      ${checks.length ? `<ul class="preflight-list">${checks.map((ch) => `<li class="${ch.status === 'PASS' ? 'ok' : ch.status === 'FAIL' ? 'bad' : ''}">${esc(`${ch.status} ${ch.id}`)} <span class="muted">${esc(ch.detail || '')}</span></li>`).join('')}</ul>` : ''}
    </div>`;
  };
  openModal(`
    <h2>Advanced NIC settings — ${esc(c.name)}</h2>
    <p class="sub">Read-only WAN NIC analysis. Nothing here changes an interface; the Hub only reads what the CLI reports.</p>
    <div class="mtu-verdict-line"><span>Overall WAN risk: <strong>${esc(String((data.combined && data.combined.overall_risk) || 'unknown').toUpperCase())}</strong></span></div>
    ${side('iran', 'Iran')}
    ${side('foreign', 'Foreign')}
    <div class="foot"><button type="button" class="btn modal-cancel">Close</button></div>`, { wide: true });
}

// The Connections page owns the MTU drill-down panel, so its close control is bound
// here rather than left to the page shell.
const mtuPanelClose = document.getElementById('btn-conn-mtu-close');
if (mtuPanelClose) {
  mtuPanelClose.addEventListener('click', () => {
    const panel = document.getElementById('connections-mtu');
    if (panel) panel.classList.add('hidden');
  });
}

// The page controls in app.js reach the renderer through this namespace.
window.ConnectionsUI = { load: loadConnections, render: renderConnections, analyzeMtu, openMtuDetails };
