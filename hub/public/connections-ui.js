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

  const body = rows.map((c) => `
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
      <td class="conn-actions">
        <button class="btn btn-ghost btn-sm btn-conn-edit" data-id="${c.id}">Edit</button>
        <button class="btn btn-ghost btn-sm btn-conn-timeline" data-id="${c.id}">Timeline</button>
      </td>
    </tr>`).join('');

  wrap.innerHTML = `
    <div class="conn-table-wrap">
      <table class="conn-table">
        <thead><tr>
          <th>Name</th><th>Iran Server</th><th>Foreign Server</th><th>Tunnel</th>
          <th>Subnet</th><th>Key</th><th>TCP</th><th>UDP</th>
          <th>Iran State</th><th>Foreign State</th><th>Last Verified</th><th></th>
        </tr></thead>
        <tbody>${body || '<tr><td colspan="12" class="muted" style="padding:14px">No connection matches that filter.</td></tr>'}</tbody>
      </table>
    </div>`;

  $$('.btn-conn-edit', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openConnectionEdit(Number(btn.dataset.id)));
  });
  $$('.btn-conn-timeline', wrap).forEach((btn) => {
    btn.addEventListener('click', () => openConnectionTimeline(Number(btn.dataset.id)));
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

// The page controls in app.js reach the renderer through this namespace.
window.ConnectionsUI = { load: loadConnections, render: renderConnections };
