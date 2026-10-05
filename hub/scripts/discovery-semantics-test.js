'use strict';

// Discovery outcome classification and topology preservation.
//
// The contract under test: a probe that could not reach the server is an
// AVAILABILITY failure, while a probe that succeeded and found no manager is a
// genuine STATE. Only the second may change a server's topology, so a transient
// SSH failure can never move a server to UNCONFIGURED.

const {
  assert, check, checkAsync, report,
} = require('./_harness');
const discovery = require('../server/discovery');

// Build a marker-delimited probe body the way the real script prints it.
function probeBody({ installed = 1, version = 'gre-manager v2.8.2', roles = null, statusRaw = null } = {}) {
  const lines = ['@@BEGIN gre@@', `installed=${installed}`];
  if (installed) {
    lines.push(version);
    lines.push('@@BEGIN status_json@@');
    if (statusRaw !== null) lines.push(statusRaw);
    else if (roles) lines.push(JSON.stringify({ roles, tunnels_up: roles.length ? 1 : 0 }));
    lines.push('@@END status_json@@');
  }
  lines.push('@@END gre@@');
  lines.push('@@BEGIN tunnels@@', '@@END tunnels@@');
  lines.push('@@BEGIN managed_tuns@@', '@@END managed_tuns@@');
  lines.push('@@BEGIN legacy@@', '@@END legacy@@');
  return `${lines.join('\n')}\n`;
}

console.log('discovery outcome classification:');

const FAILURES = [
  ['timeout', { rc: -1, stdout: '', stderr: 'command timed out after 60000ms' }],
  ['authentication failure', { rc: -1, stdout: '', stderr: 'ssh error: All configured authentication methods failed' }],
  ['connection refused', { rc: -1, stdout: '', stderr: 'ssh error: connect ECONNREFUSED 10.0.0.1:22' }],
  ['host key mismatch', { hostkey_mismatch: true, presented_fp: 'SHA256:deadbeef' }],
  ['transport reset', { rc: -1, stdout: '', stderr: 'ssh error: read ECONNRESET' }],
  ['no credentials', { rc: -1, stdout: '', stderr: 'no credentials stored — set a password or reinstall the SSH key' }],
];

for (const [label, result] of FAILURES) {
  check(`${label} is a FAILURE, never a state`, () => {
    const verdict = discovery.classifyProbeResult(result);
    assert.equal(verdict.ok, false, `${label} must not be treated as a successful discovery`);
    assert(verdict.errorClass, 'a failure needs an error class');
    assert(verdict.reason, 'a failure needs a human reason');
    assert(!verdict.snapshot, 'a failure must not carry a snapshot');
  });
}

check('a truncated probe (markers missing) is a FAILURE, not "no manager"', () => {
  const verdict = discovery.classifyProbeResult({ rc: 0, stdout: 'partial output with no markers\n', stderr: '' });
  assert.equal(verdict.ok, false, 'unparseable output must not become an empty-role state');
  assert.equal(verdict.errorClass, 'malformed');
});

check('a zero exit code with no output is a FAILURE', () => {
  const verdict = discovery.classifyProbeResult({ rc: 0, stdout: '', stderr: '' });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.errorClass, 'malformed');
});

check('manager genuinely absent is a SUCCESSFUL probe with zero roles', () => {
  const verdict = discovery.classifyProbeResult({ rc: 0, stdout: probeBody({ installed: 0 }), stderr: '' });
  assert.equal(verdict.ok, true, 'a completed probe that found no manager is still a successful discovery');
  assert(verdict.snapshot, 'a successful discovery must carry the state');
  assert.equal(verdict.snapshot.manager.installed, false);
  assert.deepEqual(verdict.snapshot.roles, []);
});

check('a FOREIGN server yields roles=["FOREIGN"]', () => {
  const verdict = discovery.classifyProbeResult({ rc: 0, stdout: probeBody({ roles: ['FOREIGN'] }), stderr: '' });
  assert.equal(verdict.ok, true);
  assert.deepEqual(verdict.snapshot.roles, ['FOREIGN']);
  assert.equal(verdict.snapshot.manager.installed, true);
  assert.equal(verdict.snapshot.manager.version, '2.8.2');
});

check('a status_json parse error is still a successful probe', () => {
  const verdict = discovery.classifyProbeResult({ rc: 0, stdout: probeBody({ statusRaw: '{not json' }), stderr: '' });
  assert.equal(verdict.ok, true, 'a malformed status body means the manager is present but unhappy, not unreachable');
  assert.equal(verdict.snapshot.status.parse_error, true);
});

console.log('\nsecret sanitisation:');

check('probe error messages are redacted before they can be stored', () => {
  const cases = [
    ['ssh error for user:sup3rsecret@host', ['sup3rsecret']],
    ['password=hunter2 failed', ['hunter2']],
    ['{"privateKey":"abc123def"}', ['abc123def']],
    ['Authorization: Bearer sk-live-abcdef123456', ['sk-live-abcdef123456']],
    ['ss://YWVzOnNlY3JldA==@1.2.3.4:3001', ['ss://', 'c2VjcmV0']],
    ['-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----', ['MIIabc']],
  ];
  for (const [input, forbidden] of cases) {
    const out = discovery.sanitizeMessage(input);
    for (const fragment of forbidden) {
      assert(!out.includes(fragment), `"${fragment}" survived sanitisation: ${out}`);
    }
  }
});

check('a failed probe carries only a sanitised detail', () => {
  const verdict = discovery.classifyProbeResult({
    rc: -1, stdout: '', stderr: 'ssh error: user:sup3rsecret@10.0.0.1 unreachable',
  });
  assert.equal(verdict.ok, false);
  assert(!String(verdict.detail).includes('sup3rsecret'), `leaked: ${verdict.detail}`);
});

console.log('\nhealth probe:');

check('a healthy transport is acknowledged by its marker', () => {
  // Exercised through the classifier path indirectly; the marker constant is the
  // contract the remote command and the parser share.
  assert.equal(discovery.HEALTH_PROBE, 'echo hub-health-ok');
  assert.equal(discovery.HEALTH_MARKER, 'hub-health-ok');
  assert(discovery.HEALTH_PROBE.includes(discovery.HEALTH_MARKER),
    'the command must print the marker the parser looks for');
});

check('error classes declare whether a retry is worth attempting', () => {
  assert.equal(discovery.isRetryable('timeout'), true);
  assert.equal(discovery.isRetryable('transport'), true);
  assert.equal(discovery.isRetryable('refused'), true);
  assert.equal(discovery.isRetryable('hostkey'), false, 'a pinned host key must not be silently retried away');
  assert.equal(discovery.isRetryable('auth'), false);
  assert.equal(discovery.isRetryable('nonsense-class'), true, 'unknown classes default to retryable');
});

check('every declared error class has a reason and a retry policy', () => {
  for (const [name, meta] of Object.entries(discovery.ERROR_CLASSES)) {
    assert(typeof meta.reason === 'string' && meta.reason, `${name} needs a reason`);
    assert(typeof meta.retryable === 'boolean', `${name} needs a retryable flag`);
  }
  for (const name of ['timeout', 'auth', 'refused', 'hostkey', 'transport', 'malformed', 'remote', 'nocreds']) {
    assert(discovery.ERROR_CLASSES[name], `missing required error class ${name}`);
  }
});

console.log('\nbackward compatibility:');

async function main() {
  await checkAsync('legacy discover() still returns a snapshot-shaped failure', async () => {
    // The old contract: a caller that ignores the verdict still gets roles:[] and
    // an `error` string, so nothing downstream breaks.
    const server = { id: 1, name: 'x', host: '127.0.0.1', ssh_port: 1, username: 'root', auth_type: 'password' };
    const snap = await discovery.discover(server, 'pw', {});
    assert(snap && typeof snap === 'object', 'discover() must still resolve to an object');
    assert(Array.isArray(snap.roles), 'the legacy shape must keep a roles array');
    assert.equal(snap.roles.length, 0, 'an unreachable host yields no roles (the legacy behaviour)');
    assert(snap.error, 'the legacy shape must carry an error string');
    assert(snap.error_class, 'and now also the classified reason');
  });

  report('discovery tests');
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
