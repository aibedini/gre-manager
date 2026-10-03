'use strict';

// The event log is persisted and shown in the UI, so it must never carry
// anything that could reconstruct a working client. These assertions pin both
// halves of that contract: secrets are removed, operational facts survive.

const { assert, check, report } = require('./_harness');
const { RouteOrchestrator } = require('../server/route-orchestrator');

const redact = RouteOrchestrator.redact;

// Each case: a raw string, plus every fragment that must NOT survive.
const SECRET_CASES = [
  ['ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:3001#navid', ['ss://', 'c2VjcmV0']],
  ['existing credential resolved: password=hunter2secret', ['hunter2secret']],
  ['{"password":"abc123def"}', ['abc123def']],
  ['{"passwd":"abc123def"}', ['abc123def']],
  ['{"secret":"abc123def"}', ['abc123def']],
  ['{"privateKey":"abc123def"}', ['abc123def']],
  ['Authorization: Bearer sk-abcdef1234567890', ['sk-abcdef1234567890']],
  ['authorization: bearer eyJhbGciOiJIUzI1NiJ9.abc', ['eyJhbGciOiJIUzI1NiJ9.abc']],
  ['cookie: session=abcdef123456', ['session=abcdef123456']],
  ['x-csrf-token: deadbeefdeadbeef', ['deadbeefdeadbeef']],
  ['{"token":"abcdef1234567890"}', ['abcdef1234567890']],
  ['vmess://eyJhZGQiOiIxLjIuMy40In0=', ['vmess://', 'eyJhZGQiOiIxLjIuMy40In0=']],
  ['vless://uuid@1.2.3.4:443', ['vless://']],
  ['trojan://secret@1.2.3.4:443', ['secret@1.2.3.4']],
  ['-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----', ['MIIabc123']],
];

// Facts an operator needs, which must never be redacted away.
const KEEP_CASES = [
  'inbound #7 protocol=shadowsocks port=3001',
  'navid attached to inbound #7',
  'panel NetlenTRNew1 3x-ui v3.7.0 first_class',
  'public endpoint 193.24.120.23:3001',
  'route IRWEBD-NAVID-TR reached ACTIVE',
  'runtime_gre_iran PASS 10.201.1.1/30',
];

console.log('secret redaction:');

for (const [input, forbidden] of SECRET_CASES) {
  check(`redacts ${JSON.stringify(input.slice(0, 44))}`, () => {
    const out = redact(input);
    for (const fragment of forbidden) {
      assert(!out.includes(fragment), `"${fragment}" survived redaction: ${out}`);
    }
    assert(!/ss:\/\/|vmess:\/\/|vless:\/\/|trojan:\/\//i.test(out), `a share link survived: ${out}`);
    assert(!/BEGIN [A-Z ]*PRIVATE KEY/.test(out), `a private key survived: ${out}`);
  });
}

check('keeps the operational facts an operator needs', () => {
  for (const input of KEEP_CASES) {
    const out = redact(input);
    for (const token of input.split(/\s+/).filter((t) => /[a-z0-9]/i.test(t))) {
      assert(out.includes(token), `"${token}" was lost from "${input}" -> "${out}"`);
    }
  }
});

check('is applied on the way into route_events, not just offered as a helper', () => {
  const source = require('fs').readFileSync(require('path').join(__dirname, '..', 'server', 'route-orchestrator.js'), 'utf8');
  assert(/const safe = RouteOrchestrator\.redact\(detail\);/.test(source),
    'event() must sanitise its detail through redact()');
});

check('handles empty and non-string input without throwing', () => {
  assert.equal(redact(''), '');
  assert.equal(redact(null), '');
  assert.equal(redact(undefined), '');
  assert.equal(typeof redact(1234), 'string');
});

report('redaction tests');
