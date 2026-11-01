'use strict';

// Review #7 (message-grant envelope, 2026-11-01): the issued_at contract.
//
// Findings measured against the pre-fix tree 20140e9:
//   R7-1 HIGH: a body WITHOUT issued_at was signed; the primary Python
//        consumer (openreceipts receipt.py verify) CRASHES on such an
//        artifact (KeyError: 'issued_at').
//   R7-2 HIGH: issued_at was format-bounded only. Impossible calendar dates
//        ("2026-02-30", Date.parse normalizes to March 2) and offsets outside
//        the RFC3339 grammar ("+99:99", second "60") were accepted and signed.
//        The grant expiry already refuses exactly this class (canonical round
//        trip); the body field did not.
//
// The first block FAILS on the pre-fix tree and must pass after the fix.
// The guards at the bottom pass on BOTH trees (the false-positive guards).

process.umask(0o077);

const assert = require('node:assert');
const test = require('node:test');
const { evaluateMessage } = require('../src/policy-message');

const PUBKEY = Buffer.alloc(32, 9).toString('base64');

function grant(overrides = {}) {
  return {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: PUBKEY, maxBytes: '700', expiresAt: futureIso(),
    windowMaxMessages: '5', windowSeconds: '3600', ...overrides,
  };
}

function futureIso(seconds = 3600) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function body(overrides = {}) {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-01T00:00:00+00:00',
    claims: { version: 'v0.1.0' },
    ...overrides,
  };
}

// ---------- the fix (red on the pre-fix tree) ----------

test('R7-1: a receipt body without issued_at is refused, not signed', () => {
  const b = body();
  delete b.issued_at;
  assert.equal(evaluateMessage(b, grant()).refused, 'envelope');
});

test('R7-2a: an impossible calendar date normalizes no more', () => {
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-02-30T00:00:00+00:00' }), grant()).refused,
    'envelope',
  );
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-02-30T00:00:00Z' }), grant()).refused,
    'envelope',
  );
});

test('R7-2b: offsets outside the RFC3339 grammar are refused', () => {
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-11-01T00:00:00+99:99' }), grant()).refused,
    'envelope',
  );
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-11-01T00:00:00+24:00' }), grant()).refused,
    'envelope',
  );
});

test('R7-2c: a leap second spelling is refused', () => {
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-06-30T23:59:60Z' }), grant()).refused,
    'envelope',
  );
});

test('R7-2d: month/day component ranges are enforced', () => {
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-13-01T00:00:00Z' }), grant()).refused,
    'envelope',
  );
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-01-32T00:00:00Z' }), grant()).refused,
    'envelope',
  );
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-01-01T25:00:00Z' }), grant()).refused,
    'envelope',
  );
});

// ---------- guards (green on both trees) ----------

test('guard: the openreceipts native spellings still pass', () => {
  assert.equal(evaluateMessage(body(), grant()).allowed, true);
  assert.equal(evaluateMessage(body({ issued_at: '2026-11-01T00:00:00Z' }), grant()).allowed, true);
  // sub-second fractions stay format-legal
  assert.equal(evaluateMessage(body({ issued_at: '2026-11-01T00:00:00.123456Z' }), grant()).allowed, true);
  // a real UTC-offset timezone (the docs' example style)
  assert.equal(evaluateMessage(body({ issued_at: '2026-10-12T15:30:00+02:00' }), grant()).allowed, true);
});

test('guard: note stays optional and bounded', () => {
  assert.equal(evaluateMessage(body({ note: 'ok' }), grant()).allowed, true);
  assert.equal(evaluateMessage(body({ note: 'x'.repeat(257) }), grant()).refused, 'envelope');
});

test('guard: schema/pins/claims/size/expiry semantics unchanged', () => {
  assert.equal(evaluateMessage(body({ schema: 'openreceipts/v2' }), grant()).refused, 'invalid_schema');
  assert.equal(evaluateMessage(body({ issuer: 'someoneelse' }), grant()).refused, 'issuer');
  assert.equal(evaluateMessage(body({ type: 'scan' }), grant()).refused, 'type');
  assert.equal(evaluateMessage(body({ subject: 'auroraxo/other' }), grant()).refused, 'subject');
  assert.equal(evaluateMessage(body({ claims: { k: 42 } }), grant()).refused, 'claims');
  assert.equal(
    evaluateMessage(body({ claims: { pad: 'x'.repeat(800) } }), grant({ maxBytes: '300' })).refused,
    'message_too_large',
  );
  assert.equal(evaluateMessage(body(), grant({ expiresAt: futureIso(-1) })).refused, 'expired');
  assert.equal(
    evaluateMessage(JSON.parse('{"schema":"openreceipts/v1","extra":1}'), grant()).refused,
    'envelope',
  );
});

test('guard: canonical bytes of a valid body are unchanged by the fix', () => {
  const v = evaluateMessage(body(), grant());
  assert.equal(v.allowed, true);
  assert.equal(
    v.messageBytes.toString('utf8'),
    '{"claims":{"version":"v0.1.0"},"issued_at":"2026-11-01T00:00:00+00:00","issuer":"auroraxo","schema":"openreceipts/v1","subject":"auroraxo/signerd","type":"release"}',
  );
});

test('guard: a body with an own __proto__ property is refused without throwing', () => {
  const parsed = JSON.parse('{"schema":"openreceipts/v1","issuer":"auroraxo","type":"release","subject":"auroraxo/signerd","claims":{"version":"v1"},"__proto__":[]}');
  assert.doesNotThrow(() => evaluateMessage(parsed, grant()));
  assert.equal(evaluateMessage(parsed, grant()).refused, 'envelope');
});
