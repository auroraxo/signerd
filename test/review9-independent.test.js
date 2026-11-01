'use strict';

// Review #9 (independent, 2026-11-01): findings from my own probes, written
// against HEAD 5770b59 on branch independent/envelope-review.
//
// R9-1 (MINOR): the 24h future bound is computed on an instant whose
//   fractional seconds were DROPPED (policy-message.js issuedAtMs assembled
//   the instant with setUTCHours(..., 0)), so a receipt stamped
//   now+24h+1ms up to now+24h+999.999ms was signed although the documented
//   contract is "refused beyond now + 24h". Measured with a frozen clock:
//   ==+24h ALLOW, +1ms ALLOW, +999ms ALLOW, +999999us ALLOW, +1s REFUSE.
//
// R9-2 (LOW): src/client.js buildReceiptBody treats issued_at as optional
//   (`if (typeof issuedAt === 'string')`) while 84888d4 made it REQUIRED at
//   the daemon. A caller that follows the helper's own signature gets a body
//   the daemon always refuses ('envelope'). The helper is exported API of
//   this repo and its JSDoc lists issued_at among the built fields without
//   marking it as required.
//
// Ladder convention (repo): the FIRST block must be RED on the pre-fix tree
// and GREEN here. The guards at the bottom must be GREEN on BOTH trees (they
// are the false-positive watchdogs).
//
// Pre-fix trees used for falsification:
//   20140e9 — parent of 84888d4 (no future bound at all)
//   5770b59 — HEAD before this review's fixes (bound present, overshoot present)

process.umask(0o077);

const assert = require('node:assert');
const test = require('node:test');
const { evaluateMessage } = require('../src/policy-message');
const { buildReceiptBody } = require('../src/client');

const PUBKEY = Buffer.alloc(32, 9).toString('base64');
// Frozen clock: bound = 1970-01-02T00:00:00.000Z exactly.
const FROZEN = new Date(0);

function grant(overrides = {}) {
  return {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: PUBKEY, maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
    windowMaxMessages: '5', windowSeconds: '3600', ...overrides,
  };
}

function body(overrides = {}) {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '1970-01-01T00:00:00Z',
    claims: { version: 'v0.1.0' },
    ...overrides,
  };
}

// ---------- R9-1: the future bound must hold at the millisecond ----------

test('R9-1: issued_at +24h+1ms past the bound is refused', () => {
  const v = evaluateMessage(body({ issued_at: '1970-01-02T00:00:00.001Z' }), grant(), FROZEN);
  assert.equal(v.refused, 'issued_at_in_future');
});

test('R9-1: issued_at +24h+999ms past the bound is refused', () => {
  const v = evaluateMessage(body({ issued_at: '1970-01-02T00:00:00.999Z' }), grant(), FROZEN);
  assert.equal(v.refused, 'issued_at_in_future');
});

test('R9-1: issued_at +24h+999.999ms (max fraction) past the bound is refused', () => {
  const v = evaluateMessage(
    body({ issued_at: '1970-01-02T00:00:00.999999Z' }), grant(), FROZEN);
  assert.equal(v.refused, 'issued_at_in_future');
});

test('R9-1: the fraction counts in the bound for a non-UTC offset too', () => {
  // 1970-01-02T00:00:00+00:00 is the bound; +00:00 with a fraction 1ms over
  // must refuse, exactly like the Z spelling.
  const v = evaluateMessage(
    body({ issued_at: '1970-01-02T00:00:00.001+00:00' }), grant(), FROZEN);
  assert.equal(v.refused, 'issued_at_in_future');
});

// ---------- R9-2: the client helper must not build a refused body ----------

test('R9-2: buildReceiptBody without issuedAt builds an accepted body', () => {
  const b = buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    claims: { version: 'v1' },
  });
  const v = evaluateMessage(b, grant());
  assert.equal(v.allowed, true,
    `the helper's own output must pass the policy (got refused=${v.refused})`);
});

// ---------- guards: green on BOTH the pre-fix tree and this one ----------

test('guard: exactly +24h (no fraction) is still allowed (boundary is inclusive)', () => {
  const v = evaluateMessage(body({ issued_at: '1970-01-02T00:00:00Z' }), grant(), FROZEN);
  assert.equal(v.allowed, true);
});

test('guard: the measured consumer stamp (+21.4h) is still allowed', () => {
  const now = Date.now();
  const stamp = new Date(now + 21.4 * 3600 * 1000).toISOString();
  const v = evaluateMessage(body({ issued_at: stamp }), grant(), new Date(now));
  assert.equal(v.allowed, true);
});

test('guard: a past stamp with a fraction is still allowed', () => {
  const v = evaluateMessage(
    body({ issued_at: '1970-01-01T00:00:00.123456Z' }), grant(), FROZEN);
  assert.equal(v.allowed, true);
});

test('guard: a past stamp far back is still allowed (backdating stays legal)', () => {
  const v = evaluateMessage(
    body({ issued_at: '1900-01-01T00:00:00+00:00' }), grant(), FROZEN);
  assert.equal(v.allowed, true);
});

test('guard: buildReceiptBody with an explicit issuedAt is accepted', () => {
  const b = buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    claims: { version: 'v1' }, issuedAt: '1970-01-01T00:00:00+00:00',
  });
  const v = evaluateMessage(b, grant(), FROZEN);
  assert.equal(v.allowed, true);
});

test('guard: canonical bytes of an explicit-issuedAt body are unchanged', () => {
  const b = buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    claims: { version: 'v1' }, issuedAt: '1970-01-01T00:00:00+00:00',
  });
  const v = evaluateMessage(b, grant(), FROZEN);
  assert.equal(v.allowed, true);
  assert.equal(
    v.messageBytes.toString('utf8'),
    '{"claims":{"version":"v1"},"issued_at":"1970-01-01T00:00:00+00:00","issuer":"auroraxo","schema":"openreceipts/v1","subject":"auroraxo/signerd","type":"release"}',
  );
});

// ---------- the review-7 classes must stay refused (regression watchdog) ----------

test('regression: 2030-dated receipt stays refused', () => {
  const v = evaluateMessage(
    body({ issued_at: '2030-01-01T00:00:00+00:00' }), grant(), FROZEN);
  assert.equal(v.refused, 'issued_at_in_future');
});

test('regression: Feb 30 stays refused', () => {
  const v = evaluateMessage(
    body({ issued_at: '2026-02-30T00:00:00Z' }), grant());
  assert.equal(v.refused, 'envelope');
});

test('regression: +99:99 offset stays refused', () => {
  const v = evaluateMessage(
    body({ issued_at: '2026-11-01T00:00:00+99:99' }), grant());
  assert.equal(v.refused, 'envelope');
});

test('regression: missing issued_at stays refused', () => {
  const b = body();
  delete b.issued_at;
  assert.equal(evaluateMessage(b, grant()).refused, 'envelope');
});
