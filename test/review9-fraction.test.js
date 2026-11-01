'use strict';

// Review #9 (2026-11-01, independent follow-up to the review-7 issued_at
// fix): fractional seconds were dropped, so the 24h future bound was loose
// by up to 999999 microseconds.
//
// Findings measured against the pre-fix tree 5770b59:
//   R9-1 MED: issuedAtMs() assembled the instant with
//        setUTCHours(hour, minute, second, 0) — the ISSUED_AT regex matched
//        an optional 1-6 digit fraction but the fraction was NEVER captured
//        or applied. A body dated exactly now+24h plus .999999 was accepted
//        as if it were exactly now+24h: measured ALLOWED at
//        now+24h+0.999999s (999999 microseconds past the documented bound),
//        while now+24h+1s was refused. The bound's real edge was therefore
//        fuzzy: any spelling within the last 999999 microseconds of the
//        second boundary slipped through.
//
//   Not a false alarm: the sub-second spelling is a real RFC3339 moment
//   that openreceipts' own signer CAN emit — receipt.py defaults to
//   timespec="seconds" but accepts an explicit --issued-at, and the Node
//   verifier parses fractions. The daemon must not be the only party that
//   misreads the artifact.
//
// The first block FAILS on the pre-fix tree (fraction boundary accepted)
// and passes after the fix. The guards at the bottom pass on BOTH trees.

process.umask(0o077);

const assert = require('node:assert');
const test = require('node:test');
const { evaluateMessage } = require('../src/policy-message');

const PUBKEY = Buffer.alloc(32, 9).toString('base64');

function grant(overrides = {}) {
  return {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: PUBKEY, maxBytes: '3072', expiresAt: '2099-01-01T00:00:00Z',
    windowMaxMessages: '4', windowSeconds: '3600', ...overrides,
  };
}

function body(overrides = {}) {
  return {
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', claims: {},
    issued_at: '2026-06-15T00:00:00Z', ...overrides,
  };
}

// Pinned clock: fixed so the boundary is reproducible, not "whenever the
// suite runs". BASE is exactly 24h before TARGET.
const BASE = new Date('2026-06-15T00:00:00.000Z');
const TARGET = '2026-06-16T00:00:00Z';

test('R9-1: a fraction inside the last microsecond of the second is bounded', () => {
  // Exactly +24h: allowed — the bound is inclusive (strict >).
  assert.equal(evaluateMessage(body({ issued_at: TARGET }), grant(), BASE).allowed, true,
    'exactly +24h must stay allowed (inclusive bound)');

  // 1 millisecond over: refused (this already worked pre-fix).
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-06-16T00:00:01Z' }), grant(), BASE).refused,
    'issued_at_in_future');

  // The defect: sub-second fractions were truncated to the second boundary,
  // so everything from +24h.000001s up to +24h.999999s slipped past the
  // bound. These must now be refused.
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-06-16T00:00:00.000001Z' }), grant(), BASE).refused,
    'issued_at_in_future', '1 microsecond over the bound must be refused');
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-06-16T00:00:00.500000Z' }), grant(), BASE).refused,
    'issued_at_in_future', 'half a second over the bound must be refused');
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-06-16T00:00:00.999999Z' }), grant(), BASE).refused,
    'issued_at_in_future', 'the full 999999 microseconds over the bound must be refused');
});

test('R9-1: the same fraction arithmetic works through a non-Z offset', () => {
  // Same instant as TARGET but spelled +00:00 — must behave identically.
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-16T00:00:00.000001+00:00' }), grant(), BASE).refused,
    'issued_at_in_future', '1 microsecond over via +00:00 must be refused');
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-16T00:00:00+00:00' }), grant(), BASE).allowed, true);

  // An offset spelling whose instant is inside the bound stays allowed even
  // with a fraction: +02:00 of 00:00:00.999999 on the target day denotes
  // 22:00:00.999999Z the day BEFORE, i.e. well in the past.
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-16T00:00:00.999999+02:00' }), grant(), BASE).allowed, true);
});

test('R9-1: truncation is gone — fractions below 1ms still round-trip the instant', () => {
  // Guard against a fix that only *rejects* fractions: .123456 must still
  // be ACCEPTED when it is comfortably in the past, because openreceipts
  // emits fractions and review #7 pinned that acceptance.
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-06-15T00:00:00.123456Z' }), grant(), BASE).allowed, true,
    'a past-dated sub-millisecond fraction must stay allowed');
});

test('guard (passes on BOTH trees): the bound itself did not move', () => {
  // Exactly +24h accepted, +1s refused, far future refused, past allowed —
  // these are the review-7 semantics, unchanged by the fraction fix.
  assert.equal(evaluateMessage(body({ issued_at: TARGET }), grant(), BASE).allowed, true);
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-16T00:00:01Z' }), grant(), BASE).refused, 'issued_at_in_future');
  assert.equal(evaluateMessage(body({ issued_at: '2026-07-15T00:00:00Z' }), grant(), BASE).refused, 'issued_at_in_future');
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-14T23:00:00Z' }), grant(), BASE).allowed, true);
  // Grammar guards from review #7 stay refused.
  assert.equal(evaluateMessage(body({ issued_at: '2026-02-30T00:00:00Z' }), grant(), BASE).refused, 'envelope');
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-16T00:00:00.1234567Z' }), grant(), BASE).refused, 'envelope');
  assert.equal(evaluateMessage(body({ issued_at: '2026-06-16T00:00:60Z' }), grant(), BASE).refused, 'envelope');
});

test('guard (passes on BOTH trees): year-9999 boundary still refused via the future bound', () => {
  // Out-of-safe-integer-range instant: the fix falls back to whole-ms
  // precision there rather than changing the verdict class.
  const r = evaluateMessage(body({ issued_at: '9999-12-31T23:59:59.999999+23:59' }), grant(), BASE);
  assert.equal(r.refused, 'issued_at_in_future');
});
