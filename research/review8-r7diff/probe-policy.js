'use strict';

// Review #8 — adversarial review of the Review-#7 fix diff (84888d4),
// scoped to the three shipped changes in src/policy-message.js:
//   (1) issued_at made REQUIRED (BODY_KEYS),
//   (2) issuedAtMs(): strict RFC3339 grammar + real calendar day +
//       explicit assembly (setUTCFullYear/setUTCHours, no Date.parse),
//   (3) future bound: refused('issued_at_in_future') beyond now+24h.
//
// Every probe states what it expects and why. The false-positive guards at
// the bottom are the cases that must KEEEP working (valid real-world
// spellings the real consumer produces).

process.umask(0o077);

const assert = require('node:assert');
const { evaluateMessage } = require('../../src/policy-message');

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

// The daemon clock is pinned per probe; the default now is 2026-11-01T02:00Z.
const PINNED_NOW = new Date('2026-11-01T02:00:00.000Z');

let pass = 0, fail = 0;
function check(name, fn) {
  try { fn(); pass++; console.log(`PASS  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}

// ---------------------------------------------------------------- required --

check('R8-1: issued_at missing -> envelope (required)', () => {
  const b = body(); delete b.issued_at;
  assert.equal(evaluateMessage(b, grant(), PINNED_NOW).refused, 'envelope');
});

check('R8-2: issued_at non-string (number) -> envelope', () => {
  assert.equal(evaluateMessage(body({ issued_at: 1793500000 }), grant(), PINNED_NOW).refused, 'envelope');
});

check('R8-3: issued_at inherited from Object.prototype does NOT satisfy required', () => {
  // ownString reads own properties only; a polluted prototype must not
  // satisfy the REQUIRED check.
  const b = body(); delete b.issued_at;
  Object.prototype.issued_at = '2026-11-01T00:00:00+00:00';
  try {
    assert.equal(evaluateMessage(b, grant(), PINNED_NOW).refused, 'envelope');
  } finally { delete Object.prototype.issued_at; }
});

// ------------------------------------------------------------------ grammar --

check('R8-4: leap second :60 and invalid offsets stay refused', () => {
  for (const bad of ['2026-11-01T00:00:60+00:00', '2026-11-01T00:00:00+24:00',
    '2026-11-01T00:00:00+99:99', '2026-11-01T24:00:00+00:00']) {
    assert.equal(evaluateMessage(body({ issued_at: bad }), grant(), PINNED_NOW).refused, 'envelope', bad);
  }
});

check('R8-5: impossible calendar dates stay refused (Feb 30, Feb 29 non-leap, day 32)', () => {
  for (const bad of ['2026-02-30T00:00:00+00:00', '2027-02-29T00:00:00+00:00',
    '2026-01-32T00:00:00+00:00', '2026-04-31T00:00:00+00:00']) {
    assert.equal(evaluateMessage(body({ issued_at: bad }), grant(), PINNED_NOW).refused, 'envelope', bad);
  }
});

check('R8-6: leap-day spellings on real leap years stay ACCEPTED', () => {
  // Guard: 2024 and 2000 are leap years (2000 is, 1900/2100 are not).
  for (const ok of ['2024-02-29T00:00:00+00:00', '2000-02-29T00:00:00+00:00']) {
    const v = evaluateMessage(body({ issued_at: ok }), grant(), new Date('2026-11-01T02:00:00.000Z'));
    // accepted (past-dated) -> allowed, NOT a refusal
    assert.ok(v.allowed, `${ok} must be allowed`);
  }
});

check('R8-7: fractional seconds (1-6 digits) accepted, 7 digits refused', () => {
  for (const ok of ['2026-11-01T00:00:00.5+00:00', '2026-11-01T00:00:00.123456+00:00',
    '2026-11-01T00:00:00.5Z']) {
    const v = evaluateMessage(body({ issued_at: ok }), grant(), new Date('2026-11-01T02:00:00.000Z'));
    assert.ok(v.allowed, ok);
  }
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-11-01T00:00:00.1234567+00:00' }), grant(), PINNED_NOW).refused,
    'envelope');
});

// ------------------------------------------------------ future bound + UTC --

check('R8-8: +23:59:30 future is INSIDE the 24h tolerance (accepted)', () => {
  const v = evaluateMessage(body({ issued_at: '2026-11-01T23:59:30+00:00' }), grant(), PINNED_NOW);
  assert.ok(v.allowed, '23h59m30s future must be allowed');
});

check('R8-9: +24h:00:01 future is REFUSED (boundary measured, not assumed)', () => {
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-11-02T02:00:01+00:00' }), grant(), PINNED_NOW).refused,
    'issued_at_in_future');
  // exactly at 24h: allowed (strict >)
  const v = evaluateMessage(body({ issued_at: '2026-11-02T02:00:00+00:00' }), grant(), PINNED_NOW);
  assert.ok(v.allowed, 'exactly +24h must be allowed (strict >)');
});

check('R8-10: far-future year 9999 refused via issued_at_in_future', () => {
  assert.equal(
    evaluateMessage(body({ issued_at: '9999-01-01T00:00:00+00:00' }), grant(), PINNED_NOW).refused,
    'issued_at_in_future');
});

check('R8-11: negative-offset spellings shift to UTC correctly for the bound', () => {
  // 2026-11-01T21:30:00-03:00 == 2026-11-02T00:30:00Z -> +22.5h from pinned now: inside.
  const inside = evaluateMessage(body({ issued_at: '2026-11-01T21:30:00-03:00' }), grant(), PINNED_NOW);
  assert.ok(inside.allowed, 'negative offset resolving to +22.5h must be allowed');
  // 2026-11-02T01:00:00-03:00 == 2026-11-02T04:00:00Z -> +26h: refused.
  assert.equal(
    evaluateMessage(body({ issued_at: '2026-11-02T01:00:00-03:00' }), grant(), PINNED_NOW).refused,
    'issued_at_in_future');
});

check('R8-12: extreme offsets do not overflow the Date range (no NaN escape)', () => {
  // Grammar allows ±23:59 offsets; assembling UTC parts then subtracting
  // ~24h must stay finite for the largest representable in-grammar year.
  const v = evaluateMessage(
    body({ issued_at: '9999-12-31T23:59:59.999999+23:59' }), grant(), PINNED_NOW);
  assert.equal(v.refused, 'issued_at_in_future');
});

check('R8-13: hostile now (Date subclass lying about getTime) still bounds future', () => {
  class Hostile extends Date {
    getTime() { return 0; } // claims 1970: an unconstrained check would refuse everything or none
  }
  const v = evaluateMessage(body({ issued_at: '2026-11-01T00:00:00+00:00' }), grant(), new Hostile());
  // readClock rejects the subclass -> refused('invalid_clock'), never signed on a forged clock.
  assert.equal(v.refused, 'invalid_clock');
});

// ----------------------------------------------------- false-positive guards --

check('GUARD: the exact spelling the daily runner produces is accepted', () => {
  // run.sh: --issued-at "${DAY}T21:00:00+00:00"
  const v = evaluateMessage(body({ issued_at: '2026-11-01T21:00:00+00:00' }), grant(), PINNED_NOW);
  assert.ok(v.allowed, 'daily-runner spelling must remain allowed');
});

check('GUARD: consumer default (datetime.now().isoformat(timespec="seconds")) accepted', () => {
  // receipt.py default: 2026-11-01T02:00:00+00:00 form, +/- a real day.
  const v = evaluateMessage(body({ issued_at: '2026-11-01T02:00:00+00:00' }), grant(), PINNED_NOW);
  assert.ok(v.allowed);
});

check('GUARD: Z-form accepted; note remains optional; canonical size still enforced', () => {
  assert.ok(evaluateMessage(body({ issued_at: '2026-11-01T00:00:00Z' }), grant(), PINNED_NOW).allowed);
  const withNote = body(); withNote.note = 'x'.repeat(200);
  assert.ok(evaluateMessage(withNote, grant(), PINNED_NOW).allowed);
  const tooLongNote = body(); tooLongNote.note = 'x'.repeat(257);
  assert.equal(evaluateMessage(tooLongNote, grant(), PINNED_NOW).refused, 'envelope');
});

console.log(`\nprobe-policy: ${pass} pass / ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
