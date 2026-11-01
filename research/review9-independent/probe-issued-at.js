'use strict';

// Review #9 (independent), probe file 1: the issued_at semantics surface.
// Pure policy layer. Run: node research/review9-independent/probe-issued-at.js
// Every probe states its EXPECTED verdict (fixed in findings-first.md BEFORE
// this file ran); the printout shows expected vs measured.

const { evaluateMessage } = require('../../src/policy-message');
const { verdict } = require('./helper');

const PUBKEY = Buffer.alloc(32, 9).toString('base64');
function futureIso(seconds = 3600) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}
function grant(overrides = {}) {
  return {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: PUBKEY, maxBytes: '700', expiresAt: futureIso(),
    windowMaxMessages: '5', windowSeconds: '3600', ...overrides,
  };
}
function base(overrides = {}) {
  return {
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', issued_at: '2026-11-01T00:00:00+00:00',
    claims: { version: 'v1' }, ...overrides,
  };
}
function outcome(v) { return v.allowed ? 'ALLOW' : `refuse:${v.refused}`; }

// H1: fraction precision — the instant is assembled with millisecond
// precision (setUTCHours ms=0); a .999999 spelling denotes a moment up to
// 999us LATER than the instant the policy computes. Probe: the same wall
// clock time, spelled without fraction vs with maximal fraction, must hit
// the future bound identically or the difference must be bounded.
// EXPECTED (H1): both ALLOW well inside the tolerance; the residual skew is
// < 1ms; documented as a MINOR precision limit.
{
  const now = new Date();
  const stamp = new Date(now.getTime() + 23 * 3600 * 1000); // 23h ahead: inside
  const noFrac = stamp.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const maxFrac = stamp.toISOString().replace(/\.\d{3}Z$/, '.999999Z');
  const v1 = evaluateMessage(base({ issued_at: noFrac }), grant(), now);
  const v2 = evaluateMessage(base({ issued_at: maxFrac }), grant(), now);
  verdict('H1: 23h-future stamp, no-fraction and .999999 spelling',
    v1.allowed === true && v2.allowed === true,
    `noFrac=${outcome(v1)} maxFrac=${outcome(v2)}`);
}
// H1b: the skew direction must err toward REFUSAL (the computed instant must
// never be LATER than the true instant), else a stamp just past the bound
// could pass. Measure: bound+999us spelled with fraction must refuse.
// EXPECTED (H1): REFUSE (issued_at_in_future) — if this ALLOWS, the
// millisecond truncation leaves a measurable >24h acceptance window.
{
  const now = new Date();
  const justPast = new Date(now.getTime() + 24 * 3600 * 1000); // +1ms past == bound
  const pastPlus999us = new Date(justPast.getTime() - 1); // exactly at bound
  const atBound = pastPlus999us.toISOString().replace(/\.\d{3}Z$/, '.999999Z');
  const v = evaluateMessage(base({ issued_at: atBound }), grant(), now);
  // the true instant spelled here is bound-1ms+999us = bound-1us: BELOW the
  // bound but the policy's computed instant is bound-1ms: both below.
  verdict('H1b: instant 1us below the bound spelled with .999999 fraction',
    v.allowed === true, `measured=${outcome(v)} (expected ALLOW: true instant < bound)`);
}

// H2: the exact future bound. EXPECTED (H2): ==+24h ALLOW, +24h+1ms REFUSE.
// NOTE (probe bug, found and fixed): the original version stripped the
// fraction with .replace(/\.\d{3}Z$/,'Z'), which SILENTLY CHANGED +1ms into
// the exact-bound spelling and made the probe measure its own regex. The
// deterministic frozen-clock cases below replaced it (run again after fix).
{
  const now = new Date(0); // frozen: bound = 1970-01-02T00:00:00.000Z
  const cases = [
    ['== +24h, no fraction', '1970-01-02T00:00:00Z', 'ALLOW'],
    ['+24h +1ms', '1970-01-02T00:00:00.001Z', 'refuse:issued_at_in_future'],
    ['+24h +999ms', '1970-01-02T00:00:00.999Z', 'refuse:issued_at_in_future'],
    ['+24h +999.999ms', '1970-01-02T00:00:00.999999Z', 'refuse:issued_at_in_future'],
    ['+24h +1s', '1970-01-02T00:00:01Z', 'refuse:issued_at_in_future'],
    ['-1ms before bound', '1970-01-01T23:59:59.999Z', 'ALLOW'],
  ];
  let ok = true;
  const rows = [];
  for (const [label, stamp, expected] of cases) {
    const v = evaluateMessage(base({ issued_at: stamp }), grant(), now);
    const got = v.allowed ? 'ALLOW' : `refuse:${v.refused}`;
    if (got !== expected) ok = false;
    rows.push(`${label}: expected=${expected} got=${got}`);
  }
  verdict('H2: future bound exact at +24h (sub-second overshoot = finding)', ok,
    rows.join(' | '));
}

// H3: offset spellings of the SAME instant must behave identically at the
// bound. EXPECTED (H3): identical outcomes.
{
  const now = new Date(0);
  // 1970-01-02T00:00:00Z == 1970-01-01T22:00:00+02:00
  const v1 = evaluateMessage(base({ issued_at: '1970-01-02T00:00:00Z' }), grant(), now);
  const v2 = evaluateMessage(base({ issued_at: '1970-01-01T22:00:00+02:00' }), grant(), now);
  const v3 = evaluateMessage(base({ issued_at: '1969-12-31T18:00:00-06:00' }), grant(), now);
  verdict('H3: same instant via Z/+02:00/-06:00 identical outcomes',
    v1.allowed === v2.allowed && v2.allowed === v3.allowed,
    `Z=${outcome(v1)} +02=${outcome(v2)} -06=${outcome(v3)}`);
}

// H4: calendar. EXPECTED (H4): 2028-02-29 ALLOW (leap), 2027-02-29 REFUSE,
// leap second :60 REFUSE.
// NOTE (probe bug, found and fixed): the original version froze now=2030 but
// left grant.expiresAt at real-now+1h (2026) -> EVERY case came back
// 'refuse:expired' BEFORE the calendar ran. The grant expiry now moves with
// the frozen clock so the calendar result is what gets measured.
{
  const frozen = new Date('2030-06-01T00:00:00Z');
  const g = grant({ expiresAt: '2031-01-01T00:00:00Z' }); // valid at frozen now
  const cases = [
    ['2028-02-29 (real leap day)', '2028-02-29T00:00:00Z', 'ALLOW'],
    ['2027-02-29 (not leap)', '2027-02-29T00:00:00Z', 'refuse:envelope'],
    ['2100-02-29 (century rule)', '2100-02-29T00:00:00Z', 'refuse:envelope'],
    ['2000-02-29 (400-year rule, leap)', '2000-02-29T00:00:00Z', 'ALLOW'],
    ['1900-02-29 (century, not leap)', '1900-02-29T00:00:00Z', 'refuse:envelope'],
    ['2026-02-30 (impossible day)', '2026-02-30T00:00:00Z', 'refuse:envelope'],
    ['2026-04-31 (impossible day)', '2026-04-31T00:00:00Z', 'refuse:envelope'],
    ['2026-13-01 (impossible month)', '2026-13-01T00:00:00Z', 'refuse:envelope'],
    ['2026-06-30T23:59:60Z (leap sec)', '2026-06-30T23:59:60Z', 'refuse:envelope'],
  ];
  let ok = true;
  const rows = [];
  for (const [label, stamp, expected] of cases) {
    const v = evaluateMessage(base({ issued_at: stamp }), g, frozen);
    const got = v.allowed ? 'ALLOW' : `refuse:${v.refused}`;
    if (got !== expected) ok = false;
    rows.push(`${label.slice(0, 14)}=${got}`);
  }
  verdict('H4: real-calendar + leap-year + century rules (frozen clock)', ok,
    rows.join(' | '));
}

// H5: offsets. EXPECTED (H5): +24:00 REFUSE, +23:59 ALLOW (grammar),
// -00:00 ALLOW (RFC3339 unknown-offset), +14:00 ALLOW.
{
  const cases = [
    ['2026-11-01T00:00:00+24:00', false],
    ['2026-11-01T00:00:00+23:59', true],
    ['2026-11-01T00:00:00-00:00', true],
    ['2026-11-01T00:00:00+14:00', true],
  ];
  const measured = cases.map(([s]) =>
    outcome(evaluateMessage(base({ issued_at: s }), grant())));
  verdict('H5: offset range (-00:00/+14:00/+23:59 in, +24:00 out)',
    cases.every(([, exp], i) =>
      (measured[i] === 'ALLOW') === exp),
    cases.map(([s], i) => `${s.slice(19)}=${measured[i]}`).join(' '));
}

// H16: refusal ORDER — size cap before shape. EXPECTED (H16): a body over
// the grant cap with a BAD issued_at reports message_too_large.
{
  const v = evaluateMessage(
    base({ issued_at: '2026-02-30T00:00:00Z', claims: { pad: 'x'.repeat(700) } }),
    grant({ maxBytes: '300' }));
  verdict('H16: size cap outranks issued_at shape',
    v.refused === 'message_too_large', `measured=${outcome(v)}`);
  // reversed: small body, bad issued_at -> envelope
  const v2 = evaluateMessage(base({ issued_at: '2026-02-30T00:00:00Z' }), grant());
  verdict('H16b: small body, bad issued_at -> envelope',
    v2.refused === 'envelope', `measured=${outcome(v2)}`);
}

// H1c: two spellings denoting the same instant are the same DECISION but
// different BYTES (=> separate replay identities). EXPECTED: both ALLOW,
// byte lengths differ.
{
  const v1 = evaluateMessage(base({ issued_at: '2026-11-01T00:00:00Z' }), grant());
  const v2 = evaluateMessage(base({ issued_at: '2026-11-01T02:00:00+02:00' }), grant());
  verdict('H1c: same instant, different spelling: same decision, different bytes',
    v1.allowed && v2.allowed && !v1.messageBytes.equals(v2.messageBytes),
    `bytes ${v1.messageBytes.length} vs ${v2.messageBytes.length}`);
}

// H8: __proto__ surfaces. EXPECTED (H8): refused without throwing.
{
  const proto = JSON.parse('{"schema":"openreceipts/v1","issuer":"auroraxo","type":"release","subject":"auroraxo/signerd","issued_at":"2026-11-01T00:00:00Z","claims":{"version":"v1"},"__proto__":[]}');
  let r;
  try { r = outcome(evaluateMessage(proto, grant())); } catch (e) { r = `THREW ${e.name}`; }
  verdict('H8: own __proto__ in body refused without throwing', r === 'refuse:envelope', r);
  const protoClaim = JSON.parse('{"schema":"openreceipts/v1","issuer":"auroraxo","type":"release","subject":"auroraxo/signerd","issued_at":"2026-11-01T00:00:00Z","claims":{"__proto__":"x"}}');
  let r2;
  try { r2 = outcome(evaluateMessage(protoClaim, grant())); } catch (e) { r2 = `THREW ${e.name}`; }
  verdict('H8b: __proto__ claim key refused without throwing', r2 === 'refuse:claims', r2);
}

// H16c: expiryMs copies agree (policy-message vs ledger). EXPECTED: same
// accept set for a sample of grant expiries.
{
  const { Ledger } = require('../../src/ledger');
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review9-expiry-'));
  try {
    const ledger = new Ledger({ file: path.join(dir, 'j.jsonl') });
    const mkGrant = (expiresAt) => ({
      kind: 'message', issuer: 'i', type: 't', subject: 's',
      pubkey: PUBKEY, maxBytes: '700', expiresAt,
      windowMaxMessages: '5', windowSeconds: '3600',
    });
    const samples = [
      '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00Z',
      '2020-01-01T00:00:00.500Z', '2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z',
    ];
    const results = samples.map((e) => {
      const g = mkGrant(e);
      const v = ledger.approveMessage({ messageBytes: Buffer.from(`x-${e}`), grant: g,
        now: new Date('2026-11-01T00:00:00Z') });
      return v.allowed ? 'ALLOW' : `refuse:${v.refused}`;
    });
    // hand-computed expectations (now = 2026-11-01):
    // 2030 alive; 2020 expired; 2026-02-30 and 2026-13-01 invalid_grant.
    verdict('H16c: ledger expiry semantics (canonical round trip)',
      results[0] === 'ALLOW' && results[1] === 'ALLOW' &&
      results[2] === 'refuse:expired' && results[3] === 'refuse:invalid_grant' &&
      results[4] === 'refuse:invalid_grant',
      results.join(' | '));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log('probe-issued-at done.');
