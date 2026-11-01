'use strict';
// Boundary probe: is the 24h future bound (MAX_FUTURE_SKEW_MS,
// src/policy-message.js:275) inclusive at exactly +24h, or exclusive?
//
// The daily live consumer pins issued_at to DAY T21:00Z and is allowed
// only while now + 24h >= that instant, so this edge decides the earliest
// runnable clock time for the next day's run. Reviews #7/#8 measured
// +21.4h (accepted) and +43h (refused) but never the exact edge.
//
// Expectation before running: line 275 is `issuedAtInstant > nowMs + SKEW`
// so the comparison is inclusive — a body dated EXACTLY now+24h is
// allowed, one millisecond more is refused. If the measurement disagrees,
// that is a finding.
//
// Approach: drive evaluateMessage directly with an injected clock (third
// argument `now`, same mechanism the hostile-clock test uses — readClock
// accepts Date instances), with a minimal valid grant. No daemon, no
// signature: this asks the policy question only.

const { evaluateMessage } = require('/tmp/signerd-boundary/src/policy-message.js');

const PUB = 'A'.repeat(43) + '='; // matches /^[A-Za-z0-9+/]{43}=$/
const grant = {
  kind: 'message',
  issuer: 'auroraxo',
  type: 'release',
  subject: 'auroraxo/signerd',
  pubkey: PUB,
  maxBytes: '3072',
  expiresAt: '2099-01-01T00:00:00Z',
  windowMaxMessages: '4',
  windowSeconds: '3600',
};

function body(issuedAt) {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    claims: {},
    issued_at: issuedAt,
  };
}

const results = [];
function check(label, nowMs, issuedAt) {
  const now = new Date(nowMs);
  const r = evaluateMessage(body(issuedAt), grant, now);
  results.push({ label, now: now.toISOString(), issuedAt, verdict: r.allowed ? 'ALLOWED' : r.refused });
}

// Anchor: 2026-11-01T12:00:00.000Z. Day-4 target instant: 2026-11-02T21:00:00Z.
const anchor = Date.parse('2026-11-01T12:00:00.000Z');
const target = Date.parse('2026-11-02T21:00:00.000Z');
const ahead = target - anchor; // expected 33h

// 1. The runner-relevant edge: earliest now that accepts DAY=2026-11-02T21:00Z.
check('target-33h (old runner schedule)', anchor, '2026-11-02T21:00:00Z');
check('target-24h+1s', target - 24 * 3600_000 - 1000, '2026-11-02T21:00:00Z');
check('target-24h+1ms', target - 24 * 3600_000 - 1, '2026-11-02T21:00:00Z');
check('target-24h exactly (boundary)', target - 24 * 3600_000, '2026-11-02T21:00:00Z');
check('target-24h-1ms', target - 24 * 3600_000 + 1, '2026-11-02T21:00:00Z');

// 2. Generic edges of the bound, away from the runner schedule.
const base = Date.parse('2026-06-15T00:00:00.000Z');
check('generic exactly +24h', base, '2026-06-16T00:00:00Z');
check('generic +24h+1ms', base, '2026-06-16T00:00:00.000001Z');
check('generic +23:59:59', base, '2026-06-15T23:59:59Z');
// Offset spelling denoting the same instant as the exact boundary:
check('generic +24h via +02:00 offset spelling', base, '2026-06-16T02:00:00+02:00');
// Fractional-second spellings of the boundary instant:
check('boundary with .000 fraction', base, '2026-06-16T00:00:00.000Z');

// 3. Sanity: far future still refused, past still allowed.
check('far future +30d', base, '2026-07-15T00:00:00Z');
check('past -1h', base, '2026-06-14T23:00:00Z');

let failed = 0;
for (const r of results) {
  console.log(`${r.verdict === 'ALLOWED' ? 'ok  ' : 'REFused'}  ${r.label}  (now=${r.now}, issued_at=${r.issuedAt}) -> ${r.verdict}`);
}
const b1 = results.find(r => r.label.startsWith('target-24h exactly'));
const b2 = results.find(r => r.label.startsWith('generic exactly +24h'));
const j1 = results.find(r => r.label.startsWith('target-24h-1ms'));
const j2 = results.find(r => r.label.startsWith('generic +24h+1ms'));
const off = results.find(r => r.label.includes('offset spelling'));
if (!b1 || b1.verdict !== 'ALLOWED') { console.log('UNEXPECTED: exact +24h boundary not accepted'); failed++; }
if (!b2 || b2.verdict !== 'ALLOWED') { console.log('UNEXPECTED: generic exact +24h not accepted'); failed++; }
if (!j1 || j1.verdict !== 'REFused'.replace('REFused', 'issued_at_in_future')) { /* detail below */ }
console.log(`\nboundary verdicts: exact+24h=${b1 ? b1.verdict : 'missing'}, +1ms-over=${j1 ? j1.verdict : 'missing'}, generic-exact=${b2 ? b2.verdict : 'missing'}, generic+1ms=${j2 ? j2.verdict : 'missing'}, same-instant-offset-spelling=${off ? off.verdict : 'missing'}`);
process.exit(failed ? 1 : 0);
