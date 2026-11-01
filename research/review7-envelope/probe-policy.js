'use strict';

// Review #7 (message-grant envelope), probe file 1: the POLICY layer.
// Run directly: node research/review7-envelope/probe-policy.js
// Every probe prints PASS (the claimed guarantee holds) or VIOLATION (it
// does not, on THIS tree). Run against both trees for the ladder.
// Findings measured against pre-fix tree 20140e9: see report.md.

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
function outcome(v) { return v.allowed ? 'ALLOWED' : `refused=${v.refused}`; }

// p1 (R7-1): a body WITHOUT issued_at. The claim under test: the daemon
// refuses (the openreceipts Python verifier CRASHES on such an artifact).
{
  const b = base(); delete b.issued_at;
  const v = evaluateMessage(b, grant());
  verdict('R7-1 policy: body without issued_at refused (consumer crashes on it)',
    v.refused === 'envelope', outcome(v));
}

// p2 (R7-2a): impossible calendar dates must not normalize into real ones.
// Date.parse maps Feb 30 -> Mar 2; policy.js already refuses this class for
// the GRANT expiry, the body field must agree.
{
  const v1 = evaluateMessage(base({ issued_at: '2026-02-30T00:00:00+00:00' }), grant());
  const v2 = evaluateMessage(base({ issued_at: '2026-02-30T00:00:00Z' }), grant());
  verdict('R7-2a policy: Feb 30 refused, not normalized to Mar 2',
    v1.refused === 'envelope' && v2.refused === 'envelope', `${outcome(v1)} / ${outcome(v2)}`);
}

// p3 (R7-2b): RFC3339 grammar on the offset and the seconds field.
{
  const bad = ['+99:99', '+24:00', '13:00' /* no, covered by shape */, 'T25:00:00Z'];
  const offsets = ['+99:99', '+24:00', '2026-11-01T25:00:00Z'];
  const outcomes = offsets.map((s) =>
    outcome(evaluateMessage(base({ issued_at: s.startsWith('+') ? `2026-11-01T00:00:00${s}` : s }), grant())));
  // grammar-valid but outside real-world tz range stays ALLOWED (RFC3339
  // only requires 00-23 hours) - pinned as a limit, not a defect.
  const grammar = outcome(evaluateMessage(base({ issued_at: '2026-11-01T00:00:00+15:00' }), grant()));
  const leap = outcome(evaluateMessage(base({ issued_at: '2026-06-30T23:59:60Z' }), grant()));
  verdict('R7-2b policy: offsets/clock outside RFC3339 grammar refused (+15:00 grammar-legal, leap second refused)',
    outcomes.every((o) => o === 'refused=envelope') && grammar === 'ALLOWED' && leap === 'refused=envelope',
    `+99:99 ${outcomes[0]}, +24:00 ${outcomes[1]}, hour25 ${outcomes[2]}, +15:00 ${grammar}, leap ${leap}`);
}

// p4 (R7-3): issued_at must not be signed far into the future. 24h tolerance
// is MEASURED against the consumer: research/consumer-live-2026-11-01 was
// signed at 23:40 UTC Oct 31 with issued_at 2026-11-01T21:00 (+21.4h) and
// must keep verifying.
{
  const future2030 = evaluateMessage(base({ issued_at: '2030-01-01T00:00:00+00:00' }), grant());
  const withinTolerance = evaluateMessage(
    base({ issued_at: new Date(Date.now() + 21.5 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, '+00:00').replace('Z', '+00:00') }),
    grant());
  const past = evaluateMessage(base({ issued_at: '2020-01-01T00:00:00+00:00' }), grant());
  verdict('R7-3 policy: 2030 refused, 21.5h (consumer stamp) allowed, past allowed (backdating)',
    future2030.refused === 'issued_at_in_future' && withinTolerance.allowed === true && past.allowed === true,
    `2030 ${outcome(future2030)}, 21.5h ${outcome(withinTolerance)}, 2020 ${outcome(past)}`);
}

// Guards below must hold on BOTH trees (false-positive guards).

{
  const ok = evaluateMessage(base(), grant());
  const bad = evaluateMessage(JSON.parse('{"schema":"openreceipts/v1","extra":1}'), grant());
  const noSubject = evaluateMessage((() => { const b = base(); delete b.subject; return b; })(), grant());
  verdict('guard: native spelling allowed; unknown key and missing subject refused',
    ok.allowed === true && bad.refused === 'envelope' && noSubject.refused === 'envelope');
}

{
  const big = evaluateMessage(base({ claims: { pad: 'x'.repeat(800) } }), grant({ maxBytes: '300' }));
  const expired = evaluateMessage(base(), grant({ expiresAt: futureIso(-3600) }));
  verdict('guard: size cap before shape; expired grant refused',
    big.refused === 'message_too_large' && expired.refused === 'expired');
}

{
  const pinned = grant({ claimKeys: 'version' });
  const allowed = evaluateMessage(base({ claims: { version: 'v1' } }), pinned);
  const widened = evaluateMessage(base({ claims: { version: 'v1', channel: 'dev' } }), pinned);
  const broken = grant({ claimKeys: 'version,x y' });
  const brokenVerdict = evaluateMessage(base({ claims: { version: 'v1' } }), broken);
  verdict('guard: claimKeys allowlist enforced; broken allowlist = empty (refuse all)',
    allowed.allowed === true && widened.refused === 'claims' && brokenVerdict.refused === 'claims');
}

{
  const proto = JSON.parse('{"schema":"openreceipts/v1","issuer":"auroraxo","type":"release","subject":"auroraxo/signerd","claims":{"version":"v1"},"__proto__":[]}');
  let r;
  try { r = evaluateMessage(proto, grant()).refused; } catch (e) { r = `THREW ${e.name}`; }
  verdict('guard: own __proto__ property refused without throwing', r === 'envelope', r);
}
