'use strict';

// Review #9 (independent), probe file 6: canonicalization differential
// (daemon bytes vs python3 json.dumps) over MY OWN hostile value set, plus
// the measured cost of the review-7 checks.
//
// Run: node research/review9-independent/probe-canonical.js

const { spawnSync } = require('node:child_process');
const { canonicalReceiptBytes } = require('../../src/receipt-identity');
const { evaluateMessage } = require('../../src/policy-message');
const { verdict } = require('./helper');

// My hostile set — deliberately not the review-7 set: control chars, DEL,
// quotes, backslash, ASCII extremes, BMP oddities, combining marks, RTL,
// U+2028/2029, BOM, NBSP, lone surrogate escapes, astral, and the numeric
// classes (which must be unreachable through the policy).
const HOSTILE = {
  nul: '\u0000', bell: '\u0007', backspace: '\b', tab: '\t', newline: '\n',
  vertical_tab: '\v', formfeed: '\f', carriage_return: '\r', escape: '\u001b',
  del: '\u007f', quote: 'a"b', backslash: 'a\\b', slash: 'a/b',
  tilde: '~', space_edge: '  padded  ', ctrl_1f: '\u001f',
  latin1_high: '\u00e9', nbsp: '\u00a0', replacement: '\ufffd',
  u2028: '\u2028', u2029: '\u2029', bom: '\ufeff', zero_width: '\u200b',
  combining: 'éx', rtl: '\u05d0\u05d1',
  astral_emoji: '\u{1F600}', astral_high: '\u{10FFFF}',
  astral_maths: '\u{1D400}',
  surrogate_pair_escape_in_source: '\ud83d\ude00', // same as astral_emoji via escape
  lone_surrogate: '\ud800',
  mixed: 'é中\ud800~"\\\n\u007f\u2028\u{1F600}',
};

/** python3 canonical bytes of the same object. */
function pythonCanonical(obj) {
  const script = [
    'import json,sys',
    'obj=json.load(sys.stdin)',
    'sys.stdout.buffer.write(json.dumps(obj,sort_keys=True,separators=(",",":")).encode())',
  ].join('\n');
  const r = spawnSync('python3', ['-c', script], { input: JSON.stringify(obj) });
  if (r.status !== 0) throw new Error(`python failed: ${r.stderr}`);
  return r.stdout;
}

{
  let identical = 0;
  const mismatches = [];
  for (const [key, value] of Object.entries(HOSTILE)) {
    const body = { note: value, claims: { [`claim_${key}`]: value } };
    const js = canonicalReceiptBytes(body);
    const py = pythonCanonical(body);
    if (js.equals(py)) identical += 1;
    else mismatches.push(`${key}: js=${js.toString('hex').slice(0, 60)} py=${py.toString('hex').slice(0, 60)}`);
  }
  verdict(`canonical: JS vs python3 byte-identical on all ${Object.keys(HOSTILE).length} hostile values`,
    mismatches.length === 0,
    mismatches.length === 0 ? `${identical}/${Object.keys(HOSTILE).length} identical`
      : `${identical}/${Object.keys(HOSTILE).length} — MISMATCHES: ${mismatches.join(' | ')}`);
}

// Key ORDER: JS Object.keys().sort() vs Python sorted(): both UTF-16/ASCII for
// ASCII keys, but Python sorts by CODE POINT while JS sorts by UTF-16 code
// unit. A key above the BMP vs a key in U+E000..U+FFFF would differ. Claim
// keys are constrained to NAME (ASCII), so this must be UNREACHABLE through
// the policy — measured at the policy layer: a non-ASCII claim key refused.
{
  const body = {
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', issued_at: '2026-11-01T00:00:00+00:00',
    claims: { '\u{1D400}': 'v', '\uffff': 'w' },
  };
  const grant = {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: Buffer.alloc(32, 9).toString('base64'), maxBytes: '700',
    expiresAt: '2030-01-01T00:00:00.000Z', windowMaxMessages: '5', windowSeconds: '3600',
  };
  const v = evaluateMessage(body, grant);
  verdict('canonical: a non-ASCII claim key (the only sort-order divergent class) is refused at the policy',
    v.refused === 'claims', `outcome=${v.allowed ? 'ALLOW' : v.refused}`);

  // And prove the divergence would exist if the key were reachable: JS and
  // Python sort differently for astral vs U+E000+ keys.
  const divergent = { '\u{1D400}': '1', '\uffff': '2' };
  const jsOrder = Object.keys(divergent).sort();
  const pyOrder = JSON.parse(spawnSync('python3',
    ['-c', 'import json;print(json.dumps(sorted(json.loads(\'{"\\\\ud835\\\\udc00":"1","\\\\uffff":"2"}\').keys())))'],
    { encoding: 'utf8' }).stdout);
  verdict('canonical: the sort divergence EXISTS in the abstract (JS UTF-16 vs Python code point)',
    jsOrder[0] !== pyOrder[0],
    `js=[${jsOrder.map((s) => s.codePointAt(0).toString(16))}] py=[${pyOrder.map((s) => s.codePointAt(0).toString(16))}]`);
}

// Number classes: must be unreachable (all value slots are string-typed).
{
  const grant = {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: Buffer.alloc(32, 9).toString('base64'), maxBytes: '700',
    expiresAt: '2030-01-01T00:00:00.000Z', windowMaxMessages: '5', windowSeconds: '3600',
  };
  const mk = (overrides) => ({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', issued_at: '2026-11-01T00:00:00+00:00',
    claims: { version: 'v1' }, ...overrides,
  });
  const cases = [
    ['claim value 1e21', mk({ claims: { version: 1e21 } }), 'refuse:claims'],
    ['claim value -0', mk({ claims: { version: -0 } }), 'refuse:claims'],
    ['claim value 42.0', mk({ claims: { version: 42.0 } }), 'refuse:claims'],
    ['claim value bool', mk({ claims: { version: true } }), 'refuse:claims'],
    ['claim value null', mk({ claims: { version: null } }), 'refuse:claims'],
    ['claim value nested obj', mk({ claims: { version: { a: 1 } } }), 'refuse:claims'],
    ['claim value array', mk({ claims: { version: [1] } }), 'refuse:claims'],
    ['note number', mk({ note: 42 }), 'refuse:envelope'],
    ['issued_at number', mk({ issued_at: 1760000000 }), 'refuse:envelope'],
    ['negative-number claim key', mk({ claims: { '-0': 'v' } }), 'refuse:claims'],
    // NOTE (probe bug, found and fixed): the expected strings were written
    // without the 'refuse:' prefix, so every correct refusal looked like a
    // VIOLATION. The expectations now carry the same format the outcome uses.
    ['exponent claim key', mk({ claims: { '1e21': 'v' } }), 'ALLOW'], // ASCII key matches NAME by design
  ];
  const rows = [];
  let ok = true;
  for (const [label, b, expected] of cases) {
    const v = evaluateMessage(b, grant);
    const got = v.allowed ? 'ALLOW' : `refuse:${v.refused}`;
    // '1e21' as a KEY matches NAME (digits start) — so it is ALLOWED by the
    // policy and lands in the canonical bytes as a STRING key. That is the
    // honest expectation; only VALUES are pinned to strings.
    const expect = label.startsWith('exponent claim key') ? 'ALLOW' : expected;
    if (got !== expect) ok = false;
    rows.push(`${label}=${got}`);
  }
  verdict('canonical: number-typed values are unreachable (all value slots string-pinned)',
    ok, rows.join(' | '));
}

// Cost: evaluateMessage happy path, 20k iterations (same order as the
// author's number so the two are comparable).
{
  const grant = {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: Buffer.alloc(32, 9).toString('base64'), maxBytes: '700',
    expiresAt: '2030-01-01T00:00:00.000Z', windowMaxMessages: '5', windowSeconds: '3600',
  };
  const b = {
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', issued_at: '2026-11-01T00:00:00+00:00',
    claims: { version: 'v0.1.0', channel: 'dev' },
  };
  const N = 20000;
  // warmup
  for (let i = 0; i < 2000; i += 1) evaluateMessage(b, grant);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < N; i += 1) evaluateMessage(b, grant);
  const t1 = process.hrtime.bigint();
  const usPerOp = Number(t1 - t0) / N / 1000;
  console.log(`COST  evaluateMessage happy path: ${usPerOp.toFixed(2)} us/op (n=${N})`);
}

console.log('probe-canonical done.');
