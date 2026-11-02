'use strict';

// Pin tools/wire-prefix.mjs and its committed report.
//
// THE CLAIM UNDER TEST: byte 0 of a transaction wire identifies version-1
// messages WITHOUT parsing them - byte 0 is 0x81 for v1, and for legacy/v0 it
// is the compact-u16 signature count, which inside the policy's 1232-byte cap
// cannot reach 0x80. src/policy.js refuses versioned wire by this rule before
// it parses anything, so if the claim were false, the classifier would refuse
// (or worse, admit) legacy transactions.
//
// What CI can do offline: re-derive the separation claim from the committed
// report, prove the signature-count bound arithmetically, and check the tool's
// NO-VERDICT exit codes against an unreachable RPC (exit 3, never a number).
// What CI must NOT do: hit mainnet. A live run is re-runnable by hand with
// `node tools/wire-prefix.mjs`.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'wire-prefix.mjs');
const REPORT = path.join(ROOT, 'research', 'first-byte-distribution-2026-11-02.json');
const POLICY_MAX_WIRE_BYTES = 1232;
const SIGNATURE_BYTES = 64;
// Conservative minimum for the message part; the bound only needs to be the
// right order of magnitude and is checked against live data in the report.
const MINIMUM_MESSAGE_BYTES = 100;

function maxSignaturesUnderCap(cap, sig = SIGNATURE_BYTES, minMsg = MINIMUM_MESSAGE_BYTES) {
  let n = 0;
  while ((n + 1) * sig + minMsg <= cap) n++;
  return n;
}

function run(args, env = {}) {
  try {
    const stdout = execFileSync(process.execPath, [TOOL, ...args], {
      cwd: ROOT, encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    });
    return { code: 0, stdout };
  } catch (err) {
    return { code: err.status ?? -1, stdout: err.stdout || '', stderr: err.stderr || '' };
  }
}

test('the committed report is a real pairing-verified sample', () => {
  const r = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(r.unpaired, 0, 'every row must be pairing-verified before it is counted');
  assert.ok(r.total > 1000, 'the sample must be large enough to matter, not a handful of rows');
  assert.ok(Array.isArray(r.slots) && r.slots.length >= 4, 'the report must name its slots');
  assert.equal(r.policyMaxWireBytes, POLICY_MAX_WIRE_BYTES,
    'the report must carry the policy cap its bound is derived from');
  for (const v of ['0', '1', 'legacy']) {
    assert.ok(r.byVersion[v] && r.byVersion[v].count > 0, `bucket ${v} must not be empty`);
  }
  assert.ok(r.limits.length >= 3, 'the report must state its own limits');
});

test('the separation claim holds: no legacy/v0 wire starts at or above 0x80', () => {
  const r = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  // Re-derive, never trust the stored boolean: every observed first byte of
  // every non-v1 bucket, and every observed first byte of the v1 bucket.
  const nonV1 = new Set();
  for (const [v, g] of Object.entries(r.byVersion)) {
    for (const fb of Object.keys(g.firstBytes)) {
      if (v === '1') assert.ok(parseInt(fb, 16) >= 0x80,
        `version 1 must start at or above 0x80, saw 0x${fb}`);
      else nonV1.add(fb);
    }
  }
  for (const fb of nonV1) {
    assert.ok(parseInt(fb, 16) < 0x80,
      `non-v1 wire starting at 0x${fb} would make byte-0 classification unsafe`);
  }
  // And the counts must actually exercise the claim.
  assert.equal(r.byVersion['1'].count >= 500, true, 'v1 sample too small to be evidence');
  assert.ok([...nonV1].length >= 3, 'the non-v1 buckets must cover several prefixes');
});

test('the signature-count bound proves 0x80 is unreachable under the cap', () => {
  const r = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  const bound = maxSignaturesUnderCap(POLICY_MAX_WIRE_BYTES);
  assert.equal(r.separation.maxSignaturesUnderCap, bound,
    'the committed bound must re-derive from the policy cap');
  // The rule: a compact-u16 signature count under the cap can never be >=
  // 0x80, because 0x80 is the continuation threshold - a count >= 0x80 means
  // >= 128 signatures, and 128 signatures alone are 8192 bytes, far over the
  // 1232-byte cap.
  assert.ok(bound < 128,
    `bound ${bound} must stay below 128 (the compact-u16 continuation threshold)`);
  assert.ok(128 * SIGNATURE_BYTES > POLICY_MAX_WIRE_BYTES,
    '128 signatures must not fit under the cap - that is the whole safety argument');
  // The bound must be tight in the sense it claims: one more signature (plus
  // the minimum message) no longer fits.
  assert.ok((bound + 1) * SIGNATURE_BYTES + MINIMUM_MESSAGE_BYTES > POLICY_MAX_WIRE_BYTES,
    'one more signature must exceed the cap - otherwise the bound is not tight');
  // The live data must agree with the arithmetic: no observed legacy/v0
  // transaction can carry more signatures than the bound allows in its length.
  for (const v of ['0', 'legacy']) {
    const g = r.byVersion[v];
    assert.ok(g.maxLen <= POLICY_MAX_WIRE_BYTES,
      `bucket ${v} observed maxLen ${g.maxLen} exceeds the cap - the rule would never see such a row`);
    assert.ok(Math.floor(g.minLen / SIGNATURE_BYTES) <= bound,
      `bucket ${v} minLen implies more signatures than the bound allows`);
  }
});

test('the report records the observed prefixes it was built from', () => {
  const r = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.deepEqual(r.separation.v1FirstBytes, ['81'], 'v1 must be observed only as 0x81');
  assert.deepEqual(r.separation.nonV1FirstBytes, [...new Set(r.separation.nonV1FirstBytes)].sort(),
    'the non-v1 prefix list must be sorted and duplicate-free');
  assert.ok(r.separation.minV1FirstByte > r.separation.maxNonV1FirstByte,
    'the stored separation must be a strict gap, not an overlap');
  assert.equal(r.separation.separated, true);
});

test('the tool refuses to report a number when the RPC is unreachable', () => {
  // Exit 3 is NO VERDICT: an instrument that cannot sample must fail loudly,
  // never publish a zero or partial number as a finding. 127.0.0.1:1 is a
  // closed port, so this stays offline and fast.
  const { code, stderr } = run([], { SOLANA_RPC: 'http://127.0.0.1:1/' });
  assert.equal(code, 3, `expected NO VERDICT exit, got ${code}; stderr: ${stderr.slice(0, 300)}`);
  assert.match(stderr, /NO VERDICT/);
});
