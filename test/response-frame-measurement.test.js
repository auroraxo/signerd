'use strict';
// PIN: the two-tree response-frame measurement artifacts must be honest.
//
// The measurement (tools/measure-response-frame.js) ran the same four faces
// over the published pre-fix tree (v0.2.29, d45cc9a) and this tree, and
// committed both verdicts as JSON artifacts.
//
// What this test checks, WITHOUT re-running the measurement (which spawns a
// CLI and a streaming server per face):
//   P1 both artifacts parse and name the tool;
//   P2 the PRE-FIX artifact shows the defect on all four faces - the clock
//      blame (request_timeout after 11 s with 125 MB buffered), the bare
//      `error:` code, the missing repair, and the relayed non-verdict;
//   P3 the FIXED artifact shows NO defect and the same four faces;
//   P4 the memory-and-clock numbers moved the way the fix claims (125 MB ->
//      0 MB, 11105 ms -> under 500 ms) - a verdict that changed while the
//      measurements did not would be a verdict about the label, not the code;
//   P5 the cap in the artifact matches the source, and it sits ABOVE the
//      derived worst case of the response contract (a cap below the contract
//      would be the request side's own 2026-11-11 defect, which destroyed
//      legal frames);
//   P6 no host path leaks into either artifact.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const FACES = ['R1-oversized-frame', 'R2-non-json-frame', 'R3-verdict-less-close', 'R4-no-verdict-field'];

function read(name) {
  return JSON.parse(fs.readFileSync(path.join(REPO, 'research', name), 'utf8'));
}
const pre = () => read('response-frame-v0.2.29-2026-11-16.json');
const post = () => read('response-frame-fixed-2026-11-16.json');

test('P1 both artifacts parse and name the tool', () => {
  for (const r of [pre(), post()]) {
    assert.strictEqual(r.tool, 'measure-response-frame');
    assert.strictEqual(r.date, '2026-11-16');
    assert.strictEqual(r.totalFaces, 4);
  }
  assert.strictEqual(pre().tree, 'worktree');
  assert.strictEqual(pre().head, 'd45cc9a', 'the pre-fix measurement must pin the published tree');
});

test('P2 the pre-fix tree is defective on all four faces', () => {
  const r = pre();
  assert.strictEqual(r.verdict, 'client-swallows-response-failures');
  assert.strictEqual(r.defectiveFaces, 4);
  for (const name of FACES) {
    assert.strictEqual(r.cases[name].defect, true, `${name} must be defective pre-fix`);
    assert.strictEqual(r.cases[name].artifactWritten, false,
      `${name}: the pre-fix client must at least not write an artifact`);
  }
  // The measured defect itself: the clock blamed for an unfinished frame.
  assert.strictEqual(r.cases['R1-oversized-frame'].code, 'request_timeout');
  assert.strictEqual(r.cases['R1-oversized-frame'].hasFix, false);
  assert.ok(r.cases['R1-oversized-frame'].library.rssGrowthMB >= 64,
    'the unbounded buffer must be measured, not asserted');
  assert.ok(r.cases['R1-oversized-frame'].elapsedMs > 4000,
    'the pre-fix verdict must come from the timeout, i.e. late');
  // The other three faces: no repair reached the operator.
  assert.strictEqual(r.cases['R2-non-json-frame'].code, 'error', 'a bare Error prints as "error:"');
  assert.strictEqual(r.cases['R3-verdict-less-close'].hasFix, false);
  assert.strictEqual(r.cases['R4-no-verdict-field'].code, '');
  assert.strictEqual(r.cases['R4-no-verdict-field'].stdoutHead, '{"error":"boom"}',
    'nobody\'s answer was relayed to stdout');
});

test('P3 the fixed tree names every failure of the same four faces', () => {
  const r = post();
  assert.strictEqual(r.verdict, 'client-names-every-response-failure');
  assert.strictEqual(r.defectiveFaces, 0);
  for (const name of FACES) {
    const c = r.cases[name];
    assert.strictEqual(c.defect, false, `${name} must be clean post-fix`);
    assert.ok(c.code && c.code !== 'error', `${name} must carry a named code: ${c.code}`);
    assert.strictEqual(c.hasFix, true, `${name} must reach the operator WITH a repair`);
    assert.strictEqual(c.artifactWritten, false, `${name} must write nothing`);
    assert.ok(!c.stdoutHead || c.stdoutHead === '', `${name} must relay nothing: ${c.stdoutHead}`);
  }
  assert.strictEqual(r.cases['R1-oversized-frame'].code, 'response_too_large');
  assert.strictEqual(r.cases['R2-non-json-frame'].code, 'response_invalid');
  assert.strictEqual(r.cases['R3-verdict-less-close'].code, 'connection_closed');
  assert.strictEqual(r.cases['R4-no-verdict-field'].code, 'response_invalid');
});

test('P4 the numbers moved, not only the labels', () => {
  const a = pre().cases['R1-oversized-frame'];
  const b = post().cases['R1-oversized-frame'];
  assert.ok(b.library.rssGrowthMB <= 4,
    `the buffer must stop growing at the cap (was ${a.library.rssGrowthMB} MB, now ${b.library.rssGrowthMB} MB)`);
  assert.strictEqual(b.library.outcome.code, 'response_too_large');
  assert.ok(b.elapsedMs < 500,
    `the refusal must come from the cap, not the clock (was ${a.elapsedMs} ms, now ${b.elapsedMs} ms)`);
  assert.ok(b.elapsedMs * 4 < a.elapsedMs,
    'the fix must change the measurement, not the prose');
});

test('P5 the cap matches the source and sits above the response contract', () => {
  const r = post();
  assert.strictEqual(r.maxResponseBytes, 8192);
  const source = fs.readFileSync(path.join(REPO, 'src', 'daemon.js'), 'utf8');
  const m = source.match(/MAX_RESPONSE_BYTES = ([\d_]+);/);
  assert.ok(m, 'src/daemon.js must declare MAX_RESPONSE_BYTES');
  assert.strictEqual(Number(m[1].replace(/_/g, '')), r.maxResponseBytes,
    'the artifact and the source must carry the same cap');
  // The derived worst case of the response contract: base64 of a signed
  // wire at the policy ceiling (1232 + 65 = 1297 bytes -> 1732 chars),
  // signature (88), two sha256 hex (128), counters and envelope.
  const derivedWorstCase = Math.ceil((1232 + 65) / 3) * 4 + 88 + 128 + 400;
  assert.ok(r.maxResponseBytes > derivedWorstCase,
    `the cap must admit every honest answer (${derivedWorstCase} < ${r.maxResponseBytes})`);
  const wireCap = source.match(/MAX_WIRE_BYTES = (\d+)/)
    || fs.readFileSync(path.join(REPO, 'src', 'policy.js'), 'utf8').match(/MAX_WIRE_BYTES = (\d+)/);
  assert.ok(wireCap, 'the wire ceiling the cap derives from must still exist');
  assert.strictEqual(Number(wireCap[1]), 1232, 'the derivation is pinned to the measured ceiling');
});

test('P6 no host path leaks into either artifact', () => {
  for (const r of [pre(), post()]) {
    const text = JSON.stringify(r);
    assert.ok(!text.includes('/home/'), 'no home path in the artifact');
    assert.ok(!text.includes('/tmp/'), 'no tmp path in the artifact');
  }
});
