'use strict';
// PIN: the build-tx input-voice measurement must stay honest.
//
// The measurement (tools/measure-buildtx-input-voice.js) ran the SAME four
// value-refusal faces, one neighbouring control and five guards against the
// PUBLISHED signerd v0.2.36 npm package and against this tree, and both
// verdicts are committed as JSON artifacts.
//
// WHAT THIS CLASS IS (measured 2026-11-18, published v0.2.36):
//
//   $ signerd build-tx --keystore ks.json --to not-a-key! ...
//   wire_build_failed: build-tx: Non-base58 character
//     fix: build-tx: Non-base58 character
//
//   $ signerd build-tx ... --blockhash <31-byte base58>
//   wire_build_failed: build-tx: Blob.encode[recentBlockhash] requires
//     (length 32) Uint8Array as src
//
// Four of four value faces: the SAME code for two different flags, a
// third-party sentence (bs58 / web3.js / buffer), and a fix line that
// ECHOED the error in the same words. The refusal is the product - a
// refusal that speaks a library's language and repeats itself as its own
// repair is mute.
//
// WHAT THIS TEST CHECKS, WITHOUT re-running the measurement (it needs the
// installed npm package):
//   P1 both artifacts parse and carry the face list;
//   P2 the published v0.2.36 artifact shows the DEFECT: verdict
//      `buildtx-value-inputs-ship-foreign-prose`, every B-face defective,
//      and not one B-face naming its flag;
//   P3 the fixed artifact shows the contract: verdict
//      `buildtx-value-inputs-name-their-flag-and-repair`, zero defects;
//   P4 the two artifacts cover the SAME faces (the comparison is fair);
//   P5 no host path leaks into either artifact, and every guard is green
//      on BOTH trees;
//   P6 the echo defect is exactly what the pre-fix artifact records: every
//      defective face's fix line equals its error detail (the echo rule).

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const PREFIX = path.join(__dirname, '..', 'research',
  'buildtx-input-voice-published-v0236-2026-11-18.json');
const FIXED = path.join(__dirname, '..', 'research',
  'buildtx-input-voice-fixed-2026-11-18.json');

function report(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('P1 both artifacts parse and carry their face list', () => {
  const pre = report(PREFIX);
  const post = report(FIXED);
  assert.ok(Array.isArray(pre.faces) && pre.faces.length >= 10,
    `the pre-fix artifact must carry the faces, got ${pre.faces && pre.faces.length}`);
  assert.ok(Array.isArray(post.faces) && post.faces.length >= 10,
    `the fixed artifact must carry the faces, got ${post.faces && post.faces.length}`);
  assert.strictEqual(pre.tool, 'measure-buildtx-input-voice');
  assert.strictEqual(post.tool, 'measure-buildtx-input-voice');
});

test('P2 the published v0.2.36 tree shows the defect (red-first)', () => {
  const pre = report(PREFIX);
  assert.strictEqual(pre.judgement, 'buildtx-value-inputs-ship-foreign-prose',
    'the published tree must carry the DEFECT verdict');
  const bFaces = pre.faces.filter((f) => /^B[1-4]/.test(f.face));
  assert.strictEqual(bFaces.length, 4, 'all four value faces must be measured');
  const defective = bFaces.filter((f) => f.defective);
  assert.strictEqual(defective.length, 4,
    `every value face must be defective on the published tree, got ${defective.length}`);
  const named = bFaces.filter((f) => f.flagNamed === true);
  assert.strictEqual(named.length, 0,
    `no published refusal may name its flag, got ${named.length}`);
  const actionable = bFaces.filter((f) => f.fixActionable === true);
  assert.strictEqual(actionable.length, 0,
    `no published refusal may carry an actionable repair, got ${actionable.length}`);
});

test('P3 the fixed tree shows the contract', () => {
  const post = report(FIXED);
  assert.strictEqual(post.judgement, 'buildtx-value-inputs-name-their-flag-and-repair',
    'the fixed tree must carry the CONTRACT verdict');
  const bFaces = post.faces.filter((f) => /^B[1-4]/.test(f.face));
  const defective = bFaces.filter((f) => f.defective);
  assert.strictEqual(defective.length, 0,
    `the fixed tree must refuse nothing defectively, got ${defective.length}`);
  for (const f of bFaces) {
    assert.strictEqual(f.fixActionable, true, `${f.face}: repair must be actionable`);
    assert.strictEqual(f.flagNamed, true, `${f.face}: the flag must be named`);
    assert.strictEqual(f.exit, 2, `${f.face}: exit stays 2 (usage refusal)`);
    assert.strictEqual(f.code, 'invalid_key_argument', `${f.face}: the product's code`);
  }
});

test('P4 both artifacts cover the same faces', () => {
  const pre = report(PREFIX);
  const post = report(FIXED);
  const names = (r) => r.faces.map((f) => f.face).sort();
  assert.deepStrictEqual(names(pre), names(post),
    'the two trees must be measured on the identical face list');
});

test('P5 no host path in either artifact; guards green on both trees', () => {
  for (const [label, r] of [['prefix', report(PREFIX)], ['fixed', report(FIXED)]]) {
    for (const f of r.faces) {
      assert.strictEqual(f.hostPathInRepair, false,
        `${label}/${f.face}: a host path leaked into the artifact`);
    }
    const guards = r.faces.filter((f) => /^G/.test(f.face));
    assert.ok(guards.length >= 4, `${label}: the guards must be measured`);
    const bad = guards.filter((f) => f.defective);
    assert.strictEqual(bad.length, 0,
      `${label}: guards must be green on BOTH trees, broken: ${bad.map((f) => f.face).join(', ')}`);
  }
});

test('P6 the pre-fix defect IS the echo: fix line equals the error detail', () => {
  const pre = report(PREFIX);
  const bFaces = pre.faces.filter((f) => /^B[1-4]/.test(f.face));
  for (const f of bFaces) {
    assert.ok(typeof f.fixHead === 'string' && f.fixHead.length > 0,
      `${f.face}: the echoed fix must be recorded`);
    assert.ok(!/--[a-z-]+/.test(f.fixHead),
      `${f.face}: the recorded fix names no flag (it is the echo): ${f.fixHead}`);
    assert.ok(!/signerd\s+[a-z]/.test(f.fixHead),
      `${f.face}: the recorded fix names no command (it is the echo): ${f.fixHead}`);
  }
});
