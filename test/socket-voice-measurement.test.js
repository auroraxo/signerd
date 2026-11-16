'use strict';
// PIN: the two-tree socket-voice measurement artifacts must be honest.
//
// The measurement (tools/measure-socket-voice.js) ran the same six faces
// over the PUBLISHED pre-fix tree (v0.2.30, e29634a - what npm serves) and
// this tree, and committed both verdicts as JSON artifacts.
//
// What this test checks, WITHOUT re-running the measurement (which starts a
// daemon and builds a stale-socket fixture per face):
//   P1 both artifacts parse and name the tool;
//   P2 the PUBLISHED artifact shows the defect on all six faces - the
//      unrunnable repair (`unknown_flag: --socket`, exit 2), the raw errno
//      as the answer (ENOENT / ECONNREFUSED), and the missing diagnostic;
//   P3 the FIXED artifact is clean on the same six faces and still carries
//      the two controls;
//   P4 the NUMBERS moved the way the fix claims: 6 defective -> 0, and the
//      repair the refusal names went from unrunnable (exit 2) to runnable
//      (a state answer, exit 1) - a verdict that changed while the
//      measurements did not would be a verdict about the label;
//   P5 the controls hold on BOTH trees (the happy path signs, the file
//      status answers) - a socket voice that refuses everything is not a
//      voice;
//   P6 no host path leaks into either artifact.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const FACES = [
  'S1-status-repair-runnable',
  'S2-sign-absent-socket',
  'S3-sign-stale-socket',
  'S4-status-stale-socket',
  'S5-sign-refusal-repair-runs',
  'S6-status-live-socket',
];

function read(name) {
  return JSON.parse(fs.readFileSync(path.join(REPO, 'research', name), 'utf8'));
}
const pre = () => read('socket-voice-v0.2.30-2026-11-16.json');
const post = () => read('socket-voice-fixed-2026-11-16.json');

test('P1 both artifacts parse and name the tool', () => {
  for (const r of [pre(), post()]) {
    assert.strictEqual(r.tool, 'measure-socket-voice');
    assert.strictEqual(r.date, '2026-11-16');
    assert.strictEqual(r.totalFaces, 6, 'the six defect faces must be present');
  }
  assert.strictEqual(pre().tree, 'published', 'the pre-fix measurement must pin the published tree');
  assert.strictEqual(pre().head, 'e29634a', 'the pre-fix measurement must pin the released commit');
  assert.strictEqual(post().tree, 'worktree');
});

test('P2 the published tree is defective on all six faces', () => {
  const r = pre();
  assert.strictEqual(r.verdict, 'operator-hears-raw-errno-and-unrunnable-repair');
  assert.strictEqual(r.defectiveFaces, 6);
  for (const name of FACES) {
    assert.strictEqual(r.cases[name].defect, true, `${name} must be defective pre-fix`);
  }
  // The measured defect itself: the named repair cannot be run.
  assert.strictEqual(r.cases['S1-status-repair-runnable'].code, 'unknown_flag');
  assert.strictEqual(r.cases['S1-status-repair-runnable'].exit, 2,
    'the named repair command was a usage refusal');
  // ... and the raw errno was the answer, in place of a state.
  assert.strictEqual(r.cases['S2-sign-absent-socket'].code, 'ENOENT');
  assert.strictEqual(r.cases['S3-sign-stale-socket'].code, 'ECONNREFUSED');
  // The repair S2 named, run as written, hit the same wall.
  assert.strictEqual(r.cases['S5-sign-refusal-repair-runs'].code, 'unknown_flag');
});

test('P3 the fixed tree answers every one of the same six faces with a state', () => {
  const r = post();
  assert.strictEqual(r.verdict, 'operator-hears-a-socket-state-not-an-errno');
  assert.strictEqual(r.defectiveFaces, 0);
  for (const name of FACES) {
    const c = r.cases[name];
    assert.strictEqual(c.defect, false, `${name} must be clean post-fix`);
    assert.ok(!c.skip, `${name} must have been measured, not skipped: ${c.skip || ''}`);
  }
  assert.strictEqual(r.cases['S1-status-repair-runnable'].code, 'socket_missing');
  assert.strictEqual(r.cases['S2-sign-absent-socket'].code, 'socket_missing');
  assert.strictEqual(r.cases['S3-sign-stale-socket'].code, 'socket_stale');
  assert.strictEqual(r.cases['S4-status-stale-socket'].code, 'socket_stale');
  assert.strictEqual(r.cases['S5-sign-refusal-repair-runs'].code, 'socket_missing');
  assert.strictEqual(r.cases['S6-status-live-socket'].exit, 0,
    'the live daemon is reported, not refused');
  for (const name of FACES) {
    const c = r.cases[name];
    if (c.exit !== 0) {
      assert.strictEqual(c.hasFix, true, `${name} must reach the operator WITH a repair`);
    }
  }
});

test('P4 the numbers moved, not only the labels', () => {
  const a = pre();
  const b = post();
  assert.ok(b.defectiveFaces < a.defectiveFaces,
    'the fix must reduce the measured defects');
  assert.strictEqual(b.defectiveFaces, 0, 'every measured face must be clean');
  // The repair went from exit 2 / unknown_flag to a real state answer: the
  // operator's command changed meaning, not only the wording around it.
  assert.strictEqual(a.cases['S5-sign-refusal-repair-runs'].exit, 2);
  assert.strictEqual(b.cases['S5-sign-refusal-repair-runs'].exit, 1);
  assert.strictEqual(b.cases['S5-sign-refusal-repair-runs'].repairRan, true,
    'the fixed artifact must record that the repair was RUN');
  // The raw errnos are gone as answers.
  for (const name of ['S2-sign-absent-socket', 'S3-sign-stale-socket']) {
    assert.ok(/^(ENOENT|ECONNREFUSED)$/.test(a.cases[name].code),
      `${name} must show the raw errno it used to answer`);
    assert.ok(/^socket_/.test(b.cases[name].code),
      `${name} must answer with a state`);
  }
});

test('P5 the controls hold on BOTH trees', () => {
  for (const r of [pre(), post()]) {
    const sign = r.cases['G1-control-sign-still-signs'];
    assert.strictEqual(sign.exit, 0,
      `${r.tree}: the real daemon must still sign: ${sign.stdoutHead}`);
    assert.strictEqual(sign.artifactWritten, true,
      `${r.tree}: the signature must be delivered`);
    const files = r.cases['G2-control-status-files'];
    assert.strictEqual(files.exit, 0,
      `${r.tree}: status --grants --ledger must still answer`);
  }
});

test('P6 no host path leaks into either artifact', () => {
  for (const r of [pre(), post()]) {
    const text = JSON.stringify(r);
    assert.ok(!text.includes('/home/'), 'no home path in the artifact');
    assert.ok(!text.includes('/tmp/'), 'no tmp path in the artifact');
  }
});
