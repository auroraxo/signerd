'use strict';

// THE MEASUREMENT PIN for the REVOCATION face of the grant-file lost-update
// fix (2026-11-17). tools/measure-grant-file-lock.js measured append||append
// only; the lock's own comment names remove||append as THE security face (a
// lost update that resurrects a removed grant is a silent revocation undo,
// because the loader re-reads the file on every request). The artifacts
// research/grant-file-revocation-race-{prefix,fixed}-2026-11-17.json measure
// that interleaving: 6 concurrent appends against 2 concurrent removes on a
// file that starts with {doomed1, doomed2, good}.
//
//   T1 both artifacts exist, name this tool and the pre-fix baseline
//      (commit 6e33571 - the code that shipped v0.2.34, extracted with
//      git archive, never this working tree);
//   T2 the prefix tree shows the defect (a resurrected revoked grant, a
//      lost append, or an ok-reported remove that did not happen) and the
//      fixed tree shows none - a baseline that shows nothing makes the fix
//      unmeasurable, verdicts revocation-race-lost-update vs
//      revocation-and-append-serialize;
//   T3 the fixed tree's numbers are exact: every round lands good + new1..6
//      (7 grants), both removes report ok, no lock left behind - the fix
//      must not swap a lost update for refusals;
//   T4 neither artifact carries a host path (a committed artifact that names
//      the measuring host is a snapshot, not a measurement);
//   T5 the verdicts are falsifiable: swap them in either artifact and this
//      file goes RED.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const PREFIX_ARTIFACT = path.join(ROOT, 'research', 'grant-file-revocation-race-prefix-2026-11-17.json');
const FIXED_ARTIFACT = path.join(ROOT, 'research', 'grant-file-revocation-race-fixed-2026-11-17.json');

function readArtifact(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('T1 both artifacts exist and name the tool and the pre-fix baseline', () => {
  const pre = readArtifact(PREFIX_ARTIFACT);
  const fixed = readArtifact(FIXED_ARTIFACT);
  for (const r of [pre, fixed]) {
    assert.equal(r.tool, 'tools/measure-grant-file-revocation-race.js');
    assert.equal(r.prefixSha, '6e33571',
      'the baseline must be the pre-fix commit (6e33571), extracted with git archive');
    assert.ok(r.runs.length >= 5, 'at least 5 rounds per tree');
    assert.equal(r.appendersPerRound, 6, '6 concurrent appends per round');
    assert.equal(r.removersPerRound, 2, '2 concurrent removes per round');
  }
});

test('T2 the prefix tree showed the defect; the fixed tree shows none', () => {
  const pre = readArtifact(PREFIX_ARTIFACT);
  const fixed = readArtifact(FIXED_ARTIFACT);
  const preFaces = pre.defectFaces;
  assert.ok(preFaces.R1_revoked_grant_back + preFaces.R2_added_missing_after_ok >= 1,
    'the prefix tree must show a resurrected revoked grant or a lost append, else the fix is unmeasurable');
  assert.equal(pre.verdict, 'revocation-race-lost-update');
  assert.equal(fixed.verdict, 'revocation-and-append-serialize');
  for (const [face, count] of Object.entries(fixed.defectFaces)) {
    assert.equal(count, 0, `the fixed tree must show 0 of ${face}`);
  }
});

test('T3 the fixed tree lands every write: 7 grants per round, no refusals swapped in', () => {
  const fixed = readArtifact(FIXED_ARTIFACT);
  for (const run of fixed.runs) {
    assert.deepEqual(run.names, ['good', 'new1', 'new2', 'new3', 'new4', 'new5', 'new6'],
      'every round must land good + all six appends');
    assert.equal(run.appendOk, 6, 'all six appends reported ok');
    assert.equal(run.removeOk, 2, 'both removes reported ok');
    assert.equal(run.r4_lock_left, false, 'no lock left behind');
  }
});

test('T4 neither artifact carries a host path', () => {
  for (const p of [PREFIX_ARTIFACT, FIXED_ARTIFACT]) {
    const raw = fs.readFileSync(p, 'utf8');
    assert.ok(!raw.includes('/home/'), `${path.basename(p)} must not name a home path`);
    assert.ok(!raw.includes('/tmp/signerd-'), `${path.basename(p)} must not name a sandbox path`);
  }
});

test('T5 FALSIFICATION: a swapped verdict is caught', () => {
  const pre = readArtifact(PREFIX_ARTIFACT);
  const fixed = readArtifact(FIXED_ARTIFACT);
  assert.notEqual(pre.verdict, fixed.verdict);
  assert.equal(fixed.verdict, 'revocation-and-append-serialize');
  assert.notEqual(pre.defectFaces, fixed.defectFaces);
});
