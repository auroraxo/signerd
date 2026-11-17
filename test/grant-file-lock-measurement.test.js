'use strict';

// THE MEASUREMENT PIN for the grant-file lost-update fix (2026-11-17).
//
// The artifacts research/grant-file-lock-{prefix,fixed}-2026-11-17.json are
// what the card and the PR cite, so they must be measurements and not
// stories:
//
//   T1 both artifacts exist, name the tool and the pre-fix baseline they
//      measured (commit 6e33571 - the code that shipped v0.2.34, extracted
//      with git archive, never this working tree);
//   T2 the prefix tree shows the defect on the measured rounds (A1/A2) -
//      a baseline that shows nothing makes the fix unmeasurable - and the
//      fixed tree shows none, verdict grant-file-writes-serialize;
//   T3 the fixed tree's numbers are exact: every round reports all 9
//      grants on disk (create + 8 appends), zero refused writers, no lock
//      left behind - the fix must not swap a lost update for refusals;
//   T4 neither artifact carries a host path (a committed artifact that
//      names the measuring host is a snapshot, not a measurement);
//   T5 the verdicts are falsifiable: rewrite the prefix verdict to
//      "serialize" and this file goes RED.
//
// T4 and T5 are falsifiable on purpose; the tool re-derives nothing here -
// the ladder in test/grant-file-lock.test.js re-derives the BEHAVIOUR live.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const PREFIX_ARTIFACT = path.join(ROOT, 'research', 'grant-file-lock-prefix-2026-11-17.json');
const FIXED_ARTIFACT = path.join(ROOT, 'research', 'grant-file-lock-fixed-2026-11-17.json');

function readArtifact(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('T1 both artifacts exist and name the tool and the pre-fix baseline', () => {
  const pre = readArtifact(PREFIX_ARTIFACT);
  const fixed = readArtifact(FIXED_ARTIFACT);
  for (const r of [pre, fixed]) {
    assert.equal(r.tool, 'tools/measure-grant-file-lock.js');
    assert.equal(r.prefixSha, '6e33571',
      'the baseline must be the pre-fix commit (6e33571), extracted with git archive');
    assert.equal(r.generatedAt, '2026-11-17');
    assert.ok(r.runs.length >= 3, 'at least 3 rounds per tree');
    assert.equal(r.writersPerRound, 8, '8 concurrent appends per round');
  }
});

test('T2 the prefix tree showed the defect; the fixed tree shows none', () => {
  const pre = readArtifact(PREFIX_ARTIFACT);
  const fixed = readArtifact(FIXED_ARTIFACT);
  assert.ok(pre.defectFaces.A1_ok_vs_disk_mismatch >= 1,
    'the prefix tree must show the ok-vs-disk mismatch (A1), else the fix is unmeasurable');
  assert.ok(pre.defectFaces.A2_grants_missing >= 1,
    'the prefix tree must show missing grants (A2)');
  assert.equal(pre.verdict, 'lost-updates-present');
  assert.equal(fixed.verdict, 'grant-file-writes-serialize');
  for (const v of Object.values(fixed.defectFaces)) {
    assert.equal(v, 0, 'the fixed tree must show no defect face');
  }
});

test('T3 the fixed tree numbers are exact: 9 grants every round, 0 refused', () => {
  const fixed = readArtifact(FIXED_ARTIFACT);
  for (const run of fixed.runs) {
    assert.equal(run.grantsOnDisk, 9, 'create + 8 appends must all land');
    assert.equal(run.appendOkReports, 8, 'every append reports ok');
    assert.equal(run.createOk, true, 'the create reports ok');
    assert.equal(run.refusedWriters, 0,
      'the fix must serialize, not refuse (concurrent writers are legitimate)');
    assert.equal(run.a3_lockLeft, false, 'no lock file left behind');
  }
});

test('T4 neither artifact carries a host path', () => {
  for (const p of [PREFIX_ARTIFACT, FIXED_ARTIFACT]) {
    const text = fs.readFileSync(p, 'utf8');
    assert.equal(/\/home\/|\/Users\/|\/root\/|\/tmp\/signerd-lockmeasure-/.test(text), false,
      `host path in ${path.basename(p)}`);
  }
});

test('T5 the verdicts are falsifiable (a hand-edited verdict goes RED)', () => {
  const pre = readArtifact(PREFIX_ARTIFACT);
  // The prefix artifact must DISAGREE with the fixed verdict; if someone
  // rewrites the prefix verdict to the passing one, this pin breaks.
  assert.notEqual(pre.verdict, 'grant-file-writes-serialize',
    'the prefix verdict must carry the defect, never the passing verdict');
  // The defect faces must be consistent with the verdict they carry.
  if (pre.verdict === 'lost-updates-present') {
    assert.ok(pre.defectFaces.A1_ok_vs_disk_mismatch > 0 || pre.defectFaces.A2_grants_missing > 0,
      'a defect verdict with zero defect faces is a story, not a measurement');
  }
});
