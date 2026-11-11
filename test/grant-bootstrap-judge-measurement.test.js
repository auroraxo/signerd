'use strict';

// The MEASUREMENT PIN for the grant bootstrap's loader judgement
// (2026-11-11).
//
// The artifact research/grant-bootstrap-judge-2026-11-11.json is what the
// release notes and the card cite, so it must be a measurement and not a
// story:
//
//   T1 the artifact exists, names its tool and the PRE-FIX BASELINE it
//      measured (29fc8c5 — the published v0.2.16 tree, extracted with git
//      archive — the code that shipped, never this working tree);
//   T2 the baseline showed every defect face and this tree shows none:
//      verdict `violations-present -> refusals-present`, 4/4 → 0/4;
//   T3 the guards held on both trees (the fix must not break the
//      documented quickstart) — missing-file creation, valid-file
//      extension, sealed-file refusal;
//   T4 every refusal on this tree names the PRODUCT's loader reason
//      (grant_field_invalid / grant_file_mode / grant_file_symlink), not a
//      bespoke verdict;
//   T5 the artifact carries no host path (a committed artifact that names
//      the measuring host is a snapshot, not a measurement).
//
// T2 and T5 are falsifiable on purpose: hand-edit a defect count in the
// artifact, or add a host path, and this test must go RED.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT = path.join(ROOT, 'research', 'grant-bootstrap-judge-2026-11-11.json');

function readArtifact() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

const FACES = ['broken', 'mode-0664', 'symlink', 'exists-broken'];
const GUARDS = ['missing', 'valid', 'sealed'];

test('T1 the artifact exists and names the pre-fix baseline it measured', () => {
  const r = readArtifact();
  assert.equal(r.tool, 'tools/measure-grant-bootstrap-judge.js');
  assert.equal(r.preFix.ref, '29fc8c5',
    'the baseline must be the pre-fix commit (29fc8c5 = the tree that shipped v0.2.16), extracted with git archive');
  assert.equal(r.generatedAt, '2026-11-11');
  assert.ok(r.measuredAt.startsWith('2026-11-11'), 'measured on 2026-11-11');
});

test('T2 the pre-fix tree showed all four defect faces; this tree shows none', () => {
  const r = readArtifact();
  for (const face of FACES) {
    assert.equal(r.preFix.faces[face].classification, 'defect',
      `a baseline without the ${face} face makes the fix unmeasurable`);
  }
  assert.equal(r.preFixFaceCount, FACES.length, 'every face must be RED on the baseline');
  for (const face of FACES) {
    assert.equal(r.fixed.faces[face].classification, 'refused',
      `this tree must refuse the ${face} face`);
  }
  assert.equal(r.fixedFaceCount, 0, 'this tree must show no defect');
  assert.equal(r.verdict, 'violations-present -> refusals-present');
});

test('T3 the guards held on both trees (the documented quickstart survives)', () => {
  const r = readArtifact();
  for (const guard of GUARDS) {
    assert.equal(r.fixed.guards[guard].classification, 'holds',
      `the ${guard} guard must hold on this tree`);
    assert.equal(r.preFix.guards[guard].classification, 'holds',
      `the ${guard} guard must also hold on the baseline (a broken guard is not a measured defect)`);
  }
  assert.equal(r.fixedGuardBrokenCount, 0);
});

test('T4 every refusal on this tree names the loader reason', () => {
  const r = readArtifact();
  assert.equal(r.fixed.faces.broken.observed.reason, 'grant_field_invalid',
    'a file the daemon refuses at start must be refused by the loader verdict');
  assert.equal(r.fixed.faces['mode-0664'].observed.reason, 'grant_file_mode',
    'the mode refusal must be the loader reason, never a silent chmod-repair');
  assert.equal(r.fixed.faces.symlink.observed.reason, 'grant_file_symlink',
    'a symlink must be refused by name');
  assert.equal(r.fixed.faces['exists-broken'].observed.reason, 'grant_field_invalid',
    'the judgement must come BEFORE the name check (no ok verdict for a dead file)');
  // And the refusal must not have written: bytes unchanged on every face.
  for (const face of FACES) {
    assert.equal(r.fixed.faces[face].observed.fileChanged, false,
      `the refused ${face} case must not have changed the file`);
  }
  assert.equal(r.fixed.faces['mode-0664'].observed.modeAfter, 0o664,
    'the refusal must not tighten the mode either (tighten-then-trust is the bug)');
});

test('T5 the artifact carries no host path (a snapshot is not a measurement)', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  for (const needle of ['/home/', '/Users/', '/tmp/', 'C:\\']) {
    assert.ok(!raw.includes(needle), `the artifact must not contain ${needle}`);
  }
});
