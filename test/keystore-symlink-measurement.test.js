'use strict';
// PIN: the two-tree keystore-symlink measurement artifact must be honest.
//
// The measurement (tools/measure-keystore-symlink.js) ran the SAME probe over
// the published pre-fix tree (git archive v0.2.21) and this tree, and committed
// the verdict as a JSON artifact.
//
// What this test checks, WITHOUT re-running the measurement (which needs a git
// object store and two live trees):
//   P1 the artifact parses, carries the question and the pre-fix ref;
//   P2 the pre-fix tree shows the defect (7 faces defective, verdict
//      keystore-symlink-defect-present) and the fixed tree holds the rule
//      (0 violations, verdict keystore-symlink-rule-holds);
//   P3 every named face on the PRE-FIX tree is defective — the faces are the
//      ones a stranger hit on the published tree;
//   P4 every named face on the FIXED tree is refused or atomic;
//   P5 every guard holds on BOTH trees (the fix does not weaken the ordinary
//      keygen/import/load paths, and never did);
//   P6 no host path leaks into the artifact.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ARTIFACT = path.join(__dirname, '..', 'research', 'keystore-symlink-2026-11-13.json');
const DEFECT_FACES = ['K1', 'K2', 'K3', 'K4', 'K5', 'K6', 'K7'];

function report() { return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8')); }

test('P1 the artifact parses and carries the question and the pre-fix ref', () => {
  const r = report();
  assert.strictEqual(typeof r.question, 'string');
  assert.ok(r.question.length > 0);
  assert.strictEqual(r.preFix.ref, 'v0.2.21', 'the pre-fix tree must be the published tag');
});

test('P2 pre-fix shows the defect, fixed tree holds the rule', () => {
  const r = report();
  assert.strictEqual(r.preFix.verdict, 'keystore-symlink-defect-present');
  assert.ok(r.preFix.violations >= DEFECT_FACES.length,
    `pre-fix must show all ${DEFECT_FACES.length} faces defective: ${r.preFix.violations}`);
  assert.strictEqual(r.fixedTree.verdict, 'keystore-symlink-rule-holds');
  assert.strictEqual(r.fixedTree.violations, 0, 'the fixed tree must have 0 violations');
});

test('P3 every named face on the PRE-FIX tree is defective', () => {
  const r = report();
  for (const id of DEFECT_FACES) {
    const face = r.preFix.faces[id];
    assert.ok(face, `${id}: face must exist in the pre-fix tree`);
    assert.strictEqual(face.defect, true, `${id}: pre-fix tree must show the defect`);
  }
});

test('P4 every named face on the FIXED tree is refused or atomic', () => {
  const r = report();
  for (const id of DEFECT_FACES) {
    const face = r.fixedTree.faces[id];
    assert.ok(face, `${id}: face must exist in the fixed tree`);
    assert.strictEqual(face.defect, false, `${id}: fixed tree must hold the rule`);
  }
  // The refusal is NAMED on the fixed tree — a bare refusal (or a silently
  // followed link) fails this pin.
  for (const id of ['K1', 'K2', 'K3', 'K4', 'K5', 'K6']) {
    assert.strictEqual(r.fixedTree.faces[id].refusal, 'keystore_symlink',
      `${id}: the refusal must be named keystore_symlink`);
  }
  assert.strictEqual(r.fixedTree.faces.K7.truncatesTargetDirectly, false,
    'the fixed writer must not truncate the target directly');
  assert.strictEqual(r.fixedTree.faces.K7.publishedFileStillOldCompleteBytes, true,
    'an interrupted replacement must leave the old complete bytes');
});

test('P5 every guard holds on BOTH trees', () => {
  const r = report();
  for (const g of r.guards.preFix) assert.strictEqual(g.ok, true, `${g.id} (pre-fix): ${JSON.stringify(g)}`);
  for (const g of r.guards.fixedTree) assert.strictEqual(g.ok, true, `${g.id} (fixed): ${JSON.stringify(g)}`);
  assert.strictEqual(r.preFix.guardFailures, 0);
  assert.strictEqual(r.fixedTree.guardFailures, 0);
});

test('P6 no host path leaks into the artifact', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  assert.doesNotMatch(raw, /\/home\/[A-Za-z0-9._-]+/, 'no /home/ path may appear');
  assert.doesNotMatch(raw, /\/Users\/[A-Za-z0-9._-]+/, 'no /Users/ path may appear');
  assert.doesNotMatch(raw, /\/tmp\//, 'no /tmp/ path may appear');
});
