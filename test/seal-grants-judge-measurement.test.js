'use strict';
// PIN: the two-tree seal-grants measurement artifact must be honest.
//
// The measurement (tools/measure-seal-grants-judge.js) ran the SAME probe
// over the pre-fix tree (git archive <prefix>) and this tree, and committed
// the verdict as a JSON artifact.
//
// What this test checks, WITHOUT re-running the measurement (which needs a
// git object store and a full CLI round trip per case):
//   P1 the artifact parses, carries the named schema and prefix;
//   P2 the verdict is "seal-grants-judge-holds" and all three checks are true;
//   P3 every defect face on the PRE-FIX tree shows the defect: status 0 +
//      ok:true (the command sealed a file the loader refuses);
//   P4 every defect face on the FIXED tree is refused: status != 0, no
//      ok:true, fileUnchanged, no seal written, and a named reason;
//   P5 every guard holds: the documented repair paths still exit 0 with
//      ok:true on the fixed tree;
//   P6 no host path leaks into the artifact.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ARTIFACT = path.join(__dirname, '..', 'research', 'seal-grants-judge-2026-11-13.json');
const DEFECT_CASES = ['broken-grant', 'typo-field', 'reserved-name', 'symlink'];
const GUARD_CASES = ['valid', 'reseal', 'out-copy'];

function report() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('P1 the artifact parses and carries its schema', () => {
  const r = report();
  assert.strictEqual(r.schema, 'signerd/seal-grants-judge/v1');
  assert.strictEqual(typeof r.prefix, 'string');
});

test('P2 the verdict holds with every check true', () => {
  const r = report();
  assert.strictEqual(r.verdict, 'seal-grants-judge-holds');
  assert.strictEqual(r.checks.prefixShowsAllDefectFaces, true);
  assert.strictEqual(r.checks.fixedTreeRefusesEveryDefectFace, true);
  assert.strictEqual(r.checks.guardsHoldOnFixedTree, true);
});

test('P3 the pre-fix tree shows every defect face', () => {
  const r = report();
  for (const name of DEFECT_CASES) {
    const d = r.prefixTree.defects[name];
    assert.strictEqual(d.status, 0, `${name}: pre-fix tree must exit 0 (the defect): ${d.status}`);
    assert.strictEqual(d.okVerdict, true, `${name}: pre-fix tree must report ok:true`);
  }
});

test('P4 the fixed tree refuses every defect face and writes nothing', () => {
  const r = report();
  for (const name of DEFECT_CASES) {
    const d = r.fixedTree.defects[name];
    assert.notStrictEqual(d.status, 0, `${name}: fixed tree must refuse`);
    assert.strictEqual(d.okVerdict, false, `${name}: fixed tree must not report ok:true`);
    assert.strictEqual(d.fileUnchanged, true, `${name}: a refused seal must leave the file untouched`);
    assert.strictEqual(d.sealed, false, `${name}: no seal may be written for a refused file`);
    assert.strictEqual(typeof d.reason, 'string', `${name}: the refusal must be named`);
  }
  // The names are the loader's own reasons — one judge, both paths.
  assert.strictEqual(r.fixedTree.defects['broken-grant'].reason, 'grant_field_invalid');
  assert.strictEqual(r.fixedTree.defects['typo-field'].reason, 'grant_unknown_field');
  assert.strictEqual(r.fixedTree.defects['reserved-name'].reason, 'grant_name_invalid');
  assert.strictEqual(r.fixedTree.defects['symlink'].reason, 'grant_file_symlink');
});

test('P5 the guards hold on the fixed tree', () => {
  const r = report();
  for (const name of GUARD_CASES) {
    const g = r.fixedTree.guards[name];
    assert.strictEqual(g.status, 0, `guard ${name} must pass: ${g.stderrHead}`);
    assert.strictEqual(g.okVerdict, true, `guard ${name} must report ok:true`);
  }
});

test('P6 the artifact carries no host paths', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  assert.ok(!/\/home\/[a-z0-9_-]+/.test(raw),
    'the committed artifact must be portable: no host user path');
  assert.ok(!/\/tmp\/signerd-sealjudge-/.test(raw),
    'the committed artifact must not name its scratch directories');
});
