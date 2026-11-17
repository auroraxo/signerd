'use strict';
// PIN: the two-tree VERDICT-surface measurement artifact must be honest.
//
// The measurement (tools/measure-grant-key-verdict.js) ran the SAME probe
// over the pre-fix tree (git archive v0.2.32) and this tree, and committed
// the verdict as a JSON artifact.
//
// What this test checks, WITHOUT re-running the measurement (which needs a
// git object store and a full CLI round trip per case):
//   P1 the artifact parses, carries the named schema and prefix;
//   P2 the verdict is "grant-key-verdict-holds" and every check is true;
//   P3 every defect face on the PRE-FIX tree shows the defect: exit 0 +
//      ok:true — and `seal-grants` really SEALED the dead file (the sharpest
//      face: an authenticated file no daemon can run);
//   P4 every defect face on the FIXED tree is refused: exit != 0, no
//      ok:true, named reason, and the seal case leaves the file byte-
//      identical with no seal written;
//   P5 every guard holds on the fixed tree: single-key files still answer
//      ok:true on all three surfaces, the cross-encoding case is ONE key,
//      and `grant-remove` still repairs an already broken file;
//   P6 no host path leaks into the artifact.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ARTIFACT = path.join(__dirname, '..', 'research', 'grant-key-verdict-2026-11-17.json');
const DEFECT_CASES = ['status-two-key', 'seal-two-key', 'verify-sealed-two'];
const GUARD_CASES = ['status-single', 'seal-single', 'verify-single', 'cross-encoding', 'remove-repairs'];

function report() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('P1 the artifact parses and carries its schema', () => {
  const r = report();
  assert.strictEqual(r.schema, 'signerd/grant-key-verdict/v1');
  assert.strictEqual(typeof r.prefix, 'string');
});

test('P2 the verdict holds with every check true', () => {
  const r = report();
  assert.strictEqual(r.verdict, 'grant-key-verdict-holds');
  for (const value of Object.values(r.checks)) assert.strictEqual(value, true);
});

test('P3 the pre-fix tree shows every defect face', () => {
  const r = report();
  for (const name of DEFECT_CASES) {
    const d = r.prefixTree.defects[name];
    assert.strictEqual(d.status, 0, `${name}: pre-fix tree must exit 0 (the defect): ${d.status}`);
    assert.strictEqual(d.okVerdict, true, `${name}: pre-fix tree must report ok:true`);
  }
  // The measured defect, spelled out: the pre-fix tree AUTHENTICATED a file
  // the daemon refuses to run.
  assert.strictEqual(r.prefixTree.defects['seal-two-key'].sealed, true,
    'seal-grants must have sealed the dead file on the pre-fix tree');
});

test('P4 the fixed tree refuses every defect face and writes nothing', () => {
  const r = report();
  for (const name of DEFECT_CASES) {
    const d = r.fixedTree.defects[name];
    assert.notStrictEqual(d.status, 0, `${name}: fixed tree must refuse`);
    assert.strictEqual(d.okVerdict, false, `${name}: fixed tree must not report ok:true`);
    assert.strictEqual(typeof d.reason, 'string', `${name}: the refusal must be named`);
  }
  // One judge, one reason: the refusal is the same code the write paths use.
  for (const name of DEFECT_CASES) {
    assert.strictEqual(r.fixedTree.defects[name].reason, 'grant_file_key_mismatch',
      `${name}: the refusal must be grant_file_key_mismatch`);
  }
  const seal = r.fixedTree.defects['seal-two-key'];
  assert.strictEqual(seal.fileUnchanged, true, 'a refused seal must leave the file untouched');
  assert.strictEqual(seal.sealed, false, 'no seal may be written for a refused file');
  const verify = r.fixedTree.defects['verify-sealed-two'];
  assert.strictEqual(verify.fileUnchanged, true, 'verify-grants must not rewrite the file');
});

test('P5 the guards hold on the fixed tree', () => {
  const r = report();
  for (const name of GUARD_CASES) {
    const g = r.fixedTree.guards[name];
    assert.strictEqual(g.status, 0, `guard ${name} must pass: ${g.stderrHead}`);
    assert.strictEqual(g.okVerdict, true, `guard ${name} must report ok:true`);
  }
  assert.strictEqual(r.fixedTree.guards['remove-repairs'].repairWorked, true,
    'grant-remove must still repair an already broken file');
});

test('P6 the artifact carries no host paths', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  assert.doesNotMatch(raw, /\/home\/|\/Users\/|\/tmp\//,
    'the committed artifact must not contain host paths');
});
