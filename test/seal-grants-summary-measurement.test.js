'use strict';
// PIN: the two-tree seal-grants-SUMMARY measurement artifact must be honest.
//
// The measurement (tools/measure-seal-grants-summary.js) ran the SAME probe
// over the pre-fix tree (git archive <prefix>) and this tree, and committed
// the verdict as a JSON artifact.
//
// What this test checks, WITHOUT re-running the measurement (which needs a
// git object store and a full CLI round trip per case):
//   P1 the artifact parses, carries the named schema and prefix;
//   P2 the verdict is "seal-grants-summary-holds" and all three checks are true;
//   P3 the pre-fix tree shows BOTH defect faces: the window budget and the
//      message scope are absent from the summary (the measured defect);
//   P4 the fixed tree shows NEITHER face and has no drift: every summary
//      field equals the sealed document's field;
//   P5 the guard holds on the fixed tree: a valid file still seals and still
//      keeps every field the summary always had;
//   P6 no host path leaks into the artifact.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ARTIFACT = path.join(__dirname, '..', 'research', 'seal-grants-summary-2026-11-15.json');
const FACES = ['tx-window', 'message-scope'];

function report() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('P1 the artifact parses and carries its schema', () => {
  const r = report();
  assert.strictEqual(r.schema, 'signerd/seal-grants-summary/v1');
  assert.strictEqual(typeof r.prefix, 'string');
  assert.strictEqual(typeof r.tool, 'string');
});

test('P2 the verdict holds with every check true', () => {
  const r = report();
  assert.strictEqual(r.verdict, 'seal-grants-summary-holds');
  assert.strictEqual(r.instrumentSound, true,
    'the instrument must show the defect on the pre-fix tree');
  assert.deepStrictEqual(r.prefixShowsDefect, FACES);
  assert.deepStrictEqual(r.fixedShowsDefect, []);
  assert.deepStrictEqual(r.fixedDrift, []);
  assert.strictEqual(r.guardsHold, true);
});

test('P3 the pre-fix tree hides the budget and the scope (the measured defect)', () => {
  const r = report();
  for (const name of FACES) {
    const d = r.prefixTree.defects[name];
    assert.strictEqual(d.ok, true, `${name}: the pre-fix seal must succeed: ${d.exit}`);
    assert.strictEqual(d.showsWindowBudget, false,
      `${name}: the pre-fix summary must hide the window budget`);
    assert.strictEqual(d.showsMessageScope, false,
      `${name}: the pre-fix summary must hide the message scope`);
    assert.ok(d.missingFields.length > 0,
      `${name}: the pre-fix summary must drop sealed fields`);
  }
  // The concrete numbers the pulse measured, so the artifact cannot drift
  // into a claim no run produced.
  assert.deepStrictEqual(r.prefixTree.defects['tx-window'].missingFields,
    ['windowMaxLamports', 'windowSeconds']);
  assert.deepStrictEqual(r.prefixTree.defects['message-scope'].missingFields,
    ['kind', 'issuer', 'type', 'subject', 'pubkey', 'maxBytes',
      'windowMaxMessages', 'windowSeconds']);
});

test('P4 the fixed tree shows the whole scope with no drift', () => {
  const r = report();
  for (const name of FACES) {
    const d = r.fixedTreeResults.defects[name];
    assert.strictEqual(d.ok, true, `${name}: the seal must still succeed: ${d.exit}`);
    assert.strictEqual(d.driftFree, true, `${name}: no sealed field may be missing`);
    assert.deepStrictEqual(d.missingFields, [], `${name}: no missing fields`);
    assert.deepStrictEqual(d.contradictingFields, [], `${name}: no contradiction`);
  }
  assert.strictEqual(r.fixedTreeResults.defects['tx-window'].showsWindowBudget, true);
  assert.strictEqual(r.fixedTreeResults.defects['message-scope'].showsMessageScope, true);
});

test('P5 the guard holds on the fixed tree', () => {
  const r = report();
  const g = r.fixedTreeResults.guards.valid;
  assert.strictEqual(g.exit, 0, 'a valid file must still seal');
  assert.strictEqual(g.ok, true, 'the verdict must stay ok:true');
  assert.strictEqual(g.named, true, 'the grant must be named');
  assert.strictEqual(g.keepsSigner, true, 'the summary must keep signer');
  assert.strictEqual(g.keepsDestination, true, 'the summary must keep destination');
  assert.strictEqual(g.keepsMaxLamports, true, 'the summary must keep maxLamports');
  assert.strictEqual(g.keepsExpiresAt, true, 'the summary must keep expiresAt');
});

test('P6 the artifact carries no host paths', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  assert.ok(!/\/home\/[a-z0-9_-]+/.test(raw),
    'the committed artifact must be portable: no host user path');
  assert.ok(!/\/tmp\/signerd-sealsummary-/.test(raw),
    'the committed artifact must not name its scratch directories');
});
