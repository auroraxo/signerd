'use strict';
// PIN: the two-tree SEAL-MODE measurement artifact must be honest.
//
// The measurement (tools/measure-seal-mode-degradation.js) ran the SAME
// probe over the pre-fix tree (git archive 41cd128 = the published v0.2.27)
// and this tree, and committed the verdict as a JSON artifact.
//
// What this test checks, WITHOUT re-running the measurement (which needs a
// git object store and a full daemon round trip per case):
//   P1 the artifact parses, carries the named schema and prefix;
//   P2 the verdict is "seal-mode-holds" with the instrument sound;
//   P3 the pre-fix tree shows ALL THREE defect faces - the keyless read
//      loads the TAMPERED destination, status reports {"ok":true,
//      "sealed":false}, and the daemon SERVES the tampered file;
//   P4 the fixed tree shows NEITHER face: loader refused with
//      grant_file_sealed, status exit 1, daemon refused with the same code;
//   P5 the controls hold on BOTH trees: the JOURNAL half refuses
//      (ledger_sealed) and the keyed read still refuses tampered content;
//   P6 the guards hold on BOTH trees (the re-seal repair keeps working),
//      and the artifact carries no host or scratch paths.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ARTIFACT = path.join(__dirname, '..', 'research', 'seal-mode-degradation-2026-11-16.json');
const FACES = ['F1-keyless-read', 'F2-keyless-status', 'F3-tamper-blind'];
const TAMPERED = '11111111111111111111111111111111';

function report() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('P1 the artifact parses and carries its schema', () => {
  const r = report();
  assert.strictEqual(r.schema, 'signerd/seal-mode/v1');
  assert.strictEqual(typeof r.prefix, 'string');
  assert.strictEqual(typeof r.tool, 'string');
});

test('P2 the verdict holds, instrument sound, no face on the fixed tree', () => {
  const r = report();
  assert.strictEqual(r.verdict, 'seal-mode-holds');
  assert.strictEqual(r.instrumentSound, true,
    'the instrument must show the defect on the pre-fix tree');
  assert.deepStrictEqual(r.prefixShowsDefect, FACES);
  assert.deepStrictEqual(r.fixedShowsDefect, []);
  assert.strictEqual(r.journalControlHolds, true);
  assert.strictEqual(r.keyedRefusalHolds, true);
  assert.strictEqual(r.guardsHold, true);
});

test('P3 the pre-fix tree degrades on all three faces (the measured defect)', () => {
  const r = report();
  const p = r.prefixTree;
  // F1: the loader read the sealed file without a passphrase - and handed
  // back the TAMPERED destination. That is the defect in one number.
  assert.strictEqual(p.keyless.keylessLoader.loaded, true,
    'the pre-fix loader must load a sealed file keylessly (the defect)');
  assert.strictEqual(p.keyless.keylessLoader.readTampered, true,
    'the pre-fix loader must hand back the tampered destination');
  assert.strictEqual(p.keyless.keylessLoader.destination, TAMPERED);
  // F2: status said ok, and said the file was not sealed.
  assert.strictEqual(p.keyless.keylessStatus.exit, 0,
    'the pre-fix status must exit 0 on a sealed file (the defect)');
  assert.strictEqual(p.keyless.keylessStatus.ok, true);
  assert.strictEqual(p.keyless.keylessStatus.reportedSealed, false);
  // F3: the daemon SERVED the sealed+tampered file without the passphrase.
  assert.strictEqual(p.daemon.started, true,
    'the pre-fix daemon must serve a sealed+tampered file (the defect)');
  assert.strictEqual(p.daemon.refused, false);
});

test('P4 the fixed tree refuses all three faces with the named reason', () => {
  const r = report();
  const f = r.fixedTreeResults;
  assert.strictEqual(f.keyless.keylessLoader.loaded, false);
  assert.strictEqual(f.keyless.keylessLoader.code, 'grant_file_sealed');
  assert.strictEqual(f.keyless.keylessLoader.readTampered, false,
    'the tampered destination must never reach a keyless caller');
  assert.notStrictEqual(f.keyless.keylessStatus.exit, 0,
    'status must refuse a sealed file it cannot verify');
  assert.notStrictEqual(f.keyless.keylessStatus.ok, true);
  assert.strictEqual(f.daemon.started, false);
  assert.strictEqual(f.daemon.refused, true);
  assert.strictEqual(f.daemon.reason, 'grant_file_sealed');
});

test('P5 the controls hold on BOTH trees: journal refuses, keyed read refuses', () => {
  const r = report();
  assert.strictEqual(r.prefixTree.journal.refusedWithLedgerSealed, true,
    'the journal half always refused - it is the control');
  assert.strictEqual(r.fixedTreeResults.journal.refusedWithLedgerSealed, true);
  for (const side of ['prefixTree', 'fixedTreeResults']) {
    assert.strictEqual(r[side].keyless.keyedRefusesTamper.refused, true,
      `${side}: the keyed read must still refuse tampered content`);
    assert.strictEqual(r[side].keyless.keyedRefusesTamper.reason,
      'grant_file_seal_mismatch');
  }
});

test('P6 the guards hold on BOTH trees and the artifact is portable', () => {
  const r = report();
  for (const side of ['prefixTree', 'fixedTreeResults']) {
    const g = r[side].guards;
    assert.strictEqual(g.firstSeal.ok, true, `${side}: sealing must work`);
    assert.strictEqual(g.resealAfterHandEdit.ok, true,
      `${side}: the documented re-seal repair must keep working`);
    assert.strictEqual(g.resealedVerifies.ok, true,
      `${side}: the new seal must verify`);
  }
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  assert.ok(!/\/home\/[a-z0-9_-]+/.test(raw),
    'the committed artifact must be portable: no host user path');
  assert.ok(!/\/tmp\/signerd-sealmode-/.test(raw),
    'the committed artifact must not name its scratch directories');
});
