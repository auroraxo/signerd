'use strict';
// PIN: the two-tree operator-input voice measurements must be honest.
//
// The measurement (tools/measure-input-voice.js) ran the SAME nine faces
// against the PUBLISHED v0.2.22 npm tarball and against this tree, and both
// verdicts are committed as JSON artifacts.
//
// What this test checks, WITHOUT re-running the measurement (it needs the
// unpacked npm tarball of the published tag):
//   P1 both artifacts parse and carry the face list;
//   P2 the pre-fix artifact (published v0.2.22) shows the DEFECT: verdict
//      `violations-present` with the raw-errno faces leaking ENOENT/EACCES/
//      EISDIR and exiting 1 (a usage refusal must be exit 2);
//   P3 the fixed artifact shows the contract: verdict `refusals-present`,
//      0 violations, every face named after itself with a `fix:` line and
//      exit 2;
//   P4 the two artifacts cover the SAME faces (the comparison is fair);
//   P5 no host path leaks into either artifact.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const FIXED = path.join(__dirname, '..', 'research', 'input-voice-fixed-2026-11-14.json');
const PREFIX = path.join(__dirname, '..', 'research', 'input-voice-v0.2.22-2026-11-14.json');
// The faces that were measured leaking a raw errno on the published tree.
const DEFECT_FACES = [
  'passphrase_file_missing', 'passphrase_file_not_a_file', 'passphrase_file_unreadable',
  'tx_not_a_file', 'tx_unreadable',
  'body_missing', 'body_not_a_file', 'body_unreadable',
];
// The one face that already had the product's voice on v0.2.22 (2026-11-05).
const GUARD_FACE = 'tx_missing';

function report(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('P1 both artifacts parse and carry their face list', () => {
  for (const p of [FIXED, PREFIX]) {
    const r = report(p);
    assert.strictEqual(typeof r.measuredAt, 'string', `${p}: measuredAt`);
    assert.ok(Array.isArray(r.rows) && r.rows.length === 9, `${p}: nine faces`);
    assert.strictEqual(r.faces, 9, `${p}: faces count`);
  }
});

test('P2 the published v0.2.22 tree shows the defect', () => {
  const r = report(PREFIX);
  assert.strictEqual(r.verdict, 'violations-present', 'the pre-fix tree must violate');
  assert.ok(r.violations >= 8, `at least 8 faces must violate: ${r.violations}`);
  const byId = new Map(r.rows.map((row) => [row.id, row]));
  // One face (passphrase directory) failed WITHOUT a raw errno on the
  // published tree: it exited 2 with a message that named neither a code
  // nor a repair (`passphrase-file must be a regular file`). The other
  // seven leaked a raw errno and exited 1.
  const NAMED_BUT_BARE = ['passphrase_file_not_a_file'];
  for (const id of DEFECT_FACES) {
    const row = byId.get(id);
    assert.ok(row, `${id}: face present in the pre-fix artifact`);
    assert.strictEqual(row.ok, false, `${id}: pre-fix must be a violation`);
    if (NAMED_BUT_BARE.includes(id)) {
      assert.strictEqual(row.rawErrno, false, `${id}: no errno, just no voice`);
      assert.strictEqual(row.hasFix, false, `${id}: the repair line was missing`);
      assert.strictEqual(row.named, false, `${id}: no machine-readable code`);
    } else {
      assert.strictEqual(row.rawErrno, true, `${id}: a raw errno must be what leaked`);
      assert.strictEqual(row.exit, 1,
        `${id}: the errno escape used exit 1, not the usage code 2`);
    }
  }
  // The guard face was already correct before the fix.
  const guard = byId.get(GUARD_FACE);
  assert.strictEqual(guard.ok, true, `${GUARD_FACE}: already correct on v0.2.22`);
});

test('P3 the fixed tree honours the contract on every face', () => {
  const r = report(FIXED);
  assert.strictEqual(r.verdict, 'refusals-present', 'the fixed tree must refuse by name');
  assert.strictEqual(r.violations, 0, 'the fixed tree must have no violation');
  for (const row of r.rows) {
    assert.strictEqual(row.ok, true, `${row.id}: must be ok`);
    assert.strictEqual(row.named, true, `${row.id}: must be named`);
    assert.strictEqual(row.hasFix, true, `${row.id}: must carry a repair`);
    assert.strictEqual(row.exit, 2, `${row.id}: a usage refusal exits 2`);
    assert.strictEqual(row.rawErrno, false, `${row.id}: no raw errno`);
    assert.ok(row.id === row.firstLine.split(':')[0],
      `${row.id}: the refusal must name itself (first line: ${row.firstLine})`);
  }
});

test('P4 both artifacts cover the same faces (a fair comparison)', () => {
  const fixed = report(FIXED).rows.map((row) => row.id).sort();
  const prefix = report(PREFIX).rows.map((row) => row.id).sort();
  assert.deepStrictEqual(fixed, prefix, 'the two trees must be probed with the same faces');
});

test('P5 no host path leaks into either artifact', () => {
  for (const p of [FIXED, PREFIX]) {
    const text = fs.readFileSync(p, 'utf8');
    assert.doesNotMatch(text, /\/home\/[a-z]+\//, `${p}: host home path leaked`);
    assert.doesNotMatch(text, /signerd-input-voice-measure-[A-Za-z0-9]{6,}/,
      `${p}: a tmpdir name leaked into the artifact`);
  }
});
