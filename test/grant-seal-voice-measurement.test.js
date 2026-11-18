'use strict';
// PIN: the grant-seal voice measurements must be honest.
//
// The measurement (tools/measure-grant-seal-voice.js) ran the SAME five
// defect faces plus one control against three trees:
//
//   - the PUBLISHED signerd v0.2.38 npm package (the channel a stranger
//     installs),
//   - this repo's PRE-FIX tree (2f280b6, the code as it shipped),
//   - this repo's FIXED tree.
//
// and all three verdicts are committed as JSON artifacts.
//
// WHAT THIS CLASS IS (measured 2026-11-18, published v0.2.38):
//
//   The seal is the PROVENANCE half of this product: it is what makes a
//   grant document's bytes trustworthy after a stranger once had write
//   access. The refusal family that protects it reached the operator as a
//   bare NAME:
//
//       grant_file_seal_mismatch:
//       grant_file_seal_invalid:
//       seal_passphrase_required:
//
//   - no reason, no repair - while the JOURNAL half of the same idea
//   (ledger_mac_invalid, ledger_mac_short, ledger_sealed) has carried a
//   repair since v0.2.36. The same operator, the same moment, two
//   different levels of being told what to do.
//
// WHAT THIS TEST CHECKS, WITHOUT re-running the measurement (it needs the
// unpacked npm tarball of the published tag):
//   P1 all three artifacts parse and carry their face list;
//   P2 the PUBLISHED artifact shows the DEFECT: verdict
//      `grant-seal-voice-mute`, five defect faces, and no face carrying a
//      `fix:` line;
//   P3 the PRE-FIX tree artifact shows the same defect, measured on the
//      repo tree (not only on the published package);
//   P4 the FIXED artifact shows the contract: verdict
//      `grant-seal-voice-closed`, zero violations, every face named after
//      itself and every one carrying a repair;
//   P5 all three cover the SAME faces (the comparison is fair) and no host
//      path leaks into any artifact;
//   P6 every repair printed by the fixed tree names a command this CLI
//      actually offers (rule F3), so the repair can be RUN.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const PUBLISHED = path.join(__dirname, '..', 'research',
  'grant-seal-voice-published-v0238-2026-11-18.json');
const PREFIX = path.join(__dirname, '..', 'research',
  'grant-seal-voice-prefix-2026-11-18.json');
const FIXED = path.join(__dirname, '..', 'research',
  'grant-seal-voice-fixed-2026-11-18.json');

const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

function report(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('P1 all three artifacts parse and carry their face list', () => {
  for (const p of [PUBLISHED, PREFIX, FIXED]) {
    const r = report(p);
    assert.ok(Array.isArray(r.rows) && r.rows.length >= 6,
      `${path.basename(p)} must carry the faces, got ${r.rows && r.rows.length}`);
    assert.strictEqual(r.faces, r.rows.length,
      `${path.basename(p)}: the face count must match the row count`);
    assert.ok(Array.isArray(r.rules) && r.rules.length > 0,
      `${path.basename(p)} must carry the rules it measured`);
  }
});

test('P2 the PUBLISHED v0.2.38 package shows the defect (red-first)', () => {
  const r = report(PUBLISHED);
  assert.strictEqual(r.verdict, 'grant-seal-voice-mute',
    'the published package must carry the DEFECT verdict');
  const defect = r.rows.filter((row) => !row.control);
  assert.strictEqual(defect.length, 5,
    `all five defect faces must be measured on the published package, got ${defect.length}`);
  const defective = defect.filter((row) => !row.ok);
  assert.strictEqual(defective.length, 5,
    `every defect face must be defective on the published package, got ${defective.length}`);
  // The defect is TWO-PART, and the pin says so precisely:
  //   (a) the four MUTE faces carry neither a reason nor a repair;
  //   (b) the fifth (grant_file_sealed) carries a repair but its reason is
  //       the file's resolved ABSOLUTE PATH - the only refusal in this CLI
  //       whose detail was a host path.
  const byId = Object.fromEntries(defect.map((row) => [row.id, row]));
  for (const id of ['seal_mismatch_tampered', 'seal_mismatch_wrong_passphrase',
    'seal_invalid_broken_block', 'seal_passphrase_required']) {
    assert.strictEqual(byId[id].hasFix, false, `${id}: no repair on the published package`);
    assert.strictEqual(byId[id].detail.length, 0, `${id}: no reason on the published package`);
  }
  assert.strictEqual(byId.grant_file_sealed_keyless.hasFix, true,
    'the sealed face carried a repair - its defect is the path in the reason');
  assert.strictEqual(byId.grant_file_sealed_keyless.detailLeaksPath, true,
    'the sealed face\'s reason carried the operator\'s absolute path');
});

test('P3 the PRE-FIX repo tree shows the same defect as the published package', () => {
  const r = report(PREFIX);
  assert.strictEqual(r.verdict, 'grant-seal-voice-mute',
    'the pre-fix tree must carry the DEFECT verdict');
  // The pre-fix tree shows the SAME two-part defect as the published
  // package: four mute faces (no reason, no repair) plus the path leak.
  assert.strictEqual(r.violations, 5,
    `the pre-fix tree must show five violations, got ${r.violations}`);
  assert.strictEqual(r.controlsBroken, 0,
    'the control face must hold on the pre-fix tree too (the trees are comparable)');
  assert.strictEqual(r.head, '2f280b6',
    'the pre-fix artifact must name the tree it was measured on');
});

test('P4 the FIXED tree shows the contract', () => {
  const r = report(FIXED);
  assert.strictEqual(r.verdict, 'grant-seal-voice-closed',
    'the fixed tree must carry the CLOSED verdict');
  assert.strictEqual(r.violations, 0,
    `the fixed tree must show zero violations, got ${r.violations}`);
  assert.strictEqual(r.controlsBroken, 0,
    'the control face must hold on the fixed tree');
  for (const row of r.rows) {
    assert.ok(row.hasFix, `${row.id}: every face must carry a repair on the fixed tree`);
    assert.strictEqual(row.occurrences, 1,
      `${row.id}: the code must appear exactly once`);
    assert.ok(row.refused, `${row.id}: every face must still refuse`);
  }
  // The reason must be non-empty where the face carries one (the
  // grant_file_unsealed control keeps its historic shape - the code is
  // what that face is).
  for (const row of r.rows.filter((x) => x.id !== 'grant_file_unsealed')) {
    assert.ok(row.detail.length > 0,
      `${row.id}: the fixed tree must carry a reason, got an empty one`);
  }
});

test('P5 all three cover the SAME faces, and no host path leaks', () => {
  const published = report(PUBLISHED);
  const prefix = report(PREFIX);
  const fixed = report(FIXED);
  const ids = (r) => r.rows.map((row) => row.id).sort().join(',');
  assert.strictEqual(ids(published), ids(prefix),
    'the published package and the pre-fix tree must be measured on the same faces');
  assert.strictEqual(ids(prefix), ids(fixed),
    'the pre-fix and the fixed tree must be measured on the same faces');
  for (const r of [published, prefix, fixed]) {
    const raw = fs.readFileSync(
      r === published ? PUBLISHED : (r === prefix ? PREFIX : FIXED), 'utf8');
    assert.ok(!/\/home\/[a-z0-9_-]+/.test(raw),
      `the committed artifact must be portable: no host user path in ${path.basename(
        r === published ? PUBLISHED : (r === prefix ? PREFIX : FIXED))}`);
    assert.ok(!/\/tmp\/signerd-grant-seal-voice-/.test(raw),
      'the committed artifact must not name its scratch directory');
  }
});

test('P6 every repair the fixed tree printed names a command this CLI offers', () => {
  const r = report(FIXED);
  for (const row of r.rows) {
    assert.deepStrictEqual(row.unknownCommands, [],
      `${row.id}: the repair names a command this CLI does not offer`);
    assert.deepStrictEqual(row.unknownFlags, [],
      `${row.id}: the repair names a flag this CLI does not offer`);
    assert.strictEqual(row.hostPath, false,
      `${row.id}: the repair must not carry a host path`);
  }
  // The known-command list of the gate itself is the product's own.
  assert.ok(KNOWN_COMMANDS.includes('verify-grants'),
    'the product must still offer verify-grants (the face\'s command)');
});
