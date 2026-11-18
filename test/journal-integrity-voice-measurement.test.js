'use strict';
// PIN: the two-tree journal-integrity voice measurements must be honest.
//
// The measurement (tools/measure-journal-integrity-voice.js) ran the SAME
// fourteen refusal faces plus four guards against the PUBLISHED signerd
// v0.2.35 npm package and against this tree, and both verdicts are committed
// as JSON artifacts.
//
// WHAT THIS CLASS IS (measured 2026-11-18, published v0.2.35):
//
//   The journal is the replay set and the rolling-window budget. When the
//   JOURNAL refuses, the operator is one step from trusting history it
//   should not trust - and on the published tree the refusal reached them
//   as a bare NAME with no repair, and in nine of fourteen faces as
//
//       error: ledger_tampered
//
//   where the refusal's name was buried in the detail text: the first
//   colon-separated token - the one a caller reads - was the literal word
//   "error", so every journal refusal looked identical to a machine.
//
// WHAT THIS TEST CHECKS, WITHOUT re-running the measurement (it needs the
// unpacked npm tarball of the published tag):
//   P1 both artifacts parse and carry the face list;
//   P2 the pre-fix artifact (published v0.2.35) shows the DEFECT: verdict
//      `journal-integrity-refusals-ship-mute`, every J-face defective,
//      and no face carrying a `fix:` line;
//   P3 the fixed artifact shows the contract: verdict
//      `journal-integrity-refusals-name-their-repair`, zero defects,
//      every J-face named after itself and every one carrying a repair;
//   P4 the two artifacts cover the SAME faces (the comparison is fair);
//   P5 no host path leaks into either artifact, and every guard is green
//      on BOTH trees (the guards are what make the trees comparable);
//   P6 every repair printed by the fixed tree names a command this CLI
//      actually offers (rule F3), so the repair can be RUN.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const PREFIX = path.join(__dirname, '..', 'research',
  'journal-integrity-voice-published-v0235-2026-11-18.json');
const FIXED = path.join(__dirname, '..', 'research',
  'journal-integrity-voice-fixed-2026-11-18.json');

const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

function report(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('P1 both artifacts parse and carry their face list', () => {
  const pre = report(PREFIX);
  const post = report(FIXED);
  assert.ok(Array.isArray(pre.faces) && pre.faces.length >= 14,
    `the pre-fix artifact must carry the faces, got ${pre.faces && pre.faces.length}`);
  assert.ok(Array.isArray(post.faces) && post.faces.length >= 14,
    `the fixed artifact must carry the faces, got ${post.faces && post.faces.length}`);
  assert.strictEqual(pre.tool, 'measure-journal-integrity-voice');
  assert.strictEqual(post.tool, 'measure-journal-integrity-voice');
});

test('P2 the published v0.2.35 tree shows the defect (red-first)', () => {
  const pre = report(PREFIX);
  assert.strictEqual(pre.judgement, 'journal-integrity-refusals-ship-mute',
    'the published tree must carry the DEFECT verdict');
  const jFaces = pre.faces.filter((f) => f.face.startsWith('J'));
  assert.strictEqual(jFaces.length, 14, 'all fourteen J-faces must be measured');
  const defective = jFaces.filter((f) => f.defective);
  assert.strictEqual(defective.length, 14,
    `every J-face must be defective on the published tree, got ${defective.length}`);
  // Not one refusal named a repair on the published tree.
  const withFix = jFaces.filter((f) => f.hasFix === true);
  assert.strictEqual(withFix.length, 0,
    `no published refusal carried a fix: line, got ${withFix.length}`);
  // And the buried-code face: the refusal's name must not be the word
  // "error" on the published tree for the loader-raised refusals. Seven of
  // the fourteen came from the loader, which raised an error WITHOUT a code
  // (src/ledger.js), so the CLI printed the literal "error:" and the
  // refusal's own name sat in the detail text.
  const buried = jFaces.filter((f) => f.codeIsTheCode === false);
  assert.strictEqual(buried.length, 7,
    `seven loader-raised refusals were buried as "error: ..." on the published ` +
    `tree, got ${buried.length}: ${buried.map((f) => f.face).join(', ')}`);
  for (const f of buried) {
    assert.match(f.stderrHead, /^error: /,
      `${f.face} must have reached the operator as "error: ..." on the ` +
      `published tree, got: ${f.stderrHead}`);
  }
  assert.strictEqual(pre.version, '0.2.35');
  assert.strictEqual(pre.tree, 'published');
});

test('P3 the fixed tree holds the contract', () => {
  const post = report(FIXED);
  assert.strictEqual(post.judgement, 'journal-integrity-refusals-name-their-repair');
  assert.strictEqual(post.defectCount, 0,
    `the fixed tree must have zero defective faces, got ${post.defectCount}`);
  const jFaces = post.faces.filter((f) => f.face.startsWith('J'));
  assert.strictEqual(jFaces.length, 14);
  for (const f of jFaces) {
    assert.strictEqual(f.defective, false, `${f.face} is still defective`);
    assert.strictEqual(f.codeIsTheCode, true,
      `${f.face} must name itself (first stderr token), got: ${f.stderrHead}`);
    assert.strictEqual(f.hasFix, true, `${f.face} must carry a fix: line`);
    assert.strictEqual(f.exit, 1, `${f.face} must still refuse with exit 1`);
  }
});

test('P4 both artifacts cover the same faces (the comparison is fair)', () => {
  const pre = report(PREFIX).faces.map((f) => f.face).sort();
  const post = report(FIXED).faces.map((f) => f.face).sort();
  assert.deepStrictEqual(pre, post,
    'the two trees must be measured on the SAME faces');
});

test('P5 no host path in either artifact, guards green on BOTH trees', () => {
  for (const p of [PREFIX, FIXED]) {
    const r = report(p);
    const text = JSON.stringify(r);
    assert.ok(!/\/home\/|\/Users\/|\/root\//.test(text),
      `no host path may appear in ${path.basename(p)}`);
    for (const f of r.faces) {
      if (f.face.startsWith('G')) {
        assert.strictEqual(f.defective, false,
          `guard ${f.face} must be green on ${path.basename(p)} (it got ` +
          `${f.defective ? 'red' : 'green'}): ${f.note}`);
      }
      // Every repair that exists must name only commands this CLI offers.
      const unknown = f.unknownCommandsInRepair || [];
      assert.deepStrictEqual(unknown, [],
        `${f.face} names a command this CLI does not offer: ${unknown.join(', ')}`);
      assert.notStrictEqual(f.hostPathInRepair, true,
        `${f.face} carries a host path in its repair`);
    }
  }
});

test('P6 every repair the fixed tree prints names an offered command', () => {
  const post = report(FIXED);
  for (const f of post.faces.filter((x) => x.face.startsWith('J'))) {
    // The repair text itself is not in the artifact (it is scrubbed to the
    // first stderr line), so this checks the two structural rules the
    // instrument recorded: no unknown command, no host path.
    assert.deepStrictEqual(f.unknownCommandsInRepair, [],
      `${f.face} names an unknown command`);
    assert.notStrictEqual(f.hostPathInRepair, true,
      `${f.face} leaks a host path`);
    assert.notStrictEqual(f.hasCode, false,
      `${f.face} did not print its code at all`);
  }
  // And the command list this test itself believes in is the CLI's own.
  const cli = fs.readFileSync(path.join(__dirname, '..', 'src', 'cli-flags.js'), 'utf8');
  for (const cmd of KNOWN_COMMANDS) {
    assert.ok(cli.includes(`'${cmd}'`) || cli.includes(`"${cmd}"`) ||
      fs.readFileSync(path.join(__dirname, '..', 'bin', 'signerd.js'), 'utf8')
        .includes(`command === '${cmd}'`),
      `the guard's own list names a command the CLI does not dispatch: ${cmd}`);
  }
});
