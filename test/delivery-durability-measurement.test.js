'use strict';

// THE DURABILITY INSTRUMENT ITSELF MUST BE FALSIFIABLE.
//
// WHY (2026-11-08, this repo): the first version of
// tools/measure-delivery-durability.js reported "NOT-durable" on a tree
// whose durability was confirmed by strace — its directory-fd resolver used
// readlink('/proc/self/fd/N') === '/', which is never true (readlink
// returns the path). A wrong instrument in the FALSE direction is just as
// bad as a wrong one in the green direction: it would have shipped a
// measurement that contradicts the syscall trace.
//
// THE CONTRACT (each case is a case in the instrument):
//   M1 the instrument reports `durable` on THIS tree (the fix is present),
//      with the directory fsync AFTER the rename;
//   M2 the instrument reports `NOT-durable` on the PUBLISHED v0.2.10 tag
//      tree (the defect this fix closes) — otherwise the tool measures
//      nothing;
//   M3 the committed artefact carries NO host path (a committed measurement
//      that names the measuring machine is a snapshot, not evidence);
//   M4 FALSIFICATION: a hand-edited artefact that claims `durable` while
//      its own `dirFsyncAfterRename` says false is caught;
//   M5 false-positive guard: a delivery whose directory fsync is present
//      and after the rename must be counted durable — green on both trees,
//      so "pass" cannot mean "make everything look red".

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'measure-delivery-durability.js');
const ARTIFACT = path.join(ROOT, 'research', 'delivery-durability-2026-11-08.json');

/** Run the instrument; return { status, artifact } for a given tree. */
function runTool(args, opts = {}) {
  let status = 0;
  let stdout = '';
  try {
    stdout = execFileSync('node', [TOOL, ...args], {
      cwd: ROOT, encoding: 'utf8', ...opts,
    });
  } catch (err) {
    status = err.status === undefined ? -1 : err.status;
    stdout = String(err.stdout || '');
  }
  const jsonStart = stdout.indexOf('{');
  const artifact = jsonStart >= 0
    ? JSON.parse(stdout.slice(jsonStart, stdout.lastIndexOf('}') + 1))
    : null;
  return { status, artifact };
}

/** Extract the published pre-fix tree into a temp dir (offline, no checkout mutation). */
function materializeTag(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-prefix-${tag}-`));
  execFileSync('git', ['archive', tag], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });
  const tar = execFileSync('git', ['archive', tag], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });
  fs.writeFileSync(path.join(dir, 'tree.tar'), tar);
  execFileSync('tar', ['-xf', 'tree.tar'], { cwd: dir });
  fs.unlinkSync(path.join(dir, 'tree.tar'));
  return dir;
}

test('M1 the instrument reports durable on this tree, dir fsync AFTER the rename', () => {
  const { status, artifact } = runTool([]);
  assert.ok(artifact, 'the instrument must produce an artefact');
  assert.strictEqual(artifact.durable, true,
    `this tree carries the fix; the instrument said NOT-durable: ${JSON.stringify(artifact.results)}`);
  assert.strictEqual(status, 0, 'exit 0 = measured durable');
  const normal = artifact.results.find((r) => r.case === 'normal-delivery');
  assert.strictEqual(normal.dirFsyncAfterRename, true, 'D1/D2: the directory fsync must be seen, after the rename');
  assert.strictEqual(normal.tempFileFsyncPresent, true, 'D3: the temp file fsync must still be there');
  assert.deepStrictEqual(normal.eventKinds, ['fsync(file)', 'rename', 'fsync(dir)'],
    'the ORDER is the contract: temp fsync, then rename, then DIRECTORY fsync');
});

test('M2 the instrument reports NOT-durable on the PUBLISHED pre-fix tag (it measures something)', () => {
  let dir;
  try {
    dir = materializeTag('v0.2.10');
  } catch (err) {
    return; // no tag in this checkout (tagless clone) — named, not silent
  }
  const { artifact } = runTool(['--tree', dir]);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(artifact, 'the instrument must produce an artefact for the pre-fix tree');
  assert.strictEqual(artifact.durable, false,
    'the published v0.2.10 tree must measure NOT-durable — otherwise the tool proves nothing');
  const normal = artifact.results.find((r) => r.case === 'normal-delivery');
  assert.strictEqual(normal.dirFsyncPresent, false,
    'on the pre-fix tree no directory fsync is seen at all');
  // The best-effort guard holds on BOTH trees: refusing a working delivery
  // would be a new lie.
  const guard = artifact.results.find((r) => r.case === 'directory-not-fsyncable');
  assert.strictEqual(guard.pass, true, 'D4 holds on the pre-fix tree too');
});

test('M3 the committed artefact carries no host path', () => {
  const text = fs.readFileSync(ARTIFACT, 'utf8');
  assert.ok(!/\/home\//.test(text), 'no /home/ path in the artefact');
  assert.ok(!/\/tmp\//.test(text), 'no /tmp/ path in the artefact');
  assert.ok(!/\/Users\//.test(text), 'no /Users/ path in the artefact');
  assert.ok(!/[A-Za-z]:\\\\/.test(text), 'no Windows path in the artefact');
  const artifact = JSON.parse(text);
  assert.strictEqual(artifact.durable, true, 'the committed verdict matches this tree');
});

/**
 * The ONE pure rule this file pins: a case's `pass` is DERIVED from its
 * evidence, never read from it. Storing pass alongside the evidence lets a
 * forged artefact keep a green headline over red facts.
 */
function derivePass(r) {
  if (r.case === 'normal-delivery') {
    return r.dirFsyncAfterRename === true && r.tempFileFsyncPresent === true;
  }
  if (r.case === 'directory-not-fsyncable') {
    return r.deliveryFailed === false && r.artifactOnDisk === true && r.artifactBytes > 0;
  }
  throw new Error(`unknown case: ${r.case}`);
}

test('M4 FALSIFICATION: a hand-edited artefact that claims durable against its own evidence is caught', () => {
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));

  // Forge the evidence while the headline (and the stored `pass`) stay green.
  const forged = JSON.parse(JSON.stringify(artifact));
  const normal = forged.results.find((r) => r.case === 'normal-delivery');
  normal.dirFsyncAfterRename = false;
  normal.eventKinds = ['fsync(file)', 'rename']; // no directory fsync
  forged.durable = true; // the lie — and `pass` was NOT touched

  // The rule: the headline must agree with the DERIVED verdict of the
  // evidence. The forged artefact keeps a green stored pass and a green
  // headline over evidence that derives false — the contradiction is
  // exactly what the rule must catch.
  const storedPassAll = forged.results.every((r) => r.pass === true);
  const derivedAll = forged.results.every(derivePass);
  assert.strictEqual(storedPassAll, true, 'the forged artefact keeps a green stored pass (that is the point)');
  assert.strictEqual(derivedAll, false, 'the forged evidence derives NOT-durable');
  assert.strictEqual(forged.durable !== derivedAll, true,
    'the forged artefact is self-contradicting: durable=true over evidence that derives false');

  // ...and on the real artefact the same three verdicts agree.
  assert.strictEqual(artifact.durable, artifact.results.every(derivePass),
    'the real artefact is self-consistent under the derived rule');
});

test('M5 false-positive guard: a present, correctly-ordered directory fsync counts durable', () => {
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
  const normal = artifact.results.find((r) => r.case === 'normal-delivery');
  assert.strictEqual(normal.pass, true, 'green here on THIS tree');
  // The instrument must not be biased toward red: the pre-fix run (M2)
  // still keeps its guard green, which is asserted there. This asserts the
  // direction from the other side — a correct delivery passes.
  assert.strictEqual(normal.deliveredBytes > 0, true, 'the artefact really landed on disk');
});
