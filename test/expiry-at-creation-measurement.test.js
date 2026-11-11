'use strict';

// THE PIN FOR THE EXPIRY-AT-CREATION MEASUREMENT (2026-11-11).
//
// WHAT is pinned: the artifact research/expiry-at-creation-2026-11-11.json
// must describe the measurement it claims to — and the MEASUREMENT TOOL
// must still fail when the defect comes back. A committed artifact that
// no tool can reproduce is a belief, not evidence; a tool that always
// exits 0 is a rubber stamp.
//
//   M1 the artifact exists and names its baseline tag, tool and probe clock;
//   M2 the artifact shows the DEFECT on the baseline (the published tree
//      accepted a past expiry and wrote a scope the runtime refuses) and
//      the CONTRACT HOLDING on the fixed tree (nothing dead is writable);
//   M3 the guards are visible: a future expiry was writable on BOTH trees,
//      and the shape rule kept its own reason (grant_field_invalid) —
//      the fix must not have over-tightened;
//   M4 FALSIFICATION: the tool must FAIL (non-zero) when the fixed tree
//      behaves like the baseline. The tool is run against a scratch copy of
//      the baseline with the fix REMOVED — i.e. against a tree that still
//      writes dead scopes — and must report contract-violated, not
//      contract-holds. This is the direction that matters: a measurement
//      tool that cannot fail is not a measurement.
//   M5 no host paths in the artifact (the house rule).
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT = path.join(ROOT, 'research', 'expiry-at-creation-2026-11-11.json');
const TOOL = path.join(ROOT, 'tools', 'measure-expiry-at-creation.js');

function artifact() {
  assert.ok(fs.existsSync(ARTIFACT), `${ARTIFACT} must exist — the measurement is the evidence`);
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('M1 the artifact names its tool, its baseline tag and its probe clock', () => {
  const a = artifact();
  assert.strictEqual(a.tool, 'measure-expiry-at-creation');
  assert.strictEqual(a.baseline.tag, 'v0.2.17');
  assert.match(a.now, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/,
    'the probe clock must be pinned so the past/future split cannot drift');
});

test('M2 the baseline shows the defect, the fixed tree holds the contract', () => {
  const a = artifact();
  assert.strictEqual(a.verdict, 'contract-holds');
  const defects = a.cases.filter((c) => c.expect === 'defect');
  assert.ok(defects.length >= 3, 'the measurement must cover at least three defect faces');
  for (const c of defects) {
    assert.strictEqual(c.baseline.createExit, 0,
      `${c.value}: the baseline must have ACCEPTED the dead scope (create exit 0)`);
    assert.strictEqual(c.baseline.createWrote, true,
      `${c.value}: the baseline must have WRITTEN the dead scope`);
    assert.strictEqual(c.baseline.runtimeAllowed, false,
      `${c.value}: the runtime must refuse the dead scope`);
    assert.strictEqual(c.baseline.runtimeRefused, 'expired',
      `${c.value}: the runtime refusal must be named`);
    assert.strictEqual(c.fixed.createExit, 1,
      `${c.value}: the fixed tree must refuse the creation`);
    assert.strictEqual(c.fixed.createWrote, false,
      `${c.value}: the fixed tree must write nothing`);
    assert.strictEqual(c.fixed.createCode, 'grant_expired_at_creation');
    assert.strictEqual(c.fixed.library.txArgsAccepted, false,
      `${c.value}: the library face must refuse it too`);
  }
});

test('M3 the guards are visible on both trees (no over-tightening)', () => {
  const a = artifact();
  const future = a.cases.filter((c) => c.expect === 'guard' && c.value !== '2030-02-31T00:00:00Z');
  assert.ok(future.length >= 2, 'the measurement must keep the future-expiry guards visible');
  for (const c of future) {
    assert.strictEqual(c.baseline.createExit, 0, `${c.value}: the baseline must accept it`);
    assert.strictEqual(c.fixed.createExit, 0, `${c.value}: the fixed tree must still accept it`);
    assert.strictEqual(c.fixed.createWrote, true);
    assert.strictEqual(c.fixed.runtimeAllowed, true, `${c.value}: the runtime must still sign it`);
  }
  // The shape rule keeps its OWN reason on both trees.
  const shape = a.cases.find((c) => c.value === '2030-02-31T00:00:00Z');
  assert.ok(shape, 'the impossible-date case must stay in the table');
  assert.strictEqual(shape.baseline.createCode, 'grant_field_invalid');
  assert.strictEqual(shape.fixed.createCode, 'grant_field_invalid');
});

test('M4 FALSIFICATION: the tool FAILS on a tree that still writes dead scopes', () => {
  // A local CLONE (the tags come with it, so the tool's own baseline
  // extraction works inside it) with the fix files reverted to the
  // published v0.2.17 versions. The tool must then report
  // contract-violated and exit non-zero — the direction in which a
  // measurement can actually fail. A treeless `git archive` scratch is
  // NOT enough: the tool reads its baseline from git objects, and a
  // crash is not the verdict we are pinning.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-exac-falsify-'));
  const clone = spawnSync('git', ['clone', '--quiet', ROOT, dir],
    { encoding: 'utf8', timeout: 120000 });
  assert.strictEqual(clone.status, 0, `git clone failed: ${clone.stderr}`);
  const revert = spawnSync('git', ['checkout', 'v0.2.17', '--',
    'src/grantvalues.js', 'src/grantadd.js', 'bin/signerd.js'],
  { cwd: dir, encoding: 'utf8', timeout: 60000 });
  assert.strictEqual(revert.status, 0, `revert failed: ${revert.stderr}`);
  // The measurement tool and the uncommitted test stay from the FIXED tree.
  fs.copyFileSync(TOOL, path.join(dir, 'tools', 'measure-expiry-at-creation.js'));
  fs.cpSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'research'), { recursive: true });
  const res = spawnSync(process.execPath, [path.join(dir, 'tools', 'measure-expiry-at-creation.js')],
    { encoding: 'utf8', timeout: 600000, cwd: dir });
  assert.notStrictEqual(res.status, 0,
    `the tool must FAIL against the fix-reverted tree (it exited 0):\n${res.stdout}\n${res.stderr}`);
  assert.match(res.stdout, /contract-violated/,
    `the tool must report the violation, not crash:\n${res.stdout}\n${res.stderr}`);
});

test('M5 the artifact carries no host paths', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  assert.doesNotMatch(raw, /\/home\//, 'the artifact must not carry host paths');
  assert.doesNotMatch(raw, new RegExp(os.tmpdir().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    'the artifact must not carry scratch paths');
});
