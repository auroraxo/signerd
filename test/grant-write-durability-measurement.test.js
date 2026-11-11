'use strict';

// The MEASUREMENT PIN for the grant-file write durability (2026-11-11).
//
// The artifact research/grant-write-durability-2026-11-11.json is what the
// card cites, so it must be a measurement and not a story:
//
//   T1 the artifact exists, names its tool and the PRE-FIX BASELINE it
//      measured (commit 2b85a49, extracted with git archive — the code that
//      shipped, never this working tree);
//   T2 the baseline showed the defect on every write path (or the fix is
//      unmeasurable) and this tree shows none: verdict `fixed`;
//   T3 every write path has BOTH the temp-file fsync and the directory
//      fsync AFTER the rename on the fixed tree — the fix must not swap one
//      durability for the other, and the revocation must still be in
//      effect on disk;
//   T4 the artifact carries no host path (a committed artifact that names
//      the measuring host is a snapshot, not a measurement).
//
// T2 and T4 are falsifiable on purpose: hand-edit a defect count in the
// artifact, or add a host path, and this test must go RED.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT = path.join(ROOT, 'research', 'grant-write-durability-2026-11-11.json');

function readArtifact() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('T1 the artifact exists and names the pre-fix baseline it measured', () => {
  const r = readArtifact();
  assert.equal(r.tool, 'tools/measure-grant-write-durability.js');
  assert.equal(r.prefixSha, '2b85a49',
    'the baseline must be the pre-fix commit (2b85a49), extracted with git archive');
  assert.equal(r.generatedAt, '2026-11-11');
  assert.ok(r.measuredAt.startsWith('2026-11-11'), 'measured on 2026-11-11');
});

test('T2 the pre-fix tree showed the defect on every write path; this tree shows none', () => {
  const r = readArtifact();
  assert.ok(r.prefixDefects.length >= 3,
    'a baseline that shows no defect makes the fix unmeasurable');
  // The measured defect, path by path: no directory fsync on any write.
  assert.ok(r.prefixDefects.some((d) => d.startsWith('create:')));
  assert.ok(r.prefixDefects.some((d) => d.startsWith('append:')));
  assert.ok(r.prefixDefects.some((d) => d.startsWith('remove:')));
  assert.equal(r.fixedDefects.length, 0, 'this tree must show no defect');
  assert.equal(r.verdict, 'fixed');
  // The create path had no fsync of ANY kind before the fix (a plain
  // truncate-write); the other two fsynced the temp file but not the name.
  assert.equal(r.prefix.create.tempFileFsyncCount, 0);
  assert.equal(r.prefix.append.tempFileFsyncCount, 1);
  assert.equal(r.prefix.remove.tempFileFsyncCount, 1);
});

test('T3 every fixed write path has both fsyncs, in the right order, and the revocation landed', () => {
  const r = readArtifact();
  for (const key of ['create', 'append', 'remove']) {
    const f = r.fixed[key];
    assert.equal(f.dirFsyncCount, 1, `${key}: exactly one directory fsync`);
    assert.equal(f.tempFileFsyncCount, 1, `${key}: exactly one temp-file fsync`);
    assert.ok(f.renameSeen, `${key}: the write must be a rename-delivery`);
    assert.equal(f.dirFsyncAfterRename, true,
      `${key}: the directory fsync must FOLLOW the rename (order: ${f.order.join(' -> ')})`);
    assert.deepEqual(f.order, ['fsync', 'rename', 'fsync(dir)'],
      `${key}: expected fsync -> rename -> fsync(dir), got ${f.order.join(' -> ')}`);
  }
  // The removed grant is gone on disk: the durability was added WITHOUT
  // changing what the write does.
  assert.equal(r.fixed.removalApplied, 'one');
});

test('T4 the artifact carries no host path (a snapshot is not a measurement)', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  for (const needle of ['/home/', '/Users/', '/tmp/', 'C:\\']) {
    assert.ok(!raw.includes(needle), `the artifact must not contain ${needle}`);
  }
});
