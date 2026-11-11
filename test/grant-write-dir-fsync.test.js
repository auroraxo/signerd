'use strict';

// THE GRANT FILE'S ATOMIC WRITE IS ATOMIC BUT NOT DURABLE.
//
// WHY (measured 2026-11-11 on the tree that shipped v0.2.15, commit db87c26):
//
// `writeAtomic` (src/grantadd.js) is what `grant-add --append` and
// `grant-remove` use to rewrite the grant file: temp file in the same
// directory, fsync of the temp file, rename onto the target. The PARENT
// DIRECTORY is never fsynced.
//
//   openat(... ".grants.json.tmp-<pid>-...", O_WRONLY|O_CREAT|O_EXCL)
//   fsync(<temp>)          = 0     <- the TEMP FILE
//   rename(tmp, grants.json) = 0
//   (no directory fsync)
//
// A rename is a directory operation: until the directory entry is durable,
// a crash can lose it. The temp file's own fsync makes the DATA durable,
// not the NAME.
//
// The consequence at this path is a revocation that silently un-happens:
// `signerd grant-remove` runs the loader, writes, and tells the operator
// the scope is gone (exit 0, "removal takes effect on the daemon's NEXT
// request"). A crash before the directory entry is durable restores the
// OLD document — with the revoked grant still in it. The daemon re-reads
// that file on every request, so the scope the operator believed revoked is
// live again, with nothing left to say so. The same applies to
// `grant-add --append`: the new scope silently vanishes.
//
// This is the same defect the repo already closed one layer further out on
// 2026-11-08 (b3c78aa, the `--out` delivery: fsync temp -> rename -> fsync
// dir). The house convention there listed FOUR sibling sites that already
// fsync the parent directory after their rename — src/ledger.js:756,
// src/journalseal.js:237, src/journalseal-ops.js:297, src/migrate.js:145
// (a fifth, src/out-preflight.js:257, landed with that fix). The grant file
// is the FIFTH site that skipped it — and it is the file that decides which
// scopes are allowed to spend signatures.
//
// THE CONTRACT THIS FILE PINS:
//
//   D1 the grant file's atomic write fsyncs the PARENT DIRECTORY after the
//      rename, so the write the CLI reported is the write that survives;
//   D2 the directory fsync FOLLOWS the rename (before it makes the OLD
//      name durable and leaves the new entry exposed);
//   D3 the temp file's own fsync is still there (D1 must not replace it);
//   D4 a directory that cannot be fsynced must NOT fail the write — the
//      document is on disk and the house convention is best-effort
//      (src/ledger.js, src/journalseal.js). A checker that refuses a
//      working revocation is worse than the defect it fixes.
//
// The measurement patches fs.fsyncSync AND fs.renameSync on the shared
// `node:fs` module object (src/grantadd.js looks the method up on the
// module at call time) and resolves each fd through /proc/self/fd to tell a
// file fd from a DIRECTORY fd. Ordering is asserted, not just counts.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { writeGrantFile, extendGrantFile, removeGrantFromFile } = require('../src/grantadd');

function uniqueDir(tag) {
  const nanos = Date.now() * 1000 + Math.floor(Math.random() * 1000);
  return fs.mkdtempSync(path.join(os.tmpdir(), `signerd-${tag}-${nanos}-`));
}

// A tx grant in the loader's own shape (src/grantfile.js validateGrant).
function grant(name, overrides) {
  return {
    signer: '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi',
    destination: '8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR',
    maxLamports: '100000',
    windowMaxLamports: '1000000',
    windowSeconds: '60',
    expiresAt: '2099-01-01T00:00:00Z',
    ...overrides,
  };
}

/** An existing, loadable one-grant file. */
function seedGrantsFile(dir) {
  const file = path.join(dir, 'grants.json');
  writeGrantFile({ file, name: 'keep', grant: grant('keep') });
  return file;
}

/**
 * Watch fsync AND rename; each fsync records whether the fd is a DIRECTORY.
 * For call sites that only CREATE a file (no rename) pass `expectRename:false`.
 */
function watch(fn) {
  const originalFsync = fs.fsyncSync;
  const originalRename = fs.renameSync;
  const events = [];
  fs.fsyncSync = function watched(fd) {
    let isDir = false;
    let target = null;
    try {
      target = fs.readlinkSync(`/proc/self/fd/${fd}`);
      isDir = fs.statSync(`/proc/self/fd/${fd}`).isDirectory();
    } catch { /* /proc may be absent; checks fall back to weaker forms */ }
    events.push({ kind: 'fsync', isDir, target });
    return originalFsync.call(fs, fd);
  };
  fs.renameSync = function watched(from, to) {
    events.push({ kind: 'rename', from, to });
    return originalRename.call(fs, from, to);
  };
  try {
    return { events, result: fn() };
  } finally {
    fs.fsyncSync = originalFsync;
    fs.renameSync = originalRename;
  }
}

function assertDirFsyncAfterRename(events, dir, label) {
  const fsyncs = events.filter((e) => e.kind === 'fsync');
  const dirFsyncs = fsyncs.filter((e) => e.isDir);

  // D1: present at all.
  assert.ok(
    dirFsyncs.length >= 1,
    `${label}: the grant write must fsync the parent directory, but no directory fsync was seen (events: ${JSON.stringify(events)})`);

  // ...on the RIGHT directory.
  const wanted = fs.realpathSync(dir);
  const rightDir = dirFsyncs.find((e) => {
    try {
      return fs.realpathSync(e.target) === wanted;
    } catch {
      return false;
    }
  });
  assert.ok(
    rightDir,
    `${label}: the directory fsync must be on ${wanted}, observed: ${JSON.stringify(dirFsyncs.map((e) => e.target))}`);

  // D2: AFTER the rename.
  const renameIdx = events.findIndex((e) => e.kind === 'rename');
  assert.ok(renameIdx >= 0, `${label}: the grant write must rename`);
  const dirFsyncIdx = events.findIndex((e) => e.kind === 'fsync' && e.isDir);
  assert.ok(
    dirFsyncIdx > renameIdx,
    `${label}: the directory fsync must FOLLOW the rename (order: ${events.map((e) => e.kind + (e.isDir ? '(dir)' : '')).join(' -> ')})`);

  // D3: temp file fsync still there.
  const fileFsyncs = fsyncs.filter((e) => !e.isDir);
  assert.ok(
    fileFsyncs.length >= 1,
    `${label}: the temp file itself must still be fsynced (events: ${JSON.stringify(events)})`);
}

test('D1/D2/D3: grant-remove fsyncs the PARENT DIRECTORY after the rename', () => {
  const dir = uniqueDir('grant-remove-dir');
  const file = seedGrantsFile(dir);
  extendGrantFile({ file, name: 'extra', grant: grant('extra') });

  const { events, result } = watch(() => removeGrantFromFile({ file, name: 'extra' }));
  assert.equal(result.removed, 'extra', 'the revocation itself must succeed');

  assertDirFsyncAfterRename(events, dir, 'grant-remove');
});

test('D1/D2/D3: grant-add --append (extendGrantFile) fsyncs the parent directory after the rename', () => {
  const dir = uniqueDir('grant-extend-dir');
  const file = seedGrantsFile(dir);

  const { events, result } = watch(() =>
    extendGrantFile({ file, name: 'extra', grant: grant('extra') }));
  assert.equal(result.appended, true, 'the append itself must succeed');

  assertDirFsyncAfterRename(events, dir, 'grant-add --append');
});

test('D1: grant-add (create path) fsyncs the directory the new name lands in', () => {
  const dir = uniqueDir('grant-create-dir');
  const file = path.join(dir, 'grants.json');

  const { events, result } = watch(() =>
    writeGrantFile({ file, name: 'only', grant: grant('only') }));
  assert.equal(result.grant, 'only', 'the create itself must succeed');

  // The create path has no rename; what must hold is that the NEW NAME is
  // durable when the CLI returns.
  const dirFsyncs = events.filter((e) => e.kind === 'fsync' && e.isDir);
  assert.ok(
    dirFsyncs.length >= 1,
    `the grant file creation must fsync its directory, but none was seen (events: ${JSON.stringify(events)})`);
  const wanted = fs.realpathSync(dir);
  assert.ok(
    dirFsyncs.some((e) => { try { return fs.realpathSync(e.target) === wanted; } catch { return false; } }),
    `the directory fsync must be on ${wanted}, observed: ${JSON.stringify(dirFsyncs.map((e) => e.target))}`);
});

test('D4: a directory that cannot be fsynced does NOT fail the revocation', () => {
  const dir = uniqueDir('grant-dir-fsync-guard');
  const file = seedGrantsFile(dir);
  extendGrantFile({ file, name: 'extra', grant: grant('extra') });

  const original = fs.fsyncSync;
  fs.fsyncSync = function watched(fd) {
    let isDir = false;
    try {
      isDir = fs.statSync(`/proc/self/fd/${fd}`).isDirectory();
    } catch { /* no /proc */ }
    if (isDir) {
      const err = new Error('EINVAL');
      err.code = 'EINVAL';
      throw err;
    }
    return original.call(fs, fd);
  };
  let result;
  try {
    result = removeGrantFromFile({ file, name: 'extra' });
  } finally {
    fs.fsyncSync = original;
  }

  assert.equal(result.removed, 'extra',
    'a directory fsync failure must not fail a write that already landed');
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(Object.keys(doc.grants), ['keep'],
    'the revocation must still be in effect on disk');
});

test('G1: the written document is byte-correct and loadable by the product loader', () => {
  const dir = uniqueDir('grant-write-guard');
  const file = seedGrantsFile(dir);
  extendGrantFile({ file, name: 'second', grant: grant('second') });
  removeGrantFromFile({ file, name: 'second' });
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(doc.version, 1);
  assert.deepEqual(Object.keys(doc.grants), ['keep'], 'only the surviving grant remains');
});
