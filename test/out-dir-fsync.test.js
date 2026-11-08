'use strict';

// THE DELIVERED SIGNATURE MUST BE DURABLE WHEN THE CLI SAYS IT IS.
//
// WHY (measured 2026-11-08 with strace on the tree that shipped v0.2.10,
// commit 6d157c5 — the tree whose README promises the atomic delivery):
//
//   `writeOutAtomic` (src/out-preflight.js) delivers the signed artifact as
//   temp file + fsync + rename. The strace of one delivery shows:
//
//     openat(... ".signed.json.signerd-<pid>-<hex>.tmp", O_WRONLY|O_CREAT|O_EXCL)
//     fsync(22)                       = 0        <- the TEMP FILE
//     rename(".../.signed.json....tmp", ".../signed.json") = 0
//
//   ONE fsync, on the temp file, and then the rename. The PARENT DIRECTORY
//   is never fsynced.
//
//   A rename is a directory operation: until the directory entry itself is
//   durable, the rename can be lost by a crash — the target reverts to its
//   previous content, or the new name is not there at all. The file's own
//   fsync does not cover that: it makes the DATA durable, not the NAME.
//
//   The consequence is the same one this repo has been closing for a week,
//   one layer further out: the CLI exited 0, so the operator believes the
//   paid-for signature is at `--out`. A crash before the directory entry is
//   durable leaves the PREVIOUS artifact there (or none). The spend happened
//   (the daemon signed, the budget was charged, the replay identity was
//   recorded), so the retry is refused `replay` — the signature is lost, and
//   the only honest report of it (exit 3 / exit 4) never happens because the
//   CLI said everything was fine.
//
//   This is not a house-style nit: FOUR sibling atomic-write sites in this
//   very tree already fsync the parent directory after their rename —
//   src/ledger.js:756, src/journalseal.js:237, src/journalseal-ops.js:297,
//   src/migrate.js:145. The `--out` delivery is the one that skipped it,
//   and it is the one that carries a paid-for artifact.
//
// THE CONTRACT THIS FILE PINS:
//
//   D1 the delivery fsyncs the PARENT DIRECTORY after the rename, so the
//      NAME of the delivered artifact is durable when the CLI returns;
//   D2 the fsync happens AFTER the rename, not before (fsyncing the
//      directory before the rename would make the OLD name durable);
//   D3 the temp file's own fsync is still there (D1 must not replace it);
//   D4 a directory that cannot be opened for fsync must NOT fail the
//      delivery — the artifact IS on disk, and the house convention is
//      best-effort (src/ledger.js, src/journalseal.js). A checker that
//      refuses a working delivery is worse than the defect it fixes.
//
// The measurement is done by watching the actual syscalls: `fs.fsyncSync` is
// patched on the shared `node:fs` module object (the delivery looks the
// method up on the module at call time, so the patch is seen), and the fd is
// resolved through /proc/self/fd to tell a file fd from a DIRECTORY fd.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { writeOutAtomic } = require('../src/out-preflight');

function uniqueDir(tag) {
  const nanos = Date.now() * 1000 + Math.floor(Math.random() * 1000);
  return fs.mkdtempSync(path.join(os.tmpdir(), `signerd-${tag}-${nanos}-`));
}

/**
 * Run `fn` with fs.fsyncSync AND fs.renameSync watched, recording ONE ordered
 * event log. Ordering is the part that matters: fsyncing the directory
 * before the rename makes the OLD name durable, which is the M2 mutation —
 * a test that only counts fsync calls cannot see it.
 *
 * Each fsync records whether the fd refers to a DIRECTORY (via /proc/self/fd)
 * and the path it refers to. The patch is on the shared `node:fs` module
 * object, which is what src/out-preflight.js holds.
 */
function watchDelivery(fn) {
  const originalFsync = fs.fsyncSync;
  const originalRename = fs.renameSync;
  const events = [];
  fs.fsyncSync = function watched(fd) {
    let isDir = false;
    let target = null;
    try {
      target = fs.readlinkSync(`/proc/self/fd/${fd}`);
      isDir = fs.statSync(`/proc/self/fd/${fd}`).isDirectory();
    } catch {
      // /proc is not always there; assertions then fall back to weaker but
      // still honest checks.
    }
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

test('D1/D2: the delivery fsyncs the PARENT DIRECTORY, AFTER the rename', () => {
  const dir = uniqueDir('out-dir-fsync');
  const target = path.join(dir, 'signed.json');
  // A pre-existing file: the rename REPLACES it, and the directory entry is
  // what the fsync has to make durable.
  fs.writeFileSync(target, Buffer.alloc(32, 0x41));

  const { events, result } = watchDelivery(() =>
    writeOutAtomic(target, Buffer.from(JSON.stringify({ ok: true, signed: 'C'.repeat(200) }))));

  assert.equal(result.ok, true, 'the delivery itself must succeed');

  const fsyncs = events.filter((e) => e.kind === 'fsync');
  const dirFsyncs = fsyncs.filter((e) => e.isDir);

  // D1: the directory fsync must be there at all.
  assert.ok(
    dirFsyncs.length >= 1,
    `the delivery must fsync the parent directory, but no directory fsync was seen (events: ${JSON.stringify(events)})`);

  // ...and on the RIGHT directory.
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
    `the directory fsync must be on ${wanted}, but the observed ones were ${JSON.stringify(dirFsyncs.map((e) => e.target))}`);

  // D2: it must come AFTER the rename. Fsyncing the directory first makes
  // the OLD name durable and leaves the new entry exactly as exposed as if
  // the fsync had never happened.
  const renameIdx = events.findIndex((e) => e.kind === 'rename');
  assert.ok(renameIdx >= 0, 'the delivery must rename');
  const dirFsyncIdx = events.findIndex((e) => e.kind === 'fsync' && e.isDir);
  assert.ok(
    dirFsyncIdx > renameIdx,
    `the directory fsync must FOLLOW the rename (events in order: ${events.map((e) => e.kind + (e.isDir ? '(dir)' : '')).join(' -> ')})`);
});

test('D3: the temp file itself is still fsynced (the data must be durable too)', () => {
  const dir = uniqueDir('out-file-fsync');
  const target = path.join(dir, 'signed.json');

  const { events } = watchDelivery(() =>
    writeOutAtomic(target, Buffer.from('payload-bytes')));

  const fileFsyncs = events.filter((e) => e.kind === 'fsync' && !e.isDir);
  assert.ok(
    fileFsyncs.length >= 1,
    `the temp file must still be fsynced, but only directory fsyncs were seen: ${JSON.stringify(events)}`);
});

test('D4: a directory that cannot be fsynced does NOT fail the delivery', () => {
  const dir = uniqueDir('out-dir-fsync-guard');
  const target = path.join(dir, 'signed.json');

  const original = fs.fsyncSync;
  fs.fsyncSync = function watched(fd) {
    // Fail the fsync on a DIRECTORY fd only — the temp file's fsync must
    // still work, so the failure is exactly the platform-dependent case the
    // house convention treats as best-effort.
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
    result = writeOutAtomic(target, Buffer.from('payload-bytes'));
  } finally {
    fs.fsyncSync = original;
  }

  assert.equal(result.ok, true, 'a directory fsync failure must not fail the delivery');
  assert.equal(fs.readFileSync(target, 'utf8'), 'payload-bytes');
});
