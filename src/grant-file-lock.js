'use strict';

// ONE WRITER AT A TIME on a grant file - the lock the JOURNAL already has
// (src/journal-lock.js), applied to every grant-file WRITE path:
// grant-add (create + --append), grant-remove and seal-grants.
//
// WHY THIS EXISTS (measured 2026-11-17, tools/measure-grant-file-lock.js,
// on the tree that shipped v0.2.34): every grant-file write path is a
// READ-JUDGE-WRITE sequence. The writer re-reads the file, judges it with
// the product's own loader, adds / removes / seals, and renames the result
// back. Two writers at once interleave those steps and BOTH report
// {"ok":true} - measured on the published tree: 8 concurrent
// `grant-add --append` runs against one file, all 8 exit 0, and the file
// ends with 6 of the 9 grants; a second run lost 2 of 3 writes. A write
// that reports ok and did not happen is exactly the class the journal
// already refuses: the daemon stops serving a journal whose lock it lost
// (src/daemon.js #ownsJournalLock, ledger_lock_lost).
//
// The revocation face is the security face. "Revocation is the operator's
// main control" (src/daemon.js #reloadGrants) and the loader re-reads the
// file on EVERY request, so a lost update that resurrects a removed grant
// is a silent revocation undo - and a lost update that drops a grant the
// operator still believes in is a silent revocation of somebody else's.
//
// WHAT WE TAKE: a link(2) claim, judge-the-owner takeover of a provably
// dead holder, token-checked release - the rules the journal lock keeps,
// copied rather than re-invented so the two locks cannot drift apart the
// way the journal lock and the offline tools once did.
//
// The read lease (F_SETLEASE, src/lease.js) stays what it is: it proves
// that nobody holds the file OPEN FOR WRITING at the instant of a read. It
// is NOT a mutual exclusion between this product's own writers, which
// never hold the file open while they write - they write a temp file and
// rename it.
//
// GRANULARITY: one lock per grant file (<file>.lock), so grants.json and
// grants2.json never contend; only writers of the SAME file do.
//
// WAIT BUDGET: a claim waits (bounded) for a live holder instead of
// refusing a writer that would land a millisecond later - parallel writers
// in one script serialize and ALL land. The budget is 5000 ms; a judge+write
// takes milliseconds, so a live writer clears well inside it. The refusal
// still happens - waiting is bounded, never infinite (a stuck holder must
// not hang the CLI). SIGNERD_GRANT_LOCK_WAIT_MS overrides the budget
// (integer >= 0; anything else falls back to the default) - a diagnostics
// hook, not a behaviour switch: production runs use the default.
//
// LIMITS, STATED NOT HIDDEN:
//   * the lock guards THIS product's writers against EACH OTHER. A hand
//     edit (a text editor) does not take the lock - the same limit the
//     journal lock carries, with the same compensating checks (mode /
//     owner / lease / seal at every read).
//   * link(2) exclusivity is not guaranteed on NFS and some network
//     filesystems, like every link-based lock; local disk is the
//     documented surface.
//   * the lock protects the READ-JUDGE-WRITE sequence, not a later read:
//     the daemon re-reads per request and may load a state written after
//     this write returned.

const fs = require('node:fs');
const crypto = require('node:crypto');

const TAKEOVER_ATTEMPTS = 6;
const DEFAULT_WAIT_MS = 5000;
const CLAIM_POLL_MS = 10;

function waitBudgetMs() {
  const raw = process.env.SIGNERD_GRANT_LOCK_WAIT_MS;
  if (raw === undefined) return DEFAULT_WAIT_MS;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : DEFAULT_WAIT_MS;
}

function fail(reason, detail, fix) {
  const err = new Error(detail === undefined ? reason : `${reason}: ${detail}`);
  err.code = reason;
  if (typeof fix === 'string') err.fix = fix;
  return err;
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but belongs to someone else.
    return err.code === 'EPERM';
  }
}

/**
 * Sleep synchronously (this module runs inside a synchronous CLI path).
 * Atomics.wait is the only sync sleep in Node; the buffer is a dummy.
 */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Claim `<grantFile>.lock` for this process.
 *
 * Returns a release function that unlinks the lock ONLY while this
 * process's token still occupies the path - a lock that was taken over
 * (because its owner died) is never removed by the old owner.
 */
function claimGrantFileLock(grantFile, { waitMs } = {}) {
  const lockFile = `${grantFile}.lock`;
  const token = crypto.randomBytes(16).toString('hex');
  const body = JSON.stringify({ pid: process.pid, token, startedAt: Date.now() });
  const budget = typeof waitMs === 'number' && Number.isInteger(waitMs) && waitMs >= 0
    ? waitMs : waitBudgetMs();
  const deadline = Date.now() + budget;

  for (let attempt = 0; ; attempt += 1) {
    // (1) Our claim: uniquely named, 0600, durable before it is visible.
    const claim = `${lockFile}.${token}`;
    let fd;
    try {
      fd = fs.openSync(claim, 'wx', 0o600);
      try {
        fs.writeSync(fd, body);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    } catch (err) {
      if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already closed */ } }
      throw claimFailed(err);
    }

    // (2) Atomic, non-overwriting placement.
    let linked = false;
    try {
      fs.linkSync(claim, lockFile);
      linked = true;
    } catch (err) {
      if (err.code !== 'EEXIST') {
        try { fs.unlinkSync(claim); } catch { /* best effort */ }
        throw claimFailed(err);
      }
    }
    // The inode survives at lockFile when linked; the claim name is a
    // scratch link in both cases.
    try { fs.unlinkSync(claim); } catch { /* best effort */ }
    if (linked) {
      return () => {
        try {
          const now = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
          if (now && now.token === token) fs.unlinkSync(lockFile);
        } catch { /* gone or unreadable: leave it to the next owner */ }
      };
    }

    // (3) Somebody holds it: read and judge.
    let raw;
    try {
      raw = fs.readFileSync(lockFile);
    } catch (err) {
      if (err.code === 'ENOENT') continue; // released while we looked
      throw fail('grant_file_locked', err.code, retryFix());
    }
    let owner = null;
    try { owner = JSON.parse(raw.toString('utf8')); } catch { owner = null; }
    if (owner === null || typeof owner !== 'object' ||
        !Number.isInteger(owner.pid) || owner.pid <= 0 ||
        typeof owner.token !== 'string' || owner.token.length === 0) {
      // Empty or malformed: refuse rather than guess - a half-written lock
      // may be a live claim (the journal lock's own rule). An empty file
      // left by a crash between create and write is taken over once it is
      // provably OLD; until then, refuse.
      if (Date.now() >= deadline) {
        throw fail('grant_file_locked', 'unreadable lock file', retryFix());
      }
      sleepSync(CLAIM_POLL_MS);
      continue;
    }
    if (pidAlive(owner.pid)) {
      // A LIVE holder: wait for it (bounded) rather than refuse a writer
      // that would land a millisecond later.
      if (Date.now() >= deadline) {
        throw fail('grant_file_locked', `pid ${owner.pid}`, retryFix(owner.pid));
      }
      sleepSync(CLAIM_POLL_MS);
      continue;
    }

    // (4) Provably dead owner: move the stale lock aside atomically, then
    //     PROVE we moved the same bytes we inspected.
    const quarantine = `${lockFile}.stale.${token}`;
    try {
      fs.renameSync(lockFile, quarantine);
    } catch (err) {
      if (err.code === 'ENOENT') continue; // already taken; re-claim
      throw fail('grant_file_locked', err.code, retryFix());
    }
    let moved = null;
    try { moved = fs.readFileSync(quarantine); } catch { moved = null; }
    if (moved === null || !moved.equals(raw)) {
      // A different file than we inspected: a concurrent process replaced
      // the lock in our read->rename window. Restore it without clobbering
      // anything and back off; the other process owns this file now.
      try { fs.linkSync(quarantine, lockFile); } catch { /* someone re-claimed */ }
      try { fs.unlinkSync(quarantine); } catch { /* best effort */ }
      continue;
    }
    try { fs.unlinkSync(quarantine); } catch { /* best effort */ }
    // The stale lock is gone: loop and try to claim it (the stale-takeover
    // path has its own attempt budget, so a pathological lock cannot spin).
    if (attempt >= TAKEOVER_ATTEMPTS) {
      throw fail('grant_file_locked', 'stale lock takeover contention', retryFix());
    }
  }
}

/**
 * A claim that could not even be ATTEMTED: the directory refuses writes.
 *
 * The lock is an implementation detail of writing, so a directory nobody
 * can write to reports the WRITE refusal the product already speaks
 * (grant_file_write_failed, measured 2026-11-08 for a read-only grant
 * directory and pinned by test/grant-refusal-voice.test.js C3) - not a new
 * code for the same EACCES. Any other claim failure keeps its own code.
 */
function claimFailed(err) {
  if (err && (err.code === 'EACCES' || err.code === 'EROFS')) {
    const e = fail('grant_file_write_failed',
      `${err.code}: the grant file's directory cannot be written`);
    e.detail = `${err.code}: the grant file's directory cannot be written`;
    return e;
  }
  return fail('grant_file_lock_failed', err && err.code,
    'check the grant file\'s directory is writable and has space: ls -ld $(dirname <grants>)');
}

/**
 * The repair a `grant_file_locked` refusal prints. It names a command this
 * CLI offers (rule F3) and says what the operator is actually waiting for:
 * the other writer of THIS file. A pid is not a host path.
 */
function retryFix(pid) {
  const who = Number.isInteger(pid) ? ` (pid ${pid})` : '';
  return 'another signerd command is writing this grant file' + who +
    ' - wait for it to finish, then run this command again; a live writer clears in milliseconds. ' +
    'Check the file once it is quiet: signerd status --grants <grants> --ledger <ledger>. ' +
    'If NO signerd command is running, a dead writer left its lock behind - remove it: rm <grants>.lock';
}

/**
 * Run `fn` holding the grant file's lock. The lock is released even when
 * `fn` throws - a refusal must not leave the file locked.
 */
function withGrantFileLock(grantFile, fn, options) {
  const release = claimGrantFileLock(grantFile, options);
  try {
    return fn();
  } finally {
    release();
  }
}

module.exports = { claimGrantFileLock, withGrantFileLock, TAKEOVER_ATTEMPTS, waitBudgetMs };
