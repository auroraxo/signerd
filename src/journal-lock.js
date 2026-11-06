'use strict';

// The journal lock, shared by the daemon and the OFFLINE tools
// (seal-journal, migrate).
//
// WHY THIS EXISTS (measured 2026-11-06): the tools each had their own
// minimal claim - link(2) once, and on EEXIST throw `ledger_locked: stop the
// daemon first`. The daemon itself (#acquireJournalLock) had a guarded
// takeover of a provably dead owner. The asymmetry bricked the offline
// recovery path: a daemon killed with SIGKILL leaves <journal>.lock behind
// (nobody runs the release path), and then `seal-journal` and `migrate`
// refused forever with a message telling the operator to stop a daemon that
// is not running - while `signerd run` on the same journal would have taken
// the stale lock over and started. The tools were the only processes that
// could NOT proceed, and they are exactly the processes an operator reaches
// for after a crash.
//
// THE RULE, copied from the daemon rather than re-invented:
//   * claim with link(2) - atomic, never overwrites;
//   * on EEXIST read and JUDGE the owner: unreadable/malformed -> refuse
//     (never guess: a half-written lock may be a live claim);
//   * pid alive -> refuse (`ledger_locked: pid N`);
//   * pid provably dead -> rename the stale lock aside, PROVE we moved the
//     bytes we judged, then retry the claim; if the bytes changed under us,
//     restore without clobbering and back off (the race guard the daemon's
//     tests pin in test/daemon.test.js, review #1).
//
// A live daemon's lock still refuses everything here (guard G1 in
// test/sealed-mode-surface.test.js) - this module takes over DEAD owners
// only.
//
// ONE implementation, not two: the daemon's #acquireJournalLock and the
// offline tools both call this, so the two can never drift apart again -
// which is exactly how the tools ended up unable to recover what the daemon
// recovered.

const fs = require('node:fs');
const crypto = require('node:crypto');

const LOCK_TAKEOVER_ATTEMPTS = 6;

function fail(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

/**
 * Claim `<journal>.lock` for this process.
 *
 * Options:
 *   token     the caller's own token (the daemon pins one per instance so it
 *             can ask "is this still MY lock?" later); a fresh one is minted
 *             otherwise;
 *   lockBody  the exact bytes to publish (the daemon publishes its own
 *             startedAt); minted otherwise.
 *
 * Returns a release function that removes the lock ONLY if this caller still
 * owns it.
 */
function claimJournalLock(file, { token, lockBody } = {}) {
  const lockFile = `${file}.lock`;
  const ownedToken = typeof token === 'string' && token.length > 0
    ? token : crypto.randomBytes(16).toString('hex');
  const body = typeof lockBody === 'string'
    ? lockBody
    : JSON.stringify({ pid: process.pid, token: ownedToken, startedAt: Date.now() });

  for (let attempt = 0; attempt < LOCK_TAKEOVER_ATTEMPTS; attempt += 1) {
    // (1) Our claim: uniquely named, 0600, durable before it is visible.
    const claim = `${lockFile}.${ownedToken}`;
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
      throw fail('ledger_lock_failed', err.code);
    }

    // (2) Atomic, non-overwriting placement.
    let linked = false;
    try {
      fs.linkSync(claim, lockFile);
      linked = true;
    } catch (err) {
      if (err.code !== 'EEXIST') {
        try { fs.unlinkSync(claim); } catch { /* best effort */ }
        throw fail('ledger_lock_failed', err.code);
      }
    }
    // The inode survives at lockFile when linked; the claim name is a
    // scratch link in both cases.
    try { fs.unlinkSync(claim); } catch { /* best effort */ }
    if (linked) {
      return () => {
        try {
          const now = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
          if (now && now.token === ownedToken) fs.unlinkSync(lockFile);
        } catch { /* gone or unreadable: leave it to the next owner */ }
      };
    }

    // (3) Somebody holds it: read and judge.
    let raw;
    try {
      raw = fs.readFileSync(lockFile);
    } catch (err) {
      if (err.code === 'ENOENT') continue; // released while we looked
      throw fail('ledger_locked', err.code);
    }
    let owner = null;
    try { owner = JSON.parse(raw.toString('utf8')); } catch { owner = null; }
    if (owner === null || typeof owner !== 'object' ||
        !Number.isInteger(owner.pid) || owner.pid <= 0 ||
        typeof owner.token !== 'string' || owner.token.length === 0) {
      // Empty or malformed: refuse rather than guess. A crash between create
      // and write leaves an empty file; reclaiming it blind could let two
      // writers pass the lock at once.
      throw fail('ledger_locked', 'unreadable lock file');
    }
    if (pidAlive(owner.pid)) throw fail('ledger_locked', `pid ${owner.pid}`);

    // (4) Provably dead owner: move the stale lock aside atomically, then
    //     prove we moved the same bytes we inspected.
    const quarantine = `${lockFile}.stale.${ownedToken}`;
    try {
      fs.renameSync(lockFile, quarantine);
    } catch (err) {
      if (err.code === 'ENOENT') continue; // already taken; re-claim
      throw fail('ledger_locked', err.code);
    }
    let moved = null;
    try { moved = fs.readFileSync(quarantine); } catch { moved = null; }
    if (moved === null || !moved.equals(raw)) {
      // A different file than we inspected: a concurrent process replaced the
      // lock in our read->rename window. Restore it without clobbering
      // anything and back off; the other process owns this journal now.
      try { fs.linkSync(quarantine, lockFile); } catch { /* someone re-claimed */ }
      try { fs.unlinkSync(quarantine); } catch { /* best effort */ }
      continue;
    }
    try { fs.unlinkSync(quarantine); } catch { /* best effort */ }
    // The stale lock is gone: loop and try to claim it.
  }
  throw fail('ledger_locked', 'lock contention');
}

/** True only while the given token still occupies the lock path. */
function ownsJournalLock(file, token) {
  let owner = null;
  try { owner = JSON.parse(fs.readFileSync(`${file}.lock`, 'utf8')); } catch { return false; }
  return owner !== null && typeof owner === 'object' && owner.token === token;
}

module.exports = { claimJournalLock, ownsJournalLock, pidAlive, LOCK_TAKEOVER_ATTEMPTS };
