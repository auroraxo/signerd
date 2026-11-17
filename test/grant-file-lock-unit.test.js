'use strict';

// THE UNIT PINS for the grant-file lock's OWN bookkeeping (2026-11-17).
//
// The CLI ladder (test/grant-file-lock.test.js) measures the BEHAVIOUR a
// stranger sees. These pins measure the module's internals, because two
// contracts cannot be observed from the outside:
//
//   U1 the release removes ONLY the claim this process owns. A release
//      that ignores the token unlinks the path UNCONDITIONALLY - it would
//      delete a STRANGER's live claim. The mutation ladder rung
//      m_no_token_check (the token comparison removed) is pinned RED here.
//      The takeover path makes the window real: when a dead owner's lock
//      is taken over, the OLD owner's process can still be alive enough to
//      run its release - and then it would delete the NEW owner's lock.
//   U2 a provably dead owner's lock is taken over (the file is usable
//      again) - green on the fixed tree, the behaviour the takeover exists
//      for.
//   U3 the wait budget is finite and the env override is a diagnostics
//      hook: a non-integer value falls back to the default, and 0 means
//      "refuse now". The mutation ladder rung m_no_wait (the fallback
//      forced to 0) is pinned RED here.
//
// The pins use the module's own API - the same surface the product uses -
// so a rewrite of the internals that keeps the contract stays GREEN.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { claimGrantFileLock, withGrantFileLock, waitBudgetMs } =
  require(path.join(__dirname, '..', 'src', 'grant-file-lock.js'));

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lockunit-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function lockPath(grants) {
  return `${grants}.lock`;
}

test('U1 the release removes only THIS process\'s own claim', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  fs.writeFileSync(grants, '{}\n', { mode: 0o600 });

  const release = claimGrantFileLock(grants);
  const mine = JSON.parse(fs.readFileSync(lockPath(grants), 'utf8'));
  assert.equal(typeof mine.token, 'string', 'the claim must carry a token');

  // A STRANGER takes the file: the lock body now carries a token this
  // process never issued (the takeover case: the dead owner's process is
  // still around long enough to run its release).
  const stranger = { pid: process.pid, token: 'a-token-this-process-never-issued', startedAt: Date.now() };
  fs.writeFileSync(lockPath(grants), JSON.stringify(stranger), { mode: 0o600 });

  release();

  // THE CONTRACT: the stranger's claim survives our release.
  assert.equal(fs.existsSync(lockPath(grants)), true,
    'a release must not delete a lock it no longer owns');
  const now = JSON.parse(fs.readFileSync(lockPath(grants), 'utf8'));
  assert.equal(now.token, stranger.token,
    'the surviving lock must be the stranger\'s claim, untouched');
});

test('U1b our own claim IS removed when nobody else took the file', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  fs.writeFileSync(grants, '{}\n', { mode: 0o600 });

  withGrantFileLock(grants, () => {
    assert.equal(fs.existsSync(lockPath(grants)), true, 'the lock is held inside the body');
  });
  assert.equal(fs.existsSync(lockPath(grants)), false,
    'the lock must be released when the body returns');
});

test('U2 a provably dead owner\'s lock is taken over', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  fs.writeFileSync(grants, '{}\n', { mode: 0o600 });

  // A pid that cannot be alive: the claim path must judge it dead.
  const dead = { pid: 0x7fffffff, token: 'dead-owner', startedAt: Date.now() - 60000 };
  fs.writeFileSync(lockPath(grants), JSON.stringify(dead), { mode: 0o600 });

  let held = false;
  withGrantFileLock(grants, () => {
    held = true;
    const now = JSON.parse(fs.readFileSync(lockPath(grants), 'utf8'));
    assert.notEqual(now.token, 'dead-owner', 'the dead owner\'s claim must be replaced');
  });
  assert.equal(held, true, 'the body must run after the takeover');
  assert.equal(fs.existsSync(lockPath(grants)), false, 'the taken-over lock is released again');
});

test('U3 the wait budget is finite; a garbage override falls back to it', () => {
  const saved = process.env.SIGNERD_GRANT_LOCK_WAIT_MS;
  try {
    delete process.env.SIGNERD_GRANT_LOCK_WAIT_MS;
    const def = waitBudgetMs();
    assert.ok(Number.isFinite(def) && def > 0,
      `the default budget must be a finite positive number, got ${def}`);

    process.env.SIGNERD_GRANT_LOCK_WAIT_MS = 'not-a-number';
    assert.equal(waitBudgetMs(), def,
      'a non-integer override must fall back to the default budget');

    process.env.SIGNERD_GRANT_LOCK_WAIT_MS = '-1';
    assert.equal(waitBudgetMs(), def,
      'a negative override must fall back to the default budget');

    process.env.SIGNERD_GRANT_LOCK_WAIT_MS = '0';
    assert.equal(waitBudgetMs(), 0, 'an explicit 0 means "refuse now"');
  } finally {
    if (saved === undefined) delete process.env.SIGNERD_GRANT_LOCK_WAIT_MS;
    else process.env.SIGNERD_GRANT_LOCK_WAIT_MS = saved;
  }
});

test('U3b a live holder is refused when the budget is 0', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  fs.writeFileSync(grants, '{}\n', { mode: 0o600 });
  fs.writeFileSync(lockPath(grants),
    JSON.stringify({ pid: process.pid, token: 'live-holder', startedAt: Date.now() }),
    { mode: 0o600 });

  assert.throws(() => claimGrantFileLock(grants, { waitMs: 0 }),
    (err) => err && err.code === 'grant_file_locked',
    'a live holder with a zero budget must be refused with the lock code');
  assert.equal(fs.existsSync(lockPath(grants)), true,
    'the refused claimant must leave the holder\'s lock alone');
});
