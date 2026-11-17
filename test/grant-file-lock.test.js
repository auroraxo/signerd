'use strict';

// ONE WRITER AT A TIME ON THE GRANT FILE - the lost-update gate
// (measured 2026-11-17, tools/measure-grant-file-lock.js).
//
// THE DEFECT (on the tree that shipped v0.2.34): every grant-file write
// path is a read-judge-write sequence with no mutual exclusion, so two
// concurrent writers interleave and BOTH report {"ok":true} while one
// update is silently lost:
//
//   8 concurrent `grant-add --append` on ONE file -> all 8 exit 0,
//   file ends with 6..7 of the 9 grants (3 runs, measured)
//
// The revocation face is the security face: the loader re-reads the grant
// file on EVERY request (src/daemon.js #reloadGrants), so a lost update
// that resurrects a removed grant is a silent revocation undo, and a lost
// update that drops a grant is a silent revocation of somebody else's.
// The journal already refuses this class (ledger_lock_lost); the grant
// file did not.
//
// WHAT THIS FILE PINS (all via the CLI - the ladder must be runnable
// against a pre-fix checkout, so it imports NOTHING from the new module):
//
//   DEFECT PINS - RED on the pre-fix tree (6e33571, the code that shipped
//   v0.2.34), GREEN here:
//   D1 8 concurrent appends: all 8 report ok AND all 9 grants are present
//      (pre-fix: 6-7 of 9 on disk with 8 ok-outputs)
//   D3 a writer that cannot take the lock REFUSES - code once, a repair
//      naming a real CLI command, exit 1 (pre-fix: no lock exists, the
//      write proceeds and wins a race)
//   G1 stale lock lifecycle: a dead owner's lock is taken over, the write
//      lands, the lock is released (pre-fix: the planted lock file is
//      never touched - the product had no lock lifecycle at all)
//
//   GUARDS - green on BOTH trees:
//   D2 six concurrent CREATEs: ok-outputs == grants on disk, exactly one
//      ok (measured: this path never lost a write even pre-fix)
//   G2 a lock file next to the grant file does not change what the
//      loader/verdict surfaces report (status, verify-grants)
//   G3 the happy sequential surface is untouched: create/append/remove
//      still refuse exactly what they refused before (grant_exists,
//      grant_not_found, grant_file_exists)
//
// The house rules apply: measured numbers, guards green on both trees,
// the repair names a command the CLI offers, no host paths.

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

const SIGNER = '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi';
const DEST = '8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR';

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-grantlock-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function cliSync(args, env) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', timeout: 30000,
    env: env ? { ...process.env, ...env } : process.env,
  });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function addArgs(grants, name, { append = false } = {}) {
  const args = ['grant-add', '--grants', grants, '--name', name, '--signer', SIGNER,
    '--destination', DEST, '--max-lamports', '100000', '--window-max-lamports', '1000000',
    '--window-seconds', '60', '--expires', '2099-01-01T00:00:00Z'];
  if (append) args.splice(3, 0, '--append');
  return args;
}

function grantNames(grants) {
  return Object.keys(JSON.parse(fs.readFileSync(grants, 'utf8')).grants).sort();
}

/** Spawn `count` appends at once; resolve with all exit codes + outputs. */
function concurrentAppends(grants, names) {
  return Promise.all(names.map((name) => new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...addArgs(grants, name, { append: true })], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  })));
}

function okCount(results) {
  return results.filter((r) => r.code === 0 && /"ok":true/.test(r.stdout)).length;
}

test('D1 8 concurrent appends: every ok:true is on disk - no lost update', async () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  const created = cliSync(addArgs(grants, 'good'));
  assert.equal(created.status, 0, `create must work: ${created.stderr}`);

  const names = Array.from({ length: 8 }, (_, i) => `g${i + 1}`);
  const results = await concurrentAppends(grants, names);
  const ok = okCount(results);
  const present = grantNames(grants);

  // THE DEFECT: pre-fix all 8 report ok and the file ends with 6-7 of 9.
  assert.equal(ok, 8, `all 8 writers must report ok, got ${ok} (stderr: ${results.map((r) => r.stderr).join(' | ')})`);
  assert.equal(present.length, 9,
    `all 9 grants must be present, found ${present.length}: ${present.join(',')}`);
  for (const name of names) assert.ok(present.includes(name), `missing ${name}`);
  // The lock must not be left behind: a leaked lock bricks every later write.
  assert.equal(fs.existsSync(`${grants}.lock`), false, 'the lock file must be released');
});

test('D2 six concurrent CREATEs: the ok-outputs match what is on disk', async () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  const run = () => new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...addArgs(grants, 'first')], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.on('close', (code) => resolve({ code, stdout }));
  });
  const results = await Promise.all(Array.from({ length: 6 }, run));
  const ok = okCount(results);
  const present = grantNames(grants);
  // Measured 2026-11-17 (4 live runs, this gate): the CREATE path lost no
  // write even before the lock - every pre-fix run answered ok exactly once
  // and the file held exactly that grant, so creation never manufactured a
  // state the disk does not show. The gate stays: the contract must keep
  // holding under the lock (exactly one ok, the disk agrees, no leftover).
  assert.equal(ok, 1,
    `exactly one create must report ok, got ${ok}`);
  assert.ok(present.includes('first'), 'the surviving create must be intact');
  assert.equal(ok, present.length,
    `ok-outputs (${ok}) must equal grants on disk (${present.length})`);
  assert.equal(fs.existsSync(`${grants}.lock`), false, 'the lock file must be released');
});

test('D3 a writer that cannot take the lock refuses with one code and a repair', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');

  // A LIVE holder: this process's own pid (never dead while we wait).
  fs.writeFileSync(`${grants}.lock`,
    JSON.stringify({ pid: process.pid, token: 'held-by-the-test', startedAt: Date.now() }),
    { mode: 0o600 });

  // Budget 0: refuse instead of waiting - the assertion is about the
  // VOICE, not the wait.
  const res = cliSync(addArgs(grants, 'while-held', { append: true }),
    { SIGNERD_GRANT_LOCK_WAIT_MS: '0' });

  assert.equal(res.status, 1, `a held lock must be refused (got ${res.status}): ${res.stdout}`);
  assert.equal(/"ok":true/.test(res.stdout), false, 'nothing may be reported as written');
  // The code appears exactly ONCE on stderr (the house voice rule)...
  const codeLines = res.stderr.split('\n').filter((l) => l.startsWith('grant_file_locked'));
  assert.equal(codeLines.length, 1, `one code line expected, got: ${res.stderr}`);
  // ...with a repair on its own line...
  assert.match(res.stderr, /^\s*fix: /m, `a fix: line is required: ${res.stderr}`);
  // ...naming a command THIS CLI offers (rule F3).
  assert.match(res.stderr, /signerd (status|grant-add|grant-remove)/,
    `the repair must name a real command: ${res.stderr}`);
  // D4/F1: the repair must also be in the SHARED refusal map - the CLI's
  // own table (src/refusal-voice.js), not only on the error object. One
  // place maps a code to a repair; a code that is missing there is a
  // refusal that ships mute for every other caller.
  const { refusalFix } = require(path.join(ROOT, 'src', 'refusal-voice.js'));
  const shared = refusalFix('grant_file_locked');
  assert.ok(typeof shared === 'string' && shared.length > 0,
    'grant_file_locked must have a repair in the shared refusal map');
  assert.match(shared, /signerd (status|grant-add|grant-remove)/,
    `the shared repair must name a real command: ${shared}`);
  // D4: no host path in the refusal (rule 3).
  assert.equal(/\/home\/|\/Users\/|\/root\/|signerd-grantlock-/.test(res.stderr), false,
    `the refusal must not carry a host path: ${res.stderr}`);
  // The holder's lock is still OURS (the refused writer must not free it).
  const owner = JSON.parse(fs.readFileSync(`${grants}.lock`, 'utf8'));
  assert.equal(owner.token, 'held-by-the-test', 'a refused writer must not release the holder');
});

test('D3b grant-remove under a held lock refuses the same way (one code, one repair)', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');
  fs.writeFileSync(`${grants}.lock`,
    JSON.stringify({ pid: process.pid, token: 'held-by-the-test', startedAt: Date.now() }),
    { mode: 0o600 });
  const res = cliSync(['grant-remove', '--grants', grants, '--name', 'good'],
    { SIGNERD_GRANT_LOCK_WAIT_MS: '0' });
  assert.equal(res.status, 1, `a held lock must be refused: ${res.stdout}`);
  assert.ok(grantNames(grants).includes('good'), 'nothing may be removed');
  const codeLines = res.stderr.split('\n').filter((l) => l.startsWith('grant_file_locked'));
  assert.equal(codeLines.length, 1, `one code line expected: ${res.stderr}`);
  assert.match(res.stderr, /^\s*fix: /m, `a fix: line is required: ${res.stderr}`);
  const owner = JSON.parse(fs.readFileSync(`${grants}.lock`, 'utf8'));
  assert.equal(owner.token, 'held-by-the-test', 'a refused writer must not release the holder');
});

test('D3c seal-grants under a held lock refuses the same way (one code, one repair)', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'lock-test passphrase\n', { mode: 0o600 });
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');
  fs.writeFileSync(`${grants}.lock`,
    JSON.stringify({ pid: process.pid, token: 'held-by-the-test', startedAt: Date.now() }),
    { mode: 0o600 });
  const res = cliSync(['seal-grants', '--grants', grants, '--seal-passphrase-file', pass],
    { SIGNERD_GRANT_LOCK_WAIT_MS: '0' });
  assert.equal(res.status, 1, `a held lock must be refused: ${res.stdout}`);
  assert.equal(/"ok":true/.test(res.stdout), false, 'nothing may be reported as sealed');
  const codeLines = res.stderr.split('\n').filter((l) => l.startsWith('grant_file_locked'));
  assert.equal(codeLines.length, 1, `one code line expected: ${res.stderr}`);
  assert.match(res.stderr, /^\s*fix: /m, `a fix: line is required: ${res.stderr}`);
});

test('F2 the wait budget is bounded and the refusal is immediate when it is 0', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');
  fs.writeFileSync(`${grants}.lock`,
    JSON.stringify({ pid: process.pid, token: 'held-by-the-test', startedAt: Date.now() }),
    { mode: 0o600 });
  const started = Date.now();
  const res = cliSync(addArgs(grants, 'while-held', { append: true }),
    { SIGNERD_GRANT_LOCK_WAIT_MS: '0' });
  const elapsed = Date.now() - started;
  assert.equal(res.status, 1, `a held lock must be refused: ${res.stdout}`);
  // The wait is BOUNDED: a budget of 0 means no waiting at all. A writer
  // that waits forever would hang the CLI on a stuck holder.
  assert.ok(elapsed < 3000, `the refusal must not hang (took ${elapsed} ms)`);
  // And the default budget is a finite number, not Infinity.
  const { waitBudgetMs } = require(path.join(ROOT, 'src', 'grant-file-lock.js'));
  assert.ok(Number.isFinite(waitBudgetMs()), 'the default wait budget must be finite');
});

test('G1 a stale lock (dead owner) is taken over, the write lands, the lock is released', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');

  // A provably dead owner: a child process whose pid we watched exit.
  const child = spawn(process.execPath, ['-e', '']);
  const childPid = child.pid;
  return new Promise((resolve) => child.on('close', () => {
    fs.writeFileSync(`${grants}.lock`,
      JSON.stringify({ pid: childPid, token: 'stale-owner', startedAt: Date.now() - 60000 }),
      { mode: 0o600 });
    const res = cliSync(addArgs(grants, 'after-stale', { append: true }));
    assert.equal(res.status, 0, `a dead owner's lock must be taken over: ${res.stderr}`);
    assert.ok(grantNames(grants).includes('after-stale'), 'the write must land');
    assert.equal(fs.existsSync(`${grants}.lock`), false, 'the taken-over lock must be released');
    resolve();
  }));
});

test('G2 a lock file next to the grant file changes nothing on the read surfaces', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');
  // A foreign file in the grant directory (the lock file's neighbours must
  // be irrelevant to the loader): the loader judges the grant FILE, not the
  // directory's file list.
  fs.writeFileSync(path.join(dir, 'grants.json.lock'),
    JSON.stringify({ pid: process.pid, token: 'idle', startedAt: Date.now() }), { mode: 0o600 });
  const verify = cliSync(['verify-grants', '--grants', grants]);
  const status = cliSync(['status', '--grants', grants, '--ledger', path.join(dir, 'j.jsonl')]);
  assert.equal(status.status, 0, `status must ignore the lock: ${status.stderr}`);
  // And the daemon-facing surfaces agree with a clean directory.
  fs.unlinkSync(path.join(dir, 'grants.json.lock'));
  const statusClean = cliSync(['status', '--grants', grants, '--ledger', path.join(dir, 'j.jsonl')]);
  assert.equal(statusClean.status, 0, statusClean.stderr);
  assert.equal(status.stdout, statusClean.stdout,
    'the verdict must not depend on a neighbour file');
  const verifyClean = cliSync(['verify-grants', '--grants', grants]);
  assert.equal(verify.stdout, verifyClean.stdout,
    'the verify verdict must not depend on a neighbour file');
  assert.equal(verify.stderr, verifyClean.stderr,
    'the verify refusal must not depend on a neighbour file');
});

test('G4 the garbage wait-budget override falls back to a real budget - a dead holder clears', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create must work');

  // THE CONTRACT (module rule, src/grant-file-lock.js): a NON-INTEGER
  // SIGNERD_GRANT_LOCK_WAIT_MS falls back to the default budget - the env
  // var is a diagnostics hook, so garbage in the environment must not
  // turn the budget into 0 and refuse every parallel writer.
  //
  // Deterministic pin for the mutation-ladder rung m_no_wait (the budget
  // forced to 0 for a non-integer override): a LIVE holder that dies 1.2 s
  // in must be WAITED FOR - the writer then takes over the dead owner's
  // lock and lands the write. With budget 0 the writer refuses instantly
  // and this test goes RED. Green on BOTH trees: the pre-fix tree has no
  // lock machinery at all, so its writer lands immediately.
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 1200)']);
  const holderPid = child.pid;
  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', () => {
      fs.writeFileSync(`${grants}.lock`,
        JSON.stringify({ pid: holderPid, token: 'live-then-dead', startedAt: Date.now() }),
        { mode: 0o600 });

      const res = cliSync(addArgs(grants, 'after-holder-died', { append: true }),
        { SIGNERD_GRANT_LOCK_WAIT_MS: 'not-a-number' });
      assert.equal(res.status, 0,
        `a garbage override must fall back to the default budget and wait: ${res.stderr}`);
      assert.ok(grantNames(grants).includes('after-holder-died'),
        'the write must land once the holder dies');
      // The stale lock is consumed by the takeover - but do NOT pin its
      // absence: the pre-fix tree never touched a foreign neighbour file.
      if (fs.existsSync(`${grants}.lock`)) fs.unlinkSync(`${grants}.lock`);
      resolve();
    });
  });
});

test('G3 the sequential surface refuses exactly what it refused before', () => {
  const dir = sandbox();
  const grants = path.join(dir, 'grants.json');
  assert.equal(cliSync(addArgs(grants, 'good')).status, 0, 'create');

  const again = cliSync(addArgs(grants, 'other'));
  assert.equal(again.status, 1, 'a second create is still grant_file_exists');
  assert.match(again.stderr, /^grant_file_exists/m);

  const dup = cliSync(addArgs(grants, 'good', { append: true }));
  assert.equal(dup.status, 1, 'a duplicate name is still grant_exists');
  assert.match(dup.stderr, /^grant_exists/m);

  const removeMissing = cliSync(['grant-remove', '--grants', grants, '--name', 'nope']);
  assert.equal(removeMissing.status, 1, 'a missing name is still grant_not_found');
  assert.match(removeMissing.stderr, /^grant_not_found/m);

  const removed = cliSync(['grant-remove', '--grants', grants, '--name', 'good']);
  assert.equal(removed.status, 0, `removal must still work: ${removed.stderr}`);
  assert.deepEqual(grantNames(grants), [], 'the file is emptied');
  assert.equal(fs.existsSync(`${grants}.lock`), false, 'no lock left behind');
});
