'use strict';

// R4-1: a grant file that somebody holds open for WRITING must be refused,
// even when the file's mode looks perfectly tight.
//
// The hole this closes: chmod does not revoke an already-open descriptor. A
// process that opened the file for writing while it was group/other-writable
// keeps that descriptor after the operator tightens the mode. The daemon
// re-reads the grant file on EVERY request, so such a file must never be
// parsed - otherwise forged grants reach the signer.
//
// Every test here is written so that it FAILS against the pre-fix tree and
// PASSES after the fix. The pre-fix tree had no writer detection at all, so
// "refused" is the assertion that separates them.

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const { loadGrantFile } = require('../src/grantfile');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r4-'));
}

const GOOD = {
  signer: '11111111111111111111111111111111',
  destination: 'So11111111111111111111111111111111111111112',
  maxLamports: '1000000',
  expiresAt: '2099-01-01T00:00:00Z',
  windowMaxLamports: '1000000',
  windowSeconds: '60',
};

function writeGrant(dir, extra) {
  const file = path.join(dir, 'grants.json');
  const doc = { version: 1, grants: { ops: { ...GOOD, ...extra } } };
  fs.writeFileSync(file, JSON.stringify(doc));
  fs.chmodSync(file, 0o600);
  return file;
}

/**
 * Hold `file` open with the given access mode until the returned stop() runs.
 * `mode` is 'r' (read) or 'w' (write).
 *
 * The holder releases itself when a flag file appears. Signalling was the
 * obvious alternative and it does not work here: a root-held descriptor
 * cannot be killed by the test's own uid, so a SIGKILL to the sudo wrapper
 * leaves the actual fd owner alive and every later assertion contaminated
 * (and the test file then hangs on an open pipe). Polling a release flag is
 * uid-independent and leaves nothing behind.
 *
 * The holder also has a hard self-timeout, so a failed stop() can never keep
 * the suite alive.
 */
function hold(file, mode, uid) {
  const access = mode === 'w' ? 'os.O_RDWR' : 'os.O_RDONLY';
  const release = `${file}.release`;
  const code = [
    'import os,time',
    `fd=os.open(${JSON.stringify(file)}, ${access})`,
    `release=${JSON.stringify(release)}`,
    "print('held',flush=True)",
    'deadline=time.time()+30',
    'while not os.path.exists(release) and time.time()<deadline:',
    '    time.sleep(0.02)',
  ].join('\n');
  const argv = uid === 'root'
    ? ['sudo', '-n', 'python3', '-c', code]
    : ['python3', '-c', code];
  const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });

  let isReady = false;
  let readyResolve = null;
  let readyReject = null;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const timer = setTimeout(() => readyReject(new Error('holder did not open the file')), 15000);
  let buf = '';
  child.stdout.on('data', (d) => {
    buf += d.toString();
    if (buf.includes('held') && !isReady) {
      isReady = true;
      clearTimeout(timer);
      readyResolve();
    }
  });
  child.on('error', (err) => {
    clearTimeout(timer);
    if (!isReady) readyReject(err);
  });
  child.on('exit', (code) => {
    clearTimeout(timer);
    // Only an exit BEFORE readiness is a test failure; afterwards it is the
    // expected result of stop().
    if (!isReady) readyReject(new Error(`holder exited early: ${code}`));
  });

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    clearTimeout(timer);
    try {
      fs.writeFileSync(release, 'go');
    } catch {
      // The holder may already be gone; the wait below still terminates.
    }
    await new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve();
        return;
      }
      const done = () => resolve();
      child.once('exit', done);
      // Never strand the awaiter, whatever happens.
      setTimeout(resolve, 5000);
    });
    try {
      fs.unlinkSync(release);
    } catch { /* already gone */ }
  };
  return { ready, stop };
}

test('R4-1: a grant file held open for WRITING is refused', async () => {
  const dir = tmpDir();
  const file = writeGrant(dir);
  const holder = hold(file, 'w');
  try {
    await holder.ready;
    // The mode is 0600 and the owner is us: every pre-R4-1 check passes. Only
    // the open write handle makes this file untrustworthy.
    assert.throws(() => loadGrantFile(file), /grant_file_held_writer/,
      'a grant file with an open write handle must be refused');
  } finally {
    await holder.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-1: a grant file held open for READING is still accepted', async () => {
  const dir = tmpDir();
  const file = writeGrant(dir);
  const holder = hold(file, 'r');
  try {
    await holder.ready;
    // The counterpart of the test above: a reader cannot forge anything. If
    // this failed, the daemon would refuse to sign whenever anybody looked
    // at the file - a false positive that would make the daemon unusable.
    const loaded = loadGrantFile(file);
    assert.deepEqual(loaded.names, ['ops']);
  } finally {
    await holder.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-1: the write handle is detected for a FOREIGN uid too', async (t) => {
  // This is the case a /proc scan cannot see: the fd table of a process owned
  // by another user is not readable. The kernel, however, decides leases for
  // every uid.
  const probe = spawn('sudo', ['-n', 'true'], { stdio: 'ignore' });
  const ok = await new Promise((resolve) => {
    probe.on('error', () => resolve(false));
    probe.on('exit', (code) => resolve(code === 0));
  });
  if (!ok) {
    t.skip('sudo not available: cannot create a foreign-uid holder');
    return;
  }

  const dir = tmpDir();
  const file = writeGrant(dir);
  const holder = hold(file, 'w', 'root');
  try {
    await holder.ready;
    assert.throws(() => loadGrantFile(file), /grant_file_held_writer/,
      'a foreign-uid writer must be detected - a /proc scan cannot see it');
  } finally {
    await holder.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-1: once the writer is gone, the same file is accepted again', async () => {
  const dir = tmpDir();
  const file = writeGrant(dir);
  const holder = hold(file, 'w');
  try {
    await holder.ready;
    assert.throws(() => loadGrantFile(file), /grant_file_held_writer/);
  } finally {
    await holder.stop();
  }
  // No permanent poisoning: the refusal reflects the CURRENT state.
  const loaded = loadGrantFile(file);
  assert.deepEqual(loaded.names, ['ops']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R4-1: the check is a point-in-time observation, not a permanent verdict', async () => {
  // The pre-fix /proc scan cached its verdict under dev:ino:ctime:size, so a
  // writer that opened the file AFTER the first scan was never noticed. This
  // test pins the opposite: the verdict must reflect the state at each call.
  const dir = tmpDir();
  const file = writeGrant(dir);
  const first = loadGrantFile(file);
  assert.deepEqual(first.names, ['ops']);

  const holder = hold(file, 'w');
  try {
    await holder.ready;
    assert.throws(() => loadGrantFile(file), /grant_file_held_writer/,
      'a writer that appears after a successful load must be caught');
  } finally {
    await holder.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
