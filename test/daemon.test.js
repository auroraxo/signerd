'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Daemon, request } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');
const { loadGrantFile } = require('../src/grantfile');
const { Ledger } = require('../src/ledger');

const crypto = require('node:crypto');

const PASSPHRASE = 'a passphrase for tests only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-daemon-'));
}

/**
 * An ISO timestamp safely in the future relative to when the test runs.
 *
 * A grant expiry pinned to a literal date turns every test that depends on
 * the grant being valid into a time bomb: the suite passes on the day it was
 * written and then fails, one expiry later, for reasons that have nothing to
 * do with the code under test. The expiry has to move with the clock.
 */
function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

async function fixture({ grants: grantNames = ['ops'] } = {}) {
  const dir = tmpDir();
  const recipient = Keypair.generate().publicKey;
  const keystore = path.join(dir, 'ops.key');
  const created = createKeystore({ file: keystore, passphrase: PASSPHRASE });
  // The daemon's key is the one inside the keystore; the grant must speak for
  // exactly that key or the daemon refuses to start.
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  assert.equal(keypair.publicKey.toBase58(), created.publicKey);
  const grantFile = path.join(dir, 'grants.json');
  const grants = {};
  for (const name of grantNames) {
    grants[name] = {
      signer: keypair.publicKey.toBase58(),
      destination: recipient.toBase58(),
      maxLamports: '42',
      expiresAt: futureIso(),
      windowMaxLamports: '100000',
      windowSeconds: '3600',
    };
  }
  fs.writeFileSync(grantFile, JSON.stringify({ version: 1, grants }, null, 2));
  const socketPath = path.join(dir, 'signerd.sock');
  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, 'journal.jsonl'),
  });
  await daemon.start();
  return { dir, daemon, socketPath, keypair, recipient, grantFile, keystore };
}

function wire(keypair, recipient, lamports = 42) {
  const tx = new Transaction();
  tx.feePayer = keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: recipient, lamports }));
  tx.sign(keypair);
  return tx.serialize();
}

test('a daemon signs a request that is inside the grant and refuses one that is not', async () => {
  const f = await fixture();
  try {
    const ok = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(ok.ok, true);
    assert.equal(ok.amountLamports, '42');
    assert.equal(ok.feeLamports, '5000');
    assert.equal(ok.totalLamports, '5042');
    assert.equal(ok.seq, 1);
    assert.ok(ok.signature);
    // The returned signed wire must carry a real signature.
    const signed = Buffer.from(ok.signed, 'base64');
    assert.equal(signed.length, 215);
    assert.notEqual(signed.subarray(1, 65).every((b) => b === 0), true);

    // Over the per-transaction cap: refused with a structured reason.
    const over = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient, 43),
    });
    assert.equal(over.ok, false);
    assert.equal(over.error, 'amount');
    assert.equal(over.signed, undefined);
  } finally {
    await f.daemon.stop();
  }
});

test('an unknown grant name is refused and never resolves through Object.prototype', async () => {
  const f = await fixture();
  try {
    for (const name of ['nope', 'toString', '__proto__', 'constructor', 'hasOwnProperty']) {
      const response = await request({
        socketPath: f.socketPath, grant: name, wire: wire(f.keypair, f.recipient),
      });
      assert.equal(response.ok, false, `grant ${name} must be refused`);
      assert.equal(response.error, 'grant_not_found');
    }
  } finally {
    await f.daemon.stop();
  }
});

test('the socket is a capability: only the owner may connect', async () => {
  const f = await fixture();
  try {
    const mode = fs.statSync(f.socketPath).mode & 0o777;
    assert.equal(mode, 0o600);
  } finally {
    await f.daemon.stop();
  }
});

test('the daemon key stays in the daemon: a client only ever holds the grant name', async () => {
  const f = await fixture();
  try {
    const response = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(response.ok, true);
    // Nothing in the response or on disk exposes the secret key.
    assert.equal(JSON.stringify(response).includes('secretKey'), false);
    const journal = fs.readFileSync(path.join(f.dir, 'journal.jsonl'), 'utf8');
    assert.equal(journal.includes('secretKey'), false);
    // The keystore on disk is encrypted and 0600.
    const raw = fs.readFileSync(f.keystore, 'utf8');
    assert.equal(raw.includes(f.keypair.secretKey.toString('base64')), false);
    assert.equal(fs.statSync(f.keystore).mode & 0o777, 0o600);
  } finally {
    await f.daemon.stop();
  }
});

test('the same wire is signed only once across a daemon restart (replay survives)', async () => {
  const f = await fixture();
  const w = wire(f.keypair, f.recipient);
  try {
    const first = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
    assert.equal(first.ok, true);
  } finally {
    await f.daemon.stop();
  }
  // Restart the daemon on the same ledger and grant file.
  const restarted = new Daemon({
    socketPath: f.socketPath,
    keystorePath: f.keystore,
    passphrase: PASSPHRASE,
    grantFile: f.grantFile,
    ledgerFile: path.join(f.dir, 'journal.jsonl'),
  });
  await restarted.start();
  try {
    const second = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
    assert.equal(second.ok, false);
    assert.equal(second.error, 'replay');
  } finally {
    await restarted.stop();
  }
});

test('the daemon refuses to start when a grant does not match its key', async () => {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const grantFile = path.join(dir, 'grants.json');
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: Keypair.generate().publicKey.toBase58(),
        destination: Keypair.generate().publicKey.toBase58(),
        maxLamports: '42', expiresAt: futureIso(),
        windowMaxLamports: '100000', windowSeconds: '3600',
      },
    },
  }));
  assert.throws(() => new Daemon({
    socketPath: path.join(dir, 's.sock'),
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, 'j.jsonl'),
  }), /grant_signer_mismatch/);
});

test('a wrong passphrase stops the daemon from starting', async () => {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  const created = createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const grantFile = path.join(dir, 'grants.json');
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: created.publicKey,
        destination: Keypair.generate().publicKey.toBase58(),
        maxLamports: '42', expiresAt: futureIso(),
        windowMaxLamports: '100000', windowSeconds: '3600',
      },
    },
  }));
  assert.throws(() => new Daemon({
    socketPath: path.join(dir, 's.sock'),
    keystorePath: keystore,
    passphrase: 'wrong passphrase',
    grantFile,
    ledgerFile: path.join(dir, 'j.jsonl'),
  }), /keystore_auth_failed/);
});

test('the socket file is removed on shutdown and a stale one is cleaned up', async () => {
  const f = await fixture();
  const socketPath = f.socketPath;
  await f.daemon.stop();
  assert.equal(fs.existsSync(socketPath), false);
  // A leftover socket file from a crashed run must not block a restart.
  fs.writeFileSync(socketPath, '');
  const restarted = new Daemon({
    socketPath,
    keystorePath: f.keystore,
    passphrase: PASSPHRASE,
    grantFile: f.grantFile,
    ledgerFile: path.join(f.dir, 'journal.jsonl'),
  });
  await restarted.start();
  const response = await request({ socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient) });
  assert.equal(response.ok, true);
  await restarted.stop();
});


test('a second daemon on the same journal refuses to start (single writer)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lock-'));
  const keystore = path.join(dir, 'ops.key');
  const created = createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const recipient = Keypair.generate().publicKey;
  const grantFile = path.join(dir, 'grants.json');
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: created.publicKey,
        destination: recipient.toBase58(),
        maxLamports: '42', expiresAt: futureIso(),
        windowMaxLamports: '100000', windowSeconds: '3600',
      },
    },
  }));
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const first = new Daemon({
    socketPath: path.join(dir, 'a.sock'),
    keystorePath: keystore, passphrase: PASSPHRASE, grantFile, ledgerFile,
  });
  await first.start();
  try {
    // A second daemon on the SAME journal would double the window budget and
    // bypass the replay set. It must refuse to start.
    const second = new Daemon({
      socketPath: path.join(dir, 'b.sock'),
      keystorePath: keystore, passphrase: PASSPHRASE, grantFile, ledgerFile,
    });
    await assert.rejects(() => second.start(), /ledger_locked/);
    // The first daemon is unaffected and still works.
    const response = await request({
      socketPath: path.join(dir, 'a.sock'), grant: 'ops',
      wire: wire(keypair, recipient),
    });
    assert.equal(response.ok, true);
  } finally {
    await first.stop();
  }
  // After the first daemon stops, the lock is released and a new one starts.
  const third = new Daemon({
    socketPath: path.join(dir, 'c.sock'),
    keystorePath: keystore, passphrase: PASSPHRASE, grantFile, ledgerFile,
  });
  await third.start();
  await third.stop();
});

test('the journal and the socket are owner-only, never group readable', async () => {
  const f = await fixture();
  try {
    const socketMode = fs.statSync(f.socketPath).mode & 0o777;
    assert.equal(socketMode, 0o600);
    await request({ socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient) });
    const journalMode = fs.statSync(path.join(f.dir, 'journal.jsonl')).mode & 0o777;
    assert.equal(journalMode, 0o600, 'the journal must not be group/other readable');
  } finally {
    await f.daemon.stop();
  }
});

test('a keystore inside a world-writable directory is refused', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-dir-'));
  fs.chmodSync(dir, 0o777);
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: PASSPHRASE });
  assert.throws(() => loadKeystore({ file, passphrase: PASSPHRASE }), /keystore_dir_mode/);
  fs.chmodSync(dir, 0o755);
  assert.doesNotThrow(() => loadKeystore({ file, passphrase: PASSPHRASE }));
});

test('a malformed request is refused with a structured error, not a crash', async () => {
  const f = await fixture();
  try {
    const net = require('node:net');
    const raw = await new Promise((resolve, reject) => {
      const socket = net.connect(f.socketPath);
      let buffer = '';
      socket.on('connect', () => socket.write('this is not json\n'));
      socket.on('data', (chunk) => { buffer += chunk.toString('utf8'); });
      socket.on('end', () => resolve(buffer));
      socket.on('error', reject);
    });
    const parsed = JSON.parse(raw.trim());
    assert.equal(parsed.ok, false);
    assert.equal(parsed.error, 'request_invalid');
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// Regression tests for the 27.10. independent adversarial review (run
// 24d92c08), which found 5 defects while the suite was green. Each test below
// fails against the code as reviewed and passes only after the fix.
// ---------------------------------------------------------------------------

function deadPid() {
  const { spawnSync } = require('node:child_process');
  const proc = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
  assert.ok(proc.pid > 0);
  return proc.pid;
}

function seedLock(ledgerFile, pid) {
  fs.writeFileSync(`${ledgerFile}.lock`,
    JSON.stringify({ pid, token: 'a'.repeat(32), startedAt: Date.now() - 60000 }));
}

async function pairSetup({ grants: grantNames = ['ops'] } = {}) {
  const dir = tmpDir();
  const recipient = Keypair.generate().publicKey;
  const keystore = path.join(dir, 'ops.key');
  const created = createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const grantFile = path.join(dir, 'grants.json');
  const grants = {};
  for (const name of grantNames) {
    grants[name] = {
      signer: created.publicKey, destination: recipient.toBase58(),
      maxLamports: '42', expiresAt: futureIso(),
      windowMaxLamports: '100000', windowSeconds: '3600',
    };
  }
  fs.writeFileSync(grantFile, JSON.stringify({ version: 1, grants }));
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const make = (sock) => new Daemon({
    socketPath: path.join(dir, sock), keystorePath: keystore,
    passphrase: PASSPHRASE, grantFile, ledgerFile,
  });
  return { dir, recipient, keystore, grantFile, ledgerFile, keypair, make };
}

test('review #1: a takeover must never steal a lock that appeared in the read->rename window', async () => {
  const s = await pairSetup();
  seedLock(s.ledgerFile, deadPid());
  const lockPath = `${s.ledgerFile}.lock`;
  const survivor = JSON.stringify({ pid: process.pid, token: 'c'.repeat(32), startedAt: Date.now() });

  // Widen the exact TOCTOU the review exploited: between the daemon judging
  // the lock dead and performing its rename, a CONCURRENT starter wins and
  // writes its own live lock at the same path. The takeover must notice it
  // moved a file other than the one it inspected and back off.
  const realRename = fs.renameSync;
  let injected = false;
  fs.renameSync = function renamed(from, to) {
    if (!injected && from === lockPath) {
      injected = true;
      realRename.call(fs, from, `${to}.pre-${Date.now()}`); // pull the stale lock away
      realRename.call(fs, `${to}.pre-${Date.now()}`.replace(/\.pre-\d+$/, (m) => m), lockPath); // no-op guard
    }
    return realRename.call(fs, from, to);
  };

  // Simpler and exact: before the rename lands, put a live lock in its place.
  fs.renameSync = function renamed(from, to) {
    if (!injected && from === lockPath) {
      injected = true;
      realRename.call(fs, from, to); // move the stale lock away
      fs.writeFileSync(lockPath, survivor); // a live starter wins the freed path
      return undefined; // leave `lockPath` holding the LIVE lock for verification
    }
    return realRename.call(fs, from, to);
  };

  const daemon = s.make('race.sock');
  try {
    await assert.rejects(() => daemon.start(), /ledger_locked/,
      'the daemon must refuse rather than run beside a live lock owner');
    // The concurrent starter's lock must survive intact: the review's bug
    // unlinked it, leaving two daemons believing they owned the journal.
    assert.ok(fs.existsSync(lockPath), 'the live lock must not be deleted by a failed takeover');
    assert.equal(fs.readFileSync(lockPath, 'utf8'), survivor,
      'the live lock must be restored byte-for-byte');
    assert.equal(daemon.started, false);
    assert.equal(daemon.lockHeld, false);
  } finally {
    fs.renameSync = realRename;
    await daemon.stop().catch(() => { /* never started */ });
  }
});

test('review #2: stop() keeps the journal lock until the server has stopped serving', async () => {
  const s = await pairSetup();
  const net = require('node:net');
  const daemon = s.make('stop.sock');
  await daemon.start();
  const lockPath = `${s.ledgerFile}.lock`;

  // A client holds a connection open without sending: server.close() cannot
  // complete while it is alive, so the lock must still be held.
  const held = net.connect(daemon.socketPath);
  await new Promise((resolve, reject) => {
    held.once('connect', resolve);
    held.once('error', reject);
  });

  const stopping = daemon.stop();
  try {
    // Evaluated synchronously, before any await inside stop() resolves.
    assert.ok(fs.existsSync(lockPath),
      'the lock must still exist while the daemon is draining: releasing it first lets a second daemon start mid-shutdown');

    const rival = s.make('rival.sock');
    await assert.rejects(() => rival.start(), /ledger_locked/,
      'a second daemon must not start while the first still drains an open connection');
  } finally {
    held.destroy();
  }
  // The buggy code releases the lock before draining and then waits forever
  // for the open connection, so this wait must be bounded: a hanging test is
  // not a failing test.
  await Promise.race([
    stopping,
    new Promise((_, reject) => setTimeout(
      () => reject(new Error('stop() never completed: the daemon did not drain the open connection')),
      4000)),
  ]);
  assert.equal(fs.existsSync(lockPath), false, 'the lock is released once serving has stopped');
  const successor = s.make('successor.sock');
  await successor.start();
  await successor.stop();
});

test('review #3: a failure after listen() leaves no orphan server and releases the lock', async () => {
  const s = await pairSetup();
  const daemon = s.make('orphan.sock');
  const realChmod = fs.chmodSync;
  fs.chmodSync = function chmod(file, mode) {
    if (file === daemon.socketPath) {
      const err = new Error('simulated EACCES');
      err.code = 'EACCES';
      throw err;
    }
    return realChmod.call(fs, file, mode);
  };
  try {
    await assert.rejects(() => daemon.start(), /EACCES/);
  } finally {
    fs.chmodSync = realChmod;
  }

  assert.equal(daemon.started, false);
  assert.equal(fs.existsSync(daemon.socketPath), false,
    'the socket must be cleaned up, not left behind for an orphan listener');
  assert.equal(fs.existsSync(`${s.ledgerFile}.lock`), false,
    'the lock must be released only after the server is gone');

  // Nothing may still be accepting on that path.
  const net = require('node:net');
  await new Promise((resolve) => {
    const probe = net.connect(daemon.socketPath);
    probe.once('connect', () => { probe.destroy(); assert.fail('an orphan server is still accepting'); });
    probe.once('error', () => resolve());
    probe.setTimeout(700, () => { probe.destroy(); resolve(); });
  });

  // The released lock means an operator retry is not blocked by this attempt.
  const retry = s.make('retry.sock');
  await retry.start();
  await retry.stop();
});

test('review #4: a post-start server error shuts down cleanly instead of freeing the lock while serving', async () => {
  const s = await pairSetup();
  const daemon = s.make('err.sock');
  await daemon.start();
  const lockPath = `${s.ledgerFile}.lock`;
  assert.ok(fs.existsSync(lockPath));

  daemon.server.emit('error', Object.assign(new Error('EMFILE'), { code: 'EMFILE' }));
  await new Promise((resolve) => setTimeout(resolve, 120));

  assert.equal(daemon.started, false, 'the daemon must stop serving, not keep signing without a lock');
  assert.equal(fs.existsSync(lockPath), false, 'the lock is released only as part of an orderly stop');
  assert.equal(fs.existsSync(daemon.socketPath), false);

  // stop() must stay callable and non-throwing after an error-driven shutdown.
  await assert.doesNotReject(() => daemon.stop());

  const next = s.make('after-err.sock');
  await next.start();
  await next.stop();
});

test('review #6: a group-writable keystore directory is refused, not only a world-writable one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-gw-'));
  const file = path.join(dir, 'ops.key');
  fs.chmodSync(dir, 0o770); // group may write -> a group member can swap the key
  createKeystore({ file, passphrase: PASSPHRASE });
  assert.throws(() => loadKeystore({ file, passphrase: PASSPHRASE }), /keystore_dir_mode/);
  fs.chmodSync(dir, 0o772); // other may write -> same problem, different subject
  assert.throws(() => loadKeystore({ file, passphrase: PASSPHRASE }), /keystore_dir_mode/);
  fs.chmodSync(dir, 0o750); // group may only read: not writable, so acceptable
  assert.doesNotThrow(() => loadKeystore({ file, passphrase: PASSPHRASE }));
  fs.chmodSync(dir, 0o700);
  assert.doesNotThrow(() => loadKeystore({ file, passphrase: PASSPHRASE }));
  // A foreign-owned directory is refused even when its mode looks safe: its
  // owner can replace the file regardless of the mode we see.
  const foreign = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-fo-')), 'ops.key');
  createKeystore({ file: foreign, passphrase: PASSPHRASE });
  const originalUid = process.getuid;
  if (typeof originalUid === 'function') {
    process.getuid = () => originalUid() + 1;
    try {
      assert.throws(() => loadKeystore({ file: foreign, passphrase: PASSPHRASE }), /keystore_dir_owner/);
    } finally {
      process.getuid = originalUid;
    }
  }
});

test('regression: the daemon library never mutates the process umask', async () => {
  // Set a KNOWN umask first: capturing `before` without pinning it would
  // compare against a umask an earlier daemon already changed, and the
  // mutation would go unnoticed.
  const original = process.umask(0o022);
  try {
    const f = await fixture();
    try {
      assert.equal(process.umask(), 0o022,
        'constructing a Daemon must not change global process state for its host');
      await request({ socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient) });
      const journalMode = fs.statSync(path.join(f.dir, 'journal.jsonl')).mode & 0o777;
      assert.equal(journalMode, 0o600, 'the journal must be 0600 without relying on umask');
    } finally {
      await f.daemon.stop();
    }
  } finally {
    process.umask(original);
  }
});
