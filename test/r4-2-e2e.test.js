'use strict';

// End-to-end: a LIVE daemon must refuse to sign while a stranger holds the
// JOURNAL open for writing.
//
// This is the user-level statement of R4-2. The journal's mode is 0600, its
// owner is the daemon's own user, its directory checks pass and its hash
// chain verifies - but a process that opened it for writing before the mode
// was tightened can still write through that descriptor at any moment. The
// journal IS the replay set and the spend budget, so believing those bytes
// lets a signer sign the same message twice or spend past the window cap.
//
// Pre-fix behaviour: the daemon SIGNS the request -> the test fails.
// Post-fix behaviour: the daemon refuses with ledger_held_writer.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const { Daemon, request } = require('../src/daemon');
const { createKeystore } = require('../src/keystore');

const PASSPHRASE = 'a passphrase for tests only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r42-e2e-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function wire(keypair, recipient, lamports = 42) {
  const tx = new Transaction();
  tx.feePayer = keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: recipient, lamports }));
  tx.sign(keypair);
  return tx.serialize();
}

/** Hold `file` open for writing until the release flag appears. */
function holdForWriting(file) {
  const release = `${file}.release`;
  const code = [
    'import os,time',
    `fd=os.open(${JSON.stringify(file)}, os.O_RDWR)`,
    `release=${JSON.stringify(release)}`,
    "print('held',flush=True)",
    'deadline=time.time()+30',
    'while not os.path.exists(release) and time.time()<deadline:',
    '    time.sleep(0.02)',
  ].join('\n');
  const child = spawn('python3', ['-c', code], { stdio: ['ignore', 'pipe', 'pipe'] });
  const ready = new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('holder not ready')), 15000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('held')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on('error', reject);
  });
  const stop = async () => {
    fs.writeFileSync(release, 'go');
    await new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('exit', resolve);
      setTimeout(resolve, 5000);
    });
    try { fs.unlinkSync(release); } catch { /* gone */ }
  };
  return { ready, stop };
}

async function startDaemon(dir, name) {
  const keystore = path.join(dir, `${name}.key`);
  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const { loadKeystore } = require('../src/keystore');
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const recipient = Keypair.generate().publicKey;
  const grantFile = path.join(dir, `${name}-grants.json`);
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: keypair.publicKey.toBase58(),
        destination: recipient.toBase58(),
        maxLamports: '1000000',
        expiresAt: futureIso(),
        windowMaxLamports: '1000000',
        windowSeconds: '60',
      },
    },
  }));
  fs.chmodSync(grantFile, 0o600);
  const socketPath = path.join(dir, `${name}.sock`);
  const ledgerFile = path.join(dir, `${name}-journal.jsonl`);
  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile,
  });
  await daemon.start();
  return { daemon, socketPath, keypair, recipient, grantFile, ledgerFile };
}

test('R4-2 end-to-end: a live daemon refuses to sign while a stranger holds the journal open for writing', async () => {
  const dir = tmpDir();
  // Baseline: with nobody holding the journal, the daemon signs. This proves
  // the refusal below is caused by the write handle, not by a broken setup.
  const f = await startDaemon(dir, 'live');
  try {
    const before = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(before.ok, true, `baseline must succeed, got ${JSON.stringify(before)}`);
    assert.ok(before.signature);
    assert.ok(fs.existsSync(f.ledgerFile), 'the baseline approval must have created the journal');

    // A stranger opens the journal for writing while the daemon is running.
    // The mode still reads 0600 and the owner is still us - only the open
    // handle is wrong, which is exactly what no stat can see.
    const holder = holdForWriting(f.ledgerFile);
    await holder.ready;
    assert.equal(fs.statSync(f.ledgerFile).mode & 0o777, 0o600,
      'the mode must still look tight: only the open handle is wrong');
    try {
      const refused = await request({
        socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
      });
      assert.equal(refused.ok, false, 'the daemon must refuse while a writer holds the journal');
      assert.equal(refused.error, 'ledger_held_writer',
        `expected ledger_held_writer, got ${refused.error}`);
      assert.equal(refused.signature, undefined, 'a refused request must carry no signature');
    } finally {
      await holder.stop();
    }

    // Once the handle is gone the same journal works again: the refusal
    // reflects the current state, not a poisoned verdict.
    const after = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(after.ok, true, `must recover after the writer leaves, got ${JSON.stringify(after)}`);
    assert.ok(after.signature);
  } finally {
    await f.daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-2: a daemon refuses to be constructed while a stranger holds the journal open', async () => {
  const dir = tmpDir();
  const f = await startDaemon(dir, 'first');
  // One approval first, so the journal really exists on disk.
  const seeded = await request({
    socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
  });
  assert.equal(seeded.ok, true, `seed approval must succeed, got ${JSON.stringify(seeded)}`);
  await f.daemon.stop();

  // The journal exists now. A stranger grabs it before the restart - the
  // operator's reload, the crash-restart path, anything that re-opens the
  // journal - and reopening must fail closed rather than trust those bytes.
  const holder = holdForWriting(f.ledgerFile);
  try {
    await holder.ready;
    const socketPath = path.join(dir, 'second.sock');
    assert.throws(() => new Daemon({
      socketPath,
      keystorePath: path.join(dir, 'first.key'),
      passphrase: PASSPHRASE,
      grantFile: f.grantFile,
      ledgerFile: f.ledgerFile,
    }), /ledger_held_writer/,
    'reopen must refuse a journal somebody has open for writing');
    assert.equal(fs.existsSync(socketPath), false,
      'a refused construction must leave no socket behind');
  } finally {
    await holder.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
