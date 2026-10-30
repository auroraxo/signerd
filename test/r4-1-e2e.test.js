'use strict';

// End-to-end: a LIVE daemon must refuse to sign while a stranger holds the
// grant file open for writing.
//
// This is the actual attack R4-1 describes, at the level a user meets it: the
// grant file's mode is 0600 and the owner is the daemon's own user, so every
// static check passes - but a process that opened the file for writing before
// the mode was tightened can still write through it, and the daemon re-reads
// the file on EVERY request. If the daemon signs here, forged grants reach
// the signer.
//
// Pre-fix behaviour (HEAD): the daemon SIGNS the request -> the test fails.
// Post-fix behaviour: the daemon refuses with grant_file_held_writer.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const { Daemon, request } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');

const PASSPHRASE = 'a passphrase for tests only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r4-e2e-'));
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
  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, `${name}-journal.jsonl`),
  });
  await daemon.start();
  return { daemon, socketPath, keypair, recipient, grantFile };
}

test('R4-1 end-to-end: a live daemon refuses to sign while a stranger holds the grant file open for writing', async () => {
  const dir = tmpDir();
  // Baseline: with nobody holding the file, the daemon signs. This proves
  // that the refusal below is caused by the write handle and not by a broken
  // setup.
  const f = await startDaemon(dir, 'live');
  try {
    const before = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(before.ok, true, `baseline must succeed, got ${JSON.stringify(before)}`);
    assert.ok(before.signature);

    // A stranger opens the file for writing while the daemon is running - the
    // situation an operator creates by tightening a previously-writable file,
    // and the one an attacker creates by holding the handle from before the
    // chmod. The mode still reads 0600 and the owner is still us.
    const holder = holdForWriting(f.grantFile);
    await holder.ready;
    assert.equal(fs.statSync(f.grantFile).mode & 0o777, 0o600,
      'the mode must still look tight: only the open handle is wrong');
    try {
      const refused = await request({
        socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
      });
      assert.equal(refused.ok, false, 'the daemon must refuse while a writer holds the file');
      assert.equal(refused.error, 'grant_file_held_writer',
        `expected grant_file_held_writer, got ${refused.error}`);
      assert.equal(refused.signature, undefined, 'a refused request must carry no signature');
    } finally {
      await holder.stop();
    }

    // Once the handle is gone the same file is usable again: the refusal
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
