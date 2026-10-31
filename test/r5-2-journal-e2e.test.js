'use strict';

// End-to-end: a LIVE sealed daemon, and the p3/p15 attack timeline against it
// at the DAEMON level (not just the ledger unit).
//
//   1. a sealed daemon starts, signs, and writes BOTH the format-4 record and
//      the seal floor;
//   2. after a restart with the passphrase, replay protection survived (the
//      message is still remembered);
//   3. a stranger truncates the journal while the daemon is down - the
//      RESTART must refuse with ledger_mac_short (p3), not start fresh and
//      re-sign the same message;
//   4. a stranger forges the journal with a recomputed unkeyed chain - the
//      RESTART must refuse (p15);
//   5. an unsealed daemon (no passphrase) refuses the sealed journal (never
//      degraded), and a sealed daemon refuses an unsealed journal.
//
// Pre-fix behaviour: the sealed journal does not exist; the truncation and
// forgery restarts SUCCEED and the same message can be signed again.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const { Daemon, request } = require('../src/daemon');
const { chainHash, GENESIS_HASH } = require('../src/ledger');
const { createKeystore, loadKeystore } = require('../src/keystore');

const PASSPHRASE = 'a passphrase for tests only';
const SEAL_PASSPHRASE = 'a journal seal passphrase for tests only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r5j-e2e-'));
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

async function startSealedDaemon(dir, name) {
  const keystore = path.join(dir, `${name}.key`);
  // Reuse an existing keystore: a restart must NOT create a new key (that
  // would be a different reason to fail than the one under test).
  if (!fs.existsSync(keystore)) createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const recipient = Keypair.generate().publicKey;
  const grantFile = path.join(dir, `${name}-grants.json`);
  if (!fs.existsSync(grantFile)) {
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
  }
  const socketPath = path.join(dir, `${name}.sock`);
  const ledgerFile = path.join(dir, `${name}-journal.jsonl`);
  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile,
    journalSealPassphrase: SEAL_PASSPHRASE,
  });
  await daemon.start();
  return { daemon, socketPath, keypair, recipient, grantFile, ledgerFile };
}

/** Construct the daemon without starting it: only the Ledger refuses. */
async function newDaemon(dir, name, opts = {}) {
  const keystore = path.join(dir, `${name}.key`);
  if (!fs.existsSync(keystore)) createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const recipient = Keypair.generate().publicKey;
  const grantFile = path.join(dir, `${name}-grants.json`);
  if (!fs.existsSync(grantFile)) {
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
  }
  return new Daemon({
    socketPath: path.join(dir, `${name}.sock`),
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, `${name}-journal.jsonl`),
    journalSealPassphrase: opts.unsealed ? undefined : SEAL_PASSPHRASE,
  });
}

test('R5-2 journal e2e: sealed daemon signs, survives restart, replays are refused', async () => {
  const dir = tmpDir();
  try {
    const f = await startSealedDaemon(dir, 'live');
    const w = wire(f.keypair, f.recipient);
    const first = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
    assert.equal(first.ok, true, `baseline must sign: ${JSON.stringify(first)}`);
    assert.equal(first.seq, 1);

    const record = JSON.parse(fs.readFileSync(f.ledgerFile, 'utf8').trim().split('\n')[0]);
    assert.equal(record.v, 4, 'the sealed daemon must write format-4 records');
    assert.match(record.x, /^[0-9a-f]{64}$/, 'every record must carry the keyed chain MAC');
    const anchor = JSON.parse(fs.readFileSync(`${f.ledgerFile}.anchor`, 'utf8'));
    assert.equal(anchor.count, 1);
    assert.equal(anchor.head, record.x, 'the floor must end where the chain ends');
    assert.equal(fs.statSync(f.ledgerFile).mode & 0o777, 0o600);
    assert.equal(fs.statSync(`${f.ledgerFile}.anchor`).mode & 0o777, 0o600);

    await f.daemon.stop();

    // Restart with the passphrase: replay protection must have survived.
    const f2 = await startSealedDaemon(dir, 'live');
    try {
      const replay = await request({ socketPath: f2.socketPath, grant: 'ops', wire: w });
      assert.equal(replay.ok, false, 'a sealed restart must still refuse the replay');
      assert.equal(replay.error, 'replay');
      const next = await request({
        socketPath: f2.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
      });
      assert.equal(next.ok, true, `a new message must still sign: ${JSON.stringify(next)}`);
      assert.equal(next.seq, 2);
    } finally {
      await f2.daemon.stop();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R5-2 journal e2e p3: a truncated journal refuses to RESTART (no double-sign)', async () => {
  const dir = tmpDir();
  try {
    const f = await startSealedDaemon(dir, 'live');
    const w = wire(f.keypair, f.recipient);
    const first = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
    assert.equal(first.ok, true, `baseline must sign: ${JSON.stringify(first)}`);
    assert.ok(first.signature, 'the first signature exists');
    await f.daemon.stop();

    // The stranger truncates while the daemon is down (p3). Mode, owner and
    // directory all stay correct - only the CONTENT is gone.
    fs.writeFileSync(f.ledgerFile, '', { mode: 0o600 });

    await assert.rejects(
      async () => {
        const restarted = await startSealedDaemon(dir, 'live');
        await restarted.daemon.stop();
      },
      (err) => /ledger_mac_short/.test(err.message),
      'the daemon must refuse to restart on a truncated sealed journal',
    );

    // The signature that was already issued still verifies as bytes, but the
    // replay set is what must NOT come back empty: since the daemon refuses
    // to start, the message can never be re-approved. That is the whole
    // point of the refusal above (pre-fix: restart succeeds, seq resets).
    assert.ok(fs.existsSync(`${f.ledgerFile}.anchor`), 'the floor stays, as evidence');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R5-2 journal e2e p15: a re-chained forgery refuses to restart', async () => {
  const dir = tmpDir();
  try {
    const f = await startSealedDaemon(dir, 'live');
    const w = wire(f.keypair, f.recipient);
    const first = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
    assert.equal(first.ok, true, `baseline must sign: ${JSON.stringify(first)}`);
    await f.daemon.stop();

    // The stranger forges: lowers the spend, recomputes the unkeyed chain,
    // leaves the keyed `x` (cannot recompute it).
    const recs = fs.readFileSync(f.ledgerFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    recs[0].a = '1';
    let prev = GENESIS_HASH;
    for (const r of recs) {
      r.h = chainHash(prev, r);
      prev = r.h;
    }
    fs.writeFileSync(f.ledgerFile, `${recs.map((r) => JSON.stringify(r)).join('\n')}\n`, { mode: 0o600 });

    await assert.rejects(
      async () => {
        const restarted = await startSealedDaemon(dir, 'live');
        await restarted.daemon.stop();
      },
      (err) => /ledger_mac_invalid/.test(err.message),
      'the daemon must refuse to restart on a forged sealed journal',
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R5-2 journal e2e: sealed and unsealed daemons never trust each other\'s journals', async () => {
  const dir = tmpDir();
  try {
    const f = await startSealedDaemon(dir, 'sealed');
    const first = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(first.ok, true, `baseline must sign: ${JSON.stringify(first)}`);
    await f.daemon.stop();

    // Unsealed daemon on the sealed journal: refuse, never degrade.
    await assert.rejects(
      async () => { const d = await newDaemon(dir, 'sealed', { unsealed: true }); await d.stop(); },
      (err) => /ledger_sealed/.test(err.message),
      'an unsealed daemon must refuse a sealed journal',
    );
    // Sealed daemon on an unsealed journal: refuse and name the way out.
    const plainDir = tmpDir();
    try {
      const keystore = path.join(plainDir, 'p.key');
      createKeystore({ file: keystore, passphrase: PASSPHRASE });
      const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
      const plainRecipient = Keypair.generate().publicKey;
      const grantFile = path.join(plainDir, 'p-grants.json');
      fs.writeFileSync(grantFile, JSON.stringify({
        version: 1,
        grants: {
          ops: {
            signer: keypair.publicKey.toBase58(),
            destination: plainRecipient.toBase58(),
            maxLamports: '1000000',
            expiresAt: futureIso(),
            windowMaxLamports: '1000000',
            windowSeconds: '60',
          },
        },
      }));
      fs.chmodSync(grantFile, 0o600);
      const ledgerFile = path.join(plainDir, 'p-journal.jsonl');
      const plain = new Daemon({
        socketPath: path.join(plainDir, 'p.sock'),
        keystorePath: keystore,
        passphrase: PASSPHRASE,
        grantFile,
        ledgerFile,
      });
      await plain.start();
      try {
        const signed = await request({
          socketPath: path.join(plainDir, 'p.sock'), grant: 'ops',
          wire: wire(keypair, plainRecipient),
        });
        assert.equal(signed.ok, true, `unsealed baseline must sign: ${JSON.stringify(signed)}`);
      } finally {
        // Always stop: a leaked daemon keeps the event loop alive and the
        // whole test file would hang instead of failing.
        await plain.stop();
      }

      await assert.rejects(
        async () => {
          const d = new Daemon({
            socketPath: path.join(plainDir, 'p2.sock'),
            keystorePath: keystore,
            passphrase: PASSPHRASE,
            grantFile,
            ledgerFile,
            journalSealPassphrase: SEAL_PASSPHRASE,
          });
          await d.start();
          await d.stop();
        },
        (err) => /ledger_unsealed|seal-journal/.test(err.message),
        'a sealed daemon must refuse an unsealed journal and say how to seal it',
      );
    } finally {
      fs.rmSync(plainDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
