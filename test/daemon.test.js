'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Daemon, request } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');

const crypto = require('node:crypto');

const PASSPHRASE = 'a passphrase for tests only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-daemon-'));
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
      expiresAt: '2026-10-28T10:00:00Z',
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
        maxLamports: '42', expiresAt: '2026-10-28T10:00:00Z',
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
        maxLamports: '42', expiresAt: '2026-10-28T10:00:00Z',
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
