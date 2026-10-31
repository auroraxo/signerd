'use strict';

// End-to-end for the message-grant envelope: a LIVE daemon signs an
// openreceipts/v1 receipt body over its Unix socket, and the artifact is
// verified by the OPENRECEIPTS verifiers (Python receipt.py + Node
// verify.mjs) - two independent implementations that signerd does not ship.
//
// The false-allow probes at the bottom each pin one way the envelope could
// sign something it must not: a receipt over a transaction grant, a
// transaction wire over a message grant, an over-cap receipt, a replayed
// receipt, an expired grant, and a grant whose pinned key is not the
// daemon's key.

process.umask(0o077);

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair } = require('@solana/web3.js');

const { Daemon, request } = require('../src/daemon');
const { createKeystore, importKeystore } = require('../src/keystore');
const { canonicalReceiptBytes } = require('../src/receipt-identity');

const BIN = path.join(__dirname, '..', 'bin', 'signerd.js');
const OPENRECEIPTS = path.resolve(__dirname, '..', '..', 'openreceipts');
const PASSPHRASE = 'a passphrase for the message e2e only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-message-e2e-'));
}

function futureIso(hours = 1) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

/** The raw Ed25519 public key as base64, via OpenSSL (not the product code). */
function publicKeyB64(keypair) {
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    keypair.publicKey.toBytes(),
  ]);
  const jwk = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })
    .export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

function body(overrides = {}) {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-10-31T18:00:00+00:00',
    claims: { version: 'v0.1.0', channel: 'dev' },
    ...overrides,
  };
}

/**
 * Fixture: the daemon key exists as an OPENRECEIPTS PKCS8 key file, migrated
 * into the keystore via the real import path - the shape of a real adoption.
 */
function fixture(t) {
  const dir = tmpDir();
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  const keypair = Keypair.generate();
  const pkcs8 = keypair.secretKey.subarray(0, 32);
  // web3.js seed -> PKCS8 PEM via OpenSSL, written where receipt.py looks.
  const der = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      pkcs8,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const pem = der.export({ format: 'pem', type: 'pkcs8' });
  const issuerKey = path.join(dir, 'auroraxo.key');
  fs.writeFileSync(issuerKey, pem, { mode: 0o600 });
  const issuerPub = path.join(dir, 'auroraxo.pub');
  fs.writeFileSync(issuerPub, publicKeyB64(keypair) + '\n', { mode: 0o600 });

  const keystore = path.join(dir, 'ops.key');
  // importKeystore accepts JSON/base58/raw-64, not PEM (parseSecretFile
  // refuses guessing): the mechanical PEM->raw conversion is the caller's
  // job, exactly as the envelope-fit verdict documented it.
  const rawSecret = path.join(dir, 'auroraxo.raw');
  fs.writeFileSync(rawSecret, Buffer.concat([
    Buffer.from(keypair.secretKey.subarray(0, 64))]), { mode: 0o600 });
  importKeystore({ file: keystore, passphrase: PASSPHRASE, from: rawSecret });
  const pubB64 = publicKeyB64(keypair);

  const grantFile = path.join(dir, 'grants.json');
  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const writeGrants = (grants) => {
    fs.writeFileSync(grantFile, JSON.stringify({ version: 1, grants }, null, 2), { mode: 0o600 });
  };
  const messageGrant = (overrides = {}) => ({
    kind: 'message',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    pubkey: pubB64,
    maxBytes: '700',
    expiresAt: futureIso(),
    windowMaxMessages: '5',
    windowSeconds: '3600',
    ...overrides,
  });
  return {
    dir, keypair, keystore, pubB64, issuerKey, issuerPub,
    grantFile, socketPath, ledgerFile, writeGrants, messageGrant,
    passphraseFile: (() => {
      const p = path.join(dir, 'pass');
      fs.writeFileSync(p, PASSPHRASE + '\n', { mode: 0o600 });
      return p;
    })(),
  };
}

async function startDaemon(f, grants) {
  f.writeGrants(grants);
  const daemon = new Daemon({
    socketPath: f.socketPath,
    keystorePath: f.keystore,
    passphrase: PASSPHRASE,
    grantFile: f.grantFile,
    ledgerFile: f.ledgerFile,
  });
  await daemon.start();
  return daemon;
}

/** Run the real CLI sign-message subcommand against the live socket. */
function signMessageCli(f, grantName, bodyFile, out) {
  return new Promise((resolve) => {
    const args = [BIN, 'sign-message', '--socket', f.socketPath, '--grant', grantName,
      '--body', bodyFile];
    if (out) args.push('--out', out);
    const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', () => {});
    child.on('exit', (code) => resolve({ code, stdout }));
  });
}

test('message e2e: a live daemon signs a receipt an openreceipts verifier accepts', async (t) => {
  const f = fixture(t);
  const daemon = await startDaemon(f, { releases: f.messageGrant() });
  t.after(() => daemon.stop());

  const bodyFile = path.join(f.dir, 'body.json');
  // Deliberately NOT the canonical key order: the daemon must canonicalize.
  fs.writeFileSync(bodyFile, JSON.stringify(
    { claims: { channel: 'dev', version: 'v0.1.0' }, issued_at: '2026-10-31T18:00:00+00:00',
      subject: 'auroraxo/signerd', type: 'release', issuer: 'auroraxo',
      schema: 'openreceipts/v1' },
    null, 2,
  ));
  const receiptFile = path.join(f.dir, 'receipt.json');
  const run = await signMessageCli(f, 'releases', bodyFile, receiptFile);
  assert.equal(run.code, 0, `daemon refused: ${run.stdout}`);

  const response = JSON.parse(run.stdout);
  assert.equal(response.ok, true);
  assert.equal(response.kind, 'message');
  assert.equal(response.windowMessages, '1');

  // The artifact is openreceipts-shaped and the signature covers the
  // CANONICAL bytes, verified under OpenSSL with the imported key.
  const doc = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));
  assert.deepEqual(doc.receipt, body());
  assert.equal(doc.pubkey, f.pubB64);
  const sig = Buffer.from(doc.sig, 'base64');
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), f.keypair.publicKey.toBytes()]);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(crypto.verify(null, canonicalReceiptBytes(body()), keyObject, sig), true,
    'signature must verify over the canonical bytes under OpenSSL');

  // Independent verifiers: the openreceipts Python CLI and the Node verifier.
  if (fs.existsSync(path.join(OPENRECEIPTS, 'receipt.py'))) {
    const py = await new Promise((resolve) => {
      const child = spawn('python3', [
        path.join(OPENRECEIPTS, 'receipt.py'), 'verify', receiptFile,
        '--key', f.issuerPub], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (c) => { out += c; });
      child.stderr.on('data', (c) => { out += c; });
      child.on('exit', (code) => resolve({ code, out }));
    });
    assert.equal(py.code, 0, `receipt.py refused: ${py.out}`);
    assert.match(py.out, /OK/);
    const node = await new Promise((resolve) => {
      const child = spawn(process.execPath, [
        path.join(OPENRECEIPTS, 'verify.mjs'), '--key', f.issuerPub, receiptFile],
      { stdio: ['ignore', 'pipe', 'pipe'], cwd: OPENRECEIPTS });
      let out = '';
      child.stdout.on('data', (c) => { out += c; });
      child.stderr.on('data', (c) => { out += c; });
      child.on('exit', (code) => resolve({ code, out }));
    });
    assert.equal(node.code, 0, `verify.mjs refused: ${node.out}`);
  } else {
    t.skip('openreceipts checkout not present; verifier cross-check skipped');
  }
});

test('message e2e: window cap, replay and expiry refuse with data', async (t) => {
  const f = fixture(t);
  const daemon = await startDaemon(f, {
    releases: f.messageGrant({ windowMaxMessages: '2' }),
  });
  t.after(() => daemon.stop());

  const send = async (claims) => {
    const file = path.join(f.dir, `body-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(file, JSON.stringify(body({ claims })));
    const child = spawn(process.execPath, [BIN, 'sign-message', '--socket', f.socketPath,
      '--grant', 'releases', '--body', file], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', () => {});
    return { child, done: new Promise((resolve) => child.on('exit', (code) => resolve({ code, stdout: out }))) };
  };

  const first = await (await send({ version: 'v0.1.0' })).done;
  assert.equal(first.code, 0, first.stdout);
  const second = await (await send({ version: 'v0.2.0' })).done;
  assert.equal(second.code, 0, second.stdout);
  const third = await (await send({ version: 'v0.3.0' })).done;
  const thirdResponse = JSON.parse(third.stdout);
  assert.equal(thirdResponse.ok, false);
  assert.equal(thirdResponse.error, 'window_cap');
  assert.equal(thirdResponse.detail.windowMessages, '2');
  assert.equal(thirdResponse.detail.windowRemainingMessages, '0');

  // Replay: the FIRST receipt body again is refused even though the window
  // has room - one signature per distinct receipt, ever.
  const replayFile = path.join(f.dir, 'replay.json');
  fs.writeFileSync(replayFile, JSON.stringify(body({ claims: { version: 'v0.1.0' } })));
  const replay = await signMessageCli(f, 'releases', replayFile);
  assert.equal(JSON.parse(replay.stdout).error, 'replay');

  // Expired grant: the operator pulls the expiry back, the reload on the
  // next request refuses without a restart.
  f.writeGrants({ releases: f.messageGrant({ expiresAt: new Date(
    Math.floor(Date.now() / 1000 - 60) * 1000).toISOString() }) });
  const late = await signMessageCli(f, 'releases', replayFile);
  assert.equal(JSON.parse(late.stdout).error, 'expired');
});

test('message e2e: the two envelopes cannot borrow each other', async (t) => {
  const f = fixture(t);
  const destination = Keypair.generate().publicKey.toBase58();
  const daemon = await startDaemon(f, {
    releases: f.messageGrant(),
    transfers: {
      signer: f.keypair.publicKey.toBase58(),
      destination,
      maxLamports: '1000000',
      expiresAt: futureIso(),
      windowMaxLamports: '1000000',
      windowSeconds: '3600',
    },
  });
  t.after(() => daemon.stop());

  const bodyFile = path.join(f.dir, 'body.json');
  fs.writeFileSync(bodyFile, JSON.stringify(body()));

  // A receipt on the transaction grant is refused, never signed.
  const wrongKind = await signMessageCli(f, 'transfers', bodyFile);
  assert.equal(JSON.parse(wrongKind.stdout).error, 'grant_kind_mismatch');

  // A transaction wire on the message grant is refused, never signed.
  const { SystemProgram, Transaction } = require('@solana/web3.js');
  const tx = new Transaction();
  tx.feePayer = f.keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: f.keypair.publicKey, toPubkey: destination, lamports: 42 }));
  tx.sign(f.keypair);
  const wireFile = path.join(f.dir, 'wire.bin');
  fs.writeFileSync(wireFile, tx.serialize());
  const sign = new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, 'sign', '--socket', f.socketPath,
      '--grant', 'releases', '--tx', wireFile], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', () => {});
    child.on('exit', (code) => resolve({ code, stdout: out }));
  });
  const wireResult = await sign;
  assert.equal(JSON.parse(wireResult.stdout).error, 'grant_kind_mismatch');
});

test('message e2e: a grant pinning another key poisons the file at load, live and at start', async (t) => {
  const f = fixture(t);
  const other = Keypair.generate();
  const rogue = f.messageGrant({ issuer: 'someone-else', pubkey: publicKeyB64(other) });

  // Surface 1: a poisoned file refuses to START a daemon at all.
  f.writeGrants({ releases: f.messageGrant(), rogue });
  assert.throws(() => new Daemon({
    socketPath: f.socketPath,
    keystorePath: f.keystore,
    passphrase: PASSPHRASE,
    grantFile: f.grantFile,
    ledgerFile: f.ledgerFile,
  }).start(), /grant_key_mismatch/);

  // Surface 2: revocation live — a healthy daemon started next to the good
  // grant refuses every request the moment the file carries the rogue grant.
  const daemon = await startDaemon(f, { releases: f.messageGrant() });
  t.after(() => daemon.stop());
  const bodyFile = path.join(f.dir, 'body.json');
  fs.writeFileSync(bodyFile, JSON.stringify(body()));
  const before = await signMessageCli(f, 'releases', bodyFile);
  assert.equal(before.code, 0, `healthy grant must sign: ${before.stdout}`);
  f.writeGrants({ releases: f.messageGrant(), rogue });
  const run = await signMessageCli(f, 'releases', bodyFile);
  const response = JSON.parse(run.stdout);
  assert.equal(response.ok, false);
  assert.match(String(response.error), /grant_(key_mismatch|file_invalid)/);
});
