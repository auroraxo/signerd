'use strict';

// R5-2 grant half: a sealed grant file gives verifiable provenance.
//
// The probe this closes (adversarial review #5, p2): an attacker who could
// write the grant file BEFORE the chmod leaves forged grants behind; every
// static check (owner, mode, directory, lease) then passes and the daemon
// signs the attacker's destination. Tightening a mode cannot restore
// provenance - a MAC under a passphrase the attacker does not hold can.
//
// Falsification ladder (same convention as r4-1/r4-2):
//   pre-fix tree (78235bc): the daemon has no seal concept -> the forged
//     document is loaded and SIGNED -> the attack tests FAIL;
//   post-fix: forged/unsealed documents are refused, signed honestly only
//     under a valid seal.
//
// The last test is the FALSE-POSITIVE GUARD: an honestly sealed file with
// the correct passphrase must behave exactly like before. It is expected to
// pass on BOTH trees.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const { loadGrantFile } = require('../src/grantfile');
const {
  canonicalPayload, deriveSealKey, parseSeal, sealDocument, verifySealMac,
  makeSealKeyProvider,
} = require('../src/grantseal');
const { Daemon, request } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');

const PASSPHRASE = 'a seal passphrase for tests only';
const WRONG_PASSPHRASE = 'not the passphrase';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-seal-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function grantDoc(signer, destination) {
  return {
    version: 1,
    grants: {
      ops: {
        signer,
        destination,
        maxLamports: '1000000',
        expiresAt: futureIso(),
        windowMaxLamports: '1000000',
        windowSeconds: '60',
      },
    },
  };
}

function writeDoc(dir, doc, name = 'grants.json') {
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');
  fs.chmodSync(file, 0o600);
  return file;
}

function keyProvider(passphrase = PASSPHRASE) {
  return makeSealKeyProvider(passphrase);
}

function wire(keypair, recipient, lamports = 42) {
  const tx = new Transaction();
  tx.feePayer = keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: recipient, lamports }));
  tx.sign(keypair);
  return tx.serialize();
}

// ---------------------------------------------------------------- unit level

test('a sealed document verifies, and any change to the payload breaks the MAC', () => {
  const signer = Keypair.generate().publicKey.toBase58();
  const destination = Keypair.generate().publicKey.toBase58();
  const doc = grantDoc(signer, destination);
  const sealed = sealDocument(doc, PASSPHRASE);

  const parsed = parseSeal(sealed);
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  const key = deriveSealKey(PASSPHRASE, parsed.salt);
  assert.deepEqual(verifySealMac(sealed, key), { ok: true });

  // Value change (the actual forgery): destination swapped to the attacker.
  const forged = JSON.parse(JSON.stringify(sealed));
  forged.grants.ops.destination = Keypair.generate().publicKey.toBase58();
  assert.equal(verifySealMac(forged, key).reason, 'grant_file_seal_mismatch');

  // Adding a second grant is equally visible.
  const extended = JSON.parse(JSON.stringify(sealed));
  extended.grants.injected = sealed.grants.ops;
  assert.equal(verifySealMac(extended, key).reason, 'grant_file_seal_mismatch');

  // Raising a cap is the most tempting edit and is equally visible.
  const raised = JSON.parse(JSON.stringify(sealed));
  raised.grants.ops.maxLamports = '999999999999';
  assert.equal(verifySealMac(raised, key).reason, 'grant_file_seal_mismatch');

  // The MAC covers the version: a document cannot be downgraded to an older
  // rule set and keep a valid seal.
  const downgraded = { ...sealed, version: 2 };
  assert.equal(verifySealMac(downgraded, key).reason, 'grant_file_seal_mismatch');
});

test('a wrong passphrase derives a different key and the seal does not verify', () => {
  const doc = grantDoc(
    Keypair.generate().publicKey.toBase58(),
    Keypair.generate().publicKey.toBase58(),
  );
  const sealed = sealDocument(doc, PASSPHRASE);
  const parsed = parseSeal(sealed);
  assert.equal(parsed.ok, true);
  const wrongKey = deriveSealKey(WRONG_PASSPHRASE, parsed.salt);
  assert.equal(verifySealMac(sealed, wrongKey).reason, 'grant_file_seal_mismatch');
});

test('seal damage is refused at load time with the exact reason', () => {
  const doc = grantDoc(
    Keypair.generate().publicKey.toBase58(),
    Keypair.generate().publicKey.toBase58(),
  );
  const sealed = sealDocument(doc, PASSPHRASE);
  const cases = [
    [doc, 'grant_file_unsealed'],
    [{ ...sealed, seal: null }, 'grant_file_seal_invalid'],
    [{ ...sealed, seal: { ...sealed.seal, alg: 'sha1' } }, 'grant_file_seal_invalid'],
    [{ ...sealed, seal: { ...sealed.seal, v: 99 } }, 'grant_file_seal_invalid'],
    [{ ...sealed, seal: { ...sealed.seal, mac: 'not-hex-at-all'.padEnd(64, '0') } },
      'grant_file_seal_invalid'],
    [{ ...sealed, seal: { ...sealed.seal, kdf: { ...sealed.seal.kdf, N: 1024 } } },
      'grant_file_seal_invalid'],
    [{ ...sealed, seal: { ...sealed.seal, kdf: { ...sealed.seal.kdf, salt: Buffer.alloc(4).toString('base64') } } },
      'grant_file_seal_invalid'],
  ];
  for (const [candidate, reason] of cases) {
    const dir = tmpDir();
    const file = writeDoc(dir, candidate);
    assert.throws(() => loadGrantFile(file, { sealKeyFor: keyProvider() }),
      new RegExp(reason), `expected ${reason} for ${JSON.stringify(candidate.seal)}`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('reformatting does not invalidate the seal; reordering keys does not either', () => {
  const doc = grantDoc(
    Keypair.generate().publicKey.toBase58(),
    Keypair.generate().publicKey.toBase58(),
  );
  const sealed = sealDocument(doc, PASSPHRASE);
  const key = deriveSealKey(PASSPHRASE, parseSeal(sealed).salt);
  // Compact vs pretty, and reversed key order at the top level.
  const resealed = JSON.parse(JSON.stringify(sealed).replace(/\n|\s{2}/g, ''));
  const reordered = { seal: sealed.seal, grants: sealed.grants, version: sealed.version };
  assert.equal(verifySealMac(resealed, key).ok, true, 'whitespace is not payload');
  assert.equal(verifySealMac(reordered, key).ok, true, 'key order is not payload');
  // But a VALUE change after reformatting is still caught.
  resealed.grants.ops.maxLamports = '1';
  assert.equal(verifySealMac(resealed, key).reason, 'grant_file_seal_mismatch');
});

test('the seal key provider caches per salt (one scrypt per reseal, not per request)', () => {
  const doc = grantDoc(
    Keypair.generate().publicKey.toBase58(),
    Keypair.generate().publicKey.toBase58(),
  );
  const sealed = sealDocument(doc, PASSPHRASE);
  const salt = parseSeal(sealed).salt;
  const provider = keyProvider();
  const a = provider(salt);
  const b = provider(salt);
  assert.equal(a, b, 'same buffer instance expected from the cache');
  const start = process.hrtime.bigint();
  for (let i = 0; i < 1000; i += 1) provider(salt);
  const perCallMs = Number(process.hrtime.bigint() - start) / 1e6;
  // 1000 cached lookups must cost far less than a single scrypt (~60ms).
  assert.ok(perCallMs < 50, `cached lookups took ${perCallMs.toFixed(1)}ms for 1000 calls`);
});

// ----------------------------------------------------------- load-time level

test('load-time: forged grants are refused even though owner/mode/lease are clean', () => {
  const signer = Keypair.generate().publicKey.toBase58();
  const honest = Keypair.generate().publicKey.toBase58();
  const attacker = Keypair.generate().publicKey.toBase58();
  const dir = tmpDir();
  const file = writeDoc(dir, sealDocument(grantDoc(signer, honest), PASSPHRASE));
  // Baseline loads.
  assert.deepEqual(loadGrantFile(file, { sealKeyFor: keyProvider() }).names, ['ops']);

  // The p2 attack: grants rewritten in place, mode stays 0600, owner stays
  // us, no writer holds the file open. Only the BYTES changed.
  const forged = JSON.parse(fs.readFileSync(file, 'utf8'));
  forged.grants.ops.destination = attacker;
  forged.grants.ops.maxLamports = '999999999999';
  fs.writeFileSync(file, JSON.stringify(forged, null, 2) + '\n');
  fs.chmodSync(file, 0o600);
  assert.throws(() => loadGrantFile(file, { sealKeyFor: keyProvider() }),
    /grant_file_seal_mismatch/);

  // Stripping the seal entirely (the "simpler" forgery) is refused too.
  delete forged.seal;
  fs.writeFileSync(file, JSON.stringify(forged, null, 2) + '\n');
  fs.chmodSync(file, 0o600);
  assert.throws(() => loadGrantFile(file, { sealKeyFor: keyProvider() }),
    /grant_file_unsealed/);

  // Wrong passphrase: the operator's own seal does not open with another key.
  fs.writeFileSync(file, JSON.stringify(sealDocument(grantDoc(signer, honest), WRONG_PASSPHRASE)) + '\n');
  fs.chmodSync(file, 0o600);
  assert.throws(() => loadGrantFile(file, { sealKeyFor: keyProvider() }),
    /grant_file_seal_mismatch/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// --------------------------------------------------------------- daemon level

async function startSealedDaemon(dir, name) {
  const keystore = path.join(dir, `${name}.key`);
  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const honest = Keypair.generate().publicKey;
  const attacker = Keypair.generate().publicKey;
  const doc = sealDocument(
    grantDoc(keypair.publicKey.toBase58(), honest.toBase58()), PASSPHRASE);
  const grantFile = writeDoc(dir, doc, `${name}-grants.json`);
  const socketPath = path.join(dir, `${name}.sock`);
  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, `${name}-journal.jsonl`),
    grantSealPassphrase: PASSPHRASE,
  });
  await daemon.start();
  return { daemon, socketPath, keypair, honest, attacker, grantFile };
}

test('e2e: the daemon refuses a forged-but-pristine-mode grant file when sealing is on', async () => {
  const dir = tmpDir();
  // The daemon starts against the FORGED file (the attack predates the
  // daemon, exactly like it predates the chmod). If the seal cannot vouch
  // for the bytes, the daemon must not come up signing them.
  const keystore = path.join(dir, 'forge.key');
  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const honest = Keypair.generate().publicKey.toBase58();
  const attacker = Keypair.generate().publicKey.toBase58();
  const sealed = sealDocument(grantDoc(keypair.publicKey.toBase58(), honest), PASSPHRASE);
  const forged = JSON.parse(JSON.stringify(sealed));
  forged.grants.ops.destination = attacker;
  const grantFile = writeDoc(dir, forged, 'forge-grants.json');

  // Grants are validated in the CONSTRUCTOR: a forged document must stop the
  // daemon before it ever binds the socket.
  const build = () => new Daemon({
    socketPath: path.join(dir, 'forge.sock'),
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, 'forge-journal.jsonl'),
    grantSealPassphrase: PASSPHRASE,
  });
  assert.throws(build, (err) => err.code === 'grant_file_seal_mismatch' ||
    /grant_file_seal_mismatch/.test(err.message),
  'the daemon must refuse to start on a forged sealed document');

  // And the same document without a seal is equally refused.
  delete forged.seal;
  fs.writeFileSync(grantFile, JSON.stringify(forged, null, 2) + '\n');
  fs.chmodSync(grantFile, 0o600);
  const build2 = () => new Daemon({
    socketPath: path.join(dir, 'forge2.sock'),
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, 'forge2-journal.jsonl'),
    grantSealPassphrase: PASSPHRASE,
  });
  assert.throws(build2, (err) => err.code === 'grant_file_unsealed' ||
    /grant_file_unsealed/.test(err.message),
  'a missing seal must not be accepted when sealing is required');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('e2e: forged grants during a live run are refused per request, then the honest file works again', async () => {
  const dir = tmpDir();
  const f = await startSealedDaemon(dir, 'live');
  try {
    const before = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.honest),
    });
    assert.equal(before.ok, true, `sealed baseline must sign: ${JSON.stringify(before)}`);

    // Attack while the daemon runs: destination rewritten to the attacker,
    // mode kept 0600, no open writer. The lease is clean; only bytes changed.
    const doc = JSON.parse(fs.readFileSync(f.grantFile, 'utf8'));
    doc.grants.ops.destination = f.attacker.toBase58();
    fs.writeFileSync(f.grantFile, JSON.stringify(doc, null, 2) + '\n');
    fs.chmodSync(f.grantFile, 0o600);

    const forged = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.attacker),
    });
    assert.equal(forged.ok, false, 'a forged sealed document must not authorize signing');
    assert.equal(forged.error, 'grant_file_seal_mismatch');
    assert.equal(forged.signature, undefined, 'a refused request carries no signature');

    // Recovery: the operator re-seals the honest file -> signing resumes.
    const honest = grantDoc(f.keypair.publicKey.toBase58(), f.honest.toBase58());
    fs.writeFileSync(f.grantFile, JSON.stringify(sealDocument(honest, PASSPHRASE), null, 2) + '\n');
    fs.chmodSync(f.grantFile, 0o600);
    const after = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.honest),
    });
    assert.equal(after.ok, true, `reseal must restore signing: ${JSON.stringify(after)}`);
    assert.ok(after.signature);
  } finally {
    await f.daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('FALSE-POSITIVE GUARD: an honestly sealed file behaves exactly like an unsealed one', async () => {
  const dir = tmpDir();
  const f = await startSealedDaemon(dir, 'guard');
  try {
    const signed = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.honest),
    });
    assert.equal(signed.ok, true, JSON.stringify(signed));
    assert.ok(signed.signature);
    assert.equal(signed.amountLamports, '42');

    // And load-time parity: the sealed document yields the same grants as the
    // unsealed one.
    const doc = JSON.parse(fs.readFileSync(f.grantFile, 'utf8'));
    const unsealed = { version: doc.version, grants: doc.grants };
    const dir2 = tmpDir();
    const plain = writeDoc(dir2, unsealed, 'plain.json');
    const sealedNames = loadGrantFile(f.grantFile, { sealKeyFor: keyProvider() }).names;
    const plainNames = loadGrantFile(plain).names;
    assert.deepEqual(sealedNames, plainNames);
    // Legacy path preserved: without seal mode, an unsealed file loads and
    // a sealed file is simply a document with an ignored extra field.
    assert.deepEqual(loadGrantFile(plain).names, ['ops']);
    fs.rmSync(dir2, { recursive: true, force: true });
  } finally {
    await f.daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
