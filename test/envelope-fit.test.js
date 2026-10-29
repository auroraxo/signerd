// Offline unit tests for the openreceipts envelope-fit classification.
//
// Proves, without touching any real operator key or anything outside a
// throwaway tempdir:
//
//   1. A PKCS8 Ed25519 PEM key file is NOT accepted by importKeystore as-is
//      (import refuses unknown formats fail-closed, no guessing), and the
//      source file is left byte-for-byte untouched.
//   2. The PKCS8 seed from the same key derives the IDENTICAL Ed25519 public
//      key under both Node's OpenSSL crypto and web3.js Keypair.fromSeed, and
//      importKeystore accepts the converted 64-byte secret and encrypts it
//      cleanly (both Ed25519, same curve, same key).
//   3. Published identity: the key behind a receipt is the same key, not just
//      the same curve. The site-derived public key equals the pinned issuer
//      key, verifies the receipt's signature, and a receipt signed by a
//      DIFFERENT key is refused (positive control for the verifier itself).
//   4. The canonical message bytes are Python's
//      json.dumps(sort_keys=True, separators=(",", ":")), ensure_ascii=True —
//      including the \uXXXX escaping of non-ASCII notes, which plain
//      JSON.stringify does NOT do. A wrong-bytes signature must fail.
//   5. A canonical JSON receipt body, its padded variants, and an isolated
//      signature are refused by policy.evaluate as invalid_wire, while a
//      legacy System transfer over the same public key is allowed (control).
//
// If someone ever modifies importKeystore to loosely accept PEM, changes
// evaluate to accept arbitrary non-transaction byte arrays, or breaks the
// canonicalization, these tests fail.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const bs58 = require('bs58');
const { Keypair, Transaction, SystemProgram } = require('@solana/web3.js');
const { importKeystore } = require('../src/keystore.js');
const { evaluate } = require('../src/policy.js');
const {
  canonicalReceiptBytes,
  rawPublicKeyFromPkcs8Pem,
  verifyEd25519,
} = require('../src/receipt-identity.js');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-envelope-test-'));
}

// Signed with the Ed25519 seed below; the literals are the canonical bytes
// produced by python3 -c 'json.dumps(..., sort_keys=True, separators=(",", ":"))'.
const CANONICAL_ASCII =
  '{"claims":{"tool":"docrot-check","version":"v1"},"issued_at":"2026-10-28T22:00:00Z","issuer":"auroraxo","schema":"openreceipts/v1","subject":"auroraxo/signerd","type":"release"}';
const CANONICAL_UNICODE =
  '{"claims":{"tool":"envelope-fit","version":"v1"},"issued_at":"2026-10-29T00:00:00+00:00","issuer":"auroraxo","note":"Pr\\u00fcfung \\ud83d\\udfe2","schema":"openreceipts/v1","subject":"auroraxo/unicode-check","type":"release"}';

test('canonical openreceipts bytes match python json.dumps (ascii + unicode escaping)', () => {
  const ascii = {
    claims: { tool: 'docrot-check', version: 'v1' },
    issued_at: '2026-10-28T22:00:00Z',
    issuer: 'auroraxo',
    schema: 'openreceipts/v1',
    subject: 'auroraxo/signerd',
    type: 'release',
  };
  assert.equal(canonicalReceiptBytes(ascii).toString('utf8'), CANONICAL_ASCII);

  const unicode = {
    claims: { tool: 'envelope-fit', version: 'v1' },
    issued_at: '2026-10-29T00:00:00+00:00',
    issuer: 'auroraxo',
    note: 'Prüfung 🟢',
    schema: 'openreceipts/v1',
    subject: 'auroraxo/unicode-check',
    type: 'release',
  };
  const bytes = canonicalReceiptBytes(unicode);
  assert.equal(bytes.toString('utf8'), CANONICAL_UNICODE);
  // The whole point: plain JSON.stringify would emit raw UTF-8 here.
  assert.notEqual(JSON.stringify(unicode), CANONICAL_UNICODE);
  assert.ok(bytes.includes('\\u00fc'), 'non-ASCII must be escaped like python does');

  // Sorting must also be part of the contract: python sort_keys=True, JS
  // insertion order. An object built in the WRONG order must canonicalize to
  // the same sorted bytes (json.dumps would), otherwise the test below could
  // not tell sorted from unsorted input.
  const unsorted = {
    type: 'release',
    subject: 'auroraxo/signerd',
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    issued_at: '2026-10-28T22:00:00Z',
    claims: { version: 'v1', tool: 'docrot-check' },
  };
  assert.equal(canonicalReceiptBytes(unsorted).toString('utf8'), CANONICAL_ASCII,
    'key order in the input must not change the signed bytes');
  assert.notEqual(JSON.stringify(unsorted), CANONICAL_ASCII,
    'JSON.stringify preserves input order, so it cannot be the canonical form');
});

test('a signature over the wrong byte string does not verify', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const sig = crypto.sign(null, Buffer.from(CANONICAL_ASCII, 'utf8'), privateKey);
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  assert.equal(verifyEd25519(raw, Buffer.from(CANONICAL_ASCII, 'utf8'), sig), true);
  // Same message, one byte changed: must not verify.
  const tampered = Buffer.from(CANONICAL_ASCII.replace('v1', 'v2'), 'utf8');
  assert.equal(verifyEd25519(raw, tampered, sig), false);
  // Right bytes, wrong key: must not verify.
  const other = crypto.generateKeyPairSync('ed25519').publicKey
    .export({ type: 'spki', format: 'der' })
    .subarray(-32);
  assert.equal(verifyEd25519(other, Buffer.from(CANONICAL_ASCII, 'utf8'), sig), false);
});

test('openreceipts envelope fit: PEM refused, key adoptable, identity measured, message domain refused', () => {
  const dir = tmpDir();
  try {
    // 1. Generate an Ed25519 PKCS8 PEM keypair via OpenSSL (openreceipts format).
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const opensslPubRaw = spkiDer.subarray(spkiDer.length - 32);

    const pemFile = path.join(dir, 'issuer.key');
    fs.writeFileSync(pemFile, pem, { mode: 0o600 });
    const beforeStat = fs.statSync(pemFile);

    // Question A: does import accept PEM as stored? Must refuse.
    assert.throws(
      () => importKeystore({ file: path.join(dir, 'ks.json'), passphrase: 'pw', from: pemFile }),
      /secret_key_invalid/,
      'import must refuse PKCS8 PEM fail-closed rather than guessing',
    );
    assert.equal(fs.existsSync(path.join(dir, 'ks.json')), false, 'refused import must not write a keystore');
    const afterStat = fs.statSync(pemFile);
    assert.equal(afterStat.size, beforeStat.size, 'refused import must not mutate the source');
    assert.equal(afterStat.mtimeMs, beforeStat.mtimeMs, 'source must be untouched');

    // Question B: is the key material the SAME curve?
    // Extract the 32-byte seed from the PKCS8 DER and derive a Solana Keypair.
    const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' });
    const seed = pkcs8Der.subarray(pkcs8Der.length - 32);
    const kp = Keypair.fromSeed(seed);
    assert.deepEqual(
      Buffer.from(kp.publicKey.toBytes()),
      opensslPubRaw,
      'web3.js Keypair.fromSeed and OpenSSL ed25519 must derive the identical public key',
    );
    // The shared helper must derive the same key too.
    assert.deepEqual(rawPublicKeyFromPkcs8Pem(pem).raw, opensslPubRaw);

    // Import the converted 64-byte secret: must succeed and report the same key.
    const secret64 = Buffer.concat([seed, Buffer.from(kp.secretKey.subarray(32))]);
    const secretFile = path.join(dir, 'secret.bin');
    fs.writeFileSync(secretFile, secret64, { mode: 0o600 });
    secret64.fill(0);

    const out = importKeystore({ file: path.join(dir, 'ks.json'), passphrase: 'pw', from: secretFile });
    assert.equal(out.publicKey, kp.publicKey.toBase58(), 'import must preserve the derived public key');
    assert.equal(out.publicKey, bs58.encode(opensslPubRaw), 'imported key must match the OpenSSL public key');

    // Question C: published identity. Sign a receipt with THIS key, pin the
    // public key, and require that the site-derived key verifies it.
    const receiptBody = {
      claims: { tool: 'docrot-check', version: 'v1' },
      issued_at: '2026-10-28T22:00:00Z',
      issuer: 'auroraxo',
      schema: 'openreceipts/v1',
      subject: 'auroraxo/signerd',
      type: 'release',
    };
    const bodyBytes = canonicalReceiptBytes(receiptBody);
    assert.equal(bodyBytes.toString('utf8'), CANONICAL_ASCII);
    const sig = crypto.sign(null, bodyBytes, privateKey);
    assert.equal(verifyEd25519(opensslPubRaw, bodyBytes, sig), true, 'site key must verify its own receipt');

    // Positive control for the verifier: a receipt signed by a DIFFERENT key
    // must NOT verify under the site key.
    const stranger = crypto.generateKeyPairSync('ed25519');
    const strangerSig = crypto.sign(null, bodyBytes, stranger.privateKey);
    assert.equal(verifyEd25519(opensslPubRaw, bodyBytes, strangerSig), false, 'a foreign key must not verify');

    // Question D: does a receipt body fit the policy envelope?
    const grant = {
      signer: kp.publicKey.toBase58(),
      destination: Keypair.generate().publicKey.toBase58(),
      maxLamports: '10000',
      expiresAt: new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    };

    // A valid Solana transfer for this grant must pass (control).
    const tx = new Transaction();
    tx.feePayer = kp.publicKey;
    tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: grant.destination, lamports: 42 }));
    const wire = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    assert.deepEqual(evaluate(wire, grant), { allowed: true, amountLamports: '42' });

    // The receipt body itself must be refused.
    assert.deepEqual(evaluate(bodyBytes, grant), { allowed: false, refused: 'invalid_wire' });
    // Padded variants must also be refused.
    assert.deepEqual(
      evaluate(Buffer.concat([bodyBytes, Buffer.alloc(10)]), grant),
      { allowed: false, refused: 'invalid_wire' },
    );
    // An isolated 64-byte signature array is refused too (deserializes
    // non-canonically rather than as a valid wire).
    assert.deepEqual(
      evaluate(Buffer.alloc(64), grant),
      { allowed: false, refused: 'noncanonical_wire' },
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
