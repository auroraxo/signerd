'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createKeystore, loadKeystore, importKeystore, writeKeystore } = require('../src/keystore');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-key-'));
}

test('a created keystore decrypts back to the same key and is not world readable', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'ops.key');
  const created = createKeystore({ file, passphrase: 'correct horse battery staple' });
  const mode = fs.statSync(file).mode & 0o777;
  assert.equal(mode, 0o600, 'keystore must not be group/other accessible');
  const loaded = loadKeystore({ file, passphrase: 'correct horse battery staple' });
  assert.equal(loaded.publicKey.toBase58(), created.publicKey);
  // The secret must not appear in the file in any form.
  const raw = fs.readFileSync(file, 'utf8');
  const secretB58 = require('bs58').encode(loaded.secretKey);
  assert.equal(raw.includes(secretB58), false);
  assert.equal(raw.includes(Buffer.from(loaded.secretKey).toString('base64')), false);
});

test('a wrong passphrase and tampered ciphertext both fail closed', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'right' });
  assert.throws(() => loadKeystore({ file, passphrase: 'wrong' }), /keystore_auth_failed/);
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const bytes = Buffer.from(doc.secret, 'base64');
  bytes[0] ^= 0xff;
  doc.secret = bytes.toString('base64');
  fs.writeFileSync(file, JSON.stringify(doc));
  assert.throws(() => loadKeystore({ file, passphrase: 'right' }), /keystore_auth_failed/);
});

test('a keystore with loose permissions is refused even though decryption would work', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'right' });
  fs.chmodSync(file, 0o644);
  assert.throws(() => loadKeystore({ file, passphrase: 'right' }), /keystore_mode/);
  fs.chmodSync(file, 0o640);
  assert.throws(() => loadKeystore({ file, passphrase: 'right' }), /keystore_mode/);
});

test('an existing keystore is not overwritten silently', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'right' });
  assert.throws(() => createKeystore({ file, passphrase: 'right' }), /keystore_exists/);
  const overwritten = createKeystore({ file, passphrase: 'right', overwrite: true });
  assert.ok(overwritten.publicKey);
});

test('a missing or malformed keystore file fails closed', () => {
  const dir = tmpDir();
  assert.throws(() => loadKeystore({ file: path.join(dir, 'nope.key'), passphrase: 'x' }),
    /keystore_unreadable/);
  const file = path.join(dir, 'bad.key');
  fs.writeFileSync(file, 'not json');
  fs.chmodSync(file, 0o600);
  assert.throws(() => loadKeystore({ file, passphrase: 'x' }), /keystore_invalid/);
});

// ---------------------------------------------------------------------------
// Import: the migration path. Without it signerd can only ever hold a key it
// generated itself, and no site that already holds a key can move over.
// ---------------------------------------------------------------------------

test('an existing solana-keygen id.json imports to the SAME public key', () => {
  const dir = tmpDir();
  const source = path.join(dir, 'id.json');
  const target = path.join(dir, 'ops.key');
  // What the 21 key-load sites actually read: a JSON byte array.
  const keypair = require('@solana/web3.js').Keypair.generate();
  fs.writeFileSync(source, JSON.stringify(Array.from(keypair.secretKey)) + '\n', { mode: 0o600 });

  const out = importKeystore({ file: target, passphrase: 'pw', from: source });
  assert.equal(out.publicKey, keypair.publicKey.toBase58(), 'import must preserve the public key');
  assert.equal(out.source, source);
  assert.equal(out.sourceMode, '600');
  assert.equal(fs.statSync(target).mode & 0o777, 0o600);

  // The decrypted key must be byte-identical to the source: migration may not
  // silently swap the key underneath the operator.
  const loaded = loadKeystore({ file: target, passphrase: 'pw' });
  assert.equal(Buffer.from(loaded.secretKey).equals(Buffer.from(keypair.secretKey)), true);

  // The secret must not appear in the keystore in any encoding.
  const raw = fs.readFileSync(target, 'utf8');
  assert.equal(raw.includes(require('bs58').encode(loaded.secretKey)), false);
  assert.equal(raw.includes(Buffer.from(loaded.secretKey).toString('base64')), false);

  // The plaintext source must be left exactly as it was: signerd adopts a key,
  // it never deletes a file the operator still owns.
  const sourceAfter = JSON.parse(fs.readFileSync(source, 'utf8'));
  assert.equal(sourceAfter.length, 64);
  assert.deepEqual(sourceAfter, Array.from(keypair.secretKey));
});

test('import accepts the base58 and raw-64-byte encodings and rejects everything else', () => {
  const dir = tmpDir();
  const keypair = require('@solana/web3.js').Keypair.generate();
  const secret = Buffer.from(keypair.secretKey);

  const b58File = path.join(dir, 'b58.txt');
  fs.writeFileSync(b58File, require('bs58').encode(secret) + '\n');
  assert.equal(
    importKeystore({ file: path.join(dir, 'a.key'), passphrase: 'pw', from: b58File }).publicKey,
    keypair.publicKey.toBase58());

  const rawFile = path.join(dir, 'raw.bin');
  fs.writeFileSync(rawFile, secret);
  assert.equal(
    importKeystore({ file: path.join(dir, 'b.key'), passphrase: 'pw', from: rawFile }).publicKey,
    keypair.publicKey.toBase58());

  // Wrong length JSON: refused, never guessed at.
  const short = path.join(dir, 'short.json');
  fs.writeFileSync(short, JSON.stringify(Array.from(secret.slice(0, 32))));
  assert.throws(() => importKeystore({ file: path.join(dir, 'c.key'), passphrase: 'pw', from: short }),
    /secret_key_invalid/);

  // Not an array, not base58, not 64 bytes: refused.
  const junk = path.join(dir, 'junk.txt');
  fs.writeFileSync(junk, 'hello world');
  assert.throws(() => importKeystore({ file: path.join(dir, 'd.key'), passphrase: 'pw', from: junk }),
    /secret_key_invalid/);

  // A byte array whose 32..64 half does not match the derived public key:
  // web3.js refuses it, so no half-written keystore is left behind.
  const broken = Buffer.from(secret);
  broken[40] ^= 0xff;
  const brokenFile = path.join(dir, 'broken.json');
  fs.writeFileSync(brokenFile, JSON.stringify(Array.from(broken)));
  const target = path.join(dir, 'e.key');
  assert.throws(() => importKeystore({ file: target, passphrase: 'pw', from: brokenFile }),
    /secret_key_invalid/);
  assert.equal(fs.existsSync(target), false, 'a refused import must not leave a keystore behind');
});

test('import refuses a missing source and refuses to overwrite its own source', () => {
  const dir = tmpDir();
  const source = path.join(dir, 'id.json');
  const target = path.join(dir, 'ops.key');
  const keypair = require('@solana/web3.js').Keypair.generate();
  fs.writeFileSync(source, JSON.stringify(Array.from(keypair.secretKey)) + '\n', { mode: 0o600 });

  assert.throws(
    () => importKeystore({ file: target, passphrase: 'pw', from: path.join(dir, 'nope.json') }),
    /import_source_unreadable/);
  assert.throws(() => importKeystore({ file: target, passphrase: 'pw', from: target, overwrite: true }),
    /import_source_is_target|import_source_unreadable/);

  importKeystore({ file: target, passphrase: 'pw', from: source });
  // Existing target, no overwrite: refused rather than clobbered.
  assert.throws(() => importKeystore({ file: target, passphrase: 'pw', from: source }),
    /keystore_exists/);
  // With overwrite the key is replaced, and decrypts to the new public key.
  const second = require('@solana/web3.js').Keypair.generate();
  fs.writeFileSync(source, JSON.stringify(Array.from(second.secretKey)) + '\n', { mode: 0o600 });
  const replaced = importKeystore({ file: target, passphrase: 'pw', from: source, overwrite: true });
  assert.equal(replaced.publicKey, second.publicKey.toBase58());
});
