'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createKeystore, loadKeystore } = require('../src/keystore');

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
