'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const bs58 = require('bs58');
const { Keypair } = require('@solana/web3.js');

// scrypt parameters: interactive cost, bounded memory (N*r*128 = 16 MiB).
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 };
const VERSION = 1;

function fail(reason, detail) {
  const err = new Error(detail === undefined ? reason : `${reason}: ${detail}`);
  err.code = reason;
  return err;
}

function deriveKey(passphrase, salt) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) throw fail('passphrase_required');
  return crypto.scryptSync(Buffer.from(passphrase, 'utf8'), salt, SCRYPT.keylen,
    { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem });
}

/**
 * Create an encrypted keystore file at `file` (mode 0600).
 * Format: { v, publicKey (base58, public), kdf, cipher: {iv, tag}, secret (base64) }
 * The secret key never appears in plaintext on disk.
 */
function createKeystore({ file, passphrase, overwrite = false }) {
  if (typeof file !== 'string' || file.length === 0) throw fail('keystore_path_required');
  if (fs.existsSync(file) && !overwrite) throw fail('keystore_exists');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const keypair = Keypair.generate();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(keypair.secretKey)), cipher.final()]);
  const doc = {
    v: VERSION,
    publicKey: bs58.encode(keypair.publicKey.toBytes()),
    kdf: { name: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64') },
    cipher: { name: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') },
    secret: ciphertext.toString('base64'),
  };
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600); // writeFileSync's mode applies on create only
  key.fill(0);
  return { file, publicKey: doc.publicKey };
}

/**
 * Load and decrypt a keystore. Fail closed:
 * - any group/other permission bit -> keystore_mode (a world-readable key file
 *   is refused even though decryption would succeed);
 * - wrong passphrase or tampered bytes -> keystore_auth_failed (GCM tag).
 */
function loadKeystore({ file, passphrase }) {
  if (typeof file !== 'string' || file.length === 0) throw fail('keystore_path_required');
  let raw;
  try {
    raw = fs.readFileSync(file);
  } catch (err) {
    throw fail('keystore_unreadable', err.code);
  }
  const mode = fs.statSync(file).mode & 0o777;
  if ((mode & 0o077) !== 0) throw fail('keystore_mode', mode.toString(8));
  let doc;
  try {
    doc = JSON.parse(raw.toString('utf8'));
  } catch {
    throw fail('keystore_invalid');
  }
  if (doc === null || typeof doc !== 'object' || doc.v !== VERSION) throw fail('keystore_invalid');
  if (typeof doc.secret !== 'string' || typeof doc.cipher !== 'object' || doc.cipher === null ||
      typeof doc.kdf !== 'object' || doc.kdf === null || doc.kdf.name !== 'scrypt' ||
      doc.cipher.name !== 'aes-256-gcm') throw fail('keystore_invalid');
  let salt;
  let iv;
  let tag;
  let ciphertext;
  try {
    salt = Buffer.from(doc.kdf.salt, 'base64');
    iv = Buffer.from(doc.cipher.iv, 'base64');
    tag = Buffer.from(doc.cipher.tag, 'base64');
    ciphertext = Buffer.from(doc.secret, 'base64');
  } catch {
    throw fail('keystore_invalid');
  }
  if (salt.length !== 16 || iv.length !== 12 || tag.length !== 16) throw fail('keystore_invalid');
  const key = deriveKey(passphrase, salt);
  let secret = null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    try {
      secret = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      // GCM tag mismatch: wrong passphrase or tampered ciphertext. Both are
      // reported the same way, so a caller cannot tell them apart.
      throw fail('keystore_auth_failed');
    }
    if (secret.length !== 64) throw fail('keystore_invalid');
    // Keypair.fromSecretKey keeps a reference to this buffer: the key material
    // now lives in the returned keypair, by design (the daemon holds the key
    // for its lifetime). It is only wiped below, when the load fails.
    let keypair;
    try {
      keypair = Keypair.fromSecretKey(secret);
    } catch {
      throw fail('keystore_invalid');
    }
    if (doc.publicKey !== undefined && doc.publicKey !== keypair.publicKey.toBase58()) {
      throw fail('keystore_invalid');
    }
    return keypair;
  } catch (err) {
    if (secret !== null) secret.fill(0);
    throw err;
  } finally {
    key.fill(0); // the KDF output is never needed after decryption
  }
}

module.exports = { createKeystore, loadKeystore };
