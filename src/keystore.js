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
  return writeKeystore({ file, passphrase, secretKey: Keypair.generate().secretKey, overwrite: true });
}

/**
 * Encrypt and write a keystore file at `file` (mode 0600) for an EXISTING
 * secret key. The secret never appears in plaintext on disk.
 *
 * This is deliberately separate from key GENERATION: creating a key and
 * adopting one you already hold are different acts, and only the second one
 * lets an existing key-load site migrate. Both write the same format.
 */
function writeKeystore({ file, passphrase, secretKey, overwrite = false }) {
  if (typeof file !== 'string' || file.length === 0) throw fail('keystore_path_required');
  if (fs.existsSync(file) && !overwrite) throw fail('keystore_exists');
  const secret = Buffer.from(secretKey);
  if (secret.length !== 64) { secret.fill(0); throw fail('secret_key_invalid'); }
  // Validation before anything is written: an invalid secret must not leave a
  // half-written keystore behind. Keypair.fromSecretKey verifies that bytes
  // 32..64 are the public key the first 32 bytes derive.
  let keypair;
  try {
    keypair = Keypair.fromSecretKey(secret);
  } catch {
    secret.fill(0);
    throw fail('secret_key_invalid');
  }
  // Read the public key BEFORE the secret is wiped: web3.js builds the
  // Keypair's publicKey as a view over bytes 32..64 of the same buffer, so
  // zeroing `secret` first would serialise an all-zero public key into the
  // keystore while every signature would still verify — a silent key swap.
  const publicKeyBase58 = bs58.encode(Buffer.from(keypair.publicKey.toBytes()));
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  secret.fill(0); // the plaintext secret is not needed after encryption
  keypair = null; // its publicKey/secretKey were views over `secret`
  const doc = {
    v: VERSION,
    publicKey: publicKeyBase58,
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
 * Parse the secret key out of a plaintext key file the way the tooling that
 * holds them actually stores it:
 *   - a JSON byte array (solana-keygen's id.json, what almost every one of my
 *     own key-load sites does: JSON.parse(readFileSync(path))),
 *   - a base58-encoded 64-byte secret (the SOLANA_PRIVATE_KEY / bs58 form),
 *   - a raw 64-byte file.
 * Returns a Buffer the caller must wipe. Anything else is refused: guessing at
 * key encodings is how a migration silently imports the wrong key.
 */
function parseSecretFile(raw) {
  if (Buffer.isBuffer(raw) && raw.length === 64) return Buffer.from(raw);
  const text = raw.toString('utf8').trim();
  if (text.startsWith('[')) {
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw fail('secret_key_invalid', 'json'); }
    if (!Array.isArray(parsed) || parsed.length !== 64 ||
        parsed.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      throw fail('secret_key_invalid', 'json');
    }
    return Buffer.from(parsed);
  }
  if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(text)) {
    let decoded;
    try { decoded = Buffer.from(bs58.decode(text)); } catch { throw fail('secret_key_invalid', 'base58'); }
    if (decoded.length !== 64) { decoded.fill(0); throw fail('secret_key_invalid', 'base58'); }
    return decoded;
  }
  throw fail('secret_key_invalid');
}

/**
 * Adopt an EXISTING plaintext secret key into an encrypted keystore.
 *
 * This is the migration path: without it, signerd can only ever hold a key it
 * generated itself, and every key-load site that already holds a key is stuck.
 * The plaintext source file is read and encrypted; the in-memory copy is
 * wiped. Nothing is written back to the source, and the source is never
 * deleted: that file may still be in use by something else.
 */
function importKeystore({ file, passphrase, from, overwrite = false }) {
  if (typeof from !== 'string' || from.length === 0) throw fail('import_source_required');
  if (path.resolve(from) === path.resolve(file)) throw fail('import_source_is_target');
  let raw;
  try {
    raw = fs.readFileSync(from);
  } catch (err) {
    throw fail('import_source_unreadable', err.code);
  }
  const sourceMode = fs.statSync(from).mode & 0o777;
  const secret = parseSecretFile(raw);
  raw.fill(0);
  let result;
  try {
    result = writeKeystore({ file, passphrase, secretKey: secret, overwrite });
  } catch (err) {
    secret.fill(0);
    throw err;
  }
  return { ...result, source: from, sourceMode: sourceMode.toString(8) };
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
  // A keystore inside a directory that others can write can be swapped out
  // before it is read: the attacker substitutes their own key and the daemon
  // signs with it. A sticky directory (like /tmp) is fine, because there only
  // the file's own owner may remove it.
  //
  // The check covers BOTH group-writable and world-writable directories, and
  // it also requires the directory to be owned by us: a directory owned by
  // someone else can have its contents replaced no matter how it is chmod'ed.
  const dirPath = path.dirname(path.resolve(file));
  const dirStat = fs.statSync(dirPath);
  const dirMode = dirStat.mode & 0o7777;
  if ((dirMode & 0o022) !== 0 && (dirMode & 0o1000) === 0) {
    throw fail('keystore_dir_mode', dirMode.toString(8));
  }
  if (typeof process.getuid === 'function' &&
      dirStat.uid !== process.getuid() && dirStat.uid !== 0) {
    throw fail('keystore_dir_owner', String(dirStat.uid));
  }
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

module.exports = { createKeystore, loadKeystore, writeKeystore, importKeystore, parseSecretFile };
