'use strict';

// Sealed grant files: verifiable PROVENANCE for the grant document.
//
// Why this exists (R5-2, probe p2 of adversarial review #5):
//
//   The kernel-enforced read lease (R4-1) proves that NOBODY holds the grant
//   file open for writing at the instant we read it. It cannot say where the
//   BYTES came from. An attacker who had write access to the grant file
//   earlier leaves forged grants behind, the operator then tightens the mode
//   to 0600, and every static check passes - owner, mode, directory, lease -
//   while the daemon signs the attacker's destination. Tightening a mode
//   cannot restore content provenance.
//
//   A seal restores provenance: the grant document carries an HMAC-SHA256
//   over its own canonical payload, keyed by a passphrase-derived key the
//   attacker does not have. Without that passphrase the document cannot be
//   modified or forged: any change to the payload breaks the MAC, and a
//   document WITHOUT a seal is refused when a seal is required.
//
//   The seal lives INSIDE the grant file on purpose. A separate seal file
//   would be a second file an attacker could replace wholesale (new salt,
//   MAC computed under their own passphrase). One document, one MAC, one
//   secret.
//
// What this does NOT do (honest limits):
//   - it is not a signature; it proves only that the document was sealed by
//     a holder of the passphrase and has not changed since;
//   - re-sealing with `signerd seal-grants` TRUSTS the file content it is
//     handed - sealing a forged file makes the forgery valid. The command
//     prints exactly what it sealed for that reason;
//   - it does not protect the journal (R5-2's other half, a keyed journal
//     MAC, is still open);
//   - an attacker with write access to the grant file can still DENY service
//     (that was already true: deleting the file refuses every request).
//
// Performance: scrypt (N=16384, 16 MiB) runs only when the document's salt
// changes - once per daemon start, once per re-seal. Every ordinary request
// pays one HMAC-SHA256 over a small document.

const crypto = require('node:crypto');

// Same shape as the keystore's scrypt parameters: interactive cost, bounded
// memory (N*r*128 = 16 MiB).
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 };

const SEAL_VERSION = 1;
const MAX_CACHED_KEYS = 8;

/**
 * Canonical JSON: object keys sorted, no insignificant whitespace. Two files
 * that differ only in key order or formatting are the SAME payload, so a
 * reformat does not need a reseal - but any change of VALUE does.
 */
function canonicalJson(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (typeof value === 'object') {
    return '{' + Object.keys(value).sort()
      .map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key]))
      .join(',') + '}';
  }
  return JSON.stringify(value);
}

/**
 * The bytes a seal covers: the whole document EXCEPT the seal field. The
 * version is included, so a document cannot be downgraded to an older rule
 * set and still carry a valid MAC.
 */
function canonicalPayload(doc) {
  return Buffer.from(canonicalJson({ version: doc.version, grants: doc.grants }), 'utf8');
}

function deriveSealKey(passphrase, salt) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    const err = new Error('seal_passphrase_required');
    err.code = 'seal_passphrase_required';
    throw err;
  }
  if (!Buffer.isBuffer(salt) || salt.length !== 16) {
    const err = new Error('grant_file_seal_invalid');
    err.code = 'grant_file_seal_invalid';
    throw err;
  }
  return crypto.scryptSync(Buffer.from(passphrase, 'utf8'), salt, SCRYPT.keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem,
  });
}

/**
 * Seal a grant document under a passphrase. Returns a NEW document with the
 * seal field added; the input is not modified. Re-sealing an already-sealed
 * document replaces the old seal over the current content.
 */
function sealDocument(doc, passphrase) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    const err = new Error('grant_file_invalid');
    err.code = 'grant_file_invalid';
    throw err;
  }
  const salt = crypto.randomBytes(16);
  const key = deriveSealKey(passphrase, salt);
  const mac = crypto.createHmac('sha256', key).update(canonicalPayload(doc)).digest('hex');
  const sealed = { version: doc.version, grants: doc.grants };
  sealed.seal = {
    v: SEAL_VERSION,
    alg: 'hmac-sha256',
    kdf: { name: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64') },
    mac,
  };
  return sealed;
}

/**
 * Validate the SHAPE of the seal field and return its 16-byte salt.
 * Structural only - possession of a well-formed seal proves nothing until
 * verifySealMac runs it under a key derived from the passphrase.
 */
function parseSeal(doc) {
  if (doc === null || typeof doc !== 'object') {
    return { ok: false, reason: 'grant_file_invalid' };
  }
  const seal = doc.seal;
  if (seal === undefined) return { ok: false, reason: 'grant_file_unsealed' };
  if (seal === null || typeof seal !== 'object' || Array.isArray(seal) ||
      seal.v !== SEAL_VERSION || seal.alg !== 'hmac-sha256') {
    return { ok: false, reason: 'grant_file_seal_invalid' };
  }
  const kdf = seal.kdf;
  if (kdf === null || typeof kdf !== 'object' || kdf.name !== 'scrypt' ||
      kdf.N !== SCRYPT.N || kdf.r !== SCRYPT.r || kdf.p !== SCRYPT.p ||
      typeof kdf.salt !== 'string' || typeof seal.mac !== 'string' ||
      !/^[0-9a-f]{64}$/.test(seal.mac)) {
    return { ok: false, reason: 'grant_file_seal_invalid' };
  }
  const salt = Buffer.from(kdf.salt, 'base64');
  if (salt.length !== 16) return { ok: false, reason: 'grant_file_seal_invalid' };
  return { ok: true, salt };
}

/**
 * Verify the MAC of a shape-valid seal under an already-derived key.
 */
function verifySealMac(doc, key) {
  if (!Buffer.isBuffer(key) || key.length !== SCRYPT.keylen) {
    return { ok: false, reason: 'grant_file_seal_key_missing' };
  }
  const expected = crypto.createHmac('sha256', key).update(canonicalPayload(doc)).digest('hex');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(doc.seal.mac, 'hex');
  // Constant-time compare: a timing side channel on the MAC would leak the
  // correct bytes one at a time.
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'grant_file_seal_mismatch' };
  }
  return { ok: true };
}

/**
 * A passphrase -> key function with a small salt-keyed cache.
 *
 * The grant file is re-read on EVERY request, so deriving scrypt per request
 * would add ~16 MiB of work to each one. The cache means scrypt runs once
 * per SALT: at daemon start, and once more when the operator re-seals the
 * file while the daemon runs (which changes the salt). A writer who churns
 * salts can force re-derivation - but a writer of the grant file can already
 * refuse every request by deleting it, so this is not a new capability.
 * The cache is capped so churn cannot grow memory without bound.
 */
function makeSealKeyProvider(passphrase) {
  const cache = new Map();
  return function sealKeyFor(salt) {
    const id = salt.toString('base64');
    const hit = cache.get(id);
    if (hit !== undefined) {
      // Refresh insertion order for simple LRU behaviour.
      cache.delete(id);
      cache.set(id, hit);
      return hit;
    }
    const key = deriveSealKey(passphrase, salt);
    cache.set(id, key);
    if (cache.size > MAX_CACHED_KEYS) {
      cache.delete(cache.keys().next().value);
    }
    return key;
  };
}

module.exports = {
  canonicalJson, canonicalPayload, deriveSealKey, sealDocument, parseSeal,
  verifySealMac, makeSealKeyProvider, SEAL_VERSION, SCRYPT, MAX_CACHED_KEYS,
};
