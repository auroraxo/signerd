'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readUnderLease } = require('./lease');
const { verifySealMac, parseSeal } = require('./grantseal');

const REQUIRED_FIELDS = [
  'signer', 'destination', 'maxLamports', 'expiresAt',
  'windowMaxLamports', 'windowSeconds',
];
// Names that could reach Object.prototype if copied naively. The pattern below
// already excludes them (it must start with an alphanumeric), kept for clarity.
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_GRANTS = 1000;

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
const U64 = /^(0|[1-9][0-9]*)$/;
const EXPIRES = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;

function fail(reason, detail) {
  const err = new Error(detail === undefined ? reason : `${reason}: ${detail}`);
  err.code = reason;
  return err;
}

/**
 * Strict per-grant schema check, run at load time so a typo fails at startup
 * instead of silently weakening a live grant. Value semantics (key validity,
 * canonical expiry, u64 ranges) are re-checked by policy.js/ledger.js on every
 * request; this check makes the file's shape explicit and rejects unknown
 * fields, which are always a mistake in a security-relevant config file.
 */
function validateGrant(name, grant) {
  if (RESERVED.has(name) || !NAME.test(name)) throw fail('grant_name_invalid', name);
  if (grant === null || typeof grant !== 'object' || Array.isArray(grant)) {
    throw fail('grant_invalid', name);
  }
  const own = Object.getOwnPropertyNames(grant);
  for (const field of own) {
    if (!REQUIRED_FIELDS.includes(field)) throw fail('grant_unknown_field', `${name}.${field}`);
  }
  for (const field of REQUIRED_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(grant, field);
    if (descriptor === undefined || !('value' in descriptor) ||
        typeof descriptor.value !== 'string' || descriptor.value.length === 0) {
      throw fail('grant_field_invalid', `${name}.${field}`);
    }
  }
  if (!BASE58.test(grant.signer) || !BASE58.test(grant.destination)) {
    throw fail('grant_field_invalid', `${name}.key`);
  }
  if (!U64.test(grant.maxLamports) || !U64.test(grant.windowMaxLamports) ||
      !U64.test(grant.windowSeconds) || !EXPIRES.test(grant.expiresAt)) {
    throw fail('grant_field_invalid', `${name}.format`);
  }
  // A zero-width window would set cutoff = now and exclude every record at or
  // before now: the cap would silently never engage. Refuse it at load time
  // (the ledger refuses it again per request).
  if (grant.windowSeconds === '0') throw fail('grant_field_invalid', `${name}.windowSeconds`);
}

/**
 * Load a grant file: { "version": 1, "grants": { "<name>": {...}, ... } }.
 * Returns a null-prototype map so `hasOwnProperty`-style lookups on request
 * data can never resolve through Object.prototype, plus the sorted names.
 */
function loadGrantFile(file, options = {}) {
  // options.sealKeyFor: (salt) => key buffer. Provided by the daemon when the
  // operator passed --grant-seal-passphrase-file; then the document MUST
  // carry a valid HMAC seal. Absent: legacy behaviour, unsealed files load.
  const sealKeyFor = typeof (options && options.sealKeyFor) === 'function'
    ? options.sealKeyFor : null;
  const resolved = path.resolve(file);
  // The grant file is re-read on EVERY request (revocation must take effect
  // immediately), so its path has to stay trustworthy for the whole process
  // lifetime, not just at startup. A directory another user can write lets
  // them swap the file between two requests; a directory owned by someone
  // else can be rearranged regardless of its mode.
  let dirStat;
  try {
    dirStat = fs.statSync(path.dirname(resolved));
  } catch (err) {
    // A missing directory means the file cannot exist either; report it the
    // same way as a missing file.
    throw fail('grant_file_unreadable', err.code);
  }
  const dirMode = dirStat.mode & 0o7777;
  if ((dirMode & 0o022) !== 0 && (dirMode & 0o1000) === 0) {
    throw fail('grant_file_dir_mode', dirMode.toString(8));
  }
  if (typeof process.getuid === 'function' &&
      dirStat.uid !== process.getuid() && dirStat.uid !== 0) {
    throw fail('grant_file_dir_owner', String(dirStat.uid));
  }
  // Read THROUGH a kernel-enforced read lease: the helper's fstat describes
  // the inode the bytes actually came from, and it fails outright if any
  // process (of any uid) holds the file open for writing. This replaces both
  // the lstat-then-read sequence and the /proc scan that preceded it - there
  // is no window left in which the path can be swapped or the file opened.
  const { meta, bytes } = readUnderLease(resolved);
  // The mode/owner checks now run on the fd we read, not on a separate lstat
  // of the path: a stat that precedes the read can describe a different file
  // than the one that gets parsed. O_NOFOLLOW in the helper means a symlink
  // at this path is refused (ELOOP -> grant_file_invalid), and a non-regular
  // file is refused too.
  if (typeof process.getuid === 'function' &&
      meta.uid !== process.getuid() && meta.uid !== 0) {
    throw fail('grant_file_owner', String(meta.uid));
  }
  // R3-1: writable by anybody else means the grants - and with them the set
  // of transactions the daemon will sign - may already have been forged.
  // Tightening the mode cannot restore content provenance, so the file is
  // REFUSED outright, exactly like the journal. Readable is harmless (no
  // secret in this file).
  const mode = meta.mode & 0o777;
  if ((mode & 0o022) !== 0) throw fail('grant_file_mode', mode.toString(8));

  let raw;
  try {
    raw = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes);
  } catch (err) {
    throw fail('grant_file_unreadable', err.code);
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw fail('grant_file_invalid');
  }
  if (doc === null || typeof doc !== 'object' || doc.version !== 1 ||
      typeof doc.grants !== 'object' || doc.grants === null || Array.isArray(doc.grants)) {
    throw fail('grant_file_invalid');
  }
  // R5-2 (probe p2): a lease proves nobody holds the file open for writing
  // AT THE INSTANT OF THE READ; it cannot say where the bytes came from. When
  // the operator runs the daemon with a seal passphrase, the document MUST
  // carry a valid HMAC under that passphrase - forged grants left behind
  // before a chmod are refused even though owner, mode, directory and lease
  // all look clean. Unsealed, mismatching and shape-broken documents all
  // fail CLOSED with distinct reasons.
  if (sealKeyFor !== null) {
    const parsed = parseSeal(doc);
    if (!parsed.ok) throw fail(parsed.reason);
    const verdict = verifySealMac(doc, sealKeyFor(parsed.salt));
    if (!verdict.ok) throw fail(verdict.reason);
  }
  const entries = Object.getOwnPropertyNames(doc.grants);
  if (entries.length > MAX_GRANTS) throw fail('grant_file_invalid', 'too many grants');
  const grants = Object.create(null);
  for (const name of entries) {
    if (RESERVED.has(name)) throw fail('grant_name_invalid', name);
    // JSON.parse creates a plain own data property even for "__proto__", but
    // read through the descriptor to be independent of that behaviour.
    const grant = Object.getOwnPropertyDescriptor(doc.grants, name).value;
    validateGrant(name, grant);
    Object.defineProperty(grants, name, { value: grant, enumerable: true, writable: false, configurable: false });
  }
  return { grants, names: Object.keys(grants).sort() };
}

module.exports = { loadGrantFile, validateGrant };
;
