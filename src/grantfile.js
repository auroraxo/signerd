'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { readUnderLease } = require('./lease');
const { verifySealMac, parseSeal } = require('./grantseal');
const {
  isCanonicalPublicKey, isCanonicalBase64PublicKey, isCanonicalExpiry, isU64,
  isWindowMaxLamports, isWindowSeconds, isMessageCount,
} = require('./grantvalues');

const REQUIRED_FIELDS = [
  'signer', 'destination', 'maxLamports', 'expiresAt',
  'windowMaxLamports', 'windowSeconds',
];
// Message grants (the message-grant envelope, 2026-10-31): a DIFFERENT
// schema for a different act. They speak about a receipt domain, not about
// a Solana destination, so the two field sets are kept disjoint on purpose —
// a grant that mixes them is a mistake in a security-relevant config file
// and is refused, not sorted out at request time.
const MESSAGE_FIELDS = [
  'kind', 'issuer', 'type', 'subject', 'pubkey', 'maxBytes', 'expiresAt',
  'windowMaxMessages', 'windowSeconds',
];
const MESSAGE_OPTIONAL = ['claimKeys'];
// Names that could reach Object.prototype if copied naively. The pattern below
// already excludes them (it must start with an alphanumeric), kept for clarity.
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_GRANTS = 1000;

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
  const kindField = Object.getOwnPropertyDescriptor(grant, 'kind');
  const isMessage = kindField !== undefined && ('value' in kindField);
  if (isMessage) {
    if (kindField.value !== 'message') throw fail('grant_field_invalid', `${name}.kind`);
    for (const field of own) {
      if (!MESSAGE_FIELDS.includes(field) && !MESSAGE_OPTIONAL.includes(field)) {
        // A tx-only field (destination, maxLamports, ...) inside a message
        // grant is refused by the same unknown-field rule.
        throw fail('grant_unknown_field', `${name}.${field}`);
      }
    }
    for (const field of MESSAGE_FIELDS) {
      const descriptor = Object.getOwnPropertyDescriptor(grant, field);
      if (descriptor === undefined || !('value' in descriptor) ||
          typeof descriptor.value !== 'string' || descriptor.value.length === 0) {
        throw fail('grant_field_invalid', `${name}.${field}`);
      }
    }
    if (!NAME.test(grant.issuer) || !NAME.test(grant.type) ||
        !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(grant.subject)) {
      throw fail('grant_field_invalid', `${name}.scope`);
    }
    if (!isCanonicalBase64PublicKey(grant.pubkey)) {
      throw fail('grant_field_invalid', `${name}.pubkey`);
    }
    if (!isU64(grant.maxBytes) || Number(grant.maxBytes) < 1 ||
        Number(grant.maxBytes) > 3072 || !isMessageCount(grant.windowMaxMessages) ||
        !isWindowSeconds(grant.windowSeconds) ||
        !isCanonicalExpiry(grant.expiresAt)) {
      throw fail('grant_field_invalid', `${name}.format`);
    }
    if (Object.getOwnPropertyDescriptor(grant, 'claimKeys')) {
      const value = Object.getOwnPropertyDescriptor(grant, 'claimKeys').value;
      if (typeof value !== 'string') throw fail('grant_field_invalid', `${name}.claimKeys`);
      for (const key of value.split(',')) {
        if (key.length === 0 || !NAME.test(key)) {
          throw fail('grant_field_invalid', `${name}.claimKeys`);
        }
      }
    }
    return;
  }
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
  // The keys must be real 32-byte canonical public keys, not merely base58
  // CHARSET - the runtime parses them with `new PublicKey(v).toBase58() === v`
  // and refuses everything else as invalid_grant. A file that loads but can
  // never sign is the defect this module refuses to write or read
  // (measured 2026-11-08: 16 of 30 create-time values were refused at
  // request time; tools/measure-grant-value-contract.mjs).
  if (!isCanonicalPublicKey(grant.signer) || !isCanonicalPublicKey(grant.destination)) {
    throw fail('grant_field_invalid', `${name}.key`);
  }
  // `isWindowMaxLamports` judges MEANING, not form: a decimal u64 AND a cap
  // at least the base fee (5000), because every approval costs
  // amount + 5000 against the window and a smaller cap can never be
  // satisfied (research/grant-cap-domain-2026-11-09.json).
  if (!isU64(grant.maxLamports) || !isWindowMaxLamports(grant.windowMaxLamports) ||
      !isWindowSeconds(grant.windowSeconds) || !isCanonicalExpiry(grant.expiresAt)) {
    throw fail('grant_field_invalid', `${name}.format`);
  }
}

/**
 * Load a grant file: { "version": 1, "grants": { "<name>": {...}, ... } }.
 * Returns a null-prototype map so `hasOwnProperty`-style lookups on request
 * data can never resolve through Object.prototype, plus the sorted names.
 */
function loadGrantFile(file, options = {}) {
  // options.sealKeyFor: (salt) => key buffer. Provided by the daemon when the
  // operator passed --grant-seal-passphrase-file; then the document MUST
  // carry a valid HMAC seal. Absent: an UNSEALED document loads (the legacy
  // path), but a SEALED one is refused - see the branch below.
  //
  // options.allowSealedWithoutKey: judge a sealed document's payload WITHOUT
  // verifying its seal. Exactly ONE caller may pass it: `seal-grants`, on the
  // documented "edit the file by hand, then re-seal" repair, where the old
  // seal is stale by construction (that is why the operator is re-sealing)
  // and only the payload has to be judged before a fresh seal is written.
  // Never pass it to serve a request: a seal nobody checked is not a seal.
  const sealKeyFor = typeof (options && options.sealKeyFor) === 'function'
    ? options.sealKeyFor : null;
  const allowSealedWithoutKey = options && options.allowSealedWithoutKey === true;
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
  } else if (!allowSealedWithoutKey &&
             Object.getOwnPropertyDescriptor(doc, 'seal') !== undefined) {
    // NO KEY, but the document carries a seal. Measured 2026-11-16 on this
    // tree: this branch used to be skipped entirely, so a sealed grant file
    // was read as if it were unsealed - the GRANT half degraded where the
    // JOURNAL half refuses. After `seal-grants`, tampering with the file and
    // then loading it without a passphrase returned the TAMPERED grants
    // (`status` -> {"ok":true,"sealed":false}), while the same file with the
    // passphrase refused grant_file_seal_mismatch and the sealed JOURNAL with
    // no passphrase refused ledger_sealed. "Never degraded" is one rule for
    // both halves of one seal: a document whose MAC cannot be checked is not
    // readable content, so the seal block must be parsed for a reason and
    // the read refused. Shape is checkable without the key, so a broken seal
    // block still reports grant_file_seal_invalid rather than the missing
    // passphrase - the same two reasons a keyed read would give.
    const parsed = parseSeal(doc);
    if (!parsed.ok) throw fail(parsed.reason);
    throw fail('grant_file_sealed',
      `the grant file carries a seal (${resolved}) but no passphrase was given: ` +
      'pass --grant-seal-passphrase-file <file> to read it');
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

/**
 * WHAT THE OPERATOR SEES after a seal: every field the loader accepted for
 * this grant, in schema order. `seal-grants` prints one of these per grant
 * because sealing a forged file makes the forgery valid — but it used to
 * print a HAND-PICKED SUBSET (`name, signer, destination, maxLamports,
 * expiresAt`): a message grant's whole scope (issuer/type/subject/pubkey/
 * maxBytes/window) came out as `{name, expiresAt}` alone, and a tx grant's
 * rolling window budget — the cap that actually bounds the spend — was
 * invisible (measured 2026-11-15, research/seal-grants-summary-2026-11-15).
 * The lists below ARE the schema, so this summary cannot lag a field the
 * loader accepts.
 */
function grantSummary(name, grant) {
  const summary = { name };
  const isMessage = Object.getOwnPropertyDescriptor(grant, 'kind') !== undefined;
  const fields = isMessage ? MESSAGE_FIELDS : REQUIRED_FIELDS;
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(grant, field);
    if (descriptor !== undefined && 'value' in descriptor) {
      summary[field] = descriptor.value;
    }
  }
  if (isMessage) {
    const optional = Object.getOwnPropertyDescriptor(grant, 'claimKeys');
    if (optional !== undefined && 'value' in optional) summary.claimKeys = optional.value;
  }
  return summary;
}

module.exports = { loadGrantFile, validateGrant, grantSummary, MAX_GRANTS };
;
