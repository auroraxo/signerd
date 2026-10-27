'use strict';

const fs = require('node:fs');

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
function loadGrantFile(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
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
