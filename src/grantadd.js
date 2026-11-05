'use strict';
// Create a grant file — the step the documented quickstart was missing
// (measured 2026-11-05).
//
// WHY THIS EXISTS: the README's one-time setup block said it creates "an
// encrypted keystore and a grant file" and then showed `signerd run
// --grants ~/.config/signerd/grants.json` — but nothing in the CLI ever
// created that file and the README never showed the transaction-grant
// schema. A stranger running the documented steps verbatim hit
// `grant_file_unreadable: ENOENT` at the very next command (measured live
// against the v0.2.0 tag: `npm install github:auroraxo/signerd#v0.2.0`
// + the Shape block under umask 0002).
//
// The grant file IS security-relevant config (it says what the daemon may
// sign), so this module keeps the same rules the loader enforces:
//   - the file is written 0600 (never umask-inherited: the keygen-loop
//     lesson from 2026-11-02 — signerd must not manufacture a state it
//     later refuses);
//   - a directory we create is 0700; a directory that already exists is the
//     operator's and is judged by the loader's rules, not rewritten here;
//   - an existing file is never clobbered;
//   - a SEALED grant file is never rewritten (it would destroy the seal's
//     provenance);
//   - the schema is validated by the PRODUCT's own validator
//     (src/grantfile.js validateGrant), so this module cannot invent a
//     grant shape the daemon would refuse.
//
// Nothing here is a security claim: the file it writes is exactly as safe as
// the file an operator would have written by hand, and no less.

const fs = require('node:fs');
const path = require('node:path');
const { validateGrant } = require('./grantfile');

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
const U64 = /^(0|[1-9][0-9]*)$/;
const EXPIRES = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;

function fail(reason, detail) {
  const err = new Error(detail === undefined ? reason : `${reason}: ${detail}`);
  err.code = reason;
  return err;
}

/**
 * Validate the arguments of a transaction grant BEFORE anything is written.
 * Every failure is a named reason, so the CLI can print a repair instead of
 * a stack trace.
 */
function validateTxGrantArgs(args) {
  const out = {};
  if (typeof args.name !== 'string' || !NAME.test(args.name)) throw fail('grant_name_invalid', String(args.name));
  out.name = args.name;
  if (typeof args.signer !== 'string' || !BASE58.test(args.signer)) throw fail('grant_field_invalid', 'signer');
  out.signer = args.signer;
  if (typeof args.destination !== 'string' || !BASE58.test(args.destination)) throw fail('grant_field_invalid', 'destination');
  out.destination = args.destination;
  for (const field of ['maxLamports', 'windowMaxLamports', 'windowSeconds']) {
    const value = args[field];
    if (typeof value !== 'string' || !U64.test(value)) throw fail('grant_field_invalid', field);
    out[field] = value;
  }
  if (out.windowSeconds === '0') throw fail('grant_field_invalid', 'windowSeconds');
  if (typeof args.expiresAt !== 'string' || !EXPIRES.test(args.expiresAt)) throw fail('grant_field_invalid', 'expiresAt');
  out.expiresAt = args.expiresAt;
  return out;
}

/**
 * Validate the arguments of a MESSAGE grant (the openreceipts envelope).
 * The pinned key is the daemon's own public key in standard-padded base64;
 * issuer/type/subject come from the receipt body the operator signs.
 */
function validateMessageGrantArgs(args) {
  const out = {};
  if (typeof args.name !== 'string' || !NAME.test(args.name)) throw fail('grant_name_invalid', String(args.name));
  out.name = args.name;
  for (const field of ['issuer', 'type', 'subject']) {
    const value = args[field];
    if (typeof value !== 'string' || value.length === 0) throw fail('grant_field_invalid', field);
    out[field] = value;
  }
  if (typeof args.pubkey !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(args.pubkey)) {
    throw fail('grant_field_invalid', 'pubkey');
  }
  out.pubkey = args.pubkey;
  if (typeof args.maxBytes !== 'string' || !U64.test(args.maxBytes) || Number(args.maxBytes) < 1) {
    throw fail('grant_field_invalid', 'maxBytes');
  }
  out.maxBytes = args.maxBytes;
  if (typeof args.expiresAt !== 'string' || !EXPIRES.test(args.expiresAt)) throw fail('grant_field_invalid', 'expiresAt');
  out.expiresAt = args.expiresAt;
  if (typeof args.windowMaxMessages !== 'string' || !U64.test(args.windowMaxMessages)) {
    throw fail('grant_field_invalid', 'windowMaxMessages');
  }
  out.windowMaxMessages = args.windowMaxMessages;
  if (typeof args.windowSeconds !== 'string' || !U64.test(args.windowSeconds) || args.windowSeconds === '0') {
    throw fail('grant_field_invalid', 'windowSeconds');
  }
  out.windowSeconds = args.windowSeconds;
  if (args.claimKeys !== undefined) {
    if (typeof args.claimKeys !== 'string') throw fail('grant_field_invalid', 'claimKeys');
    for (const key of args.claimKeys.split(',')) {
      if (key.length === 0 || !NAME.test(key)) throw fail('grant_field_invalid', 'claimKeys');
    }
    out.claimKeys = args.claimKeys;
  }
  return out;
}

/**
 * The grant object in the product's own schema. Validated by the product's
 * own validator below — this module never decides on its own what a valid
 * grant looks like.
 */
function buildTxGrant(args) {
  const v = validateTxGrantArgs(args);
  return {
    signer: v.signer,
    destination: v.destination,
    maxLamports: v.maxLamports,
    expiresAt: v.expiresAt,
    windowMaxLamports: v.windowMaxLamports,
    windowSeconds: v.windowSeconds,
  };
}

function buildMessageGrant(args) {
  const v = validateMessageGrantArgs(args);
  const grant = {
    kind: 'message',
    issuer: v.issuer,
    type: v.type,
    subject: v.subject,
    pubkey: v.pubkey,
    maxBytes: v.maxBytes,
    expiresAt: v.expiresAt,
    windowMaxMessages: v.windowMaxMessages,
    windowSeconds: v.windowSeconds,
  };
  if (v.claimKeys !== undefined) grant.claimKeys = v.claimKeys;
  return grant;
}

/**
 * Write a grant file with exactly one grant in it.
 *
 * Refuses (never overwrites):
 *   - an existing file  -> grant_file_exists
 *   - a sealed file      -> grant_file_sealed (a rewrite would destroy the
 *                           HMAC provenance; re-seal with `seal-grants`)
 *   - a grant the product's validator rejects -> the validator's reason
 */
function writeGrantFile({ file, name, grant }) {
  const resolved = path.resolve(file);
  // The product's validator is the judge of the grant shape.
  validateGrant(name, grant);

  if (fs.existsSync(resolved)) {
    let existing = null;
    try { existing = JSON.parse(fs.readFileSync(resolved, 'utf8')); } catch { /* unreadable/garbage */ }
    if (existing && Object.getOwnPropertyDescriptor(existing, 'seal') !== undefined) {
      throw fail('grant_file_sealed', resolved);
    }
    throw fail('grant_file_exists', resolved);
  }

  const dir = path.dirname(resolved);
  let dirExists = true;
  try {
    fs.statSync(dir);
  } catch (err) {
    if (err.code !== 'ENOENT') throw fail('grant_file_dir_unreadable', err.code);
    dirExists = false;
  }
  if (!dirExists) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dir, 0o700); } catch { /* loader's rules verify */ }
  }

  const doc = { version: 1, grants: { [name]: grant } };
  fs.writeFileSync(resolved, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(resolved, 0o600); // writeFileSync's mode applies on create only
  return { file: resolved, grant: name };
}

/**
 * Add a grant to an EXISTING grant file (used by the message bootstrap):
 * the file is re-read, one grant is added, and the file is written back with
 * the same rules. A sealed file is still refused.
 */
function addGrantToFile({ file, name, grant }) {
  const resolved = path.resolve(file);
  validateGrant(name, grant);
  if (!fs.existsSync(resolved)) {
    return writeGrantFile({ file: resolved, name, grant });
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  } catch {
    throw fail('grant_file_invalid');
  }
  if (doc === null || typeof doc !== 'object' || doc.version !== 1 ||
      typeof doc.grants !== 'object' || doc.grants === null || Array.isArray(doc.grants)) {
    throw fail('grant_file_invalid');
  }
  if (Object.getOwnPropertyDescriptor(doc, 'seal') !== undefined) {
    throw fail('grant_file_sealed', resolved);
  }
  if (Object.getOwnPropertyNames(doc.grants).includes(name)) {
    throw fail('grant_exists', name);
  }
  const grants = {};
  for (const existing of Object.getOwnPropertyNames(doc.grants)) {
    grants[existing] = doc.grants[existing];
  }
  grants[name] = grant;
  const out = { version: 1, grants };
  fs.writeFileSync(resolved, JSON.stringify(out, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(resolved, 0o600);
  return { file: resolved, grant: name };
}

module.exports = {
  buildTxGrant,
  buildMessageGrant,
  validateTxGrantArgs,
  validateMessageGrantArgs,
  writeGrantFile,
  addGrantToFile,
};
