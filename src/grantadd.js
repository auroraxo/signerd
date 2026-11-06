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
const { validateGrant, loadGrantFile, MAX_GRANTS } = require('./grantfile');
const { makeSealKeyProvider, sealDocument } = require('./grantseal');

/** lstat without following the final symlink; null when nothing is there. */
function lstatOrNull(target) {
  try {
    return fs.lstatSync(target);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw fail('grant_file_unreadable', err.code);
  }
}

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

  // A SYMLINK at the grant path is refused outright, never followed. The
  // loader refuses it too (O_NOFOLLOW), so writing through one would create
  // the state the product refuses to read - and would place the grant file
  // at a path the operator never named (measured 2026-11-05: a dangling
  // link made grant-add write to the link target OUTSIDE the directory).
  const link = lstatOrNull(resolved);
  if (link !== null && link.isSymbolicLink()) throw fail('grant_file_symlink', resolved);

  if (link !== null) {
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

const MAX_GRANTS_LOCAL = MAX_GRANTS; // single source of truth: src/grantfile.js

/**
 * Add a grant to an EXISTING grant file — the CLI's `--append` path.
 *
 * WHY: measured 2026-11-05, `signerd grant-add` wrote exactly one grant and
 * refused every run against an existing file (`grant_file_exists: <path>`),
 * so a second scope was impossible from the CLI: the loader happily loads a
 * whole map of grants, but no documented command could create one. The
 * message bootstrap already had this capability internally
 * (addGrantToFile); this is the same act for transaction grants, held to
 * the loader's own rules.
 *
 * THE RULE THIS KEEPS: a file that would be refused at `run` time is
 * refused here — grant-add must not write a file the product refuses to
 * read (the keygen-loop lesson). So the write happens only after the
 * PRODUCT's own loader (src/grantfile.js) has accepted the file in full:
 * directory mode and ownership, kernel read lease (nobody holds it open
 * for writing), file owner and mode, schema, every existing grant — and
 * the seal, when a seal passphrase is given.
 *
 * Refuses (nothing is written, ever):
 *   - the new grant is invalid          -> validateGrant's reason
 *   - the name is already in the file   -> grant_exists
 *   - the file is sealed, no passphrase  -> grant_file_sealed
 *     (a rewrite would silently destroy the HMAC provenance);
 *   - a passphrase for a file that carries no seal -> grant_file_unsealed
 *     (--seal-passphrase-file must never imply "seal this file now");
 *   - the current seal does not verify  -> the loader's grant_file_seal_*
 *     reason (never extend content we could not authenticate);
 *   - anything else the loader refuses (mode, owner, directory, lease,
 *     shape, an invalid existing grant) -> the loader's reason;
 *   - the result would exceed the loader's grant cap -> grant_file_invalid.
 *
 * WRITES: temp file in the same directory (O_EXCL, 0600) + fsync + rename.
 * Two properties this buys over a truncate-in-place write:
 *   - a crash can only leave the OLD complete document or the NEW complete
 *     document, never a torn one the daemon would refuse on the next
 *     request;
 *   - the daemon's read lease (F_RDLCK) never conflicts with the write:
 *     src/lease.js — a read lease conflicts only with openers FOR WRITING,
 *     and renaming does not open the target file. A truncate-write would
 *     lose the lease race and fail against a running daemon; the rename
 *     path does not.
 * A stranger holding an open WRITE handle to the old inode (the R4-1
 * shape) cannot stop this write — but they also cannot reach the new
 * content: their descriptor stays on the orphaned inode, and the read
 * lease still refuses their file while they hold it.
 *
 * LIMITS: an appended grant takes effect on the daemon's NEXT request (the
 * loader re-reads every request) — it does not restart or notify the
 * daemon; a sealed file is not extendable by CLI without the passphrase
 * (see extendGrantFile's own rules); a hand-edited sealed file must be
 * re-sealed with `seal-grants`.
 */
function extendGrantFile({ file, name, grant, sealPassphrase }) {
  validateGrant(name, grant);
  const resolved = path.resolve(file);

  // Never follow a symlink here either: the loader refuses one at load time
  // (O_NOFOLLOW), so extending it would write content to a path the product
  // will not read, at a path the operator never named.
  const link = lstatOrNull(resolved);
  if (link !== null && link.isSymbolicLink()) throw fail('grant_file_symlink', resolved);

  if (link === null) {
    // No file yet: creating it is exactly what grant-add already does.
    if (sealPassphrase !== undefined) {
      // --seal-passphrase-file must never silently seal a file it creates.
      throw fail('grant_file_unsealed', resolved);
    }
    return writeGrantFile({ file: resolved, name, grant });
  }

  // Seal presence needs the raw document: loadGrantFile only VERIFIES a
  // seal when a key provider is given and would otherwise ignore it — the
  // one outcome this command must never produce is an unsealed write over
  // a sealed file (the daemon in sealed mode would then refuse the file,
  // or worse, a later reader would not know a seal was ever there).
  let raw;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw fail('grant_file_unreadable', err.code);
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw fail('grant_file_invalid');
  }
  const sealed = doc !== null && typeof doc === 'object' &&
    Object.getOwnPropertyDescriptor(doc, 'seal') !== undefined;
  if (sealed && sealPassphrase === undefined) throw fail('grant_file_sealed', resolved);
  if (!sealed && sealPassphrase !== undefined) throw fail('grant_file_unsealed', resolved);

  // THE JUDGE: the product's loader, with the seal key when the operator
  // gave one. Directory, lease, owner, mode, schema, seal, and every
  // existing grant must all pass before anything is written.
  const options = sealPassphrase === undefined ? {}
    : { sealKeyFor: makeSealKeyProvider(sealPassphrase) };
  const loaded = loadGrantFile(resolved, options);

  if (Object.getOwnPropertyNames(loaded.grants).includes(name)) {
    throw fail('grant_exists', name);
  }
  const existing = Object.getOwnPropertyNames(loaded.grants);
  if (existing.length + 1 > MAX_GRANTS_LOCAL) throw fail('grant_file_invalid', 'too many grants');

  const grants = {};
  for (const key of existing) grants[key] = loaded.grants[key];
  grants[name] = grant;
  const out = sealPassphrase === undefined
    ? { version: 1, grants }
    : sealDocument({ version: 1, grants }, sealPassphrase);

  writeAtomic(resolved, out);
  return {
    file: resolved,
    grant: name,
    appended: true,
    grants: Object.keys(grants).sort(),
    sealed: sealPassphrase !== undefined,
  };
}

/**
 * Remove ONE grant from an existing grant file — the CLI's `grant-remove`.
 *
 * WHY: measured 2026-11-05, the card's honest-limits list said "kein
 * Grant-Entfernen (Handedit)": there was NO command to revoke a scope.
 * `grant-add` could add one, the loader loads a MAP of grants, and the
 * daemon re-reads the file on EVERY request (revocation is supposed to take
 * effect immediately) — yet the operator had to hand-edit a
 * security-relevant JSON file to take a scope away.
 *
 * The hand-edit path is exactly the path this product refuses elsewhere:
 *   - a hand edit can leave the file in a state the daemon refuses at run
 *     time (a broken grant) → the daemon then refuses EVERY request,
 *     including the scopes that were still valid;
 *   - a hand edit of a SEALED file destroys the HMAC provenance, and the
 *     repair (re-seal) is a second hand step;
 *   - a hand edit is a non-atomic truncate: a crash leaves a torn file.
 *
 * THE RULE THIS KEEPS: exactly the same rule extendGrantFile keeps — a file
 * that would be refused at `run` time is refused here. The PRODUCT's own
 * loader (src/grantfile.js) is the judge: directory mode and ownership, the
 * kernel read lease (nobody holds the file open for writing), file owner and
 * mode, schema, every remaining grant, and the seal when a passphrase is
 * given. Nothing is written until the whole file has been accepted.
 *
 * Refuses (nothing is written, ever):
 *   - the grant is not in the file           -> grant_not_found (the refusal
 *     names the grants that ARE in the file);
 *   - the file is sealed and no passphrase    -> grant_file_sealed
 *     (a rewrite would destroy the seal's provenance);
 *   - a passphrase for a file with no seal    -> grant_file_unsealed
 *     (--seal-passphrase-file must never imply "seal this file now");
 *   - the current seal does not verify        -> the loader's
 *     grant_file_seal_* reason (never destroy content we could not
 *     authenticate);
 *   - anything else the loader refuses        -> the loader's reason.
 *
 * WRITES: the same atomic temp+fsync+rename as extendGrantFile — the
 * daemon's read lease (F_RDLCK) never conflicts with the write, so a
 * revocation works against a RUNNING daemon; the removal takes effect on
 * the daemon's NEXT request, with no restart and no signal.
 *
 * A SEALED file is re-sealed as part of the act (the old seal covers
 * content that no longer exists; the new seal covers the content that
 * does), so the file stays loadable in the daemon's sealed mode.
 *
 * LIMITS: the removal is by NAME — it removes the whole scope, it does not
 * narrow a cap (edit the file for that); the surviving grants are copied
 * through byte-identically; a grant that is removed while a request is in
 * flight is judged by the loader's read at the START of that request.
 */
function removeGrantFromFile({ file, name, sealPassphrase }) {
  if (typeof name !== 'string' || !NAME.test(name)) throw fail('grant_name_invalid', String(name));
  const resolved = path.resolve(file);

  // Never follow a symlink: the loader refuses one (O_NOFOLLOW), so writing
  // through it would touch a path the operator never named — the same
  // defect measured on grant-add (2026-11-05).
  const link = lstatOrNull(resolved);
  if (link !== null && link.isSymbolicLink()) throw fail('grant_file_symlink', resolved);
  if (link === null) throw fail('grant_file_unreadable', 'ENOENT');

  // Seal presence needs the raw document: loadGrantFile only VERIFIES a
  // seal when a key provider is given and would otherwise ignore it — the
  // one outcome this command must never produce is an unsealed write over
  // a sealed file.
  let raw;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw fail('grant_file_unreadable', err.code);
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw fail('grant_file_invalid');
  }
  const sealed = doc !== null && typeof doc === 'object' &&
    Object.getOwnPropertyDescriptor(doc, 'seal') !== undefined;
  if (sealed && sealPassphrase === undefined) throw fail('grant_file_sealed', resolved);
  if (!sealed && sealPassphrase !== undefined) throw fail('grant_file_unsealed', resolved);

  // THE JUDGE: the product's loader, with the seal key when the operator
  // gave one. Directory, lease, owner, mode, schema, seal, and every
  // existing grant must all pass before anything is written.
  const options = sealPassphrase === undefined ? {}
    : { sealKeyFor: makeSealKeyProvider(sealPassphrase) };
  const loaded = loadGrantFile(resolved, options);

  const existing = Object.getOwnPropertyNames(loaded.grants);
  if (!existing.includes(name)) {
    const err = fail('grant_not_found', name);
    err.grants = existing.slice().sort();
    throw err;
  }

  // The survivors are copied through BYTE-IDENTICALLY (the grant objects
  // the loader parsed, not a re-serialization of our own): a removal is not
  // a chance to rewrite a grant's content.
  const grants = {};
  for (const key of existing) {
    if (key === name) continue;
    grants[key] = loaded.grants[key];
  }

  const out = sealPassphrase === undefined
    ? { version: 1, grants }
    : sealDocument({ version: 1, grants }, sealPassphrase);

  writeAtomic(resolved, out);
  return {
    file: resolved,
    removed: name,
    grants: Object.keys(grants).sort(),
    sealed: sealPassphrase !== undefined,
  };
}

/**
 * Write a whole grant document atomically: temp file in the SAME directory
 * (O_EXCL so the name cannot be a planted symlink), fsync, fchmod 0600
 * (never umask-inherited), rename. On any failure the temp file is removed
 * and the target keeps its previous bytes.
 */
function writeAtomic(target, doc) {
  const dir = path.dirname(target);
  const tmp = path.join(dir,
    `.${path.basename(target)}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  let fd;
  try {
    fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeFileSync(fd, JSON.stringify(doc, null, 2) + '\n');
    fs.fsyncSync(fd);
    fs.fchmodSync(fd, 0o600); // mode applies at create, but never trust the umask
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, target);
  } catch (err) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    try { fs.unlinkSync(tmp); } catch { /* never existed */ }
    const e = new Error('grant_file_write_failed');
    e.code = 'grant_file_write_failed';
    if (err && err.code) e.detail = err.code;
    throw e;
  }
}

module.exports = {
  buildTxGrant,
  buildMessageGrant,
  validateTxGrantArgs,
  validateMessageGrantArgs,
  writeGrantFile,
  addGrantToFile,
  extendGrantFile,
  removeGrantFromFile,
};
