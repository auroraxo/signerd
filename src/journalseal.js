'use strict';

// Sealed journal: verifiable PROVENANCE for the journal file (R5-2, journal
// half).
//
// Why this exists (probes p3, p10, p15 of adversarial review #5):
//
//   The journal IS the replay set AND the window budget. The read lease
//   (R4-2) proves that nobody holds the journal open for writing AT THE
//   INSTANT OF THE READ; the mode/owner checks prove who may open it now.
//   Neither says where the BYTES came from. A stranger who had write access
//   earlier can truncate the journal (p3), write through a MAP_SHARED mapping
//   that survives a chmod (p10), or forge records with a recomputed UNKEYED
//   chain (p15) - the operator then tightens the mode to 0600 and every
//   static check passes while the daemon signs the same message twice or
//   spends past the grant's cap. Tightening a mode cannot restore content
//   provenance.
//
//   The seal restores provenance in two layers:
//
//   1. A KEYED CHAIN over the records. Every record carries `x`, an
//      HMAC-SHA256 under a passphrase-derived key over (previous x, this
//      record's chain hash). The unkeyed chain hash `h` commits to the
//      record body, so `x` commits to the body AND to every record before
//      it. Editing one byte of one record invalidates that record's `x` and
//      every later `x`: a forged or re-chained journal cannot produce a
//      valid chain without the key (p15), and a write through a stale
//      mapping is caught the same way (p10).
//
//   2. An ANCHOR (floor) next to the journal: `<journal>.anchor`, holding
//      the record count and the chain head, sealed with the same key. A
//      chain alone cannot see truncation - every PREFIX of a valid chain is
//      a valid chain - so the anchor says how much history the daemon
//      itself approved. A journal shorter than its anchor is refused
//      (p3).
//
//   Why the anchor is a separate file and not a field in the journal: the
//   truncation attacker removes exactly the journal. A floor inside the file
//   it protects proves nothing.
//
//   Why the anchor is written AFTER the record (never before): an anchor
//   ahead of the journal is what truncation looks like. The commit order is
//   record -> anchor, and a crash in between leaves a journal that is AHEAD
//   of its anchor. That is the benign shape, because the caller only learns
//   "allowed" after the anchor is durable, so an unanchored tail was never
//   reported to anybody. It is dropped on the next load, which restores the
//   exact invariant "anchor.count == journal record count".
//
// What this does NOT do (honest limits):
//   - it is not a signature; it proves only that the journal was sealed by a
//     holder of the passphrase and has not changed since;
//   - sealing an EXISTING journal (`signerd seal-journal`) TRUSTS the
//     content it is handed - sealing a forged journal makes the forgery
//     valid. The command verifies the unkeyed chain first, refuses while a
//     daemon holds the journal lock, and prints exactly what it sealed;
//   - a ROLLBACK of both the journal and the anchor to an older, genuine
//     pair is indistinguishable from an old state. The anchor is therefore
//     born 0600 and refused outright when it is group/other accessible, but
//     a file-local seal cannot beat an attacker who can replace both files
//     with old copies. Closing that needs state outside this directory;
//   - deleting BOTH the journal and the anchor (needs write access to the
//     directory, which the path checks refuse) is indistinguishable from a
//     first start;
//   - the seal key is domain-separated from the grant-file seal key (fixed
//     public salt below), so both seals stay independent even when the
//     operator picks the same passphrase;
//   - it does not protect the keystore.
//
// Performance: scrypt (N=16384, 16 MiB) runs once per daemon start. Every
// append pays one HMAC-SHA256 over 128 bytes plus one atomic anchor rewrite.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Same cost parameters as the grant seal and the keystore: interactive
// cost, bounded memory (N*r*128 = 16 MiB).
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 };

// The salt is FIXED and public on purpose: the secret is the passphrase, and
// a fixed, domain-separated salt means the derived key is stable across
// restarts without being stored anywhere an attacker could touch. It also
// keeps this key distinct from the grant-file seal key (which salts with a
// per-document random salt), so grant seal and journal seal stay independent
// even under one passphrase.
const KEY_SALT = Buffer.from('signerd/journal-seal/v1', 'utf8');

const ANCHOR_VERSION = 1;
const ANCHOR_ALG = 'hmac-sha256';
const CHAIN_LABEL = 'signerd-journal-chain-v1';
const GENESIS_LABEL = 'signerd-journal-genesis-v1';
const MAX_ANCHOR_BYTES = 4096;

// The claim prefix is part of the MAC input, so the anchor cannot be
// reinterpreted under another rule set.
const ANCHOR_PREFIX = 'signerd-journal-anchor';

function fail(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

/** Derive the journal seal key from the operator's passphrase. */
function deriveJournalKey(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw fail('journal_seal_passphrase_required');
  }
  return crypto.scryptSync(Buffer.from(passphrase, 'utf8'), KEY_SALT, SCRYPT.keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem,
  });
}

/** The first link of the keyed chain: a key-dependent constant. */
function genesisMac(key) {
  return crypto.createHmac('sha256', key).update(GENESIS_LABEL).digest('hex');
}

/**
 * The keyed MAC of one record: HMAC over (previous x, this record's chain
 * hash). The record's chain hash already commits to the whole record body,
 * so this commits to the body AND to every record before it. A record that
 * is edited, dropped, reordered or re-chained breaks the chain here.
 */
function chainMac(key, prevX, recordHash) {
  if (!Buffer.isBuffer(key) || key.length !== SCRYPT.keylen) {
    throw fail('journal_seal_key_invalid');
  }
  if (typeof prevX !== 'string' || !/^[0-9a-f]{64}$/.test(prevX)) {
    throw fail('journal_seal_chain_invalid');
  }
  if (typeof recordHash !== 'string' || !/^[0-9a-f]{64}$/.test(recordHash)) {
    throw fail('journal_seal_chain_invalid');
  }
  return crypto.createHmac('sha256', key)
    .update(`${CHAIN_LABEL}\u0000${prevX}\u0000${recordHash}`).digest('hex');
}

/** The anchor path next to a journal file. */
function anchorPath(journalFile) {
  return `${path.resolve(journalFile)}.anchor`;
}

/**
 * The anchor document: what the daemon expects the journal to look like.
 * `count` is the number of records the anchor covers, `head` the keyed chain
 * head after the last of them.
 */
function anchorDocument({ count, head }) {
  return { v: ANCHOR_VERSION, alg: ANCHOR_ALG, count, head };
}

/** The keyed MAC over the anchor's own claim. */
function anchorMac(key, doc) {
  if (!Buffer.isBuffer(key) || key.length !== SCRYPT.keylen) {
    throw fail('journal_seal_key_invalid');
  }
  const claim = `${ANCHOR_PREFIX}|v${doc.v}|count=${doc.count}|head=${doc.head}|`;
  return crypto.createHmac('sha256', key).update(claim).digest('hex');
}

/**
 * Path hygiene for the anchor, stricter than the journal's own: a journal
 * that is merely READABLE leaks nothing (no secret in it), but a readable
 * ANCHOR hands an attacker an old anchor they could restore later to roll
 * the seal back. So group/other access of ANY kind is refused, never
 * repaired. A missing anchor is not an error here: the caller decides what
 * that means. Returns true when the anchor exists, false when it does not.
 */
function assertAnchorPath(file) {
  const resolved = path.resolve(file);
  const dirPath = path.dirname(resolved);
  let dirStat;
  try {
    dirStat = fs.statSync(dirPath);
  } catch {
    return false; // no directory -> no anchor (and no journal either)
  }
  const dirMode = dirStat.mode & 0o7777;
  if ((dirMode & 0o022) !== 0 && (dirMode & 0o1000) === 0) {
    throw fail('ledger_anchor_dir', dirMode.toString(8));
  }
  if (typeof process.getuid === 'function' &&
      dirStat.uid !== process.getuid() && dirStat.uid !== 0) {
    throw fail('ledger_anchor_dir', String(dirStat.uid));
  }
  let stat;
  try {
    stat = fs.lstatSync(resolved); // lstat: a symlink at this path is refused
  } catch (err) {
    if (err.code === 'ENOENT') return false;
    throw fail('ledger_anchor_invalid', err.code);
  }
  if (!stat.isFile()) throw fail('ledger_anchor_invalid', 'not a regular file');
  if (typeof process.getuid === 'function' &&
      stat.uid !== process.getuid() && stat.uid !== 0) {
    throw fail('ledger_anchor_owner', String(stat.uid));
  }
  const mode = stat.mode & 0o777;
  // Not group/other accessible EITHER: see the header. No repair - repairing
  // a possibly-captured anchor cannot un-capture it.
  if ((mode & 0o077) !== 0) throw fail('ledger_anchor_mode', mode.toString(8));
  return true;
}

/**
 * Write the anchor atomically: a temp file in the same directory, fsynced,
 * then renamed over the old anchor, then the directory is fsynced (best
 * effort, exactly like the journal's own directory fsync). A crash leaves
 * either the old or the new anchor - never a half-written one. The temp name
 * is random so a concurrent writer cannot race us onto a name we rename.
 */
function writeAnchor(anchorFile, doc) {
  const dir = path.dirname(path.resolve(anchorFile));
  const tmp = path.join(dir, `.${path.basename(anchorFile)}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    try { fs.fchmodSync(fd, 0o600); } catch { /* checked below */ }
    const buffer = Buffer.from(JSON.stringify(doc) + '\n', 'utf8');
    let written = 0;
    while (written < buffer.length) {
      written += fs.writeSync(fd, buffer, written, buffer.length - written);
    }
    // The anchor decides what the journal says; it must be durable BEFORE it
    // becomes visible at its path.
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, anchorFile); // commit point
  } catch (err) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    try { fs.unlinkSync(tmp); } catch { /* best effort */ }
    throw fail('ledger_anchor_unwritable', err.code || err.message);
  }
  try {
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch { /* platform-dependent; the journal treats its dir fsync the same way */ }
}

/**
 * Read and shape-check the anchor (path hygiene: caller calls
 * assertAnchorPath first). Returns { ok: true, doc } or { ok: false, reason }.
 */
function readAnchor(anchorFile) {
  let raw;
  try {
    raw = fs.readFileSync(anchorFile);
  } catch (err) {
    if (err.code === 'ENOENT') return { ok: false, reason: 'ledger_anchor_missing' };
    return { ok: false, reason: 'ledger_anchor_unreadable' };
  }
  if (raw.length > MAX_ANCHOR_BYTES) return { ok: false, reason: 'ledger_anchor_invalid' };
  let doc;
  try {
    doc = JSON.parse(raw.toString('utf8'));
  } catch {
    return { ok: false, reason: 'ledger_anchor_invalid' };
  }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc) ||
      doc.v !== ANCHOR_VERSION || doc.alg !== ANCHOR_ALG ||
      !Number.isSafeInteger(doc.count) || doc.count < 0 ||
      typeof doc.head !== 'string' || !/^[0-9a-f]{64}$/.test(doc.head) ||
      typeof doc.mac !== 'string' || !/^[0-9a-f]{64}$/.test(doc.mac)) {
    return { ok: false, reason: 'ledger_anchor_invalid' };
  }
  return { ok: true, doc };
}

/**
 * Check the anchor's own claim against the key. A claim that does not verify
 * cannot be believed: the floor is exactly as good as its MAC.
 */
function verifyAnchor(key, doc) {
  if (doc === null || typeof doc !== 'object') {
    return { ok: false, reason: 'ledger_anchor_invalid' };
  }
  if (anchorMac(key, doc) !== doc.mac) {
    return { ok: false, reason: 'ledger_anchor_mismatch' };
  }
  return { ok: true };
}

/** Build a complete, sealed anchor document. */
function sealAnchor(key, { count, head }) {
  const doc = anchorDocument({ count, head });
  doc.mac = anchorMac(key, doc);
  return doc;
}

module.exports = {
  deriveJournalKey, genesisMac, chainMac,
  anchorPath, anchorDocument, sealAnchor, anchorMac, verifyAnchor,
  assertAnchorPath, writeAnchor, readAnchor,
  SCRYPT, KEY_SALT, ANCHOR_VERSION, ANCHOR_ALG, MAX_ANCHOR_BYTES,
};
