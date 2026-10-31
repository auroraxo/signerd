'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { evaluate, ownField, readClock } = require('./policy');
const { readUnderLease } = require('./lease');
const seal = require('./journalseal');

// The journal is loaded and re-read through the same kernel-enforced read
// lease that guards the grant file (R4-2): a write handle that predates a
// chmod can mutate the replay set and the spend budget at any moment, and
// neither the mode bits nor the chain hash say so at the instant we trust the
// bytes. The cap is far above what the append path can sustain (it re-reads
// the whole journal on every approval), so it is a hostile-helper guardrail,
// not the binding size limit; a journal beyond it fails to load rather than
// being truncated.
const JOURNAL_LEASE_MAX_BYTES = 512 * 1024 * 1024;

const MAX_U64 = (1n << 64n) - 1n;

// A legacy wire starts with a compact-u16 signature count (one byte when the
// count is 1), then the 64 signature bytes, then the message.
const SIGNATURE_COUNT_BYTE = 1;
const SIGNATURE_BYTES = 64;
const MESSAGE_OFFSET = SIGNATURE_COUNT_BYTE + SIGNATURE_BYTES;

// The replay identity of a transaction is its MESSAGE, not the bytes the
// client sent.
//
// The 64-byte signature slot is client-controlled and carries no meaning: the
// daemon replaces it. Two wires that differ ONLY in that slot are the same
// transaction message and produce the same signature. Keying the replay set
// on the whole wire therefore let the same message be approved - and signed -
// twice, and the signed artifact was not in the replay set either (a client
// could hand the signed wire back and be approved again).
//
// The message is what the signature commits to, so the message is what must
// be signed at most once. The message image is the wire without its
// signature slot; for any other wire shape the whole wire is used, so an
// unrecognized layout can never collide with a message.
function messageImage(wire) {
  if (wire.length > MESSAGE_OFFSET && wire[0] === SIGNATURE_COUNT_BYTE) {
    return wire.subarray(MESSAGE_OFFSET);
  }
  return wire;
}

// The policy envelope admits exactly one signature and no ComputeBudget
// instruction, so the chain's base fee is fixed at 5000 lamports and no
// prioritization fee can be attached. Every approval is therefore charged
// amount + BASE_FEE_LAMPORTS against the grant's rolling window.
const BASE_FEE_LAMPORTS = 5000n;

function refused(reason, extra) {
  return extra === undefined
    ? { allowed: false, refused: reason }
    : { allowed: false, refused: reason, ...extra };
}

// A refusal with a named code, so the loader's error names reach the
// operator (ledger_mac_short, ledger_anchor_missing, ...).
function ledgerError(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

function parseU64(value) {
  return typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)
    ? (() => { const n = BigInt(value); return n <= MAX_U64 ? n : null; })()
    : null;
}

function failWrite(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

// Strict grant-window parsing: fail closed on anything that is not a plain
// positive decimal string / safe integer. Never coerce. Fields are read
// from the grant's OWN properties only, so a polluted Object.prototype cannot
// supply a window cap. A zero-width window is refused rather than honored:
// cutoff = now would exclude every record at or before now, so a cap of 0
// seconds would silently never engage (fail open).
function parseWindow(grant) {
  const maxField = ownField(grant, 'windowMaxLamports');
  const secondsField = ownField(grant, 'windowSeconds');
  if (!maxField.ok || !secondsField.ok) return null;
  const max = parseU64(maxField.value);
  const seconds = typeof secondsField.value === 'string' &&
    /^(0|[1-9][0-9]*)$/.test(secondsField.value)
    ? Number(secondsField.value) : null;
  if (max === null || seconds === null || !Number.isSafeInteger(seconds) || seconds <= 0) return null;
  return { max, seconds };
}

// Same canonical-expiry rule as policy.js: Date.parse normalizes impossible
// calendar dates, so the round trip must reproduce the input exactly.
function expiryMs(grant) {
  const field = ownField(grant, 'expiresAt');
  if (!field.ok || typeof field.value !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(field.value)) return NaN;
  const timestamp = field.value;
  const expiry = Date.parse(timestamp);
  if (!Number.isFinite(expiry)) return NaN;
  const canonical = new Date(expiry).toISOString();
  const expected = timestamp.replace(/(\.\d{1,3})?Z$/, (_, fraction) =>
    `${fraction ? (fraction + '000').slice(0, 4) : '.000'}Z`);
  return canonical === expected ? expiry : NaN;
}

// The scope key identifies the money destination a grant speaks for. Spend is
// counted per scope, so two grants that share a signer AND a destination share
// one window budget instead of each getting a fresh cap. Grants for different
// destinations are independent, which is what the operator's allowlist means.
function scopeKey(grant) {
  const signerField = ownField(grant, 'signer');
  const destinationField = ownField(grant, 'destination');
  if (!signerField.ok || !destinationField.ok) return null;
  const signer = signerField.value;
  const destination = destinationField.value;
  if (typeof signer !== 'string' || typeof destination !== 'string') return null;
  if (signer.length === 0 || destination.length === 0) return null;
  return `${signer}\u0000${destination}`;
}

// Each record carries the sha256 of its own fields plus the previous
// record's chain hash, so the journal is self-verifying: an in-place edit
// (even a same-size one, e.g. "a":"42" -> "a":"12") breaks the chain at load
// and the constructor fails closed. The body is a fixed field order joined by
// NUL, which is safe because every field is a number or a decimal/hex string.
const GENESIS_HASH = '0'.repeat(64);

// Journal format 2 records BOTH identities:
//   w = sha256 of the raw WIRE - unchanged from format 1, so `w` keeps its
//       meaning across the migration and existing records stay comparable;
//   m = sha256 of the MESSAGE  - the replay identity (one signature per
//       message), which a format-1 record simply does not carry.
// The chain body depends on the format, so a record cannot be silently
// upgraded or downgraded: dropping or adding `v` changes the body and breaks
// the chain hash, which the loader reports as ledger_tampered.
// Journal format 3 (2026-10-29, the migration release) = format 2 + an
// explicit "message identity unknown" marker:
//   v = 3
//   m = sha256 of the MESSAGE, or null when the record's message identity is
//       UNKNOWN. null is only possible for a migrated format-1 row whose
//       original wire the operator explicitly discarded. A null `m` is never
//       added to the message replay set, so it can never collide with a real
//       message hash.
// Journal format 2 (2026-10-29) is still accepted: `v` = 2 and `m` is always a
// real message hash.
//
// The chain body depends on the format, so a record cannot be silently
// upgraded or downgraded: dropping or adding `v` changes the body and breaks
// the chain hash, which the loader reports as ledger_tampered.
const JOURNAL_FORMAT = 3;

// Journal format 4 (2026-10-31, the sealed journal): format 3 plus a keyed
// chain MAC `x` on every record (R5-2 journal half, probes p3/p10/p15).
// A sealed journal is loaded ONLY with the seal key: without it the loader
// refuses (ledger_sealed) rather than trusting unauthenticated history - an
// unkeyed daemon must never believe sealed history, and a sealed daemon must
// believe ONLY sealed history.
const SEALED_JOURNAL_FORMAT = 4;

// Format 2 is still accepted; format 4 = format 3's fields plus `x`.
const FORMAT_V2_FIELDS = ['v', 's', 't', 'w', 'm', 'a', 'f', 'k', 'h'].sort();
const FORMAT_1_FIELDS = ['s', 't', 'w', 'a', 'f', 'k', 'h'].sort();
const FORMAT_4_FIELDS = [...FORMAT_V2_FIELDS, 'x'].sort();

function recordBody(record) {
  // Format 1 (pre-2026-10-29): no `v`, no `m`.
  if (record.v === undefined) {
    return [record.s, record.t, record.w, record.a, record.f, record.k].join('\u0000');
  }
  // Formats 2 and 3: `m` is a hex hash, or null in format 3 ("unknown").
  // A hex string can never be the literal "null", so the body stays
  // unambiguous in both cases.
  const m = record.m === null ? 'null' : record.m;
  return [record.v, record.s, record.t, record.w, m, record.a, record.f, record.k].join('\u0000');
}

function chainHash(prevHash, record) {
  return crypto.createHash('sha256')
    .update(prevHash + '\u0000' + recordBody(record)).digest('hex');
}

const FORMAT_2_FIELDS = FORMAT_V2_FIELDS;

function ownFields(record) {
  return Object.getOwnPropertyNames(record).sort();
}

function sameFields(actual, expected) {
  return actual.length === expected.length && actual.every((f, i) => f === expected[i]);
}

function validRecord(record, previousSeq, seenWires, seenMessages, format) {
  if (typeof record !== 'object' || record === null) return false;
  const { s, t, w, a, f, k, h } = record;
  if (!Number.isSafeInteger(s) || s !== previousSeq + 1) return false;
  if (!Number.isSafeInteger(t) || t < 0) return false;
  if (typeof w !== 'string' || !/^[0-9a-f]{64}$/.test(w)) return false;
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) return false;
  if (typeof k !== 'string' || k.length === 0) return false;
  if (parseU64(a) === null || parseU64(f) === null) return false;
  // Format 4 carries exactly the v3 fields plus the keyed MAC `x`.
  if (format === 4 &&
      (typeof record.x !== 'string' || !/^[0-9a-f]{64}$/.test(record.x))) return false;
  const fields = ownFields(record);
  if (record.v === 2 || record.v === 3 || record.v === 4) {
    if (!sameFields(fields, format === 4 ? FORMAT_4_FIELDS : FORMAT_2_FIELDS)) return false;
    const hexM = typeof record.m === 'string' && /^[0-9a-f]{64}$/.test(record.m);
    // null ("identity unknown") exists only in formats 3 and 4.
    if (!hexM && !((record.v === 3 || record.v === 4) && record.m === null)) return false;
    if (seenWires.has(w)) return false;
    if (hexM && seenMessages.has(record.m)) return false;
    return true;
  }
  // A format-1 record: the wire hash is the only identity it carries.
  if (!sameFields(fields, FORMAT_1_FIELDS)) return false;
  if (seenWires.has(w)) return false;
  return true;
}

/**
 * Parse and verify journal bytes (structure + hash chain). Pure: no repair, no
 * policy about formats. Shared by the loader and the migration tool so both
 * apply identical rules. Throws ledger_corrupt / ledger_tampered.
 */
/**
 * Parse and verify journal bytes (structure + hash chain). Pure: no repair, no
 * policy about formats. Shared by the loader and the migration tool so both
 * apply identical rules. Throws ledger_corrupt / ledger_tampered.
 *
 * options.macKey: the sealed-journal key. When present, every record must be
 *   a format-4 record and its keyed chain MAC `x` is verified, so an edited,
 *   dropped, reordered or re-chained record is refused
 *   (ledger_mac_invalid). When absent, a format-4 record is refused
 *   (ledger_sealed): unauthenticated history is never trusted, and a sealed
 *   journal is never silently degraded into an unsealed one.
 */
function parseJournal(raw, options = {}) {
  // Locate the torn tail in BYTES, never through a decoded string (a decoded
  // invalid byte becomes 3 bytes of U+FFFD and the repair would cut into the
  // last durable record).
  const lastNewline = raw.lastIndexOf(0x0a);
  const validBytes = lastNewline === -1 ? 0 : lastNewline + 1;
  const tailTorn = validBytes !== raw.length;
  const segments = raw.subarray(0, validBytes).toString('utf8').split('\n');
  segments.pop(); // padding after the final newline, never a record
  const records = [];
  const fingerprints = new Set();
  const messageHashes = new Set();
  let seq = 0;
  let lastHash = GENESIS_HASH;
  let legacyRecords = 0;
  let sealedRecords = 0;
  const macKey = Buffer.isBuffer(options.macKey) ? options.macKey : null;
  // The keyed chain starts at a key-dependent genesis, so the first record's
  // MAC is not a constant that an attacker could precompute.
  let prevX = macKey ? seal.genesisMac(macKey) : null;
  let xHead = prevX;
  for (const line of segments) {
    let record;
    try { record = JSON.parse(line); } catch { throw new Error('ledger_corrupt'); }
    const isSealed = record !== null && typeof record === 'object' &&
      record.v === SEALED_JOURNAL_FORMAT;
    // A sealed record without the key: refuse, never accept-and-ignore.
    if (isSealed && !macKey) throw new Error('ledger_sealed');
    if (!validRecord(record, seq, fingerprints, messageHashes,
      isSealed ? SEALED_JOURNAL_FORMAT : undefined)) {
      throw new Error('ledger_corrupt');
    }
    if (chainHash(lastHash, record) !== record.h) throw new Error('ledger_tampered');
    if (isSealed) {
      // The keyed chain: prev_x -> this record's chain hash. The chain hash
      // commits to the record body, so this commits to the body AND to every
      // record before it.
      if (seal.chainMac(macKey, prevX, record.h) !== record.x) {
        throw new Error('ledger_mac_invalid');
      }
      prevX = record.x;
      xHead = record.x;
      sealedRecords += 1;
    }
    records.push(record);
    fingerprints.add(record.w);
    // A null `m` (formats 3/4, identity unknown) never enters the replay set.
    if (typeof record.m === 'string') messageHashes.add(record.m);
    if (record.v === undefined) legacyRecords += 1;
    seq = record.s;
    lastHash = record.h;
  }
  return {
    records, validBytes, tailTorn, legacyRecords, sealedRecords,
    fingerprints, messageHashes, seq, lastHash, xHead,
  };
}

/**
 * Journal hygiene, checked BEFORE the journal is trusted.
 *
 * The journal IS the replay set and the window budget. If another user can
 * write it, they can truncate it: after the next daemon start the replay set
 * and the window are empty, and an already-signed message is signed again.
 * The keystore already refuses a foreign-owned or world-writable file; the
 * journal must refuse the same things, or it is the weaker half of the pair.
 */
function assertJournalPath(file) {
  const resolved = path.resolve(file);
  const dirPath = path.dirname(resolved);
  let dirStat;
  try {
    dirStat = fs.statSync(dirPath);
  } catch {
    // A missing directory is the daemon's job to create; the file cannot
    // exist in it either, so there is nothing foreign to trust yet.
    return;
  }
  if (!dirStat.isDirectory()) throw new Error('ledger_dir_invalid');
  const dirMode = dirStat.mode & 0o7777;
  // A group/world-writable directory lets a stranger replace the journal.
  // A STICKY directory is safe: only the file's own owner may remove it.
  if ((dirMode & 0o022) !== 0 && (dirMode & 0o1000) === 0) {
    throw new Error('ledger_dir_mode');
  }
  if (typeof process.getuid === 'function' &&
      dirStat.uid !== process.getuid() && dirStat.uid !== 0) {
    throw new Error('ledger_dir_owner');
  }
  let stat;
  try {
    // lstat, NOT stat: a symlink at this path can be re-pointed by whoever
    // controls it, so the replay set would live somewhere we do not own.
    stat = fs.lstatSync(resolved);
  } catch (err) {
    if (err.code === 'ENOENT') return;
    throw new Error('ledger_unreadable');
  }
  if (!stat.isFile()) throw new Error('ledger_not_a_file');
  if (typeof process.getuid === 'function' &&
      stat.uid !== process.getuid() && stat.uid !== 0) {
    throw new Error('ledger_owner');
  }
  const mode = stat.mode & 0o777;
  // Group/other WRITABLE is refused outright even though we own the file:
  // somebody else could already have written to it, and the chain hash is
  // unkeyed sha256, so a forged journal validates. Content provenance is
  // broken once a stranger can write - do not read it at all.
  if ((mode & 0o022) !== 0) throw new Error('ledger_mode');
  // Group/other READABLE only leaks what was signed; readers cannot alter the
  // replay set, so we repair it to 0600 instead of bricking an existing
  // journal (the keystore, which is a secret, refuses outright).
  if ((mode & 0o055) !== 0) {
    try { fs.chmodSync(resolved, 0o600); } catch { /* falls through to check */ }
    const repaired = fs.lstatSync(resolved).mode & 0o777;
    if ((repaired & 0o077) !== 0) throw new Error('ledger_mode');
  }
}

/**
 * Append-only, fsync-before-approval spend/replay ledger. This is bookkeeping
 * only: it decides whether an already policy-approved transaction may consume
 * grant budget, and it makes that decision durable before it returns. It does
 * not parse transactions, does not hold keys, and does not sign.
 *
 * Fail-closed semantics:
 * - journal unreadable or a complete record corrupt -> constructor throws,
 *   the owning process must not start;
 * - a torn final line (crash mid-append) is dropped on load: fsync happens
 *   before approval returns, so a torn record was never approved;
 * - an append/fsync failure during approve -> {allowed:false, refused:
 *   'ledger_write_failed'} and nothing enters the in-memory state;
 * - a FAILED append never leaves bytes behind: the journal is rolled back to
 *   the last durable length before the refusal is returned, so the next
 *   approval cannot append after a half-written line (which would make the
 *   journal permanently unloadable). If that rollback itself fails the ledger
 *   poisons itself and refuses every further approval ('ledger_inconsistent').
 * - identical wire bytes are approved at most once, ever (sha256 replay set).
 *
 * Concurrency: single writer, enforced by the owning daemon's pid lock file
 * (`<journal>.lock`). Journal grows without bound (compaction is future work).
 *
 * Trust: the bytes are read through a read lease, so a process that holds the
 * journal open for writing (e.g. a descriptor that survived a chmod) is
 * refused at load and at every append instead of being believed.
 *
 * Since journal format 2 (2026-10-29) there are TWO identities per approval:
 * `w` = sha256 of the raw wire (unchanged from format 1) and `m` = sha256 of
 * the MESSAGE, which is what the signature actually commits to. The message
 * identity is what makes "one signature per transaction message" true: the
 * 64-byte signature slot is client-controlled, so two wires differing only in
 * that slot are one message, and the signed artifact we return has the same
 * message as the input. Format-1 journals carry only `w` and therefore keep
 * only the old wire-level guarantee.
 */
class Ledger {
  constructor({ file, sealPassphrase }) {
    if (typeof file !== 'string' || file.length === 0) throw new Error('ledger_file_required');
    this.file = file;
    this.macKey = null;
    this.xHead = null;
    if (sealPassphrase !== undefined && sealPassphrase !== null) {
      if (typeof sealPassphrase !== 'string' || sealPassphrase.length === 0) {
        throw new Error('journal_seal_passphrase_required');
      }
      // Derived EAGERLY, from a fixed public salt (see journalseal): with a
      // passphrase there is no "journal keeps running unsealed" fallback.
      // Deriving lazily from an anchor that may not exist yet silently
      // downgraded a sealed daemon to the unkeyed path - exactly the hole
      // this feature closes.
      this.macKey = seal.deriveJournalKey(sealPassphrase);
      this.xHead = seal.genesisMac(this.macKey);
    }
    this.records = [];
    this.fingerprints = new Set();
    this.messageHashes = new Set();
    this.seq = 0;
    this.lastHash = GENESIS_HASH; // chain head: verification of the next record
    this.fileBytes = 0; // last durable length; append failures roll back to it
    this.poisoned = false;
    // A digest of the durable bytes, not just their length. A size-only check
    // accepted a SAME-SIZE in-place tamper (e.g. "a":"42" -> "a":"12"), which
    // silently changed what the journal says was spent.
    this.digest = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
    // The journal is the replay set and the window budget: refuse to trust a
    // file somebody else could write, BEFORE reading a single record out of it.
    assertJournalPath(file);
    this.#load();
  }

  /** Remember the length AND the content of the durable journal bytes. */
  #setDurable(bytes, content) {
    this.fileBytes = bytes;
    this.digest = crypto.createHash('sha256').update(content).digest('hex');
  }

  #load() {
    let raw = null;
    try {
      raw = readUnderLease(this.file, {
        prefix: 'ledger', maxBytes: JOURNAL_LEASE_MAX_BYTES,
      }).bytes;
    } catch (err) {
      // A missing journal is the normal first start, not an error - unless a
      // seal floor exists that claims history the file no longer holds (p3:
      // delete-or-truncate to empty). That is refused, not "fresh start".
      if (err && err.detail === 'ENOENT') {
        if (this.macKey) this.#checkAnchorOnMissingJournal();
        return;
      }
      // Fail closed, with the reason intact, for everything the lease probe
      // can name: a held write handle, leases unsupported on this kernel, a
      // file the lease was denied on. The pre-lease code path reported all of
      // these as ledger_unreadable, which hid the refusal an operator needs.
      if (err && typeof err.code === 'string' && err.code.startsWith('ledger_')) {
        throw err;
      }
      throw new Error('ledger_unreadable');
    }
    const parsed = parseJournal(raw, { macKey: this.macKey });
    // FAIL CLOSED on format 1 (R3-2): those records carry no message identity,
    // so loading them would silently break "one message approved at most once,
    // ever" across the upgrade (same message + different signature slot was
    // re-approved). The operator must migrate explicitly.
    if (parsed.legacyRecords > 0) {
      const err = new Error(`ledger_legacy_format: ${parsed.legacyRecords} record(s) carry no message identity; ` +
        `run "signerd migrate --ledger ${this.file} --wires <dir>" (or --discard-legacy to accept the loss explicitly)`);
      err.code = 'ledger_legacy_format';
      throw err;
    }
    if (this.macKey) {
      // Sealed daemon, journal that is not (fully) sealed. Our own tools
      // never produce a mixed journal (seal-journal rewrites every line), so
      // a MIXED chain means records were spliced in without the key.
      if (parsed.sealedRecords !== parsed.records.length) {
        if (parsed.sealedRecords === 0) {
          throw ledgerError('ledger_unsealed_journal',
            `passphrase given but ${parsed.records.length} record(s) are unsealed; ` +
            `run "signerd seal-journal --journal ${this.file} --journal-seal-passphrase-file <file>" ` +
            '(it verifies the existing chain first and prints what it seals)');
        }
        throw ledgerError('ledger_mac_invalid',
          `${parsed.records.length - parsed.sealedRecords} unsealed record(s) spliced into a sealed chain`);
      }
      this.#checkAnchor(parsed);
      this.xHead = parsed.xHead;
    } else {
      // No key, but a seal floor exists: this journal WAS sealed. Loading it
      // without the passphrase would trust history nobody authenticated - and
      // a journal truncated to ZERO records would look like a fresh start.
      // Refuse instead of degrading.
      this.#refuseIfSealFloorExists();
    }
    this.records = parsed.records;
    this.fingerprints = parsed.fingerprints;
    this.messageHashes = parsed.messageHashes;
    this.seq = parsed.seq;
    this.lastHash = parsed.lastHash;
    this.#setDurable(parsed.validBytes, raw.subarray(0, parsed.validBytes));
    if (parsed.tailTorn) this.#repair(parsed.validBytes);
  }

  /**
   * Refuse a journal that has a seal floor when no passphrase was given.
   * The floor is the marker that this journal was ever sealed; without the
   * key its content cannot be verified, so it must not be trusted.
   */
  #refuseIfSealFloorExists() {
    const anchorFile = seal.anchorPath(this.file);
    let exists;
    try {
      exists = seal.assertAnchorPath(anchorFile);
    } catch (err) {
      throw ledgerError(err.code || 'ledger_anchor_invalid', err.message);
    }
    if (!exists) return;
    const read = seal.readAnchor(anchorFile);
    if (!read.ok) throw ledgerError(read.reason, `cannot trust the seal floor ${anchorFile}`);
    throw ledgerError('ledger_sealed',
      `the journal has a seal floor (${anchorFile}) but no passphrase was given: ` +
      'start the daemon with --journal-seal-passphrase-file');
  }

  /**
   * The length floor (R5-2 p3): a chain alone cannot see truncation, because
   * every PREFIX of a valid chain is a valid chain. The anchor says how much
   * history this daemon itself approved; a journal shorter than that is
   * refused.
   *
   * The comparison is deliberately NOT an equality on the head: after a crash
   * between the record write and the anchor write the journal is AHEAD of its
   * anchor. That tail was never reported to a caller (the caller only sees
   * "allowed" after the anchor is durable), so dropping it is safe - and
   * requiring equality would brick the daemon on a crash. The rule is
   * therefore: the journal must contain AT LEAST the anchored prefix, and
   * that prefix must verify.
   */
  #checkAnchor(parsed) {
    const anchorFile = seal.anchorPath(this.file);
    let exists;
    try {
      exists = seal.assertAnchorPath(anchorFile);
    } catch (err) {
      throw ledgerError(err.code || 'ledger_anchor_invalid', err.message);
    }
    if (!exists) {
      // No floor yet. A fresh journal is legitimate; a journal WITH records
      // but no floor is not: the floor is what makes the history provable.
      if (parsed.records.length > 0) {
        throw ledgerError('ledger_anchor_missing',
          `the journal holds ${parsed.records.length} record(s) but its seal floor ${anchorFile} is missing`);
      }
      return;
    }
    const read = seal.readAnchor(anchorFile);
    if (!read.ok) throw ledgerError(read.reason, `cannot trust the seal floor ${anchorFile}`);
    const doc = read.doc;
    const check = seal.verifyAnchor(this.macKey, doc);
    if (!check.ok) {
      throw ledgerError(check.reason,
        `the seal floor ${anchorFile} does not verify under this passphrase`);
    }
    // The anchored prefix must be exactly the first doc.count records, and
    // its keyed chain head must be the anchored head. Verifying the chain of
    // the WHOLE journal already happened in parseJournal (every record's `x`
    // is checked against its predecessor), so reaching this point means the
    // journal's chain is intact; what is left is the LENGTH question.
    if (parsed.records.length < doc.count) {
      throw ledgerError('ledger_mac_short',
        `the journal holds ${parsed.records.length} record(s), the seal floor claims ${doc.count}: ` +
        'history was removed (truncation) or the floor belongs to another journal');
    }
    // The anchored prefix must end at the anchored head: the floor's head is
    // the chain head after exactly doc.count records.
    const anchoredHead = doc.count === 0
      ? seal.genesisMac(this.macKey)
      : parsed.records[doc.count - 1].x;
    if (anchoredHead !== doc.head) {
      throw ledgerError('ledger_anchor_mismatch',
        'the anchored prefix does not end at the anchored chain head');
    }
  }

  /** A journal that is gone entirely, but whose floor still claims history. */
  #checkAnchorOnMissingJournal() {
    const anchorFile = seal.anchorPath(this.file);
    let exists;
    try {
      exists = seal.assertAnchorPath(anchorFile);
    } catch (err) {
      throw ledgerError(err.code || 'ledger_anchor_invalid', err.message);
    }
    if (!exists) return; // no floor, no history: a genuine first start
    const read = seal.readAnchor(anchorFile);
    if (!read.ok) throw ledgerError(read.reason, `cannot trust the seal floor ${anchorFile}`);
    if (read.doc.count === 0) return; // the floor never claimed any record
    throw ledgerError('ledger_mac_short',
      `the journal is missing but its seal floor claims ${read.doc.count} record(s): ` +
      'history was deleted (truncation)');
  }

  #repair(validBytes) {
    let fd;
    try {
      fd = fs.openSync(this.file, 'r+');
      fs.ftruncateSync(fd, validBytes);
      fs.fsyncSync(fd);
    } catch {
      throw new Error('ledger_unreadable');
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }

  /** Roll the file back to the last durable length. Failure poisons the ledger. */
  #rollback(targetBytes) {
    let fd;
    try {
      fd = fs.openSync(this.file, 'r+');
      fs.ftruncateSync(fd, targetBytes);
      fs.fsyncSync(fd);
      return true;
    } catch {
      this.poisoned = true;
      return false;
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }

  #appendLine(record) {
    const line = JSON.stringify(record) + '\n';
    const buffer = Buffer.from(line, 'utf8');
    const startBytes = this.fileBytes;
    // The journal must still be exactly the state this ledger believes in.
    // If another process (or an operator) changed the file since the last
    // append, appending after it would merge into foreign bytes and could
    // make the journal permanently unloadable. Refuse instead.
    //
    // The read goes through the lease as well: a writer that already holds a
    // descriptor on this file could rewrite it after a plain read and before
    // our append, so "unchanged so far" is not a verdict we can vouch for.
    //
    // The check compares the CONTENT (length and sha256), not just the
    // length: a same-size in-place edit must not pass as "unchanged".
    let current = null;
    try {
      current = readUnderLease(this.file, {
        prefix: 'ledger', maxBytes: JOURNAL_LEASE_MAX_BYTES,
      }).bytes;
    } catch (err) {
      if (err && err.detail === 'ENOENT') {
        current = Buffer.alloc(0);
      } else if (err && typeof err.code === 'string' && err.code.startsWith('ledger_')) {
        throw failWrite(err.code);
      } else {
        throw failWrite('ledger_write_failed');
      }
    }
    if (current.length !== startBytes) throw failWrite('ledger_changed');
    if (crypto.createHash('sha256').update(current).digest('hex') !== this.digest) {
      throw failWrite('ledger_changed');
    }
    const existed = fs.existsSync(this.file);
    let fd;
    let opened = false;
    try {
      fd = fs.openSync(this.file, 'a', 0o600);
      opened = true;
      // openSync's mode is masked by the process umask, so set it explicitly:
      // a library must not depend on (or mutate) a host process's umask.
      try { fs.fchmodSync(fd, 0o600); } catch { /* checked below via fstat */ }
      // The path may have been replaced between construction and this append
      // (we only stat'ed the path back then). The bytes we are about to append
      // must go to a file WE own with no group/other access - otherwise the
      // spend record is heading into somebody else's file.
      if (typeof process.getuid === 'function') {
        const stat = fs.fstatSync(fd);
        if (stat.uid !== process.getuid() && stat.uid !== 0) throw failWrite('ledger_insecure');
        if ((stat.mode & 0o077) !== 0) throw failWrite('ledger_insecure');
      }
      // writeSync may write fewer bytes than requested (and can fail after a
      // partial write). Loop until the whole line is in, then fsync.
      let written = 0;
      while (written < buffer.length) {
        written += fs.writeSync(fd, buffer, written, buffer.length - written);
      }
      fs.fsyncSync(fd);
    } catch (err) {
      // A partial line in the MIDDLE of the journal would make every future
      // load fail ('ledger_corrupt'), i.e. the daemon could never start again.
      // Undo whatever reached the file before the failure.
      if (opened && !this.#rollback(startBytes)) {
        throw failWrite('ledger_inconsistent');
      }
      throw err.code === 'ledger_insecure' ? err : failWrite('ledger_write_failed');
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
    this.#setDurable(startBytes + buffer.length, Buffer.concat([current, buffer]));
    if (!existed) {
      // openSync's mode is masked by the process umask, so set it explicitly:
      // a library must not depend on (or mutate) a host process's umask.
      try { fs.chmodSync(this.file, 0o600); } catch { /* best effort */ }
      // Best effort: make the directory entry durable too.
      try {
        const dfd = fs.openSync(path.dirname(path.resolve(this.file)), 'r');
        try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
      } catch { /* platform-dependent; data durability already ensured */ }
    }
  }
  /**
   * Decide whether an already policy-verified amount may consume budget.
   * Callers must have a positive verdict from evaluate() first; this function
   * does not inspect the wire and trusts only the amount string it is given.
   */
  approve({ wire, amountLamports, grant, now = new Date() }) {
    // A rollback failure means the file may hold bytes we cannot account for:
    // no further approval can be made durable, so every request refuses.
    if (this.poisoned) return refused('ledger_inconsistent');
    if ((!Buffer.isBuffer(wire) && !(wire instanceof Uint8Array)) || wire.length === 0) {
      return refused('invalid_wire');
    }
    const amount = parseU64(amountLamports);
    if (amount === null) return refused('invalid_amount');
    const window = parseWindow(grant);
    if (window === null) return refused('invalid_grant_window');
    const scope = scopeKey(grant);
    if (scope === null) return refused('invalid_grant');
    const expiry = expiryMs(grant);
    if (!Number.isFinite(expiry)) return refused('invalid_grant');
    // Same hardened clock as policy.js: read once, real Date only, so a
    // hostile `now` cannot bypass expiry here either.
    const nowMs = readClock(now);
    if (!Number.isFinite(nowMs)) return refused('invalid_clock');
    if (nowMs >= expiry) return refused('expired');

    const fingerprint = messageImage(wire);
    const messageSha256 = crypto.createHash('sha256').update(fingerprint).digest('hex');
    const wireSha256 = crypto.createHash('sha256').update(wire).digest('hex');
    // Replay check on BOTH: message identity (one signature per transaction
    // message) AND wire identity (the raw wire bytes).
    if (this.messageHashes.has(messageSha256)) return refused('replay');
    if (this.fingerprints.has(wireSha256)) return refused('replay');

    // Rolling window over (now - windowSeconds, now], deliberately including
    // any record timestamped in the future: a backwards clock must not shrink
    // already-recorded spend. An absurd window size counts every record.
    const windowMs = window.seconds * 1000;
    const cutoff = Number.isSafeInteger(windowMs) ? nowMs - windowMs : -Infinity;
    let spent = 0n;
    for (const record of this.records) {
      if (record.k === scope && record.t > cutoff) spent += BigInt(record.a) + BigInt(record.f);
    }
    const cost = amount + BASE_FEE_LAMPORTS;
    const remaining = window.max > spent ? window.max - spent : 0n;
    if (spent + cost > window.max) {
      return refused('window_cap', {
        windowSpentLamports: spent.toString(),
        windowRemainingLamports: remaining.toString(),
      });
    }

    const recordBody = {
      v: this.macKey ? SEALED_JOURNAL_FORMAT : JOURNAL_FORMAT,
      s: this.seq + 1,
      t: nowMs,
      w: wireSha256,
      m: messageSha256,
      a: amount.toString(),
      f: BASE_FEE_LAMPORTS.toString(),
      k: scope,
    };
    const record = { ...recordBody, h: chainHash(this.lastHash, recordBody) };
    if (this.macKey) {
      // The keyed chain link. this.xHead is always known here: a sealed
      // daemon either loaded a verified chain or starts at the keyed
      // genesis.
      record.x = seal.chainMac(this.macKey, this.xHead, record.h);
    }
    // Captured so an anchor failure after the record write can undo the
    // record: journal and floor must not diverge in a direction the caller
    // was told is safe.
    const preBytes = this.fileBytes;
    const preDigest = this.digest;
    try {
      this.#appendLine(record);
    } catch (err) {
      // Nothing entered in-memory state: the caller saw a refusal, so no
      // signature may be produced for this wire under this ledger. The file
      // was rolled back to its last durable length, so the journal stays
      // loadable; if even the rollback failed, the poisoned flag keeps every
      // later approval refused until an operator intervenes.
      //
      // Every refusal this ledger can raise is named ledger_*; passing it
      // through keeps the reason visible (ledger_held_writer must not be
      // reported as a generic ledger_write_failed).
      const code = err && typeof err.code === 'string' && err.code.startsWith('ledger_')
        ? err.code
        : 'ledger_write_failed';
      return refused(code);
    }
    // In-memory state advances only after the record is durable AND, in
    // sealed mode, the anchor is durable: the caller's "allowed" therefore
    // implies "sealed history includes it". If the anchor write fails, the
    // journal is rolled back and the approval is refused - a sealed daemon
    // never returns an approval that outlives its floor.
    if (this.macKey && !this.#advanceAnchor(record, preBytes, preDigest)) {
      return refused('ledger_anchor_unwritable');
    }
    this.records.push(record);
    this.fingerprints.add(wireSha256);
    this.messageHashes.add(messageSha256);
    this.seq = record.s;
    this.lastHash = record.h;
    this.xHead = record.x;
    const totalSpent = spent + cost;
    return {
      allowed: true,
      amountLamports: record.a,
      feeLamports: record.f,
      totalLamports: cost.toString(),
      wireSha256,
      messageSha256,
      seq: record.s,
      windowSpentLamports: totalSpent.toString(),
      windowRemainingLamports: (window.max - totalSpent).toString(),
    };
  }

  /**
   * Move the floor forward after the record is durable. Order matters and is
   * deliberate: record first, anchor second, caller told third. A crash
   * between record and anchor leaves the journal AHEAD of the floor, which
   * the loader accepts (the tail was never reported - it is dropped only if
   * it is torn, and kept otherwise because it verifies). The reverse order
   * would put the floor ahead of the journal, which is indistinguishable
   * from truncation and would brick the daemon.
   *
   * If the anchor cannot be written, the just-appended record is rolled
   * back so journal and floor stay identical, and the approval is refused.
   * If even the rollback fails, the poisoned flag refuses every later
   * approval: a sealed daemon fails closed, never "sealed most of the time".
   */
  #advanceAnchor(record, preBytes, preDigest) {
    try {
      seal.writeAnchor(seal.anchorPath(this.file), seal.sealAnchor(this.macKey, {
        count: record.s,
        head: record.x,
      }));
      return true;
    } catch (err) {
      if (this.#rollback(preBytes)) {
        this.fileBytes = preBytes;
        this.digest = preDigest;
      } else {
        this.poisoned = true;
      }
      return false;
    }
  }

  snapshot() {
    return { records: this.records.length, seq: this.seq, fingerprints: this.fingerprints.size };
  }

  /** Records whose message identity is unknown (operator-accepted migration gap). */
  legacyState() {
    let unknown = 0;
    for (const r of this.records) if (r.m === null) unknown += 1;
    return { unknownMessageRecords: unknown };
  }
}

/**
 * The gate that must sit between evaluate() and any future signature path.
 * Fails closed when no ledger is attached: an allowed policy verdict alone
 * is never sufficient to consume budget.
 */
function gate(wire, grant, now = new Date(), ledger) {
  const verdict = evaluate(wire, grant, now);
  if (!verdict.allowed) return verdict;
  if (!ledger || typeof ledger.approve !== 'function') return refused('ledger_unavailable');
  return ledger.approve({ wire, amountLamports: verdict.amountLamports, grant, now });
}

module.exports = {
  Ledger, gate, BASE_FEE_LAMPORTS,
  parseJournal, messageImage, assertJournalPath, chainHash, JOURNAL_FORMAT, GENESIS_HASH,
  JOURNAL_LEASE_MAX_BYTES, SEALED_JOURNAL_FORMAT, anchorPath: seal.anchorPath,
};
