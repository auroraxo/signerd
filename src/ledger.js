'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { evaluate, ownField, readClock } = require('./policy');

const MAX_U64 = (1n << 64n) - 1n;

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

function recordBody(record) {
  return [record.s, record.t, record.w, record.a, record.f, record.k].join('\u0000');
}

function chainHash(prevHash, record) {
  return crypto.createHash('sha256')
    .update(prevHash + '\u0000' + recordBody(record)).digest('hex');
}

function validRecord(record, previousSeq, seenFingerprints) {
  if (typeof record !== 'object' || record === null) return false;
  const { s, t, w, a, f, k, h } = record;
  if (!Number.isSafeInteger(s) || s !== previousSeq + 1) return false;
  if (!Number.isSafeInteger(t) || t < 0) return false;
  if (typeof w !== 'string' || !/^[0-9a-f]{64}$/.test(w)) return false;
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) return false;
  if (seenFingerprints.has(w)) return false;
  if (typeof k !== 'string' || k.length === 0) return false;
  return parseU64(a) !== null && parseU64(f) !== null;
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
 */
class Ledger {
  constructor({ file }) {
    if (typeof file !== 'string' || file.length === 0) throw new Error('ledger_file_required');
    this.file = file;
    this.records = [];
    this.fingerprints = new Set();
    this.seq = 0;
    this.lastHash = GENESIS_HASH; // chain head: verification of the next record
    this.fileBytes = 0; // last durable length; append failures roll back to it
    this.poisoned = false;
    // A digest of the durable bytes, not just their length. A size-only check
    // accepted a SAME-SIZE in-place tamper (e.g. "a":"42" -> "a":"12"), which
    // silently changed what the journal says was spent.
    this.digest = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
    this.#load();
  }

  /** Remember the length AND the content of the durable journal bytes. */
  #setDurable(bytes, content) {
    this.fileBytes = bytes;
    this.digest = crypto.createHash('sha256').update(content).digest('hex');
  }

  #load() {
    let raw;
    try {
      raw = fs.readFileSync(this.file);
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw new Error('ledger_unreadable');
    }
    // Locate the torn tail in BYTES, never through a decoded string. Decoding
    // first would turn an invalid byte into U+FFFD (3 bytes) while the raw tail
    // was 1 byte, so the computed offset would be short and the repair would
    // truncate INTO the last durable record and silently drop an approval.
    const lastNewline = raw.lastIndexOf(0x0a);
    const validBytes = lastNewline === -1 ? 0 : lastNewline + 1;
    const tailTorn = validBytes !== raw.length;
    const text = raw.subarray(0, validBytes).toString('utf8');
    // validBytes always ends at a newline (or is 0), so the split's final
    // empty element is padding and never a record.
    const segments = text.split('\n');
    segments.pop();
    for (const line of segments) {
      let record;
      try { record = JSON.parse(line); } catch { throw new Error('ledger_corrupt'); }
      if (!validRecord(record, this.seq, this.fingerprints)) throw new Error('ledger_corrupt');
      // Chain check: a record whose fields were edited in place (same size,
      // same length) no longer hashes to its stored h -> the file was altered
      // after it was written. Distinct from structural corruption so the
      // operator can tell tampering from a bad disk.
      if (chainHash(this.lastHash, record) !== record.h) throw new Error('ledger_tampered');
      this.records.push(record);
      this.fingerprints.add(record.w);
      this.seq = record.s;
      this.lastHash = record.h;
    }
    this.#setDurable(validBytes, raw.subarray(0, validBytes));
    if (tailTorn) this.#repair(validBytes);
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
    // The check compares the CONTENT (length and sha256), not just the
    // length: a same-size in-place edit must not pass as "unchanged".
    let current = null;
    try {
      current = fs.readFileSync(this.file);
    } catch (err) {
      if (err.code !== 'ENOENT') throw failWrite('ledger_write_failed');
      current = Buffer.alloc(0);
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
      throw failWrite('ledger_write_failed');
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

    const fingerprint = crypto.createHash('sha256').update(wire).digest('hex');
    if (this.fingerprints.has(fingerprint)) return refused('replay');

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

    const record = {
      s: this.seq + 1,
      t: nowMs,
      w: fingerprint,
      a: amount.toString(),
      f: BASE_FEE_LAMPORTS.toString(),
      k: scope,
      h: chainHash(this.lastHash, { s: this.seq + 1, t: nowMs, w: fingerprint, a: amount.toString(), f: BASE_FEE_LAMPORTS.toString(), k: scope }),
    };
    try {
      this.#appendLine(record);
    } catch (err) {
      // Nothing entered in-memory state: the caller saw a refusal, so no
      // signature may be produced for this wire under this ledger. The file
      // was rolled back to its last durable length, so the journal stays
      // loadable; if even the rollback failed, the poisoned flag keeps every
      // later approval refused until an operator intervenes.
      const code = err && err.code === 'ledger_inconsistent'
        ? 'ledger_inconsistent'
        : (err && err.code === 'ledger_changed' ? 'ledger_changed' : 'ledger_write_failed');
      return refused(code);
    }
    this.records.push(record);
    this.fingerprints.add(record.w);
    this.seq = record.s;
    this.lastHash = record.h;
    const totalSpent = spent + cost;
    return {
      allowed: true,
      amountLamports: record.a,
      feeLamports: record.f,
      totalLamports: cost.toString(),
      wireSha256: fingerprint,
      seq: record.s,
      windowSpentLamports: totalSpent.toString(),
      windowRemainingLamports: (window.max - totalSpent).toString(),
    };
  }

  snapshot() {
    return { records: this.records.length, seq: this.seq, fingerprints: this.fingerprints.size };
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

module.exports = { Ledger, gate, BASE_FEE_LAMPORTS };
