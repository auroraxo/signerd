'use strict';

// seal-journal: turn an EXISTING journal into a sealed (format-4) journal.
//
// What this does, in order - every step is a refusal, never a best effort:
//
//   1. path hygiene for the journal AND its future floor;
//   2. claim the daemon's journal lock: a running daemon must not be racing
//      this rewrite (it would append format-3 records behind our seal, or
//      read the journal we replace);
//   3. read the journal under the same read lease the daemon uses (R4-2);
//   4. PARSE it fully - structure, unkeyed chain, no torn tail. Sealing a
//      forged journal would make the forgery valid, so this refuses first;
//   5. rewrite every record as format 4: same bodies, v=4, plus the keyed
//      chain MAC x. The unkeyed chain hashes change with v, so the whole
//      chain is recomputed from genesis and self-checked before touching
//      disk;
//   6. write the new journal (backup first, rename as commit point), then
//      the seal floor. Order matters: a crash between the two leaves a
//      journal AHEAD of its floor, which the loader accepts; the reverse
//      would look like truncation and brick the daemon;
//   7. print exactly what was sealed (seq range, record count, wire hashes)
//      - the operator must see it, because the command cannot know whether
//      the history it just sealed was honest.
//
// Refuses: while the daemon holds the lock, on format-1 records (migrate
// first), on a torn tail (start the daemon once), on a journal that does not
// parse, and on a missing journal.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  parseJournal, assertJournalPath, chainHash, SEALED_JOURNAL_FORMAT,
  JOURNAL_LEASE_MAX_BYTES, GENESIS_HASH,
} = require('./ledger');
const { readUnderLease } = require('./lease');
const seal = require('./journalseal');

function fail(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

// Claim the daemon's own journal lock (atomic link, never overwrites) for the
// whole seal, so a daemon starting mid-rewrite is refused instead of racing
// the rename. Mirrors migrate.js exactly.
function lockJournal(file) {
  const lockFile = `${file}.lock`;
  const token = crypto.randomBytes(16).toString('hex');
  const claim = `${lockFile}.${token}`;
  const fd = fs.openSync(claim, 'wx', 0o600);
  try {
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, token, startedAt: Date.now() }));
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  try {
    fs.linkSync(claim, lockFile);
  } catch (err) {
    throw fail('ledger_locked', err.code === 'EEXIST' ? 'stop the daemon first' : err.code);
  } finally {
    try { fs.unlinkSync(claim); } catch { /* best effort */ }
  }
  return () => {
    try {
      const owner = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
      if (owner && owner.token === token) fs.unlinkSync(lockFile);
    } catch { /* gone */ }
  };
}

function writeExclusive(file, bytes, mode = 0o600) {
  const fd = fs.openSync(file, 'wx', mode); // never overwrites, never follows a symlink
  try {
    fs.writeSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
}

function sealExistingJournal({ journalFile, passphrase }) {
  if (typeof journalFile !== 'string' || journalFile.length === 0) {
    throw fail('ledger_file_required');
  }
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw fail('journal_seal_passphrase_required');
  }
  const resolved = path.resolve(journalFile);
  assertJournalPath(resolved);

  const key = seal.deriveJournalKey(passphrase);
  const release = lockJournal(resolved);
  try {
    let raw;
    try {
      raw = readUnderLease(resolved, {
        prefix: 'ledger', maxBytes: JOURNAL_LEASE_MAX_BYTES,
      }).bytes;
    } catch (err) {
      if (err && err.detail === 'ENOENT') throw fail('ledger_missing');
      if (err && typeof err.code === 'string' && err.code.startsWith('ledger_')) throw err;
      throw fail('ledger_unreadable');
    }

    // Step 4: verify BEFORE trusting. No key here: the unkeyed chain must
    // already hold, otherwise the forgery would be sealed into truth.
    let parsed;
    try {
      parsed = parseJournal(raw);
    } catch (err) {
      // An already-SEALED journal cannot be parsed without the key (that is
      // the point of the seal). Parse it WITH the key instead: if it
      // verifies, this journal is already sealed and sealing it again would
      // be a no-op.
      if (err.message !== 'ledger_sealed') throw err;
      const verified = parseJournal(raw, { macKey: key });
      const floor = seal.sealAnchor(key, {
        count: verified.seq, head: verified.xHead,
      });
      const existing = seal.readAnchor(seal.anchorPath(resolved));
      if (existing.ok) {
        const check = seal.verifyAnchor(key, existing.doc);
        if (!check.ok) {
          throw fail('ledger_anchor_mismatch',
            'the journal is sealed but its seal floor does not verify under this passphrase');
        }
      }
      return {
        sealed: false, reason: 'already_sealed', records: verified.records.length,
        seq: verified.seq, journal: resolved, floor: { count: floor.count, head: floor.head },
      };
    }
    if (parsed.tailTorn) {
      throw fail('ledger_torn_tail', 'start the daemon once to repair it, then seal-journal');
    }
    if (parsed.legacyRecords > 0) {
      throw fail('ledger_legacy_format',
        'migrate the journal first (signerd migrate), then seal-journal');
    }
    if (parsed.sealedRecords > 0) {
      throw fail('ledger_sealed', 'the journal is partially sealed; refusing to rewrite a mixed journal');
    }

    // Step 5: recompute the chain under v=4 with keyed MACs. Self-check
    // before touching disk.
    const xLines = [];
    let prevH = GENESIS_HASH;
    let prevX = seal.genesisMac(key);
    for (const r of parsed.records) {
      const body = {
        v: SEALED_JOURNAL_FORMAT, s: r.s, t: r.t, w: r.w, m: r.m,
        a: r.a, f: r.f, k: r.k,
      };
      const rec = { ...body, h: chainHash(prevH, body) };
      rec.x = seal.chainMac(key, prevX, rec.h);
      prevH = rec.h;
      prevX = rec.x;
      xLines.push(JSON.stringify(rec));
    }
    const out = Buffer.from(`${xLines.join('\n')}\n`, 'utf8');
    const check = parseJournal(out, { macKey: key });
    if (check.records.length !== parsed.records.length ||
        check.sealedRecords !== parsed.records.length ||
        check.seq !== parsed.seq) {
      throw fail('seal_self_check_failed');
    }
    const floor = seal.sealAnchor(key, { count: parsed.seq, head: prevX });

    // Step 6: backup, replace, then floor. Rename is the commit point.
    const suffix = crypto.randomBytes(8).toString('hex');
    const backup = `${resolved}.pre-seal.${suffix}.bak`;
    const tmp = `${resolved}.seal.${suffix}.tmp`;
    writeExclusive(backup, raw);
    writeExclusive(tmp, out);
    try {
      const now = readUnderLease(resolved, {
        prefix: 'ledger', maxBytes: JOURNAL_LEASE_MAX_BYTES,
      }).bytes;
      if (!now.equals(raw)) throw fail('ledger_changed');
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, resolved);
    } catch (err) {
      try { fs.unlinkSync(tmp); } catch { /* already moved */ }
      throw err;
    }
    try {
      const dfd = fs.openSync(path.dirname(resolved), 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* platform-dependent, same as the journal's own dir fsync */ }
    seal.writeAnchor(seal.anchorPath(resolved), floor);

    // Step 7: what exactly was sealed. The operator must be able to see it.
    return {
      sealed: true,
      journal: resolved,
      anchor: seal.anchorPath(resolved),
      backup,
      records: parsed.records.length,
      seqFrom: 1,
      seqTo: parsed.seq,
      wireSha256: parsed.records.map((r) => r.w),
      floor: { count: floor.count, head: floor.head },
    };
  } finally {
    release();
  }
}

module.exports = { sealExistingJournal };
