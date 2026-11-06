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
const { claimJournalLock } = require('./journal-lock');
const seal = require('./journalseal');

function fail(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

// Claim the daemon's own journal lock (atomic link, never overwrites) for the
// whole seal, so a daemon starting mid-rewrite is refused instead of racing
// the rename. Mirrors migrate.js exactly.
//
// 2026-11-06: this used to be a bare link(2) that refused EVERY EEXIST with
// "stop the daemon first". The daemon has a guarded takeover of a provably
// dead owner, the tools did not - so a daemon killed with SIGKILL (which
// leaves <journal>.lock behind) bricked seal-journal and migrate forever,
// with a message telling the operator to stop a daemon that was not running.
// The shared module now applies the daemon's rule: a LIVE owner refuses, a
// provably DEAD owner is taken over.
function lockJournal(file) {
  return claimJournalLock(file);
}

function writeExclusive(file, bytes, mode = 0o600) {
  const fd = fs.openSync(file, 'wx', mode); // never overwrites, never follows a symlink
  try {
    fs.writeSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
}

/**
 * R6-4c (review #6, p4): does the floor witness THIS journal's chain?
 *
 * The same rule the daemon's #checkAnchor applies: the floor's count must not
 * exceed the chain, and the keyed head after floor.count records must be the
 * floor's head (genesisMac for count 0). Returns null when the floor agrees,
 * or a refusal error naming why it does not. Called only AFTER this tool
 * knows the keyed chain of the journal it was handed - before that point the
 * head question is unanswerable and any answer would be a guess.
 */
function checkFloorAgainstChain(floorDoc, keyedHeads, seq, key, anchorPath) {
  if (floorDoc.count > seq) {
    return fail('ledger_mac_short',
      `the journal holds ${seq} record(s), the seal floor ${anchorPath} claims ${floorDoc.count}: ` +
      'history was removed (truncation)');
  }
  const anchoredHead = floorDoc.count === 0
    ? seal.genesisMac(key)
    : keyedHeads[floorDoc.count - 1];
  if (anchoredHead !== floorDoc.head) {
    return fail('ledger_anchor_mismatch',
      `the seal floor ${anchorPath} does not witness this journal's history ` +
      `(floor head ${floorDoc.head.slice(0, 12)}..., journal head ${String(anchoredHead).slice(0, 12)}...): ` +
      'the journal was replaced, or the floor belongs to another journal');
  }
  return null;
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
      const anchorPath = seal.anchorPath(resolved);
      let exists;
      try {
        exists = seal.assertAnchorPath(anchorPath);
      } catch (anchorErr) {
        throw fail(anchorErr.code || 'ledger_anchor_invalid', anchorErr.message);
      }
      if (exists) {
        // R6-4a (review #6, p4): the floor must WITNESS this journal, not
        // merely be authentic. The same three questions the daemon's
        // #checkAnchor asks are asked here, so the tool and the daemon agree
        // on what state they are in.
        const existing = seal.readAnchor(anchorPath);
        if (!existing.ok) {
          throw fail(existing.reason, `cannot read the seal floor ${anchorPath}`);
        }
        const check = seal.verifyAnchor(key, existing.doc);
        if (!check.ok) {
          throw fail('ledger_anchor_mismatch',
            'the journal is sealed but its seal floor does not verify under this passphrase');
        }
        const countCheck = checkFloorAgainstChain(existing.doc,
          verified.records.map((r) => r.x), verified.seq, key, anchorPath);
        if (countCheck !== null) throw countCheck;
      } else {
        // R6-4b (review #6, p4): the daemon refuses to start with
        // ledger_anchor_missing, and the recovery tool used to print
        // already_sealed and leave the brick in place. The journal itself
        // verified record by record under this key, so the floor is derived
        // from authenticated history - create it and SAY so. Residual limit:
        // a floor deleted together with truncation beforehand is undetectable
        // here (the marker is gone); that limit is documented, not papered
        // over.
        seal.writeAnchor(anchorPath, floor);
        return {
          sealed: false, reason: 'already_sealed', floorRepaired: true,
          records: verified.records.length, seq: verified.seq, journal: resolved,
          floor: { count: floor.count, head: floor.head },
        };
      }
      return {
        sealed: false, reason: 'already_sealed', floorRepaired: false,
        records: verified.records.length, seq: verified.seq, journal: resolved,
        floor: { count: floor.count, head: floor.head },
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

    // R6-4c (review #6, p4/c1, c5): the seal floor is the operator's witness
    // over history, so before rewriting the journal the existing floor (if
    // any) is read and checked with the SAME three questions the daemon asks:
    // authentic under this passphrase, not longer than the journal, and its
    // head at floor.count must be the journal's keyed head at that point.
    // The head comparison is deferred to after step 5 - only there does this
    // tool know what keyed head THIS journal yields; without it case5 (a
    // forged journal handed to the tool beside the operator's genuine floor)
    // would pass every earlier check and be laundered into acceptance.
    const anchorPath = seal.anchorPath(resolved);
    let anchorExists;
    try {
      anchorExists = seal.assertAnchorPath(anchorPath);
    } catch (anchorErr) {
      throw fail(anchorErr.code || 'ledger_anchor_invalid', anchorErr.message);
    }
    const preexisting = anchorExists ? seal.readAnchor(anchorPath) : null;
    if (anchorExists && !preexisting.ok) {
      throw fail(preexisting.reason, `cannot read the seal floor ${anchorPath}`);
    }
    if (preexisting !== null) {
      const anchorCheck = seal.verifyAnchor(key, preexisting.doc);
      if (!anchorCheck.ok) {
        throw fail('ledger_anchor_mismatch',
          `the existing seal floor ${anchorPath} does not verify under this passphrase; ` +
          'seal-journal never replaces a floor it cannot verify');
      }
      if (preexisting.doc.count > parsed.seq) {
        throw fail('ledger_mac_short',
          `the journal holds ${parsed.seq} record(s), the seal floor claims ${preexisting.doc.count}: ` +
          'history was removed (truncation) - recover from a backup instead of resealing');
      }
    }

    // Step 5: recompute the chain under v=4 with keyed MACs. Self-check
    // before touching disk.
    const xLines = [];
    const keyedHeads = []; // head after each record, for the floor check below
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
      keyedHeads.push(rec.x);
      xLines.push(JSON.stringify(rec));
    }
    // A 0-record journal must seal to a 0-byte sealed journal, not to a
    // lone newline: joining an empty record list produced '\n', which
    // parseJournal rejects as ledger_corrupt - the tool refused a CLEAN empty
    // file with a corruption code (measured: p4 case1, identical on the
    // pre-fix tree). Empty is exactly what a fresh sealed journal is.
    const out = xLines.length === 0
      ? Buffer.alloc(0)
      : Buffer.from(`${xLines.join('\n')}\n`, 'utf8');
    const check = parseJournal(out, { macKey: key });
    if (check.records.length !== parsed.records.length ||
        check.sealedRecords !== parsed.records.length ||
        check.seq !== parsed.seq) {
      throw fail('seal_self_check_failed');
    }
    const floor = seal.sealAnchor(key, { count: parsed.seq, head: prevX });
    // R6-4c: the lineage question, now answerable. A floor whose head at its
    // count is not THIS journal's keyed head witnesses a different history -
    // a genuine floor beside a forged journal (p4 case5) - and replacing it
    // would launder the forgery. Refuse instead.
    if (preexisting !== null) {
      const mismatch = checkFloorAgainstChain(preexisting.doc, keyedHeads,
        parsed.seq, key, anchorPath);
      if (mismatch !== null) throw mismatch;
    }
    const floorOverwritten = preexisting !== null &&
      (preexisting.doc.count !== floor.count || preexisting.doc.head !== floor.head);

    // Step 6: backup, replace, then floor. Rename is the commit point.
    const suffix = crypto.randomBytes(8).toString('hex');
    const backup = `${resolved}.pre-seal.${suffix}.bak`;
    const tmp = `${resolved}.seal.${suffix}.tmp`;
    if (preexisting !== null) {
      // R6-4c: the replaced floor is preserved next to the backup, so the
      // operator's previous history claim is never destroyed by the recovery
      // tool itself.
      writeExclusive(`${backup}.anchor`, JSON.stringify(preexisting.doc) + '\n');
    }
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
      floorRepaired: false,
      floorOverwritten,
    };
  } finally {
    release();
  }
}

module.exports = { sealExistingJournal };
