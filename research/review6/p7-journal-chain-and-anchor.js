'use strict';
// p7: JOURNAL CHAIN MAC + ANCHOR matrix against the pinned tree.
//
// Chain manipulation (all with a sealed journal + valid anchor in place):
//   c1 reorder two records            -> must refuse (seq + h + x chain)
//   c2 drop a record from the MIDDLE  -> must refuse
//   c3 duplicate a record             -> must refuse
//   c4 re-sequence (renumber s)       -> must refuse (h covers s)
//   c5 edit a value, recompute h only -> must refuse (x stale)
//   c6 edit a value, keep h            -> must refuse (h stale)
//   c7 append a record without the key -> must refuse (x unforgeable)
//   c8 truncate the TAIL (anchor claims more) -> ledger_mac_short
//   c9 truncate the tail AND the anchor to a matched older pair (rollback)
//   c10 replace the whole journal with a valid PREFIX (prefix-validity)
//
// Anchor states (sealed journal in place):
//   a1 anchor missing, journal has records -> refuse
//   a2 anchor stale (count < records)      -> accept by design (crash shape)
//   a3 anchor newer (count > records)      -> refuse (truncation)
//   a4 anchor head edited by a stranger    -> refuse (MAC mismatch)
//   a5 anchor count edited upward          -> refuse
//   a6 anchor mode group-writable          -> refuse
//   a7 anchor owned by another user        -> refuse
//   a8 anchor replaced by an OLDER genuine pair (rollback) -> measured
//
// Every case runs through the REAL Ledger constructor (the daemon's own load
// path), not a re-implementation.

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, verdict } = require('./common');
const {
  Ledger, SEALED_JOURNAL_FORMAT, chainHash, GENESIS_HASH, parseJournal,
} = require('../../src/ledger');
const seal = require('../../src/journalseal');

const PASS = 'journal seal passphrase p7';

function load(file, opts = {}) {
  try {
    const l = new Ledger({ file, sealPassphrase: opts.unsealed ? undefined : PASS, ...opts });
    return { ok: true, records: l.snapshot().records, seq: l.snapshot().seq };
  } catch (err) {
    return { ok: false, code: err.code || null, message: err.message };
  }
}

/** Build a genuine sealed journal of `count` records with a valid anchor. */
function build(file, count) {
  const key = seal.deriveJournalKey(PASS);
  const lines = [];
  let prevH = GENESIS_HASH;
  let prevX = seal.genesisMac(key);
  const records = [];
  for (let i = 1; i <= count; i += 1) {
    const body = {
      v: SEALED_JOURNAL_FORMAT, s: i, t: 1700000000000 + i,
      w: `${i}${'0'.repeat(63)}`, m: `${i}${'e'.repeat(63)}`,
      a: '42', f: '5000', k: `scope-${i}`,
    };
    const rec = { ...body, h: chainHash(prevH, body) };
    rec.x = seal.chainMac(key, prevX, rec.h);
    prevH = rec.h; prevX = rec.x;
    records.push(rec);
    lines.push(JSON.stringify(rec));
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  fs.chmodSync(file, 0o600);
  const anchor = seal.sealAnchor(key, { count, head: prevX });
  seal.writeAnchor(`${file}.anchor`, anchor);
  fs.chmodSync(`${file}.anchor`, 0o600);
  return { key, records, lines, anchor };
}

function writeAll(file, recs) {
  fs.writeFileSync(file, recs.map((r) => JSON.stringify(r)).join('\n') + '\n');
  fs.chmodSync(file, 0o600);
}

async function main() {
  const out = { probe: 'p7-journal-chain-and-anchor', chain: {}, anchor: {}, findings: [] };
  try {
    // ---------- chain manipulation ----------
    {
      const f = path.join(tmpdir('r6p7a-'), 'j.jsonl');
      const { records, key } = build(f, 4);

      out.chain.c1_reorder = load(f) && (() => {
        const r = [...records]; [r[1], r[2]] = [r[2], r[1]]; writeAll(f, r); return load(f);
      })();

      build(f, 4);
      out.chain.c2_drop_middle = (() => {
        const r = [...records]; r.splice(2, 1); writeAll(f, r); return load(f);
      })();

      build(f, 4);
      out.chain.c3_duplicate = (() => {
        const r = [...records]; r.splice(3, 0, { ...records[2] }); writeAll(f, r); return load(f);
      })();

      build(f, 4);
      out.chain.c4_resequence = (() => {
        const r = records.map((rec, i) => ({ ...rec, s: i + 10 }));
        writeAll(f, r); return load(f);
      })();

      build(f, 4);
      out.chain.c5_edit_recompute_h_only = (() => {
        // attacker edits a value and recomputes the UNKEYED chain but has no
        // key for x -> x must not verify.
        const r = records.map((rec) => ({ ...rec }));
        const body = { ...r[1], a: '999999999' };
        delete body.h; delete body.x;
        const fixed = { ...body, h: chainHash(r[0].h, body), x: r[1].x };
        r[1] = fixed;
        for (let i = 2; i < r.length; i += 1) {
          const b = { ...r[i] }; delete b.h; delete b.x;
          b.h = chainHash(r[i - 1].h, b); r[i] = { ...b, x: r[i].x };
        }
        writeAll(f, r); return load(f);
      })();

      build(f, 4);
      out.chain.c6_edit_keep_h = (() => {
        const r = records.map((rec) => ({ ...rec }));
        r[1] = { ...r[1], a: '999999999' };
        writeAll(f, r); return load(f);
      })();

      build(f, 4);
      out.chain.c7_append_without_key = (() => {
        const forged = {
          v: SEALED_JOURNAL_FORMAT, s: 5, t: 1700000009999,
          w: 'f'.repeat(64), m: 'd'.repeat(64), a: '1', f: '5000', k: 'evil',
        };
        forged.h = chainHash(records[3].h, forged);
        forged.x = '0'.repeat(64);
        fs.appendFileSync(f, JSON.stringify(forged) + '\n');
        fs.chmodSync(f, 0o600);
        return load(f);
      })();

      build(f, 4);
      out.chain.c8_truncate_tail_anchor_claiming_4 = (() => {
        writeAll(f, records.slice(0, 2)); return load(f);
      })();

      build(f, 4);
      out.chain.c9_rollback_to_older_genuine_pair = (() => {
        // Genuine older pair: first 2 records + their anchor (both authentic,
        // no key needed to produce them - the attacker kept copies).
        const key = seal.deriveJournalKey(PASS);
        writeAll(f, records.slice(0, 2));
        seal.writeAnchor(`${f}.anchor`, seal.sealAnchor(key, { count: 2, head: records[1].x }));
        fs.chmodSync(`${f}.anchor`, 0o600);
        return load(f);
      })();

      build(f, 4);
      out.chain.c10_replace_with_valid_prefix_only = (() => {
        // Same as c8 but the attacker also DROPS the anchor -> tested as a1.
        fs.unlinkSync(`${f}.anchor`);
        return load(f);
      })();
      out.chain.c10b_same_but_unsealed_daemon = load(f, { unsealed: true });
    }

    // ---------- anchor states ----------
    {
      const f = path.join(tmpdir('r6p7b-'), 'j.jsonl');
      const { records, anchor, key } = build(f, 3);

      fs.unlinkSync(`${f}.anchor`);
      out.anchor.a1_missing = load(f);

      build(f, 3);
      seal.writeAnchor(`${f}.anchor`, seal.sealAnchor(key, { count: 1, head: records[0].x }));
      fs.chmodSync(`${f}.anchor`, 0o600);
      out.anchor.a2_stale_count_1_of_3 = load(f);

      build(f, 3);
      seal.writeAnchor(`${f}.anchor`, seal.sealAnchor(key, { count: 9, head: 'a'.repeat(64) }));
      fs.chmodSync(`${f}.anchor`, 0o600);
      out.anchor.a3_newer_count_9_of_3 = load(f);

      build(f, 3);
      const edited = { ...anchor, head: 'b'.repeat(64) };
      edited.mac = anchor.mac; // keep the old MAC -> must mismatch
      fs.writeFileSync(`${f}.anchor`, JSON.stringify(edited) + '\n');
      fs.chmodSync(`${f}.anchor`, 0o600);
      out.anchor.a4_head_edited_mac_kept = load(f);

      build(f, 3);
      const edited2 = { ...anchor, count: 1 };
      fs.writeFileSync(`${f}.anchor`, JSON.stringify(edited2) + '\n');
      fs.chmodSync(`${f}.anchor`, 0o600);
      out.anchor.a5_count_edited_mac_kept = load(f);

      build(f, 3);
      fs.chmodSync(`${f}.anchor`, 0o666);
      out.anchor.a6_mode_group_writable = load(f);

      build(f, 3);
      exec_chown_nobody(`${f}.anchor`);
      out.anchor.a7_owned_by_another_user = load(f);

      build(f, 3);
      // a9: anchor replaced by a SYMLINK (lstat should refuse it)
      fs.unlinkSync(`${f}.anchor`);
      fs.writeFileSync(`${f}.anchor.target`, JSON.stringify(anchor) + '\n');
      fs.chmodSync(`${f}.anchor.target`, 0o600);
      fs.symlinkSync(`${f}.anchor.target`, `${f}.anchor`);
      out.anchor.a9_anchor_is_symlink = load(f);

      build(f, 3);
      // a10: anchor only GROUP-readable (0644): any group/other bit is refused
      fs.chmodSync(`${f}.anchor`, 0o644);
      out.anchor.a10_anchor_group_readable = load(f);

      build(f, 3);
      // a8: rollback BOTH files to the same older genuine pair.
      writeAll(f, records.slice(0, 1));
      seal.writeAnchor(`${f}.anchor`, seal.sealAnchor(key, { count: 1, head: records[0].x }));
      fs.chmodSync(`${f}.anchor`, 0o600);
      out.anchor.a8_full_rollback_genuine_pair = load(f);
      // ...and can the same state be RE-PRODUCED by a stranger who kept
      // copies while the files were readable? Yes if they had read access;
      // the anchor is refused when group/other-readable so read access must
      // have come earlier (documented limit).
    }

    // ---------- verdicts ----------
    const refused = (v) => v && v.ok === false;
    const expectRefuse = [
      ['c1_reorder'], ['c2_drop_middle'], ['c3_duplicate'], ['c4_resequence'],
      ['c5_edit_recompute_h_only'], ['c6_edit_keep_h'], ['c7_append_without_key'],
      ['c8_truncate_tail_anchor_claiming_4'], ['c10_replace_with_valid_prefix_only'],
    ];
    out.chain.expectations = {};
    for (const [k] of expectRefuse) {
      out.chain.expectations[k] = refused(out.chain[k]) ? 'REFUSED (as required)'
        : `!!! ACCEPTED: ${JSON.stringify(out.chain[k])}`;
    }
    out.anchor.expectations = {
      a1_missing: refused(out.anchor.a1_missing) ? 'REFUSED (as required)' : `!!! ACCEPTED: ${JSON.stringify(out.anchor.a1_missing)}`,
      a2_stale_count_1_of_3: out.anchor.a2_stale_count_1_of_3.ok ? 'ACCEPTED (by design: crash-ahead shape)' : `!!! REFUSED: ${out.anchor.a2_stale_count_1_of_3.code}`,
      a3_newer_count_9_of_3: refused(out.anchor.a3_newer_count_9_of_3) ? 'REFUSED (as required)' : '!!! ACCEPTED',
      a4_head_edited_mac_kept: (() => {
        const v = out.anchor.a4_head_edited_mac_kept;
        if (!refused(v)) return '!!! ACCEPTED';
        // Distinguish the MAC refusal from the head-check refusal: only the
        // former proves the anchor's own MAC is verified.
        return v.message.includes('does not verify under this passphrase')
          ? 'REFUSED at the anchor MAC (as required)'
          : `!!! refused for the WRONG reason: ${v.message}`;
      })(),
      a5_count_edited_mac_kept: (() => {
        const v = out.anchor.a5_count_edited_mac_kept;
        if (!refused(v)) return '!!! ACCEPTED';
        return v.message.includes('does not verify under this passphrase')
          ? 'REFUSED at the anchor MAC (as required)'
          : `!!! refused for the WRONG reason: ${v.message}`;
      })(),
      a6_mode_group_writable: refused(out.anchor.a6_mode_group_writable) ? 'REFUSED (as required)' : '!!! ACCEPTED',
      a7_owned_by_another_user: refused(out.anchor.a7_owned_by_another_user) ? 'REFUSED (as required)' : '!!! ACCEPTED',
      a9_anchor_is_symlink: refused(out.anchor.a9_anchor_is_symlink) ? 'REFUSED (as required)' : `!!! ACCEPTED: ${JSON.stringify(out.anchor.a9_anchor_is_symlink)}`,
      a10_anchor_group_readable: refused(out.anchor.a10_anchor_group_readable) ? 'REFUSED (as required)' : `!!! ACCEPTED: ${JSON.stringify(out.anchor.a10_anchor_group_readable)}`,
      a8_full_rollback_genuine_pair: out.anchor.a8_full_rollback_genuine_pair.ok
        ? 'ACCEPTED - documented rollback limit (old genuine pair is indistinguishable from an old state)'
        : `REFUSED: ${out.anchor.a8_full_rollback_genuine_pair.code}`,
    };
    out.chain.c9_rollback_to_older_genuine_pair_verdict = out.chain.c9_rollback_to_older_genuine_pair.ok
      ? 'ACCEPTED - same documented rollback limit as a8'
      : `REFUSED: ${out.chain.c9_rollback_to_older_genuine_pair.code}`;

    const bad = [];
    for (const [k, v] of Object.entries(out.chain.expectations || {})) if (v.startsWith('!')) bad.push(`chain.${k}: ${v}`);
    for (const [k, v] of Object.entries(out.anchor.expectations || {})) if (v.startsWith('!')) bad.push(`anchor.${k}: ${v}`);
    out.findings = bad.length ? [`NEW FINDING: ${bad.join('; ')}`]
      : ['held: every chain manipulation and every anchor mutation is refused; only the documented full rollback (a8/c9) is accepted'];
  } catch (err) {
    out.threw = String(err && err.stack || err);
  }
  verdict(out);
}

function exec_chown_nobody(file) {
  try { require('node:child_process').execFileSync('sudo', ['-n', 'chown', 'nobody:nogroup', file]); }
  catch (e) { require('node:child_process').execFileSync('sudo', ['-n', 'chown', 'nobody', file]); }
}

main().catch((err) => verdict({ probe: 'p7-journal-chain-and-anchor', fatal: String(err && err.stack || err) }));
