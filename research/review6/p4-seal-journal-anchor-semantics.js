'use strict';
// p4: the seal-journal RECOVERY path and the seal floor.
//
// `signerd seal-journal` is the operator's documented recovery tool for a
// journal whose floor (anchor) is wrong or missing. What it does with an
// EXISTING anchor is not documented and looks wrong:
//
//   a) it never reads the existing anchor in the "seal a fresh journal" branch,
//      so it SILENTLY OVERWRITES the operator's floor with one derived from
//      the journal it was handed;
//   b) in the "already sealed" branch it refuses to create a missing anchor,
//      so the documented recovery tool CANNOT repair the one state the
//      daemon refuses to start in (ledger_anchor_missing).
//
// This probe measures all four anchor states:
//   1. fresh (unsealed) journal, no anchor      -> seals, writes anchor
//   2. sealed journal, anchor PRESENT            -> "already_sealed"
//   3. sealed journal, anchor DELETED            -> "already_sealed", anchor
//                                                    still missing?  (the
//                                                    daemon then refuses
//                                                    ledger_anchor_missing)
//   4. sealed journal, anchor present but STALE  (count/head from an older
//      prefix) -> "already_sealed", stale floor kept?

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, fixture, verdict } = require('./common');
const { Ledger, SEALED_JOURNAL_FORMAT, chainHash, GENESIS_HASH } = require('../../src/ledger');
const seal = require('../../src/journalseal');
const { sealExistingJournal } = require('../../src/journalseal-ops');

const PASS = 'journal seal passphrase p4';

function buildSealedJournal(file, count, headOffset = 0) {
  const key = seal.deriveJournalKey(PASS);
  const lines = [];
  let prevH = GENESIS_HASH;
  let prevX = seal.genesisMac(key);
  for (let i = 1; i <= count; i += 1) {
    const body = {
      v: SEALED_JOURNAL_FORMAT, s: i, t: 1700000000000 + i,
      w: String(i).repeat(64).slice(0, 64), m: String(i).padStart(2, '0').repeat(32).slice(0, 64),
      a: '42', f: '5000', k: 'scope',
    };
    const rec = { ...body, h: chainHash(prevH, body) };
    rec.x = seal.chainMac(key, prevX, rec.h);
    prevH = rec.h; prevX = rec.x;
    lines.push(JSON.stringify(rec));
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  fs.chmodSync(file, 0o600);
  return { key, lines, head: prevX };
}

function attempt(file, label) {
  try {
    const r = sealExistingJournal({ journalFile: file, passphrase: PASS });
    return { label, ok: true, result: r };
  } catch (err) {
    return { label, ok: false, code: err.code, message: err.message };
  }
}

function daemonLoad(file) {
  try {
    new Ledger({ file, sealPassphrase: PASS });
    return { ok: true };
  } catch (err) { return { ok: false, code: err.code || null, message: err.message }; }
}

async function main() {
  const dir = tmpdir();
  const out = { probe: 'p4-seal-journal-anchor-semantics', results: {}, findings: [] };
  try {
    // ---- case 1: fresh unsealed journal, no anchor ----
    {
      const j = path.join(dir, 'c1.jsonl');
      fs.writeFileSync(j, '');
      fs.chmodSync(j, 0o600);
      const r = attempt(j, 'fresh unsealed journal, no anchor');
      out.results.case1 = r;
      out.results.case1_anchor_exists_after = fs.existsSync(j + '.anchor');
    }

    // ---- case 2: sealed journal, anchor present ----
    {
      const j = path.join(dir, 'c2.jsonl');
      const { key } = buildSealedJournal(j, 2);
      seal.writeAnchor(j + '.anchor', seal.sealAnchor(key, { count: 2, head: seal.chainMac(key, seal.genesisMac(key), JSON.parse(fs.readFileSync(j, 'utf8').trim().split('\n')[1]).h) }));
      fs.chmodSync(j + '.anchor', 0o600);
      const before = fs.readFileSync(j + '.anchor', 'utf8');
      const r = attempt(j, 'sealed journal, anchor present');
      out.results.case2 = r;
      out.results.case2_anchor_unchanged = fs.readFileSync(j + '.anchor', 'utf8') === before;
      out.results.case2_daemon_load = daemonLoad(j);
    }

    // ---- case 3: sealed journal, anchor DELETED ----
    {
      const j = path.join(dir, 'c3.jsonl');
      buildSealedJournal(j, 2);
      const r = attempt(j, 'sealed journal, anchor DELETED');
      out.results.case3 = r;
      out.results.case3_anchor_exists_after = fs.existsSync(j + '.anchor');
      out.results.case3_daemon_load = daemonLoad(j);
      out.results.case3_recovery_possible = (() => {
        // Can ANY documented command repair this? seal-journal already ran.
        const r2 = attempt(j, 'second seal-journal attempt');
        return { second: r2, anchor_exists: fs.existsSync(j + '.anchor') };
      })();
    }

    // ---- case 4: sealed journal, STALE anchor (count=1 of 2 records) ----
    {
      const j = path.join(dir, 'c4.jsonl');
      const { key, lines } = buildSealedJournal(j, 2);
      const firstRec = JSON.parse(lines[0]);
      seal.writeAnchor(j + '.anchor', seal.sealAnchor(key, { count: 1, head: firstRec.x }));
      fs.chmodSync(j + '.anchor', 0o600);
      const r = attempt(j, 'sealed journal, STALE anchor (count=1 of 2)');
      out.results.case4 = r;
      out.results.case4_anchor_after = JSON.parse(fs.readFileSync(j + '.anchor', 'utf8'));
      out.results.case4_daemon_load = daemonLoad(j);
    }

    // ---- case 5: THE OVERWRITE - sealed journal whose content was forged,
    //      with the operator's ORIGINAL floor still in place. seal-journal
    //      is the operator's recovery move; what happens to the floor? ----
    {
      const j = path.join(dir, 'c5.jsonl');
      const { key } = buildSealedJournal(j, 1);
      seal.writeAnchor(j + '.anchor', seal.sealAnchor(key, { count: 1, head: JSON.parse(fs.readFileSync(j, 'utf8').trim()).x }));
      fs.chmodSync(j + '.anchor', 0o600);
      const originalAnchor = fs.readFileSync(j + '.anchor', 'utf8');

      // Attacker (file write only) replaces the journal with a FORGED v3
      // record carrying a recomputed UNKEYED chain: it parses, it has no
      // keyed MAC, and it is NOT the history the floor describes.
      const { chainHash: ch } = require('../../src/ledger');
      const body = {
        v: 3, s: 1, t: 1700000000000,
        w: 'f'.repeat(64), m: 'e'.repeat(64), a: '999999999', f: '5000', k: 'attacker',
      };
      const forged = { ...body, h: ch(GENESIS_HASH, body) };
      fs.writeFileSync(j, JSON.stringify(forged) + '\n');
      fs.chmodSync(j, 0o600);

      out.results.case5_before = { anchor: JSON.parse(originalAnchor) };
      out.results.case5_daemon_load_before_sealjournal = daemonLoad(j);
      const r = attempt(j, 'FORGED v3 journal, operator floor still present');
      out.results.case5_sealjournal = r;
      const after = fs.readFileSync(j + '.anchor', 'utf8');
      out.results.case5_anchor_overwritten = after !== originalAnchor;
      out.results.case5_anchor_after = JSON.parse(after);
      out.results.case5_daemon_load_after_sealjournal = daemonLoad(j);
      out.results.case5_journal_now = JSON.parse(fs.readFileSync(j, 'utf8').trim());
    }

    // ---- verdict ----
    if (out.results.case3_anchor_exists_after === false && out.results.case3_daemon_load.ok === false) {
      out.findings.push('NEW FINDING: seal-journal cannot repair a MISSING seal floor - the daemon stays bricked (ledger_anchor_missing) and the tool reports "already_sealed"');
    }
    if (out.results.case5_anchor_overwritten === true && out.results.case5_daemon_load_before_sealjournal.ok === false
        && out.results.case5_daemon_load_after_sealjournal.ok === true) {
      out.findings.push('NEW FINDING: seal-journal silently OVERWRITES the operator\'s seal floor, converting a refusal (ledger_anchor_mismatch) into an accepted forged history');
    }
  } catch (err) {
    out.threw = String(err && err.stack || err);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p4-seal-journal-anchor-semantics', fatal: String(err && err.stack || err) }));
