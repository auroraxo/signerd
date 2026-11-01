'use strict';
// p2: the seal-floor guard's coverage when the JOURNAL FILE IS GONE.
//
// Two guards exist for "this journal was sealed":
//   sealed   daemon (macKey)  -> #checkAnchorOnMissingJournal() on ENOENT
//   unsealed daemon (no key)  -> #refuseIfSealFloorExists() ... but ONLY on
//                                the success path of #load(), i.e. only when
//                                the journal file EXISTS.
//
// Question: does an UNSEALED daemon (no --journal-seal-passphrase-file) start
// "fresh" when the journal file has been DELETED but the seal floor
// (<journal>.anchor) is still there and claims history? If yes, the no-key
// downgrade guard is existence-based on the JOURNAL, while the sealed guard is
// existence-based on the ANCHOR - an asymmetry.
//
// Also measures the paired direction: sealed daemon + missing journal +
// anchor (must refuse ledger_mac_short), and unsealed daemon + existing-but-
// empty journal + anchor (must refuse ledger_sealed).

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, fixture, makeWire, writeJson, verdict } = require('./common');
const { Ledger, SEALED_JOURNAL_FORMAT, chainHash, GENESIS_HASH } = require('../../src/ledger');
const seal = require('../../src/journalseal');

function construct(fn) {
  try { fn(); return { ok: true }; } catch (err) { return { ok: false, code: err.code || null, message: err.message }; }
}

async function main() {
  const dir = tmpdir();
  const out = { probe: 'p2-missing-journal-anchor-present', results: {} };
  try {
    const f = fixture(dir);
    const jfile = path.join(dir, 'j.jsonl');
    const afile = seal.anchorPath(jfile);

    // ---- Build a genuine SEALED journal + anchor (1 record) ----
    const key = seal.deriveJournalKey('sealed journal passphrase');
    const body = {
      v: SEALED_JOURNAL_FORMAT, s: 1, t: Date.now(),
      w: 'a'.repeat(64), m: 'b'.repeat(64),
      a: '42', f: '5000', k: `k scope`,
    };
    const rec = { ...body, h: chainHash(GENESIS_HASH, body) };
    rec.x = seal.chainMac(key, seal.genesisMac(key), rec.h);
    fs.writeFileSync(jfile, JSON.stringify(rec) + '\n');
    fs.chmodSync(jfile, 0o600);
    seal.writeAnchor(afile, seal.sealAnchor(key, { count: 1, head: rec.x }));
    fs.chmodSync(afile, 0o600);
    out.fixture = {
      journal_bytes: fs.statSync(jfile).size,
      anchor_exists: fs.existsSync(afile),
      anchor: JSON.parse(fs.readFileSync(afile, 'utf8')),
    };

    // ---- A: SEALED daemon, journal deleted, anchor present ----
    fs.unlinkSync(jfile);
    out.results.A_sealed_daemon_journal_deleted_anchor_present =
      construct(() => new Ledger({ file: jfile, sealPassphrase: 'sealed journal passphrase' }));

    // ---- B: UNSEALED daemon, journal deleted, anchor present ----
    out.results.B_unsealed_daemon_journal_deleted_anchor_present =
      construct(() => new Ledger({ file: jfile }));

    // ---- C: UNSEALED daemon, journal EXISTS but EMPTY, anchor present ----
    fs.writeFileSync(jfile, '');
    fs.chmodSync(jfile, 0o600);
    out.results.C_unsealed_daemon_journal_empty_anchor_present =
      construct(() => new Ledger({ file: jfile }));
    fs.unlinkSync(jfile);

    // ---- D: restore journal; UNSEALED daemon, journal present (sealed), anchor present ----
    fs.writeFileSync(jfile, JSON.stringify(rec) + '\n');
    fs.chmodSync(jfile, 0o600);
    out.results.D_unsealed_daemon_journal_sealed_anchor_present =
      construct(() => new Ledger({ file: jfile }));

    // ---- E: anchor DELETED, journal present (sealed), UNSEALED daemon ----
    fs.unlinkSync(afile);
    out.results.E_unsealed_daemon_journal_sealed_anchor_DELETED =
      construct(() => new Ledger({ file: jfile }));

    // ---- F: anchor DELETED, journal REWRITTEN as format 3 with a recomputed
    //         UNKEYED chain (anyone with file write can do this), UNSEALED
    //         daemon: is the downgrade guard gone? ----
    const body3 = { ...body, v: 3 };
    delete body3.x;
    const rec3 = { ...body3, h: chainHash(GENESIS_HASH, body3) };
    fs.writeFileSync(jfile, JSON.stringify(rec3) + '\n');
    fs.chmodSync(jfile, 0o600);
    out.results.F_unsealed_daemon_journal_rewritten_v3_anchor_DELETED =
      construct(() => new Ledger({ file: jfile }));

    // ---- G: same as F but with the anchor still present (control) ----
    seal.writeAnchor(afile, seal.sealAnchor(key, { count: 1, head: rec.x }));
    fs.chmodSync(afile, 0o600);
    out.results.G_unsealed_daemon_journal_rewritten_v3_anchor_PRESENT =
      construct(() => new Ledger({ file: jfile }));

    // ---- H: anchor present but its OWN read is refused: does the failure
    //         surface as ledger_sealed (refuse) rather than being ignored? ----
    fs.chmodSync(afile, 0o666);
    out.results.H_unsealed_daemon_anchor_group_writable =
      construct(() => new Ledger({ file: jfile }));
    fs.chmodSync(afile, 0o600);

    // ---- Verdict summary ----
    const bRes = out.results.B_unsealed_daemon_journal_deleted_anchor_present;
    const fRes = out.results.F_unsealed_daemon_journal_rewritten_v3_anchor_DELETED;
    out.verdict_B = bRes.ok ? 'FAIL-OPEN: unsealed daemon started fresh with an anchor claiming history'
      : `fail-closed: ${bRes.code}`;
    out.verdict_F = fRes.ok ? 'FAIL-OPEN: forged v3 journal accepted after the anchor was deleted'
      : `fail-closed: ${fRes.code}`;
    out.findings = [];
    if (bRes.ok) out.findings.push('NEW FINDING?: no-passphrase downgrade guard is skipped when the journal file is absent');
    if (fRes.ok) out.findings.push('LIMIT/NAME: deleting the anchor (directory write) removes the unsealed downgrade guard entirely');
  } catch (err) {
    out.threw = String(err && err.stack || err);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p2-missing-journal-anchor-present', fatal: String(err && err.stack || err) }));
