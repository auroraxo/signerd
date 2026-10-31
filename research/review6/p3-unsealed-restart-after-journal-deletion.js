'use strict';
// p3: END-TO-END downgrade & history laundering through the unsealed-mode
// skip of the seal-floor guard (Daemon level, live socket).
//
// Timeline (every step is something a local attacker with write access to the
// state directory can do while the daemon is DOWN; the unsealed daemon is the
// configuration the README still documents as the default `signerd run`):
//
//   1. operator runs a SEALED daemon, signs one wire W  -> journal record R1
//      (format 4, keyed MAC) + anchor floor (count=1).
//   2. daemon stops. Attacker DELETES the journal file (the same write
//      capability that truncation p3 needed; the directory is the operator's
//      own state dir - the README's documented layout).
//   3. Operator (or an init script) restarts the daemon UNSEALED - e.g. after
//      an upgrade that moved the passphrase file, a config regression, or the
//      documented default command line. The seal-floor guard is skipped on
//      the ENOENT path (no key => #refuseIfSealFloorExists is never reached),
//      so the daemon starts FRESH with an empty replay set.
//   4. The client re-sends W: the daemon SIGNS IT AGAIN. On-chain this is a
//      second signature over a message the ledger says was signed once - the
//      exact double-sign that the journal seal (R5-2 journal half) exists to
//      prevent, reachable without knowing the seal passphrase.
//   5. When the operator re-seals (seal-journal) or restarts sealed, the
//      foreign format-3 record - minted under a genesis the sealed chain
//      never had - bricks the load: the audit trail cannot be re-sealed
//      without manual surgery (chainHash mismatch => ledger_corrupt /
//      ledger_tampered).
//
// Control cases: the SEALED restart refuses the same state (ledger_mac_short);
// an unsealed restart with the journal merely TRUNCATED (not deleted) also
// refuses (ledger_sealed via #refuseIfSealFloorExists). Only deletion opens
// the hole - which is exactly what this probe pins.

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const {
  tmpdir, fixture, makeWire, writeJson, grantDoc, futureIso,
  start, stop, request, KSPASS, verdict,
} = require('./common');
const { Daemon } = require('../../src/daemon');
const { Ledger, JOURNAL_FORMAT, GENESIS_HASH, chainHash } = require('../../src/ledger');
const seal = require('../../src/journalseal');

async function main() {
  const dir = tmpdir();
  const out = {
    probe: 'p3-unsealed-restart-after-journal-deletion',
    steps: [],
    findings: [],
  };
  let daemon = null;
  try {
    const f = fixture(dir);
    const JSEAL = 'the operator journal seal passphrase';
    writeJson(f.sealPassFile, { text: JSEAL } && JSEAL + '\n');

    // ---- step 1: sealed daemon signs W once ----
    writeJson(f.grantFile, grantDoc(f.keypair.publicKey.toBase58(), f.honest));
    daemon = await start(f, { journalSealPassphrase: JSEAL });
    const W = makeWire(f.keypair, f.honest);
    const first = await request({ socketPath: f.socketPath, grant: 'ops', wire: W });
    out.steps.push({ step: '1 sealed sign', ok: first.ok, seq: first.seq, error: first.error });
    if (!first.ok) throw new Error('baseline sealed sign failed');
    const firstSignature = first.signature;
    await stop(daemon); daemon = null;

    const anchorSnapshot = fs.readFileSync(f.ledgerFile + '.anchor', 'utf8');
    const sealedRecord = fs.readFileSync(f.ledgerFile, 'utf8');
    out.steps.push({
      step: '1b durable state',
      journal_format: JSON.parse(sealedRecord.trim()).v,
      anchor: JSON.parse(anchorSnapshot),
    });

    // ---- step 2: attacker deletes the journal file ----
    fs.unlinkSync(f.ledgerFile);
    out.steps.push({ step: '2 attacker deletes journal', journal_exists: fs.existsSync(f.ledgerFile), anchor_exists: fs.existsSync(f.ledgerFile + '.anchor') });

    // ---- step 3a: CONTROL - a SEALED restart must refuse ----
    let control;
    try {
      new Ledger({ file: f.ledgerFile, sealPassphrase: JSEAL });
      control = { ok: true };
    } catch (err) { control = { ok: false, code: err.code }; }
    out.steps.push({ step: '3a control sealed restart', ...control });

    // ---- step 3b: CONTROL - truncated (not deleted) journal, unsealed ----
    fs.writeFileSync(f.ledgerFile, '');
    fs.chmodSync(f.ledgerFile, 0o600);
    let control2;
    try {
      new Ledger({ file: f.ledgerFile });
      control2 = { ok: true };
    } catch (err) { control2 = { ok: false, code: err.code }; }
    out.steps.push({ step: '3b control truncated+unsealed', ...control2 });

    // ---- step 3c: THE HOLE - deleted journal, UNSEALED restart ----
    fs.unlinkSync(f.ledgerFile);
    let unsealed;
    try {
      new Ledger({ file: f.ledgerFile });
      unsealed = { ok: true };
    } catch (err) { unsealed = { ok: false, code: err.code }; }
    out.steps.push({ step: '3c unsealed restart, journal deleted', ...unsealed });
    if (unsealed.ok) out.findings.push('CONFIRMED: unsealed restart ignores the seal floor when the journal file is absent');

    // ---- step 4: the same wire is signed AGAIN by the live unsealed daemon ----
    daemon = await start(f); // unsealed: no journalSealPassphrase
    const second = await request({ socketPath: f.socketPath, grant: 'ops', wire: W });
    out.steps.push({
      step: '4 re-sign same wire on unsealed daemon',
      ok: second.ok,
      error: second.error,
      seq: second.seq,
      same_message_signed_twice: second.ok && second.messageSha256 === first.messageSha256,
    });
    if (second.ok && second.messageSha256 === first.messageSha256) {
      out.findings.push('CONFIRMED: DOUBLE SIGN - the same message was signed twice across the downgrade');
    }
    const secondSignature = second.signature;
    await stop(daemon); daemon = null;

    // ---- step 5: journal file now holds a FOREIGN v3 record behind the
    //      operator's back; can the operator re-seal or restart sealed? ----
    const nowRecord = JSON.parse(fs.readFileSync(f.ledgerFile, 'utf8').trim());
    out.steps.push({
      step: '5 journal state after downgrade',
      record_v: nowRecord.v,
      record_has_x: typeof nowRecord.x === 'string',
      record_seq: nowRecord.s,
    });

    // 5a: seal-journal on this journal (the operator's recovery path):
    const { sealExistingJournal } = require('../../src/journalseal-ops');
    let reseal;
    try {
      reseal = { ok: true, result: sealExistingJournal({ journalFile: f.ledgerFile, passphrase: JSEAL }) };
    } catch (err) { reseal = { ok: false, code: err.code, message: err.message }; }
    out.steps.push({ step: '5a operator re-seals (recovery)', ...reseal, message: reseal.message });

    // 5b: restart sealed on the post-downgrade journal
    let restartSealed;
    try {
      new Ledger({ file: f.ledgerFile, sealPassphrase: JSEAL });
      restartSealed = { ok: true };
    } catch (err) { restartSealed = { ok: false, code: err.code }; }
    out.steps.push({ step: '5b sealed restart after downgrade', ...restartSealed });

    // 5c: is the pre-downgrade SEALED history still recoverable at all?
    //     (attacker kept a copy of the original journal + anchor)
    out.steps.push({
      step: '5c original sealed history byte-identical copy still loads?',
      note: 'the downgrade DESTROYED the audit trail in place; the sealed copy is gone unless backed up',
      journal_now_unsealed: nowRecord.v === JOURNAL_FORMAT,
    });

    out.signatures = { first: firstSignature, second: secondSignature };
    out.summary = out.findings.length
      ? 'REAL DEFECT: deleting the journal bypasses the no-passphrase downgrade guard; double-sign follows'
      : 'held: all restart shapes refused';
  } catch (err) {
    out.threw = String(err && err.stack || err);
  } finally {
    await stop(daemon);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p3-unsealed-restart-after-journal-deletion', fatal: String(err && err.stack || err) }));
