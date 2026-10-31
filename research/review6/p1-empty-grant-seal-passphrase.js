'use strict';
// p1: does an EMPTY (or newline-only) seal passphrase file silently DISABLE
// sealed-grant mode instead of failing closed?
//
// bin/signerd.js readPassphrase() returns '' for an empty file, and
// src/daemon.js decides "seal mode on" from the LENGTH of the string:
//
//   this.sealKeyFor = typeof grantSealPassphrase === 'string'
//     && grantSealPassphrase.length > 0 ? makeSealKeyProvider(...) : null;
//
// So `--grant-seal-passphrase-file <empty file>` may degrade to UNSEALED mode
// in the daemon, while the very same empty passphrase is a hard error in
// `signerd status` (seal_passphrase_required) and in the journal side
// (journal_seal_passphrase_required). One flag, three behaviours.
//
// ATTACK: a stranger leaves a forged, UNSEALED grant document behind (the
// review-#5 p2 shape). The operator believes sealed mode is on. A wire
// paying the ATTACKER's destination must NOT be signed.
//
// Two grant files are used, so each layer is measured on its own:
//   sealed.json  - honestly sealed (CLI-layer passphrase tests)
//   forged.json  - unsealed, destination = attacker (the e2e test)

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const {
  fixture, makeWire, writeJson, grantDoc, tmpdir, start, stop, request, verdict,
} = require('./common');
const { loadGrantFile } = require('../../src/grantfile');
const { sealDocument, makeSealKeyProvider } = require('../../src/grantseal');

const BIN = path.join(__dirname, '..', '..', 'bin', 'signerd.js');
const { spawnSync } = require('node:child_process');

function runCli(args) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', timeout: 30000 });
  return {
    status: r.status,
    stdout: (r.stdout || '').trim().slice(0, 300),
    stderr: (r.stderr || '').trim().slice(0, 300),
    accepted: r.status === 0,
  };
}

async function main() {
  const dir = tmpdir();
  const out = { probe: 'p1-empty-grant-seal-passphrase', findings: [] };
  let daemon = null;
  try {
    const f = fixture(dir);
    const SEALED_FILE = path.join(dir, 'sealed.json');
    const FORGED_FILE = path.join(dir, 'forged.json');
    const LEDGER = path.join(dir, 'j.jsonl');

    // --- the honestly sealed document (CLI-layer tests) ---
    const sealed = sealDocument(grantDoc(f.keypair.publicKey.toBase58(), f.honest),
      'the operator seal passphrase');
    writeJson(SEALED_FILE, sealed, 0o600);

    // --- the forged document a stranger leaves behind (e2e test) ---
    const forged = grantDoc(f.keypair.publicKey.toBase58(), f.attacker,
      { maxLamports: '1000000000', windowMaxLamports: '1000000000' });
    writeJson(FORGED_FILE, forged, 0o600);

    // --- the operator's seal passphrase file: EMPTY (a touched file) ---
    fs.writeFileSync(f.sealPassFile, '');
    fs.chmodSync(f.sealPassFile, 0o600);

    // ================= CLI layer =================
    out.cli_status_sealed_doc_empty_passphrase = runCli([
      'status', '--grants', SEALED_FILE, '--ledger', LEDGER,
      '--grant-seal-passphrase-file', f.sealPassFile,
    ]);
    out.cli_verify_grants_empty_passphrase = runCli([
      'verify-grants', '--grants', SEALED_FILE, '--seal-passphrase-file', f.sealPassFile,
    ]);

    // ================= library layer =================
    // What `new Daemon({grantSealPassphrase: ''})` computes:
    out.daemon_sealKeyFor_for_empty_string =
      (typeof '' === 'string' && ''.length > 0) ? 'provider (sealed mode ON)' : 'null (sealed mode OFF)';

    // The `status` code path builds a provider unconditionally:
    try {
      loadGrantFile(SEALED_FILE, { sealKeyFor: makeSealKeyProvider('') });
      out.loadGrantFile_empty_passphrase_provider = 'ACCEPTED';
    } catch (err) { out.loadGrantFile_empty_passphrase_provider = `REFUSED: ${err.code || err.message}`; }

    // The journal side of the same empty passphrase:
    const { Ledger } = require('../../src/ledger');
    try {
      new Ledger({ file: path.join(dir, 'j2.jsonl'), sealPassphrase: '' });
      out.journal_empty_passphrase = 'ACCEPTED (fail-open)';
    } catch (err) { out.journal_empty_passphrase = `REFUSED: ${err.code || err.message}`; }

    // ================= END TO END =================
    // The daemon is given EXACTLY what bin/signerd.js would pass after
    // readPassphrase() on an empty file: ''.
    f.grantFile = FORGED_FILE;
    let started = true;
    try {
      daemon = await start(f, { grantSealPassphrase: '' });
    } catch (err) {
      started = false;
      out.e2e_daemon_start = `REFUSED at start: ${err.code || err.message}`;
    }
    if (started) {
      const w = makeWire(f.keypair, f.attacker); // pay the ATTACKER
      const resp = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
      out.e2e_empty_passphrase_daemon_forged_grant = {
        ok: resp.ok,
        error: resp.error,
        verdict: resp.ok ? 'ACCEPTED - FORGED GRANT SIGNED (fail-open)' : `REFUSED (${resp.error})`,
      };
      if (resp.ok) {
        const { VersionedTransaction } = require('@solana/web3.js');
        const tx = VersionedTransaction.deserialize(Buffer.from(resp.signed, 'base64'));
        out.signed_destination = tx.message.accountKeys[1].toBase58();
        out.destination_is_attacker = out.signed_destination === f.attacker;
      }
    }

    // ================= CONTROL =================
    // The SAME forged file with a NON-empty passphrase must be refused, and
    // the daemon must refuse to start (sealed mode really on).
    await stop(daemon); daemon = null;
    fs.writeFileSync(f.sealPassFile, 'the operator seal passphrase\n');
    fs.chmodSync(f.sealPassFile, 0o600);
    try {
      loadGrantFile(FORGED_FILE, { sealKeyFor: makeSealKeyProvider('the operator seal passphrase') });
      out.control_nonempty_passphrase_on_forged = 'ACCEPTED (!!)';
    } catch (err) { out.control_nonempty_passphrase_on_forged = `REFUSED: ${err.code || err.message}`; }
    f.grantFile = FORGED_FILE;
    try {
      const d = await start(f, { grantSealPassphrase: 'the operator seal passphrase' });
      await stop(d); daemon = null;
      out.control_daemon_with_real_passphrase = 'STARTED (!!)';
    } catch (err) {
      out.control_daemon_with_real_passphrase = `REFUSED at start: ${err.code || err.message}`;
    }

    out.findings.push(
      started && out.e2e_empty_passphrase_daemon_forged_grant.verdict === 'ACCEPTED - FORGED GRANT SIGNED (fail-open)'
        ? 'NEW FINDING: --grant-seal-passphrase-file with an empty file silently disables sealed-grant mode (the forged, unsealed grant is signed)'
        : 'held: the empty passphrase was refused everywhere it was exercised'
    );
  } catch (err) {
    out.threw = `${err.code || ''}: ${err.message}`;
    out.findings.push('probe threw (see threw)');
  } finally {
    await stop(daemon);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p1-empty-grant-seal-passphrase', fatal: String(err && err.stack || err) }));
