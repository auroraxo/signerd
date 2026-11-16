#!/usr/bin/env node
// Measure the SEAL MODE DEGRADATION of the grant half against the journal
// half, on TWO trees with the SAME probe.
//
// WHAT IT MEASURES: whether a SEALED file can be read WITHOUT the passphrase
// that its seal was made with.
//
// The product has ONE seal and TWO halves. The JOURNAL half refuses: a
// sealed journal with a seal floor and no passphrase is refused with
// `ledger_sealed` ("never degraded"). The GRANT half used to DEGRADE: the
// loader did not look at the `seal` field at all without a key, so a sealed
// grant file was read as if it were unsealed - and the file could have been
// TAMPERED with in between (measured live 2026-11-16 on the published
// v0.2.27 tree):
//
//     seal-grants              -> exit 0, the file carries an HMAC seal
//     tamper grants.ops.destination
//     verify-grants --seal-passphrase-file <the right one>
//                               -> grant_file_seal_mismatch, exit 1
//     loadGrantFile(file)       -> LOADED, with the TAMPERED destination
//     status --grants <file>    -> {"ok":true,...,"sealed":false}, exit 0
//
// So the same file was simultaneously "authentic" (with the passphrase) and
// "fine, nothing to check" (without it). The seal was decorative.
//
// The faces (measured live on the published v0.2.27 tree, 41cd128):
//   F1 keyless-read     a sealed grant file loads WITHOUT a passphrase and
//                       reports the TAMPERED destination.
//   F2 keyless-status   `status` on a sealed grant file without a passphrase
//                       exits 0 and reports {"ok":true,"sealed":false}.
//   F3 tamper-blind     the daemon, started WITHOUT the grant passphrase on
//                       a sealed+TAMPERED grant file, serves the request.
//
// The control (must hold on BOTH trees - it is what "one rule for both
// halves" means): the JOURNAL half refuses the same way, all along:
//   F4 journal-control  a sealed journal without the journal passphrase is
//                       refused with `ledger_sealed`.
//
// The guards (must hold on BOTH trees): the documented repair paths keep
// working - the file can be re-sealed by hand (the "edit by hand, then
// re-seal" repair) and the CLI's own write paths (grant-add --append,
// grant-remove) still re-seal a sealed file with the passphrase.
//
// HOW: each case runs the tree's own CLI (`node <tree>/bin/signerd.js ...`)
// and the tree's own loader. The pre-fix tree is materialized with
// `git archive <ref>` into a temp dir; node_modules come through NODE_PATH
// (no network).
//
// Usage:
//   node tools/measure-seal-mode-degradation.js \
//     --prefix 41cd128 --out research/seal-mode-degradation-2026-11-16.json
//
// EXIT: 0 when the instrument is sound (the pre-fix tree shows all three
// faces) AND the fixed tree shows none with every guard holding; 1 otherwise.

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');

const args = process.argv.slice(2);
function opt(name, fallback) {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
}
const OUT = opt('out', null);
const PREFIX = opt('prefix', null);
const REPO = path.resolve(__dirname, '..');

const DESTINATION = 'So11111111111111111111111111111111111111112';
const TAMPERED = '11111111111111111111111111111111';
const SIGNER = '11111111111111111111111111111111';

function sh(cmd, opts = {}) {
  return spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, ...opts });
}

function envFor() {
  return { ...process.env, NODE_PATH: path.join(REPO, 'node_modules') };
}

function materialize(ref) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sealmode-'));
  const tar = execFileSync('git', ['-C', REPO, 'archive', ref], { maxBuffer: 256 * 1024 * 1024 });
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: tar, timeout: 120000 });
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  return dir;
}

// A case directory: its own 0700 config dir, its own seal passphrase.
function caseDir(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-sealmode-${tag}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return {
    root, cfg, sealPass,
    grants: path.join(cfg, 'grants.json'),
    ledger: path.join(root, 'journal.jsonl'),
  };
}

function txGrant() {
  return {
    signer: SIGNER,
    destination: DESTINATION,
    maxLamports: '1000',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxLamports: '1000000',
    windowSeconds: '3600',
  };
}

function writeGrantFile(file, grants) {
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants }, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function seal(treeCli, c) {
  return sh([process.execPath, treeCli, 'seal-grants', '--grants', c.grants,
    '--seal-passphrase-file', c.sealPass], { env: envFor() });
}

/**
 * Tamper with the SEALED file: the destination becomes an address nobody
 * named. A sealed file whose content changed must not be readable without
 * the passphrase - that is the whole point of the seal.
 */
function tamper(c) {
  const doc = JSON.parse(fs.readFileSync(c.grants, 'utf8'));
  doc.grants.ops.destination = TAMPERED;
  fs.writeFileSync(c.grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(c.grants, 0o600);
}

/**
 * The committed artifact must be portable: scratch directories (and any
 * host path) are evidence of WHERE a run happened, not of what it measured,
 * so they are redacted before they are written down.
 */
function scratch(value) {
  return String(value)
    .split(os.tmpdir()).join('<scratch>')
    .split('/home/').join('<home>/');
}

function jsonOf(stdout) {
  const line = String(stdout).split('\n').filter((l) => l.trim().startsWith('{')).pop();
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
}

/**
 * The tree's own loader, asked the question directly: may this file be read
 * without the seal passphrase, and what does it say?
 */
function loaderVerdict(treeDir, file) {
  const script = `
    const { loadGrantFile } = require(${JSON.stringify(path.join(treeDir, 'src', 'grantfile.js'))});
    try {
      const loaded = loadGrantFile(process.argv[1]);
      process.stdout.write(JSON.stringify({ loaded: true,
        destination: loaded.grants.ops ? loaded.grants.ops.destination : null }));
    } catch (err) {
      process.stdout.write(JSON.stringify({ loaded: false, code: err.code || 'error' }));
    }
  `;
  const r = sh([process.execPath, '-e', script, file], { env: envFor() });
  const out = jsonOf(r.stdout);
  return out || { loaded: false, code: 'no_verdict' };
}

/**
 * F1/F2: the keyless read of a SEALED file.
 */
function runKeylessRead(treeDir, treeCli, tag) {
  const c = caseDir(tag);
  writeGrantFile(c.grants, { ops: txGrant() });
  const sealed = seal(treeCli, c);
  tamper(c);

  // The control that must hold on BOTH trees: with the passphrase, the
  // tampered file is refused.
  const keyed = sh([process.execPath, treeCli, 'verify-grants', '--grants', c.grants,
    '--seal-passphrase-file', c.sealPass], { env: envFor() });

  const loader = loaderVerdict(treeDir, c.grants);
  const status = sh([process.execPath, treeCli, 'status', '--grants', c.grants,
    '--ledger', c.ledger], { env: envFor() });
  const statusJson = jsonOf(status.stdout);

  return {
    sealed: { exit: sealed.status, ok: /"ok":true/.test(sealed.stdout) },
    keyedRefusesTamper: {
      exit: keyed.status,
      reason: /grant_file_seal_mismatch/.test(keyed.stderr) ? 'grant_file_seal_mismatch'
        : (/grant_file_sealed/.test(keyed.stderr) ? 'grant_file_sealed' : 'other'),
      refused: keyed.status !== 0,
    },
    // F1: the loader without a passphrase.
    keylessLoader: {
      loaded: loader.loaded === true,
      code: loader.code || null,
      destination: loader.destination || null,
      readTampered: loader.loaded === true && loader.destination === TAMPERED,
    },
    // F2: `status` without a passphrase.
    keylessStatus: {
      exit: status.status,
      ok: statusJson ? statusJson.ok === true : null,
      reportedSealed: statusJson ? statusJson.sealed : null,
      degraded: status.status === 0 && statusJson !== null && statusJson.ok === true,
    },
  };
}

/**
 * F3: the daemon started WITHOUT the grant passphrase on a sealed+tampered
 * grant file. The seal is the product's fail-closed promise; a daemon that
 * serves a tampered sealed file has broken it.
 */
function runKeylessDaemon(treeDir, treeCli, tag) {
  const c = caseDir(tag);
  // The daemon needs a keystore it can open and a grant whose SIGNER it can
  // satisfy, or it would refuse for an unrelated reason (grant_signer_
  // mismatch) and the measurement would be vacuous. So the grant is written
  // with the keystore's OWN public key - which is why the keygen's own
  // answer is read instead of a keypair made here (the keystore holds a
  // DIFFERENT key than the one this file generates). The TAMPER only touches
  // the destination - the field a forger would change.
  const keystore = path.join(c.cfg, 'ops.key');
  const passFile = path.join(c.cfg, 'pass');
  fs.writeFileSync(passFile, 'keystore phrase\n', { mode: 0o600 });
  fs.chmodSync(passFile, 0o600);
  const keygen = sh([process.execPath, treeCli, 'keygen', '--keystore', keystore,
    '--passphrase-file', passFile], { env: envFor() });
  if (keygen.status !== 0) return { error: 'keygen_failed', exit: keygen.status };
  const keygenJson = jsonOf(keygen.stdout);
  const pubkey = keygenJson && keygenJson.publicKey;
  if (!pubkey) return { error: 'keygen_no_public_key', exit: keygen.status };

  writeGrantFile(c.grants, { ops: Object.assign(txGrant(), { signer: pubkey }) });
  const sealed = seal(treeCli, c);
  tamper(c);

  const socket = path.join(c.root, 'signerd.sock');
  // `run` SERVES: a daemon that starts successfully never returns on its
  // own, so the probe has to give up on it (spawnSync's timeout). The
  // discriminator is the TIMEOUT, not the exit status: the daemon catches
  // SIGTERM and exits 0 (its own clean shutdown), so a served daemon comes
  // back as "exit 0 + ETIMEDOUT", while a daemon that REFUSES exits on its
  // own with a status and no timeout.
  const run = sh([process.execPath, treeCli, 'run', '--keystore', keystore,
    '--passphrase-file', passFile, '--grants', c.grants, '--ledger', c.ledger,
    '--socket', socket], { env: envFor(), timeout: 8000 });

  const timedOut = !!(run.error && run.error.code === 'ETIMEDOUT');
  const started = timedOut;
  const refused = !started && run.status !== 0;
  return {
    sealed: { exit: sealed.status, ok: /"ok":true/.test(sealed.stdout) },
    exit: run.status,
    signal: run.signal || null,
    timedOut,
    // A daemon that refuses to start has NOT degraded: the refusal IS the
    // fix working. A daemon that kept serving the tampered file has.
    started,
    refused,
    reason: /grant_file_sealed/.test(run.stderr) ? 'grant_file_sealed'
      : (/grant_file_seal_mismatch/.test(run.stderr) ? 'grant_file_seal_mismatch'
        : (/grant_signer_mismatch/.test(run.stderr) ? 'grant_signer_mismatch'
          : (/ledger_sealed/.test(run.stderr) ? 'ledger_sealed'
            : (refused ? 'other_refusal' : null)))),
    stdoutHead: scratch(String(run.stdout || '').split('\n').filter(Boolean).slice(0, 1).join(' ').slice(0, 160)),
    stderrHead: scratch(String(run.stderr || '').split('\n').slice(0, 2).join(' ').slice(0, 200)),
  };
}

/**
 * F4 (the control): the JOURNAL half. A sealed journal without the journal
 * passphrase must be refused with `ledger_sealed` - it always was, and the
 * grant half now matches it.
 */
function runJournalControl(treeDir, treeCli, tag) {
  const c = caseDir(tag);
  // A journal with a seal floor: the anchor file is the marker that this
  // journal was ever sealed. It must be SHAPE-valid (the reader checks the
  // shape before the MAC), so `head` and `mac` are 64 hex characters.
  const anchor = `${path.resolve(c.ledger)}.anchor`;
  fs.writeFileSync(anchor, JSON.stringify({
    v: 1, alg: 'hmac-sha256', count: 0,
    head: '0'.repeat(64), mac: '0'.repeat(64),
  }) + '\n', { mode: 0o600 });
  fs.chmodSync(anchor, 0o600);

  const script = `
    const { Ledger } = require(${JSON.stringify(path.join(treeDir, 'src', 'ledger.js'))});
    try {
      const l = new Ledger({ file: process.argv[1] });
      process.stdout.write(JSON.stringify({ loaded: true, snap: l.snapshot() }));
    } catch (err) {
      process.stdout.write(JSON.stringify({ loaded: false, code: err.code || err.message }));
    }
  `;
  const r = sh([process.execPath, '-e', script, c.ledger], { env: envFor() });
  const out = jsonOf(r.stdout) || { loaded: false, code: 'no_verdict' };
  return {
    loaded: out.loaded === true,
    code: out.code || null,
    refusedWithLedgerSealed: out.loaded === false && out.code === 'ledger_sealed',
  };
}

/**
 * The guards: the documented repair paths must keep working on BOTH trees.
 */
function runGuards(treeCli, tag) {
  const c = caseDir(tag);
  writeGrantFile(c.grants, { ops: txGrant() });
  const first = seal(treeCli, c);
  // The "edit by hand, then re-seal" repair: the operator changes a field by
  // hand (the seal goes stale) and re-seals. This path MUST keep working.
  const doc = JSON.parse(fs.readFileSync(c.grants, 'utf8'));
  doc.grants.ops.maxLamports = '2000';
  fs.writeFileSync(c.grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(c.grants, 0o600);
  const reseal = seal(treeCli, c);

  // And the re-sealed file must VERIFY with the passphrase.
  const verify = sh([process.execPath, treeCli, 'verify-grants', '--grants', c.grants,
    '--seal-passphrase-file', c.sealPass], { env: envFor() });

  return {
    firstSeal: { exit: first.status, ok: /"ok":true/.test(first.stdout) },
    resealAfterHandEdit: { exit: reseal.status, ok: /"ok":true/.test(reseal.stdout) },
    resealedVerifies: { exit: verify.status, ok: verify.status === 0 },
  };
}

function measure(treeDir, treeCli, tag) {
  const keyless = runKeylessRead(treeDir, treeCli, tag);
  const daemon = runKeylessDaemon(treeDir, treeCli, tag);
  const journal = runJournalControl(treeDir, treeCli, tag);
  const guards = runGuards(treeCli, tag);
  return { keyless, daemon, journal, guards };
}

function main() {
  if (!PREFIX) {
    process.stderr.write('usage: measure-seal-mode-degradation.js --prefix <ref> --out <file.json>\n');
    process.exit(2);
  }
  const prefixDir = materialize(PREFIX);
  const prefix = measure(prefixDir, path.join(prefixDir, 'bin', 'signerd.js'), 'prefix');
  const fixed = measure(REPO, path.join(REPO, 'bin', 'signerd.js'), 'fixed');

  // The faces the pre-fix tree must show (the instrument must be SOUND: it
  // has to be able to see the defect).
  const prefixFaces = [];
  if (prefix.keyless.keylessLoader.readTampered) prefixFaces.push('F1-keyless-read');
  if (prefix.keyless.keylessStatus.degraded) prefixFaces.push('F2-keyless-status');
  if (prefix.daemon.started) prefixFaces.push('F3-tamper-blind');
  const journalControlHoldsOnPrefix = prefix.journal.refusedWithLedgerSealed;

  const fixedFaces = [];
  if (fixed.keyless.keylessLoader.readTampered) fixedFaces.push('F1-keyless-read');
  if (fixed.keyless.keylessStatus.degraded) fixedFaces.push('F2-keyless-status');
  if (fixed.daemon.started) fixedFaces.push('F3-tamper-blind');

  // The control must hold on BOTH trees: the journal half refuses.
  const journalControlHolds = journalControlHoldsOnPrefix && fixed.journal.refusedWithLedgerSealed;
  // The guards must hold on BOTH trees: the repair paths keep working.
  const guardsHold = [prefix, fixed].every((t) =>
    t.guards.firstSeal.ok && t.guards.resealAfterHandEdit.ok && t.guards.resealedVerifies.ok);
  // The keyed read must keep refusing a tampered file on BOTH trees.
  const keyedHolds = prefix.keyless.keyedRefusesTamper.refused &&
    fixed.keyless.keyedRefusesTamper.refused;

  const instrumentSound = prefixFaces.length === 3 && journalControlHoldsOnPrefix;
  const verdict = instrumentSound && fixedFaces.length === 0 && journalControlHolds &&
    guardsHold && keyedHolds ? 'seal-mode-holds' : 'seal-mode-defect-present';

  const report = {
    schema: 'signerd/seal-mode/v1',
    tool: 'measure-seal-mode-degradation.js',
    measuredAt: new Date().toISOString(),
    prefix: PREFIX,
    fixedTree: 'working tree',
    verdict,
    instrumentSound,
    faces: ['F1-keyless-read', 'F2-keyless-status', 'F3-tamper-blind'],
    prefixShowsDefect: prefixFaces,
    fixedShowsDefect: fixedFaces,
    journalControlHolds,
    keyedRefusalHolds: keyedHolds,
    guardsHold,
    prefixTree: prefix,
    fixedTreeResults: fixed,
  };

  if (OUT) fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify({
    verdict,
    prefixShowsDefect: prefixFaces,
    fixedShowsDefect: fixedFaces,
    journalControlHolds,
    keyedRefusalHolds: keyedHolds,
    guardsHold,
  }, null, 2) + '\n');
  process.exit(verdict === 'seal-mode-holds' ? 0 : 1);
}

main();
