#!/usr/bin/env node
'use strict';
// Measure the VERDICT surfaces' ONE-KEY rule on TWO trees: the PRE-FIX tree
// and the FIXED tree, with the SAME probe.
//
// WHAT IT MEASURES: whether the surfaces that TELL THE OPERATOR whether a
// grant file is usable agree with the DAEMON about what a usable file is.
//
// v0.2.32 (2026-11-17) put the rule on the WRITE paths: `grant-add --append`
// and the message bootstrap refuse a grant that pins another key
// (grant_file_key_mismatch). The other half of the same rule was left open:
//
//   $ signerd status --grants g.json --ledger j.json
//   {"ok":true,"grants":["foreign","good"],...}         <- ok:true
//   $ signerd verify-grants --grants g.json --seal-passphrase-file p
//   {"ok":true,"grants":["foreign","good"]}             <- ok:true
//   $ signerd seal-grants --grants g.json --seal-passphrase-file p
//   {"ok":true,"grants":[{"name":"foreign",...},...]}   <- SEALED IT
//   $ signerd run --keystore ops.key --grants g.json ...
//   grant_signer_mismatch: foreign                       <- the daemon refuses
//
// A file that pins TWO keys can never be run by this daemon (signerd holds
// exactly ONE key; src/daemon.js #reloadGrants refuses the whole file), so
// all three surfaces report a DEAD file as fine - and `seal-grants` makes it
// AUTHENTIC, the strongest provenance statement the product can make about
// content nothing will ever sign. A verdict that degrades is not a verdict:
// the same class the repo closed on 2026-11-16 (v0.2.28, grant half vs
// journal half of the seal).
//
// FACES (each runs the tree's own CLI):
//   V1 status-two-key     `status` on an unsealed two-key file
//   V2 seal-two-key       `seal-grants` on an unsealed two-key file
//   V3 verify-sealed-two  `verify-grants` on a SEALED two-key file (the
//                         state an operator reaches by sealing on an older
//                         tree, or by hand-editing and re-sealing: the MAC
//                         is valid, the payload is dead)
//   G1 status-single      GUARD: one key, still fine
//   G2 seal-single        GUARD: one key, still fine
//   G3 verify-single      GUARD: one key, still fine
//   G4 cross-encoding     GUARD: tx grant base58 + message grant base64 of
//                         the SAME key - one key, must still be accepted
//   G5 remove-repairs     GUARD: `grant-remove` still repairs a file that is
//                         already broken (the loader must stay readable)
//
// A defect face is DEFECTIVE when the surface answers exit 0 / ok:true for a
// file no daemon can run, or when it changes the bytes (sealing it).
//
// Usage:
//   node tools/measure-grant-key-verdict.js --prefix <ref> --out <file>
//
//   --prefix <ref>  a git ref materialized with `git archive` (e.g. v0.2.32)
//                   as the PRE-FIX baseline - never this working tree.
//   --out <file>    where to write the JSON verdict (default:
//                   research/grant-key-verdict-<date>.json).
//
// EXIT: 0 when the measurement is sound AND the fixed tree refuses every
// defect face with every guard holding; 1 otherwise.
//
// No network. No writes outside os.tmpdir() and the output file.

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
// --published <dir>: measure an INSTALLED signerd (the bytes a stranger
// installs) instead of this checkout, as the sibling instruments do.
const PUBLISHED = opt('published', null);
const REPO = path.resolve(__dirname, '..');
const FIXED_DIR = PUBLISHED ? path.resolve(PUBLISHED) : REPO;

function sh(cmd, opts = {}) {
  return spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, ...opts });
}

function envFor() {
  // The installed package has no node_modules of its own: its dependencies
  // resolve upward, and this checkout supplies the key module for probes.
  return { ...process.env, NODE_PATH: path.join(REPO, 'node_modules') };
}

/** Materialize a git ref into a temp dir (the published baseline). */
function materialize(ref) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-keyverdict-'));
  const tar = execFileSync('git', ['-C', REPO, 'archive', ref], { maxBuffer: 256 * 1024 * 1024 });
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: tar, timeout: 120000 });
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  return dir;
}

/** Fresh secret dir with a seal passphrase; no paths leave the report. */
function caseDir(tag, name) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-keyverdict-${tag}-${name}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return {
    root, cfg, sealPass,
    grants: path.join(cfg, 'grants.json'),
    ledger: path.join(cfg, 'ledger.jsonl'),
  };
}

/** The key module of the FIXED tree (published trees ship the same module). */
function keypair() {
  const { Keypair } = require(path.join(REPO, 'node_modules', '@solana/web3.js'));
  return Keypair.generate();
}

function txGrant(keypair) {
  return {
    signer: keypair.publicKey.toBase58(),
    destination: 'So11111111111111111111111111111111111111112',
    maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxLamports: '500000000',
    windowSeconds: '3600',
  };
}

function messageGrant(keypair) {
  const raw = Buffer.from(keypair.publicKey.toBytes());
  return {
    kind: 'message',
    issuer: 'acme', type: 'release', subject: 'acme/app',
    pubkey: raw.toString('base64'),
    maxBytes: '512',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxMessages: '10',
    windowSeconds: '3600',
  };
}

function writeGrants(file, grants) {
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants }, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function fileState(p) {
  try {
    const st = fs.lstatSync(p);
    return { missing: false, mode: st.mode & 0o777, bytes: fs.readFileSync(p, 'utf8') };
  } catch (err) {
    return { missing: true, mode: null, bytes: null };
  }
}

function reasonOf(stderr) {
  const m = String(stderr).match(/\b(grant_[a-z_]+)\b/);
  return m ? m[1] : null;
}

/** Prepare the file state for a case. */
function prepare(c, name, sealFn) {
  if (name === 'remove-repairs' || name === 'status-two-key' || name === 'seal-two-key') {
    writeGrants(c.grants, { good: txGrant(keypair()), foreign: txGrant(keypair()) });
    return;
  }
  if (name === 'verify-sealed-two') {
    writeGrants(c.grants, { good: txGrant(keypair()), foreign: txGrant(keypair()) });
    const passphrase = fs.readFileSync(c.sealPass, 'utf8').replace(/\n$/, '');
    const doc = JSON.parse(fs.readFileSync(c.grants, 'utf8'));
    fs.writeFileSync(c.grants, JSON.stringify(sealFn(doc, passphrase), null, 2) + '\n',
      { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
    return;
  }
  if (name === 'status-single' || name === 'remove-repairs') {
    writeGrants(c.grants, { good: txGrant(keypair()) });
    return;
  }
  if (name === 'seal-single') {
    writeGrants(c.grants, { good: txGrant(keypair()) });
    return;
  }
  if (name === 'verify-single') {
    // verify-grants VERIFIES A SEAL, so the file must be sealed first: the
    // guard asks whether a legitimate single-key sealed file still passes.
    writeGrants(c.grants, { good: txGrant(keypair()) });
    const passphrase = fs.readFileSync(c.sealPass, 'utf8').replace(/\n$/, '');
    const doc = JSON.parse(fs.readFileSync(c.grants, 'utf8'));
    fs.writeFileSync(c.grants, JSON.stringify(sealFn(doc, passphrase), null, 2) + '\n',
      { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
    return;
  }
  if (name === 'cross-encoding') {
    const k = keypair();
    writeGrants(c.grants, { ops: txGrant(k), releases: messageGrant(k) });
    return;
  }
  throw new Error(`unknown case ${name}`);
}

function runCase(treeDir, tag, name) {
  const c = caseDir(tag, name);
  // The seal function of the tree under test: a published tree ships its own.
  const { sealDocument } = require(path.join(treeDir, 'src', 'grantseal'));
  prepare(c, name, sealDocument);
  const cli = path.join(treeDir, 'bin', 'signerd.js');

  const argsFor = {
    'status-two-key': ['status', '--grants', c.grants, '--ledger', c.ledger],
    'seal-two-key': ['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass],
    'verify-sealed-two': ['verify-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass],
    'status-single': ['status', '--grants', c.grants, '--ledger', c.ledger],
    'seal-single': ['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass],
    'verify-single': ['verify-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass],
    'cross-encoding': ['status', '--grants', c.grants, '--ledger', c.ledger],
    'remove-repairs': ['grant-remove', '--grants', c.grants, '--name', 'foreign'],
  }[name];

  const before = fileState(c.grants);
  const r = sh([process.execPath, cli, ...argsFor], { env: envFor() });
  const after = fileState(c.grants);

  const sealedAfter = (() => {
    try { return JSON.parse(fs.readFileSync(c.grants, 'utf8')).seal !== undefined; }
    catch { return false; }
  })();

  let repairWorked = null;
  if (name === 'remove-repairs') {
    try {
      const { loadGrantFile } = require(path.join(treeDir, 'src', 'grantfile'));
      repairWorked = loadGrantFile(c.grants).names.join(',') === 'good';
    } catch { repairWorked = false; }
  }

  return {
    case: name,
    status: r.status,
    okVerdict: /"ok":true/.test(r.stdout),
    reason: reasonOf(r.stderr),
    fileUnchanged: before.bytes === after.bytes && before.mode === after.mode,
    sealed: sealedAfter,
    repairWorked,
    // Scratch directories never reach the committed artifact: the transient
    // root is replaced by <case>/ and only the first two lines are kept.
    stderrHead: r.stderr.split('\n').slice(0, 2).join(' | ').split(c.root).join('<case>/'),
  };
}

const DEFECT_CASES = ['status-two-key', 'seal-two-key', 'verify-sealed-two'];
const GUARD_CASES = ['status-single', 'seal-single', 'verify-single', 'cross-encoding', 'remove-repairs'];

function measure(treeDir, tag) {
  const defects = {};
  for (const name of DEFECT_CASES) defects[name] = runCase(treeDir, tag, name);
  const guards = {};
  for (const name of GUARD_CASES) guards[name] = runCase(treeDir, tag, name);
  return { defects, guards };
}

function main() {
  if (!PREFIX) {
    process.stderr.write('usage: measure-grant-key-verdict.js --prefix <ref> --out <file.json>\n');
    process.exit(2);
  }
  const prefixDir = materialize(PREFIX);
  const fixedDir = FIXED_DIR;

  const prefix = measure(prefixDir, 'prefix');
  const fixed = measure(fixedDir, 'fixed');

  // Soundness: the pre-fix tree must SHOW every defect face (otherwise the
  // instrument proves nothing), and the fixed tree must refuse every one
  // with the file untouched.
  const prefixShowsAll = DEFECT_CASES.every((n) => {
    const d = prefix.defects[n];
    return d.status === 0 && d.okVerdict;
  });
  const prefixSealsIt = prefix.defects['seal-two-key'].sealed === true;
  const fixedRefusesAll = DEFECT_CASES.every((n) => {
    const d = fixed.defects[n];
    return d.status !== 0 && d.okVerdict === false;
  });
  const fixedFileUntouched = fixed.defects['seal-two-key'].fileUnchanged &&
    fixed.defects['seal-two-key'].sealed === false;
  const guardsHold = GUARD_CASES.every((n) => {
    const g = fixed.guards[n];
    return g.status === 0 && g.okVerdict === true;
  }) && fixed.guards['remove-repairs'].repairWorked === true;

  const verdict = prefixShowsAll && prefixSealsIt && fixedRefusesAll &&
    fixedFileUntouched && guardsHold
    ? 'grant-key-verdict-holds'
    : 'grant-key-verdict-broken';

  const report = {
    schema: 'signerd/grant-key-verdict/v1',
    measuredAt: new Date().toISOString(),
    prefix: PREFIX,
    fixed: PUBLISHED ? 'published' : 'working-tree',
    verdict,
    defectCases: DEFECT_CASES,
    guardCases: GUARD_CASES,
    prefixTree: prefix,
    fixedTree: fixed,
    checks: {
      prefixShowsAllDefectFaces: prefixShowsAll,
      prefixSealsTheDeadFile: prefixSealsIt,
      fixedTreeRefusesEveryDefectFace: fixedRefusesAll,
      fixedTreeLeavesTheFileUntouched: fixedFileUntouched,
      guardsHoldOnFixedTree: guardsHold,
    },
  };
  if (OUT) {
    fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
    fs.writeFileSync(path.resolve(OUT), JSON.stringify(report, null, 2) + '\n');
  }
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(verdict === 'grant-key-verdict-holds' ? 0 : 1);
}

main();
