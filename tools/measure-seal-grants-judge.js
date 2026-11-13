#!/usr/bin/env node
// Measure the SEAL COMMAND's judgement of a grant file on TWO trees: the
// PRE-FIX tree and the FIXED tree, with the SAME probe.
//
// WHAT IT MEASURES: whether `signerd seal-grants` refuses a grant file that
// the PRODUCT's own loader (src/grantfile.js) refuses — the rule the
// sibling write paths already keep:
//   - extendGrantFile    (`grant-add --append`):  "THE JUDGE: the product's
//     loader, ... Nothing is written until the whole file has been accepted."
//   - removeGrantFromFile (`grant-remove`):       same rule, same wording.
//   - addGrantToFile      (`sign-message --add-grant`): fixed for exactly
//     this class on 2026-11-11 (v0.2.17).
// seal-grants was the one write path left behind: it hand-parsed the
// document and sealed whatever it found.
//
// The four defect faces (measured live on the pre-fix tree 98bcfa0 =
// published v0.2.20, 2026-11-13):
//   S1  broken-grant   an existing grant the loader refuses
//                      (windowMaxLamports:"1" — below the 5000-lamport base
//                      fee): seal-grants exited 0 with {"ok":true}; the
//                      loader refused grant_field_invalid.
//   S2  typo-field     a grant with a misspelled field (maxLamport): the
//                      seal made the typo AUTHENTIC — the loader still
//                      refuses grant_unknown_field.
//   S3  reserved-name  a grant named "__proto__": seal-grants reported
//                      grants:[] (the name vanished from the summary) while
//                      the loader refuses grant_name_invalid.
//   S4  symlink        a symlink at the grant path was written THROUGH
//                      (the loader refuses one with O_NOFOLLOW).
// The guards (must hold on BOTH trees — the fix must not break the
// documented repair paths): sealing a valid file, re-sealing an already
// sealed valid file, seal-grants --out to another path.
//
// HOW: each case runs the tree's own CLI (`node <tree>/bin/signerd.js
// seal-grants ...`) and records the verdict, the refusal reason, and the
// file state (bytes, mode, link) before/after. The pre-fix tree is
// materialized with `git archive <ref>` into a temp dir; node_modules are
// supplied through NODE_PATH (no network, no install).
//
// Usage:
//   node tools/measure-seal-grants-judge.js \
//     --prefix 98bcfa0 --out research/seal-grants-judge-2026-11-13.json
//
// EXIT: 0 when the measurement is sound AND the fixed tree refuses every
// defect face with every guard holding; 1 otherwise (instrument unsound =
// the pre-fix tree does not show a face, or the fixed tree shows one).

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');

const args = process.argv.slice(2);
function opt(name, fallback) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return args[i + 1];
}
const OUT = opt('out', null);
const PREFIX = opt('prefix', null);
const REPO = path.resolve(__dirname, '..');
const DESTINATION = 'So11111111111111111111111111111111111111112';

function sh(cmd, opts = {}) {
  return spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, ...opts });
}

function envFor() {
  return { ...process.env, NODE_PATH: path.join(REPO, 'node_modules') };
}

function materialize(ref) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sealjudge-'));
  const tar = execFileSync('git', ['-C', REPO, 'archive', ref], { maxBuffer: 256 * 1024 * 1024 });
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: tar, timeout: 120000 });
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  return dir;
}

function validGrant() {
  return {
    signer: DESTINATION, destination: DESTINATION, maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z', windowMaxLamports: '500000000',
    windowSeconds: '3600',
  };
}

function caseDir(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-sealjudge-${tag}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return { root, cfg, sealPass, grants: path.join(cfg, 'grants.json') };
}

function fileState(p) {
  try {
    const st = fs.lstatSync(p);
    return {
      isSymlink: st.isSymbolicLink(),
      missing: false,
      mode: st.mode & 0o777,
      bytes: st.isSymbolicLink() ? null : fs.readFileSync(p, 'utf8'),
    };
  } catch (err) {
    return { isSymlink: false, missing: true, mode: null, bytes: null };
  }
}

function reasonOf(stderr) {
  const m = String(stderr).match(/\b(grant_[a-z_]+)\b/);
  return m ? m[1] : null;
}

function prepare(c, name) {
  if (name === 'broken-grant') {
    const g = validGrant();
    g.windowMaxLamports = '1'; // below the base fee: the loader refuses it
    fs.writeFileSync(c.grants, JSON.stringify({ version: 1, grants: { releases: g } }, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
    return;
  }
  if (name === 'typo-field') {
    const g = validGrant();
    g.maxLamport = g.maxLamports; // a misspelled field: unknown to the loader
    delete g.maxLamports;
    fs.writeFileSync(c.grants, JSON.stringify({ version: 1, grants: { releases: g } }, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
    return;
  }
  if (name === 'reserved-name') {
    // RAW JSON text: a JS-side assignment would hit the prototype setter.
    fs.writeFileSync(c.grants,
      `{"version": 1, "grants": {"__proto__": ${JSON.stringify(validGrant())}}}\n`, { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
    return;
  }
  if (name === 'symlink') {
    const target = path.join(c.cfg, 'real-target.json');
    fs.writeFileSync(target, JSON.stringify({ version: 1, grants: { releases: validGrant() } }, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(target, 0o600);
    fs.symlinkSync(target, c.grants);
    return;
  }
  if (name === 'valid' || name === 'reseal' || name === 'out-copy') {
    fs.writeFileSync(c.grants, JSON.stringify({ version: 1, grants: { releases: validGrant() } }, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
    return;
  }
  throw new Error(`unknown case ${name}`);
}

function runCase(treeCli, tag, name) {
  const c = caseDir(tag);
  prepare(c, name);
  const argsList = ['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass];
  if (name === 'out-copy') argsList.push('--out', path.join(c.cfg, 'sealed.json'));

  const before = fileState(c.grants);
  const first = sh([process.execPath, treeCli, ...argsList], { env: envFor() });
  const after = fileState(c.grants);

  // The loader's own verdict on the same file (the JUDGE this command must
  // agree with). For the symlink case the loader reads the link's target,
  // so the verdict is taken on the real file.
  const judgeTarget = before.isSymlink ? fs.readlinkSync(c.grants) : c.grants;
  const judge = sh([process.execPath, treeCli, 'status', '--grants', judgeTarget,
    '--ledger', path.join(c.root, 'ledger.jsonl')], { env: envFor() });

  const sealed = (() => {
    try { return JSON.parse(fs.readFileSync(c.grants, 'utf8')).seal !== undefined; }
    catch { return false; }
  })();

  return {
    case: name,
    loaderRefused: judge.status !== 0,
    loaderReason: reasonOf(judge.stderr),
    status: first.status,
    okVerdict: /"ok":true/.test(first.stdout),
    reason: reasonOf(first.stderr),
    fileUnchanged: before.bytes === after.bytes && before.mode === after.mode && before.isSymlink === after.isSymlink,
    wroteThroughSymlink: before.isSymlink && after.isSymlink === false,
    sealed,
    // Scratch directories never reach the committed artifact: only the
    // refusal's first two lines with the transient root replaced by <case>/
    // (pinned by test/seal-grants-judge-measurement.test.js P6).
    stderrHead: first.stderr.split('\n').slice(0, 2).join(' | ')
      .split(c.root).join('<case>'),
  };
}

const DEFECT_CASES = ['broken-grant', 'typo-field', 'reserved-name', 'symlink'];
const GUARD_CASES = ['valid', 'reseal', 'out-copy'];

function measure(treeCli, tag) {
  const defects = {};
  for (const name of DEFECT_CASES) defects[name] = runCase(treeCli, tag, name);
  const guards = {};
  for (const name of GUARD_CASES) guards[name] = runCase(treeCli, tag, name);
  return { defects, guards };
}

function main() {
  if (!PREFIX) {
    process.stderr.write('usage: measure-seal-grants-judge.js --prefix <ref> --out <file.json>\n');
    process.exit(2);
  }
  const prefixDir = materialize(PREFIX);
  const prefixCli = path.join(prefixDir, 'bin', 'signerd.js');
  const fixedCli = path.join(REPO, 'bin', 'signerd.js');

  const prefix = measure(prefixCli, 'prefix');
  const fixed = measure(fixedCli, 'fixed');

  // Soundness: the pre-fix tree must SHOW every defect face (otherwise the
  // instrument proves nothing), and the fixed tree must REFUSE every one.
  const prefixShowsAll = DEFECT_CASES.every((n) => prefix.defects[n].status === 0);
  const fixedRefusesAll = DEFECT_CASES.every((n) => {
    const d = fixed.defects[n];
    return d.status !== 0 && d.okVerdict === false && d.fileUnchanged;
  });
  const guardsHold = GUARD_CASES.every((n) => fixed.guards[n].status === 0 && fixed.guards[n].okVerdict);

  const verdict = prefixShowsAll && fixedRefusesAll && guardsHold
    ? 'seal-grants-judge-holds'
    : 'seal-grants-judge-broken';

  const report = {
    schema: 'signerd/seal-grants-judge/v1',
    measuredAt: new Date().toISOString(),
    prefix: PREFIX,
    verdict,
    defectCases: DEFECT_CASES,
    guardCases: GUARD_CASES,
    prefixTree: prefix,
    fixedTree: fixed,
    checks: {
      prefixShowsAllDefectFaces: prefixShowsAll,
      fixedTreeRefusesEveryDefectFace: fixedRefusesAll,
      guardsHoldOnFixedTree: guardsHold,
    },
  };
  if (OUT) {
    fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
    fs.writeFileSync(path.resolve(OUT), JSON.stringify(report, null, 2) + '\n');
  }
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(verdict === 'seal-grants-judge-holds' ? 0 : 1);
}

main();
