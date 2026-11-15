#!/usr/bin/env node
// Measure the SEAL SUMMARY of `signerd seal-grants` on TWO trees with the
// SAME probe.
//
// WHAT IT MEASURES: whether the summary the seal command prints names the
// scope it just certified. `seal-grants` exists partly because sealing a
// forged file makes the forgery valid — so it prints what it sealed. It
// printed a HAND-PICKED SUBSET of the fields it had just sealed:
//
//     { name, signer, destination, maxLamports, expiresAt }
//
// The defect faces (measured live on the published v0.2.26 tree, 812135f):
//   S1  tx grant — the rolling window budget was invisible: the summary of a
//       grant sealed with windowMaxLamports 18446744073709551615 (the u64
//       maximum, i.e. no budget at all) contained no budget field.
//   S2  message grant — the whole scope was invisible: the summary of a
//       message grant was {name, expiresAt} — no issuer, type, subject,
//       pubkey, maxBytes, windowMaxMessages, windowSeconds.
//   S3  drift — the summary is compared field by field against the sealed
//       document that was written: a printed value that differs from the
//       file, or a file field the summary dropped, is a violation.
//
// The guards (must hold on BOTH trees): sealing a valid file works and
// still names the grant; the fields the summary always had (name, signer,
// destination, maxLamports, expiresAt) are still there.
//
// HOW: each case runs the tree's own CLI (`node <tree>/bin/signerd.js
// seal-grants ...`) and reads the summary off stdout and the sealed
// document off disk. The pre-fix tree is materialized with `git archive
// <ref>` into a temp dir; node_modules come through NODE_PATH (no network).
//
// Usage:
//   node tools/measure-seal-grants-summary.js \
//     --prefix 812135f --out research/seal-grants-summary-2026-11-15.json
//
// EXIT: 0 when the instrument is sound (the pre-fix tree shows the faces)
// AND the fixed tree shows none with every guard holding; 1 otherwise.

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
const SIGNER = '11111111111111111111111111111111';
const PUBKEY_B64 = Buffer.alloc(32, 1).toString('base64');

function sh(cmd, opts = {}) {
  return spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, ...opts });
}

function envFor() {
  return { ...process.env, NODE_PATH: path.join(REPO, 'node_modules') };
}

function materialize(ref) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sealsummary-'));
  const tar = execFileSync('git', ['-C', REPO, 'archive', ref], { maxBuffer: 256 * 1024 * 1024 });
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: tar, timeout: 120000 });
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  return dir;
}

function txGrant(overrides = {}) {
  return Object.assign({
    signer: SIGNER,
    destination: DESTINATION,
    maxLamports: '1000',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxLamports: '18446744073709551615',
    windowSeconds: '1',
  }, overrides);
}

function messageGrant(overrides = {}) {
  return Object.assign({
    kind: 'message',
    issuer: 'acme',
    type: 'release',
    subject: 'acme/app',
    pubkey: PUBKEY_B64,
    maxBytes: '700',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxMessages: '5',
    windowSeconds: '3600',
  }, overrides);
}

const CASES = {
  'tx-window': { grants: { ops: txGrant() } },
  'message-scope': { grants: { releases: messageGrant() } },
};

function caseDir(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-sealsummary-${tag}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return { root, cfg, sealPass, grants: path.join(cfg, 'grants.json') };
}

function summaryOf(stdout) {
  const line = String(stdout).split('\n').filter((l) => l.trim().startsWith('{')).pop();
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
}

function runCase(treeCli, tag, name) {
  const c = caseDir(tag);
  const doc = { version: 1, grants: CASES[name].grants };
  fs.writeFileSync(c.grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(c.grants, 0o600);

  const r = sh([process.execPath, treeCli, 'seal-grants', '--grants', c.grants,
    '--seal-passphrase-file', c.sealPass], { env: envFor() });

  const out = summaryOf(r.stdout);
  const entry = out && Array.isArray(out.grants) ? out.grants[0] : null;
  let sealed = null;
  try { sealed = JSON.parse(fs.readFileSync(c.grants, 'utf8')); } catch { sealed = null; }

  const written = sealed && sealed.grants ? sealed.grants[Object.keys(sealed.grants)[0]] : null;
  const visible = entry ? Object.keys(entry).filter((k) => k !== 'name') : [];
  const missing = written ? Object.keys(written).filter((f) => !visible.includes(f)) : [];
  const contradicts = [];
  if (entry && written) {
    for (const [field, value] of Object.entries(entry)) {
      if (field === 'name') continue;
      if (written[field] !== value) contradicts.push(field);
    }
  }

  return {
    case: name,
    exit: r.status,
    ok: /"ok":true/.test(r.stdout),
    summaryFields: visible,
    missingFields: missing,
    contradictingFields: contradicts,
    // The defect, stated as a yes/no: does the summary name the budget and
    // the scope it just made valid?
    showsWindowBudget: !!(entry && entry.windowMaxLamports !== undefined),
    showsMessageScope: !!(entry && entry.kind === 'message' && entry.issuer !== undefined),
    driftFree: missing.length === 0 && contradicts.length === 0,
  };
}

function measure(treeCli, tag) {
  const defects = {};
  for (const name of Object.keys(CASES)) defects[name] = runCase(treeCli, tag, name);
  // GUARD: a valid tx grant must still seal, still be named, and still carry
  // the fields the summary always had.
  const c = caseDir(tag);
  fs.writeFileSync(c.grants, JSON.stringify({
    version: 1,
    grants: { ops: txGrant({ windowMaxLamports: '500000000', windowSeconds: '3600' }) },
  }, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(c.grants, 0o600);
  const r = sh([process.execPath, treeCli, 'seal-grants', '--grants', c.grants,
    '--seal-passphrase-file', c.sealPass], { env: envFor() });
  const out = summaryOf(r.stdout);
  const entry = out && Array.isArray(out.grants) ? out.grants.find((g) => g.name === 'ops') : null;
  const guards = {
    valid: {
      exit: r.status,
      ok: /"ok":true/.test(r.stdout),
      named: !!entry,
      keepsSigner: !!(entry && entry.signer === SIGNER),
      keepsDestination: !!(entry && entry.destination === DESTINATION),
      keepsMaxLamports: !!(entry && entry.maxLamports === '1000'),
      keepsExpiresAt: !!(entry && entry.expiresAt === '2030-01-01T00:00:00Z'),
    },
  };
  return { defects, guards };
}

function main() {
  if (!PREFIX) {
    process.stderr.write('usage: measure-seal-grants-summary.js --prefix <ref> --out <file.json>\n');
    process.exit(2);
  }
  const prefixDir = materialize(PREFIX);
  const prefix = measure(path.join(prefixDir, 'bin', 'signerd.js'), 'prefix');
  const fixed = measure(path.join(REPO, 'bin', 'signerd.js'), 'fixed');

  const faces = ['tx-window', 'message-scope'];
  const prefixShows = faces.filter((f) =>
    !prefix.defects[f].showsWindowBudget && !prefix.defects[f].showsMessageScope);
  const fixedShows = faces.filter((f) =>
    !fixed.defects[f].showsWindowBudget && !fixed.defects[f].showsMessageScope);
  const fixedDrift = faces.filter((f) => !fixed.defects[f].driftFree);
  const guardsHold = fixed.guards.valid.ok && fixed.guards.valid.named &&
    fixed.guards.valid.keepsSigner && fixed.guards.valid.keepsDestination &&
    fixed.guards.valid.keepsMaxLamports && fixed.guards.valid.keepsExpiresAt;

  const instrumentSound = prefixShows.length === faces.length;
  const verdict = instrumentSound && fixedShows.length === 0 && fixedDrift.length === 0 &&
    guardsHold ? 'seal-grants-summary-holds' : 'seal-grants-summary-defect-present';

  const report = {
    schema: 'signerd/seal-grants-summary/v1',
    tool: 'measure-seal-grants-summary.js',
    measuredAt: new Date().toISOString(),
    prefix: PREFIX,
    fixedTree: 'working tree',
    verdict,
    instrumentSound,
    faces,
    prefixShowsDefect: prefixShows,
    fixedShowsDefect: fixedShows,
    fixedDrift,
    guardsHold,
    prefixTree: prefix,
    fixedTreeResults: fixed,
  };

  if (OUT) {
    fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
  }
  process.stdout.write(JSON.stringify({
    verdict,
    prefixShowsDefect: prefixShows,
    fixedShowsDefect: fixedShows,
    fixedDrift,
    guardsHold,
  }, null, 2) + '\n');
  process.exit(verdict === 'seal-grants-summary-holds' ? 0 : 1);
}

main();
