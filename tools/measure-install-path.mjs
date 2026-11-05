#!/usr/bin/env node
// measure-install-path — what a stranger hits for EACH install path this
// project advertises, measured live, never assumed.
//
// WHY (measured 2026-11-05): the awesome-solana-ai PR #280 body advertises
// `cargo install --git https://github.com/auroraxo/signerd --tag v0.1.0`
// as the working install path, but this repo is a Node package — there is
// no Cargo.toml, so that command fails. At the same time the RELEASED tag
// v0.1.0 predates the stranger-install fixes (its manifest still carried
// "private": true, its README had no quickstart), so the path that DOES
// exist (npm git-tags) served the pre-fix tree. Two wrong claims, opposite
// directions, both invisible to a reader of the PR.
//
// This instrument measures, for one ref:
//   1. GitHub clone of the tag: does Cargo.toml exist? (authoritative
//      absence when the tag resolves and the file does not)
//   2. `cargo install --git <repo> --tag <ref>`: exit + named error
//      (the exact command a stranger copies from the PR)
//   3. `npm install github:<repo>#<ref>`: exit, installed manifest
//      (version, private flag), README quickstart anchor
//
// The crates.io-403 lesson is baked in: a NETWORK failure is never written
// as an absence. DNS/timeout errors make the surface unmeasured and the
// whole run NO VERDICT (exit 3). Only authoritative answers (GitHub/NPM
// resolving a ref and naming what it contains) produce verdicts.
//
// Usage: node tools/measure-install-path.mjs [--ref v0.2.0] [--out file]
//   Default ref: v + package.json version. Exit 0 = measured, 3 = no-verdict.
'use strict';

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_URL = process.env.SIGNERD_INSTALL_PROBE_REPO || 'https://github.com/auroraxo/signerd';
const GH_SLUG = 'github:auroraxo/signerd';
const QUICKSTART_ANCHOR = 'umask 077'; // the owner-only quickstart the tag README must carry

function classifyGitError(stderr) {
  const s = String(stderr || '');
  if (/not found/i.test(s) && /(remote|branch|tag|revision)/i.test(s)) return 'ref-missing';
  if (/Could not resolve|ENOTFOUND|timed out|Connection refused|network/i.test(s)) return 'network';
  return 'other';
}

// Pure verdict derivation so the rules are testable without network.
// clone: {attempted, ok, cargoToml, errorKind?}
// cargo: {attempted, ok, cargoTomlMissing, errorKind?}  (missing binary => attempted:false)
// npm:   {attempted, ok, manifest?{version,private}|null, readmeQuickstart, errorKind?, refMissing?}
export function derive({ ref, clone, cargo, npm }) {
  const out = {
    ref,
    cargoClaim: 'unmeasured',
    npmTagPath: 'unmeasured',
    noVerdict: false,
    reason: null,
  };
  const fail = (reason) => { out.noVerdict = true; out.reason = reason; return out; };

  if (clone.attempted && !clone.ok && clone.errorKind === 'network') return fail('clone-network');
  if (clone.attempted && !clone.ok && clone.errorKind === 'ref-missing') {
    // Authoritative: GitHub resolved nothing for this ref.
    out.cargoClaim = 'tag-missing';
    out.npmTagPath = 'tag-missing';
    return out;
  }
  if (!clone.ok) return fail(`clone-${clone.errorKind || 'failed'}`);

  if (!cargo.attempted) return fail('cargo-binary-missing');
  if (!cargo.ok && cargo.errorKind) return fail(`cargo-${cargo.errorKind}`);
  out.cargoClaim = cargo.cargoTomlMissing ? 'false-no-cargo-artifact' : 'unexpected-cargo-result';

  if (npm.attempted && !npm.ok && npm.errorKind === 'network') return fail('npm-network');
  if (npm.attempted && !npm.ok && npm.refMissing) {
    out.npmTagPath = 'tag-missing';
    return out;
  }
  if (npm.attempted && !npm.ok) return fail(`npm-${npm.errorKind || 'failed'}`);
  if (!npm.manifest) return fail('npm-manifest-unreadable');

  const m = npm.manifest;
  const defects = [];
  if (m.private === true) defects.push('private-true');
  if (!npm.readmeQuickstart) defects.push('readme-no-quickstart');
  out.npmTagPath = defects.length ? `defective:${defects.join('+')}` : 'clean';
  return out;
}

function sh(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout || 300000, cwd: opts.cwd });
  return { code: res.status, stdout: res.stdout || '', stderr: res.stderr || '', eno: res.error && res.error.code === 'ENOENT' };
}

function measure(ref, outPath) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-installpath-'));
  const report = { measuredAt: new Date().toISOString(), repo: REPO_URL, ref, surfaces: {} };

  // 1. clone the tag (shallow, exactly what cargo/npm do under the hood)
  const cloneDir = path.join(work, 'clone');
  const cloneRes = sh('git', ['clone', '--depth', '1', '--branch', ref, REPO_URL, cloneDir]);
  const clone = {
    attempted: true,
    ok: cloneRes.code === 0,
    cargoToml: cloneRes.code === 0 && fs.existsSync(path.join(cloneDir, 'Cargo.toml')),
    errorKind: cloneRes.code === 0 ? undefined : classifyGitError(cloneRes.stderr),
  };
  report.surfaces.clone = { exitCode: cloneRes.code, cargoToml: clone.cargoToml, errorKind: clone.errorKind || null };

  // 2. the exact cargo command the PR advertises
  let cargo = { attempted: false };
  const cargoProbe = sh('cargo', ['--version']);
  if (cargoProbe.eno) {
    report.surfaces.cargo = { attempted: false, reason: 'cargo-binary-not-installed' };
  } else {
    const cRes = sh('cargo', ['install', '--git', REPO_URL, '--tag', ref], { timeout: 120000 });
    const cargoTomlMissing = /could not find .*Cargo\.toml/i.test(cRes.stderr + cRes.stdout);
    cargo = {
      attempted: true,
      ok: cRes.code === 0,
      cargoTomlMissing,
      errorKind: cRes.code === 0 || cargoTomlMissing
        ? undefined
        : (/network|Could not resolve|timed out/i.test(cRes.stderr) ? 'network' : undefined),
    };
    report.surfaces.cargo = {
      exitCode: cRes.code,
      cargoTomlMissing,
      errorTail: String(cRes.stderr || '').trim().split('\n').slice(-2).join(' | ').slice(0, 300),
    };
  }

  // 3. the npm git-tag install (the path that exists for a Node package)
  const consumer = path.join(work, 'consumer');
  fs.mkdirSync(consumer, { mode: 0o700, recursive: true });
  fs.writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({ name: 'installpath-probe', version: '0.0.0', private: true }));
  const nRes = sh('npm', ['install', '--no-audit', '--no-fund', `${GH_SLUG}#${ref}`], { timeout: 300000, cwd: consumer });
  const nErr = String(nRes.stderr || '');
  let npm;
  if (nRes.code === 0) {
    const manifestPath = path.join(consumer, 'node_modules', 'signerd', 'package.json');
    const readmePath = path.join(consumer, 'node_modules', 'signerd', 'README.md');
    let manifest = null;
    try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch { /* absent tree */ }
    const readme = fs.existsSync(readmePath) ? fs.readFileSync(readmePath, 'utf8') : '';
    npm = {
      attempted: true, ok: true, manifest: manifest && { version: manifest.version, private: manifest.private === true },
      readmeQuickstart: readme.includes(QUICKSTART_ANCHOR), errorKind: undefined, refMissing: false,
    };
  } else {
    const stderrAll = nRes.stdout + nErr;
    npm = {
      attempted: true, ok: false, manifest: null, readmeQuickstart: false,
      errorKind: classifyGitError(stderrAll),
      refMissing: /not found/i.test(stderrAll) && /(remote|tag|branch|No matching version)/i.test(stderrAll),
    };
  }
  report.surfaces.npm = {
    exitCode: nRes.code,
    manifest: npm.manifest,
    readmeQuickstart: npm.readmeQuickstart,
    errorKind: npm.errorKind || null,
    errorTail: String(nRes.stderr || '').trim().split('\n').slice(-2).join(' | ').slice(0, 300),
  };

  const verdict = derive({ ref, clone, cargo, npm });
  report.verdict = { cargoClaim: verdict.cargoClaim, npmTagPath: verdict.npmTagPath };
  report.noVerdict = verdict.noVerdict;
  report.reason = verdict.reason;

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify(report.verdict) + `\nartifact: ${outPath}\n`);
  return verdict.noVerdict ? 3 : 0;
}

const argv = process.argv.slice(2);
function argOf(name, fallback) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}

// main-guard: importing the module (the test does) must NOT run a live
// measurement; only executing it as a script does.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const ref = argOf('--ref', null) || `v${JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version}`;
  const out = argOf('--out', path.join(ROOT, 'research', `install-path-${ref}-${new Date().toISOString().slice(0, 10)}.json`));
  process.exit(measure(ref, out));
}
