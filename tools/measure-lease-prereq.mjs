#!/usr/bin/env node
'use strict';

/**
 * MEASURE THE LEASE-HELPER PREREQUISITE SURFACE (2026-11-08).
 *
 * WHY (measured 2026-11-07, live, against the PUBLISHED tag v0.2.7
 * installed from an empty directory):
 *
 *   The daemon needs a small C helper (tools/leasecheck.c) for the
 *   kernel-enforced read lease that guards the grant file. The tarball
 *   ships the SOURCE, not the binary, so the helper is compiled at
 *   runtime with `cc`. A stranger on a machine without a C compiler got
 *   this as their first failure:
 *
 *     grant_file_lease_unavailable: grant_file_lease_unavailable: spawnSync cc ENOENT
 *
 *   Three defects in one refusal: the verdict is DOUBLED, the detail is
 *   an internal Node API name, and there is NO REPAIR. A read-only
 *   install directory produced a raw ld dump instead.
 *
 * WHAT THIS TOOL MEASURES (three real trees, no network):
 *   A  the PUBLISHED tag v0.2.7 (the tree a stranger installs) with no
 *      compiler  -> the defect, verbatim
 *   B  the PUBLISHED tag v0.2.7 with a read-only tools/ dir -> the ld dump
 *   C  the FIXED tree with no compiler -> the repair
 *   D  the FIXED tree with a read-only tools/ dir -> its own repair
 *   E  the FIXED tree with a working compiler -> the daemon starts
 *
 * The artifact is written to research/lease-prereq-<date>.json. It is a
 * MEASUREMENT, not an assertion: the verdict comes from what the CLI
 * actually printed.
 *
 * Usage: node tools/measure-lease-prereq.mjs [--out research/xxx.json]
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI_REL = path.join('bin', 'signerd.js');
const MISSING_CC = path.join(os.tmpdir(), 'signerd-no-such-compiler-for-measurement');

function sh(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: 'utf8', timeout: 120000, ...opts });
  const out = Buffer.isBuffer(res.stdout) ? res.stdout : Buffer.from(res.stdout || '');
  const err = Buffer.isBuffer(res.stderr) ? res.stderr : Buffer.from(res.stderr || '');
  return {
    status: res.status,
    stdout: opts.encoding === 'buffer' ? out : out.toString('utf8'),
    stderr: err.toString('utf8'),
  };
}

/**
 * Exactly what the tarball ships (package.json `files`), from any source
 * tree - the checkout, or a tag extracted from local git. The COMPILED
 * helper is never copied: the tarball never contains it, so the daemon
 * must build it at runtime (the step that fails without a compiler).
 */
function copyShippedTree(sourceRoot, dest, { readOnlyTools = false } = {}) {
  for (const d of ['bin', 'src', 'examples']) {
    fs.cpSync(path.join(sourceRoot, d), path.join(dest, d), { recursive: true });
  }
  for (const f of ['package.json', 'LICENSE', 'README.md']) {
    fs.copyFileSync(path.join(sourceRoot, f), path.join(dest, f));
  }
  fs.mkdirSync(path.join(dest, 'tools'), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, 'tools', 'leasecheck.c'), path.join(dest, 'tools', 'leasecheck.c'));
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dest, 'node_modules'), 'dir');
  if (readOnlyTools) fs.chmodSync(path.join(dest, 'tools'), 0o555);
  return path.join(dest, CLI_REL);
}

/** Extract a published tag from local git (offline; the tag object is local). */
function extractTag(ref, dest) {
  const res = sh('git', ['-C', ROOT, 'archive', '--format=tar', ref], { encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
  if (res.status !== 0) throw new Error(`git archive ${ref} failed: ${res.stderr}`);
  fs.mkdirSync(dest, { recursive: true });
  const tarPath = path.join(dest, '..', `${path.basename(dest)}.tar`);
  fs.writeFileSync(tarPath, res.stdout);
  const untar = sh('tar', ['-xf', tarPath, '-C', dest]);
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  fs.rmSync(tarPath, { force: true });
  return dest;
}

/** Remove a tree that may contain a read-only directory. */
function rmTree(dir) {
  try {
    fs.chmodSync(path.join(dir, 'tools'), 0o755);
  } catch { /* no tools dir */ }
  fs.rmSync(dir, { recursive: true, force: true });
}
function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lease-meas-'));
  const sb = path.join(dir, 'sb');
  fs.mkdirSync(sb, { mode: 0o700 });
  const pass = path.join(sb, 'pass');
  fs.writeFileSync(pass, 'lease-prereq passphrase\n', { mode: 0o600 });
  return { dir, sb, pass };
}

function cli(tree, args, env = {}) {
  return sh(process.execPath, [tree, ...args], {
    env: { ...process.env, ...env }, timeout: 30000,
  });
}

function prepare(tree, sb, pass) {
  const keygen = cli(tree, ['keygen', '--keystore', path.join(sb, 'ops.key'), '--passphrase-file', pass]);
  if (keygen.status !== 0) return { keygen: keygen.status, grantAdd: null };
  const add = cli(tree, ['grant-add',
    '--grants', path.join(sb, 'grants.json'), '--name', 'ops-24h',
    '--keystore', path.join(sb, 'ops.key'),
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000', '--window-max-lamports', '500000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  return { keygen: keygen.status, grantAdd: add.status };
}

function runArgs(sb) {
  return ['run',
    '--keystore', path.join(sb, 'ops.key'),
    '--passphrase-file', path.join(sb, 'pass'),
    '--grants', path.join(sb, 'grants.json'),
    '--ledger', path.join(sb, 'journal.jsonl'),
    '--socket', path.join(sb, 'signerd.sock')];
}

/** Classify a refusal the way the stranger reads it. */
function classify(res) {
  const err = res.stderr || '';
  const first = err.split('\n')[0] || '';
  const code = (first.split(':')[0] || '').trim();
  const occurrences = code ? (err.match(new RegExp(code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length : 0;
  return {
    exitCode: res.status,
    code,
    codeOccurrences: occurrences,
    doubledVerdict: occurrences > 1,
    hasFixLine: /\bfix:/.test(err),
    namesCompiler: /compiler/i.test(err),
    namesHelper: /leasecheck/.test(err),
    leaksNodeInternal: /spawnSync/.test(err),
    leaksCompilerDump: /collect2|ld: cannot open output file/.test(err),
    stderr: err.trim(),
  };
}

const cases = [];
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lease-measure-'));

// The PRE-FIX trees come from the published tag itself, so the defect is
// measured on what a stranger actually installs, not on this checkout.
const PRE_REF = process.argv.includes('--pre-ref')
  ? process.argv[process.argv.indexOf('--pre-ref') + 1]
  : 'v0.2.7';
const preSrc = extractTag(PRE_REF, path.join(tmpRoot, 'pre-src'));
const preVersion = JSON.parse(fs.readFileSync(path.join(preSrc, 'package.json'), 'utf8')).version;

for (const [id, label, readOnlyTools, env] of [
  ['A', 'no compiler', false, { CC: MISSING_CC }],
  ['B', 'read-only install dir', true, {}],
]) {
  const tree = copyShippedTree(preSrc, path.join(tmpRoot, `pre${id}`), { readOnlyTools });
  const { sb, pass } = sandbox();
  const prep = prepare(tree, sb, pass);
  const res = cli(tree, runArgs(sb), env);
  cases.push({ id, tree: `published tag ${PRE_REF}`, label, prep, ...classify(res) });
  rmTree(path.join(tmpRoot, `pre${id}`));
  fs.rmSync(sb, { recursive: true, force: true });
}

for (const [id, label, readOnlyTools, env] of [
  ['C', 'no compiler', false, { CC: MISSING_CC }],
  ['D', 'read-only install dir', true, {}],
]) {
  const tree = copyShippedTree(ROOT, path.join(tmpRoot, `fix${id}`), { readOnlyTools });
  const { sb, pass } = sandbox();
  const prep = prepare(tree, sb, pass);
  const res = cli(tree, runArgs(sb), env);
  cases.push({ id, tree: 'fixed tree', label, prep, ...classify(res) });
  rmTree(path.join(tmpRoot, `fix${id}`));
  fs.rmSync(sb, { recursive: true, force: true });
}

// E: the fixed tree with a working compiler must START.
{
  const tree = copyShippedTree(ROOT, path.join(tmpRoot, 'fixE'), {});
  const { sb, pass } = sandbox();
  const prep = prepare(tree, sb, pass);
  const res = spawnSync(process.execPath, [tree, ...runArgs(sb)], {
    encoding: 'utf8', timeout: 20000, env: process.env,
  });
  const started = (res.status === 0 && /"ok"\s*:\s*true/.test(res.stdout || '')) ||
    res.error?.code === 'ETIMEDOUT' || res.signal === 'SIGTERM';
  const helper = path.join(tmpRoot, 'fixE', 'tools', 'leasecheck');
  cases.push({
    id: 'E', tree: 'fixed tree', label: 'working compiler',
    prep, started, helperBuilt: fs.existsSync(helper),
    helperBytes: fs.existsSync(helper) ? fs.statSync(helper).size : 0,
    stdout: (res.stdout || '').trim().split('\n')[0] || '',
  });
  rmTree(path.join(tmpRoot, 'fixE'));
  fs.rmSync(sb, { recursive: true, force: true });
}

rmTree(tmpRoot);

const byId = Object.fromEntries(cases.map((c) => [c.id, c]));
const pre = byId.A;
const fixed = byId.C;

const verdict = {
  preFixDoubledVerdict: pre.doubledVerdict === true,
  preFixNoRepair: pre.hasFixLine === false,
  preFixLeaksInternal: pre.leaksNodeInternal === true,
  postFixSingleCode: fixed.codeOccurrences === 1,
  postFixHasRepair: fixed.hasFixLine === true,
  postFixNoInternalLeak: fixed.leaksNodeInternal === false,
  postFixReadOnlyHasOwnRepair: byId.D.hasFixLine === true && byId.D.leaksCompilerDump === false,
  postFixStillStarts: byId.E.started === true,
};

const artifact = {
  measuredAt: new Date().toISOString(),
  repo: 'https://github.com/auroraxo/signerd',
  preRef: PRE_REF,
  preVersion,
  postRef: 'working tree',
  postVersion: JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version,
  question: 'Does a stranger with no C compiler get an actionable refusal from `signerd run`?',
  method: 'three real trees (published tag v0.2.7 shape, fixed tree), offline, no network; the tarball ships the helper SOURCE and never the binary, so the helper is compiled at runtime',
  cases,
  verdict,
  noVerdict: Object.values(verdict).some((v) => v === false),
  reason: 'all verdict fields must hold for the fix to count as measured, not asserted',
};

const outArg = process.argv.indexOf('--out');
const out = outArg > -1 && process.argv[outArg + 1]
  ? path.resolve(process.argv[outArg + 1])
  : path.join(ROOT, 'research', `lease-prereq-${new Date().toISOString().slice(0, 10)}.json`);
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(artifact, null, 2) + '\n');
console.log(JSON.stringify({ out, verdict }, null, 2));
for (const c of cases) {
  console.log(`  ${c.id} ${c.tree.padEnd(16)} ${String(c.label).padEnd(24)} ${c.stderr ? c.stderr.split('\n')[0] : c.stdout}`);
}
process.exit(artifact.noVerdict ? 1 : 0);
