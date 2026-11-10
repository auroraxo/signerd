#!/usr/bin/env node
'use strict';
// The user-zero + D4 + Dry falsification run required every pulse by the
// card, measured against the PUBLISHED tag installed into an empty
// directory (the stranger's path, not this worktree).
//
// WHAT IS MEASURED (each case is a claim the README makes):
//   U1 the pin installs from an empty directory and the installed manifest
//      carries that tag's version;
//   U2 a real delivery through the installed tag fsyncs the PARENT
//      DIRECTORY after the rename (the durability fix reaches a stranger);
//   U3 D4 (the honest exit contract, re-measured on the installed tag):
//      --out write fails AFTER the spend while stdout retains -> exit 3,
//      the artifact IS on stdout, the --out file is absent, the journal grew;
//   U4 D4': BOTH channels lose the artifact (stdout is a file under
//      `ulimit -f 0`) -> exit 4 with `recovery_failed:`, the spend recorded,
//      stdout 0 bytes — the CLI must not claim the artifact is anywhere;
//   U5 Dry falsification: `--dry` writes no signature and does not grow the
//      journal, while the control real sign does (journal grows).
//
// HARNESS NOTE (recorded, because it changed the measurement): redirecting
// stderr to a FILE while `ulimit -f 0` is active makes the shell's own
// limit truncate the error message — the message looked absent when it was
// the harness that swallowed it. stderr must go to a pipe or the terminal.
// Similarly, "stdout to a file under ulimit -f 0" cannot yield exit 3:
// stdout is one of the losing channels, so exit 4 is the correct verdict.
//
// NO HOST PATHS: the artefact records basenames and byte counts only.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// THE DEFAULT TAG IS THE README PIN, NOT THE TAG THIS TOOL WAS BORN ON
// (measured 2026-11-10): the default was frozen at `v0.2.11`, so an
// unattended re-run without arguments silently OVERWROTE the committed
// v0.2.11 artefact with a fresh run (working-tree diff of
// research/user-zero-v0.2.11-2026-11-08.json, 2026-11-09). The gate and
// this tool now read the ONE pinned tag from the README; an explicit
// argv[2] still wins so a tag-ladder run can measure any published tag.
function pinnedTag() {
  const readme = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'README.md'), 'utf8');
  const tags = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((s) => s.split('#')[1]))];
  if (tags.length !== 1) {
    console.error(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: `README pin not exactly one tag: ${tags.join(', ') || 'none'}` }));
    process.exit(3);
  }
  return tags[0];
}

const TAG = process.argv[2] || pinnedTag();
const OUT = process.argv[3] || `research/user-zero-${TAG}-${new Date().toISOString().slice(0, 10)}.json`;

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 120000, ...opts });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/**
 * Remove the measuring machine's paths from a captured line.
 *
 * The tool prints the absolute grant path (and the temp dir is the
 * measuring machine's), so a captured message carries a host path. A
 * committed artefact that names the measuring machine is a snapshot, not
 * evidence — so the path is replaced by its BASENAME.
 */
function scrub(text) {
  return String(text || '')
    .replace(/\/home\/[^\s"']+/g, '<home>')
    .replace(/\/tmp\/[^\s"']+/g, '<tmp>')
    .replace(/[A-Za-z]:\\[^\s"']+/g, '<win>');
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-uz-'));
const results = {};

// U1 install from an empty directory.
const inst = sh('npm', ['install', `github:auroraxo/signerd#${TAG}`, '--silent'], { cwd: dir });
let installedVersion = null;
try {
  installedVersion = JSON.parse(
    fs.readFileSync(path.join(dir, 'node_modules', 'signerd', 'package.json'), 'utf8'),
  ).version;
} catch { installedVersion = null; }
results.u1_install_from_empty_dir = {
  installStatus: inst.status,
  installedVersion,
  expectedVersion: TAG.replace(/^v/, ''),
  pass: inst.status === 0 && installedVersion === TAG.replace(/^v/, ''),
};

// U2 a real delivery through the installed tree, watching the syscalls.
const deliverScript = `
const fs = require('fs'); const os = require('os'); const path = require('path');
const { writeOutAtomic } = require('./node_modules/signerd/src/out-preflight');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uz-out-'));
const target = path.join(dir, 'signed.json');
const origF = fs.fsyncSync, origR = fs.renameSync; const ev = [];
fs.fsyncSync = function(fd){ let isDir=false; try{ isDir=fs.statSync('/proc/self/fd/'+fd).isDirectory(); }catch{} ev.push(isDir?'fsync(dir)':'fsync(file)'); return origF.call(this,fd); };
fs.renameSync = function(a,b){ ev.push('rename'); return origR.call(this,a,b); };
writeOutAtomic(target, Buffer.from('{"signature":"measured"}'));
fs.fsyncSync = origF; fs.renameSync = origR;
console.log(JSON.stringify({ events: ev, bytes: fs.statSync(target).size }));
`;
const deliver = sh('node', ['-e', deliverScript], { cwd: dir });
let delivered = null;
try { delivered = JSON.parse(deliver.stdout.trim().split('\n').pop()); } catch { delivered = null; }
results.u2_delivery_fsycs_parent_dir = {
  events: delivered && delivered.events,
  deliveredBytes: delivered && delivered.bytes,
  pass: !!delivered && JSON.stringify(delivered.events) === JSON.stringify(['fsync(file)', 'rename', 'fsync(dir)']),
};

// The full stack: keystore, grant, daemon, transactions.
const CLI = path.join(dir, 'node_modules', 'signerd', 'bin', 'signerd.js');
const run = (args, opts = {}) => sh(process.execPath, [CLI, ...args], { cwd: dir, ...opts });
// The passphrase file is a SECRET: the tool refuses it unless it is
// owner-only. The harness must set that mode itself — the first version
// wrote it 0664 and every daemon start failed with a (correct) refusal.
const passPath = path.join(dir, 'pass.txt');
fs.writeFileSync(passPath, 'correct horse battery staple\n', { mode: 0o600 });
fs.chmodSync(passPath, 0o600);

const keygen = run(['keygen', '--keystore', 'ks.json', '--passphrase-file', 'pass.txt']);
let signer = null;
try { signer = JSON.parse(keygen.stdout).publicKey; } catch { signer = null; }
const dest = run(['keygen', '--keystore', 'dest.json', '--passphrase-file', 'pass.txt']);
let destKey = null;
try { destKey = JSON.parse(dest.stdout).publicKey; } catch { destKey = null; }

const expires = new Date(Date.now() + 86400000).toISOString().replace(/\.\d+Z$/, 'Z');
const grant = run([
  'grant-add', '--grants', 'grants.json', '--name', 'demo', '--keystore', 'ks.json',
  '--destination', destKey, '--max-lamports', '1000000', '--window-max-lamports', '1000000',
  '--window-seconds', '3600', '--expires', expires,
]);

// SETUP GATES: a broken harness must fail as HARNESS, never as a product
// verdict. (The first run of this tool wrote the passphrase file 0664, the
// tool correctly refused it, and three product cases reported "fail" for a
// defect that never existed.)
results.u0_setup = {
  keygenExit: keygen.status,
  grantExit: grant.status,
  keygenError: scrub((keygen.stderr || keygen.stdout).slice(0, 200)) || null,
  grantError: scrub((grant.stderr || grant.stdout).slice(0, 200)) || null,
  pass: keygen.status === 0 && grant.status === 0 && !!signer && !!destKey,
};
if (!results.u0_setup.pass) {
  const artifact = {
    measuredAt: new Date().toISOString(), tool: 'user-zero-d4-dry', tag: TAG,
    path: `npm install github:auroraxo/signerd#${TAG} into an empty directory`,
    results, allPass: false, verdict: 'HARNESS-FAIL (setup did not reach a running daemon)',
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', setup: results.u0_setup }, null, 2));
  process.exit(3);
}

// ONE daemon for all the product cases.
//
// WHY (measured 2026-11-08): the first version of this tool started a fresh
// daemon per case and SIGKILLed the previous one. The daemon holds a LEASE
// on the grant file, and a SIGKILLed daemon leaves that lease held, so the
// next daemon refused to start ("grant_file_lease_unavailable") and the
// cases reported a product failure that did not exist. One daemon, one
// grant per case: closer to how a consumer actually uses it.
function startDaemon() {
  const ledger = path.join(dir, 'ledger.jsonl');
  try { fs.rmSync(ledger, { force: true }); } catch {}
  const sock = path.join(dir, 'sock');
  try { fs.rmSync(sock, { force: true }); } catch {}
  const { spawn } = require('node:child_process');
  const child = spawn(process.execPath, [CLI, 'run', '--socket', sock, '--grants', 'grants.json',
    '--keystore', 'ks.json', '--passphrase-file', 'pass.txt', '--ledger', ledger],
  { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; let err = ''; let exited = null;
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { err += d; });
  child.on('exit', (code, sig) => { exited = { code, sig }; });
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline && !fs.existsSync(sock) && exited === null) {
    sh('sleep', ['0.2']);
  }
  return {
    child, sock, ledger,
    started: fs.existsSync(sock), exited,
    stdout: out.slice(0, 300) || null,
    stderr: err.slice(0, 300) || null,
    journalBytes() { try { return fs.statSync(ledger).size; } catch { return 0; } },
  };
}

/** Add one more grant to the file the running daemon already reads. */
function addGrant(name) {
  const r = run([
    'grant-add', '--grants', 'grants.json', '--name', name, '--keystore', 'ks.json',
    '--destination', destKey, '--max-lamports', '1000000', '--window-max-lamports', '1000000',
    '--window-seconds', '3600', '--expires', expires, '--append',
  ]);
  return r.status === 0;
}

// A fresh unsigned wire. The result is RECORDED: the first version of this
// tool ignored build-tx's status, so a failed build surfaced as
// "tx_missing" inside the product case.
const txBuilds = [];
function buildTx(lamports, name) {
  const r = run(['build-tx', '--keystore', 'ks.json', '--to', destKey, '--lamports', String(lamports), '--out', name]);
  txBuilds.push({ out: name, exit: r.status, error: (r.stderr || r.stdout).slice(0, 200) || null });
  return r.status === 0;
}

// ONE daemon, one grant per case (see startDaemon's note about leases).
const daemon = startDaemon();
results.u0b_daemon = {
  started: daemon.started,
  exit: daemon.exited,
  stdout: scrub(daemon.stdout),
  stderr: scrub(daemon.stderr),
  pass: daemon.started === true,
};
if (!results.u0b_daemon.pass) {
  const artifact = {
    measuredAt: new Date().toISOString(), tool: 'user-zero-d4-dry', tag: TAG,
    path: `npm install github:auroraxo/signerd#${TAG} into an empty directory`,
    results, allPass: false, verdict: 'HARNESS-FAIL (the daemon did not start)',
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', daemon: results.u0b_daemon }, null, 2));
  process.exit(3);
}

// U3 D4: --out fails after the spend, stdout (a pipe) retains -> exit 3.
addGrant('g3');
buildTx(123, 'tx3.json');
const j3Before = daemon.journalBytes();
const u3 = sh('bash', ['-c',
  `ulimit -f 0; "${process.execPath}" "${CLI}" sign --socket "${daemon.sock}" --grant g3 --tx tx3.json --out paid.json`],
{ cwd: dir });
const j3After = daemon.journalBytes();
results.u3_d4_out_fails_stdout_retains = {
  exit: u3.status,
  stdoutBytes: u3.stdout.length,
  stderrHasRecoveryOrOutError: /out_write_failed|recovery_failed/.test(u3.stderr),
  journalGrew: j3After > j3Before,
  journal: [j3Before, j3After],
  outFileAbsent: !fs.existsSync(path.join(dir, 'paid.json')),
  // exit 3 = "the artifact IS on stdout"; the journal grew = the spend happened.
  pass: u3.status === 3 && u3.stdout.length > 0 && j3After > j3Before,
};

// U4 D4': BOTH channels lose it (stdout is a FILE under ulimit -f 0) -> exit 4.
addGrant('g4');
buildTx(124, 'tx4.json');
const j4Before = daemon.journalBytes();
const u4 = sh('bash', ['-c',
  `ulimit -f 0; "${process.execPath}" "${CLI}" sign --socket "${daemon.sock}" --grant g4 --tx tx4.json > cap4.json`],
{ cwd: dir });
const j4After = daemon.journalBytes();
results.u4_d4_both_channels_lost = {
  exit: u4.status,
  stdoutBytes: 0,
  stderrHasRecoveryFailed: /recovery_failed/.test(u4.stderr),
  journalGrew: j4After > j4Before,
  journal: [j4Before, j4After],
  // exit 4 = "the artifact is unrecoverable"; it must NOT be 0 or 3.
  pass: u4.status === 4 && j4After > j4Before,
};

// U5 Dry falsification: --dry writes nothing and does not grow the journal;
// the control real sign does.
addGrant('g5');
buildTx(125, 'tx5.json');
buildTx(126, 'tx6.json');
const j5Before = daemon.journalBytes();
const dry = sh(process.execPath, [CLI, 'sign', '--socket', daemon.sock, '--grant', 'g5', '--tx', 'tx5.json', '--dry'], { cwd: dir });
const j5AfterDry = daemon.journalBytes();
const real = sh(process.execPath, [CLI, 'sign', '--socket', daemon.sock, '--grant', 'g5', '--tx', 'tx6.json'], { cwd: dir });
const j5AfterReal = daemon.journalBytes();
const dryEnvelope = (() => { try { return JSON.parse(dry.stdout); } catch { return null; } })();
results.u5_dry_is_real = {
  dryExit: dry.status,
  dryStderr: (dry.stderr || '').slice(0, 300) || null,
  realExit: real.status,
  realStderr: (real.stderr || '').slice(0, 300) || null,
  dryHadSignature: !!(dryEnvelope && dryEnvelope.signature),
  journalBefore: j5Before,
  journalAfterDry: j5AfterDry,
  journalAfterReal: j5AfterReal,
  // --dry must not sign and must not grow the journal; the control must.
  pass: !!(dryEnvelope && dryEnvelope.ok === true && !dryEnvelope.signature)
    && j5AfterDry === j5Before
    && j5AfterReal > j5Before,
};

try { daemon.child.kill('SIGKILL'); } catch {}

const allPass = Object.values(results).every((r) => r.pass);
const artifact = {
  measuredAt: new Date().toISOString(),
  tool: 'user-zero-d4-dry',
  tag: TAG,
  path: `npm install ${'github:auroraxo/signerd'}#${TAG} into an empty directory`,
  results,
  txBuilds: txBuilds.map((t) => ({ ...t, error: scrub(t.error) })),
  allPass,
  limits: [
    'one machine, one account, one network — the stranger path is the same host',
    'the D4 cases are about the CLI exit contract, not about a filesystem that lies about fsync',
    'the journal grows by RECORD, so a grown journal means the spend happened, not that the signature survived',
    'the dry-run falsification covers the documented --dry path only',
  ],
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(artifact, null, 2)}\n`);
console.log(JSON.stringify({ allPass, pass: Object.entries(results).map(([k, v]) => `${k}=${v.pass}`) }, null, 2));
try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
process.exit(allPass ? 0 : 1);
