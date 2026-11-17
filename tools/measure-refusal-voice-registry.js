#!/usr/bin/env node
'use strict';

// THE REFUSAL VOICE ON THE CHANNEL A STRANGER USES: npm install signerd,
// then a daemon policy refusal must reach the operator as a code PLUS a
// repair on stderr, while stdout keeps the machine channel.
//
// WHY (measured 2026-11-17): tools/measure-daemon-refusal-voice.js proves
// the fix on a WORKTREE. The registry tarball is what a stranger installs,
// and this is the class this product exists for — the refusal must reach
// them. The published v0.2.33 tarball answered every daemon refusal with a
// JSON line on stdout and 0 bytes on stderr (research/
// daemon-refusal-voice-prefix-2026-11-17.json, 7/7 defect faces).
//
// WHAT IT MEASURES on `npm install signerd@<pin>` (no clone):
//   V0 the installed version IS the README pin (the harness refuses to
//      measure a stale install — the frozen-assertion class);
//   V1 a sign to a destination the grant pins elsewhere: exit 1, stdout
//      carries ok:false + error + detail UNCHANGED (the machine channel),
//      stderr carries the code exactly once and a `fix:` line naming a
//      command this CLI offers and the grant NAME the operator asked for;
//   V2 a sign against a grant name that is not in the file: same contract,
//      with the unknown name substituted into the repair;
//   V3 GUARD: a legal sign still succeeds (exit 0) and stays SILENT on
//      stderr — a product that chatters on every request is not the fix;
//   V4 no host path on either channel of either refusal.
//
// NO HOST PATHS: basenames, codes and byte counts only.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

function readPin() {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const tags = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((s) => s.split('#')[1]))];
  if (tags.length !== 1) {
    console.error(`README pin is not exactly one tag: ${tags.join(', ')}`);
    process.exit(3);
  }
  return tags[0].replace(/^v/, '');
}

const HOST_PATH = /\/home\/|\/Users\/|\/root\//;

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 60000 }, opts || {}));
  return {
    status: r.status === null ? -1 : r.status,
    stdout: r.stdout === null ? '' : r.stdout,
    stderr: r.stderr === null ? '' : r.stderr,
    spawnError: r.error ? String(r.error.message) : null,
  };
}

/** The code on stderr exactly once, plus a `fix:` line, or a reason. */
function stderrShape(stderr) {
  const lines = stderr.split('\n').filter((l) => l.trim().length > 0);
  const fixLines = lines.filter((l) => l.startsWith('  fix: '));
  return {
    codeLine: lines.length > 0 && !lines[0].startsWith('  fix:') ? lines[0] : null,
    fixLine: fixLines.length === 1 ? fixLines[0].slice('  fix: '.length) : null,
    lineCount: lines.length,
  };
}

function main() {
  const pin = readPin();
  const bin = path.join(os.tmpdir(), `signerd-refusal-voice-registry-${Date.now()}`);
  fs.mkdirSync(bin, { mode: 0o700 });

  // V0: install from the registry, never from the worktree.
  const install = run('npm', ['install', `signerd@${pin}`, '--no-audit', '--no-fund', '--silent'], { cwd: bin });
  if (install.status !== 0) {
    console.log(JSON.stringify({
      verdict: 'HARNESS-FAIL',
      reason: `npm install signerd@${pin} exited ${install.status} (${install.spawnError || install.stderr.slice(0, 200)})`,
      measuredAt: new Date().toISOString(),
    }, null, 2));
    process.exit(3);
  }
  const CLI = path.join(bin, 'node_modules', 'signerd', 'bin', 'signerd.js');
  const installedVersion = JSON.parse(fs.readFileSync(
    path.join(bin, 'node_modules', 'signerd', 'package.json'), 'utf8')).version;
  if (installedVersion !== pin) {
    console.log(JSON.stringify({
      verdict: 'HARNESS-FAIL',
      reason: `the install resolved ${installedVersion}, not the pin ${pin}`,
      measuredAt: new Date().toISOString(),
    }, null, 2));
    process.exit(3);
  }

  // A legal path first: keystore, grant, daemon. Harness failures here are
  // HARNESS-FAIL (exit 3), never a measured product refusal.
  const work = path.join(bin, 'work');
  fs.mkdirSync(work, { mode: 0o700 });
  const pass = path.join(work, 'pass.txt');
  fs.writeFileSync(pass, 'secret\n', { mode: 0o600 });

  const keygen = run('node', [CLI, 'keygen', '--keystore', 'ks.json', '--passphrase-file', pass], { cwd: work });
  if (keygen.status !== 0) {
    console.log(JSON.stringify({
      verdict: 'HARNESS-FAIL',
      reason: `keygen on the installed copy exited ${keygen.status}: ${keygen.stderr.slice(0, 300)}`,
      measuredAt: new Date().toISOString(),
    }, null, 2));
    process.exit(3);
  }
  const pub = JSON.parse(keygen.stdout).publicKey;

  // A DESTINATION KEY that is not the signer: the grant pins it, the legal
  // wire pays it. (First draft pinned the signer itself, so the legal
  // control was a SELF-transfer — outside the offline-decidable envelope,
  // refused by `envelope` for a reason unrelated to this instrument.)
  const destKey = run('node', [CLI, 'keygen', '--keystore', 'ks-dest.json', '--passphrase-file', pass], { cwd: work });
  if (destKey.status !== 0) {
    console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: 'destination keygen failed', measuredAt: new Date().toISOString() }, null, 2));
    process.exit(3);
  }
  const pinnedDest = JSON.parse(destKey.stdout).publicKey;

  // A SECOND key = a valid destination the grant does NOT pin.
  const other = run('node', [CLI, 'keygen', '--keystore', 'ks2.json', '--passphrase-file', pass], { cwd: work });
  if (other.status !== 0) {
    console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: 'second keygen failed', measuredAt: new Date().toISOString() }, null, 2));
    process.exit(3);
  }
  const wrongDest = JSON.parse(other.stdout).publicKey;

  const grantAdd = run('node', [CLI, 'grant-add', '--grants', 'g.json', '--name', 'demo',
    '--keystore', 'ks.json', '--destination', pinnedDest, '--max-lamports', '100000',
    '--window-max-lamports', '200000', '--window-seconds', '60',
    '--expires', '2030-01-01T00:00:00Z'], { cwd: work });
  if (grantAdd.status !== 0) {
    console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: `grant-add failed: ${grantAdd.stderr.slice(0, 300)}`, measuredAt: new Date().toISOString() }, null, 2));
    process.exit(3);
  }

  const socket = path.join(work, 's.sock');
  const ledger = path.join(work, 'j.json');
  const daemon = require('node:child_process').spawn('node',
    [CLI, 'run', '--keystore', path.join(work, 'ks.json'), '--passphrase-file', pass,
      '--grants', path.join(work, 'g.json'), '--ledger', ledger, '--socket', socket],
    { cwd: work, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let daemonLog = '';
  daemon.stdout.on('data', (d) => { daemonLog += d; });
  daemon.stderr.on('data', (d) => { daemonLog += d; });

  const cleanup = () => { try { process.kill(-daemon.pid); } catch { try { process.kill(daemon.pid); } catch {} } };
  process.on('exit', cleanup);

  // Wait for the socket to answer, or give up as a HARNESS failure.
  let live = false;
  for (let i = 0; i < 40; i++) {
    const st = run('node', [CLI, 'status', '--socket', socket], { cwd: work });
    if (st.status === 0) { live = true; break; }
    spawnSync('sleep', ['0.5']);
  }
  if (!live) {
    console.log(JSON.stringify({
      verdict: 'HARNESS-FAIL',
      reason: `the daemon never answered the socket on the installed copy: ${daemonLog.slice(0, 300)}`,
      measuredAt: new Date().toISOString(),
    }, null, 2));
    process.exit(3);
  }

  const failures = [];
  const cases = [];

  // A legal transaction to the PINNED destination — V3's control, and the
  // fixture the refusal cases reuse.
  const tx = run('node', [CLI, 'build-tx', '--keystore', path.join(work, 'ks.json'),
    '--to', wrongDest, '--lamports', '1000', '--out', 'tx.bin'], { cwd: work });
  if (tx.status !== 0) {
    console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: `build-tx failed: ${tx.stderr.slice(0, 300)}`, measuredAt: new Date().toISOString() }, null, 2));
    process.exit(3);
  }

  // The LEGAL transaction: same grant, but it pays the destination the grant
  // pins. (First draft of this instrument reused tx.bin for V3 — a wire to
  // the UNpinned destination — so the control was refused for exactly the
  // reason V1 measures. The control must be legal by construction.)
  const txOk = run('node', [CLI, 'build-tx', '--keystore', path.join(work, 'ks.json'),
    '--to', pinnedDest, '--lamports', '1000', '--out', 'tx-ok.bin'], { cwd: work });
  if (txOk.status !== 0) {
    console.log(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: `build-tx (legal) failed: ${txOk.stderr.slice(0, 300)}`, measuredAt: new Date().toISOString() }, null, 2));
    process.exit(3);
  }

  // V1: destination — the grant pins the FIRST key, this wire pays the other.
  {
    const r = run('node', [CLI, 'sign', '--socket', socket, '--grant', 'demo',
      '--tx', path.join(work, 'tx.bin'), '--out', path.join(work, 'signed.bin')], { cwd: work });
    const shape = stderrShape(r.stderr);
    let machine;
    try { machine = JSON.parse(r.stdout); } catch { machine = null; }
    const c = {
      case: 'destination',
      exit: r.status,
      stderrCodeLine: shape.codeLine,
      stderrLineCount: shape.lineCount,
      fixPresent: shape.fixLine !== null,
      machineUnchanged: machine !== null && machine.ok === false &&
        machine.error === 'destination' &&
        machine.detail !== undefined,
      repairNamesRealCommand: shape.fixLine !== null && shape.fixLine.includes('signerd grant-add'),
      repairCarriesGrantName: shape.fixLine !== null && shape.fixLine.includes('--name demo'),
      stderrHasHostPath: HOST_PATH.test(r.stderr),
      stdoutHasHostPath: HOST_PATH.test(r.stdout),
    };
    if (c.exit !== 1) failures.push('V1: destination refusal did not exit 1');
    if (!c.fixPresent) failures.push('V1: no fix line on stderr');
    if (shape.codeLine !== 'destination') failures.push(`V1: stderr first line is ${JSON.stringify(shape.codeLine)}, not the code once`);
    if (!c.machineUnchanged) failures.push('V1: the machine channel changed shape');
    if (!c.repairNamesRealCommand) failures.push('V1: the repair does not name a command this CLI offers');
    if (!c.repairCarriesGrantName) failures.push('V1: the repair does not carry the grant name the operator asked for');
    if (c.stderrHasHostPath || c.stdoutHasHostPath) failures.push('V1: a host path reached a channel');
    cases.push(c);
  }

  // V2: unknown grant — the name must reach the repair.
  {
    const r = run('node', [CLI, 'sign', '--socket', socket, '--grant', 'ghost',
      '--tx', path.join(work, 'tx.bin'), '--out', path.join(work, 's2.bin')], { cwd: work });
    const shape = stderrShape(r.stderr);
    let machine;
    try { machine = JSON.parse(r.stdout); } catch { machine = null; }
    const c = {
      case: 'grant_not_found',
      exit: r.status,
      stderrCodeLine: shape.codeLine,
      stderrLineCount: shape.lineCount,
      fixPresent: shape.fixLine !== null,
      machineUnchanged: machine !== null && machine.ok === false && machine.error === 'grant_not_found',
      repairCarriesGrantName: shape.fixLine !== null && shape.fixLine.includes('--name ghost'),
      stderrHasHostPath: HOST_PATH.test(r.stderr),
      stdoutHasHostPath: HOST_PATH.test(r.stdout),
    };
    if (c.exit !== 1) failures.push('V2: grant_not_found did not exit 1');
    if (!c.fixPresent) failures.push('V2: no fix line on stderr');
    if (shape.codeLine !== 'grant_not_found') failures.push(`V2: stderr first line is ${JSON.stringify(shape.codeLine)}`);
    if (!c.machineUnchanged) failures.push('V2: the machine channel changed shape');
    if (!c.repairCarriesGrantName) failures.push('V2: the repair does not carry the unknown grant name');
    if (c.stderrHasHostPath || c.stdoutHasHostPath) failures.push('V2: a host path reached a channel');
    cases.push(c);
  }

  // V3: the legal path is still legal, and still SILENT on stderr.
  {
    const r = run('node', [CLI, 'sign', '--socket', socket, '--grant', 'demo',
      '--tx', path.join(work, 'tx-ok.bin'), '--out', path.join(work, 'ok.bin')], { cwd: work });
    const c = {
      case: 'legal_sign_stays_silent',
      exit: r.status,
      stderrBytes: Buffer.byteLength(r.stderr),
      wroteOutput: fs.existsSync(path.join(work, 'ok.bin')),
    };
    if (c.exit !== 0) failures.push(`V3: a legal sign exited ${c.exit}: ${r.stderr.slice(0, 200)}`);
    if (c.stderrBytes !== 0) failures.push(`V3: a legal sign wrote ${c.stderrBytes} bytes to stderr`);
    if (!c.wroteOutput) failures.push('V3: the legal sign wrote no artifact');
    cases.push(c);
  }

  cleanup();

  const hostPathFree = cases.every((c) => !c.stderrHasHostPath && !c.stdoutHasHostPath);
  const out = path.join(ROOT, 'research',
    `refusal-voice-registry-v${pin}-${new Date().toISOString().slice(0, 10)}.json`);
  const report = {
    schema: 'signerd-refusal-voice-registry/1',
    measuredAt: new Date().toISOString(),
    channel: 'registry (npm install signerd, no clone)',
    version: pin,
    verdict: failures.length === 0 ? 'refusal-voice-reaches-the-published-channel' : 'violations-present',
    failures,
    cases,
    hostPathFree,
  };
  fs.writeFileSync(out, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ verdict: report.verdict, failures, out }, null, 2));
  process.exit(failures.length === 0 ? 0 : 1);
}

main();
