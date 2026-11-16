#!/usr/bin/env node
'use strict';
// Measure what the OPERATOR is told when the socket cannot be reached - and
// whether the repair the refusal names can actually be RUN.
//
// WHY (measured 2026-11-16, published v0.2.30 tree e29634a):
//
//   signerd sign --socket /run/absent.sock --grant g --tx t
//     ENOENT: connect ENOENT /run/absent.sock
//     fix: the socket connection failed; check that --socket names a running
//          signerd daemon (signerd status --socket /run/absent.sock)
//
// Two defects in one screen. (1) The REASON is a raw errno: it names an
// internal syscall outcome, not an operator action - "ENOENT" says nothing
// about whether the daemon was never started, died, or whether the path is
// wrong, and the product's own house rule is one code + one repair per
// refusal. (2) The REPAIR CANNOT BE RUN: `signerd status --socket <path>`
// answers `unknown_flag: --socket`, exit 2 - the CLI refuses the very
// command every transport refusal tells the operator to run. src/cli-flags.js
// rule F3 says a refusal may only name a repair the CLI actually offers.
//
// THE SAME CLASS, third face: against a STALE socket (file exists, nobody
// listening - a daemon that died without unlinking) the errno is
// ECONNREFUSED, which reads like "refused to connect" and suggests a policy
// decision rather than a dead daemon; the repair again names the command
// that does not exist.
//
// FACES:
//   S1 status-repair-runnable      `signerd status --socket <absent>` itself
//                                  (the command every refusal names)
//   S2 sign-absent-socket          a sign against a path nobody ever bound
//   S3 sign-stale-socket           a sign against a socket file nobody serves
//   S4 status-stale-socket         `status --socket` on the same stale path
//   S5 sign-refusal-repair-runs    extract the repair S2's refusal names and
//                                  RUN it - the repair must be executable,
//                                  not merely written
//   S6 status-live-socket          `status --socket` on a LIVE daemon
//   G1 control-sign-still-signs    the real daemon still signs (the fix must
//                                  not refuse the happy path)
//   G2 control-status-files        `status --grants --ledger` unchanged
//
// A face is DEFECTIVE when the operator gets no socket_* code, or no repair
// line, or the repair the refusal names does not run. Raw errno codes
// (ENOENT / ECONNREFUSED / EACCES) are never a verdict of their own here:
// they are the classification INPUT, not the product's answer.
//
// Usage:
//   node tools/measure-socket-voice.js [--out <file>] [--published <dir>]
//
//   --published <dir>  run against an INSTALLED signerd (the published
//                      package), so the defect can be measured on the
//                      released tree.
//   --out <file>       where to write the JSON verdict (default:
//                      research/socket-voice-<date>.json).
//
// No network. No writes outside os.tmpdir() and the output file.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const { Keypair } = require(path.join(REPO, 'node_modules', '@solana', 'web3.js'));
const { buildTransferWire } = require(path.join(REPO, 'src', 'client.js'));

const args = process.argv.slice(2);
function argOf(flag) {
  const i = args.indexOf(flag);
  // >= 0, not > 0: a flag may be the FIRST argument (the lesson from
  // tools/measure-client-verification.js, where `i > 0` silently ignored
  // `--published <dir>` and the "published" run measured the checkout).
  return i >= 0 && args[i + 1] ? path.resolve(args[i + 1]) : null;
}
const OUT = argOf('--out') || path.join(REPO, 'research',
  `socket-voice-${new Date().toISOString().slice(0, 10)}.json`);
const PUBLISHED = argOf('--published');

const TREE = PUBLISHED || REPO;
const CLI = path.join(TREE, 'bin', 'signerd.js');
const LIB = PUBLISHED ? path.join(TREE, 'src') : path.join(REPO, 'src');

function fail(msg) { console.error(msg); process.exit(3); }
if (!fs.existsSync(CLI)) fail(`no CLI at ${CLI}`);

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function run(argv, opts = {}) {
  const res = spawnSync(process.execPath, [CLI, ...argv], {
    encoding: 'utf8', timeout: 60000, ...opts,
  });
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

/** One code + one repair: the product contract this tool checks. */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  return {
    code: (firstLine.split(':')[0] || '').trim(),
    firstLine: firstLine.slice(0, 200),
    hasFix: /(^|\n)\s*fix:/.test(text),
    // The repair every transport refusal names, if it is there at all.
    namedRepair: (/signerd status --socket (\S+)/.exec(text) || [])[1] || null,
  };
}

/** Raw errno must never be the product's answer (it is only the input). */
const RAW_ERRNO = /^(ENOENT|ECONNREFUSED|EACCES|EISDIR|ENOTDIR|ELOOP|EINVAL)$/;

async function main() {
  const dir = tmpDir('signerd-socketvoice-');

  // The honest daemon, for S6 and G1: setup exactly as the README says.
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the socket-voice measurement only\n', { mode: 0o600 });
  const keygen = run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (keygen.status !== 0) fail(`keygen failed: ${keygen.stderr}`);
  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.jsonl');
  const add = run(['grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  if (add.status !== 0) fail(`grant-add failed: ${add.stderr}`);

  const socketPath = path.join(dir, 'live.sock');
  const logPath = path.join(dir, 'daemon.log');
  const logFd = fs.openSync(logPath, 'a');
  const daemon = require('node:child_process').spawn(process.execPath, [
    CLI, 'run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', grants, '--ledger', ledger, '--socket', socketPath,
  ], { stdio: ['ignore', logFd, logFd], detached: false });
  for (let i = 0; i < 200 && !fs.existsSync(socketPath); i += 1) {
    spawnSync('sleep', ['0.05']);
  }
  const live = fs.existsSync(socketPath);
  const daemonLog = () => (fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '');

  // The grant must be signed by THE DAEMON'S OWN KEY: the policy refuses a
  // wire whose fee payer is not the daemon's signer (signer_or_fee_payer),
  // which would make the control face measure the policy instead of the
  // socket. So the wire's fee payer is the daemon key's public key, read
  // from the keystore's PUBLIC metadata (no secret is read).
  const { readKeystorePublicKey } = require(path.join(LIB, 'keystore.js'));
  const daemonPubkey = readKeystorePublicKey({ file: keystore });
  const wire = buildTransferWire({
    fromPubkey: daemonPubkey,
    // The grant pins ONE destination (the So111...2 used by the quickstart):
    // a random destination would be refused `destination` and the control
    // would measure the policy instead of the socket.
    toPubkey: 'So11111111111111111111111111111111111111112',
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  const txPath = path.join(dir, 'tx.bin');
  fs.writeFileSync(txPath, wire, { mode: 0o600 });

  const absent = path.join(dir, 'never-bound.sock');
  const stale = path.join(dir, 'stale.sock');
  // A socket file nobody serves: a listener is bound and then KILLED, never
  // closed. A graceful close unlinks the file (libuv does it as part of the
  // handle), which measures 'absent' again - while the state this whole fix
  // exists for is a daemon that died WITHOUT cleaning up. SIGKILL leaves
  // exactly that: the file, and nobody home.
  try { fs.unlinkSync(stale); } catch { /* absent */ }
  const holder = require('node:child_process').spawn(process.execPath, [
    '-e', "require('node:net').createServer(() => {}).listen(process.argv[1], () => console.log('READY'));setInterval(() => {}, 1000);",
    stale,
  ], { stdio: ['ignore', 'pipe', 'ignore'] });
  await new Promise((resolve) => {
    holder.stdout.once('data', resolve);
    holder.once('error', resolve);
    setTimeout(resolve, 5000);
  });
  try { process.kill(holder.pid, 'SIGKILL'); } catch { /* never started */ }
  for (let i = 0; i < 40 && !fs.existsSync(stale); i += 1) spawnSync('sleep', ['0.05']);
  const staleIsThere = fs.existsSync(stale);

  const faces = [];
  const record = (face, res, extra = {}) => {
    const v = voiceOf(res.stderr);
    faces.push({ face, exit: res.status, stdoutHead: (res.stdout.split('\n')[0] || '').slice(0, 200),
      voice: v, ...extra });
  };
  // The throwaway directory is replaced by a placeholder before anything is
  // recorded (the house rule from the registry-user-zero lesson): a
  // committed artifact must not carry a host path.
  const scrub = (text) => String(text || '').split(dir).join('<tmp>');

  // ---- S1 the repair command itself -----------------------------------
  record('S1-status-repair-runnable', run(['status', '--socket', absent]));

  // ---- S2 sign against an absent socket --------------------------------
  const s2 = run(['sign', '--socket', absent, '--grant', 'ops', '--tx', txPath]);
  record('S2-sign-absent-socket', s2);

  // ---- S3 sign against a stale socket ----------------------------------
  // (measured only when the stale file really survived; a harness that
  // cannot build its own fixture must say so, never report a clean verdict)
  if (staleIsThere) {
    record('S3-sign-stale-socket', run(['sign', '--socket', stale, '--grant', 'ops', '--tx', txPath]));
    record('S4-status-stale-socket', run(['status', '--socket', stale]));
  } else {
    for (const face of ['S3-sign-stale-socket', 'S4-status-stale-socket']) {
      faces.push({ face, exit: null, voice: { code: '', firstLine: '', hasFix: false },
        skip: 'the stale socket fixture could not be built on this host' });
    }
  }

  // ---- S5 RUN the repair S2 named --------------------------------------
  // The contract is not "the refusal contains the word status", it is "the
  // operator can run what the refusal says". So the path is taken out of
  // S2's own stderr and the command is executed.
  {
    const named = voiceOf(s2.stderr).namedRepair;
    if (named === null) {
      faces.push({ face: 'S5-sign-refusal-repair-runs', exit: s2.status,
        voice: voiceOf(s2.stderr), repairRan: false, repairExit: null, defect: null,
        skip: 'the refusal named no repair to run' });
    } else {
      const repair = run(['status', '--socket', named]);
      record('S5-sign-refusal-repair-runs', repair, { repairRan: true });
    }
  }

  // ---- S6 status on the LIVE daemon ------------------------------------
  if (live) {
    record('S6-status-live-socket', run(['status', '--socket', socketPath]));
  } else {
    faces.push({ face: 'S6-status-live-socket', exit: null, voice: { code: '', firstLine: '', hasFix: false },
      skip: `daemon never bound: ${daemonLog().split('\n').filter(Boolean).slice(-1)[0] || 'no log'}` });
  }

  // ---- G1 control: the real daemon still signs --------------------------
  if (live) {
    const out = path.join(dir, 'g1.bin');
    record('G1-control-sign-still-signs',
      run(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath, '--out', out]),
      { control: true, artifactWritten: fs.existsSync(out) });
  } else {
    faces.push({ face: 'G1-control-sign-still-signs', exit: null, voice: { code: '', firstLine: '', hasFix: false },
      control: true, skip: 'daemon never bound' });
  }

  // ---- G2 control: status --grants --ledger unchanged -------------------
  record('G2-control-status-files',
    run(['status', '--grants', grants, '--ledger', ledger]), { control: true });

  try { daemon.kill('SIGTERM'); } catch { /* gone */ }
  spawnSync('sleep', ['0.2']);
  try { process.kill(-daemon.pid); } catch { /* already gone */ }
  fs.closeSync(logFd);

  // ---- verdict ----------------------------------------------------------
  const namedSocketCode = (c) => /^socket_/.test(c.voice.code);
  const out = {
    tool: 'measure-socket-voice',
    date: '2026-11-16',
    tree: PUBLISHED ? 'published' : 'worktree',
    head: spawnSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO, encoding: 'utf8' })
      .stdout.trim(),
    cases: {},
  };
  for (const f of faces) {
    const skipped = typeof f.skip === 'string';
    // A SUCCESS needs no code: `status --socket` on a live daemon answers
    // {ok:true,...} on stdout and exits 0 - that is the happy path, not a
    // mute failure. A FAILURE is defective when it carries no socket_* code
    // (raw errno included), no repair line, or a repair that does not run.
    const succeeded = f.exit === 0 && /"ok":true/.test(f.stdoutHead || '');
    const defect = skipped || f.control || succeeded
      ? false
      : (!namedSocketCode(f) || !f.voice.hasFix || RAW_ERRNO.test(f.voice.code)
        || (f.face === 'S5-sign-refusal-repair-runs' && !/^socket_/.test(f.voice.code)));
    out.cases[f.face] = {
      exit: f.exit,
      code: f.voice.code,
      hasFix: f.voice.hasFix,
      firstLine: scrub(f.voice.firstLine),
      stdoutHead: scrub(f.stdoutHead || '').slice(0, 200),
      namedRepair: f.voice.namedRepair ? scrub(f.voice.namedRepair) : null,
      ...(f.repairRan !== undefined ? { repairRan: f.repairRan } : {}),
      ...(f.control ? { control: true } : {}),
      ...(f.artifactWritten !== undefined ? { artifactWritten: f.artifactWritten } : {}),
      ...(skipped ? { skip: f.skip } : {}),
      defect: skipped ? null : defect,
    };
  }
  const entries = Object.entries(out.cases);
  out.defectiveFaces = entries.filter(([, c]) => c.defect === true).length;
  out.totalFaces = entries.filter(([, c]) => c.defect !== null && !c.control && !c.skip).length;
  out.verdict = out.defectiveFaces === 0
    ? 'operator-hears-a-socket-state-not-an-errno'
    : 'operator-hears-raw-errno-and-unrunnable-repair';

  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
  console.log(JSON.stringify({ ...out, outFile: OUT }, null, 2));
  process.exit(0);
}

main().catch((err) => { console.error((err && err.stack) || err); process.exit(3); });
