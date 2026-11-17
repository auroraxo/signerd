#!/usr/bin/env node
'use strict';

// Measure what the OPERATOR is told when the DAEMON refuses a request - the
// product's headline surface ("die Verweigerung ist das Produkt").
//
// WHY (measured 2026-11-17, on the v0.2.33 tree, this tool's own first run):
//
//   signerd sign --socket <live> --grant ops --tx <tx-to-another-destination>
//     stdout: {"ok":false,"error":"destination","detail":{...}}
//     stderr: (0 bytes)
//
// The refusal reaches the operator as a machine-readable code on STDOUT and
// NOTHING else. The README promises the opposite for this exact class:
//
//   "Refusals name the flag and the fix instead of failing silently."
//
// and the CLI upholds that promise on every OTHER surface it owns:
//   - a transport refusal (socket_missing / socket_stale / ...) prints the
//     code AND a `fix:` line;
//   - a client-side verification refusal (signed_message_mismatch / ...)
//     prints the code AND a `fix:` line;
//   - an unknown flag prints the code AND two `fix:` lines;
//   - a grant-file refusal prints the code AND a `fix:` line.
//
// The DAEMON's own policy refusal - the reason the product exists - is the
// one surface that reaches the operator with an EMPTY STDERR. An operator
// who is told `destination` learns that a name of a refusal happened; they
// do not learn WHAT TO DO, which grant to use, or which command shows them
// the scope that was pinned. For the class this project cares most about
// (an agent holding grants, not keys) the refusal IS the product, so the
// refusal has to be readable by whoever holds the grant.
//
// WHAT IS AND IS NOT DEFECTIVE HERE:
//
//   A face is DEFECTIVE when the operator gets NO code on stderr, or NO
//   `fix:` line, or the repair names a command this CLI does not offer
//   (the rule from src/cli-flags.js F3: "a refusal may only name a repair
//   the CLI actually offers").
//
//   The JSON on stdout stays EXACTLY as it is: a refusal is data, and the
//   example client (src/client.js) reads `answer.error`. The fix adds the
//   human channel (stderr), it does not change the machine channel.
//
// FACES:
//   R1 destination-mismatch     a wire to a destination the grant does not pin
//   R2 unknown-grant            a grant name the file does not hold
//   R3 grant-kind-mismatch      a message body against a transaction grant
//   R4 replay                  the same wire, signed twice
//   R5 window-cap              the rolling window is spent
//   R6 expired-grant           the grant's expiry has passed
//   R7 request-invalid         a malformed request frame
//   G1 control-happy-path      a legal sign still works and stays silent
//   G2 control-grant-not-found  the JSON on stdout still carries the code
//   G3 control-no-fix-leak     the repair never contains a host path
//
// Usage:
//   node tools/measure-daemon-refusal-voice.js [--out <file>] [--published <dir>]
//
//   --published <dir>  run against an INSTALLED signerd (the published
//                      package), so the defect can be measured on the
//                      released tree.
//   --out <file>       where to write the JSON verdict (default:
//                      research/daemon-refusal-voice-<date>.json).
//
// No network. Writes only inside os.tmpdir() and the output file.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const { Keypair } = require(path.join(REPO, 'node_modules', '@solana', 'web3.js'));

const args = process.argv.slice(2);
function argOf(flag) {
  const i = args.indexOf(flag);
  // >= 0, not > 0: a flag may be the FIRST argument (the lesson from
  // tools/measure-client-verification.js).
  return i >= 0 && args[i + 1] ? path.resolve(args[i + 1]) : null;
}
const OUT = argOf('--out') || path.join(REPO, 'research',
  `daemon-refusal-voice-${new Date().toISOString().slice(0, 10)}.json`);
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

/**
 * The operator's view of a refusal: the code on stderr, and whether a repair
 * is named. The code on STDOUT is the machine channel and is measured
 * separately (it must not change).
 */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  return {
    code: (firstLine.split(':')[0] || '').trim(),
    firstLine: firstLine.slice(0, 200),
    hasFix: /(^|\n)\s*fix:/.test(text),
    stderrBytes: Buffer.byteLength(text),
  };
}

/** The commands this CLI actually offers (src/cli-flags.js rule F3). */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

/**
 * Does the repair name a command this CLI does not offer? A repair that
 * names `signerd grant-list` or `signerd status --journal` would be a
 * refusal whose repair cannot be run - the defect the socket-voice fix
 * closed for the transport surface.
 */
function repairNamesUnknownCommand(stderr) {
  const text = String(stderr || '');
  const found = [];
  const re = /signerd\s+([a-z][a-z-]*)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (!KNOWN_COMMANDS.includes(m[1])) found.push(m[1]);
  }
  return [...new Set(found)];
}

/** A host path must never appear in a refusal (the house rule). */
function hostPathsIn(text) {
  return /\/home\/|\/Users\/|\/root\/|\/tmp\/[A-Za-z0-9._-]+\//.test(String(text || ''));
}

function main() {
  const dir = tmpDir('signerd-refusalvoice-');
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the refusal-voice measurement only\n', { mode: 0o600 });
  const keygen = run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (keygen.status !== 0) fail(`keygen failed: ${keygen.stderr}`);

  const { readKeystorePublicKey } = require(path.join(LIB, 'keystore.js'));
  const daemonPubkey = readKeystorePublicKey({ file: keystore });
  const otherPubkey = Keypair.generate().publicKey.toBase58();
  // The grant pins ONE destination. The legal wire goes there; the illegal
  // one goes somewhere else - that is the `destination` refusal.
  const grantDest = 'So11111111111111111111111111111111111111112';

  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.jsonl');
  const add = run(['grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', grantDest, '--max-lamports', '500000000',
    '--window-max-lamports', '500000000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z']);
  if (add.status !== 0) fail(`grant-add failed: ${add.stderr}`);

  const { buildTransferWire } = require(path.join(LIB, 'client.js'));
  const blockhash = Keypair.generate().publicKey.toBase58();
  const goodTx = path.join(dir, 'good.bin');
  const badTx = path.join(dir, 'bad.bin');
  fs.writeFileSync(goodTx, buildTransferWire({
    fromPubkey: daemonPubkey, toPubkey: grantDest, lamports: 42, blockhash,
  }), { mode: 0o600 });
  fs.writeFileSync(badTx, buildTransferWire({
    fromPubkey: daemonPubkey, toPubkey: otherPubkey, lamports: 42, blockhash,
  }), { mode: 0o600 });

  const socketPath = path.join(dir, 'live.sock');
  const logPath = path.join(dir, 'daemon.log');
  const logFd = fs.openSync(logPath, 'a');
  const daemon = require('node:child_process').spawn(process.execPath, [
    CLI, 'run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', grants, '--ledger', ledger, '--socket', socketPath,
  ], { stdio: ['ignore', logFd, logFd], detached: false });
  for (let i = 0; i < 200 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.05']);
  if (!fs.existsSync(socketPath)) fail('the daemon never bound its socket');
  spawnSync('sleep', ['0.4']);

  const faces = [];
  const scrub = (text) => String(text || '').split(dir).join('<tmp>');
  const record = (face, res, expect) => {
    const v = voiceOf(res.stderr);
    let stdoutCode = null;
    try { stdoutCode = JSON.parse(res.stdout.split('\n')[0]).error || null; } catch { /* not json */ }
    const unknownCommands = repairNamesUnknownCommand(res.stderr);
    const leak = hostPathsIn(res.stderr);
    // DEFECTIVE when the operator gets no code, no repair, a repair that
    // names a command this CLI does not offer, or a host path.
    const defective = v.code === '' || !v.hasFix || unknownCommands.length > 0 || leak;
    faces.push({
      face,
      exit: res.status,
      expect,
      stdoutCode,
      stdoutHead: scrub((res.stdout.split('\n')[0] || '').slice(0, 200)),
      stderrHead: scrub(v.firstLine),
      stderrBytes: v.stderrBytes,
      hasCode: v.code !== '',
      hasFix: v.hasFix,
      unknownCommandsInRepair: unknownCommands,
      hostPathInRepair: leak,
      defective,
    });
  };

  // ---- R1 destination mismatch ----------------------------------------
  record('R1-destination-mismatch',
    run(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', badTx]),
    'destination');

  // ---- R2 unknown grant ------------------------------------------------
  record('R2-unknown-grant',
    run(['sign', '--socket', socketPath, '--grant', 'nosuch', '--tx', goodTx]),
    'grant_not_found');

  // ---- R3 grant kind mismatch -----------------------------------------
  // A message body against a TRANSACTION grant.
  const bodyPath = path.join(dir, 'body.json');
  fs.writeFileSync(bodyPath, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'test', type: 'scan', subject: 'test',
    claims: {}, issued_at: new Date().toISOString(),
  }) + '\n', { mode: 0o600 });
  record('R3-grant-kind-mismatch',
    run(['sign-message', '--socket', socketPath, '--grant', 'ops', '--body', bodyPath]),
    'grant_kind_mismatch');

  // ---- R4 replay -------------------------------------------------------
  // Sign the legal wire, then ask for it again.
  const first = run(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', goodTx]);
  if (first.status !== 0) fail(`the control sign failed: ${first.stderr}`);
  record('R4-replay',
    run(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', goodTx]),
    'replay');

  // ---- R5 window cap ---------------------------------------------------
  // A second grant with a tiny window, spent by one sign.
  const smallGrants = path.join(dir, 'small.json');
  const smallLedger = path.join(dir, 'small.jsonl');
  const smallSocket = path.join(dir, 'small.sock');
  // The window cap must admit EXACTLY ONE approval: every approval costs
  // amount + 5000 (the base fee), so a cap of 5001 with a 1-lamport
  // transfer spends the window exactly. The second request is over the cap.
  const add2 = run(['grant-add', '--grants', smallGrants, '--name', 'tiny', '--keystore', keystore,
    '--destination', grantDest, '--max-lamports', '500000000',
    '--window-max-lamports', '5001', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z']);
  if (add2.status !== 0) fail(`grant-add (tiny) failed: ${add2.stderr}`);
  const smallLog = fs.openSync(path.join(dir, 'daemon2.log'), 'a');
  const daemon2 = require('node:child_process').spawn(process.execPath, [
    CLI, 'run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', smallGrants, '--ledger', smallLedger, '--socket', smallSocket,
  ], { stdio: ['ignore', smallLog, smallLog], detached: false });
  for (let i = 0; i < 200 && !fs.existsSync(smallSocket); i += 1) spawnSync('sleep', ['0.05']);
  if (!fs.existsSync(smallSocket)) fail('the second daemon never bound its socket');
  spawnSync('sleep', ['0.4']);
  const capTx = path.join(dir, 'cap.bin');
  fs.writeFileSync(capTx, buildTransferWire({
    fromPubkey: daemonPubkey, toPubkey: grantDest, lamports: 1,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });
  const capFirst = run(['sign', '--socket', smallSocket, '--grant', 'tiny', '--tx', capTx]);
  if (capFirst.status !== 0) fail(`the window-cap setup sign failed: ${capFirst.stderr}`);
  // A SECOND, DIFFERENT wire: reusing capTx would be refused `replay` (the
  // journal already holds it) and the face would measure replay, not the
  // window. A fresh wire with a fresh blockhash is a legal request whose
  // only obstacle is the spent window.
  const capTx2 = path.join(dir, 'cap2.bin');
  fs.writeFileSync(capTx2, buildTransferWire({
    fromPubkey: daemonPubkey, toPubkey: grantDest, lamports: 1,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });
  record('R5-window-cap',
    run(['sign', '--socket', smallSocket, '--grant', 'tiny', '--tx', capTx2]),
    'window_cap');
  daemon2.kill('SIGKILL');

  // ---- R6 expired grant ------------------------------------------------
  // A grant whose expiry is in the past cannot be CREATED (v0.2.18 refuses
  // it), so the expired grant is reached by editing the file the daemon
  // re-reads on every request - the daemon reloads the grant file per
  // request, so an expiry that passes while it runs is the real shape.
  const expGrants = path.join(dir, 'exp.json');
  const expLedger = path.join(dir, 'exp.jsonl');
  const expSocket = path.join(dir, 'exp.sock');
  const add3 = run(['grant-add', '--grants', expGrants, '--name', 'soon', '--keystore', keystore,
    '--destination', grantDest, '--max-lamports', '500000000',
    '--window-max-lamports', '500000000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z']);
  if (add3.status !== 0) fail(`grant-add (expired) failed: ${add3.stderr}`);
  const expLog = fs.openSync(path.join(dir, 'daemon3.log'), 'a');
  const daemon3 = require('node:child_process').spawn(process.execPath, [
    CLI, 'run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', expGrants, '--ledger', expLedger, '--socket', expSocket,
  ], { stdio: ['ignore', expLog, expLog], detached: false });
  for (let i = 0; i < 200 && !fs.existsSync(expSocket); i += 1) spawnSync('sleep', ['0.05']);
  if (!fs.existsSync(expSocket)) fail('the third daemon never bound its socket');
  spawnSync('sleep', ['0.4']);
  // Rewrite the grant file with an expiry one second in the past. The
  // daemon re-reads the file on every request, so the NEXT request sees it.
  const doc = JSON.parse(fs.readFileSync(expGrants, 'utf8'));
  doc.grants.soon.expiresAt = new Date(Date.now() - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  fs.writeFileSync(expGrants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  record('R6-expired-grant',
    run(['sign', '--socket', expSocket, '--grant', 'soon', '--tx', goodTx]),
    'expired');
  daemon3.kill('SIGKILL');

  // ---- R7 malformed request frame --------------------------------------
  // A raw socket write of a malformed frame. There is no CLI on this path -
  // the frame is the API a library consumer speaks - so the operator's
  // channel here IS the frame: `fix` must travel in the JSON the daemon
  // answers with. Measured against the frame, not against the helper's
  // stderr (the helper has none; measuring that would have been an
  // instrument artifact, not a defect).
  const net = require('node:net');
  const rawFrame = spawnSync(process.execPath, ['-e', `
      const net = require('node:net');
      const s = net.connect(process.argv[1]);
      s.on('connect', () => s.end('{"not":"a request"}\\n'));
      s.on('data', (d) => { process.stdout.write(d.toString()); s.end(); });
      setTimeout(() => process.exit(0), 3000);
    `, socketPath], { encoding: 'utf8', timeout: 10000 });
  let frame = null;
  try { frame = JSON.parse(String(rawFrame.stdout || '').split('\n')[0]); } catch { /* not json */ }
  faces.push({
    face: 'R7-request-invalid',
    exit: 0,
    expect: 'request_invalid',
    stdoutCode: frame && typeof frame.error === 'string' ? frame.error : null,
    stdoutHead: '',
    // The frame IS the channel on this path: `hasFix` asks whether the
    // daemon's own answer carried the repair.
    stderrHead: scrub(String(frame && typeof frame.fix === 'string' ? frame.fix : '').slice(0, 200)),
    stderrBytes: Buffer.byteLength(String(frame && frame.fix || '')),
    hasCode: Boolean(frame && frame.error),
    hasFix: Boolean(frame && typeof frame.fix === 'string' && frame.fix.length > 0),
    unknownCommandsInRepair: frame ? repairNamesUnknownCommand(String(frame.fix || '')) : [],
    hostPathInRepair: frame ? hostPathsIn(String(frame.fix || '')) : false,
    defective: !frame || !frame.error || typeof frame.fix !== 'string' || frame.fix.length === 0 ||
      repairNamesUnknownCommand(String(frame.fix || '')).length > 0 ||
      hostPathsIn(String(frame.fix || '')),
  });

  // ---- G1 control: the happy path --------------------------------------
  // A FRESH wire: `goodTx` was signed twice by now (the control sign and
  // the replay face), so asking for it again would measure `replay`, not
  // the happy path.
  const controlTx = path.join(dir, 'control.bin');
  fs.writeFileSync(controlTx, buildTransferWire({
    fromPubkey: daemonPubkey, toPubkey: grantDest, lamports: 7,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });
  const control = run(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', controlTx]);
  faces.push({
    face: 'G1-control-happy-path',
    exit: control.status,
    expect: 'a legal sign is not a refusal',
    stdoutCode: null,
    stdoutHead: scrub((control.stdout.split('\n')[0] || '').slice(0, 120)),
    stderrHead: scrub((control.stderr.split('\n').find((l) => l.trim()) || '').slice(0, 200)),
    stderrBytes: Buffer.byteLength(control.stderr || ''),
    hasCode: false,
    hasFix: false,
    unknownCommandsInRepair: [],
    hostPathInRepair: false,
    // A legal sign must SUCCEED and must stay quiet on stderr: the fix adds
    // words to refusals only, and must not chatter on success.
    defective: control.status !== 0 || (control.stderr || '').trim().length !== 0,
  });

  // ---- G2 control: the machine channel is unchanged ---------------------
  const r2 = faces.find((f) => f.face === 'R2-unknown-grant');
  faces.push({
    face: 'G2-control-stdout-code',
    exit: 0,
    expect: 'the refusal code still reaches stdout for the example client',
    stdoutCode: r2.stdoutCode,
    stdoutHead: '',
    stderrHead: '',
    stderrBytes: 0,
    hasCode: true,
    hasFix: true,
    unknownCommandsInRepair: [],
    hostPathInRepair: false,
    defective: r2.stdoutCode !== 'grant_not_found',
  });

  daemon.kill('SIGKILL');

  const defectFaces = faces.filter((f) => f.defective);
  const guards = faces.filter((f) => f.face.startsWith('G'));
  const guardFailures = guards.filter((f) => f.defective);
  const verdict = defectFaces.length === 0 && guardFailures.length === 0
    ? 'daemon-refusal-voice-held'
    : 'daemon-refusal-voice-blind';

  const report = {
    tool: 'measure-daemon-refusal-voice',
    date: new Date().toISOString(),
    tree: PUBLISHED ? 'published' : 'repo',
    verdict,
    facesTotal: faces.length,
    defectFaces: defectFaces.length,
    guardsTotal: guards.length,
    guardFailures: guardFailures.length,
    faces,
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({
    verdict, out: OUT, faces: faces.length,
    defectFaces: defectFaces.map((f) => f.face),
    guardFailures: guardFailures.map((f) => f.face),
  }, null, 2));
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  process.exit(verdict === 'daemon-refusal-voice-held' ? 0 : 1);
}

main();
