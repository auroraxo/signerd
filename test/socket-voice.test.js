'use strict';

// THE SOCKET VOICE: when the socket cannot be reached, the operator hears a
// STATE, never a raw errno - and the repair the refusal names can be run.
//
// MEASURED 2026-11-16 (tools/measure-socket-voice.js, published v0.2.30 tree
// e29634a - research/socket-voice-v0.2.30-2026-11-16.json, verdict
// operator-hears-raw-errno-and-unrunnable-repair, 6 of 6 faces defective):
//
//   D1  Every transport refusal already told the operator to
//       "check it with signerd status --socket <path>" - and the CLI
//       answered `unknown_flag: --socket`, exit 2. The named repair could
//       not be RUN. src/cli-flags.js F3 says a refusal may only name a
//       repair the CLI actually offers.
//   D2  A sign against a path nobody ever bound answered
//       `ENOENT: connect ENOENT <path>`: a kernel syscall name, not an
//       operator action (was the daemon never started? did it die? is the
//       path wrong? ENOENT says nothing).
//   D3  A sign against a STALE socket (file exists, nobody listening - a
//       daemon that died without unlinking) answered
//       `ECONNREFUSED: connect ECONNREFUSED <path>`, which reads like a
//       policy decision rather than a dead daemon.
//   D4  The repair itself, run exactly as written: exit 2, unknown_flag.
//   D5  `status --socket` on a LIVE daemon did not exist either - the
//       one question an operator needs answered before anything else.
//   D6  An UNPROVABLE state (path that cannot even be lstat'ed) must be
//       refused as unknown, never collapsed into "dead" - the same
//       three-way rule src/socketprobe.js holds for the daemon's start.
//
// THE FIX: src/socketstatus.js is the one place that turns a probe verdict
// or a connect errno into the product's voice: socket_missing /
// socket_stale / socket_state_unknown / socket_not_reachable /
// socket_connect_failed, each with a repair that is a COMMAND, and
// `signerd status --socket <path>` now exists to answer it.
//
// LADDER: D1-D6 FAIL on the published pre-fix tree, PASS after. G1 (status
// --grants --ledger keeps its answers) and G2 (the real daemon still signs)
// PASS on BOTH trees - a socket voice that refuses the happy path is not a
// voice.
//
// Exit-code contract (stated, not guessed): a USAGE refusal (a socket path
// outside the kernel's domain) exits 2, exactly as src/socketpath.js always
// has; a STATE refusal - the daemon is not there / is dead / cannot be
// proven - exits 1, because the operator's command was well formed and the
// WORLD answered. That is the same code `sign` gives the same condition, so
// `signerd status --socket x && deploy` and `signerd sign --socket x ...`
// agree.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');

const REPO = path.resolve(__dirname, '..');
const BIN = path.join(REPO, 'bin', 'signerd.js');

const children = new Set();
process.on('exit', () => {
  for (const c of children) { try { c.kill('SIGKILL'); } catch { /* gone */ } }
});

function tmpdir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function sh(args, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', timeout: 60000, ...opts });
}

/** The product contract: one code, one repair, on the first lines. */
function voice(text) {
  const first = String(text || '').split('\n').find((l) => l.trim().length > 0) || '';
  return {
    code: (first.split(':')[0] || '').trim(),
    hasFix: /(^|\n)\s*fix:/.test(String(text || '')),
    text: String(text || ''),
  };
}

const RAW_ERRNO = /^(ENOENT|ECONNREFUSED|EACCES|EISDIR|ENOTDIR|ELOOP|EINVAL)$/;

/** A socket file nobody serves: bind it, then KILL the listener (a
 *  graceful close unlinks the file - see tools/measure-socket-voice.js). */
function staleSocket(t, dir) {
  const socketPath = path.join(dir, 'stale.sock');
  const holder = spawn(process.execPath, [
    '-e', "require('node:net').createServer(() => {}).listen(process.argv[1], () => console.log('READY'));setInterval(() => {}, 1000);",
    socketPath,
  ], { stdio: ['ignore', 'pipe', 'ignore'] });
  children.add(holder);
  return new Promise((resolve) => {
    // ONE settlement: 'data' and the timeout both land here, and a second
    // pass must neither re-kill nor resolve again (the async-after-test
    // failure a double settle produced).
    let settled = false;
    const timer = setTimeout(() => finish(), 5000);
    function finish() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { process.kill(holder.pid, 'SIGKILL'); } catch { /* gone */ }
      children.delete(holder);
      for (let i = 0; i < 40 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.05']);
      resolve(socketPath);
    }
    holder.stdout.once('data', finish);
    holder.once('error', finish);
  });
}

function startDaemon(t, dir) {
  const cfg = path.join(dir, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the socket-voice ladder only\n', { mode: 0o600 });
  const keystore = path.join(cfg, 'ops.key');
  const grants = path.join(cfg, 'grants.json');
  const ledger = path.join(dir, 'journal.jsonl');
  const socketPath = path.join(dir, 'live.sock');
  const log = path.join(dir, 'daemon.log');

  const keygen = sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const add = sh(['grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stderr}`);

  const logFd = fs.openSync(log, 'a');
  const daemon = spawn(process.execPath, [BIN, 'run', '--keystore', keystore,
    '--passphrase-file', pass, '--grants', grants, '--ledger', ledger, '--socket', socketPath],
  { stdio: ['ignore', logFd, logFd] });
  children.add(daemon);
  t.after(() => {
    try { daemon.kill('SIGKILL'); } catch { /* gone */ }
    children.delete(daemon);
    fs.closeSync(logFd);
    fs.rmSync(dir, { recursive: true, force: true });
  });
  for (let i = 0; i < 200 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.05']);
  assert.ok(fs.existsSync(socketPath),
    `the daemon must bind its socket: ${fs.readFileSync(log, 'utf8').slice(-400)}`);
  return { keystore, pass, grants, ledger, socketPath };
}

// ---------------------------------------------------------------------------
// D: the measured defects.
// ---------------------------------------------------------------------------

test('D1 status --socket names an absent socket (the command every refusal names)', () => {
  const dir = tmpdir('signerd-d1-');
  const socketPath = path.join(dir, 'never-bound.sock');
  const res = sh(['status', '--socket', socketPath]);
  const v = voice(res.stderr);
  try {
    assert.notStrictEqual(res.status, 0, 'a missing daemon must not read as ok');
    assert.strictEqual(res.status, 1, `a state refusal exits 1 (got ${res.status})`);
    assert.strictEqual(v.code, 'socket_missing',
      `the state must be named, not an errno: ${res.stderr}`);
    assert.ok(v.hasFix, `the refusal must carry a repair: ${res.stderr}`);
    // The repair must be a COMMAND, not prose: it names `signerd run`, the
    // documented way to start the daemon on that path.
    assert.match(v.text, /signerd run --keystore/,
      `the repair must name the command that starts a daemon: ${res.stderr}`);
    // ... and the machine-readable answer rides on stdout, single JSON.
    const out = JSON.parse(res.stdout);
    assert.strictEqual(out.ok, false, 'stdout must carry the refusal verdict');
    assert.strictEqual(out.error, 'socket_missing', 'stdout must carry the same code');
    assert.strictEqual(out.socket.state, 'absent', 'stdout must carry the probe state');
    // The raw errno must never reach the operator (D2's rule, same module).
    assert.doesNotMatch(res.stderr, /\bENOENT\b|\bECONNREFUSED\b|\bEACCES\b/,
      `a raw errno must never reach the operator: ${res.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D2 a sign against an absent socket is socket_missing, not a raw errno', () => {
  const dir = tmpdir('signerd-d2-');
  try {
    const socketPath = path.join(dir, 'never-bound.sock');
    const tx = path.join(dir, 'tx.bin');
    fs.writeFileSync(tx, Buffer.alloc(140, 0x2a), { mode: 0o600 });
    const res = sh(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', tx]);
    const v = voice(res.stderr);
    assert.notStrictEqual(res.status, 0, 'a dead socket must not sign');
    assert.strictEqual(v.code, 'socket_missing',
      `the refusal must NAME the state: ${res.stderr}`);
    assert.ok(v.hasFix, `the refusal must carry a repair: ${res.stderr}`);
    assert.doesNotMatch(res.stderr, /(^|\s)ENOENT:|connect ENOENT/,
      `the raw errno must not reach the operator: ${res.stderr}`);
    // The state's repair must be runnable - it names the status command
    // that D4 executes.
    assert.match(v.text, /signerd status --socket/,
      `the repair must name the diagnostic: ${res.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D3 a sign against a stale socket is socket_stale, not ECONNREFUSED', async (t) => {
  const dir = tmpdir('signerd-d3-');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const socketPath = await staleSocket(t, dir);
  const tx = path.join(dir, 'tx.bin');
  fs.writeFileSync(tx, Buffer.alloc(140, 0x2a), { mode: 0o600 });

  const res = sh(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', tx]);
  const v = voice(res.stderr);
  assert.notStrictEqual(res.status, 0, 'a dead daemon must not sign');
  assert.strictEqual(v.code, 'socket_stale',
    `a stale socket must be named as stale: ${res.stderr}`);
  assert.ok(v.hasFix, `the refusal must carry a repair: ${res.stderr}`);
  assert.doesNotMatch(res.stderr, /ECONNREFUSED/,
    `the raw errno must not reach the operator: ${res.stderr}`);
  // The repair must name the ACTUAL file to remove - a repair that says
  // "remove the stale socket file" without naming it leaves the operator
  // guessing which path (the M-class defect the mutation ladder catches).
  assert.ok(v.text.includes(socketPath),
    `the repair must name the stale file: ${res.stderr}`);
  assert.match(v.text, /rm /, `the repair must be a command: ${res.stderr}`);
});

test('D4 the repair the transport refusal names actually runs', () => {
  const dir = tmpdir('signerd-d4-');
  try {
    const socketPath = path.join(dir, 'never-bound.sock');
    const tx = path.join(dir, 'tx.bin');
    fs.writeFileSync(tx, Buffer.alloc(140, 0x2a), { mode: 0o600 });

    // Take the path OUT of the refusal's own repair line and run exactly
    // what the refusal says: the contract is not that the word "status"
    // appears, it is that the operator can do what they were told.
    const refused = sh(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', tx]);
    const named = /signerd status --socket (\S+)/.exec(refused.stderr);
    assert.ok(named, `the refusal must name a repair command: ${refused.stderr}`);

    const repair = sh(['status', '--socket', named[1]]);
    const v = voice(repair.stderr);
    assert.notStrictEqual(repair.status, 2,
      `the named repair must not be a USAGE refusal (exit 2): ${repair.stderr}`);
    assert.notStrictEqual(v.code, 'unknown_flag',
      `the named repair must be a command the CLI has: ${repair.stderr}`);
    // ...and it must answer the same state the sign refusal reported.
    assert.strictEqual(v.code, 'socket_missing',
      `the diagnostic must report the state: ${repair.stderr}`);
    const out = JSON.parse(repair.stdout);
    assert.strictEqual(out.socket.state, 'absent',
      'the diagnostic must answer with the probe state');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D5 status --socket on a LIVE daemon reports live and exits 0', async (t) => {
  const dir = tmpdir('signerd-d5-');
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });
  const { socketPath } = startDaemon(t, dir);

  const res = sh(['status', '--socket', socketPath]);
  assert.strictEqual(res.status, 0,
    `a live daemon must be reported ok: ${res.stdout}${res.stderr}`);
  const out = JSON.parse(res.stdout);
  assert.strictEqual(out.ok, true, 'a live socket answers ok');
  assert.strictEqual(out.socket.state, 'live', 'the probe state must be live');
  assert.strictEqual(out.socket.path, socketPath, 'the path must be echoed');

  // ... and the diagnostic agrees with a real round trip on the same path:
  // the wire is signed by the daemon's OWN key, or the policy would refuse
  // it for a reason that has nothing to do with liveness.
  const { Keypair } = require(path.join(REPO, 'node_modules', '@solana', 'web3.js'));
  const { buildTransferWire } = require(path.join(REPO, 'src', 'client.js'));
  const { readKeystorePublicKey } = require(path.join(REPO, 'src', 'keystore.js'));
  const tx = path.join(dir, 'tx.bin');
  fs.writeFileSync(tx, buildTransferWire({
    fromPubkey: readKeystorePublicKey({ file: path.join(dir, 'cfg', 'ops.key') }),
    toPubkey: 'So11111111111111111111111111111111111111112',
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });
  const sign = sh(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', tx,
    '--out', path.join(dir, 'signed.bin')]);
  assert.strictEqual(sign.status, 0,
    `the live socket must really sign: ${sign.stdout}${sign.stderr}`);
});

test('D6 an unprovable socket state is refused as unknown, never guessed', (t) => {
  const dir = tmpdir('signerd-d6-');
  const socketPath = path.join(dir, 'inaccessible', 'live.sock');
  fs.mkdirSync(path.dirname(socketPath), { recursive: true, mode: 0o700 });
  // A path whose STATE cannot be proven: lstat itself fails (EACCES), so
  // the probe has no verdict. The rule src/socketprobe.js holds for the
  // daemon's start applies here too: refuse, never guess.
  fs.writeFileSync(socketPath, '', { mode: 0o600 }); // a plain file, so the lstat below works...
  fs.chmodSync(path.dirname(socketPath), 0o000);
  let bites = true;
  try { fs.lstatSync(socketPath); bites = false; } catch { /* as intended */ }
  fs.chmodSync(path.dirname(socketPath), 0o700);
  fs.rmSync(dir, { recursive: true, force: true });
  if (!bites) {
    // The fixture needs a lstat that FAILS (root, or a sandboxed runner).
    // Named skip, never a silent pass over an unproven state.
    return t.skip('lstat does not fail for this user - the unknown state cannot be built here');
  }

  const dir2 = tmpdir('signerd-d6b-');
  try {
    const sock2 = path.join(dir2, 'inaccessible', 'live.sock');
    fs.mkdirSync(path.dirname(sock2), { recursive: true, mode: 0o700 });
    fs.writeFileSync(sock2, '', { mode: 0o600 });
    fs.chmodSync(path.dirname(sock2), 0o000);
    const res = sh(['status', '--socket', sock2]);
    fs.chmodSync(path.dirname(sock2), 0o700);
    const v = voice(res.stderr);
    assert.strictEqual(v.code, 'socket_state_unknown',
      `an unprovable state must be named unknown: ${res.stderr}`);
    assert.ok(v.hasFix, `the refusal must carry a repair: ${res.stderr}`);
    assert.match(v.text, /never guessed/,
      `the refusal must say the state was not guessed: ${res.stderr}`);
    assert.strictEqual(res.status, 1, 'a state refusal exits 1');
  } finally {
    fs.chmodSync(path.join(dir2, 'inaccessible'), 0o700);
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// G: guards - green on BOTH trees.
// ---------------------------------------------------------------------------

test('G1 guard: status --grants --ledger keeps its answers', () => {
  const dir = tmpdir('signerd-g1-');
  try {
    const pass = path.join(dir, 'pass');
    fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
    const keystore = path.join(dir, 'ops.key');
    const grants = path.join(dir, 'grants.json');
    const ledger = path.join(dir, 'journal.jsonl');
    assert.strictEqual(sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]).status, 0);
    assert.strictEqual(sh(['grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '500000000', '--window-max-lamports', '500000000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']).status, 0);

    const res = sh(['status', '--grants', grants, '--ledger', ledger]);
    assert.strictEqual(res.status, 0, `the documented status must keep working: ${res.stderr}`);
    const out = JSON.parse(res.stdout);
    assert.strictEqual(out.ok, true);
    assert.deepStrictEqual(out.grants, ['ops'], 'the grants answer must be unchanged');
    assert.ok(out.ledger && typeof out.ledger.seq === 'number', 'the ledger answer must be unchanged');
    assert.ok(!('socket' in out), 'without --socket there is no socket section');

    // ... and a missing --grants with no --socket is still the usage
    // refusal it always was (the dispatch must not become lenient).
    const bare = sh(['status']);
    assert.strictEqual(bare.status, 2, 'a bare status still asks for its flags');
    assert.match(bare.stderr, /missing --grants/, `the usage voice is unchanged: ${bare.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('G2 guard: the real daemon still signs through the documented path', async (t) => {
  const dir = tmpdir('signerd-g2-');
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });
  const { keystore, pass, grants, ledger, socketPath } = startDaemon(t, dir);

  // The wire must be a REAL Solana transfer signed by the daemon's own key:
  // the policy refuses anything else, and a guard that passes for the wrong
  // reason is not a guard (the v0.2.30 G2 lesson - measure, don't assume).
  const { Keypair } = require(path.join(REPO, 'node_modules', '@solana', 'web3.js'));
  const { buildTransferWire } = require(path.join(REPO, 'src', 'client.js'));
  const { readKeystorePublicKey } = require(path.join(REPO, 'src', 'keystore.js'));
  const tx = path.join(dir, 'tx.bin');
  fs.writeFileSync(tx, buildTransferWire({
    fromPubkey: readKeystorePublicKey({ file: keystore }),
    toPubkey: 'So11111111111111111111111111111111111111112',
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });

  const out = path.join(dir, 'signed.bin');
  const res = sh(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.strictEqual(res.status, 0,
    `the happy path must still sign: ${res.stdout}${res.stderr}`);
  assert.ok(fs.existsSync(out) && fs.statSync(out).size > 0, 'the signature must be delivered');
  assert.ok(ledger && grants, 'the fixture names its own files');
  void pass;
});
