'use strict';

// The SEALED-MODE SURFACE: what the README's optional seal block promises
// versus what the CLI actually executes.
//
// WHY (measured 2026-11-06, live against the working tree, pre-fix):
//
// The README's "optional (opt-in, fail-closed)" block documented commands a
// stranger cannot run:
//
//   signerd seal-grants --grants <file> \
//             --grant-seal-passphrase-file <file>      -> missing --seal-passphrase-file, exit 2
//   signerd seal-journal --ledger <file> \
//             --journal-seal-passphrase-file <file>    -> missing --journal, exit 2
//
// `seal-grants` reads `--seal-passphrase-file` (bin: readPassphrase(args,
// 'seal-passphrase-file')), `seal-journal` reads `--journal` (requireArg(args,
// 'journal')). The README used the DAEMON's flag names for the TOOLS. Same
// mistake class as the README's cargo-install line: a documented command that
// does not execute.
//
// Two more dead ends in the same block, measured:
//
//   D3 the block was placed BEFORE `signerd run` on a fresh setup, so
//      ~/.local/share/signerd/journal.jsonl did not exist yet and
//      `seal-journal` failed with `ledger_missing: ledger_missing` (exit 1) -
//      with no hint that the daemon creates the file on its first append, and
//      while the daemon still held the journal lock it serves.
//   D4 `seal-journal` and `migrate` refused a STALE lock file left by a killed
//      daemon with `ledger_locked: stop the daemon first` (exit 1), while the
//      daemon itself has a dead-PID takeover (#acquireJournalLock). A crashed
//      daemon therefore bricked the offline recovery tools: the message told
//      the operator to stop a daemon that was not running.
//
// Why no earlier instrument caught it: test/installed-tag-journey.test.js J1/J2
// check that the pinned tag DISPATCHES and DOCUMENTS each command name - they
// never check that the documented FLAGS parse, and no test executes the
// seal block from the README.
//
// THE CONTRACT:
//   S1 every seal command the README documents runs VERBATIM (same flags) and
//      exits 0.
//   S2 the README's seal block, taken FROM THE README and executed in its own
//      documented position (after the daemon ran and signed, daemon stopped),
//      succeeds - and the daemon restart line that closes it starts a sealed
//      daemon.
//   S3 a stale lock left by a dead daemon does not brick seal-journal (and
//      migrate): the tools take over exactly when the daemon would.
//   S4 the README does not contradict the CLI: the sentence that tells the
//      operator to hand-edit a sealed grant file must not exist while the CLI
//      offers a sealed --append.
//   G1 guard (green on both trees): a LIVE daemon's lock still refuses every
//      offline tool (a fix that ignores locks entirely is not a fix).
//   G2 guard (green on both trees): `seal-journal` on a missing journal still
//      refuses - S2 must fix the README's placement, not make the tool invent
//      history.
//   G3 guard (green on both trees): the seal passphrase file rules are
//      unchanged - a group-readable passphrase is still refused.
//
// LADDER: every S-test is RED against the pre-fix tree (the README's own
// commands fail verbatim, or the stale lock bricks the tool); G1/G2/G3 GREEN on
// both trees.
//
// INSTRUMENT NOTE: the daemon is spawned as a DIRECT child of this test and
// waited for after each kill. Killing a backgrounded grandchild (sh -c '&')
// leaves an unreaped zombie, and process.kill(pid, 0) reports a zombie as
// ALIVE - which would make S3's liveness precondition fail for a reason that
// has nothing to do with the defect under test.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const README = path.join(ROOT, 'README.md');

/** Daemons started by this file; never left running. */
const children = new Set();
process.on('exit', () => {
  for (const c of children) { try { c.kill('SIGKILL'); } catch { /* gone */ } }
});

function sh(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000, ...opts });
}

function tmpdir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(dir, 0o755);
  return dir;
}

function shell(script, opts = {}) {
  return spawnSync('sh', ['-c', script], { encoding: 'utf8', timeout: 120000, ...opts });
}

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (err) { return err.code === 'EPERM'; }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wait until `pid` is GONE: killed AND reaped. process.kill(pid, 0) reports an
 * unreaped zombie as ALIVE, and a synchronous spawnSync() sleep loop blocks the
 * very event loop that would reap it - so this must be async.
 */
async function waitDead(pid, ms = 15000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (!alive(pid)) return true;
    await sleep(50);
  }
  return !alive(pid);
}

/**
 * A fresh setup: keystore, one grant, passphrase + seal passphrase (both
 * owner-only), and the state directory the README's `mkdir` step creates.
 * Every file the README tells a stranger to create is created the same way.
 */
function freshSetup() {
  const root = tmpdir('signerd-seal-surface-');
  const cfg = path.join(root, 'config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const state = path.join(root, 'share', 'signerd');
  fs.mkdirSync(state, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'a different passphrase for the seal\n', { mode: 0o600 });
  const keystore = path.join(cfg, 'ops.key');
  const grants = path.join(cfg, 'grants.json');
  const keygen = sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const add = sh([
    'grant-add', '--grants', grants, '--name', 'ops-24h', '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z',
  ]);
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stderr}`);
  return {
    root, cfg, state, pass, sealPass, keystore, grants,
    journal: path.join(state, 'journal.jsonl'),
    socket: path.join(state, 'signerd.sock'),
    log: path.join(state, 'd.log'),
  };
}

/** Start the daemon as a DIRECT child (so it is reaped when killed). */
function startDaemon(s, extraArgs = []) {
  const fd = fs.openSync(s.log, 'a');
  const child = spawn(process.execPath, [
    CLI, 'run', '--keystore', s.keystore, '--passphrase-file', s.pass,
    '--grants', s.grants, '--ledger', s.journal, '--socket', s.socket, ...extraArgs,
  ], { stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.add(child);
  return waitForSocket(child, s.socket, s.log);
}

/** Wait (asynchronously, so the loop can reap) for the daemon's socket. */
async function waitForSocket(child, socket, log) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline && !fs.existsSync(socket)) await sleep(50);
  assert.ok(fs.existsSync(socket),
    `daemon must start: ${fs.readFileSync(log, 'utf8').slice(0, 400)}`);
  return child;
}

/** Stop a daemon and wait until its pid is truly gone (reaped). */
async function stopDaemon(child, signal = 'SIGTERM') {
  const gone = new Promise((resolve) => child.once('exit', resolve));
  try { child.kill(signal); } catch { /* already gone */ }
  await Promise.race([gone, sleep(15000)]);
  const dead = await waitDead(child.pid);
  assert.ok(dead,
    `daemon pid ${child.pid} must die and be reaped (kill -0 still reports it)`);
  children.delete(child);
}

/** Make the daemon write its first record (the journal's first append). */
function signOnce(s) {
  const tx = path.join(s.root, 'tx.bin');
  const build = sh(['build-tx', '--keystore', s.keystore,
    '--to', 'So11111111111111111111111111111111111111112',
    '--lamports', '42', '--out', tx]);
  assert.strictEqual(build.status, 0, `build-tx failed: ${build.stderr}`);
  const sign = sh(['sign', '--socket', s.socket, '--grant', 'ops-24h', '--tx', tx]);
  assert.strictEqual(sign.status, 0, `sign failed: ${sign.stdout}${sign.stderr}`);
}

/**
 * The two seal-tool command lines, taken FROM THE README (with their
 * continuations), as the strings a reader would copy. The harness must not
 * write the flags itself: the defect under test is exactly that the README's
 * flags and the CLI's flags disagree.
 */
function readmeSealCommands() {
  const lines = fs.readFileSync(README, 'utf8').split('\n');
  const grab = (name) => {
    const i = lines.findIndex((l) => new RegExp(`^signerd ${name}\\b`).test(l.trim()));
    if (i < 0) return null;
    const out = [lines[i]];
    for (let j = i + 1; j < lines.length && /\\\s*$/.test(lines[j - 1]); j += 1) {
      out.push(lines[j]);
    }
    return out.join('\n');
  };
  const sealGrants = grab('seal-grants');
  const sealJournal = grab('seal-journal');
  assert.ok(sealGrants !== null, 'the README must document seal-grants');
  assert.ok(sealJournal !== null, 'the README must document seal-journal');
  return { sealGrants, sealJournal };
}

/** Rewrite a README command for the sandbox and run it. */
function runReadmeCommand(command, s) {
  const script = command
    .split('\n')
    .map((l) => l.replace(/~\/\.config\/signerd/g, s.cfg)
      .replace(/~\/\.local\/share\/signerd/g, s.state)
      .replace(/(^|\s)signerd(\s|$)/, `$1"${process.execPath}" "${CLI}"$2`))
    .join('\n');
  return shell(script, { env: { ...process.env, HOME: s.root } });
}

/**
 * The seal sub-block of the README's Shape block: from the "optional (opt-in,
 * fail-closed)" comment through the two seal commands. The daemon restart line
 * that closes the block is returned separately - a daemon never exits, so it
 * is started in the background exactly as an operator's terminal would show it
 * (the README says "restart the daemon", not "run this and wait").
 */
function readmeSealBlock() {
  const lines = fs.readFileSync(README, 'utf8').split('\n');
  const start = lines.findIndex((l) => /optional \(opt-in, fail-closed\)/.test(l));
  assert.ok(start >= 0, 'the README must contain the sealed-mode block');
  const seal = [];
  const daemonLine = [];
  for (let i = start; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^signerd run /.test(line.trim())) {
      // The restart command, verbatim, including its continuations.
      daemonLine.push(line);
      for (let j = i + 1; j < lines.length && /\\\s*$/.test(lines[j - 1]); j += 1) {
        daemonLine.push(lines[j]);
      }
      break;
    }
    seal.push(line);
    if (seal.length > 40) break;
  }
  assert.ok(seal.length > 0 && daemonLine.length > 0,
    'the README seal block must contain the seal commands AND the sealed daemon restart');
  return { seal: seal.join('\n'), daemon: daemonLine.join('\n') };
}

/** Rewrite a README block for the sandbox and run it in order. */
function runReadmeBlock(block, s) {
  const script = block
    .split('\n')
    .map((l) => l.replace(/~\/\.config\/signerd/g, s.cfg)
      .replace(/~\/\.local\/share\/signerd/g, s.state)
      .replace(/(^|\s)signerd(\s|$)/, `$1"${process.execPath}" "${CLI}"$2`))
    .join('\n');
  return shell(script, { env: { ...process.env, HOME: s.root } });
}

// ---------------------------------------------------------------------------
// S1: the seal commands the README documents run VERBATIM (fresh setup).
// The two seal-tool invocations are the measured dead ends: wrong flags.
// ---------------------------------------------------------------------------
test('S1 README seal-grants/seal-journal run verbatim with the flags the README writes', async () => {
  const s = freshSetup();
  const { sealGrants, sealJournal } = readmeSealCommands();

  // The README's OWN lines, verbatim (the harness must not "fix" the flags -
  // that is the defect under test).
  const granted = runReadmeCommand(sealGrants, s);
  assert.strictEqual(granted.status, 0,
    `README's seal-grants line must run as written (exit ${granted.status}): ` +
    `${granted.stdout}${granted.stderr}`);
  assert.match(`${granted.stdout}`, /"ok":true/,
    `seal-grants must report what it sealed: ${granted.stdout}`);

  const verify = sh([
    'verify-grants', '--grants', s.grants, '--seal-passphrase-file', s.sealPass,
  ]);
  assert.strictEqual(verify.status, 0, `verify-grants must accept the fresh seal: ${verify.stderr}`);

  // `seal-journal` as documented - it needs a journal the daemon has created
  // (the README's Shape block runs `run` and `sign` first; see S2).
  const s2 = freshSetup();
  const daemon = await startDaemon(s2);
  signOnce(s2);
  await stopDaemon(daemon);

  const sealed = runReadmeCommand(sealJournal, s2);
  assert.strictEqual(sealed.status, 0,
    `README's seal-journal line must run as written (exit ${sealed.status}): ` +
    `${sealed.stdout}${sealed.stderr}`);
  assert.match(`${sealed.stdout}`, /"sealed":true/,
    `seal-journal must report what it sealed: ${sealed.stdout}`);
});

// ---------------------------------------------------------------------------
// S2: the README's sealed-mode block, taken from the README itself and run in
// its own documented position, must succeed - including the ORDER it states.
// ---------------------------------------------------------------------------
test('S2 the README sealed block runs verbatim in its documented position', async () => {
  const s = freshSetup();
  const { seal, daemon } = readmeSealBlock();

  // The block is documented AFTER the daemon has run and signed (the journal
  // exists only after the daemon's first append), and it needs the daemon
  // stopped (it holds the journal lock while it serves). The harness performs
  // exactly those documented prerequisites, then runs the block EXACTLY as
  // the README writes it.
  const first = await startDaemon(s);
  signOnce(s);
  await stopDaemon(first);

  const res = runReadmeBlock(seal, s);
  assert.strictEqual(res.status, 0,
    `the README's seal commands must run as written (exit ${res.status}):\n` +
    `stdout: ${res.stdout}\nstderr: ${res.stderr}`);
  assert.match(`${res.stdout}`, /"sealed":true/, 'seal-journal must report what it sealed');

  // The block's closing line restarts the daemon in SEALED mode: run it
  // verbatim, in the background, and require a daemon that is actually up
  // (it never exits on its own).
  const script = daemon
    .split('\n')
    .map((l) => l.replace(/~\/\.config\/signerd/g, s.cfg)
      .replace(/~\/\.local\/share\/signerd/g, s.state)
      .replace(/(^|\s)signerd(\s|$)/, `$1"${process.execPath}" "${CLI}"$2`))
    .join('\n');
  const fd = fs.openSync(s.log, 'a');
  const child = spawn('sh', ['-c', `exec ${script}`], {
    stdio: ['ignore', fd, fd], env: { ...process.env, HOME: s.root },
  });
  fs.closeSync(fd);
  children.add(child);
  try {
    // The socket file survives the first daemon's exit, so "the socket
    // exists" is NOT proof that the sealed daemon came up. Wait for the
    // daemon to ANSWER instead: a sealed daemon that refuses to start never
    // answers, and the log says why.
    const probeTx = path.join(s.root, 'probe.bin');
    const probeBuild = sh(['build-tx', '--keystore', s.keystore,
      '--to', 'So11111111111111111111111111111111111111112',
      '--lamports', '3', '--out', probeTx]);
    assert.strictEqual(probeBuild.status, 0, `build-tx failed: ${probeBuild.stderr}`);
    let answered = false;
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && !answered) {
      const probe = sh(['sign', '--socket', s.socket, '--grant', 'ops-24h', '--tx', probeTx]);
      // A refusal that is NOT a socket error means the daemon is up and
      // answering (it refuses for its own reason - that is a daemon answer,
      // not a dead socket).
      answered = !/no such file|ENOENT|connect/i.test(`${probe.stdout}${probe.stderr}`);
      if (!answered) await sleep(100);
    }
    assert.ok(answered,
      `the README's sealed daemon must start and answer: ` +
      `${fs.readFileSync(s.log, 'utf8').slice(-400)}`);
    // The sealed daemon accepts the now-sealed journal and signs again.
    const tx = path.join(s.root, 'tx2.bin');
    const build = sh(['build-tx', '--keystore', s.keystore,
      '--to', 'So11111111111111111111111111111111111111112',
      '--lamports', '7', '--out', tx]);
    assert.strictEqual(build.status, 0, `build-tx failed: ${build.stderr}`);
    const sign = sh(['sign', '--socket', s.socket, '--grant', 'ops-24h', '--tx', tx]);
    assert.strictEqual(sign.status, 0, `the SEALED daemon must sign: ${sign.stdout}${sign.stderr}`);
    assert.match(`${sign.stdout}`, /"ok":true/, `the sealed daemon must sign: ${sign.stdout}`);
  } finally {
    await stopDaemon(child);
  }
});

// ---------------------------------------------------------------------------
// S3: a STALE lock (dead daemon) must not brick the offline tools.
// ---------------------------------------------------------------------------
test('S3 seal-journal takes over a stale lock left by a dead daemon', async () => {
  const s = freshSetup();
  const daemon = await startDaemon(s);
  signOnce(s);
  await stopDaemon(daemon, 'SIGKILL');

  // The killed daemon leaves <journal>.lock behind: the measured brick.
  const lock = `${s.journal}.lock`;
  assert.ok(fs.existsSync(lock),
    'a SIGKILLed daemon must leave its lock behind - otherwise this test measures nothing');
  const owner = JSON.parse(fs.readFileSync(lock, 'utf8'));
  assert.ok(Number.isInteger(owner.pid) && owner.pid > 0, 'the lock must name its owner');
  assert.ok(!alive(owner.pid),
    `the lock left by SIGKILL must be owned by the DEAD pid ${owner.pid} ` +
    `(alive=${alive(owner.pid)}) - otherwise this test measures nothing`);

  const seal = sh([
    'seal-journal', '--journal', s.journal, '--journal-seal-passphrase-file', s.sealPass,
  ]);
  assert.strictEqual(seal.status, 0,
    `seal-journal must take over a DEAD daemon's lock (exit ${seal.status}): ${seal.stderr}`);
  assert.match(`${seal.stdout}`, /"sealed":true/);

  // migrate must not be bricked by the same artifact either.
  const s2 = freshSetup();
  const daemon2 = await startDaemon(s2);
  signOnce(s2);
  await stopDaemon(daemon2, 'SIGKILL');
  assert.ok(fs.existsSync(`${s2.journal}.lock`), 'the second crash artifact must exist');
  const mig = sh(['migrate', '--ledger', s2.journal, '--discard-legacy']);
  assert.doesNotMatch(`${mig.stdout}${mig.stderr}`, /ledger_locked/,
    `migrate must take over a DEAD daemon's lock instead of refusing with ` +
    `ledger_locked: ${mig.stdout}${mig.stderr}`);
  assert.match(`${mig.stdout}${mig.stderr}`, /already_current/,
    `migrate must reach its own verdict on a current journal: ` +
    `${mig.stdout}${mig.stderr}`);
});

// ---------------------------------------------------------------------------
// S4: the README must not contradict the CLI's capabilities.
// ---------------------------------------------------------------------------
test('S4 the README does not instruct a hand-edit where the CLI offers a sealed --append', () => {
  const text = fs.readFileSync(README, 'utf8');
  // The sentence spans a line break inside a shell comment, so the words are
  // matched across `#` and newlines.
  const saysNeverRewritten = /SEALED[\s#]*file[\s#]*is[\s#]*never[\s#]*rewritten/i.test(text);
  if (saysNeverRewritten) {
    assert.fail('the README says a sealed grant file is never rewritten, but the CLI offers ' +
      '`grant-add --append --seal-passphrase-file` (measured working 2026-11-06): ' +
      'the sentence tells the operator to hand-edit the one file the loader refuses to trust');
  }
  // And the repair the README now gives must be the one that works: append to
  // a SEALED file with the seal passphrase, then verify.
  const s = freshSetup();
  const sealed = sh(['seal-grants', '--grants', s.grants, '--seal-passphrase-file', s.sealPass]);
  assert.strictEqual(sealed.status, 0, `seal-grants failed: ${sealed.stderr}`);
  const append = sh(['grant-add', '--grants', s.grants, '--name', 'ops-second', '--append',
    '--keystore', s.keystore, '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '100000', '--window-max-lamports', '100000',
    '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z',
    '--seal-passphrase-file', s.sealPass]);
  assert.strictEqual(append.status, 0,
    `the CLI's sealed --append must work (that is the README's repair): ` +
    `${append.stdout}${append.stderr}`);
  const verify = sh(['verify-grants', '--grants', s.grants, '--seal-passphrase-file', s.sealPass]);
  assert.strictEqual(verify.status, 0, `verify-grants must accept it: ${verify.stderr}`);
});

// ---------------------------------------------------------------------------
// G1 (guard, green on both trees): a LIVE daemon's lock still refuses.
// ---------------------------------------------------------------------------
test('G1 a live daemon lock still refuses seal-journal and migrate', () => {
  const s = freshSetup();
  // A lock owned by THIS (live) process stands in for the running daemon.
  fs.writeFileSync(`${s.journal}.lock`, JSON.stringify({
    pid: process.pid, token: 'live', startedAt: Date.now(),
  }), { mode: 0o600 });
  // The journal itself must exist so the lock check is what refuses.
  fs.writeFileSync(s.journal, '', { mode: 0o600 });
  try {
    const seal = sh(['seal-journal', '--journal', s.journal,
      '--journal-seal-passphrase-file', s.sealPass]);
    assert.notStrictEqual(seal.status, 0,
      'seal-journal must refuse while a LIVE daemon holds the lock');
    assert.match(`${seal.stdout}${seal.stderr}`, /ledger_locked/);

    const mig = sh(['migrate', '--ledger', s.journal, '--discard-legacy']);
    assert.notStrictEqual(mig.status, 0, 'migrate must refuse while a live lock is held');
    assert.match(`${mig.stdout}${mig.stderr}`, /ledger_locked/);
  } finally {
    fs.rmSync(`${s.journal}.lock`, { force: true });
  }
});

// ---------------------------------------------------------------------------
// G2 (guard, green on both trees): seal-journal on a MISSING journal still
// refuses - S2 must not be fixed by making the tool invent history.
// ---------------------------------------------------------------------------
test('G2 seal-journal refuses a missing journal (fail-closed)', () => {
  const s = freshSetup();
  const seal = sh(['seal-journal', '--journal', s.journal,
    '--journal-seal-passphrase-file', s.sealPass]);
  assert.strictEqual(seal.status, 1, `expected a refusal, got exit ${seal.status}`);
  assert.match(`${seal.stdout}${seal.stderr}`, /ledger_missing/);
});

// ---------------------------------------------------------------------------
// G3 (guard, green on both trees): the seal passphrase file rules are
// unchanged - a group-readable passphrase is still refused.
// ---------------------------------------------------------------------------
test('G3 a loose seal passphrase file is still refused', () => {
  const s = freshSetup();
  fs.chmodSync(s.sealPass, 0o664);
  try {
    const seal = sh(['seal-grants', '--grants', s.grants,
      '--seal-passphrase-file', s.sealPass]);
    assert.notStrictEqual(seal.status, 0, 'a group-readable passphrase must be refused');
    assert.match(`${seal.stdout}${seal.stderr}`, /must not be group\/other accessible/);
    assert.match(`${seal.stdout}${seal.stderr}`, /chmod 600/,
      'the refusal must name the repair (repo rule)');
  } finally {
    fs.chmodSync(s.sealPass, 0o600);
  }
});
