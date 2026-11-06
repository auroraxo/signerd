'use strict';

// The FLAG-SURFACE: a flag the operator SET must never be silently ignored.
//
// WHY (measured 2026-11-06, live, against the pre-fix tree):
//
// signerd's CLI parses `--flag value` into a map and then reads the flags it
// knows. Every other flag is dropped on the floor without a word. That is
// invisible for a cosmetic flag, and it is a FAIL-OPEN for a security flag:
//
//   signerd run --keystore k --passphrase-file p --grants g --ledger l \
//               --socket s --grant-seal-passphrasefile p      <- typo: no dash
//
// The daemon read `--grant-seal-passphrase-file`, did not find it, and
// started WITHOUT sealed mode - reporting `{"ok":true}`. Measured on a
// grant file that was sealed and then TAMPERED (the cap raised, which
// breaks the HMAC):
//
//   with the CORRECT flag:  grant_file_seal_mismatch   -> the daemon refuses
//   with the TYPO'd flag:   {"ok":true}                 -> the daemon STARTS
//
// A single missing dash turned the sealed-mode guarantee off and let the
// daemon load a grant file whose seal no longer verifies. Sealed mode
// exists precisely to refuse that file.
//
// The same class, second measurement: `grant-add --seal-passphrase-file`
// WITHOUT `--append` accepted the flag and then ignored it, writing an
// UNSEALED grant file (no `seal` field) while the operator had asked for a
// sealed one. The `--append` path refuses the same situation
// (`grant_file_unsealed`, "a passphrase for a file that carries no seal") -
// two behaviours for one flag.
//
// THE CONTRACT:
//   F1 the CLI REFUSES a flag the addressed command does not take, with a
//      machine-readable reason naming the flag and the flags that command
//      does take;
//   F2 the refusal happens BEFORE anything is read, written or started;
//   F3 a flag the command DOES take is never ignored: `grant-add
//      --seal-passphrase-file` without `--append` must refuse, not write an
//      unsealed file;
//   F4 the flags the README documents are exactly the flags the commands
//      accept (no documented line can trip F1);
//   G1 guard (green on both trees): a command with the CORRECT seal flag
//      still refuses a tampered sealed grant file - the fix must not weaken
//      the seal check;
//   G2 guard (green on both trees): an unknown COMMAND still prints the
//      usage banner (the documented-surface instrument reads that banner);
//   G3 guard (green on both trees): the ordinary commands still run
//      (keygen, grant-add, sign) - a strict flag surface must not lock the
//      documented paths out.
//
// LADDER: F-tests are RED against the pre-fix tree (the typo'd flag starts a
// daemon on a tampered sealed file; grant-add writes an unsealed file);
// G-tests are GREEN on both trees.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const README = path.join(ROOT, 'README.md');

const children = new Set();
process.on('exit', () => {
  for (const c of children) { try { c.kill('SIGKILL'); } catch { /* gone */ } }
});

function sh(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000, ...opts });
}

function tmpdir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A fresh setup: keystore, one grant, a passphrase file, and a SEALED grant
 * file whose cap is then tampered with (the seal no longer verifies).
 * Every file is created the way the README tells a stranger to create it.
 */
function freshSetup() {
  const root = tmpdir('signerd-flag-surface-');
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
  const seal = sh(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.strictEqual(seal.status, 0, `seal-grants failed: ${seal.stderr}`);
  // Tamper: raise the cap on the SEALED file. The HMAC no longer verifies -
  // this is the file sealed mode exists to refuse.
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  doc.grants['ops-24h'].maxLamports = '999999999999';
  fs.writeFileSync(grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  return {
    root, cfg, state, pass, sealPass, keystore, grants,
    journal: path.join(state, 'journal.jsonl'),
    socket: path.join(state, 'signerd.sock'),
    log: path.join(state, 'd.log'),
  };
}

/**
 * Start the daemon as a DIRECT child (so it is reaped when killed) and
 * report what happened: did it start, or did it refuse?
 */
async function startDaemon(s, extraArgs = []) {
  const fd = fs.openSync(s.log, 'a');
  const child = spawn(process.execPath, [
    CLI, 'run', '--keystore', s.keystore, '--passphrase-file', s.pass,
    '--grants', s.grants, '--ledger', s.journal, '--socket', s.socket, ...extraArgs,
  ], { stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.add(child);
  const exited = new Promise((resolve) => child.once('exit', (code) => resolve(code)));
  const started = await Promise.race([
    (async () => {
      const deadline = Date.now() + 8000;
      while (Date.now() < deadline) {
        if (fs.existsSync(s.socket)) return true;
        await sleep(50);
      }
      return false;
    })(),
    exited.then(() => false),
  ]);
  return { child, started };
}

/** Stop a daemon and wait until its pid is truly gone (reaped). */
async function stopDaemon(child, signal = 'SIGTERM') {
  const gone = new Promise((resolve) => child.once('exit', resolve));
  try { child.kill(signal); } catch { /* already gone */ }
  await Promise.race([gone, sleep(10000)]);
  children.delete(child);
  try { fs.rmSync(child.spawnfile, { force: true }); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// F1/F4: the pure rule (offline).
// ---------------------------------------------------------------------------

test('F1 the rule rejects a flag the addressed command does not take', async () => {
  const { checkFlags, COMMAND_FLAGS } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const verdict = checkFlags('run', { keystore: 'k', 'grant-seal-passphrasefile': 'p' }, []);
  assert.strictEqual(verdict.ok, false);
  assert.strictEqual(verdict.code, 'unknown_flag');
  assert.strictEqual(verdict.flag, 'grant-seal-passphrasefile');
  assert.ok(Array.isArray(verdict.supported) && verdict.supported.length > 0,
    'the refusal must name the flags the command does take');
  assert.ok(COMMAND_FLAGS.run.includes('grant-seal-passphrase-file'),
    'the correct spelling must be accepted');
});

test('F1b the rule accepts every flag a command takes, and rejects an extra argument', async () => {
  const { checkFlags } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  assert.strictEqual(checkFlags('keygen', { keystore: 'k', 'passphrase-file': 'p' }, []).ok, true);
  const extra = checkFlags('keygen', { keystore: 'k' }, ['keygen', 'stray']);
  assert.strictEqual(extra.ok, false);
  assert.strictEqual(extra.code, 'unknown_argument');
  assert.strictEqual(extra.argument, 'stray');
});

test('F4 every flag the README documents is a flag the CLI accepts', async () => {
  const { documentedInvocations } = await import(`file://${path.join(ROOT, 'tools', 'measure-documented-flags.mjs')}`);
  const { checkFlags, COMMAND_FLAGS } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const invocations = documentedInvocations(fs.readFileSync(README, 'utf8'));
  assert.ok(invocations.length > 0, 'the README must document commands');
  for (const inv of invocations) {
    assert.ok(COMMAND_FLAGS[inv.command],
      `the README documents a command the CLI does not have: ${inv.command}`);
    const args = {};
    for (const flag of inv.flags) args[flag] = 'x';
    const verdict = checkFlags(inv.command, args, []);
    assert.strictEqual(verdict.ok, true,
      `the README documents a flag ${inv.command} does not take: ${JSON.stringify(verdict)}`);
  }
});

// ---------------------------------------------------------------------------
// F1/F2/F3: the live CLI.
// ---------------------------------------------------------------------------

test('F1c the CLI refuses a flag the command does not take, naming it and the repair', () => {
  const res = sh(['run', '--keystore', 'k', '--passphrase-file', 'p',
    '--grants', 'g', '--ledger', 'l', '--socket', 's',
    '--grant-seal-passphrasefile', 'p']);
  assert.notStrictEqual(res.status, 0, 'a typo in a security flag must not be accepted');
  assert.match(res.stderr, /^unknown_flag: --grant-seal-passphrasefile$/m,
    `the refusal must name the flag: ${res.stderr}`);
  assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
  assert.match(res.stderr, /--grant-seal-passphrase-file/,
    `the refusal must name the flag the command does take: ${res.stderr}`);
});

test('F1e the refusal names the closest flag the command DOES take (the repair)', () => {
  const res = sh(['run', '--keystore', 'k', '--passphrase-file', 'p',
    '--grants', 'g', '--ledger', 'l', '--socket', 's',
    '--grant-seal-passphrasefile', 'p']);
  assert.notStrictEqual(res.status, 0);
  // The typo is one dash away from the real flag: the refusal must name it,
  // or the operator is left guessing which of seven flags to change.
  assert.match(res.stderr, /did you mean --grant-seal-passphrase-file\?/,
    `the refusal must name the closest flag the command takes: ${res.stderr}`);
});

test('F1f the refusal names the repair for a typo in a plain flag', () => {
  const res = sh(['keygen', '--keystore', 'k', '--passpharse-file', 'p']);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /unknown_flag: --passpharse-file/,
    `the refusal must name the flag: ${res.stderr}`);
  assert.match(res.stderr, /did you mean --passphrase-file\?/,
    `the refusal must name the repair: ${res.stderr}`);
});

test('F2 the refusal happens before anything is read, written or started', () => {
  const dir = tmpdir('signerd-flag-surface-noop-');
  const socket = path.join(dir, 'never.sock');
  const ledger = path.join(dir, 'never.jsonl');
  const res = sh(['run', '--keystore', path.join(dir, 'no.key'),
    '--passphrase-file', path.join(dir, 'no.pass'),
    '--grants', path.join(dir, 'no.json'), '--ledger', ledger,
    '--socket', socket, '--grant-seal-passphrasefile', path.join(dir, 'no.pass')]);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /^unknown_flag:/m);
  assert.strictEqual(fs.existsSync(socket), false, 'no socket may be created');
  assert.strictEqual(fs.existsSync(ledger), false, 'no journal may be created');
});

test('F3 grant-add refuses --seal-passphrase-file without --append instead of writing an unsealed file', () => {
  const root = tmpdir('signerd-flag-surface-grant-');
  const pass = path.join(root, 'pass');
  fs.writeFileSync(pass, 'pass\n', { mode: 0o600 });
  const keystore = path.join(root, 'ops.key');
  const keygen = sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const grants = path.join(root, 'grants.json');
  const res = sh([
    'grant-add', '--grants', grants, '--name', 'ops-24h', '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z',
    '--seal-passphrase-file', pass,
  ]);
  assert.notStrictEqual(res.status, 0,
    'a seal passphrase that cannot be honored must not be silently dropped');
  assert.match(res.stderr, /grant_file_unsealed/,
    `the refusal must name the reason: ${res.stderr}`);
  assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
  assert.strictEqual(fs.existsSync(grants), false,
    'nothing may be written when the flag cannot be honored');
});

// ---------------------------------------------------------------------------
// The measured defect, live: a typo'd seal flag must not start a daemon on a
// tampered sealed grant file.
// ---------------------------------------------------------------------------

test('F1d a typo in the seal flag must not start a daemon on a tampered sealed file', async () => {
  const s = freshSetup();
  const { child, started } = await startDaemon(s, ['--grant-seal-passphrasefile', s.sealPass]);
  try {
    assert.strictEqual(started, false,
      'the daemon must NOT start: the typo must be refused before the daemon runs');
    const out = fs.readFileSync(s.log, 'utf8');
    assert.match(out, /unknown_flag/, `the refusal must be visible: ${out}`);
    assert.doesNotMatch(out, /"ok":true/, 'the daemon must not report success');
  } finally {
    await stopDaemon(child, 'SIGKILL');
  }
});

test('G1 guard: the CORRECT seal flag still refuses the tampered sealed file', async () => {
  const s = freshSetup();
  const { child, started } = await startDaemon(s, ['--grant-seal-passphrase-file', s.sealPass]);
  try {
    assert.strictEqual(started, false,
      'a tampered sealed file must be refused, exactly as before the fix');
    const out = fs.readFileSync(s.log, 'utf8');
    assert.match(out, /grant_file_seal_mismatch/, `the seal check must still fire: ${out}`);
  } finally {
    await stopDaemon(child, 'SIGKILL');
  }
});

test('G2 guard: an unknown command still prints the usage banner', () => {
  const res = sh(['ghost', '--flag', 'x']);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /signerd — scoped signing daemon for Solana \(early prototype\)/,
    `the documented-surface instrument reads this banner: ${res.stderr}`);
});

test('G3 guard: the ordinary documented commands still run', () => {
  const root = tmpdir('signerd-flag-surface-guard-');
  const pass = path.join(root, 'pass');
  fs.writeFileSync(pass, 'pass\n', { mode: 0o600 });
  const keystore = path.join(root, 'ops.key');
  const keygen = sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const grants = path.join(root, 'grants.json');
  const add = sh([
    'grant-add', '--grants', grants, '--name', 'ops-24h', '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z',
  ]);
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stderr}`);
  const tx = path.join(root, 'tx.bin');
  const build = sh(['build-tx', '--keystore', keystore,
    '--to', 'So11111111111111111111111111111111111111112',
    '--lamports', '42', '--out', tx]);
  assert.strictEqual(build.status, 0, `build-tx failed: ${build.stderr}`);
});
