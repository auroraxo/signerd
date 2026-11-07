'use strict';

// THE FLAG ARITY SURFACE: a flag the operator typed must keep the SHAPE the
// operator typed. Measured 2026-11-07, live, on the pre-fix tree 6ff287d.
//
// The 2026-11-06 fix (src/cli-flags.js, test/flag-surface.test.js) refused a
// flag the command does not take. It left THREE adjacent holes, all of the
// same shape: the parser (`parseArgs`) turns tokens into a MAP, and a map
// cannot express "given twice", "given without a value", or "given a value
// even though it is a switch". Whatever it cannot express, it drops - and a
// dropped flag is a scope change nobody approved.
//
// MEASURED, live, pre-fix tree 6ff287d (all four are FAIL-OPEN):
//
//  1. run --grants NARROW --grants WIDE
//       last wins silently. NARROW caps at 1000 lamports, WIDE at
//       999999999. The daemon enforced WIDE and SIGNED 500005000 lamports
//       (`{"ok":true,... "seq":1}`) for a transaction NARROW refuses with
//       `amount`. The operator named NARROW first; nothing said the second
//       --grants overwrote the first.
//  2. grant-add --max-lamports 1000 --max-lamports 999999999
//       EXIT 0, grant file WRITTEN with maxLamports "999999999". The cap the
//       operator typed first was replaced by the second without a word.
//  3. keygen --keystore first.key --keystore second.key
//       EXIT 0, `second.key` created, `first.key` never created - the file
//       the operator named first does not exist afterwards.
//  4. run ... --grant-seal-passphrase-file        (flag, NO value)
//       `args[...] === true`, so `typeof === 'string'` is false and sealed
//       mode is read as NOT SET. Measured on a SEALED grant file that was
//       then TAMPERED (cap raised, HMAC broken): the CORRECT flag refuses
//       `grant_file_seal_mismatch` (exit 1); the flag with no value let the
//       daemon START and report `{"ok":true}`. One forgotten path switched
//       sealed mode off - the exact failure the 2026-11-06 typo fix closed,
//       re-entering through arity instead of spelling.
//     Same class, two more measured pre-fix:
//       grant-add ... --seal-passphrase-file (no value, no --append)
//         -> EXIT 0, file written with NO `seal` field, while the flag WITH
//            a value refuses `grant_file_unsealed`. One flag, two
//            behaviours, depending on whether the path was remembered.
//       sign ... --dry true
//         -> `args.dry` becomes the STRING "true", `args.dry === true` is
//            false, the request is sent as a REAL sign: exit 0, a real
//            signature, 368 bytes appended to the journal, `--out` written
//            (215 bytes). The bare `--dry` previewed and wrote NOTHING. The
//            README promises "never degraded into a real signature" for a
//            dry that is not a boolean - the CLI degraded it anyway, because
//            it read arity as presence.
//
// THE RULES (pure, offline-pinnable; bin/signerd.js is the only caller):
//   A1 a flag given TWICE is refused (`duplicate_flag`) - signerd cannot
//      know which of the two values you meant, and last-wins silently
//      swaps scope, files and caps;
//   A2 a value-taking flag given NO value is refused (`missing_value`) -
//      before it can be read as "absent" and switch a security feature off;
//   A3 a switch (a flag with no value by design) given a value is refused
//      (`flag_takes_no_value`) - `--dry true` must never become a real sign;
//   A4 the refusal happens BEFORE anything is read, written or started;
//   A5 unknown flags still answer `unknown_flag` with the closest-flag
//      suggestion (the 2026-11-06 contract is not weakened).
//
// GUARDS (green on both trees):
//   G1 the bare switch still works: `--dry` previews, writes nothing;
//   G2 unknown flags still answer `unknown_flag` + did-you-mean;
//   G3 the ordinary documented commands still run;
//   G4 a flag that is simply ABSENT still answers `missing --<flag>` from
//      requireArg - arity refusal covers a flag that was TYPED, not one
//      that was forgotten.
//
// LADDER: A1-A3 are new API (red on the pre-fix tree: the rule does not
// exist yet); L1-L6 are live refusals, red on the pre-fix tree because each
// measures one of the four fail-opens above; G1-G4 green on both.
//
// No network. No writes outside os.tmpdir().
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const DESTINATION = '65tbL68tKJDWP5LfEoRvo7ZgA4TrbJDkSibfTgef8mH2';

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

/** A keystore + passphrase file, the way the README tells a stranger to. */
function setup(prefix) {
  const root = tmpdir(prefix);
  const pass = path.join(root, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  const keystore = path.join(root, 'ops.key');
  const keygen = sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  return { root, pass, keystore };
}

/** A grant file with the given cap, plus a build-tx transaction of `amount`. */
function grantAndTx(s, { cap, amount, grants = path.join(s.root, 'grants.json'), tx = path.join(s.root, 'tx.bin') }) {
  const add = sh([
    'grant-add', '--grants', grants, '--name', 'ops', '--keystore', s.keystore,
    '--destination', DESTINATION, '--max-lamports', String(cap),
    '--window-max-lamports', String(cap), '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z',
  ]);
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stderr}`);
  const build = sh([
    'build-tx', '--keystore', s.keystore, '--to', DESTINATION,
    '--lamports', String(amount), '--out', tx,
  ]);
  assert.strictEqual(build.status, 0, `build-tx failed: ${build.stderr}`);
  return { grants, tx };
}

/**
 * Start the daemon as a DIRECT child and report whether it started. A
 * refusal is `started:false`; a daemon that answers ok:true is `started:true`.
 *
 * `grants` is explicit (defaulting to the standard path): the arity tests
 * need to point `--grants` at specific files themselves, and a harness that
 * injected its own `--grants` would create a THIRD occurrence and make the
 * refusal about the harness rather than about the command under test.
 */
async function startDaemon(s, extraArgs, journal, socket, log,
  grants = path.join(s.root, 'grants.json')) {
  const fd = fs.openSync(log, 'a');
  const child = spawn(process.execPath, [
    CLI, 'run', '--keystore', s.keystore, '--passphrase-file', s.pass,
    '--grants', grants, '--ledger', journal,
    '--socket', socket, ...extraArgs,
  ], { stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.add(child);
  const exited = new Promise((resolve) => child.once('exit', (code) => resolve(code)));
  const started = await Promise.race([
    (async () => {
      const deadline = Date.now() + 8000;
      while (Date.now() < deadline) {
        if (fs.existsSync(socket)) return true;
        await sleep(50);
      }
      return false;
    })(),
    exited.then(() => false),
  ]);
  return { child, started };
}

async function stopDaemon(child) {
  const gone = new Promise((resolve) => child.once('exit', resolve));
  try { child.kill('SIGKILL'); } catch { /* already gone */ }
  await Promise.race([gone, sleep(10000)]);
  children.delete(child);
}

// ---------------------------------------------------------------------------
// A1-A3: the pure rules, offline.
// ---------------------------------------------------------------------------

test('A1 the rule refuses a flag given twice, naming it and both values', async () => {
  const { parseArgv } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const { problems } = parseArgv([
    'run', '--keystore', 'a.key', '--grants', 'narrow.json', '--grants', 'wide.json',
    '--ledger', 'j', '--socket', 's', '--passphrase-file', 'p',
  ]);
  const dup = problems.find((p) => p.code === 'duplicate_flag');
  assert.ok(dup, `a flag typed twice must be a violation: ${JSON.stringify(problems)}`);
  assert.strictEqual(dup.flag, 'grants');
  assert.strictEqual(dup.first, 'narrow.json', 'the refusal must be able to name the first value');
  assert.strictEqual(dup.second, 'wide.json', 'the refusal must be able to name the second value');
});

test('A2 the rule refuses a value-taking flag that carries no value', async () => {
  const { parseArgv } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const { problems } = parseArgv([
    'run', '--keystore', 'k', '--passphrase-file', 'p', '--grants', 'g',
    '--ledger', 'j', '--socket', 's', '--grant-seal-passphrase-file',
  ]);
  const miss = problems.find((p) => p.code === 'missing_value');
  assert.ok(miss, `a value flag with no value must be a violation: ${JSON.stringify(problems)}`);
  assert.strictEqual(miss.flag, 'grant-seal-passphrase-file');
});

test('A2b a value-taking flag followed by another flag is caught too', async () => {
  const { parseArgv } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const { problems } = parseArgv(['sign', '--socket', 's', '--grant', 'g', '--tx', 'f', '--out']);
  const miss = problems.find((p) => p.code === 'missing_value');
  assert.ok(miss, `--out with no path must be a violation: ${JSON.stringify(problems)}`);
  assert.strictEqual(miss.flag, 'out');
});

test('A3 the rule refuses a switch given a value', async () => {
  const { parseArgv } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const { problems } = parseArgv(['sign', '--socket', 's', '--grant', 'g', '--tx', 'f', '--dry', 'true']);
  const bad = problems.find((p) => p.code === 'flag_takes_no_value');
  assert.ok(bad, `a switch given a value must be a violation: ${JSON.stringify(problems)}`);
  assert.strictEqual(bad.flag, 'dry');
  assert.strictEqual(bad.value, 'true');
});

test('A4 a well-formed invocation has no violations at all', async () => {
  const { parseArgv } = await import(`file://${path.join(ROOT, 'src', 'cli-flags.js')}`);
  const { problems } = parseArgv([
    'grant-add', '--grants', 'g', '--name', 'n', '--keystore', 'k',
    '--destination', 'D', '--max-lamports', '1000', '--window-max-lamports', '1000',
    '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z', '--append',
  ]);
  assert.deepStrictEqual(problems, [], 'a well-formed command line must be clean');
});

// ---------------------------------------------------------------------------
// L1: the fail-open measured on a live daemon.
// ---------------------------------------------------------------------------

test('L1 run refuses two --grants and never starts (measured: signed 500005000)', async () => {
  const s = setup('signerd-arity-dupgrants-');
  const narrow = path.join(s.root, 'narrow.json');
  const wide = path.join(s.root, 'wide.json');
  grantAndTx(s, { cap: 1000, amount: 500000000, grants: narrow, tx: path.join(s.root, 'tx.bin') });
  const addWide = sh([
    'grant-add', '--grants', wide, '--name', 'ops', '--keystore', s.keystore,
    '--destination', DESTINATION, '--max-lamports', '999999999',
    '--window-max-lamports', '999999999', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z',
  ]);
  assert.strictEqual(addWide.status, 0, addWide.stderr);

  const journal = path.join(s.root, 'journal.jsonl');
  const socket = path.join(s.root, 'signerd.sock');
  const log = path.join(s.root, 'd.log');
  const { child, started } = await startDaemon(
    s, ['--grants', wide], journal, socket, log, narrow);
  try {
    assert.strictEqual(started, false,
      'the daemon must NOT start: signerd cannot know which --grants you meant');
    const out = fs.readFileSync(log, 'utf8');
    assert.match(out, /^duplicate_flag: --grants$/m,
      `the refusal must name the duplicated flag: ${out}`);
    assert.match(out, /narrow\.json/, `the refusal must name the first value: ${out}`);
    assert.match(out, /wide\.json/, `the refusal must name the second value: ${out}`);
    assert.match(out, /fix:/, `the refusal must name the repair: ${out}`);
    assert.strictEqual(fs.existsSync(journal), false, 'no journal may be created');
    assert.doesNotMatch(out, /"ok":true/, 'the daemon must not report success');
  } finally {
    await stopDaemon(child);
  }
});

// ---------------------------------------------------------------------------
// L2/L3: duplicate flags on the write paths.
// ---------------------------------------------------------------------------

test('L2 grant-add refuses a duplicated cap and writes nothing', () => {
  const s = setup('signerd-arity-dupcap-');
  const grants = path.join(s.root, 'grants.json');
  const res = sh([
    'grant-add', '--grants', grants, '--name', 'ops', '--keystore', s.keystore,
    '--destination', DESTINATION, '--max-lamports', '1000', '--max-lamports', '999999999',
    '--window-max-lamports', '1000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z',
  ]);
  assert.notStrictEqual(res.status, 0,
    'a cap given twice must not be silently resolved to the second one');
  assert.match(res.stderr, /^duplicate_flag: --max-lamports$/m,
    `the refusal must name the flag: ${res.stderr}`);
  assert.strictEqual(fs.existsSync(grants), false,
    'nothing may be written when the command line is ambiguous');
});

test('L3 keygen refuses a duplicated --keystore and creates neither file', () => {
  const s = setup('signerd-arity-dupkey-');
  const first = path.join(s.root, 'first.key');
  const second = path.join(s.root, 'second.key');
  const res = sh(['keygen', '--keystore', first, '--passphrase-file', s.pass, '--keystore', second]);
  assert.notStrictEqual(res.status, 0,
    'the operator named two files; signerd must not pick one');
  assert.match(res.stderr, /^duplicate_flag: --keystore$/m, res.stderr);
  assert.strictEqual(fs.existsSync(first), false, 'the first named keystore must not be created');
  assert.strictEqual(fs.existsSync(second), false, 'the second named keystore must not be created');
});

// ---------------------------------------------------------------------------
// L4/L5: the security flag with no value (measured fail-open on sealed mode).
// ---------------------------------------------------------------------------

test('L4 a seal flag with no value must not start the daemon on a tampered sealed file', async () => {
  const s = setup('signerd-arity-noseal-');
  const sealPass = path.join(s.root, 'seal.pass');
  fs.writeFileSync(sealPass, 'a different passphrase for the seal\n', { mode: 0o600 });
  const { grants } = grantAndTx(s, { cap: 1000, amount: 1000 });
  const seal = sh(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.strictEqual(seal.status, 0, `seal-grants failed: ${seal.stderr}`);
  // TAMPER: raise the cap on the SEALED file. The HMAC no longer verifies -
  // this is the file sealed mode exists to refuse.
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  doc.grants.ops.maxLamports = '999999999999';
  fs.writeFileSync(grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });

  const journal = path.join(s.root, 'journal.jsonl');
  const socket = path.join(s.root, 'signerd.sock');
  const log = path.join(s.root, 'd.log');
  const { child, started } = await startDaemon(
    s, ['--grant-seal-passphrase-file'], journal, socket, log, grants);
  try {
    assert.strictEqual(started, false,
      'the daemon must NOT start: a seal flag with no value must be refused, not read as absent');
    const out = fs.readFileSync(log, 'utf8');
    assert.match(out, /^missing_value: --grant-seal-passphrase-file$/m,
      `the refusal must name the flag and the reason: ${out}`);
    assert.match(out, /fix:/, `the refusal must name the repair: ${out}`);
    assert.doesNotMatch(out, /"ok":true/,
      'the tampered sealed file must never be loaded by a daemon that forgot the seal path');
  } finally {
    await stopDaemon(child);
  }
});

test('L5 grant-add refuses a seal flag with no value instead of writing an unsealed file', () => {
  const s = setup('signerd-arity-noseal-add-');
  const grants = path.join(s.root, 'grants.json');
  const res = sh([
    'grant-add', '--grants', grants, '--name', 'ops', '--keystore', s.keystore,
    '--destination', DESTINATION, '--max-lamports', '1000',
    '--window-max-lamports', '1000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z', '--seal-passphrase-file',
  ]);
  assert.notStrictEqual(res.status, 0,
    'a seal passphrase with no path must not be silently dropped');
  assert.match(res.stderr, /^missing_value: --seal-passphrase-file$/m, res.stderr);
  assert.strictEqual(fs.existsSync(grants), false,
    'nothing may be written when the seal passphrase cannot be honored');
});

// ---------------------------------------------------------------------------
// L6: `--dry true` must never become a real signature.
// ---------------------------------------------------------------------------

test('L6 --dry true is refused: no signature, journal untouched, no --out file', async () => {
  const s = setup('signerd-arity-drytrue-');
  const { grants, tx } = grantAndTx(s, { cap: 1000000, amount: 1000 });
  const journal = path.join(s.root, 'journal.jsonl');
  const socket = path.join(s.root, 'signerd.sock');
  const log = path.join(s.root, 'd.log');
  const out = path.join(s.root, 'out.bin');
  const { child, started } = await startDaemon(s, [], journal, socket, log);
  assert.strictEqual(started, true, `daemon did not start: ${fs.readFileSync(log, 'utf8')}`);
  try {
    const res = sh(['sign', '--socket', socket, '--grant', 'ops', '--tx', tx,
      '--dry', 'true', '--out', out]);
    assert.notStrictEqual(res.status, 0,
      '`--dry true` must not be sent as a real sign - the value is not a switch');
    assert.match(res.stderr, /^flag_takes_no_value: --dry$/m,
      `the refusal must name the flag: ${res.stderr}`);
    assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
    assert.strictEqual(fs.existsSync(out), false, 'no signed file may be written');
    assert.strictEqual(fs.existsSync(journal) ? fs.statSync(journal).size : 0, 0,
      'the journal must stay untouched - a dry that is refused signs nothing');
  } finally {
    await stopDaemon(child);
  }
});

// ---------------------------------------------------------------------------
// G1-G4: the guards. These must be green BEFORE the fix as well.
// ---------------------------------------------------------------------------

test('G1 guard: the bare --dry still previews and writes nothing (green on both trees)', async () => {
  const s = setup('signerd-arity-bare-dry-');
  const { grants, tx } = grantAndTx(s, { cap: 1000000, amount: 1000 });
  const journal = path.join(s.root, 'journal.jsonl');
  const socket = path.join(s.root, 'signerd.sock');
  const log = path.join(s.root, 'd.log');
  const out = path.join(s.root, 'out.bin');
  const { child, started } = await startDaemon(s, [], journal, socket, log);
  assert.strictEqual(started, true, `daemon did not start: ${fs.readFileSync(log, 'utf8')}`);
  try {
    const res = sh(['sign', '--socket', socket, '--grant', 'ops', '--tx', tx, '--dry', '--out', out]);
    assert.strictEqual(res.status, 0, `the documented dry preview must still run: ${res.stderr}`);
    const body = JSON.parse(res.stdout);
    assert.strictEqual(body.dry, true, `the preview must answer dry:true: ${res.stdout}`);
    assert.strictEqual(body.signature, undefined, 'a preview must not carry a signature');
    assert.strictEqual(fs.existsSync(out), false, 'a preview must not write --out');
    assert.strictEqual(fs.existsSync(journal) ? fs.statSync(journal).size : 0, 0,
      'a preview must not touch the journal');

    // The same body must still sign for real afterwards (the falsification).
    const real = sh(['sign', '--socket', socket, '--grant', 'ops', '--tx', tx, '--out', out]);
    assert.strictEqual(real.status, 0, `the real sign must still work: ${real.stderr}`);
    assert.ok(fs.existsSync(out), 'the real sign must write --out');
    assert.ok(fs.statSync(journal).size > 0, 'the real sign must append to the journal');
  } finally {
    await stopDaemon(child);
  }
});

test('G2 guard: an unknown flag still answers unknown_flag with a suggestion', () => {
  const res = sh(['run', '--keystore', 'k', '--passphrase-file', 'p', '--grants', 'g',
    '--ledger', 'l', '--socket', 's', '--grant-seal-passphrasefile', 'p']);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /^unknown_flag: --grant-seal-passphrasefile$/m, res.stderr);
  assert.match(res.stderr, /did you mean --grant-seal-passphrase-file\?/, res.stderr);
});

test('G3 guard: the ordinary documented commands still run', () => {
  const s = setup('signerd-arity-guard-');
  const { grants, tx } = grantAndTx(s, { cap: 500000000, amount: 42 });
  assert.ok(fs.existsSync(grants), 'grant-add must still create the file');
  assert.ok(fs.existsSync(tx), 'build-tx must still create the file');
  const add2 = sh([
    'grant-add', '--grants', grants, '--name', 'ops-2', '--keystore', s.keystore,
    '--destination', DESTINATION, '--max-lamports', '1000000',
    '--window-max-lamports', '1000000', '--window-seconds', '60',
    '--expires', '2030-01-01T00:00:00Z', '--append',
  ]);
  assert.strictEqual(add2.status, 0, `--append must still work: ${add2.stderr}`);
});

test('G4 guard: an ABSENT flag still answers missing --<flag> from requireArg', () => {
  // Arity covers a flag that was TYPED without a value, not one that was
  // forgotten. The documented `missing --x` shape must survive.
  const res = sh(['sign']);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /^missing --socket$/m,
    `an absent flag must keep the documented shape: ${res.stderr}`);
});
