'use strict';

// BUILD-TX JUDGES ITS OWN VALUE INPUTS (2026-11-18).
//
// WHY (measured 2026-11-18, tools/measure-buildtx-input-voice.js, on the
// PUBLISHED v0.2.36 npm package):
//
//   $ signerd build-tx --keystore ks.json --to not-a-key! ...
//   wire_build_failed: build-tx: Non-base58 character
//     fix: build-tx: Non-base58 character
//
// Four of four value faces refused with the SAME code, a third-party
// message (bs58, web3.js, buffer) and a `fix:` line that echoed the error
// in the same words - no flag named, nothing to do. The file-input half of
// the same command already spoke the product's voice (keystore_unreadable
// with its repair); grant-add judges the identical shape with the identical
// words (grant_field_invalid: "a base58 Ed25519 public key of exactly 32
// bytes"). The refusal is the product - and a refusal that speaks a
// library's language, in a repair that only repeats itself, is mute.
//
// THE CONTRACT:
//   D1 a mistyped --to/--blockhash refuses with the PRODUCT's code
//      (invalid_key_argument), not wire_build_failed;
//   D2 the refusal names the FLAG the operator passed;
//   D3 it names a repair that is not an echo of the error - an action,
//      stated as a flag to pass;
//   D4 a library sentence ("Non-base58 character", "Blob.encode[...]",
//      "Invalid public key input") never reaches the operator;
//   D5 the residual wire_build_failed (a well-formed value the builder
//      still refuses) carries the rebuild command, not its own detail;
//   D6/G guards: a legal build still exits 0 and writes the wire;
//      invalid_lamports, keystore_unreadable, exit code 2 and the
//      no-unknown-command rule are unchanged.
//
// THE LADDER: D1-D4 red on the pre-fix tree, guards green on both.
//
// PROVEN RED: the pre-fix commit (eafe108) run against this file shows
// D1-D4 failing with the exact foreign prose above; see the measurement
// artifact research/buildtx-input-voice-2026-11-18.json (published v0.2.36
// = same tree) for the instrument's own two-tree verdict.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const { Keypair } = require(path.join(ROOT, 'node_modules', '@solana', 'web3.js'));

/** Every command this CLI offers - a repair may only name one of these. */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

/** Third-party sentences that must never reach the operator. */
const FOREIGN_PHRASES = [
  'Non-base58 character',
  'Invalid public key input',
  'Blob.encode[',
  'Uint8Array',
  'base-x',
];

function cli(args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  const fixMatch = text.match(/(^|\n)\s*fix:\s*(.*)/);
  return { code, firstLine, hasFix: fixMatch !== null, fixText: fixMatch ? fixMatch[2].trim() : null };
}

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-buildtxgate-'));
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'buildtx gate passphrase\n', { mode: 0o600 });
  const keystore = path.join(dir, 'ops.key');
  const kg = cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(kg.status, 0, `keygen must work: ${kg.stderr}`);
  const pubkey = JSON.parse(kg.stdout).publicKey;
  const out = path.join(dir, 'tx.bin');
  // Default build: every required flag present, `extra` replaces nothing
  // (--to given twice would be a duplicate_flag refusal, so the --to faces
  // use buildTo instead of extra).
  const build = (extra) => cli(['build-tx', '--keystore', keystore, '--to', pubkey,
    '--lamports', '42', '--out', out, ...extra]);
  const buildTo = (value) => cli(['build-tx', '--keystore', keystore, '--to', value,
    '--lamports', '42', '--out', out]);
  return { dir, pass, keystore, pubkey, out, build, buildTo };
}

/** 31 raw bytes, base58: decodes fine, is NOT a 32-byte value. */
const B58_31 = (() => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const bytes = Buffer.alloc(31, 1);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = '';
  while (n > 0n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  return out;
})();

test('D1: a mistyped --to refuses with the product code, not wire_build_failed', (t) => {
  const f = fixture(t);
  const res = f.buildTo('not-a-key!');
  const v = voiceOf(res.stderr);
  assert.strictEqual(res.status, 2, 'a bad value is a usage refusal (exit 2)');
  assert.strictEqual(v.code, 'invalid_key_argument',
    `expected the product's own code, got: ${v.firstLine}`);
});

test('D1b: a 31-byte --to refuses with the product code too', (t) => {
  const f = fixture(t);
  const res = f.buildTo(B58_31);
  const v = voiceOf(res.stderr);
  assert.strictEqual(res.status, 2);
  assert.strictEqual(v.code, 'invalid_key_argument', `got: ${v.firstLine}`);
});

test('D2: the refusal names the flag the operator passed', (t) => {
  const f = fixture(t);
  // The FIRST line: that is the refusal itself (and the line whose leading
  // token a caller reads). Naming the flag only somewhere later in prose
  // would not tell the operator WHICH of the two values was wrong.
  for (const value of ['not-a-key!', B58_31]) {
    const v = voiceOf(f.buildTo(value).stderr);
    assert.ok(v.firstLine.includes('--to'),
      `the refusal line never mentions --to: ${v.firstLine}`);
  }
  for (const value of ['nonsense!!!', B58_31]) {
    const v = voiceOf(f.build(['--blockhash', value]).stderr);
    assert.ok(v.firstLine.includes('--blockhash'),
      `the refusal line never mentions --blockhash: ${v.firstLine}`);
  }
});

test('D3: the repair is an action, not an echo of the error', (t) => {
  const f = fixture(t);
  const cases = [['--to', 'not-a-key!'], ['--to', B58_31],
    ['--blockhash', 'nonsense!!!'], ['--blockhash', B58_31]];
  for (const [flag, value] of cases) {
    const res = flag === '--to' ? f.buildTo(value) : f.build([flag, value]);
    const v = voiceOf(res.stderr);
    assert.ok(v.hasFix, `${flag} ${value}: no fix line at all`);
    const firstLineDetail = v.firstLine.slice(v.firstLine.indexOf(':') + 1).trim();
    const echoed = v.fixText === firstLineDetail ||
      v.fixText.replace(/^build-tx:\s*/, '') === firstLineDetail.replace(/^build-tx:\s*/, '');
    assert.ok(!echoed, `${flag} ${value}: fix echoes the error: fix: ${v.fixText}`);
    // An ACTION: names the flag to pass or a command to run.
    assert.ok(/--[a-z-]+/.test(v.fixText) || /signerd\s+[a-z]/.test(v.fixText),
      `${flag} ${value}: fix names no flag and no command: ${v.fixText}`);
  }
});

test('D4: no third-party sentence reaches the operator', (t) => {
  const f = fixture(t);
  const cases = [['--to', 'not-a-key!'], ['--to', B58_31],
    ['--blockhash', 'nonsense!!!'], ['--blockhash', B58_31]];
  for (const [flag, value] of cases) {
    const stderr = (flag === '--to' ? f.buildTo(value) : f.build([flag, value])).stderr;
    for (const phrase of FOREIGN_PHRASES) {
      assert.ok(!stderr.includes(phrase),
        `${flag} ${value}: leaked library prose ${JSON.stringify(phrase)}:\n${stderr}`);
    }
  }
});

test('D5: --blockhash is judged by the same rule as --to', (t) => {
  const f = fixture(t);
  const res = f.build(['--blockhash', 'nonsense!!!']);
  const v = voiceOf(res.stderr);
  assert.strictEqual(res.status, 2, 'exit stays 2');
  assert.strictEqual(v.code, 'invalid_key_argument', `got: ${v.firstLine}`);
  assert.ok((v.fixText || '').includes('--blockhash'),
    `the fix for --blockhash must name --blockhash: ${v.fixText}`);
});

test('G1: a legal build still exits 0 and writes the wire', (t) => {
  const f = fixture(t);
  const res = f.build([]);
  assert.strictEqual(res.status, 0, res.stderr);
  assert.ok(fs.existsSync(f.out) && fs.statSync(f.out).size > 0, 'the wire was not written');
});

test('G2: the --lamports voice is unchanged (invalid_lamports + its fix)', (t) => {
  const f = fixture(t);
  const res = cli(['build-tx', '--keystore', f.keystore, '--to', f.pubkey,
    '--lamports', 'fortytwo', '--out', f.out]);
  const v = voiceOf(res.stderr);
  assert.strictEqual(res.status, 2);
  assert.strictEqual(v.code, 'invalid_lamports', `got: ${v.firstLine}`);
  assert.ok((v.fixText || '').includes('--lamports'), 'its fix must keep naming --lamports');
});

test('G3: the keystore face keeps its own named voice', (t) => {
  const f = fixture(t);
  const res = cli(['build-tx', '--keystore', path.join(f.dir, 'no-such.key'),
    '--to', f.pubkey, '--lamports', '42', '--out', f.out]);
  const v = voiceOf(res.stderr);
  assert.strictEqual(res.status, 2);
  assert.strictEqual(v.code, 'keystore_unreadable', `got: ${v.firstLine}`);
  assert.ok(v.hasFix && /signerd\s+keygen/.test(v.fixText), 'its fix must stay');
});

test('G4: every repair names only commands this CLI offers, and no host path', (t) => {
  const f = fixture(t);
  const cases = [['--to', 'not-a-key!'], ['--to', B58_31],
    ['--blockhash', 'nonsense!!!'], ['--blockhash', B58_31]];
  for (const [flag, value] of cases) {
    const stderr = (flag === '--to' ? f.buildTo(value) : f.build([flag, value])).stderr;
    const re = /signerd\s+([a-z][a-z-]*)/g;
    let m;
    while ((m = re.exec(stderr)) !== null) {
      assert.ok(KNOWN_COMMANDS.includes(m[1]),
        `repair names an unknown command ${m[1]}: ${stderr}`);
    }
    assert.ok(!/\/home\/|\/Users\/|\/root\//.test(stderr), `host path in refusal: ${stderr}`);
  }
});

test('D6: the residual wire_build_failed carries the rebuild command, not an echo', () => {
  // The PRE-validation makes this face unreachable through the CLI with a
  // mistyped value - so it is tested at the seam it is raised at: a wire
  // builder failure (an invalid key handed past the checks) must still
  // carry a runnable repair. The pre-fix tree printed the library's
  // sentence twice; this gate is what keeps M7 (echo returns) caught.
  const { BuildTxError, buildTransferWireBytes } =
    require(path.join(ROOT, 'src', 'buildtx.js'));
  let caught = null;
  try {
    buildTransferWireBytes({
      fromPubkey: 'not-a-public-key!', toPubkey: 'not-a-public-key!',
      lamports: 42, blockhash: 'not-a-blockhash!',
    });
  } catch (err) { caught = err; }
  assert.ok(caught instanceof BuildTxError, `expected a BuildTxError, got ${caught}`);
  assert.strictEqual(caught.code, 'wire_build_failed');
  assert.ok(typeof caught.fix === 'string' && caught.fix.length > 0,
    'the residual failure must carry its repair');
  assert.ok(/signerd\s+build-tx/.test(caught.fix),
    `the repair must name the rebuild command: ${caught.fix}`);
  assert.ok(caught.fix !== caught.message,
    'the repair must not be the error again');
});
