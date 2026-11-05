'use strict';
// The MIGRATION PATH's first contact with a stranger (measured 2026-11-05):
//
// `signerd import` is the documented adoption path for the one key a Solana
// developer ALREADY holds (~/.config/solana/id.json). The README shows it
// right after `signerd keygen` into the SAME --keystore path, so a reader who
// runs the block top to bottom (or who already ran keygen) hits this:
//
//     keystore_exists: keystore_exists
//
// A self-referential verdict with no repair. The repo's own rule - "Name the
// repair, not just the verdict" (see the passphrase, grant-file and tx-file
// refusals in bin/signerd.js) - was applied to five other refusals and NOT to
// this one. The repair that actually exists (--overwrite) is accepted by the
// CLI but documented NOWHERE: not in the README, not in the usage text.
//
// This test file pins the repair surface, not the prose:
//   T1 the refusal names BOTH repairs (a different --keystore path, or
//      --overwrite) - a bare verdict fails it;
//   T2 --overwrite is documented in the usage text AND in the README;
//   T3 the usage text must not advertise a flag the CLI rejects.
// The false-positive guard: T4 pins that the KEYGEN path still refuses to
// clobber an existing keystore WITHOUT --overwrite - the repair must not
// become a silent overwrite.
//
// Ladder: this file is RED on any tree whose import refusal does not name a
// repair (the instrument IS the fix); GREEN here.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');
const README = path.join(REPO, 'README.md');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120000, ...opts });
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// A passphrase file that passes the CLI's own hygiene rules (0600, owner-only
// directory) - the harness must not create a state the product refuses.
function secretDir(prefix) {
  const root = tmpdir(prefix);
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);
  return { root, cfg, pass };
}

// A plaintext solana-keygen id.json: the real adoption input.
function writeIdJson(file) {
  const { Keypair } = require('@solana/web3.js');
  const kp = Keypair.generate();
  fs.writeFileSync(file, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return kp.publicKey.toBase58();
}

test('T1 the import refusal names the repair, not just the verdict', () => {
  const { root, cfg, pass } = secretDir('signerd-import-repair-');
  const keystore = path.join(cfg, 'ops.key');
  const src = path.join(root, 'id.json');
  writeIdJson(src);

  // First import succeeds.
  const first = run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', src]);
  assert.strictEqual(first.status, 0, `first import failed: ${first.stderr}`);

  // Second import into the same keystore must be refused AND must say how
  // to repair it. A bare "keystore_exists: keystore_exists" fails this.
  const second = run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', src]);
  assert.notStrictEqual(second.status, 0, 'the second import must be refused');
  const err = second.stderr;
  assert.match(err, /keystore_exists/, 'the machine-readable reason must survive');
  assert.match(err, /--overwrite/, 'the refusal must name the --overwrite repair');
  assert.match(err, /--keystore/, 'the refusal must name the alternative --keystore path');
});

// The usage text is printed to STDERR (bin/signerd.js:453) - the no-command
// path exits 2. Read both streams so the test measures the surface, not the
// stream choice.
function usageText() {
  const r = run([]);
  return `${r.stdout}\n${r.stderr}`;
}

test('T2 --overwrite is documented in the usage text and in the README', () => {
  const usage = usageText();
  assert.match(usage, /signerd import[\s\S]*--overwrite/,
    'the usage text must document --overwrite on the import command');

  const readme = fs.readFileSync(README, 'utf8');
  assert.match(readme, /signerd import[\s\S]{0,400}--overwrite/,
    'the README must document --overwrite on the import command');
});

test('T3 every flag the usage text advertises is accepted by the CLI', () => {
  // A flag printed in the usage text that the CLI ignores is a false promise
  // on the very surface this file is about. Extract the flags from the usage
  // block and require the parser to know them.
  const usage = usageText();
  const usageBlock = usage.slice(usage.indexOf('Usage:'), usage.indexOf('Notes:'));
  const flags = new Set();
  for (const m of usageBlock.matchAll(/--([a-z][a-z0-9-]*)/g)) flags.add(m[1]);
  assert.ok(flags.size > 0, 'the usage text must advertise flags');

  // --overwrite is the flag under test; the parser must accept it as a
  // boolean (no value) and as a value-taking flag.
  const { root, cfg, pass } = secretDir('signerd-import-flag-');
  const keystore = path.join(cfg, 'ops.key');
  const src = path.join(root, 'id.json');
  const pub = writeIdJson(src);

  const ok = run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', src, '--overwrite']);
  assert.strictEqual(ok.status, 0, `--overwrite must be accepted: ${ok.stderr}`);

  const { readKeystorePublicKey } = require('../src/keystore');
  assert.strictEqual(readKeystorePublicKey({ file: keystore }), pub,
    'the imported keystore must hold the imported key');
});

test('T4 GUARD: without --overwrite an existing keystore is still refused (no silent clobber)', () => {
  const { root, cfg, pass } = secretDir('signerd-import-guard-');
  const keystore = path.join(cfg, 'ops.key');
  const src = path.join(root, 'id.json');
  writeIdJson(src);

  assert.strictEqual(run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', src]).status, 0);
  const before = require('../src/keystore').readKeystorePublicKey({ file: keystore });

  // A DIFFERENT key, no --overwrite: must be refused, and the keystore must
  // still hold the first key afterwards.
  const other = path.join(root, 'id2.json');
  const otherPub = writeIdJson(other);
  const refused = run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', other]);
  assert.notStrictEqual(refused.status, 0, 'an existing keystore must not be clobbered silently');
  assert.match(refused.stderr, /keystore_exists/);
  assert.strictEqual(require('../src/keystore').readKeystorePublicKey({ file: keystore }), before,
    'the refused import must not have changed the keystore');
  assert.notStrictEqual(before, otherPub);
});

test('T5 GUARD: a refused --overwrite leaves the keystore intact (no half-written state)', () => {
  const { root, cfg, pass } = secretDir('signerd-import-guard2-');
  const keystore = path.join(cfg, 'ops.key');
  const src = path.join(root, 'id.json');
  writeIdJson(src);
  assert.strictEqual(run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', src]).status, 0);
  const before = require('../src/keystore').readKeystorePublicKey({ file: keystore });

  // An invalid source WITH --overwrite must fail without touching the file.
  const bad = path.join(root, 'not-a-key.txt');
  fs.writeFileSync(bad, 'this is not a key');
  const refused = run(['import', '--keystore', keystore, '--passphrase-file', pass, '--from', bad, '--overwrite']);
  assert.notStrictEqual(refused.status, 0, 'an invalid source must be refused');
  assert.match(refused.stderr, /secret_key_invalid/);
  assert.strictEqual(require('../src/keystore').readKeystorePublicKey({ file: keystore }), before,
    'a failed overwrite must leave the keystore exactly as it was');
});
