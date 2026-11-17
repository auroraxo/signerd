'use strict';

// ONE KEY PER GRANT FILE - the VERDICT surfaces (measured 2026-11-17,
// published v0.2.32 tree; tools/measure-grant-key-verdict.js).
//
// THE DEFECT (measured on the PUBLISHED package, the bytes a stranger
// installs):
//
//   v0.2.32 (2026-11-17) closed this class on the WRITE paths: `grant-add
//   --append` and the message bootstrap now refuse a grant that pins another
//   key (grant_file_key_mismatch). What was left open is the other half of
//   the same rule - the surfaces that TELL THE OPERATOR ABOUT A FILE:
//
//   $ signerd status --grants g.json --ledger j.json
//   {"ok":true,"grants":["foreign","good"],...}      <- ok:true
//   $ signerd verify-grants --grants g.json --seal-passphrase-file p
//   {"ok":true,"grants":["foreign","good"]}          <- ok:true
//   $ signerd seal-grants --grants g.json --seal-passphrase-file p
//   {"ok":true,"grants":[{"name":"foreign",...},...]} <- SEALED IT
//   $ signerd run --keystore ops.key --grants g.json ...
//   grant_signer_mismatch: foreign                    <- the daemon refuses
//
// A file that pins TWO keys can never be run by this daemon: signerd holds
// exactly ONE key and #reloadGrants() (src/daemon.js) refuses the WHOLE
// file when one grant names another key - the previously valid grants die
// with it. So all three verdict surfaces above report a DEAD FILE as fine,
// and `seal-grants` goes further: it makes the dead file AUTHENTIC. A
// sealed, authenticated grant file is the strongest provenance statement the
// product can make ("this content is exactly what the operator sealed") -
// about a file that cannot sign anything.
//
// This is the same class the repo closed on 2026-11-16 (v0.2.28): "the GRANT
// half of the seal degraded where the JOURNAL half refuses". A verdict that
// degrades is not a verdict.
//
// THE RULE: every surface that answers "is this grant file usable?" must
// refuse a file the daemon would refuse. The ONE-KEY check compares the
// DECODED 32 bytes of each grant's pinned key (base58 `signer` for a
// transaction grant, base64 `pubkey` for a message grant), so the two
// spellings of ONE key are never called two keys.
//
// WHAT THIS FILE PINS:
//   V1 `status` refuses a two-key file: not ok:true, exit != 0, and the
//      refusal names itself (grant_file_key_mismatch)
//   V2 `seal-grants` refuses it and leaves the file BYTE-IDENTICAL - a dead
//      file must not become an authenticated dead file
//   V3 `verify-grants` refuses it
//   V4 every refusal names a REPAIR the CLI actually offers (a `fix:` line)
//   V5 GUARD: a single-key file is still fine on all three surfaces
//   V6 GUARD: the CROSS-ENCODING case - a transaction grant (base58) and a
//      message grant (base64) that pin the SAME key are ONE key and must
//      still be accepted everywhere
//   V7 GUARD: `grant-remove` still REPAIRS a file that is already broken -
//      the rule is enforced on the verdict surfaces, never by refusing to
//      read a broken file into oblivion
//
// Ladder: this file is RED on any tree whose verdict surfaces accept a
// two-key file; GREEN here.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { Keypair } = require('@solana/web3.js');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120000 });
}

function secretDir(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);
  return { root, cfg, pass };
}

/** A transaction grant pinning `keypair`'s key, base58. */
function txGrant(keypair) {
  return {
    signer: keypair.publicKey.toBase58(),
    destination: 'So11111111111111111111111111111111111111112',
    maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxLamports: '500000000',
    windowSeconds: '3600',
  };
}

/** A message grant pinning the SAME key, base64 (the openreceipts spelling). */
function messageGrant(keypair) {
  const raw = Buffer.from(keypair.publicKey.toBytes());
  return {
    kind: 'message',
    issuer: 'acme',
    type: 'release',
    subject: 'acme/app',
    pubkey: raw.toString('base64'),
    maxBytes: '512',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxMessages: '10',
    windowSeconds: '3600',
  };
}

function writeGrants(file, grants) {
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants }, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

/** A file with two grants pinning TWO different, perfectly valid keys. */
function twoKeyFile(cfg) {
  const grants = path.join(cfg, 'grants.json');
  const a = Keypair.generate();
  const b = Keypair.generate();
  writeGrants(grants, { good: txGrant(a), foreign: txGrant(b) });
  return { grants, a, b };
}

/**
 * The same two-key file, SEALED under `pass` - the state an operator reaches
 * by sealing on a tree that did not yet judge uniformity (v0.2.32 and
 * earlier), or by hand-editing a sealed file and re-sealing. `verify-grants`
 * must judge the payload, not only the MAC: an authenticated file no daemon
 * can run is still a file no daemon can run.
 */
function sealedTwoKeyFile(cfg, pass, name = 'grants.json') {
  const grants = path.join(cfg, name);
  const a = Keypair.generate();
  const b = Keypair.generate();
  writeGrants(grants, { good: txGrant(a), foreign: txGrant(b) });
  const { sealDocument } = require('../src/grantseal');
  const passphrase = fs.readFileSync(pass, 'utf8').replace(/\n$/, '');
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  fs.writeFileSync(grants, JSON.stringify(sealDocument(doc, passphrase), null, 2) + '\n',
    { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  return grants;
}

test('V1 `status` refuses a two-key file instead of reporting ok:true', () => {
  const { cfg } = secretDir('signerd-key-verdict-');
  const { grants } = twoKeyFile(cfg);
  const r = run(['status', '--grants', grants, '--ledger', path.join(cfg, 'j.json')]);
  assert.notStrictEqual(r.status, 0,
    'a file no daemon can run must not be answered with exit 0');
  assert.doesNotMatch(r.stdout, /"ok":true/,
    `the verdict must not be dressed up as a success: ${r.stdout}`);
  assert.match(r.stderr, /grant_file_key_mismatch/,
    `the refusal must name itself: ${r.stderr}`);
});

test('V2 `seal-grants` refuses a two-key file and leaves it byte-identical', () => {
  const { cfg, pass } = secretDir('signerd-key-verdict-');
  const { grants } = twoKeyFile(cfg);
  const before = fs.readFileSync(grants, 'utf8');
  const r = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', pass]);
  assert.notStrictEqual(r.status, 0,
    'a dead file must not be sealed into an authenticated dead file');
  assert.doesNotMatch(r.stdout, /"ok":true/,
    `the refusal must not be dressed up as a success: ${r.stdout}`);
  assert.match(r.stderr, /grant_file_key_mismatch/,
    `the refusal must name itself: ${r.stderr}`);
  const after = fs.readFileSync(grants, 'utf8');
  assert.strictEqual(after, before, 'the file must be untouched');
  assert.strictEqual(JSON.parse(after).seal, undefined, 'the file must stay unsealed');
});

test('V3 `verify-grants` refuses a SEALED two-key file', () => {
  const { cfg, pass } = secretDir('signerd-key-verdict-');
  const grants = sealedTwoKeyFile(cfg, pass);
  const r = run(['verify-grants', '--grants', grants, '--seal-passphrase-file', pass]);
  assert.notStrictEqual(r.status, 0,
    'verifying a file no daemon can run must not answer exit 0');
  assert.doesNotMatch(r.stdout, /"ok":true/,
    `the verdict must not be dressed up as a success: ${r.stdout}`);
  assert.match(r.stderr, /grant_file_key_mismatch/,
    `the refusal must name itself: ${r.stderr}`);
});

test('V4 every refusal names a REPAIR the CLI actually offers', () => {
  const { cfg, pass } = secretDir('signerd-key-verdict-');
  const { grants } = twoKeyFile(cfg);
  const sealed = sealedTwoKeyFile(cfg, pass, 'sealed-grants.json');
  for (const args of [
    ['status', '--grants', grants, '--ledger', path.join(cfg, 'j.json')],
    ['seal-grants', '--grants', grants, '--seal-passphrase-file', pass],
    ['verify-grants', '--grants', sealed, '--seal-passphrase-file', pass],
  ]) {
    const r = run(args);
    assert.match(r.stderr, /fix:/,
      `the refusal must name a repair: ${args[0]}: ${r.stderr}`);
    assert.match(r.stderr, /grant-remove/,
      `the repair must be the command that actually repairs: ${args[0]}: ${r.stderr}`);
  }
});

test('V5 GUARD a single-key file is still fine on every verdict surface', () => {
  const { cfg, pass } = secretDir('signerd-key-verdict-');
  const grants = path.join(cfg, 'grants.json');
  writeGrants(grants, { ops: txGrant(Keypair.generate()) });

  const status = run(['status', '--grants', grants, '--ledger', path.join(cfg, 'j.json')]);
  assert.strictEqual(status.status, 0,
    `status must accept a single-key file: ${status.stderr}`);
  assert.match(status.stdout, /"ok":true/);

  const seal = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', pass]);
  assert.strictEqual(seal.status, 0,
    `seal-grants must accept a single-key file: ${seal.stderr}`);
  assert.match(seal.stdout, /"ok":true/);

  const verify = run(['verify-grants', '--grants', grants, '--seal-passphrase-file', pass]);
  assert.strictEqual(verify.status, 0,
    `verify-grants must accept a single-key file: ${verify.stderr}`);
  assert.match(verify.stdout, /"ok":true/);
});

test('V6 GUARD the cross-encoding case is ONE key and stays accepted', () => {
  const { cfg, pass } = secretDir('signerd-key-verdict-');
  const grants = path.join(cfg, 'grants.json');
  const keypair = Keypair.generate();
  writeGrants(grants, { ops: txGrant(keypair), releases: messageGrant(keypair) });

  const status = run(['status', '--grants', grants, '--ledger', path.join(cfg, 'j.json')]);
  assert.strictEqual(status.status, 0,
    `the same key in two spellings is ONE key: ${status.stderr}`);
  assert.match(status.stdout, /"ok":true/);

  const seal = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', pass]);
  assert.strictEqual(seal.status, 0,
    `the same key in two spellings is ONE key: ${seal.stderr}`);
});

test('V7 GUARD `grant-remove` still repairs a file that is already broken', () => {
  const { cfg } = secretDir('signerd-key-verdict-');
  const { grants } = twoKeyFile(cfg);
  const r = run(['grant-remove', '--grants', grants, '--name', 'foreign']);
  assert.strictEqual(r.status, 0,
    `grant-remove must repair the file: ${r.stdout}${r.stderr}`);
  const { loadGrantFile } = require('../src/grantfile');
  assert.deepEqual(loadGrantFile(grants).names, ['good'],
    'after the removal the file must hold only the valid grant');
});
