'use strict';

// ONE KEY PER GRANT FILE - the write-time enforcement (measured 2026-11-17,
// published v0.2.31 tree; tools/measure-grant-key-uniformity.js).
//
// THE DEFECT (measured on the PUBLISHED package, the bytes a stranger
// installs):
//
//   $ signerd grant-add --grants g.json --name good --keystore ops.key ...
//   {"ok":true,...}
//   $ signerd grant-add --grants g.json --name foreign --append \
//         --signer <some OTHER pubkey> ...
//   {"ok":true,"appended":true,...}          <- WRITTEN
//   $ signerd run --keystore ops.key ... --grants g.json
//   grant_signer_mismatch: foreign           <- the WHOLE file is dead
//
// signerd holds exactly ONE key. src/daemon.js #reloadGrants() checks EVERY
// grant against that key and throws on the first mismatch, so one grant
// naming another key makes the daemon refuse to START - and it takes the
// grants that were perfectly valid before it down with it. The blast radius
// is the whole file, not the one bad grant.
//
// The write path had no key to judge against: the loader validates shape,
// mode, owner, directory, lease and seal, and NEVER agreement between
// grants. So the file the product itself would not read was written with
// ok:true - the same class this repo closed three times already (the
// keygen loop 2026-11-05, the cap domain 2026-11-09, the past expiry
// 2026-11-11, the non-canonical pubkey 2026-11-11). The house rule, printed
// in src/grantadd.js three times: "a file that would be refused at run time
// is refused here".
//
// THE RULE: one grant file pins ONE key. A transaction grant pins it base58
// in `signer`, a message grant pins the SAME key base64 in `pubkey` - so
// the rule compares the DECODED 32 bytes, never the strings.
//
// WHAT THIS FILE PINS:
//   K1 the write path REFUSES a grant that pins another key (ok:false, the
//      file untouched) - for a transaction grant AND for a message grant
//   K2 the refusal names a REPAIR the CLI actually offers
//   K3 the previously valid grant in that file still works afterwards
//      (the refusal must not have damaged the file)
//   K4 the happy path is NOT over-tightened: a second grant under the SAME
//      key is accepted, and a MESSAGE grant under the same key (base64)
//      next to a transaction grant (base58) is accepted too
//   K5 `grant-remove` still repairs an ALREADY-poisoned file - the rule is
//      enforced at WRITE time, not by refusing to READ a broken file
//
// Ladder: this file is RED on any tree whose write paths accept a second
// key; GREEN here.

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
const PASSPHRASE = 'a passphrase for the key-uniformity gate only';

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

const DESTINATION = 'So11111111111111111111111111111111111111112';
const DESTINATION2 = 'Vote111111111111111111111111111111111111111';

function grantAddArgs({ cfg, grants, name, destination = DESTINATION }) {
  return ['grant-add', '--grants', grants, '--name', name,
    '--keystore', path.join(cfg, 'ops.key'), '--destination', destination,
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'];
}

function keygen(cfg, pass) {
  const r = run(['keygen', '--keystore', path.join(cfg, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(r.status, 0, `keygen failed: ${r.stderr}`);
  return JSON.parse(r.stdout.trim().split('\n').pop());
}

/** The raw Ed25519 public key as standard-padded base64 (the message spelling). */
function publicKeyB64(keypair) {
  const raw = Buffer.from(keypair.publicKey.toBytes());
  return raw.toString('base64');
}
void publicKeyB64;

test('K1/K2/K3 a grant that pins ANOTHER key is refused, with a repair, and the file survives', () => {
  const { cfg, pass } = secretDir('signerd-key-uniformity-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');

  const first = run(grantAddArgs({ cfg, grants, name: 'ops-24h' }));
  assert.strictEqual(first.status, 0, `the first grant-add must succeed: ${first.stderr}`);
  const before = fs.readFileSync(grants, 'utf8');

  // The foreign signer: a REAL, canonical, well-formed public key - only the
  // AGREEMENT with the file's other grants is wrong. A shape check would
  // pass this, which is exactly the point.
  const foreign = Keypair.generate().publicKey.toBase58();

  const bad = run([
    'grant-add', '--grants', grants, '--name', 'foreign', '--signer', foreign,
    '--destination', DESTINATION2, '--max-lamports', '500000000',
    '--window-max-lamports', '500000000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z', '--append',
  ]);
  assert.notStrictEqual(bad.status, 0,
    'a grant that pins another key must be REFUSED, not written with ok:true');
  assert.doesNotMatch(bad.stdout, /"ok":true/,
    'the refusal must not be dressed up as a success');
  assert.match(bad.stderr, /grant_file_key_mismatch/,
    `the refusal must name itself: ${bad.stderr}`);
  // The house rule: the refusal names a REPAIR the CLI actually offers.
  assert.match(bad.stderr, /fix:/, `the refusal must name a repair: ${bad.stderr}`);
  assert.match(bad.stderr, /grant-remove/,
    `the repair must be a command that exists: ${bad.stderr}`);

  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'a refused append must not have changed the file');

  // K3: the grant that WAS valid must still be valid - the refusal may not
  // damage the file it refused to extend.
  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.deepEqual(loaded.names, ['ops-24h'],
    'only the valid grant may be in the file');
});

test('K1b a MESSAGE grant that pins ANOTHER key is refused too (base64 spelling)', () => {
  const { cfg, pass } = secretDir('signerd-key-uniformity-msg-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = path.join(cfg, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', issued_at: '2026-11-17T00:00:00Z',
    claims: { version: 'v0.1.0' },
  }), { mode: 0o600 });

  // A file pinned to the FIRST keystore's key.
  const tx = run(grantAddArgs({ cfg, grants, name: 'ops-24h' }));
  assert.strictEqual(tx.status, 0, `the tx grant must succeed: ${tx.stderr}`);
  const before = fs.readFileSync(grants, 'utf8');

  // The message bootstrap derives the pinned key from ITS keystore - so the
  // CLI-reachable way to write a second key is a SECOND keystore.
  const otherCfg = path.join(cfg, 'other');
  fs.mkdirSync(otherCfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(otherCfg, 0o700);
  keygen(otherCfg, pass);

  const bad = run([
    'sign-message', '--add-grant', '--grants', grants, '--grant', 'rogue',
    '--socket', path.join(cfg, 's.sock'),
    '--keystore', path.join(otherCfg, 'ops.key'), '--body', body,
  ]);
  assert.notStrictEqual(bad.status, 0,
    'a message grant pinned to another key must be refused');
  assert.match(bad.stderr, /grant_file_key_mismatch/,
    `the refusal must name itself: ${bad.stderr}`);
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'a refused bootstrap must not have changed the file');
});

test('K4 GUARD: the same key in both encodings is ONE key and must be accepted', () => {
  const { cfg, pass } = secretDir('signerd-key-uniformity-guard-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = path.join(cfg, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', issued_at: '2026-11-17T00:00:00Z',
    claims: { version: 'v0.1.0' },
  }), { mode: 0o600 });

  // A transaction grant under the keystore's own key.
  const tx = run(grantAddArgs({ cfg, grants, name: 'ops-24h' }));
  assert.strictEqual(tx.status, 0, `the tx grant must succeed: ${tx.stderr}`);

  // A SECOND transaction grant under the SAME key: the happy path.
  const tx2 = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']);
  assert.strictEqual(tx2.status, 0,
    `a second grant under the same key must be accepted: ${tx2.stdout}${tx2.stderr}`);

  // A MESSAGE grant under the SAME key, spelled base64: the cross-encoding
  // guard. A rule that compared the STRINGS would call this a different key
  // and refuse a legal file - the over-tightening failure mode.
  const msg = run([
    'sign-message', '--add-grant', '--grants', grants, '--grant', 'receipts',
    '--socket', path.join(cfg, 's.sock'),
    '--keystore', path.join(cfg, 'ops.key'), '--body', body,
  ]);
  // The bootstrap report is the verdict: it runs BEFORE the socket round
  // trip, and no daemon is listening here, so the exit status is the
  // (expected) socket refusal, not the bootstrap's answer.
  assert.match(msg.stderr, /"bootstrapped":true/,
    `a message grant under the same key must be accepted: ${msg.stdout}${msg.stderr}`);
  assert.doesNotMatch(msg.stderr, /grant_file_key_mismatch/,
    `the same key must never be called a second key: ${msg.stderr}`);

  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.deepEqual(loaded.names, ['ops-24h', 'ops-payroll', 'receipts'],
    'all three grants must be in the file');
});

test('K5 GUARD: grant-remove still repairs an ALREADY-poisoned file', () => {
  const { cfg, pass } = secretDir('signerd-key-uniformity-repair-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');

  // Build the poisoned file by hand - it is what a file written by the OLD
  // product (or by hand) looks like. The rule is enforced at WRITE time; a
  // file that is already broken must still be REPAIRABLE, or the operator
  // would be stuck with a daemon that refuses to start.
  const own = JSON.parse(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).stdout.trim().split('\n').pop());
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  doc.grants.foreign = {
    signer: Keypair.generate().publicKey.toBase58(),
    destination: DESTINATION2,
    maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxLamports: '500000000',
    windowSeconds: '3600',
  };
  fs.writeFileSync(grants, JSON.stringify(doc, null, 2), { mode: 0o600 });

  // The daemon refuses such a file - that is the blast radius.
  const { Daemon } = require('../src/daemon');
  assert.throws(() => new Daemon({
    socketPath: path.join(cfg, 's.sock'),
    keystorePath: path.join(cfg, 'ops.key'),
    // readPassphrase strips one trailing newline; the constructor takes the
    // same string the CLI would hand it.
    passphrase: 'correct horse battery staple',
    grantFile: grants,
    ledgerFile: path.join(cfg, 'journal.jsonl'),
  }), /grant_signer_mismatch/,
  'the daemon must refuse a file that pins two keys');

  // The documented repair must work.
  const removed = run(['grant-remove', '--grants', grants, '--name', 'foreign']);
  assert.strictEqual(removed.status, 0,
    `grant-remove must repair the file: ${removed.stdout}${removed.stderr}`);

  const { loadGrantFile } = require('../src/grantfile');
  assert.deepEqual(loadGrantFile(grants).names, ['ops-24h'],
    'after the removal the file must hold only the valid grant');
  void own;
});
