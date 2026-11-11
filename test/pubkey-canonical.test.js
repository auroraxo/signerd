'use strict';
// 11.11. PULS — THE SAME KEY IN THE WRONG SPELLING IS STILL THE WRONG FILE
//
// Measured live 2026-11-11 (repro dir pubkey-repro-*): base64 of a 32-byte
// key ends in a data char whose two low bits are always zero, so 3 of every
// 64 alphabet characters at that position decode to the SAME 32 bytes.
// Consequences on the pre-fix tree (v0.2.13 + research commits, main
// 2b85a49):
//
//   D1 (loader): loadGrantFile accepted all 3 non-canonical spellings
//                (shape regex + length 32) — the judge approved a file the
//                product can never run.
//   D2 (creation): validateMessageGrantArgs/buildMessageGrant accepted them
//                too — same class as the 2026-11-08 value-contract defect.
//   D3 (policy): evaluateMessage returned allowed for a grant pinning them
//                (shape regex only) — the refusal only fired later, and
//                for a different reason (signer_key_mismatch).
//   D4 (voice): `signerd run` against such a file exited 1 with a BARE
//                `grant_key_mismatch: releases` — no fix line, while every
//                other refusal in the CLI names one. The key bytes were
//                CORRECT; only the spelling differed, and nothing said so.
//
// The daemon itself always refused (fail-closed, exact string comparison
// against the keystore-derived canonical spelling) — the defect is the
// contract and the voice, NOT a signature over the wrong key.
//
// Guards (must pass on BOTH trees):
//   G1: the canonical spelling still loads, creates and evaluates.
//   G2: a genuinely DIFFERENT key is still refused as grant_key_mismatch
//       (the tightened rule must not swallow the real mismatch).

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { loadGrantFile } = require('../src/grantfile');
const { buildMessageGrant } = require('../src/grantadd');
const { evaluateMessage } = require('../src/policy-message');
const { isCanonicalBase64PublicKey } = require('../src/grantvalues');
const { Keypair } = require('@solana/web3.js');

const BIN = path.join(__dirname, '..', 'bin', 'signerd.js');
const SHAPE = /^[A-Za-z0-9+/]{43}=$/;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// A deterministic real key + its canonical base64 + all spellings that
// decode to the same 32 bytes but re-encode differently.
function keySet(seedFill = 7) {
  const raw = Buffer.alloc(32).fill(seedFill);
  const canon = raw.toString('base64');
  const variants = [];
  for (let i = 0; i < 64; i += 1) {
    const cand = canon.slice(0, 42) + ALPHABET[i] + '=';
    if (cand === canon) continue;
    if (Buffer.from(cand, 'base64').equals(raw)) variants.push(cand);
  }
  return { raw, canon, variants };
}

const KEYS = keySet();

function grantDoc(pubkey) {
  const expires = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return {
    version: 1,
    grants: {
      releases: {
        kind: 'message',
        issuer: 'auroraxo',
        type: 'release',
        subject: 'auroraxo/signerd',
        pubkey,
        maxBytes: '700',
        expiresAt: expires,
        windowMaxMessages: '5',
        windowSeconds: '3600',
      },
    },
  };
}

function writeGrants(dir, name, pubkey) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(grantDoc(pubkey), null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-pubkey-'));
}

test('fixture sanity: variants decode to the same bytes, re-encode differently', () => {
  assert.ok(SHAPE.test(KEYS.canon), 'canonical spelling must be well-formed');
  assert.ok(KEYS.variants.length > 0, 'need at least one non-canonical spelling');
  for (const v of KEYS.variants) {
    assert.ok(SHAPE.test(v), `variant ${v} must pass the shape regex`);
    assert.ok(Buffer.from(v, 'base64').equals(KEYS.raw), `variant ${v} must decode to the same key`);
    assert.notStrictEqual(Buffer.from(v, 'base64').toString('base64'), v,
      `variant ${v} must NOT re-encode to itself (that is what makes it non-canonical)`);
  }
});

test('D1 loader: a non-canonical pubkey spelling is refused at load, not run into at start', () => {
  const dir = tmpDir();
  for (const v of KEYS.variants) {
    const file = writeGrants(dir, `grants-${Buffer.from(v).toString('hex').slice(-8)}.json`, v);
    assert.throws(
      () => loadGrantFile(file),
      (err) => err.code === 'grant_field_invalid' && String(err.message).endsWith('pubkey'),
      `loader must refuse non-canonical spelling ${v} as grant_field_invalid: <name>.pubkey`,
    );
    fs.unlinkSync(file);
  }
  // G1: the canonical spelling still loads.
  const okFile = writeGrants(dir, 'grants-canonical.json', KEYS.canon);
  const loaded = loadGrantFile(okFile);
  assert.deepStrictEqual(loaded.names, ['releases'], 'canonical key must still load');
});

test('D2 creation path: buildMessageGrant refuses a non-canonical pubkey', () => {
  const expires = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  for (const v of KEYS.variants) {
    assert.throws(
      () => buildMessageGrant({
        name: 'releases', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
        pubkey: v, maxBytes: '700', expiresAt: expires,
        windowMaxMessages: '5', windowSeconds: '3600',
      }),
      (err) => err.code === 'grant_field_invalid',
      `creation path must refuse non-canonical spelling ${v}`,
    );
  }
  // G1: the canonical spelling is still creatable.
  const built = buildMessageGrant({
    name: 'releases', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: KEYS.canon, maxBytes: '700', expiresAt: expires,
    windowMaxMessages: '5', windowSeconds: '3600',
  });
  assert.strictEqual(built.pubkey, KEYS.canon);
});

test('D3 policy: evaluateMessage refuses a grant pinning a non-canonical spelling', () => {
  const expires = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const body = {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    claims: { messageGrant: 'live' },
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  for (const v of KEYS.variants) {
    const grant = grantDoc(v).grants.releases;
    const verdict = evaluateMessage(body, grant);
    assert.strictEqual(verdict.allowed, false, `policy must refuse spelling ${v}`);
    assert.strictEqual(verdict.refused, 'invalid_grant');
  }
  // G1: canonical spelling evaluates clean.
  const okGrant = grantDoc(KEYS.canon).grants.releases;
  const ok = evaluateMessage(body, okGrant);
  assert.strictEqual(ok.allowed, true, 'canonical pubkey must still evaluate');
});

test('D4 voice: `signerd run` on a non-canonical file names the repair', () => {
  const dir = tmpDir();
  const work = path.join(dir, 'work');
  // 0700 explicitly: the product refuses a passphrase file in a
  // group-writable directory (umask 002 default) — the fixture must not
  // manufacture the state the product later refuses.
  fs.mkdirSync(work, { mode: 0o700 });
  fs.chmodSync(work, 0o700);
  fs.chmodSync(dir, 0o700);
  const keystore = path.join(work, 'ops.key');
  const passphraseFile = path.join(work, 'pass');
  fs.writeFileSync(passphraseFile, 'pubkey test passphrase\n', { mode: 0o600 });

  const keygen = spawnSync(process.execPath, [
    BIN, 'keygen', '--keystore', keystore, '--passphrase-file', passphraseFile,
  ], { encoding: 'utf8' });
  if (keygen.status !== 0) {
    assert.fail(`keygen failed: ${keygen.stderr}`);
  }

  // Derive the keystore's OWN key (the case where the bytes are RIGHT and
  // only the spelling differs) and write its non-canonical spelling.
  const { readKeystorePublicKey } = require('../src/keystore');
  const bs58 = require('bs58');
  const canonFromStore = Buffer.from(bs58.decode(readKeystorePublicKey({ file: keystore }))).toString('base64');
  const rawStore = bs58.decode(readKeystorePublicKey({ file: keystore }));
  // Walk the last data char to a value that decodes to the same bytes but
  // re-encodes differently: the bytes are RIGHT, only the spelling differs.
  let variant = null;
  for (let i = 0; i < 64; i += 1) {
    const cand = canonFromStore.slice(0, 42) + ALPHABET[i] + '=';
    if (cand !== canonFromStore && Buffer.from(cand, 'base64').equals(Buffer.from(rawStore))) {
      variant = cand;
      break;
    }
  }
  assert.ok(variant, 'need a non-canonical spelling of the store key itself');

  const grantsFile = writeGrants(work, 'grants.json', variant);
  const ledger = path.join(work, 'journal.jsonl');
  const socket = path.join(work, 'signerd.sock');

  const run = spawnSync(process.execPath, [
    BIN, 'run', '--keystore', keystore, '--passphrase-file', passphraseFile,
    '--grants', grantsFile, '--ledger', ledger, '--socket', socket,
  ], { encoding: 'utf8', timeout: 20000 });

  assert.strictEqual(run.status, 1, 'the daemon must still refuse to start (fail-closed)');
  // POST-FIX CONTRACT: the loader now refuses the spelling at load time
  // (grant_field_invalid: <name>.pubkey with a fix line) — the daemon never
  // reaches its bare grant_key_mismatch for a spelling defect anymore.
  // PRE-FIX: exit 1 with a bare `grant_key_mismatch: releases`, 0 fix lines.
  const out = `${run.stdout}\n${run.stderr}`;
  assert.match(out, /grant_field_invalid: releases\.pubkey/,
    `refusal must name the pubkey field at load time, got: ${out}`);
  assert.match(out, /fix:/, `the refusal must name a repair, got: ${out}`);
  assert.match(out, /canonical/i,
    `the repair must name the encoding rule (CANONICAL base64), got: ${out}`);
  assert.ok(!fs.existsSync(socket), 'a refused daemon must leave no socket');
});

test('D5 bootstrap: `sign-message --add-grant` writes a pubkey that loads and starts (its own canonical spelling)', () => {
  const dir = tmpDir();
  const work = path.join(dir, 'work');
  fs.mkdirSync(work, { mode: 0o700 });
  fs.chmodSync(work, 0o700);
  fs.chmodSync(dir, 0o700);
  const keystore = path.join(work, 'ops.key');
  const passphraseFile = path.join(work, 'pass');
  fs.writeFileSync(passphraseFile, 'bootstrap passphrase\n', { mode: 0o600 });
  const keygen = spawnSync(process.execPath, [
    BIN, 'keygen', '--keystore', keystore, '--passphrase-file', passphraseFile,
  ], { encoding: 'utf8' });
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  const bodyFile = path.join(work, 'body.json');
  fs.writeFileSync(bodyFile, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', claims: { messageGrant: 'live' },
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  }, null, 2) + '\n');
  const grantsFile = path.join(work, 'grants.json');

  // The bootstrap writes the grant BEFORE the socket round trip, which will
  // fail here (no daemon) — that exit is expected; the file is the artifact.
  spawnSync(process.execPath, [
    BIN, 'sign-message', '--keystore', keystore, '--grants', grantsFile,
    '--add-grant', '--grant', 'releases', '--socket', path.join(work, 'none.sock'),
    '--body', bodyFile,
  ], { encoding: 'utf8', timeout: 15000 });

  assert.ok(fs.existsSync(grantsFile), 'bootstrap must have written the grant file');
  fs.chmodSync(grantsFile, 0o600);
  const doc = JSON.parse(fs.readFileSync(grantsFile, 'utf8'));
  const pinned = doc.grants.releases.pubkey;
  const { readKeystorePublicKey } = require('../src/keystore');
  const bs58 = require('bs58');
  const expected = Buffer.from(bs58.decode(readKeystorePublicKey({ file: keystore }))).toString('base64');
  assert.strictEqual(pinned, expected,
    'bootstrap must pin the keystore key in its exact canonical spelling');
  assert.ok(isCanonicalBase64PublicKey(pinned), 'the pinned spelling must re-encode to itself');
  // The written file must LOAD — the product's own judge.
  const loaded = loadGrantFile(grantsFile);
  assert.deepStrictEqual(loaded.names, ['releases'], 'the bootstrapped file must load');
});

test('G2 a genuinely different key is still refused as grant_key_mismatch (no over-tightening)', () => {
  const dir = tmpDir();
  const work = path.join(dir, 'work');
  fs.mkdirSync(work, { mode: 0o700 });
  fs.chmodSync(work, 0o700);
  fs.chmodSync(dir, 0o700);
  const keystore = path.join(work, 'ops.key');
  const passphraseFile = path.join(work, 'pass');
  fs.writeFileSync(passphraseFile, 'g2 passphrase\n', { mode: 0o600 });
  const keygen = spawnSync(process.execPath, [
    BIN, 'keygen', '--keystore', keystore, '--passphrase-file', passphraseFile,
  ], { encoding: 'utf8' });
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  // A DIFFERENT keypair's canonical spelling: same rules, wrong key.
  const otherSeed = Buffer.alloc(32); crypto.randomBytes(32).copy(otherSeed);
  const other = Keypair.fromSeed(otherSeed);
  const otherB64 = Buffer.from(other.publicKey.toBytes()).toString('base64');
  assert.ok(isCanonicalBase64PublicKey(otherB64), 'the other key must be canonical (rule not over-tight)');
  const grantsFile = writeGrants(work, 'grants.json', otherB64);

  const run = spawnSync(process.execPath, [
    BIN, 'run', '--keystore', keystore, '--passphrase-file', passphraseFile,
    '--grants', grantsFile, '--ledger', path.join(work, 'journal.jsonl'),
    '--socket', path.join(work, 'signerd.sock'),
  ], { encoding: 'utf8', timeout: 20000 });
  assert.strictEqual(run.status, 1, 'a genuinely different key must still refuse');
  assert.match(run.stderr, /grant_key_mismatch/, 'the real mismatch keeps its code');
  assert.match(run.stderr, /fix:/, 'the real mismatch also names a repair');
});
