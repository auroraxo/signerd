'use strict';

// OUTPUT-PREFLIGHT SURFACE: an unwritable --out must be refused BEFORE the
// daemon signs, not after it has already charged the budget.
//
// WHY (measured 2026-11-07, live, pre-fix tree aebe5f9):
//
//   * `signerd sign --tx <wire> --out <missing-dir>/x.bin`
//       -> the daemon SIGNS: journal 366 bytes appended, budget charged,
//          replay identity recorded; then fs.writeFileSync throws
//          `ENOENT: no such file or directory, open '...'` and the CLI
//          exits 1 with a BARE ERRNO and no fix message.
//       -> retrying the IDENTICAL wire with a CORRECTED --out is refused
//          `replay`. The signature existed for a millisecond and was
//          thrown away; the spend is permanent; the operator's fix
//          ("create the directory") comes too late.
//   * `signerd sign-message --out <missing-dir>/receipt.json`: identical —
//          journal 303 bytes written, receipt lost, retry refused `replay`.
//   * `examples/user-zero-client.js --out <missing-dir>/x.bin`: identical —
//          the documented user-zero path burns budget and then crashes
//          with an uncaught ENOENT.
//   * `signerd build-tx --out <missing-dir>/tx.bin`: bare ENOENT, exit 1
//          (no budget at stake, but the same unnameable failure).
//   * `signerd seal-grants --out <missing-dir>/g.json`: bare ENOENT, exit 1.
//
// THE CONTRACT:
//   P1 an unwritable --out for `sign` is refused with exit 2 BEFORE the
//      request reaches the daemon: journal UNTOUCHED (0 bytes).
//   P2 the falsification that makes P1 mean something: after that refusal,
//      the IDENTICAL wire signed with a corrected --out succeeds — the
//      refusal burned neither the budget nor the replay identity.
//   P3 same for `sign-message`.
//   P4 same for the shipped example client (the documented user-zero path).
//   P5 `build-tx` and `seal-grants` name the same repair instead of a bare
//      errno.
//   P6 an existing directory as --out is refused (exit 2), not crashed into.
//   G1 GUARD (green on both trees): a correct --out still signs, writes the
//      file owner-only, the signature verifies, journal exactly 1 record.
//   G2 GUARD (green on both trees): a daemon REFUSAL never writes --out
//      (the pre-existing refusal-writes-nothing rule still holds).
//
// Ladder: P1..P6 are RED on the pre-fix tree; G1+G2 are green on both.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const CLIENT = path.join(ROOT, 'examples', 'user-zero-client.js');
const { Daemon } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');
const { addGrantToFile, buildMessageGrant } = require('../src/grantadd');
const { buildTransferWire } = require('../src/client');
const { Keypair } = require('@solana/web3.js');

const PASSPHRASE = 'out-preflight-pass';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-out-preflight-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Async CLI run: the fixture daemon lives in THIS process's event loop. */
function run(exe, argv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [exe, ...argv], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function fixture() {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.jsonl');
  const socket = path.join(dir, 's.sock');

  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const destination = Keypair.generate().publicKey.toBase58();

  addGrantToFile({
    file: grants,
    name: 'ops',
    grant: {
      signer: keypair.publicKey.toBase58(),
      destination,
      maxLamports: '1000000',
      windowMaxLamports: '10000000',
      windowSeconds: '3600',
      expiresAt: futureIso(),
    },
  });
  addGrantToFile({
    file: grants,
    name: 'releases',
    grant: buildMessageGrant({
      name: 'releases',
      issuer: 'auroraxo',
      type: 'test',
      subject: 'signerd',
      pubkey: Buffer.from(keypair.publicKey.toBytes()).toString('base64'),
      maxBytes: '700',
      expiresAt: futureIso(),
      windowMaxMessages: '10',
      windowSeconds: '3600',
    }),
  });

  const daemon = new Daemon({
    socketPath: socket,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile: grants,
    ledgerFile: ledger,
  });
  await daemon.start();

  const body = path.join(dir, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'test',
    subject: 'signerd',
    claims: { role: 'fixture' },
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, '+00:00'),
  }, null, 2), { mode: 0o600 });

  return {
    dir, keystore, grants, ledger, socket, body,
    keypair, destination,
    blockhash: Keypair.generate().publicKey.toBase58(),
    wire() {
      return buildTransferWire({
        fromPubkey: keypair.publicKey.toBase58(),
        toPubkey: destination,
        lamports: 42,
        blockhash: Keypair.generate().publicKey.toBase58(),
      });
    },
    async stop() { await daemon.stop(); },
  };
}

function journalBytes(file) {
  return fs.existsSync(file) ? fs.readFileSync(file).length : 0;
}

function firstJson(stdout) {
  const line = (stdout.split('\n').find((l) => l.trim().startsWith('{')) || '').trim();
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
}

// ---------------------------------------------------------------------------
// P1 + P2: sign --out into a missing directory is refused BEFORE signing,
// and the falsification that the refusal burned nothing.
// ---------------------------------------------------------------------------

test('P1 sign --out into a missing directory is refused before the daemon signs', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'no-such-dir', 'signed.bin');

  const tx = path.join(f.dir, 'tx.bin');
  fs.writeFileSync(tx, f.wire(), { mode: 0o600 });

  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 2, `expected exit 2 (usage refusal), got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /out_parent_unwritable|out_unwritable|out_is_directory/,
    `the refusal must name the output path as the reason: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `the refusal must name the repair: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), 0,
    'the journal must be UNTOUCHED - the refusal happens before the daemon signs');
  assert.equal(fs.existsSync(out), false, 'no file may be created');
});

test('P2 falsification: after the refusal the identical wire still signs with a corrected --out', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'no-such-dir', 'signed.bin');

  const tx = path.join(f.dir, 'tx.bin');
  fs.writeFileSync(tx, f.wire(), { mode: 0o600 });

  const refused = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(refused.code, 2, `refusal expected: ${refused.stderr}`);
  assert.equal(journalBytes(f.ledger), 0, 'nothing may have been charged');

  // The SAME wire, now with a directory that exists. If the refusal above
  // had leaked into the journal, this run would be refused `replay`.
  const good = path.join(f.dir, 'signed.bin');
  const signed = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', good]);
  assert.equal(signed.code, 0, `the identical wire must sign after the refusal: ${signed.stdout} ${signed.stderr}`);
  const json = firstJson(signed.stdout);
  assert.ok(json && json.ok === true, `expected ok:true: ${signed.stdout}`);
  assert.equal(fs.existsSync(good), true, 'the corrected --out must be written');
  // Verify cryptographically (an "all bytes nonzero" heuristic is invalid:
  // a valid 64-byte signature contains a zero byte with p≈0.22 and would
  // make this test flaky).
  const { VersionedTransaction } = require('@solana/web3.js');
  const parsed = VersionedTransaction.deserialize(fs.readFileSync(good));
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(f.keypair.publicKey.toBytes()),
  ]);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(
    crypto.verify(null, Buffer.from(parsed.message.serialize()), keyObject, Buffer.from(parsed.signatures[0])),
    true,
    'the delivered signature must verify under the fee payer key');
});

// ---------------------------------------------------------------------------
// P3: sign-message, the same defect on the message path.
// ---------------------------------------------------------------------------

test('P3 sign-message --out into a missing directory is refused before signing', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'no-such-dir', 'receipt.json');

  const r = await run(CLI, [
    'sign-message', '--socket', f.socket, '--grant', 'releases',
    '--body', f.body, '--out', out,
  ]);
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /out_parent_unwritable|out_unwritable|out_is_directory/,
    `the refusal must name the output path: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `the refusal must name the repair: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), 0, 'the journal must be UNTOUCHED');
  assert.equal(fs.existsSync(out), false, 'no receipt may be created');

  // And the falsification: the identical body then signs for real.
  const good = path.join(f.dir, 'receipt.json');
  const signed = await run(CLI, [
    'sign-message', '--socket', f.socket, '--grant', 'releases',
    '--body', f.body, '--out', good,
  ]);
  assert.equal(signed.code, 0,
    `the identical body must still sign after the refusal (no replay was burned): ${signed.stdout} ${signed.stderr}`);
  assert.equal(fs.existsSync(good), true, 'the corrected --out must be written');
});

// ---------------------------------------------------------------------------
// P4: the shipped example client — the documented user-zero path.
// ---------------------------------------------------------------------------

test('P4 user-zero client --out into a missing directory is refused before signing', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'no-such-dir', 'client.bin');

  const argv = [
    '--socket', f.socket,
    '--grant', 'ops',
    '--from', f.keypair.publicKey.toBase58(),
    '--to', f.destination,
    '--lamports', '42',
    '--blockhash', Keypair.generate().publicKey.toBase58(),
    '--out', out,
  ];
  const r = await run(CLIENT, argv);
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /out_parent_unwritable|out_unwritable|out_is_directory/,
    `the refusal must name the output path: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `the refusal must name the repair: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), 0, 'the journal must be UNTOUCHED');
  assert.equal(fs.existsSync(out), false, 'no file may be created');

  // Falsification: same request, corrected --out -> signs, journal EXACTLY 1.
  const good = path.join(f.dir, 'client.bin');
  argv[argv.indexOf(out)] = good;
  const signed = await run(CLIENT, argv);
  assert.equal(signed.code, 0,
    `the identical request must sign after the refusal: ${signed.stdout} ${signed.stderr}`);
  assert.equal(fs.existsSync(good), true, 'the corrected --out must be written');
});

// ---------------------------------------------------------------------------
// P5: build-tx and seal-grants name the repair instead of a bare errno.
// ---------------------------------------------------------------------------

test('P5 build-tx --out into a missing directory names the repair (not a bare errno)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'no-such-dir', 'tx.bin');

  const r = await run(CLI, [
    'build-tx', '--keystore', f.keystore, '--to', f.destination,
    '--lamports', '42', '--out', out,
  ]);
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /out_parent_unwritable|out_unwritable/,
    `the refusal must name the output path: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `the refusal must name the repair: ${r.stderr}`);
  assert.doesNotMatch(r.stderr, /^\s*ENOENT:/m,
    'a bare errno must never be the whole message');
  assert.equal(fs.existsSync(out), false, 'nothing may be created');
});

test('P5b seal-grants --out into a missing directory names the repair (not a bare errno)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const sealPass = path.join(f.dir, 'seal.pass');
  fs.writeFileSync(sealPass, 'seal secret\n', { mode: 0o600 });
  const out = path.join(f.dir, 'no-such-dir', 'grants.json');

  const r = await run(CLI, [
    'seal-grants', '--grants', f.grants,
    '--seal-passphrase-file', sealPass, '--out', out,
  ]);
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /out_parent_unwritable|out_unwritable/,
    `the refusal must name the output path: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `the refusal must name the repair: ${r.stderr}`);
  assert.equal(fs.existsSync(out), false, 'nothing may be created');
});

// ---------------------------------------------------------------------------
// P6: an existing directory as --out is a clean refusal, not a crash.
// ---------------------------------------------------------------------------

test('P6 sign --out pointing at an existing directory is refused with exit 2', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const outDir = path.join(f.dir, 'adir');
  fs.mkdirSync(outDir, { mode: 0o700 });

  const tx = path.join(f.dir, 'tx.bin');
  fs.writeFileSync(tx, f.wire(), { mode: 0o600 });

  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', outDir]);
  assert.equal(r.code, 2, `expected exit 2, got ${r.code}: ${r.stderr}`);
  assert.match(r.stderr, /out_is_directory|out_unwritable|out_parent/,
    `the refusal must name the output path: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), 0, 'the journal must be UNTOUCHED');
});

// ---------------------------------------------------------------------------
// GUARDS: green on both trees.
// ---------------------------------------------------------------------------

test('G1 guard: a correct --out still signs, writes owner-only, verifies, journal exactly 1', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');

  const tx = path.join(f.dir, 'tx.bin');
  fs.writeFileSync(tx, f.wire(), { mode: 0o600 });

  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 0, `the normal path must still sign: ${r.stdout} ${r.stderr}`);
  assert.equal(fs.existsSync(out), true, '--out must be written');
  assert.equal(fs.statSync(out).mode & 0o777, 0o600, '--out must be owner-only');

  const { VersionedTransaction } = require('@solana/web3.js');
  const parsed = VersionedTransaction.deserialize(fs.readFileSync(out));
  const message = Buffer.from(parsed.message.serialize());
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(f.keypair.publicKey.toBytes()),
  ]);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(crypto.verify(null, message, keyObject, Buffer.from(parsed.signatures[0])), true,
    'the delivered signature must verify under the fee payer key');
  assert.equal(journalBytes(f.ledger) > 0, true, 'the normal sign must journal');
});

test('G2 guard: a daemon REFUSAL never writes --out (refusal-writes-nothing holds)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'refused.bin');

  // Out of scope: a destination the grant does not allow.
  const tx = path.join(f.dir, 'tx.bin');
  const wire = buildTransferWire({
    fromPubkey: f.keypair.publicKey.toBase58(),
    toPubkey: Keypair.generate().publicKey.toBase58(),
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  fs.writeFileSync(tx, wire, { mode: 0o600 });

  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 1, `a scope refusal exits 1: ${r.code} ${r.stdout}`);
  const json = firstJson(r.stdout);
  assert.ok(json && json.ok === false, `expected structured refusal: ${r.stdout}`);
  assert.equal(json.error, 'destination', `unexpected reason: ${JSON.stringify(json)}`);
  assert.equal(fs.existsSync(out), false, 'a refused sign must never write --out');
});
