'use strict';

// OUTPUT DELIVERY: a signature must never be destroyed by the write.
//
// WHY (measured live 2026-11-07, tree b58d378 — the tree that shipped the
// --out PREFLIGHT in v0.2.6):
//
// The preflight asks whether `--out` looks writable BEFORE the socket round
// trip. It answers for the PATH IT WAS GIVEN. Three cases where that is not
// the path the write hits, measured on a live daemon:
//
//   * `--out <symlink to missing dir>/x.bin` -> preflight `{ok:true}` (it
//     lstat's nothing, `existsSync` follows the dangling link and says
//     "absent", so the target branch never runs) -> daemon SIGNS (journal
//     +366 bytes, budget charged, replay identity recorded) -> writeFileSync
//     follows the link -> `ENOENT`, exit 1, stdout EMPTY -> retry refused
//     `replay`. The signature existed for a millisecond and is gone.
//   * `--out <symlink to /dev/full>` -> preflight `{ok:true}` (char device,
//     mode 666, W_OK passes; only `isDirectory()` is checked) -> SIGNS ->
//     `ENOSPC`, exit 1, stdout EMPTY, budget gone.
//   * `--out <FIFO>` -> preflight `{ok:true}` (stat().isFile() is false but
//     only isDirectory() is consulted) -> SIGNS -> `open(O_WRONLY)` on a FIFO
//     with no reader BLOCKS FOREVER. The daemon has already been paid.
//
// And the residual the card itself names — "writeFileSync-Fehler moeglich" —
// reached without any symlink, by RLIMIT_FSIZE=0:
//
//   * `sign --out <regular file>` under `ulimit -f 0` -> preflight passes
//     (the path really is writable by permission) -> SIGNS -> writeFileSync
//     throws `EFBIG`, exit 1, stdout EMPTY, retry refused `replay`.
//     Measured: journal 0 -> 366.
//
// THE DESTRUCTIVE HALF of the same bug: writeFileSync opens with O_TRUNC, so
// a FAILED write still destroys what was there. Measured: a 200-byte
// pre-existing `--out` becomes 0 bytes when the write then throws EFBIG.
//
// THE CONTRACT this file pins (test-first: all P cases RED on b58d378):
//
//   P7  a dangling-symlink --out is refused EXIT 2 BEFORE the daemon signs
//       (journal 0 bytes, no budget, no replay) and names the repair.
//   P8  a FIFO --out is refused EXIT 2 BEFORE the daemon signs — the daemon
//       must never be paid for a write that would block forever.
//   P9  a non-regular target behind a symlink (/dev/full) is refused as
//       `out_not_regular_file`, not for an unrelated reason — the reason a
//       refusal gives is part of the product.
//   P10 THE SIGNATURE IS NEVER LOST. A write failure AFTER the daemon signed
//       must exit 3 — a code that means "the work happened, the file did not"
//       — with the FULL response on stdout, including the signed wire, so the
//       operator can recover the artifact they already paid for. A signature
//       that verifies is the falsification: the bytes must be real.
//   P11 a failed write must NOT destroy a pre-existing --out file: the bytes
//       are byte-identical afterwards (atomic temp+rename, never O_TRUNC).
//   P12 sign-message, same shape: the receipt document survives on stdout.
//
//   G3 GUARD (green on both trees): a correct --out still signs, writes
//      0600, verifies, exit 0, and the success stdout does NOT carry the
//      raw `signed` field (the file does) — delivery failure must not leak
//      into the success contract.
//   G4 GUARD: a pre-existing --out file IS replaced on a successful sign
//      (atomic write must not turn into "never overwrite").
//   G5 GUARD: a daemon refusal still exits 1 and writes nothing.
//
// Ladder: P7..P12 are RED on b58d378; G3..G5 are green on both.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const CLIENT = path.join(ROOT, 'examples', 'user-zero-client.js');
const { Daemon } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');
const { addGrantToFile, buildMessageGrant } = require('../src/grantadd');
const { buildTransferWire } = require('../src/client');
const { Keypair } = require('@solana/web3.js');

const PASSPHRASE = 'out-delivery-pass';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-out-delivery-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Run the CLI (or the example client). `limitFile` wraps the invocation in
 * `ulimit -f 0`, which makes ANY write to a regular file fail with EFBIG —
 * a deterministic, rootless, network-free way to reach "the daemon has
 * signed and the write then fails".
 *
 * Always bounded: on the pre-fix tree P8 BLOCKS in open() on the FIFO, and a
 * hang must surface as a failing assertion, not a stuck suite.
 */
function run(exe, argv, { limitFile = false, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const quoted = [process.execPath, exe, ...argv]
      .map((a) => `"${String(a).replace(/"/g, '\\"')}"`).join(' ');
    const command = limitFile ? `ulimit -f 0; exec ${quoted}` : `exec ${quoted}`;
    const child = spawn('bash', ['-c', command], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, timedOut, stdout, stderr });
    });
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

  let n = 0;
  return {
    dir, keystore, grants, ledger, socket, body,
    keypair, destination,
    /** A fresh wire per call: identical wires are one message (replay). */
    wire() {
      n += 1;
      return buildTransferWire({
        fromPubkey: keypair.publicKey.toBase58(),
        toPubkey: destination,
        lamports: 42,
        blockhash: Keypair.generate().publicKey.toBase58(),
      });
    },
    writeTx() {
      const tx = path.join(dir, `tx-${n + 1}.bin`);
      fs.writeFileSync(tx, this.wire(), { mode: 0o600 });
      return tx;
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

/** Verify a serialized signed wire under the fee-payer key (not a heuristic). */
function wireVerifies(bytes, keypair) {
  const { VersionedTransaction } = require('@solana/web3.js');
  const parsed = VersionedTransaction.deserialize(bytes);
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(keypair.publicKey.toBytes()),
  ]);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return crypto.verify(
    null,
    Buffer.from(parsed.message.serialize()),
    keyObject,
    Buffer.from(parsed.signatures[0]),
  );
}

function mkfifo(p) {
  const r = spawnSync('mkfifo', ['-m', '600', p], { encoding: 'utf8' });
  if (r.error || r.status !== 0) return false;
  return true;
}

// ---------------------------------------------------------------------------
// P7: a dangling symlink as --out must be refused before the daemon signs.
// ---------------------------------------------------------------------------

test('P7 dangling-symlink --out refused before signing (journal untouched)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const link = path.join(f.dir, 'out-link');
  fs.symlinkSync(path.join(f.dir, 'no-such-dir', 'x.bin'), link);

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', link]);

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(r.code, 2, `refusal must exit 2, got ${r.code}: ${r.stderr} ${r.stdout}`);
  assert.match(r.stderr, /out_/, `refusal must name the output path: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `refusal must name the repair: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), before,
    'the journal must be UNTOUCHED: the refusal happens before the daemon signs');
  assert.equal(fs.existsSync(link), false, 'the dangling link must not become a file');

  // Falsification: the identical wire still signs with a corrected --out.
  const good = path.join(f.dir, 'signed-p7.bin');
  const signed = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', good]);
  assert.equal(signed.code, 0,
    `the identical wire must sign after the refusal: ${signed.stdout} ${signed.stderr}`);
  assert.equal(journalBytes(f.ledger) > before, true, 'the corrected run journals exactly one spend');
  assert.equal(wireVerifies(fs.readFileSync(good), f.keypair), true,
    'the delivered signature must verify');
});

// ---------------------------------------------------------------------------
// P8: a FIFO as --out must be refused before the daemon signs. On the
// pre-fix tree this HANGS after signing (open blocks); the runner's timeout
// turns that into a failing assertion.
// ---------------------------------------------------------------------------

test('P8 FIFO --out refused before signing instead of blocking the daemon', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const fifo = path.join(f.dir, 'out.fifo');
  if (!mkfifo(fifo)) return; // no mkfifo: the fixture cannot build the case

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', fifo]);

  assert.equal(r.timedOut, false,
    'a FIFO --out must not block: the CLI must be refused, not parked in open()');
  assert.equal(r.code, 2, `refusal must exit 2, got ${r.code}: ${r.stderr} ${r.stdout}`);
  assert.match(r.stderr, /out_/, `refusal must name the output path: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), before,
    'the daemon must never be paid for a write that would block forever');
});

// ---------------------------------------------------------------------------
// P9: a non-regular target behind a symlink. The REASON must be the reason —
// "/dev/full is not a regular file", not an incidental permission complaint
// about /dev.
// ---------------------------------------------------------------------------

test('P9 symlink -> char device refused as out_not_regular_file', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  if (!fs.existsSync('/dev/full')) return; // no /dev/full: no case
  const link = path.join(f.dir, 'to-full');
  fs.symlinkSync('/dev/full', link);

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', link]);

  assert.equal(r.code, 2, `refusal must exit 2, got ${r.code}: ${r.stderr} ${r.stdout}`);
  assert.match(r.stderr, /out_not_regular_file/,
    `the refusal must name THIS reason — an incidental /dev complaint hides the defect: ${r.stderr}`);
  assert.match(r.stderr, /fix:/, `refusal must name the repair: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), before, 'the journal must be UNTOUCHED');
});

// ---------------------------------------------------------------------------
// P10: THE SIGNATURE IS NEVER LOST. The write fails AFTER the daemon signed.
// exit 3 = "the work happened, the file did not". The full response — with
// the signed wire — must be on stdout, and those bytes must VERIFY. That is
// the falsification: not "some JSON", but a signature the operator can use.
// ---------------------------------------------------------------------------

test('P10 a post-signing write failure delivers the signature on stdout (exit 3)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  const tx = f.writeTx();

  const before = journalBytes(f.ledger);
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { limitFile: true });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(r.code, 3,
    `delivery failure after signing must exit 3 (signed, not written), got ${r.code}: ${r.stderr}`);

  const json = firstJson(r.stdout);
  assert.ok(json, `stdout must carry the response JSON so the signature is not lost: ${r.stdout}`);
  assert.equal(json.ok, true, `the daemon DID sign — ok must be true: ${r.stdout}`);
  assert.ok(typeof json.signed === 'string' && json.signed.length > 0,
    'stdout must carry the signed wire itself (the artifact the operator paid for)');
  assert.ok(json.outError, `stdout must carry outError naming the failed delivery: ${r.stdout}`);
  assert.ok(/fix:/.test(r.stderr), `stderr must name the repair: ${r.stderr}`);

  // FALSIFICATION: the recovered bytes are a real, usable signature.
  const recovered = Buffer.from(json.signed, 'base64');
  assert.equal(wireVerifies(recovered, f.keypair), true,
    'the recovered signature must verify — an empty or bogus body is not recovery');

  // And the spend is visible, not hidden: the budget WAS consumed.
  assert.equal(journalBytes(f.ledger) > before, true,
    'the journal must record the spend that already happened (honesty, not a cover-up)');
});

// ---------------------------------------------------------------------------
// P11: a failed write must not destroy what was already at --out. The
// pre-fix behaviour opens with O_TRUNC, so the failed write zeroes the file.
// ---------------------------------------------------------------------------

test('P11 a failed write leaves a pre-existing --out file byte-identical', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'existing.bin');
  const prior = Buffer.from('IMPORTANT PRIOR CONTENT '.repeat(8));
  fs.writeFileSync(out, prior, { mode: 0o600 });

  const tx = f.writeTx();
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { limitFile: true });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(r.code, 3, `delivery failure must exit 3, got ${r.code}: ${r.stderr}`);
  assert.equal(fs.existsSync(out), true, 'the pre-existing file must still exist');
  const after = fs.readFileSync(out);
  assert.equal(Buffer.compare(prior, after), 0,
    `a FAILED write must not destroy the previous content (was ${prior.length} bytes, now ${after.length})`);
  assert.equal(fs.statSync(out).mode & 0o777, 0o600, 'the surviving file keeps its owner-only mode');
});

// ---------------------------------------------------------------------------
// P12: sign-message — the receipt document is the same class of artifact.
// ---------------------------------------------------------------------------

test('P12 sign-message write failure puts the receipt document on stdout (exit 3)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'receipt.json');
  const before = journalBytes(f.ledger);

  const r = await run(CLI, [
    'sign-message', '--socket', f.socket, '--grant', 'releases',
    '--body', f.body, '--out', out,
  ], { limitFile: true });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(r.code, 3, `delivery failure must exit 3, got ${r.code}: ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json, `stdout must carry the response: ${r.stdout}`);
  assert.equal(json.ok, true, `the daemon DID sign: ${r.stdout}`);
  assert.ok(json.receiptDoc, 'stdout must carry the receipt document so it is not lost');
  assert.equal(typeof json.signature, 'string', 'the signature must stay on stdout');
  assert.equal(journalBytes(f.ledger) > before, true, 'the spent message grant is recorded');
});

// ---------------------------------------------------------------------------
// P13: the shipped example client — the documented user-zero path.
// ---------------------------------------------------------------------------

test('P13 user-zero client write failure keeps the signature on stdout (exit 3)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'client.bin');
  const before = journalBytes(f.ledger);

  const argv = [
    '--socket', f.socket, '--grant', 'ops',
    '--from', f.keypair.publicKey.toBase58(),
    '--to', f.destination,
    '--lamports', '42',
    '--blockhash', Keypair.generate().publicKey.toBase58(),
    '--out', out,
  ];
  const r = await run(CLIENT, argv, { limitFile: true });

  assert.equal(r.timedOut, false, 'the example must not hang');
  assert.equal(r.code, 3, `delivery failure must exit 3, got ${r.code}: ${r.stdout} ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json, `stdout must carry the response: ${r.stdout}`);
  assert.equal(json.ok, true, `the daemon DID sign: ${r.stdout}`);
  assert.ok(typeof json.signed === 'string' && json.signed.length > 0,
    'the signed wire must survive on stdout (the example is the documented user-zero path)');
  assert.ok(json.outError, 'stdout must carry outError');
  assert.equal(journalBytes(f.ledger) > before, true, 'the spend is recorded');
});

// ---------------------------------------------------------------------------
// P7b: a symlink to a VALID regular file is accepted and written THROUGH.
// The link is not the defect — the dangling link and the non-regular target
// are. A tool that resolves the link must not then REPLACE it with a
// regular file (that would break the operator's own layout), and it must
// not refuse it either.
// ---------------------------------------------------------------------------

test('P7b a symlink to a valid file is written through, not replaced', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const real = path.join(f.dir, 'real.bin');
  const link = path.join(f.dir, 'link.bin');
  fs.writeFileSync(real, Buffer.alloc(0), { mode: 0o600 });
  fs.symlinkSync(real, link);

  const tx = f.writeTx();
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', link]);
  assert.equal(r.code, 0, `a symlink to a valid file must be accepted: ${r.stdout} ${r.stderr}`);
  assert.equal(fs.lstatSync(link).isSymbolicLink(), true,
    'the link must still be a link — the delivery must not replace it');
  assert.equal(wireVerifies(fs.readFileSync(real), f.keypair), true,
    'the bytes must land in the file the link points at');
  assert.equal(fs.statSync(real).mode & 0o777, 0o600, 'and land owner-only');
});

// ---------------------------------------------------------------------------
// P7c: the example client refuses a dangling --out before it asks the
// daemon to sign (the user-zero path has the same preflight as the CLI).
// ---------------------------------------------------------------------------

test('P7c user-zero client refuses a dangling --out before signing', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const link = path.join(f.dir, 'client-link');
  fs.symlinkSync(path.join(f.dir, 'no-such-dir', 'x.bin'), link);

  const argv = [
    '--socket', f.socket, '--grant', 'ops',
    '--from', f.keypair.publicKey.toBase58(),
    '--to', f.destination,
    '--lamports', '42',
    '--blockhash', Keypair.generate().publicKey.toBase58(),
    '--out', link,
  ];
  const r = await run(CLIENT, argv);
  assert.equal(r.code, 2, `refusal must exit 2, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /out_/, `refusal must name the output path: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), 0, 'the journal must be UNTOUCHED');
});

// ---------------------------------------------------------------------------
// P7d: sign-message refuses a dangling --out before signing.
// ---------------------------------------------------------------------------

test('P7d sign-message refuses a dangling --out before signing', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const link = path.join(f.dir, 'receipt-link');
  fs.symlinkSync(path.join(f.dir, 'no-such-dir', 'receipt.json'), link);

  const r = await run(CLI, [
    'sign-message', '--socket', f.socket, '--grant', 'releases',
    '--body', f.body, '--out', link,
  ]);
  assert.equal(r.code, 2, `refusal must exit 2, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /out_/, `refusal must name the output path: ${r.stderr}`);
  assert.equal(journalBytes(f.ledger), 0, 'the journal must be UNTOUCHED');
});

// ---------------------------------------------------------------------------
// GUARDS: green on both trees.
// ---------------------------------------------------------------------------

test('G3 guard: a correct --out still signs, writes 0600, verifies, exit 0', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  const tx = f.writeTx();

  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 0, `the normal path must still sign: ${r.stdout} ${r.stderr}`);
  assert.equal(fs.existsSync(out), true, '--out must be written');
  assert.equal(fs.statSync(out).mode & 0o777, 0o600, '--out must be owner-only');
  assert.equal(wireVerifies(fs.readFileSync(out), f.keypair), true,
    'the delivered signature must verify');

  const json = firstJson(r.stdout);
  assert.ok(json && json.ok === true, `expected ok:true: ${r.stdout}`);
  assert.equal(json.signed, undefined,
    'on SUCCESS the raw wire stays out of stdout — the file is the delivery channel');
  assert.equal(json.outError, undefined, 'on SUCCESS there is no delivery error');
  assert.equal(r.code === 3, false, 'a successful sign must never take the delivery-failure path');
});

test('G4 guard: a successful sign replaces a pre-existing --out file', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'existing.bin');
  fs.writeFileSync(out, Buffer.from('STALE CONTENT THAT MUST GO'), { mode: 0o644 });

  const tx = f.writeTx();
  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 0, `the normal path must still sign: ${r.stdout} ${r.stderr}`);
  assert.notEqual(Buffer.compare(Buffer.from('STALE CONTENT THAT MUST GO'), fs.readFileSync(out)), 0,
    'a successful sign must replace the old content');
  assert.equal(wireVerifies(fs.readFileSync(out), f.keypair), true, 'the new content must verify');
  assert.equal(fs.statSync(out).mode & 0o777, 0o600, 'and land owner-only');
});

test('G5 guard: a daemon refusal still exits 1 and writes nothing', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'refused.bin');

  const wire = buildTransferWire({
    fromPubkey: f.keypair.publicKey.toBase58(),
    toPubkey: Keypair.generate().publicKey.toBase58(), // not the grant's destination
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  const tx = path.join(f.dir, 'tx-refused.bin');
  fs.writeFileSync(tx, wire, { mode: 0o600 });

  const r = await run(CLI, ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 1, `a scope refusal exits 1: ${r.code} ${r.stdout}`);
  const json = firstJson(r.stdout);
  assert.ok(json && json.ok === false, `expected structured refusal: ${r.stdout}`);
  assert.equal(json.error, 'destination', `unexpected reason: ${JSON.stringify(json)}`);
  assert.equal(fs.existsSync(out), false, 'a refused sign must never write --out');
  assert.equal(r.code === 3, false, 'a refusal is not a delivery failure');
});
