'use strict';

// DRY IN THE USER-ZERO RUN — the falsification the card asks for:
// "dry als FALSIFIKATION im naechsten user-zero-Lauf (dry-allow -> echte
// Signatur)".
//
// WHY (measured 2026-11-06, this repo): test/dry-run-surface.test.js pins the
// --dry contract against the DAEMON's own fixtures. That does not answer the
// consumer question: the real openreceipts client (`receipt.py sign
// --via-signerd`) builds the receipt body ITSELF, and if a dry run of that
// exact body had leaked anything — a journal record, a replay identity, a
// window slot — the subsequent REAL sign of the identical body would be
// refused (`replay` or `window_cap`) or the journal would carry a duplicate.
// The claim under test is precisely "dry-allow -> echte Signatur": an allowed
// dry run must leave the machine exactly as it was, so the identical request
// still signs for real afterwards.
//
// THE FALSIFICATION:
//   F1 dry the EXACT body the client is about to sign -> {ok,dry,allowed},
//      no `signature`, journal byte-identical (0 records before AND after).
//   F2 receipt.py then signs the SAME body for real -> exit 0, verified by
//      BOTH verifiers against the pinned key. A dry run that had journaled
//      the message identity would refuse here with `replay`.
//   F3 the journal after the real sign holds EXACTLY ONE record — the dry run
//      added none (a dry that journals, then a real that appends = 2 records).
//   F4 a dry run of an OUT-OF-SCOPE body refuses with the SAME reason the
//      real path refuses (`subject`), so "dry allowed" is not "dry blind".
//   G1 guard: the real sign produced a signature (green on both trees).
//
// The same sequence runs live against the daily daemon in
// research/consumer-live-daily/run.sh (step 4a) and is recorded in
// research/consumer-live-<DAY>/report.json — this file pins the behaviour so
// the daily run cannot silently rot.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair } = require('@solana/web3.js');

const { Daemon } = require('../src/daemon');
const { importKeystore } = require('../src/keystore');
const { buildReceiptBody } = require('../src/client');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

const OPENRECEIPTS = process.env.SIGNERD_OPENRECEIPTS
  ? path.resolve(process.env.SIGNERD_OPENRECEIPTS)
  : path.resolve(__dirname, '..', '..', 'openreceipts');
const RECEIPT_PY = path.join(OPENRECEIPTS, 'receipt.py');
const VERIFY_MJS = path.join(OPENRECEIPTS, 'verify.mjs');
const HAVE_OPENRECEIPTS = fs.existsSync(RECEIPT_PY) && fs.existsSync(VERIFY_MJS);
const SKIP = !HAVE_OPENRECEIPTS && 'openreceipts checkout not present; dry consumer e2e skipped';

const PASSPHRASE = 'dry consumer falsification passphrase';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-dry-consumer-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Run the CLI ASYNC: the fixture daemon lives in THIS event loop. */
function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args]);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function receiptPy(argv, home) {
  return new Promise((resolve) => {
    const child = spawn('python3', [RECEIPT_PY, ...argv], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, OPENRECEIPTS_HOME: home },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

function runNode(args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

function journalBytes(file) {
  return fs.existsSync(file) ? fs.readFileSync(file).length : 0;
}

function journalRecords(file) {
  if (!fs.existsSync(file)) return 0;
  const text = fs.readFileSync(file, 'utf8').trim();
  return text === '' ? 0 : text.split('\n').length;
}

/** Write one raw frame and read the JSON response (the daemon's own shape). */
function rawFrame(socketPath, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socketPath);
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('timeout')); }, 10000);
    socket.on('connect', () => socket.write(JSON.stringify(payload) + '\n'));
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return;
      clearTimeout(timer);
      socket.end();
      try { resolve(JSON.parse(buffer.subarray(0, newline).toString('utf8'))); }
      catch (err) { reject(err); }
    });
    socket.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

async function fixture(t) {
  const dir = tmpDir();
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const keypair = Keypair.generate();
  const pubB64 = Buffer.from(require('bs58').decode(keypair.publicKey.toBase58()))
    .toString('base64');

  const keystore = path.join(dir, 'ops.key');
  const rawSecret = path.join(dir, 'ops.raw');
  fs.writeFileSync(rawSecret, Buffer.from(keypair.secretKey.subarray(0, 64)), { mode: 0o600 });
  importKeystore({ file: keystore, passphrase: PASSPHRASE, from: rawSecret });
  fs.unlinkSync(rawSecret);

  const grantFile = path.join(dir, 'grants.json');
  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');

  const grants = {
    version: 1,
    grants: {
      releases: {
        kind: 'message',
        issuer: 'auroraxo',
        type: 'release',
        subject: 'auroraxo/openreceipts',
        pubkey: pubB64,
        maxBytes: '700',
        expiresAt: futureIso(),
        windowMaxMessages: '5',
        windowSeconds: '3600',
      },
    },
  };
  fs.writeFileSync(grantFile, JSON.stringify(grants, null, 2), { mode: 0o600 });

  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile,
  });
  await daemon.start();
  t.after(async () => { await daemon.stop(); });
  return { dir, keypair, pubB64, keystore, grantFile, socketPath, ledgerFile, daemon };
}

/**
 * The body `receipt.py sign --claim k=v --note N --issued-at T` will send:
 * the same field set, the same values. Canonicalisation sorts the keys, so a
 * byte-identical canonical message only needs identical VALUES.
 */
function bodyFor({ issuedAt, claims, note }) {
  return buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/openreceipts',
    claims, note, issuedAt,
  });
}

test('F1+F2+F3 an ALLOWED dry run of the client body leaves the machine untouched: the identical body still signs for real', { skip: SKIP }, async (t) => {
  const f = await fixture(t);
  const issuedAt = new Date(Math.floor(Date.now() / 1000) + 3600).toISOString()
    .replace(/\.\d{3}Z$/, 'Z');
  const claims = { version: 'v1.0.0' };
  const note = 'receipt signed through the signerd daemon, no key in the client';

  const bodyPath = path.join(f.dir, 'body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(bodyFor({ issuedAt, claims, note })), { mode: 0o600 });

  const before = journalBytes(f.ledgerFile);

  // F1: dry the exact body BEFORE the real sign.
  const dryOutPath = path.join(f.dir, 'dry-receipt.json');
  const dry = await runCli([
    'sign-message', '--socket', f.socketPath, '--grant', 'releases',
    '--body', bodyPath, '--out', dryOutPath, '--dry',
  ]);
  assert.equal(dry.status, 0, `dry run failed: ${dry.stderr} ${dry.stdout}`);
  const dryOut = JSON.parse(dry.stdout.trim());
  assert.equal(dryOut.ok, true);
  assert.equal(dryOut.dry, true);
  assert.equal(dryOut.allowed, true);
  assert.equal(dryOut.signature, undefined, 'dry must not produce a signature');
  assert.equal(dryOut.budgetConsumed, false);
  assert.equal(fs.existsSync(dryOutPath), false,
    'a dry run must not write --out (the promised file would look like a receipt)');
  assert.equal(journalBytes(f.ledgerFile), before,
    'an allowed dry run must not touch the journal (bytes before == after)');
  assert.ok(typeof dryOut.messageSha256 === 'string' && dryOut.messageSha256.length === 64,
    'the dry run reports the message identity it previewed');

  // F2: the REAL client signs the identical body right afterwards.
  const home = path.join(f.dir, 'client-home'); // must never be created
  const outPath = path.join(f.dir, 'receipt.json');
  const sign = await receiptPy([
    'sign', '--issuer', 'auroraxo', '--type', 'release',
    '--subject', 'auroraxo/openreceipts', '--claim', 'version=v1.0.0',
    '--note', note, '--issued-at', issuedAt,
    '--via-signerd', f.socketPath, '--grant', 'releases', '--out', outPath,
  ], home);
  assert.equal(sign.code, 0,
    `real sign after an allowed dry must succeed (dry burned nothing): ` +
    `stderr=${sign.stderr} stdout=${sign.stdout}`);
  assert.equal(fs.existsSync(home), false, 'client must not create key material');
  assert.equal(fs.existsSync(outPath), true, 'the real sign must write the receipt');

  // F2 (verification): BOTH verifiers accept it.
  const pinned = path.join(f.dir, 'pinned.pub');
  fs.writeFileSync(pinned, `${f.pubB64}\n`, { mode: 0o600 });
  const verifyPy = await receiptPy(['verify', outPath, '--key', pinned]);
  assert.equal(verifyPy.code, 0, `receipt.py verify failed: ${verifyPy.stdout}${verifyPy.stderr}`);
  const verifyMjs = await runNode([VERIFY_MJS, '--key', pinned, outPath], OPENRECEIPTS);
  assert.equal(verifyMjs.code, 0, `verify.mjs failed: ${verifyMjs.stderr}`);

  // F3: exactly ONE record — the dry run appended nothing.
  assert.equal(journalRecords(f.ledgerFile), 1,
    'journal must hold exactly the real sign; a dry that also journaled = 2');
});

test('F4 an out-of-scope body refuses under --dry with the SAME reason the real path refuses', { skip: SKIP }, async (t) => {
  const f = await fixture(t);
  const bodyPath = path.join(f.dir, 'bad-body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/SOMEONE-ELSE', claims: {},
  })), { mode: 0o600 });

  const before = journalBytes(f.ledgerFile);
  const dry = await runCli([
    'sign-message', '--socket', f.socketPath, '--grant', 'releases',
    '--body', bodyPath, '--dry',
  ]);
  assert.equal(dry.status, 1, `dry of an out-of-scope body must exit non-zero: ${dry.stdout}`);
  const out = JSON.parse(dry.stdout.trim());
  assert.equal(out.ok, false);
  assert.equal(out.error, 'subject', 'dry refusals must be the real refusals, not a silent allow');
  assert.equal(journalBytes(f.ledgerFile), before, 'a refused dry run writes nothing');
});

test('F5 a non-boolean dry on the wire fails CLOSED with request_invalid — never a real signature', { skip: SKIP }, async (t) => {
  const f = await fixture(t);
  const body = JSON.stringify(buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/openreceipts', claims: {},
  }));
  const before = journalBytes(f.ledgerFile);
  for (const badValue of ['true', 'false', 1, 0, null, [], {}]) {
    const res = await rawFrame(f.socketPath,
      { grant: 'releases', body, dry: badValue });
    assert.equal(res.ok, false,
      `dry:${JSON.stringify(badValue)} must be refused, not silently real`);
    assert.equal(res.error, 'request_invalid',
      `dry:${JSON.stringify(badValue)} must fail closed with request_invalid`);
    assert.equal(res.signature, undefined, 'a mistyped dry must never sign');
  }
  assert.equal(journalBytes(f.ledgerFile), before,
    'a mistyped dry run must write nothing to the journal');
});

test('G1 guard: the dry path did not disable the real one (signature bytes exist)', { skip: SKIP }, async (t) => {
  const f = await fixture(t);
  const bodyPath = path.join(f.dir, 'body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(buildReceiptBody({
    issuer: 'auroraxo', type: 'release', subject: 'auroraxo/openreceipts', claims: {},
  })), { mode: 0o600 });
  const outPath = path.join(f.dir, 'receipt.json');
  const res = await runCli([
    'sign-message', '--socket', f.socketPath, '--grant', 'releases',
    '--body', bodyPath, '--out', outPath,
  ]);
  assert.equal(res.status, 0, `real sign failed: ${res.stderr} ${res.stdout}`);
  const out = JSON.parse(res.stdout.trim());
  assert.ok(typeof out.signature === 'string' && out.signature.length > 0);
  assert.ok(fs.existsSync(outPath), 'real sign writes --out');
  assert.ok(journalBytes(f.ledgerFile) > 0, 'real sign journals');
});
