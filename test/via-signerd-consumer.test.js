'use strict';

// Consumer end-to-end: the REAL openreceipts receipt.py signs through the
// daemon's Unix socket. This is the client half of the 30-day test plan on
// the signerd card — what is pinned here is NOT the daemon's policy (that is
// test/message-e2e.test.js) but the CLIENT's behaviour:
//
//   1. no key material in the client: OPENRECEIPTS_HOME is never even
//      created — the process sends public values only and reads a signature;
//   2. the client VERIFIES the signature it got back BEFORE writing a file
//      (a lying daemon cannot produce a receipt);
//   3. a pinned local public key must match the daemon's key;
//   4. refusals (window cap, replay, scope mismatch, unreachable socket)
//      exit non-zero and write NOTHING;
//   5. a daemon restart between two signs does not lose budget, journal or
//      replay protection.
//
// Skips (never passes vacuously) when the openreceipts checkout is absent.

process.umask(0o077);

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair } = require('@solana/web3.js');

const { Daemon } = require('../src/daemon');
const { importKeystore } = require('../src/keystore');

// The openreceipts checkout is a SIBLING repo (~/github_repos/openreceipts in
// the dev layout, a clone next to the workspace in CI). The path can be
// overridden so CI does not depend on a directory layout that only exists on
// one machine.
const OPENRECEIPTS = process.env.SIGNERD_OPENRECEIPTS
  ? path.resolve(process.env.SIGNERD_OPENRECEIPTS)
  : path.resolve(__dirname, '..', '..', 'openreceipts');
const RECEIPT_PY = path.join(OPENRECEIPTS, 'receipt.py');
const VERIFY_MJS = path.join(OPENRECEIPTS, 'verify.mjs');
const PASSPHRASE = 'a passphrase for the via-signerd e2e only';
const HAVE_OPENRECEIPTS = fs.existsSync(RECEIPT_PY);
const HAVE_VERIFY_MJS = fs.existsSync(VERIFY_MJS);
const SKIP = !HAVE_OPENRECEIPTS && 'openreceipts checkout not present; consumer e2e skipped';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-via-'));
}

function futureIso(hours = 1) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

/** The raw Ed25519 public key as base64, via OpenSSL (not the product code). */
function publicKeyB64(keypair) {
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    keypair.publicKey.toBytes(),
  ]);
  const jwk = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })
    .export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

function fixture(t) {
  const dir = tmpDir();
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  const keypair = Keypair.generate();
  const pubB64 = publicKeyB64(keypair);

  const keystore = path.join(dir, 'ops.key');
  const rawSecret = path.join(dir, 'ops.raw');
  fs.writeFileSync(rawSecret, Buffer.from(keypair.secretKey.subarray(0, 64)), { mode: 0o600 });
  importKeystore({ file: keystore, passphrase: PASSPHRASE, from: rawSecret });

  const grantFile = path.join(dir, 'grants.json');
  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const pubFile = path.join(dir, 'issuer.pub');
  fs.writeFileSync(pubFile, pubB64 + '\n', { mode: 0o600 });

  const writeGrants = (grants) => {
    fs.writeFileSync(grantFile, JSON.stringify({ version: 1, grants }, null, 2), { mode: 0o600 });
  };
  const messageGrant = (overrides = {}) => ({
    kind: 'message',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/openreceipts',
    pubkey: pubB64,
    maxBytes: '700',
    expiresAt: futureIso(),
    windowMaxMessages: '5',
    windowSeconds: '3600',
    ...overrides,
  });
  return { dir, keypair, pubB64, keystore, pubFile, grantFile, socketPath, ledgerFile, writeGrants, messageGrant };
}

async function startDaemon(f, grants) {
  f.writeGrants(grants);
  const daemon = new Daemon({
    socketPath: f.socketPath,
    keystorePath: f.keystore,
    passphrase: PASSPHRASE,
    grantFile: f.grantFile,
    ledgerFile: f.ledgerFile,
  });
  await daemon.start();
  return daemon;
}

/**
 * Run the real receipt.py as a client process.
 *
 * `home` is the client's OPENRECEIPTS_HOME — the assertion target for "no key
 * material in the client": if the client ever loaded or created a key, it
 * would show up here.
 */
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

/** The sign invocation a real user would run, via the daemon socket. */
function signArgs({ out, claim = 'version=v1.0.0', type = 'release',
  subject = 'auroraxo/openreceipts', issuedAt, grant = 'releases', socket } = {}) {
  const argv = ['sign', '--issuer', 'auroraxo', '--type', type, '--subject', subject,
    '--claim', claim, '--via-signerd', socket, '--grant', grant, '--out', out];
  if (issuedAt !== undefined) argv.push('--issued-at', issuedAt);
  return argv;
}

function verifyPy(file, keyFile) {
  return new Promise((resolve) => {
    const args = [RECEIPT_PY, 'verify', file];
    if (keyFile) args.push('--key', keyFile);
    const child = spawn('python3', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { out += c; });
    child.on('exit', (code) => resolve({ code, out }));
  });
}

function verifyMjs(file, keyFile) {
  return new Promise((resolve) => {
    const args = [VERIFY_MJS];
    if (keyFile) args.push('--key', keyFile);
    args.push(file);
    const child = spawn(process.execPath, args, { cwd: OPENRECEIPTS, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { out += c; });
    child.on('exit', (code) => resolve({ code, out }));
  });
}

/** A daemon that answers exactly what it is told to answer — the lying server. */
function fakeSignerd(t, socketPath, response) {
  const server = net.createServer((socket) => {
    let buf = '';
    socket.on('data', (chunk) => {
      buf += chunk;
      if (!buf.includes('\n')) return;
      socket.end(JSON.stringify(response) + '\n');
    });
    socket.on('error', () => { /* client hung up */ });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.on('error', () => { /* closed below */ });
      t.after(() => new Promise((done) => { try { fs.unlinkSync(socketPath); } catch { /* gone */ } server.close(() => done()); }));
      resolve(server);
    });
  });
}

test('consumer e2e: receipt.py signs through the daemon with no key material in the client', { skip: SKIP }, async (t) => {
  const f = fixture(t);
  const daemon = await startDaemon(f, { releases: f.messageGrant() });
  t.after(() => daemon.stop());

  // The client home does not exist. A client that touches a key file would
  // CREATE it (ensure_key makes the directory) — after the run it must still
  // not exist.
  const home = path.join(f.dir, 'client-home');
  const out = path.join(f.dir, 'receipt.json');
  const run = await receiptPy(signArgs({ out, socket: f.socketPath }), home);
  assert.equal(run.code, 0, `client failed: ${run.stderr || run.stdout}`);
  assert.equal(fs.existsSync(home), false,
    'OPENRECEIPTS_HOME was created — the client touched key material');

  const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(doc.pubkey, f.pubB64, 'receipt must carry the DAEMON key');
  assert.equal(doc.receipt.type, 'release');
  assert.equal(doc.receipt.claims.version, 'v1.0.0');
  assert.equal(doc.receipt.issuer, 'auroraxo');

  // Independent verifiers, pinned to the daemon's key — the artifact is an
  // ordinary openreceipts document, indistinguishable from a local signature.
  const py = await verifyPy(out, f.pubFile);
  assert.equal(py.code, 0, `receipt.py verify refused: ${py.out}`);
  assert.match(py.out, /OK/);
  if (HAVE_VERIFY_MJS) {
    const node = await verifyMjs(out, f.pubFile);
    assert.equal(node.code, 0, `verify.mjs refused: ${node.out}`);
  }

  // A second receipt in the same window still works.
  const out2 = path.join(f.dir, 'receipt2.json');
  const second = await receiptPy(signArgs({ out: out2, claim: 'version=v2.0.0', socket: f.socketPath }), home);
  assert.equal(second.code, 0, `second sign failed: ${second.stderr || second.stdout}`);
  const py2 = await verifyPy(out2, f.pubFile);
  assert.equal(py2.code, 0, `second receipt refused: ${py2.out}`);
  assert.equal(fs.existsSync(home), false, 'client home created on the second sign');
});

test('consumer e2e: the client survives a daemon restart and replay is still refused', { skip: SKIP }, async (t) => {
  const f = fixture(t);
  let daemon = await startDaemon(f, { releases: f.messageGrant() });
  // Registered IMMEDIATELY: on a failure before the restart the first daemon
  // must still stop, otherwise the suite hangs instead of failing (measured
  // during the mutation run: 7 red tests, then the file never exited).
  // stop() is idempotent and `daemon` is reassigned before the second stop.
  t.after(() => daemon.stop());
  const home = path.join(f.dir, 'client-home');
  const fixedIssuedAt = '2026-10-31T18:00:00+00:00';

  const outA = path.join(f.dir, 'a.json');
  const first = await receiptPy(signArgs({ out: outA, claim: 'version=v1', issuedAt: fixedIssuedAt, socket: f.socketPath }), home);
  assert.equal(first.code, 0, `first sign failed: ${first.stderr || first.stdout}`);

  // Restart: same keystore, same grant file, same journal — a NEW process.
  await daemon.stop();
  daemon = await startDaemon(f, { releases: f.messageGrant() });

  const outB = path.join(f.dir, 'b.json');
  const afterRestart = await receiptPy(signArgs({ out: outB, claim: 'version=v2', issuedAt: '2026-10-31T18:01:00+00:00', socket: f.socketPath }), home);
  assert.equal(afterRestart.code, 0, `sign after restart failed: ${afterRestart.stderr || afterRestart.stdout}`);
  assert.equal((await verifyPy(outB, f.pubFile)).code, 0, 'receipt after restart must verify');

  // The SAME receipt body again — now and across the restart — is replay.
  const outA2 = path.join(f.dir, 'a-again.json');
  const replay = await receiptPy(signArgs({ out: outA2, claim: 'version=v1', issuedAt: fixedIssuedAt, socket: f.socketPath }), home);
  assert.notEqual(replay.code, 0, 'replay must exit non-zero');
  assert.match(replay.stderr, /refused: replay/, `expected a replay refusal, got: ${replay.stderr}`);
  assert.equal(fs.existsSync(outA2), false, 'a refused sign must write no file');
  assert.equal(fs.existsSync(home), false, 'client home created');
});

test('consumer e2e: an overdrawn grant refuses with data and writes nothing', { skip: SKIP }, async (t) => {
  const f = fixture(t);
  const daemon = await startDaemon(f, { releases: f.messageGrant({ windowMaxMessages: '1' }) });
  t.after(() => daemon.stop());
  const home = path.join(f.dir, 'client-home');

  const out1 = path.join(f.dir, 'one.json');
  const first = await receiptPy(signArgs({ out: out1, claim: 'version=v1', socket: f.socketPath }), home);
  assert.equal(first.code, 0, `first sign failed: ${first.stderr || first.stdout}`);

  const out2 = path.join(f.dir, 'two.json');
  const capped = await receiptPy(signArgs({ out: out2, claim: 'version=v2', socket: f.socketPath }), home);
  assert.notEqual(capped.code, 0, 'overdrawn sign must exit non-zero');
  assert.match(capped.stderr, /refused: window_cap/, `expected window_cap, got: ${capped.stderr}`);
  assert.equal(fs.existsSync(out2), false, 'a refused sign must write no file');
  assert.equal(fs.existsSync(home), false, 'client home created');
});

test('consumer e2e: a grant pinned to another scope refuses type and subject', { skip: SKIP }, async (t) => {
  const f = fixture(t);
  const daemon = await startDaemon(f, { releases: f.messageGrant() });
  t.after(() => daemon.stop());
  const home = path.join(f.dir, 'client-home');

  const wrongType = path.join(f.dir, 'wrong-type.json');
  const typeRun = await receiptPy(signArgs({ out: wrongType, type: 'scan', socket: f.socketPath }), home);
  assert.notEqual(typeRun.code, 0, 'off-scope type must exit non-zero');
  assert.match(typeRun.stderr, /refused: type\b/, `expected a type refusal, got: ${typeRun.stderr}`);
  assert.equal(fs.existsSync(wrongType), false, 'a refused sign must write no file');

  const wrongSubject = path.join(f.dir, 'wrong-subject.json');
  const subjectRun = await receiptPy(signArgs({ out: wrongSubject, subject: 'auroraxo/other', socket: f.socketPath }), home);
  assert.notEqual(subjectRun.code, 0, 'off-scope subject must exit non-zero');
  assert.match(subjectRun.stderr, /refused: subject\b/, `expected a subject refusal, got: ${subjectRun.stderr}`);
  assert.equal(fs.existsSync(wrongSubject), false, 'a refused sign must write no file');
  assert.equal(fs.existsSync(home), false, 'client home created');
});

test('consumer e2e: a lying daemon cannot produce a receipt (client verifies before writing)', { skip: SKIP }, async (t) => {
  const f = fixture(t);
  // A server that claims ok with a signature over SOMETHING ELSE. The client
  // must verify the signature over ITS body before writing anything.
  const garbage = crypto.randomBytes(64).toString('base64');
  await fakeSignerd(t, f.socketPath, {
    ok: true, kind: 'message', signature: garbage, pubkey: f.pubB64,
    messageSha256: '0'.repeat(64), seq: '1', windowMessages: '1', windowRemainingMessages: '4',
  });
  const home = path.join(f.dir, 'client-home');
  const out = path.join(f.dir, 'lied.json');
  const run = await receiptPy(signArgs({ out, socket: f.socketPath }), home);
  assert.notEqual(run.code, 0, 'a signature that does not verify must exit non-zero');
  assert.match(run.stderr, /does not verify/, `expected a verification failure, got: ${run.stderr}`);
  assert.equal(fs.existsSync(out), false, 'the lying daemon produced a receipt file');
  assert.equal(fs.existsSync(home), false, 'client home created');
});

test('consumer e2e: a pinned local key that is not the daemon key refuses', { skip: SKIP }, async (t) => {
  const f = fixture(t);
  const daemon = await startDaemon(f, { releases: f.messageGrant() });
  t.after(() => daemon.stop());

  // The client has already published a DIFFERENT key for this issuer. The
  // daemon signing with its own key must be a refusal, not a silent key swap.
  const home = path.join(f.dir, 'client-home');
  fs.mkdirSync(home, { mode: 0o700 });
  const other = Keypair.generate();
  fs.writeFileSync(path.join(home, 'auroraxo.pub'), publicKeyB64(other) + '\n', { mode: 0o600 });

  const out = path.join(f.dir, 'pinned.json');
  const run = await receiptPy(signArgs({ out, socket: f.socketPath }), home);
  assert.notEqual(run.code, 0, 'a key mismatch must exit non-zero');
  assert.match(run.stderr, /pinned/, `expected a pinned-key refusal, got: ${run.stderr}`);
  assert.equal(fs.existsSync(out), false, 'a refused sign must write no file');
  assert.deepEqual(fs.readdirSync(home), ['auroraxo.pub'],
    'the client must not create a private key next to the pinned public one');
});

test('consumer e2e: an unreachable socket refuses with data and writes nothing', { skip: SKIP }, async (t) => {
  const f = fixture(t); // no daemon started
  const home = path.join(f.dir, 'client-home');
  const out = path.join(f.dir, 'offline.json');
  const run = await receiptPy(signArgs({ out, socket: f.socketPath }), home);
  assert.notEqual(run.code, 0, 'an unreachable daemon must exit non-zero');
  assert.match(run.stderr, /cannot reach signerd/, `expected a connection failure, got: ${run.stderr}`);
  assert.equal(fs.existsSync(out), false, 'no daemon, no receipt file');
  assert.equal(fs.existsSync(home), false, 'client home created');
});
