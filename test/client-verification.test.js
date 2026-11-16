'use strict';

// THE CLIENT VERIFIES THE DAEMON'S ANSWER BEFORE IT DELIVERS ANYTHING.
//
// WHY (measured 2026-11-16, tools/measure-client-verification.js):
//
//   The daemon verifies its own output (src/signer.js) — but nothing
//   between the socket and the operator's file was checked. The socket is a
//   capability: whoever can bind it can impersonate the signing daemon
//   (src/socketprobe.js). Measured against the PUBLISHED v0.2.28 tree with a
//   server that answers exactly what a lying daemon would answer, six faces
//   were defective (research/client-verification-v0.2.28-2026-11-16.json):
//
//     F1 substituted message — a wire whose message region differs from the
//        one the operator asked to have signed was written to --out, exit 0;
//     F2 garbage signature — random bytes in the signature slot were written
//        to --out, exit 0;
//     F3 no signature — `{ok:true}` with no `signed` field crashed the CLI
//        with a raw ERR_INVALID_ARG_TYPE (exit 1, no artifact), while
//        sign-message wrote a 260-byte receipt document, exit 0;
//     F4 substituted body — a receipt signed over a DIFFERENT body was
//        written to --out, exit 0.
//
//   The example client had the same hole (F1, F2: exit 0, file written).
//
// WHAT PINS IT (this file):
//   V1-V4 each face refuses with its own named code, exit 1, and writes
//      NOTHING — no --out file, no receipt document;
//   V5 the refusal voice: the code appears exactly once on stderr and a
//      `fix:` line names the repair (the house rule, grant-refusal-voice);
//   V6 the message path refuses a substituted body with the same voice;
//   V7 CONTROL: a real daemon still signs, the artifact is written 0600 and
//      the signature verifies under the fee payer's public key — so the fix
//      cannot be "pass by refusing everything";
//   V8 the pure verifier is unit-tested in every direction (valid, tampered
//      message, garbage signature, missing, wrong length, zero slot), and
//      the message verifier in every direction too (valid, garbage, wrong
//      hash, wrong key, missing signature, malformed key).
//
// No network. No writes outside os.tmpdir().

process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { VersionedTransaction, Keypair } = require('@solana/web3.js');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const CLIENT = path.join(ROOT, 'examples', 'user-zero-client.js');
const { buildTransferWire } = require('../src/client');
const { verifySignedWire, verifyMessageSignature } = require('../src/client-verify');
const { canonicalReceiptBytes } = require('../src/receipt-identity');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-clientverify-'));
}

/**
 * A server that answers exactly what it is told to answer.
 *
 * It must run OUTSIDE this process: the measurements drive the CLI with
 * spawnSync, which blocks the event loop, so an in-process server never
 * accepts the connection (that failure mode was hit while building the
 * instrument; a timeout is not a verdict).
 */
function lyingServer(t, socketPath, answer) {
  try { fs.unlinkSync(socketPath); } catch { /* absent */ }
  const dir = path.dirname(socketPath);
  const answerFile = `${socketPath}.answer.json`;
  const serverFile = `${socketPath}.server.js`;
  fs.writeFileSync(answerFile, JSON.stringify(answer));
  fs.writeFileSync(serverFile, [
    "const net = require('node:net');",
    "const fs = require('node:fs');",
    "const [socketPath, answerFile] = process.argv.slice(2);",
    "const answer = fs.readFileSync(answerFile, 'utf8');",
    "try { fs.unlinkSync(socketPath); } catch {}",
    "const server = net.createServer((socket) => {",
    "  let buf = '';",
    "  socket.on('data', (chunk) => {",
    "    buf += chunk;",
    "    if (!buf.includes('\\n')) return;",
    "    socket.end(answer + '\\n');",
    "  });",
    "  socket.on('error', () => {});",
    "});",
    "server.listen(socketPath, () => process.stdout.write('READY\\\\n'));",
    "setTimeout(() => process.exit(0), 60000);",
    "",
  ].join('\n'));
  const child = spawn(process.execPath, [serverFile, socketPath, answerFile],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stdout.on('data', (c) => { log += c; });
  child.stderr.on('data', (c) => { log += c; });
  t.after(() => {
    try { child.kill('SIGTERM'); } catch { /* gone */ }
    fs.rmSync(socketPath, { force: true });
    fs.rmSync(answerFile, { force: true });
    fs.rmSync(serverFile, { force: true });
    fs.rmSync(`${socketPath}.log`, { force: true });
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server never bound; saw: ${log}`)), 10000);
    const poll = setInterval(() => {
      if (fs.existsSync(socketPath)) {
        clearInterval(poll);
        clearTimeout(timer);
        resolve();
      }
    }, 25);
    child.on('exit', () => {
      clearInterval(poll);
      clearTimeout(timer);
      reject(new Error(`server exited early; saw: ${log}`));
    });
  });
}

function cli(args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

/** A wire the lying servers answer about: an ordinary legacy transfer. */
function fixtureWire() {
  const signer = Keypair.generate();
  const wire = buildTransferWire({
    fromPubkey: signer.publicKey.toBase58(),
    toPubkey: Keypair.generate().publicKey.toBase58(),
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  const tx = VersionedTransaction.deserialize(wire);
  tx.sign([signer]);
  return { signer, wire, signed: Buffer.from(tx.serialize()) };
}

const TX_FIELDS = {
  amountLamports: '42', feeLamports: '5000', totalLamports: '5042',
  wireSha256: '0'.repeat(64), messageSha256: '0'.repeat(64), seq: '1',
  windowSpentLamports: '5042', windowRemainingLamports: '1000000',
};

function receiptBody() {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    claims: { version: 'v0.0.0-test' },
    issued_at: '2026-11-16T10:00:00+00:00',
  };
}

// ---------------------------------------------------------------------------
// V1-V3: the transaction path refuses every lying face.
// ---------------------------------------------------------------------------

test('V1 a substituted message is refused, named, and writes nothing', async (t) => {
  const dir = tmpDir();
  const { wire, signed } = fixtureWire();
  const tampered = Buffer.from(signed);
  tampered[tampered.length - 1] ^= 0xff;
  const socketPath = path.join(dir, 'sub.sock');
  await lyingServer(t, socketPath, { ok: true, signature: 'x', signed: tampered.toString('base64'), ...TX_FIELDS });

  const txFile = path.join(dir, 'tx.bin');
  fs.writeFileSync(txFile, wire, { mode: 0o600 });
  const out = path.join(dir, 'signed.bin');
  const res = cli(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txFile, '--out', out]);

  assert.equal(res.status, 1, `must refuse, not sign: ${res.stdout}${res.stderr}`);
  assert.match(res.stderr, /^signed_message_mismatch: /m, `wrong code: ${res.stderr}`);
  assert.equal(fs.existsSync(out), false, 'a substituted wire must never reach --out');
  // The code appears exactly once, and the repair is named (grant-refusal-voice).
  assert.equal((res.stderr.match(/signed_message_mismatch/g) || []).length, 1, res.stderr);
  assert.match(res.stderr, /fix: /, `no repair named: ${res.stderr}`);
  // Nothing on stdout may carry an artifact either.
  assert.ok(!res.stdout.includes('"signed"'), `stdout must not carry the wire: ${res.stdout}`);
});

test('V2 a garbage signature is refused, named, and writes nothing', async (t) => {
  const dir = tmpDir();
  const { wire, signed } = fixtureWire();
  const garbage = Buffer.from(signed);
  garbage.set(crypto.randomBytes(64), 1);
  const socketPath = path.join(dir, 'garbage.sock');
  await lyingServer(t, socketPath, { ok: true, signature: 'x', signed: garbage.toString('base64'), ...TX_FIELDS });

  const txFile = path.join(dir, 'tx.bin');
  fs.writeFileSync(txFile, wire, { mode: 0o600 });
  const out = path.join(dir, 'signed.bin');
  const res = cli(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txFile, '--out', out]);

  assert.equal(res.status, 1, `must refuse: ${res.stdout}${res.stderr}`);
  assert.match(res.stderr, /^signed_signature_invalid: /m, `wrong code: ${res.stderr}`);
  assert.equal(fs.existsSync(out), false, 'an unverifiable signature must never reach --out');
  assert.equal((res.stderr.match(/signed_signature_invalid/g) || []).length, 1, res.stderr);
  assert.match(res.stderr, /fix: /, `no repair named: ${res.stderr}`);
});

test('V3 ok:true with no signature refuses by name (was: a raw ERR_INVALID_ARG_TYPE)', async (t) => {
  const dir = tmpDir();
  const { wire } = fixtureWire();
  const socketPath = path.join(dir, 'nosig.sock');
  await lyingServer(t, socketPath, { ok: true, signature: 'x', ...TX_FIELDS });

  const txFile = path.join(dir, 'tx.bin');
  fs.writeFileSync(txFile, wire, { mode: 0o600 });
  const out = path.join(dir, 'signed.bin');
  const res = cli(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txFile, '--out', out]);

  assert.equal(res.status, 1, `must refuse: ${res.stdout}${res.stderr}`);
  assert.match(res.stderr, /^signed_missing: /m, `wrong code: ${res.stderr}`);
  assert.ok(!/ERR_INVALID_ARG_TYPE|TypeError/.test(res.stderr),
    `the refusal must be the product's voice, not a Node errno: ${res.stderr}`);
  assert.equal(fs.existsSync(out), false, 'nothing may be written');
  assert.match(res.stderr, /fix: /, `no repair named: ${res.stderr}`);
});

// ---------------------------------------------------------------------------
// V4/V6: the message path refuses a substituted body.
// ---------------------------------------------------------------------------

async function messageFace(t, { answer, expectCode }) {
  const dir = tmpDir();
  const socketPath = path.join(dir, 'msg.sock');
  await lyingServer(t, socketPath, answer);
  const bodyFile = path.join(dir, 'body.json');
  fs.writeFileSync(bodyFile, JSON.stringify(receiptBody(), null, 2), { mode: 0o600 });
  const out = path.join(dir, 'receipt.json');
  const res = cli(['sign-message', '--socket', socketPath, '--grant', 'ops', '--body', bodyFile, '--out', out]);
  assert.equal(res.status, 1, `must refuse: ${res.stdout}${res.stderr}`);
  assert.match(res.stderr, new RegExp(`^${expectCode}: `, 'm'), `wrong code: ${res.stderr}`);
  assert.equal(fs.existsSync(out), false, 'an unverifiable receipt must never reach --out');
  assert.equal((res.stderr.match(new RegExp(expectCode, 'g')) || []).length, 1, res.stderr);
  assert.match(res.stderr, /fix: /, `no repair named: ${res.stderr}`);
  return res;
}

test('V4 a receipt signed over another body is refused', async (t) => {
  const { ed25519 } = require('@noble/curves/ed25519.js');
  const seed = crypto.randomBytes(32);
  const other = Buffer.from(JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'attacker', type: 'release',
    subject: 'auroraxo/signerd', claims: {}, issued_at: '2026-11-16T10:00:00+00:00',
  }));
  await messageFace(t, {
    answer: {
      ok: true, kind: 'message',
      signature: Buffer.from(ed25519.sign(other, seed)).toString('base64'),
      pubkey: Buffer.from(ed25519.getPublicKey(seed)).toString('base64'),
      messageSha256: crypto.createHash('sha256').update(other).digest('hex'),
      seq: '1', windowMessages: '1', windowRemainingMessages: '4',
    },
    expectCode: 'signed_message_mismatch',
  });
});

test('V6 ok:true with no receipt signature refuses by name', async (t) => {
  await messageFace(t, {
    answer: {
      ok: true, kind: 'message',
      pubkey: Buffer.from(crypto.randomBytes(32)).toString('base64'),
      messageSha256: '0'.repeat(64), seq: '1', windowMessages: '1', windowRemainingMessages: '4',
    },
    expectCode: 'signed_missing',
  });
});

test('V5 the example client refuses a lying daemon too', async (t) => {
  const dir = tmpDir();
  const { signer, signed } = fixtureWire();
  const tampered = Buffer.from(signed);
  tampered[tampered.length - 1] ^= 0xff;
  const socketPath = path.join(dir, 'client.sock');
  await lyingServer(t, socketPath, { ok: true, signature: 'x', signed: tampered.toString('base64'), ...TX_FIELDS });

  const out = path.join(dir, 'signed.bin');
  const res = spawnSync(process.execPath, [CLIENT,
    '--socket', socketPath, '--grant', 'ops',
    '--from', signer.publicKey.toBase58(),
    '--to', Keypair.generate().publicKey.toBase58(),
    '--lamports', '42',
    '--blockhash', Keypair.generate().publicKey.toBase58(),
    '--out', out], { encoding: 'utf8', timeout: 60000 });

  assert.equal(res.status, 1, `must refuse: ${res.stdout}${res.stderr}`);
  assert.match(res.stderr, /^signed_message_mismatch: /m, `wrong code: ${res.stderr}`);
  assert.equal(fs.existsSync(out), false, 'the example client must not write an unverified wire');
  assert.match(res.stderr, /fix: /, `no repair named: ${res.stderr}`);
});

// ---------------------------------------------------------------------------
// V7: the honest path must still work — the fix cannot be "refuse everything".
// ---------------------------------------------------------------------------

test('V7 a real daemon still signs, and the artifact verifies', async (t) => {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the client-verification test only\n', { mode: 0o600 });
  const keygen = cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.equal(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const daemonPubkey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;

  const destination = Keypair.generate().publicKey.toBase58();
  const grants = path.join(dir, 'grants.json');
  const expiry = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const add = cli(['grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', destination, '--max-lamports', '1000', '--window-max-lamports', '1000000',
    '--window-seconds', '3600', '--expires', expiry]);
  assert.equal(add.status, 0, `grant-add failed: ${add.stdout}${add.stderr}`);

  const socketPath = path.join(dir, 'real.sock');
  const log = path.join(dir, 'daemon.log');
  const logFd = fs.openSync(log, 'a');
  // The daemon is spawned DIRECTLY (not through `sh -c ... &`): a shell
  // wrapper keeps the pipe open for the backgrounded child, and the test
  // runner then waits for a stream that never ends.
  const daemon = spawn(process.execPath, [CLI, 'run',
    '--keystore', keystore, '--passphrase-file', pass,
    '--grants', grants, '--ledger', path.join(dir, 'journal.jsonl'),
    '--socket', socketPath], { stdio: ['ignore', logFd, logFd] });
  t.after(() => {
    try { daemon.kill('SIGTERM'); } catch { /* gone */ }
    try { fs.closeSync(logFd); } catch { /* closed */ }
  });
  for (let i = 0; i < 200 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.05']);
  assert.ok(fs.existsSync(socketPath), `daemon never came up: ${fs.readFileSync(log, 'utf8')}`);

  const wire = buildTransferWire({
    fromPubkey: daemonPubkey, toPubkey: destination,
    lamports: 42, blockhash: Keypair.generate().publicKey.toBase58(),
  });
  const txFile = path.join(dir, 'tx-real.bin');
  fs.writeFileSync(txFile, wire, { mode: 0o600 });
  const out = path.join(dir, 'real.bin');
  const res = cli(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txFile, '--out', out]);

  assert.equal(res.status, 0, `the honest path must still sign: ${res.stdout}${res.stderr}`);
  const bytes = fs.readFileSync(out);
  assert.equal(bytes.length, wire.length, 'the signed wire must be the same transaction');
  assert.ok(bytes.subarray(65).equals(wire.subarray(65)), 'the message region must be untouched');
  const mode = fs.statSync(out).mode & 0o777;
  assert.equal(mode, 0o600, `the artifact must be 0600, got ${mode.toString(8)}`);

  // Independent verification: Node's OpenSSL ed25519, not the product's helpers.
  const tx = VersionedTransaction.deserialize(bytes);
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(tx.message.accountKeys[0].toBytes())]);
  const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(crypto.verify(null, Buffer.from(tx.message.serialize()), key,
    Buffer.from(tx.signatures[0])), true, 'the signature must verify under the fee payer key');

  // And the verifier itself agrees with the independent check.
  assert.equal(verifySignedWire({ wire, signed: bytes }).ok, true);
});

// ---------------------------------------------------------------------------
// V8: the pure verifier, every direction.
// ---------------------------------------------------------------------------

test('V8a verifySignedWire: valid, and every failure direction', () => {
  const { wire, signed } = fixtureWire();
  assert.equal(verifySignedWire({ wire, signed }).ok, true);

  const tampered = Buffer.from(signed);
  tampered[tampered.length - 1] ^= 0xff;
  assert.equal(verifySignedWire({ wire, signed: tampered }).code, 'signed_message_mismatch');

  const garbage = Buffer.from(signed);
  garbage.set(crypto.randomBytes(64), 1);
  assert.equal(verifySignedWire({ wire, signed: garbage }).code, 'signed_signature_invalid');

  assert.equal(verifySignedWire({ wire }).code, 'signed_missing');
  assert.equal(verifySignedWire({ wire, signed: null }).code, 'signed_missing');

  const longer = Buffer.concat([signed, Buffer.from([0])]);
  assert.equal(verifySignedWire({ wire, signed: longer }).code, 'signed_length_mismatch');

  const zeroSlot = Buffer.from(signed);
  zeroSlot.fill(0, 1, 65);
  assert.equal(verifySignedWire({ wire, signed: zeroSlot }).code, 'signed_signature_empty');

  const garbageCount = Buffer.from(signed);
  garbageCount[0] = 2;
  assert.equal(verifySignedWire({ wire, signed: garbageCount }).code, 'signed_count_mismatch');

  const notBytes = verifySignedWire({ wire: 'not a wire', signed });
  assert.equal(notBytes.code, 'signed_wire_invalid');
});

test('V8b verifyMessageSignature: valid, and every failure direction', () => {
  const { ed25519 } = require('@noble/curves/ed25519.js');
  const body = receiptBody();
  const seed = crypto.randomBytes(32);
  const pubkey = Buffer.from(ed25519.getPublicKey(seed));
  const messageBytes = canonicalReceiptBytes(body);
  const good = {
    ok: true,
    signature: Buffer.from(ed25519.sign(messageBytes, seed)).toString('base64'),
    pubkey: pubkey.toString('base64'),
    messageSha256: crypto.createHash('sha256').update(messageBytes).digest('hex'),
  };
  assert.equal(verifyMessageSignature({ body, response: good }).ok, true);

  // The signature verifies under the returned key but over OTHER bytes, and
  // the daemon reports the hash of THOSE bytes: the client catches it on the
  // hash first (the body it sent is not the body that was signed).
  const otherBytes = canonicalReceiptBytes({ ...body, issuer: 'attacker' });
  assert.equal(verifyMessageSignature({ body, response: {
    ...good,
    signature: Buffer.from(ed25519.sign(otherBytes, seed)).toString('base64'),
    messageSha256: crypto.createHash('sha256').update(otherBytes).digest('hex'),
  } }).code, 'signed_message_mismatch');

  // The same substituted signature, but with the hash of the body the client
  // actually sent: the hash check passes and the SIGNATURE check catches it.
  assert.equal(verifyMessageSignature({ body, response: {
    ...good,
    signature: Buffer.from(ed25519.sign(otherBytes, seed)).toString('base64'),
  } }).code, 'signed_signature_invalid');

  // Same signature, but the daemon reports a hash for a different body.
  assert.equal(verifyMessageSignature({ body, response: {
    ...good, messageSha256: '0'.repeat(64),
  } }).code, 'signed_message_mismatch');

  // A key that did not make this signature.
  assert.equal(verifyMessageSignature({ body, response: {
    ...good, pubkey: Buffer.from(crypto.randomBytes(32)).toString('base64'),
  } }).code, 'signed_signature_invalid');

  assert.equal(verifyMessageSignature({ body, response: { ...good, signature: undefined } }).code, 'signed_missing');
  assert.equal(verifyMessageSignature({ body, response: { ...good, pubkey: undefined } }).code, 'signed_missing');
  assert.equal(verifyMessageSignature({ body, response: null }).code, 'signed_missing');
  assert.equal(verifyMessageSignature({ body, response: { ...good, pubkey: 'AAAA' } }).code, 'signed_pubkey_invalid');
  assert.equal(verifyMessageSignature({ body, response: { ...good, signature: 'AAAA' } }).code, 'signed_signature_invalid');
});
