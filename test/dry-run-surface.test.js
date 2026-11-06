'use strict';

// DRY-RUN SURFACE: the contract the README promised —
// "`--dry` runs the same scope path without producing a real signature."
//
// WHY (measured 2026-11-06, this repo):
//
// The README has claimed "--dry runs the same scope path without producing a
// real signature" since RFC stage. Measured on the live code:
//
//   1. CLI: `signerd sign ... --dry` exited 2 with `unknown_flag: --dry`
//      (since 0c5dedb, which made the flag surface strict; before that the
//      flag was silently DROPPED, so an operator asking for a dry run got
//      a REAL SIGNATURE and consumed budget).
//   2. Socket: the daemon's request decoder ignored unrecognized fields, so
//      a client that set `{ dry: true }` in the frame got a real signature
//      back and burned the transaction's replay record in the journal.
//   3. Value safety: `dry: "true"` (the string shape a JSON mistake or
//      coercion produces) must never silently become a non-dry request — it
//      must fail closed (`request_invalid`).
//
// THE CONTRACT:
//   D1 CLI `signerd sign --dry ...`: runs the policy and grant check,
//      returns `{ ok: true, dry: true, allowed: true, amountLamports, ... }`
//      without a `signed` wire or `signature`, produces no `--out` file,
//      and leaves the journal UNTOUCHED (0 records appended).
//   D2 CLI `signerd sign-message --dry ...`: does the same for message grants.
//   D3 Replay survival: because budget was NOT consumed and no record was
//      journaled, the EXACT SAME wire/message can be signed for real
//      afterwards and succeeds.
//   D4 Window budget survival: a dry run does not charge against the grant's
//      rolling window cap.
//   D5 Policy enforcement is identical: an out-of-scope transaction (e.g.
//      over the lamports cap, or wrong destination) is REFUSED with the
//      exact same reason it would have been on a real sign attempt.
//   D6 Value typing: `dry` must be a boolean. A string `"true"` or number `1`
//      is rejected with `request_invalid` (fail closed, never silently real).
//   G1 Guard: a regular sign (without `--dry`) produces a real signature and
//      records to the journal (green on both trees).
//   G2 Guard: unknown flags are STILL refused (the flag hygiene rule holds).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync, spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const { Daemon, request } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');
const { buildTransferWire, buildReceiptBody } = require('../src/client');
const { Keypair } = require('@solana/web3.js');

const PASSPHRASE = 'dry-surface-test-pass';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-dry-test-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function base58(bytes) {
  return require('bs58').encode(bytes);
}

/**
 * Run the CLI ASYNC: the fixture daemon lives in THIS process, so a spawnSync
 * would block the very event loop that has to answer the CLI's socket request
 * (measured: it hangs until request_timeout). Returns { status, stdout, stderr }.
 */
function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { encoding: 'utf8' });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

/** Raw socket helper: write one JSON frame and read the JSON response. */
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

async function fixture() {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.jsonl');
  const socket = path.join(dir, 's.sock');
  fs.writeFileSync(pass, `${PASSPHRASE}\n`, { mode: 0o600 });

  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const recipient = Keypair.generate().publicKey.toBase58();

  const grantData = {
    version: 1,
    grants: {
      ops: {
        signer: keypair.publicKey.toBase58(),
        destination: recipient,
        maxLamports: '1000000',
        windowMaxLamports: '200000',
        windowSeconds: '3600',
        expiresAt: futureIso(),
      },
      'ops-receipt': {
        kind: 'message',
        issuer: 'aurora',
        type: 'test',
        subject: 'ship',
        pubkey: Buffer.from(require('bs58').decode(keypair.publicKey.toBase58())).toString('base64'),
        maxBytes: '700',
        windowMaxMessages: '5',
        windowSeconds: '3600',
        expiresAt: futureIso(),
      },
    },
  };
  fs.writeFileSync(grants, JSON.stringify(grantData, null, 2), { mode: 0o600 });

  const daemon = new Daemon({
    socketPath: socket,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile: grants,
    ledgerFile: ledger,
  });
  await daemon.start();

  const dummyHash = base58(Buffer.alloc(32, 7));
  const makeWire = (lamports = 42) => buildTransferWire({
    fromPubkey: keypair.publicKey.toBase58(),
    toPubkey: recipient,
    lamports,
    blockhash: dummyHash,
  });

  return { dir, keystore, pass, grants, ledger, socket, keypair, recipient, daemon, makeWire };
}

// ---------------------------------------------------------------------------
// D1 + D3: dry transaction via CLI
// ---------------------------------------------------------------------------
test('D1 CLI sign --dry verifies the transaction, produces no signature and writes no journal', async () => {
  const f = await fixture();
  try {
    const txPath = path.join(f.dir, 'tx.bin');
    const outPath = path.join(f.dir, 'signed.bin');
    fs.writeFileSync(txPath, f.makeWire(42), { mode: 0o600 });

    const res = await runCli([
      'sign', '--socket', f.socket, '--grant', 'ops', '--tx', txPath,
      '--out', outPath, '--dry',
    ]);

    assert.equal(res.status, 0, `CLI sign --dry failed: ${res.stderr}`);
    const out = JSON.parse(res.stdout.trim());
    assert.equal(out.ok, true);
    assert.equal(out.dry, true);
    assert.equal(out.allowed, true);
    assert.equal(out.amountLamports, '42');
    assert.equal(out.totalLamports, '5042');
    assert.equal(out.signed, undefined, 'dry run must not produce a signed wire');
    assert.equal(out.signature, undefined, 'dry run must not produce a signature');

    // No file was written to --out.
    assert.equal(fs.existsSync(outPath), false, '--out file must not be created on --dry');

    // No record was appended to the journal.
    const journalSize = fs.existsSync(f.ledger) ? fs.readFileSync(f.ledger).length : 0;
    assert.equal(journalSize, 0, 'dry run must not append to the journal');

    // D3: The SAME wire can now be signed for real (replay not burned).
    const realRes = await runCli([
      'sign', '--socket', f.socket, '--grant', 'ops', '--tx', txPath,
      '--out', outPath,
    ]);
    assert.equal(realRes.status, 0, `subsequent real sign failed: ${realRes.stderr}`);
    const realOut = JSON.parse(realRes.stdout.trim());
    assert.equal(realOut.ok, true);
    assert.equal(fs.existsSync(outPath), true, 'real sign must write the --out file');
    assert.ok(fs.readFileSync(f.ledger).length > 0, 'real sign must append to the journal');
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// D2: dry message via CLI
// ---------------------------------------------------------------------------
test('D2 CLI sign-message --dry verifies the receipt body without signing or journaling', async () => {
  const f = await fixture();
  try {
    const bodyPath = path.join(f.dir, 'body.json');
    const outPath = path.join(f.dir, 'receipt.json');
    const body = buildReceiptBody({ issuer: 'aurora', type: 'test', subject: 'ship', claims: {} });
    fs.writeFileSync(bodyPath, JSON.stringify(body), { mode: 0o600 });

    const res = await runCli([
      'sign-message', '--socket', f.socket, '--grant', 'ops-receipt',
      '--body', bodyPath, '--out', outPath, '--dry',
    ]);

    assert.equal(res.status, 0, `CLI sign-message --dry failed: ${res.stderr} STDOUT=${res.stdout}`);
    const out = JSON.parse(res.stdout.trim());
    assert.equal(out.ok, true);
    assert.equal(out.dry, true);
    assert.equal(out.allowed, true);
    assert.equal(out.kind, 'message');
    assert.equal(out.signature, undefined, 'dry message run must not produce a signature');
    assert.equal(fs.existsSync(outPath), false, 'receipt file must not be written on --dry');

    const journalSize = fs.existsSync(f.ledger) ? fs.readFileSync(f.ledger).length : 0;
    assert.equal(journalSize, 0, 'dry message run must not append to the journal');
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// D4: Window budget survival
// ---------------------------------------------------------------------------
test('D4 a dry run does not consume window budget', async () => {
  const f = await fixture();
  try {
    const w = f.makeWire(50000); // 50k lamports
    const dry = await request({ socketPath: f.socket, grant: 'ops', wire: w, dry: true });
    assert.equal(dry.ok, true);
    assert.equal(dry.dry, true);

    // The falsifying case: 50k dry (55k with fee) + 145k real (150k with
    // fee) = 205k > 200k window cap. If a dry run charged the window, this
    // real sign would be refused `window_cap`. It must succeed, and the
    // recorded spend must be the REAL one alone (150000).
    const realWire = f.makeWire(145000);
    const real = await request({ socketPath: f.socket, grant: 'ops', wire: realWire });
    assert.equal(real.ok, true, `real sign should succeed because dry did not count: ${JSON.stringify(real)}`);
    assert.equal(real.windowSpentLamports, '150000'); // 145k + 5k fee; the dry 50k is NOT in it
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// D5: Policy enforcement is identical on dry runs
// ---------------------------------------------------------------------------
test('D5 out-of-scope requests refuse identically under dry run', async () => {
  const f = await fixture();
  try {
    // Over the per-transaction cap (1M):
    const overWire = f.makeWire(1000001);
    const dryOver = await request({ socketPath: f.socket, grant: 'ops', wire: overWire, dry: true });
    assert.equal(dryOver.ok, false);
    assert.equal(dryOver.error, 'amount');

    // Message grant with wrong subject:
    const badBody = buildReceiptBody({ issuer: 'aurora', type: 'test', subject: 'wrong', claims: {} });
    const dryBadMsg = await request({
      socketPath: f.socket, grant: 'ops-receipt', body: JSON.stringify(badBody), dry: true,
    });
    assert.equal(dryBadMsg.ok, false);
    assert.equal(dryBadMsg.error, 'subject');
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// D6: Value typing — mistyped dry field fails closed
// ---------------------------------------------------------------------------
test('D6 a non-boolean dry field fails closed with request_invalid', async () => {
  const f = await fixture();
  try {
    const wireB64 = f.makeWire(42).toString('base64');
    for (const badValue of ['true', 'false', 1, 0, null, [], {}]) {
      const res = await rawFrame(f.socket, { grant: 'ops', wire: wireB64, dry: badValue });
      assert.equal(res.ok, false, `expected dry:${JSON.stringify(badValue)} to be refused`);
      assert.equal(res.error, 'request_invalid');
    }
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// G1: Guard — normal sign still produces signatures and journals
// ---------------------------------------------------------------------------
test('G1 guard: normal sign produces valid signature and durably journals', async () => {
  const f = await fixture();
  try {
    const res = await request({ socketPath: f.socket, grant: 'ops', wire: f.makeWire(42) });
    assert.equal(res.ok, true);
    assert.ok(typeof res.signed === 'string');
    assert.ok(typeof res.signature === 'string');
    assert.equal(res.dry, undefined);
    assert.ok(fs.readFileSync(f.ledger).length > 0);
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// G2: Guard — unknown flags are still refused
// ---------------------------------------------------------------------------
test('G2 guard: unknown flags to sign and sign-message are still refused', () => {
  const r1 = spawnSync(process.execPath, [CLI, 'sign', '--foo'], { encoding: 'utf8' });
  assert.equal(r1.status, 2);
  assert.match(r1.stderr, /unknown_flag: --foo/);

  const r2 = spawnSync(process.execPath, [CLI, 'sign-message', '--bar'], { encoding: 'utf8' });
  assert.equal(r2.status, 2);
  assert.match(r2.stderr, /unknown_flag: --bar/);
});
