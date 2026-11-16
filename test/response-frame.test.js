'use strict';

// The response FRAME must be bounded, and every failure of that frame must
// reach the operator BY NAME with a repair.
//
// MEASURED 2026-11-16 (tools/measure-response-frame.js, published v0.2.29
// tree d45cc9a — research/response-frame-v0.2.29-2026-11-16.json, verdict
// client-swallows-response-failures, 4/4 faces defective):
//
//   D1  The REQUEST frame is capped by name (MAX_REQUEST_BYTES = 25_600,
//       refused `request_too_large`) and the mirror on the response side
//       did not exist: request() did `buffer = Buffer.concat(...)` until a
//       newline appeared, with no upper bound. A server that streams
//       without ever sending a newline made the client buffer every byte
//       it received — measured 125-137 MB of RSS growth inside the 10 s
//       timeout window — and the verdict was `request_timeout`: the clock
//       blamed for a frame the server never finished.
//
//   D2  A frame that is not JSON was rejected with a BARE Error: no err.code
//       (the CLI printed the generic `error: response_invalid`) and no
//       repair line, where every other refusal in this product names one
//       code and one `fix:`.
//
//   D3  `connection_closed` carries a repair IN THE SOURCE, but the CLI's
//       generic error path printed code + detail only, so the repair never
//       reached the operator. Measured: `connection_closed: ` and nothing
//       else on stderr.
//
//   D4  A frame that parsed but was not a verdict at all (`{"error":"boom"}`,
//       no `ok` field) was RESOLVED and relayed to stdout verbatim, as if
//       the daemon had answered. The contract the daemon itself keeps is
//       one boolean `ok` field on every frame.
//
// The cap is derived from the response contract, not from a guess (the
// request-side D1 defect was exactly a guessed cap that destroyed legal
// frames): the largest honest field is `signed` = base64 of a wire at the
// 1232-byte policy ceiling => <= 1732 chars, plus signature (<= 88), two
// sha256 hex (128), counters, envelope and detail => ~2450 bytes worst
// case; MEASURED on this tree, a real sign answers 716 bytes. The cap is
// set at 8192 — 3.3x the derived worst case.
//
// Ladder: D1/D2/D3/D4 FAIL on the pre-fix tree, PASS after. G1 (a
// worst-case-sized honest frame still resolves) and G2 (the real daemon
// still signs through the documented CLI path) PASS on BOTH trees — a fix
// that refuses every frame is not a fix, and a cap that swallows the
// response contract is not a contract.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const { request } = require('../src/daemon');
const { buildTransferWire } = require('../src/client');

const BIN = path.join(__dirname, '..', 'bin', 'signerd.js');
const REPO = path.join(__dirname, '..');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-respframe-'));
}

// The grant PINS the destination, so the guard's grant and its wire must
// name the same one - otherwise the daemon refuses the request as
// `destination` and the guard would measure the policy, not the frame.
const DESTINATION = '11111111111111111111111111111112';

/**
 * A server that answers in ONE fixed way, for as long as it is up.
 * In-process on purpose: the CLI is spawned ASYNC here (unlike the
 * measurement tool, whose spawnSync would block a sibling server).
 *
 * kind: 'stream' (never a newline) | 'answer' | 'close'
 */
function startFace(t, face) {
  const dir = tmpDir();
  const socketPath = path.join(dir, 'face.sock');
  const server = net.createServer((socket) => {
    socket.on('error', () => { /* the client hangs up on refusal */ });
    socket.on('data', () => {
      if (face.kind === 'answer') { socket.end(face.answer + '\n'); return; }
      if (face.kind === 'close') { socket.destroy(); return; }
      if (face.kind === 'stream') {
        const chunk = Buffer.alloc(64 * 1024, 0x41);
        let sent = 0;
        const pump = () => {
          while (sent < face.bytes) {
            const ok = socket.write(chunk);
            sent += chunk.length;
            if (!ok) { socket.once('drain', pump); return; }
          }
        };
        pump();
      }
    });
  });
  server.listen(socketPath);
  t.after(() => {
    server.close();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ }
  });
  return { socketPath, dir };
}

function runCli(args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [BIN, ...args], { cwd: REPO, ...opts });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('error', reject);
    p.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

/** The named-code + repair contract: one code, one `fix:` line. */
function voiceOf(stderr) {
  const first = String(stderr || '').split('\n').find((l) => l.trim().length > 0) || '';
  return {
    code: (first.split(':')[0] || '').trim(),
    hasFix: /(^|\n)\s*fix:/.test(String(stderr || '')),
  };
}

// D1: an unterminated frame is refused BY NAME, promptly — before the
// client's own timeout could turn it into a clock blame. The timeout is
// passed at 8000 ms and the refusal must land well inside 4000 ms: only
// the cap can be that early.
test('D1 an oversized response frame is refused by name, not by the clock', async (t) => {
  const { socketPath } = startFace(t, { kind: 'stream', bytes: 8 * 1024 * 1024 });
  const started = Date.now();
  let settled;
  try {
    const answer = await request({ socketPath, grant: 'ops', wire: Buffer.alloc(100).toString('base64'), timeoutMs: 8000 });
    settled = { kind: 'resolved', answer };
  } catch (err) {
    settled = { kind: 'rejected', code: err.code, message: err.message, fix: err.fix };
  }
  const waited = Date.now() - started;

  assert.strictEqual(settled.kind, 'rejected',
    `an unterminated frame must not resolve: ${JSON.stringify(settled)}`);
  assert.strictEqual(settled.code, 'response_too_large',
    `the client must name the frame, not its own clock: ${JSON.stringify(settled)}`);
  assert.ok(settled.fix && settled.fix.length > 0,
    `the refusal must carry a repair: ${JSON.stringify(settled)}`);
  // The repair must be a complete `fix:` line AND carry the bound: a
  // repair that says nothing the operator can check is the same silence
  // in different words (caught by M3 of the mutation ladder).
  assert.ok(/^\s*fix:/.test(settled.fix),
    `the repair must be a fix: line: ${JSON.stringify(settled.fix)}`);
  assert.ok(/8192/.test(settled.fix),
    `the repair must state the bound: ${JSON.stringify(settled.fix)}`);
  // ...and the size of an HONEST answer, so the operator can tell the cap
  // from a cap that swallows the contract (caught by M3).
  assert.ok(/2450/.test(settled.fix),
    `the repair must give the honest size for scale: ${JSON.stringify(settled.fix)}`);
  assert.ok(waited < 4000,
    `the refusal must come from the cap, not the timeout (waited ${waited}ms)`);
});

// D2: a frame that is not JSON is a named refusal with a repair.
test('D2 a non-JSON response frame is refused by name with a repair', async (t) => {
  const { socketPath } = startFace(t, { kind: 'answer', answer: 'not json' });
  let settled;
  try {
    const answer = await request({ socketPath, grant: 'ops', wire: Buffer.alloc(100).toString('base64'), timeoutMs: 8000 });
    settled = { kind: 'resolved', answer };
  } catch (err) {
    settled = { kind: 'rejected', code: err.code, message: err.message, fix: err.fix };
  }

  assert.strictEqual(settled.kind, 'rejected',
    `a non-JSON frame must not resolve: ${JSON.stringify(settled)}`);
  assert.strictEqual(settled.code, 'response_invalid',
    `the refusal must carry its own code (a bare Error prints as "error:"): ${JSON.stringify(settled)}`);
  assert.ok(settled.fix && settled.fix.length > 0,
    `the refusal must carry a repair: ${JSON.stringify(settled)}`);
  assert.ok(/^\s*fix:/.test(settled.fix),
    `the repair must be a fix: line: ${JSON.stringify(settled.fix)}`);
  assert.ok(/JSON/.test(settled.fix),
    `the repair must say what was wrong with the frame: ${JSON.stringify(settled.fix)}`);
});

// D3: the repair the client attaches must SURVIVE to the operator's
// stderr — the CLI's generic error path is what the operator reads.
test('D3 a verdict-less close reaches the operator WITH its repair line', async (t) => {
  const { socketPath } = startFace(t, { kind: 'close' });
  const txPath = path.join(tmpDir(), 'tx.bin');
  fs.writeFileSync(txPath, buildTransferWire({
    fromPubkey: '11111111111111111111111111111111',
    toPubkey: '11111111111111111111111111111112',
    lamports: 1,
    blockhash: '11111111111111111111111111111111',
  }), { mode: 0o600 });

  const res = await runCli(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath]);
  const voice = voiceOf(res.stderr);

  assert.strictEqual(voice.code, 'connection_closed',
    `the operator must see the named failure: ${JSON.stringify(voice)} / ${res.stderr.slice(0, 200)}`);
  assert.ok(voice.hasFix,
    `the repair the client carries must reach stderr: ${JSON.stringify(voice)} / ${res.stderr.slice(0, 300)}`);
  assert.strictEqual(res.code, 1);
});

// D4: a frame with no `ok` field is NOT a verdict. The client must refuse
// it instead of handing the operator an answer nobody gave.
test('D4 a frame without a verdict field is refused, not relayed', async (t) => {
  const { socketPath } = startFace(t, { kind: 'answer', answer: '{"error":"boom"}' });
  const txPath = path.join(tmpDir(), 'tx.bin');
  fs.writeFileSync(txPath, buildTransferWire({
    fromPubkey: '11111111111111111111111111111111',
    toPubkey: '11111111111111111111111111111112',
    lamports: 1,
    blockhash: '11111111111111111111111111111111',
  }), { mode: 0o600 });

  const res = await runCli(['sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath]);
  const voice = voiceOf(res.stderr);

  assert.strictEqual(res.code, 1);
  assert.strictEqual(voice.code, 'response_invalid',
    `the refusal must be named: ${JSON.stringify(voice)} / ${res.stderr.slice(0, 200)}`);
  assert.ok(voice.hasFix,
    `the refusal must carry a repair: ${res.stderr.slice(0, 300)}`);
  assert.ok(!res.stdout.includes('boom'),
    `an answer nobody gave must not be relayed to stdout: ${res.stdout.slice(0, 200)}`);
});

// G1: a worst-case-sized HONEST frame (the ~2450 bytes the response
// contract can produce) must still resolve. This pins the cap's
// derivation: a cap below the contract would turn the fix into the very
// defect the request side had (D1 of request-frame, 2026-11-11).
test('G1 a worst-case-sized honest frame still resolves', async (t) => {
  const honest = {
    ok: true,
    signature: 'A'.repeat(88),
    signed: Buffer.alloc(1297, 7).toString('base64'),
    amountLamports: '18446744073709551615',
    feeLamports: '5000',
    totalLamports: '5000',
    wireSha256: 'a'.repeat(64),
    messageSha256: 'b'.repeat(64),
    seq: '18446744073709551615',
    windowSpentLamports: '5000',
    windowRemainingLamports: '18446744073709551615',
    detail: 'padding to the derived worst case of the response contract'.repeat(10),
  };
  const answer = JSON.stringify(honest);
  const { socketPath } = startFace(t, { kind: 'answer', answer });
  assert.ok(answer.length > 2400 && answer.length < 8192,
    `the guard frame must sit between the derived worst case and the cap (got ${answer.length})`);

  const resolved = await request({ socketPath, grant: 'ops', wire: Buffer.alloc(100).toString('base64'), timeoutMs: 8000 });
  assert.strictEqual(resolved.ok, true);
  assert.strictEqual(resolved.seq, honest.seq);
});

// G2: the real daemon's frame still passes the new shape rule — the
// boolean `ok` requirement must reject a lying frame, never an honest one.
test('G2 the real daemon still signs through the documented CLI path', async (t) => {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.log');
  const socketPath = path.join(dir, 's.sock');
  fs.writeFileSync(pass, 'response-frame-guard-passphrase\n', { mode: 0o600 });

  const run = (args) => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [BIN, ...args], { cwd: REPO });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('error', reject);
    p.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  const t1 = await run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(t1.code, 0, t1.stderr);
  const publicKey = JSON.parse(t1.stdout.trim().split('\n').pop()).publicKey;
  const t2 = await run(['grant-add', '--grants', grants, '--name', 'ops',
    '--keystore', keystore, '--destination', DESTINATION,
    '--max-lamports', '1000000', '--window-max-lamports', '10000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(t2.code, 0, t2.stderr);

  const daemon = spawn(process.execPath, [BIN, 'run', '--keystore', keystore,
    '--passphrase-file', pass, '--grants', grants, '--ledger', ledger,
    '--socket', socketPath], { cwd: REPO });
  t.after(() => {
    daemon.kill();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ }
  });
  for (let i = 0; i < 200 && !fs.existsSync(socketPath); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(fs.existsSync(socketPath), 'daemon did not start');

  const out = path.join(dir, 'signed.bin');
  // The wire is built HERE, not taken from a fixture: a guard that depends
  // on a file the checkout may not have is a guard that measures the
  // checkout, not the product.
  const wire = buildTransferWire({
    fromPubkey: publicKey,
    // A DISTINCT destination: fee payer == destination deduplicates to two
    // account keys, which the daemon's envelope rule (exactly three, one
    // instruction) refuses - measured while building this guard: the
    // refusal came back {ok:false, error:'envelope'} and the guard blamed
    // the product for a wire the policy was right to refuse.
    toPubkey: DESTINATION,
    lamports: 42,
    blockhash: '11111111111111111111111111111111',
  });
  const txPath = path.join(dir, 'tx.bin');
  fs.writeFileSync(txPath, wire, { mode: 0o600 });
  const sign = await run(['sign', '--socket', socketPath, '--grant', 'ops',
    '--tx', txPath, '--out', out]);
  assert.strictEqual(sign.code, 0, `real sign failed: ${sign.stderr}`);
  assert.ok(fs.existsSync(out) && fs.readFileSync(out).length > 0, 'no artifact');
});
