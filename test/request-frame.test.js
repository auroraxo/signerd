'use strict';

// The request FRAME must carry every body the documented body contract
// admits, and every frame the daemon refuses must say so.
//
// MEASURED 2026-11-11 (PULS R, tools/measure-request-frame.js, published
// v0.2.14 tree 1342aea — verdict "silent-destroy"):
//
//   D1  A body of at most 4096 chars — the documented limit
//       (decodeRequest: bodyField.value.length > 4096) — whose characters
//       are multibyte (CJK: 3 UTF-8 bytes) or raw control chars (re-escaped
//       as \u00XX: 6 bytes) produces a frame of 12000–24500 bytes, while
//       MAX_REQUEST_BYTES was 8704, derived as "worst case every character
//       escapes to two (\")". JSON.stringify does NOT escape non-ASCII:
//       the comment's own arithmetic was wrong for the dominant cases.
//       The cap fired BEFORE the newline scan: socket.destroy(), no
//       response line. Measured live: a 4096-char CJK body got nothing
//       back; the shipped client hung to its own timer and reported
//       request_timeout (12007 ms) for a request the transport had
//       already killed. The daemon never judged a request it was
//       contractually bound to judge.
//
//   D2  The cap refusal itself was silent: an oversized frame got
//       connection-close instead of {ok:false, error:...}, while every
//       other malformed request in this product answers with a reason.
//
//   D3  The shipped client (src/daemon.js request()) had no 'close'
//       handler: a verdict-less close surfaced as a 10 s clock blame
//       instead of a named transport failure.
//
// Ladder: D1a/D1b/D2/D3 FAIL on the pre-fix tree, PASS after. G1 (small
// body signs through the real CLI) and G2 (the 4096-CHAR body limit still
// refuses by name) PASS on BOTH trees — a fix that refuses everything is
// not a fix, and a cap that swallows the documented contract is not a
// contract.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const { request } = require('../src/daemon');

const BIN = path.join(__dirname, '..', 'bin', 'signerd.js');
const REPO = path.join(__dirname, '..');

// The cap the pre-fix tree enforced; the defect premises are pinned
// against it, not against whatever the source says today.
const OLD_CAP_BYTES = 8704;

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-frame-'));
}

/** One raw round trip: send `payload` + newline, wait for one response line. */
function rawRequest(socketPath, payload, waitMs = 6000) {
  return new Promise((resolve) => {
    const socket = net.connect(socketPath);
    let buf = Buffer.alloc(0);
    const outcome = { answered: false, closed: false, error: null, timeout: false };
    const done = () => {
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already gone */ }
      resolve(outcome);
    };
    const timer = setTimeout(() => { outcome.timeout = true; done(); }, waitMs);
    socket.on('connect', () => socket.write(payload + '\n'));
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return;
      outcome.answered = true;
      try { outcome.response = JSON.parse(buf.subarray(0, nl).toString('utf8')); }
      catch { outcome.response = null; }
      done();
    });
    socket.on('close', () => { outcome.closed = true; done(); });
    socket.on('error', (err) => { outcome.error = err.code || err.message; done(); });
  });
}

const RECEIPT_SKELETON = (note) => JSON.stringify({
  schema: 'openreceipts/v1',
  issuer: 'auroraxo',
  type: 'release',
  subject: 'auroraxo/signerd',
  issued_at: '2026-11-11T03:00:00Z',
  claims: { note },
});

/** Largest note run of `filler` that keeps the body text at <= limit chars. */
function bodyAtLimit(filler, limit = 4096) {
  let n = 0;
  let body;
  do {
    n += 1;
    body = RECEIPT_SKELETON(filler.repeat(n));
  } while (body.length <= limit);
  return RECEIPT_SKELETON(filler.repeat(n - 1));
}

async function startDaemon(t) {
  const dir = tmpDir();
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.log');
  const socketPath = path.join(dir, 's.sock');
  fs.writeFileSync(pass, 'frame-surface-passphrase\n', { mode: 0o600 });

  const run = (args) => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [BIN, ...args], { cwd: REPO });
    let stderr = '';
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('error', reject);
    p.on('close', (code) => resolve({ code, stderr }));
  });

  let r = await run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(r.code, 0, `keygen failed: ${r.stderr}`);
  const publicKey = JSON.parse(fs.readFileSync(keystore, 'utf8')).publicKey;
  r = await run(['grant-add', '--grants', grants, '--name', 'ops',
    '--signer', publicKey, '--destination', publicKey,
    '--max-lamports', '1000000', '--window-max-lamports', '10000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(r.code, 0, `grant-add failed: ${r.stderr}`);

  const proc = spawn(process.execPath, [BIN, 'run',
    '--keystore', keystore, '--passphrase-file', pass, '--grants', grants,
    '--ledger', ledger, '--socket', socketPath],
    { cwd: REPO, stdio: ['ignore', 'pipe', 'pipe'] });
  let daemonStderr = '';
  proc.stderr.on('data', (d) => { daemonStderr += d; });

  for (let i = 0; i < 150 && !fs.existsSync(socketPath); i += 1) {
    await new Promise((res) => setTimeout(res, 100));
  }
  let up = false;
  for (let i = 0; i < 50 && !up; i += 1) {
    up = await new Promise((res) => {
      const s = net.connect(socketPath);
      s.on('connect', () => { s.destroy(); res(true); });
      s.on('error', () => res(false));
      setTimeout(() => { try { s.destroy(); } catch { /* gone */ } res(false); }, 200);
    });
    if (!up) await new Promise((res) => setTimeout(res, 100));
  }
  if (!up) { proc.kill(); throw new Error(`daemon did not start: ${daemonStderr}`); }

  t.after(() => {
    proc.kill();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  return { socketPath, keystore, dir };
}

test('request frame surface', async (t) => {
  const daemon = await startDaemon(t);

  // Bootstrap the MESSAGE grant through the documented product path
  // (sign-message --add-grant pins the keystore's canonical key and
  // maxBytes 700) and sign one small receipt on the way.
  const smallBodyPath = path.join(daemon.dir, 'small.json');
  fs.writeFileSync(smallBodyPath, RECEIPT_SKELETON('bootstrap'));

  const bootstrap = await new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, 'sign-message',
      '--socket', daemon.socketPath, '--grant', 'rel',
      '--body', smallBodyPath, '--add-grant', '--keystore', daemon.keystore],
      { cwd: REPO });
    let out = '', stderr = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (code) => resolve({ code, out, stderr }));
  });

  // G1 (guard, both trees): a small documented body signs through the real
  // CLI. If this fails nothing else here means anything.
  t.test('G1 small body signs through the documented path', () => {
    assert.strictEqual(bootstrap.code, 0,
      `bootstrap sign-message failed: ${bootstrap.stderr}`);
    const answer = JSON.parse(bootstrap.out);
    assert.strictEqual(answer.ok, true, `expected a signature: ${bootstrap.out.slice(0, 300)}`);
    assert.strictEqual(typeof answer.signature, 'string');
    assert.ok(answer.signature.length > 40, 'signature must be present');
  });

  // D1a (defect): a 4096-char CJK body — inside the documented char
  // contract, above the pre-fix 8704 frame cap. Premise pinned
  // independently: frame > OLD_CAP. The daemon must ANSWER (the grant's
  // 700-byte cap engages: message_too_large), never destroy silently.
  t.test('D1a body inside the 4096-char contract gets a verdict, not silence', async () => {
    const body = bodyAtLimit('\u4e2d');
    assert.ok(body.length <= 4096, `premise: body must stay at/under the limit, got ${body.length}`);
    assert.ok(body.length >= 4090, 'premise: body must reach the limit');
    const payload = JSON.stringify({ grant: 'rel', body });
    const frameBytes = Buffer.byteLength(payload, 'utf8');
    assert.ok(frameBytes > OLD_CAP_BYTES,
      `premise: frame (${frameBytes}) must exceed the pre-fix ${OLD_CAP_BYTES} cap`);

    const res = await rawRequest(daemon.socketPath, payload);
    assert.ok(res.answered,
      `daemon destroyed the connection without a verdict (closed=${res.closed}, ` +
      `timeout=${res.timeout}, frame=${frameBytes}B, body=${body.length}ch)`);
    assert.ok(res.response && typeof res.response.error === 'string',
      `expected a structured refusal, got ${JSON.stringify(res.response)}`);
    assert.strictEqual(res.response.error, 'message_too_large',
      `the grant's byte cap must be the named verdict: ${JSON.stringify(res.response)}`);
  });

  // D1b (defect): the worst case the old comment missed entirely — RAW
  // control characters in the JSON body TEXT re-escape to 6 bytes each
  // inside the frame (4096 * 6 + envelope ≈ 23.9 KB). Still inside the char
  // contract; the body text itself is invalid JSON, so the verdict must
  // arrive as body_invalid, not as silence.
  t.test('D1b worst-case re-escape body still gets a verdict', async () => {
    const head = '{"schema":"openreceipts/v1","issuer":"auroraxo","type":"release","subject":"auroraxo/signerd","issued_at":"2026-11-11T03:00:00Z","claims":{"note":"';
    const tail = '"}}';
    assert.ok(head.length + tail.length < 4096, 'fixture skeleton must leave room for the note');
    // Raw U+0001 bytes in the JSON TEXT. JSON.stringify must NOT be the
    // layer that escapes them here — the FRAME layer escaping them is the
    // mechanism under test (a fixture built via RECEIPT_SKELETON(\u0001…)
    // would double-escape and produce only ~4.8 KB frames).
    const body = head + '\u0001'.repeat(4096 - head.length - tail.length) + tail;
    assert.strictEqual(body.length, 4096, 'premise: body exactly at the documented char limit');
    let parses = true;
    try { JSON.parse(body); } catch { parses = false; }
    assert.ok(!parses, 'premise: raw control chars make the body text invalid JSON');
    const payload = JSON.stringify({ grant: 'rel', body });
    const frameBytes = Buffer.byteLength(payload, 'utf8');
    assert.ok(frameBytes > OLD_CAP_BYTES,
      `premise: control re-escape must exceed the pre-fix cap, got ${frameBytes}`);
    assert.ok(frameBytes > 20000,
      `premise: this is the 6-byte-per-char case, got ${frameBytes}`);

    const res = await rawRequest(daemon.socketPath, payload);
    assert.ok(res.answered,
      `silent destroy at ${frameBytes}B (closed=${res.closed}, timeout=${res.timeout})`);
    assert.ok(res.response && typeof res.response.error === 'string',
      `structured verdict expected: ${JSON.stringify(res.response)}`);
    assert.strictEqual(res.response.error, 'body_invalid',
      `raw control chars in JSON text are body_invalid, not silence: ${JSON.stringify(res.response)}`);
  });

  // D2 (defect): the byte-cap refusal itself must be NAMED. A frame over
  // the (raised) cap is answered with request_too_large, stating the
  // bound, before the connection goes away.
  t.test('D2 over-cap frame is refused by name before close', async () => {
    const payload = JSON.stringify({ grant: 'rel', body: 'x'.repeat(40000) });
    const frameBytes = Buffer.byteLength(payload, 'utf8');
    assert.ok(frameBytes > 25600, 'premise: frame must exceed the raised cap');

    const res = await rawRequest(daemon.socketPath, payload);
    assert.ok(res.answered,
      `over-cap frame was destroyed in silence (closed=${res.closed}, timeout=${res.timeout})`);
    assert.ok(res.response, `expected a JSON verdict: ${JSON.stringify(res.response)}`);
    assert.strictEqual(res.response.ok, false);
    assert.strictEqual(res.response.error, 'request_too_large',
      `named cap refusal expected: ${JSON.stringify(res.response)}`);
    assert.ok(typeof res.response.fix === 'string' && res.response.fix.includes('request frame'),
      `the refusal must name the repair: ${JSON.stringify(res.response)}`);
  });

  // G2 (guard, both trees): raising the FRAME cap must not disable the
  // documented 4096-CHAR body limit: a 4100-char ASCII body (small frame)
  // still refuses by name.
  t.test('G2 body-char limit still refuses by name at 4100 chars', async () => {
    const body = RECEIPT_SKELETON('a'.repeat(4100));
    assert.ok(body.length > 4096, 'fixture must cross the char limit');
    const payload = JSON.stringify({ grant: 'rel', body });
    assert.ok(Buffer.byteLength(payload, 'utf8') < 8704,
      'premise: this frame fits the OLD cap — the refusal is the char rule, not the frame');
    const res = await rawRequest(daemon.socketPath, payload);
    assert.ok(res.answered, 'an in-range frame must always be answered');
    assert.strictEqual(res.response && res.response.error, 'request_invalid');
  });
});

// D3 (defect): the shipped client must NAME a connection that closes
// without a verdict instead of hanging for its full timeout and blaming
// the clock (measured pre-fix: request_timeout after 12007 ms for a
// request the daemon had already destroyed at the transport layer).
test('D3 client names a verdict-less close instead of the timeout', async (t) => {
  const dir = tmpDir();
  const socketPath = path.join(dir, 'silent.sock');
  const silent = net.createServer((sock) => {
    sock.on('data', () => { sock.destroy(); }); // read, then close with no verdict
    sock.on('error', () => { /* ignore */ });
  });
  await new Promise((resolve) => silent.listen(socketPath, resolve));
  t.after(() => {
    silent.close();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ }
  });

  const started = Date.now();
  let settled;
  try {
    const answer = await request({ socketPath, grant: 'rel', body: '{}', timeoutMs: 8000 });
    settled = { kind: 'resolved', answer };
  } catch (err) {
    settled = { kind: 'rejected', code: err.code, message: err.message };
  }
  const waited = Date.now() - started;

  assert.strictEqual(settled.kind, 'rejected',
    `a verdict-less close must not resolve: ${JSON.stringify(settled)}`);
  assert.strictEqual(settled.code, 'connection_closed',
    `the client must name the close, not blame its own clock: ${JSON.stringify(settled)}`);
  assert.ok(waited < 4000,
    `the close must surface promptly, not after the full timeout (waited ${waited}ms)`);
});
