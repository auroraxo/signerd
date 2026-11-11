#!/usr/bin/env node
'use strict';
// Puls R probe: does every request frame the body contract admits get a
// NAMED verdict, and is every refused frame refused BY NAME?
//
// Measured on v0.2.14 (tree 1342aea) before the fix: MAX_REQUEST_BYTES was
// 8704, derived as 4096*2 + ~90 = 8282 ("worst case every character escapes
// to two"). JSON.stringify does not escape non-ASCII (CJK = 3 UTF-8 bytes)
// and re-escapes control chars to 6 bytes, so bodies INSIDE the documented
// 4096-char limit produced frames of 12000-24000 bytes -> buffer cap fired
// BEFORE the newline scan -> socket.destroy() with no response line
// ("silent-destroy"); the shipped client reported its own request_timeout
// after 12 s.
//
// Post-fix the cap is derived from the true worst case (4096*6 + envelope
// = 25600), an over-cap frame gets {ok:false, error:"request_too_large"},
// and the client names a verdict-less close (connection_closed).
//
// Cases (id: expectation on a conforming tree):
//   S1  5000 ASCII chars  (frame < cap, body text > 4096) -> request_invalid
//   S2  9000 ASCII chars  (old cap < frame < new cap)     -> message_too_large
//   S3  ~4000 CJK chars   (body <= 4096, old cap < frame < new cap)
//                                                         -> message_too_large
//   S4  25500 ASCII chars (frame > new cap)               -> request_too_large
//   G2  4096+ ASCII chars (frame < cap, body text > 4096) -> request_invalid
//   G1  small body        (guard: the happy path still answers) -> ok
//
// On the pre-fix tree S2/S3/S4 answer nothing (silent destroy) — the same
// script is the red/green instrument. Exit 0: verdict written. Exit 3:
// harness failure.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
process.umask(0o077);

function fail(msg) { console.error(msg); process.exit(3); }

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { cwd: REPO, ...opts });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', reject);
    p.on('close', (code) => resolve({ code, out, err }));
  });
}

/** Raw socket client: send one frame, record what comes back (or that nothing does). */
function probe(socketPath, payload, waitMs = 4000) {
  return new Promise((resolve) => {
    const net = require('node:net');
    const socket = net.connect(socketPath);
    let buf = Buffer.alloc(0);
    let outcome = { answered: false, closed: false, error: null };
    const done = () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(outcome);
    };
    const timer = setTimeout(() => { outcome.timeout = true; done(); }, waitMs);
    socket.on('connect', () => socket.write(payload + '\n'));
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a);
      if (nl !== -1) {
        outcome.answered = true;
        try { outcome.response = JSON.parse(buf.subarray(0, nl).toString('utf8')); }
        catch { outcome.response = { unparseable: buf.subarray(0, nl).toString('utf8').slice(0, 200) }; }
        done();
      }
    });
    socket.on('close', () => { outcome.closed = true; done(); });
    socket.on('error', (err) => { outcome.error = err.code || err.message; outcome.closed = true; done(); });
  });
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-frame-'));
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  const grants = path.join(dir, 'grants.json');
  const ledger = path.join(dir, 'journal.log');
  const socket = path.join(dir, 's.sock');
  fs.writeFileSync(pass, 'probe-passphrase\n');
  process.env.CC = process.env.CC || 'cc';

  let r = await run(process.execPath, [path.join(REPO, 'bin', 'signerd.js'), 'keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (r.code !== 0) fail(`keygen failed: ${r.err}`);
  const ks = JSON.parse(fs.readFileSync(keystore, 'utf8'));
  r = await run(process.execPath, [path.join(REPO, 'bin', 'signerd.js'), 'grant-add',
    '--grants', grants, '--name', 'probe', '--signer', ks.publicKey,
    '--destination', ks.publicKey, '--max-lamports', '1000000',
    '--window-max-lamports', '10000000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z']);
  if (r.code !== 0) fail(`grant-add failed: ${r.err}`);

  const daemon = spawn(process.execPath, [path.join(REPO, 'bin', 'signerd.js'), 'run',
    '--keystore', keystore, '--passphrase-file', pass, '--grants', grants,
    '--ledger', ledger, '--socket', socket], { cwd: REPO, stdio: ['ignore', 'pipe', 'pipe'] });
  let daemonErr = '';
  daemon.stderr.on('data', (d) => { daemonErr += d; });

  // Wait for the socket to accept connections.
  for (let i = 0; i < 100; i += 1) {
    if (fs.existsSync(socket)) break;
    await new Promise((res) => setTimeout(res, 100));
  }
  let up = false;
  for (let i = 0; i < 50 && !up; i += 1) {
    up = await new Promise((res) => {
      const net = require('node:net');
      const s = net.connect(socket);
      s.on('connect', () => { s.destroy(); res(true); });
      s.on('error', () => res(false));
      setTimeout(() => { try { s.destroy(); } catch {} res(false); }, 200);
    });
    if (!up) await new Promise((res) => setTimeout(res, 100));
  }
  if (!up) { daemon.kill(); fail(`daemon did not start: ${daemonErr}`); }

  // Bootstrap the MESSAGE grant through the documented product path
  // (sign-message --add-grant), exactly like test/request-frame.test.js:
  // without it every body probe is judged grant_kind_mismatch (the tx
  // grant from grant-add) and never reaches the message policy at all.
  const smallBody = path.join(dir, 'small.json');
  fs.writeFileSync(smallBody, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'probe',
    subject: 'auroraxo/signerd', issued_at: '2026-11-11T03:00:00Z',
    claims: { note: 'bootstrap' },
  }));
  r = await run(process.execPath, [path.join(REPO, 'bin', 'signerd.js'), 'sign-message',
    '--socket', socket, '--grant', 'rel', '--body', smallBody,
    '--add-grant', '--keystore', keystore]);
  if (r.code !== 0) fail(`sign-message bootstrap failed: ${r.err}`);
  const bootAnswer = JSON.parse(r.out);
  if (bootAnswer.ok !== true) fail(`bootstrap did not sign: ${r.out.slice(0, 200)}`);

  const bodyOf = (text) => JSON.stringify({
    grant: 'rel',
    body: JSON.stringify({
      schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'probe',
      subject: 'auroraxo/signerd', issued_at: '2026-11-11T03:00:00Z',
      claims: { note: text },
    }),
  });

  const cases = {};
  // S1: body text over 4096 chars, frame under the cap -> named body refusal.
  cases.S1 = { desc: '5000 ASCII chars (body-limit refusal, frame < cap)', payload: bodyOf('a'.repeat(5000)), expect: 'request_invalid' };
  // S2: frame between the OLD cap (8704) and the new one; body text over the
  // 4096-char limit, so the char rule — not the transport — must judge.
  cases.S2 = { desc: '9000 ASCII chars (old cap < frame < new cap)', payload: bodyOf('a'.repeat(9000)), expect: 'request_invalid' };
  // S3: body INSIDE the documented 4096-char limit (3900 CJK + skeleton ≈
  // 4080 chars), frame over the OLD cap -> the grant's byte cap judges.
  cases.S3 = { desc: '3900 CJK chars (body <= 4096, old cap < frame < new cap)', payload: bodyOf('\u4e2d'.repeat(3900)), expect: 'message_too_large' };
  // S4: frame over the NEW cap -> refused by name, never destroyed.
  cases.S4 = { desc: '26000 ASCII chars (frame > new cap)', payload: bodyOf('a'.repeat(26000)), expect: 'request_too_large' };
  // G2: over the documented body limit, frame under cap.
  cases.G2 = { desc: '4096+ ASCII chars (body limit, frame < cap)', payload: bodyOf('a'.repeat(4096)), expect: 'request_invalid' };
  // G1: small body -> normal answer (either signature or a policy refusal,
  // but a structured {ok:...} line from the daemon).
  cases.G1 = { desc: 'small ASCII body (guard)', payload: bodyOf('ok'), expect: 'ok' };

  for (const [id, c] of Object.entries(cases)) {
    c.frameBytes = Buffer.byteLength(c.payload, 'utf8');
    const res = await probe(socket, c.payload);
    c.answered = res.answered;
    c.verdict = res.answered ? (res.response && (res.response.ok === true ? 'ok' : res.response.error)) : null;
    c.transport = res.error ? `error:${res.error}` : res.timeout ? 'timeout' : res.closed ? 'closed-no-answer' : 'open';
  }

  daemon.kill();
  await new Promise((res) => daemon.on('close', res));
  fs.rmSync(dir, { recursive: true, force: true });

  const daemonSource = fs.readFileSync(path.join(REPO, 'src', 'daemon.js'), 'utf8');
  const capMatch = daemonSource.match(/MAX_REQUEST_BYTES = ([\d_]+);/);
  if (!capMatch) fail('MAX_REQUEST_BYTES not found in src/daemon.js');
  const maxRequestBytes = Number(capMatch[1].replace(/_/g, ''));
  const out = {
    tool: 'measure-request-frame',
    date: '2026-11-11',
    tree: process.env.TREE_LABEL || 'worktree',
    maxRequestBytes,
    cases: {},
  };
  for (const [id, c] of Object.entries(cases)) {
    out.cases[id] = {
      desc: c.desc, frameBytes: c.frameBytes, expect: c.expect,
      answered: c.answered, verdict: c.verdict, transport: c.transport,
      // A contract violation is: no verdict at all (silent transport), or a
      // verdict other than the documented expectation.
      silent: c.answered === false,
      violation: c.answered !== true || c.verdict !== c.expect,
    };
  }
  const silentCount = Object.values(out.cases).filter((c) => c.silent).length;
  const violations = Object.values(out.cases).filter((c) => c.violation).map((c) => Object.keys(out.cases).find((k) => out.cases[k] === c));
  out.silentCases = silentCount;
  out.violations = violations;
  out.verdict = violations.length === 0 ? 'refusals-present' : 'violations-present';

  const outFile = process.argv[2] || path.join(REPO, 'research', 'request-frame-2026-11-11.json');
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2) + '\n');
  console.log(JSON.stringify({ ...out, outFile }, null, 2));
  process.exit(0);
}

main().catch((err) => { console.error(err && err.stack || err); process.exit(3); });
