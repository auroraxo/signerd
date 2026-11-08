'use strict';

// THE RECOVERY CHANNEL MUST BE CHECKED, NOT ASSUMED.
//
// WHY (measured live 2026-11-08, on the tree that shipped v0.2.9 — the tree
// whose README says "On exit 3 the signed wire ... is still on stdout"):
//
// exit 3 means "the daemon signed, the file delivery failed". The product's
// promise for that exit is that the PAID-FOR artifact is recoverable: the
// signed wire (or the signed receipt document) is on stdout, so the operator
// salvages it instead of paying twice. The README sells exactly that:
//   | 3 | **the signature was made, the file delivery failed** |
//   "On exit 3 the signed wire (or the signed receipt document) is still on
//    stdout"
//
// Nothing checks whether the recovery channel can carry it. Measured on the
// published v0.2.9 behaviour, with the daemon signing for real:
//
//   CASE A — both channels dead at once.
//     `ulimit -f 0` (RLIMIT_FSIZE=0) and stdout redirected to a REGULAR FILE
//     (the normal way an operator/CI captures a CLI result: `... > signed.json`),
//     with `--out` also a regular file. Every write to a regular file fails
//     with EFBIG. The CLI writes the response with `process.stdout.write(...)`
//     (ASYNC) and immediately calls `process.exit(3)`.
//     Measured:
//        exit 3, stdout 0 bytes, stderr 0 bytes,
//        journal 366 -> 732 bytes (THE SPEND HAPPENED),
//        the --out file still holds its previous content,
//        retry of the same wire refused `{"error":"replay"}`,
//        and the journal holds only hashes — no signature. Unrecoverable.
//     The exit code says "signed, not written"; the truth is "signed, not
//     written, and NOT on stdout either".
//
//   CASE B — stdout is a device that always fails (/dev/full), --out fails too.
//     Same shape: exit 3, stdout 0 bytes, stderr 0 bytes, journal grew.
//
//   CASE C — the generic shape behind A and B: the response is written
//     ASYNCHRONOUSLY and the process exits immediately. On a healthy channel
//     the bytes usually land (measured 30/30 for a 64 KiB payload), but
//     "usually" is not the guarantee this exit code sells.
//
// WHY THIS IS A PRODUCT DEFECT AND NOT A HARNESS ARTIFACT:
//   stdout-is-a-file is the ordinary capture pattern. And the exit code's
//   whole meaning is "the artifact is here" — an exit code that can be
//   produced while the artifact is gone is a lie in the one place the
//   product promised truth. The journal proves the spend happened, so the
//   operator has paid and cannot retry: exit 3 is the last place the truth
//   could have been told.
//
// THE CONTRACT THIS FILE PINS (the ladder):
//
//   R1 (CASE A) A delivery failure must never report exit 3 UNLESS the
//       artifact ACTUALLY reached stdout. The response must be written
//       SYNCHRONOUSLY to fd 1 and the write VERIFIED. If stdout cannot take
//       the artifact, do not claim it can — and never go silent.
//   R2 (CASE B) Same for a device channel that always fails: the CLI must
//       VERIFY the stdout write, and when the verification fails it must say
//       `recovery_failed` on stderr instead of implying the artifact is on
//       stdout. An exit 3 that claims a recovery the channel never carried
//       fails this case even though stdout itself is unreadable here.
//   R3 (CASE C, guard) With a healthy stdout the response must land
//       COMPLETELY: the exit-3 contract (signed wire on stdout) must hold on
//       a pipe under the delivery failure. Green on both trees; a fix that
//       breaks the healthy recovery path fails here.
//   R4 (CASE D) stdout pointing at /dev/null is a channel that RETAINS
//       nothing: the write succeeds, the bytes are gone. "No error" is not
//       proof of delivery; the CLI must not claim exit 3 either.
//   R5 (CASE E) a PARTIAL write: `ulimit -f 1` lets 1024 bytes through to a
//       regular file and fails the next one with EFBIG. The first write
//       SUCCEEDS, so a "did it throw?" check does not catch it — but a
//       truncated artefact is not an artefact. Measured on the pre-fix tree:
//       exit 3 with exactly 1024 bytes of truncated JSON on stdout.
//   G1 GUARD (green both trees): the ORDINARY success path with
//       stdout-to-file capture is unchanged (exit 0, ok:true).
//   G2 GUARD (green both trees): the ordinary pipe path is unchanged.
//   G3 GUARD (green both trees): the example client (the documented
//       user-zero path) keeps its contract.
//
// Ladder: R1/R2/R4/R5 are RED on the pre-fix tree (0059c7a / v0.2.9) —
// measured, not assumed: `research/recovery-channel-2026-11-08/red-baseline.txt`
// holds the captured run (4 red, 4 green) against the real pre-fix binaries
// in a separate worktree.
// R3/G1..G3 are green on BOTH trees, so the fix cannot be "make it pass by
// changing the healthy path".

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const CLIENT = path.join(ROOT, 'examples', 'user-zero-client.js');
const { Daemon } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');
const { addGrantToFile } = require('../src/grantadd');
const { buildTransferWire } = require('../src/client');
const { Keypair } = require('@solana/web3.js');

const PASSPHRASE = 'recovery-channel-pass';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-recovery-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Run the CLI under `ulimit -f 0` (RLIMIT_FSIZE=0: every write to a REGULAR
 * FILE fails with EFBIG), with a choice of where stdout goes:
 *
 *   stdoutKind 'pipe'   — a healthy pipe (the ordinary case).
 *   stdoutKind 'file'   — a REGULAR FILE: the CI/operator capture pattern
 *                         (`signerd sign ... > signed.json`). Under the limit
 *                         this channel is DEAD — CASE A.
 *   stdoutKind 'device' — stdoutPath, e.g. /dev/full: a device that accepts
 *                         the open and fails every write — CASE B.
 *
 * stderr is ALWAYS a pipe, so the CLI's own words are readable even when
 * stdout is a device. The daemon runs in the test process (no limit), so the
 * journal keeps working and the spend premise is unaffected.
 */
function run(exe, argv, { limit = false, stdoutKind = 'pipe', stdoutPath = null, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    let stdoutFd = null;
    let outPath = stdoutPath;
    if (stdoutKind === 'file') {
      outPath = outPath || path.join(tmpDir(), 'stdout.json');
      stdoutFd = fs.openSync(outPath, 'w');
    } else if (stdoutKind === 'device') {
      stdoutFd = fs.openSync(outPath, 'w');
    }
    const quoted = [process.execPath, exe, ...argv]
      .map((a) => `"${String(a).replace(/"/g, '\\"')}"`).join(' ');
    // `limit: true` defaults to 0 (no bytes allowed); a numeric limit sets
    // the 1 KiB block count (e.g. limit: 1 allows 1024 bytes, the threshold
    // for measuring partial writes).
    const limitBlocks = limit === true ? 0 : (typeof limit === 'number' ? limit : null);
    const command = limitBlocks !== null ? `ulimit -f ${limitBlocks}; exec ${quoted}` : `exec ${quoted}`;
    const stdio = stdoutFd === null ? ['ignore', 'pipe', 'pipe'] : ['ignore', stdoutFd, 'pipe'];
    const child = spawn('bash', ['-c', command], { stdio });
    let stderr = '';
    let piped = '';
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    if (child.stdout) child.stdout.on('data', (d) => { piped += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => {
      clearTimeout(timer);
      if (stdoutFd !== null) { try { fs.closeSync(stdoutFd); } catch { /* ignore */ } }
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      let stdout = '';
      if (stdoutFd !== null) {
        // NEVER read a device back: /dev/full is an endless stream of zeros
        // and reading it would allocate until the process is killed.
        if (stdoutKind === 'file') {
          try { stdout = fs.readFileSync(outPath, 'utf8'); } catch { stdout = ''; }
        }
        try { fs.closeSync(stdoutFd); } catch { /* ignore */ }
      } else {
        stdout = piped;
      }
      resolve({ code, timedOut, stdout, stderr, stdoutPath: outPath });
    });
  });
}

/** Run the CLI with NO limit — the healthy capture paths (guards). */
function runPlain(exe, argv, opts = {}) {
  return run(exe, argv, { ...opts, limit: false });
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

  // A message grant, so the sign-message path (the receipt document, which
  // is a much LARGER exit-3 payload than the wire) can be measured too.
  addGrantToFile({
    file: grants,
    name: 'releases',
    grant: {
      kind: 'message',
      issuer: 'auroraxo',
      type: 'release',
      subject: 'auroraxo/signerd',
      pubkey: keypair.publicKey.toBuffer().toString('base64'),
      maxBytes: '3000',
      expiresAt: futureIso(),
      windowMaxMessages: '100',
      windowSeconds: '3600',
    },
  });

  const daemon = new Daemon({
    socketPath: socket,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile: grants,
    ledgerFile: ledger,
  });
  await daemon.start();

  let n = 0;
  let m = 0;
  return {
    dir, keystore, grants, ledger, socket,
    keypair, destination,
    writeTx() {
      n += 1;
      const tx = path.join(dir, `tx-${n}.bin`);
      fs.writeFileSync(tx, buildTransferWire({
        fromPubkey: keypair.publicKey.toBase58(),
        toPubkey: destination,
        lamports: 42,
        blockhash: Keypair.generate().publicKey.toBase58(),
      }), { mode: 0o600 });
      return tx;
    },
    /**
     * A receipt body big enough that the sign-message exit-3 payload EXCEEDS
     * 1024 bytes — the size at which a write under `ulimit -f 1` lands
     * PARTIALLY (1024 bytes) and then fails with EFBIG. That is the only
     * way to measure whether a truncated artefact is caught rather than
     * claimed.
     */
    writeBody() {
      m += 1;
      const claims = {};
      for (let i = 0; i < 12; i++) {
        claims[`claim_${i}`] = `value-${i}-padding-to-inflate-the-body-size`;
      }
      const body = {
        schema: 'openreceipts/v1',
        issuer: 'auroraxo',
        subject: 'auroraxo/signerd',
        type: 'release',
        claims,
        issued_at: new Date(Math.floor(Date.now() / 1000) * 1000)
          .toISOString().replace(/\.\d{3}Z$/, 'Z'),
      };
      const file = path.join(dir, `body-${m}.json`);
      fs.writeFileSync(file, JSON.stringify(body), { mode: 0o600 });
      return file;
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
// R1 — CASE A: stdout is a REGULAR FILE (the CI/operator capture pattern),
// RLIMIT_FSIZE=0 kills both the --out delivery and the stdout write, the
// daemon DOES sign (the journal proves the spend), and the CLI must not exit
// 3 unless the signed wire is really on stdout.
//
// This is the measured, reproducible way to lose a paid-for signature.
// ---------------------------------------------------------------------------

test('R1 exit 3 is allowed only when the signed wire ACTUALLY reached stdout (CASE A)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  fs.writeFileSync(out, 'PRIOR', { mode: 0o600 });

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);

  const r = await run(CLI,
    ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { limit: true, stdoutKind: 'file' });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(journalBytes(f.ledger) > before, true,
    'the daemon DID sign (journal grew): the spend happened — this is the premise');

  const json = firstJson(r.stdout);
  if (r.code === 3) {
    // Exit 3 promises the signed wire on stdout. This is exactly where the
    // pre-fix tree fails: exit 3 with 0 bytes on stdout.
    assert.ok(json,
      `exit 3 promises the signed wire on stdout, but stdout carried ` +
      `${r.stdout.length} bytes; stderr: ${JSON.stringify(r.stderr)}`);
    assert.equal(typeof json.signed, 'string',
      'exit 3 must carry the signed wire (the signed bytes are the artifact)');
    assert.ok(json.outError, 'outError must name the failed delivery');
    // If exit 3 is claimed, the artifact must be the REAL signed wire.
    const wire = Buffer.from(json.signed, 'base64');
    assert.ok(wire.length > 0, 'the recovery artifact must be non-empty bytes');
  } else {
    assert.notEqual(r.code, 3,
      `the CLI must not claim the recoverable exit 3 when the artifact never ` +
      `reached stdout (stdout ${r.stdout.length} bytes)`);
    assert.ok(r.stderr.length > 0,
      'a CLI that could not deliver the artifact must SAY SO — silence is the defect');
    assert.ok(/recovery_failed|out_write_failed/i.test(r.stderr),
      `stderr must name the dead recovery channel, got: ${JSON.stringify(r.stderr)}`);
  }
});

// ---------------------------------------------------------------------------
// R2 — CASE B: stdout is a device that always fails (/dev/full) while the
// --out delivery also fails. The daemon signs (premise), and the CLI must
// VERIFY the stdout write rather than assume it.
//
// /dev/full is a character device, so RLIMIT_FSIZE does not touch the stdout
// write: only the --out file write fails (EFBIG). stdout is unreadable here,
// so the observable contract is the CLI's own statement: an exit 3 that never
// verified the channel must not add "the recovery channel is also dead".
// ---------------------------------------------------------------------------

test('R2 a dead device recovery channel must be VERIFIED and named (CASE B)', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  fs.writeFileSync(out, 'PRIOR', { mode: 0o600 });

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);

  // stdout -> /dev/full (every write fails with ENOSPC), --out -> a regular
  // file that cannot grow (EFBIG). stderr stays a pipe so the CLI's words
  // are readable.
  const r = await run(CLI,
    ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { limit: true, stdoutKind: 'device', stdoutPath: '/dev/full' });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(journalBytes(f.ledger) > before, true,
    'the daemon DID sign — the spend happened (the premise of the case)');

  assert.ok(r.stderr.length > 0,
    'the CLI must never be silent when both delivery channels fail');
  assert.ok(/recovery_failed|out_write_failed/i.test(r.stderr),
    `stderr must name the failed delivery, got: ${JSON.stringify(r.stderr)}`);

  if (r.code === 3) {
    // Exit 3 still claims "the artifact is on stdout". That claim is only
    // allowed if the write to stdout was VERIFIED — i.e. the CLI itself
    // learned that stdout carried it. A pre-fix CLI never checks, so it can
    // never say the channel is dead: that silence is the defect.
    assert.ok(/recovery_failed/i.test(r.stderr),
      'exit 3 on a dead recovery channel requires an explicit ' +
      '`recovery_failed` statement that the stdout write was attempted and ' +
      `failed — got only: ${JSON.stringify(r.stderr)}`);
  } else {
    assert.notEqual(r.code, 3, 'no silent exit 3');
    assert.ok(/recovery_failed/i.test(r.stderr),
      `stderr must carry the recovery_failed statement, got: ${JSON.stringify(r.stderr)}`);
  }
});

// ---------------------------------------------------------------------------
// R4 — CASE D: stdout points at /dev/null. The write SUCCEEDS and the bytes
// are DISCARDED. A "no error" check would still be lying here: nothing
// retains what was written, so the artifact is gone exactly as in CASE A,
// while the CLI would have said "the signature is on stdout".
//
// Added after the red baseline was captured for R1/R2 (the baseline file
// records the 6-test ladder; this case is the 7th, measured the same way).
// ---------------------------------------------------------------------------

test('R4 a stdout that DISCARDS bytes must not be claimed as a recovery channel', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  fs.writeFileSync(out, 'PRIOR', { mode: 0o600 });

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);

  const r = await run(CLI,
    ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { limit: true, stdoutKind: 'device', stdoutPath: '/dev/null' });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(journalBytes(f.ledger) > before, true, 'the daemon DID sign (the spend happened)');

  assert.ok(r.stderr.length > 0, 'the CLI must never be silent');
  assert.ok(/recovery_failed|out_write_failed/i.test(r.stderr),
    `stderr must name the failed delivery, got: ${JSON.stringify(r.stderr)}`);
  assert.notEqual(r.code, 3,
    'exit 3 promises the artifact is on stdout; a discarding stdout cannot keep it');
  assert.ok(/recovery_failed/i.test(r.stderr),
    `stderr must carry the recovery_failed statement, got: ${JSON.stringify(r.stderr)}`);
});

// ---------------------------------------------------------------------------
// R5 — CASE E: the PARTIAL write. `ulimit -f 1` allows 1024 bytes to a
// regular file and fails the next one with EFBIG. The receipt document is
// 1099 bytes and the exit-3 payload 1402 bytes, so the write lands HALF the
// artefact and then fails.
//
// This is the case a "did the write throw?" check does NOT catch: the first
// write SUCCEEDED. A response that was cut in half is not the artefact, and
// the operator would parse truncated JSON — or, worse, a truncated receipt
// that still verifies.
//
// The contract: a partial write is a FAILED delivery. The CLI must not exit
// 3 on it, and it must say so.
// ---------------------------------------------------------------------------

test('R5 a PARTIAL write must not be reported as a delivered artefact', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'receipt.json');
  const body = f.writeBody();
  const before = journalBytes(f.ledger);

  // 1 KiB limit: the --out receipt (1099 bytes) fails with EFBIG, and the
  // stdout payload (1402 bytes) would land 1024 bytes and then fail.
  const r = await run(CLI,
    ['sign-message', '--socket', f.socket, '--grant', 'releases', '--body', body, '--out', out],
    { limit: 1, stdoutKind: 'file' });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(journalBytes(f.ledger) > before, true, 'the daemon DID sign (the spend happened)');

  if (r.code === 3) {
    // Exit 3 claims the artefact is on stdout. With a 1 KiB cap and a
    // 1402-byte payload, a COMPLETE delivery is impossible — so either the
    // file carried fewer bytes than the payload (truncated), or the claim is
    // false. Both are defects.
    const complete = r.stdout.endsWith('\n') && r.stdout.trim().length > 0
      && (() => { try { JSON.parse(r.stdout.trim()); return true; } catch { return false; } })();
    assert.ok(complete,
      `exit 3 on a 1 KiB cap must still carry a COMPLETE JSON artefact; ` +
      `got ${r.stdout.length} bytes: ${JSON.stringify(r.stdout.slice(0, 200))}`);
  } else {
    assert.ok(r.stderr.length > 0, 'a failed delivery must SAY SO');
    assert.ok(/recovery_failed|out_write_failed/i.test(r.stderr),
      `stderr must name the failed delivery, got: ${JSON.stringify(r.stderr)}`);
    // And the truncated stdout must not be mistaken for an artefact.
    assert.ok(!firstJson(r.stdout) || r.stdout.length < 1402,
      'a truncated payload must not be presented as the complete artefact');
  }
});

// ---------------------------------------------------------------------------
// R3 — CASE C guard: with a HEALTHY stdout (a pipe) and a delivery failure,
// the exit-3 contract must still hold and the response must arrive
// COMPLETELY. Green on both trees: it pins that the fix does not break the
// ordinary recovery path.
// ---------------------------------------------------------------------------

test('R3 GUARD a healthy pipe stdout still gets the complete exit-3 response', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  fs.writeFileSync(out, 'PRIOR', { mode: 0o600 });

  const tx = f.writeTx();
  const before = journalBytes(f.ledger);

  // The limit kills the --out write (EFBIG) while stdout is a healthy pipe.
  const r = await run(CLI,
    ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { limit: true, stdoutKind: 'pipe' });

  assert.equal(r.timedOut, false, 'the CLI must not hang');
  assert.equal(journalBytes(f.ledger) > before, true, 'the daemon DID sign');

  assert.equal(r.code, 3,
    `a delivery failure on a healthy stdout must still be exit 3 (recovery ` +
    `contract unchanged): code=${r.code} stdout=${r.stdout.length}b ` +
    `stderr=${JSON.stringify(r.stderr)}`);
  const json = firstJson(r.stdout);
  assert.ok(json, `the response must be COMPLETELY on stdout: ${r.stdout.length} bytes`);
  assert.equal(json.ok, true, `the daemon signed: ${r.stdout}`);
  assert.equal(typeof json.signed, 'string', 'the signed wire must be on stdout');
  assert.ok(json.outError, 'outError must name the failed delivery');
});

// ---------------------------------------------------------------------------
// G1 GUARD — the ORDINARY success path with stdout captured to a FILE is
// unchanged. Green on both trees; a fix that breaks ordinary capture fails
// here.
// ---------------------------------------------------------------------------

test('G1 GUARD ordinary stdout-to-file capture still gets exit 0 with ok:true', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  const tx = f.writeTx();

  const r = await run(CLI,
    ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out],
    { stdoutKind: 'file' });

  assert.equal(r.code, 0, `ordinary capture must succeed: ${r.stdout} ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json && json.ok === true, `expected ok:true: ${r.stdout}`);
  assert.equal(json.signed, undefined, 'on success the raw wire stays out of stdout');
  assert.ok(fs.existsSync(out) && fs.statSync(out).size > 0, '--out must hold the wire');
});

// ---------------------------------------------------------------------------
// G2 GUARD — the ordinary pipe path is unchanged (exit 0, ok:true).
// ---------------------------------------------------------------------------

test('G2 GUARD the ordinary pipe path is unchanged', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'signed.bin');
  const tx = f.writeTx();
  const r = await run(CLI,
    ['sign', '--socket', f.socket, '--grant', 'ops', '--tx', tx, '--out', out]);
  assert.equal(r.code, 0, `the ordinary path must succeed: ${r.stdout} ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json && json.ok === true, `expected ok:true: ${r.stdout}`);
  assert.equal(json.signed, undefined, 'on success the raw wire stays out of stdout');
});

// ---------------------------------------------------------------------------
// G3 GUARD — the example client (the documented user-zero path) keeps its
// contract: exit 0/3 with a readable stdout, and a clean refusal when the
// --out cannot be used.
// ---------------------------------------------------------------------------

test('G3 GUARD the example client keeps its exit-code and stdout contract', async (t) => {
  const f = await fixture();
  t.after(() => f.stop());
  const out = path.join(f.dir, 'client.bin');

  const argv = [
    '--socket', f.socket, '--grant', 'ops',
    '--from', f.keypair.publicKey.toBase58(),
    '--to', f.destination,
    '--lamports', '42',
    '--blockhash', Keypair.generate().publicKey.toBase58(),
    '--out', out,
  ];
  const r = await run(CLIENT, argv);
  assert.equal(r.timedOut, false, 'the example must not hang');
  assert.ok([0, 3].includes(r.code), `unexpected exit ${r.code}: ${r.stdout} ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json, `stdout must carry JSON: ${r.stdout}`);
  assert.equal(json.ok, true, `the daemon signed: ${r.stdout}`);
  if (r.code === 3) {
    assert.equal(typeof json.signed, 'string',
      'the example client must also carry the signed wire on exit 3');
  }
});
