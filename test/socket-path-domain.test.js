'use strict';

// THE SOCKET PATH DOMAIN (2026-11-09).
//
// WHAT THE DOMAIN IS: the kernel's, not ours. `struct sockaddr_un` carries
// `char sun_path[108]`; measured on this host with a real bind+connect round
// trip: 108 bytes works, 109 bytes are EINVAL. The kernel measures BYTES of
// the string it was handed - a 90-character path that is 135 bytes is
// refused, while 105 ASCII bytes are accepted.
//
// THE DEFECT, measured on the pre-fix tree (dc75e63) before this file:
//   1. `path.resolve(socketPath).length > 100` judged CHARACTER counts of
//      the RESOLVED path against a number that is neither the limit nor the
//      right unit, so:
//        a) a 105-byte path the kernel ACCEPTS was refused (false refusal);
//        b) a 90-char / 135-byte path PASSED and died at bind with a raw
//           `EINVAL: listen EINVAL: invalid argument ...` - the daemon's own
//           refusal surface bypassed;
//   2. the refusal was `socket_path_too_long: ` - no value, no limit, no
//      repair, violating the house voice (test/grant-refusal-voice.test.js);
//   3. the CLIENT never preflighted: `signerd sign --socket <121 bytes>`
//      printed `EINVAL: connect EINVAL <path> - Local (undefined:undefined)`.
//
// THE RULES THIS PINS:
//   S1 the daemon refuses an over-limit path NAMING the byte count, the
//      limit and the repair (not an empty detail).
//   S2 the client refuses the same path with the SAME voice - one module
//      (src/socketpath.js) reads both sides.
//   S3 a multibyte path is judged in BYTES: 90 chars / 135 bytes is refused
//      by the constructor, never reaching bind().
//   S4 a 105-byte path the kernel accepts is NOT refused (the old code's
//      false refusal).
//   G1 (guard, green on both trees) a normal short path still signs
//      end-to-end through a live daemon.
//   G2 (guard, green on both trees) a path over the kernel limit is still
//      refused with code socket_path_too_long.
//   G3 (guard, green on both trees) a missing --socket is still
//      socket_path_required.
//
// Ladder: S1-S4 are RED on the pre-fix tree; G1-G3 are GREEN on both.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Daemon, request } = require('../src/daemon');
const { createKeystore, loadKeystore } = require('../src/keystore');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const PASSPHRASE = 'a passphrase for tests only';

/** An absolute path of EXACTLY `totalBytes` ASCII bytes ending in /s.sock. */
function exactLengthPath(dir, totalBytes) {
  const suffix = '/s.sock';
  const need = totalBytes - dir.length - suffix.length;
  assert.ok(need >= 1, `fixture dir ${dir} is too long to build a ${totalBytes}-byte path`);
  const p = `${dir}${'a'.repeat(need)}${suffix}`;
  assert.equal(Buffer.byteLength(p), totalBytes, 'the fixture path must be exactly the length it claims');
  return p;
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function fixture({ socketPath, construct = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  const recipient = Keypair.generate().publicKey;
  const keystore = path.join(dir, 'ops.key');
  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const grantFile = path.join(dir, 'grants.json');
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: keypair.publicKey.toBase58(),
        destination: recipient.toBase58(),
        maxLamports: '42',
        expiresAt: futureIso(),
        windowMaxLamports: '100000',
        windowSeconds: '3600',
      },
    },
  }, null, 2));
  const sock = socketPath || path.join(dir, 'signerd.sock');
  const build = () => new Daemon({
    socketPath: sock,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile: path.join(dir, 'journal.jsonl'),
  });
  // `construct: false` for the cases that EXPECT the constructor to throw.
  const daemon = construct ? build() : null;
  return { dir, daemon, build, socketPath: sock, keypair, recipient, keystore, grantFile };
}

function wire(keypair, recipient, lamports = 42) {
  const tx = new Transaction();
  tx.feePayer = keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: recipient, lamports }));
  tx.sign(keypair);
  return tx.serialize();
}

// ---------------------------------------------------------------------------
// S1: the daemon's refusal names the value, the limit and the repair.
// ---------------------------------------------------------------------------

test('S1 an over-limit socket path is refused with byte count, limit and repair', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  const tooLong = exactLengthPath(dir, 121);
  const f = fixture({ socketPath: tooLong, construct: false });
  assert.throws(
    () => f.build(),
    (err) => {
      assert.equal(err.code, 'socket_path_too_long');
      assert.match(err.message, /is 121 bytes/, `must name the byte count: ${err.message}`);
      assert.match(err.message, /at most 108 bytes/, `must name the limit: ${err.message}`);
      return true;
    },
    'a path over the kernel limit must be refused by the constructor',
  );
});

test('S1b the CLI prints the socket refusal with a repair line, not an empty detail', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  const tooLong = exactLengthPath(dir, 121);
  const txFile = path.join(dir, 'tx.bin');
  fs.writeFileSync(txFile, Buffer.alloc(215));
  const run = spawnSync(process.execPath, [
    CLI, 'sign', '--socket', tooLong, '--grant', 'ops', '--tx', txFile,
  ], { encoding: 'utf8', timeout: 30000 });
  assert.notEqual(run.status, 0, 'the refusal must be non-zero');
  assert.match(run.stderr, /^socket_path_too_long: \S/m, `empty detail: ${JSON.stringify(run.stderr)}`);
  assert.match(run.stderr, /is 121 bytes/, 'the refusal must name the value');
  assert.match(run.stderr, /^ {2}fix: /m, `the refusal must name the repair: ${JSON.stringify(run.stderr)}`);
  assert.doesNotMatch(run.stderr, /undefined:undefined/, 'no Node-internal text may leak');
  assert.doesNotMatch(run.stderr, /EINVAL/, 'no raw errno may reach the operator');
});

// ---------------------------------------------------------------------------
// S2: the client and the daemon are one voice (src/socketpath.js).
// ---------------------------------------------------------------------------

test('S2 the client refuses an over-limit path with the same code and repair', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  const tooLong = exactLengthPath(dir, 121);
  await assert.rejects(
    () => request({ socketPath: tooLong, grant: 'ops', wire: Buffer.alloc(215) }),
    (err) => {
      assert.equal(err.code, 'socket_path_too_long');
      assert.match(err.message, /is 121 bytes/);
      assert.match(err.fix, /fix: use a shorter --socket path/, 'the refusal carries its repair');
      return true;
    },
    'the client must refuse the path BEFORE the round trip',
  );
});

// ---------------------------------------------------------------------------
// S3: the unit is BYTES, not characters.
// ---------------------------------------------------------------------------

test('S3 a 90-character path that is 135 bytes is refused before bind', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  // 45 "a" + 45 "ä" = 90 characters, 45 extra bytes = 135 bytes total.
  const suffix = '/s.sock';
  const multibyte = 'ä'.repeat(45);
  const need = 135 - Buffer.byteLength(dir) - Buffer.byteLength(suffix) - Buffer.byteLength(multibyte);
  assert.ok(need >= 1, 'fixture dir too long');
  const p = `${dir}${'a'.repeat(need)}${multibyte}${suffix}`;
  assert.equal(p.length, 90, 'the path is 90 characters');
  assert.equal(Buffer.byteLength(p), 135, '... but 135 bytes');
  const f = fixture({ socketPath: p, construct: false });
  assert.throws(
    () => f.build(),
    (err) => {
      assert.equal(err.code, 'socket_path_too_long');
      assert.match(err.message, /is 135 bytes/, 'judged in BYTES');
      return true;
    },
    'a path the kernel would reject at bind() must be refused at construction',
  );
});

// ---------------------------------------------------------------------------
// S4: the false refusal - a path the kernel ACCEPTS must not be refused.
// ---------------------------------------------------------------------------

test('S4 a 105-byte socket path starts (the pre-fix code refused it)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  const socketPath = exactLengthPath(dir, 105);
  const f = fixture({ socketPath });
  await f.daemon.start();
  try {
    assert.equal(f.daemon.started, true, '105 bytes is inside the kernel domain (measured: 108 works)');
    const response = await request({ socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient) });
    assert.equal(response.ok, true, 'and it serves a real signature');
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// Guards: green on BOTH trees. They are the reason the fix cannot lie.
// ---------------------------------------------------------------------------

test('G1 a normal short path still signs end-to-end (guard, green on both trees)', async () => {
  const f = fixture();
  await f.daemon.start();
  try {
    const response = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(response.ok, true);
    assert.ok(response.signature, 'a signature must come back');
  } finally {
    await f.daemon.stop();
  }
});

test('G2 a path over the kernel limit is still refused with the same code (guard)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sockpath-'));
  const p = `${dir}${'b'.repeat(200)}/s.sock`;
  const f = fixture({ socketPath: p, construct: false });
  assert.throws(
    () => f.build(),
    (err) => err.code === 'socket_path_too_long',
  );
});

test('G3 a missing --socket is still socket_path_required (guard, green on both)', () => {
  assert.throws(
    () => new Daemon({
      socketPath: '',
      keystorePath: 'k',
      passphrase: PASSPHRASE,
      grantFile: 'g',
      ledgerFile: 'l',
    }),
    (err) => err.code === 'socket_path_required',
  );
});
