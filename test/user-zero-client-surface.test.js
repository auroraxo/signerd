'use strict';

// THE USER-ZERO CLIENT'S OWN FLAG SURFACE (measured 2026-11-07, live).
//
// WHY (measured, this repo, pre-fix tree dabb688):
//
// `bin/signerd` got a strict flag surface on 2026-11-06 (unknown flag ->
// unknown_flag) and a strict flag ARITY surface on 2026-11-07 (a flag given
// twice -> duplicate_flag, a value flag with no value -> missing_value, a
// switch given a value -> flag_takes_no_value). Both were real fail-opens:
// a typo'd flag was dropped, a duplicated flag silently took the last value,
// and `--dry true` became a REAL signature.
//
// The EXAMPLE CLIENT - `examples/user-zero-client.js`, the file that ships
// in the npm package under "files": ["examples"] and the executable form the
// README points a stranger at - kept its OWN parseArgs. It was never
// measured. Measured live against the real daemon (pre-fix, exit codes and
// journal deltas from the run that produced this file):
//
//   U1  --totally-unknown x      -> exit 0, a REAL signature, 366 journal
//                                   bytes, --out written. The flag was
//                                   dropped without a word.
//   U2  --lamports 22 --lamports 999
//                                -> exit 0, a REAL signature for 999
//                                   lamports. Last wins, silently: the
//                                   operator named 22 first.
//   U3  --out (no value)         -> exit 0, a REAL signature. The --out
//                                   flag was read as absent.
//   U4  --hold yes               -> exit 0, a REAL signature. A switch
//                                   was given a value.
//   U5  --dry                    -> exit 0, a REAL signature, 366 journal
//                                   bytes, --out written. THE REVERSE of
//                                   what the flag means: the README says
//                                   a dry run signs nothing.
//   U6  --dry, then the SAME wire signed for real
//                                -> the second run is REFUSED `replay`,
//                                   because the "dry" run really signed.
//                                   A dry that is not dry consumes the
//                                   budget it promised to leave alone.
//
// The client is the FIRST thing a user-zero adopter touches: it is the
// documented way to ask for a signature without holding a key. A client
// that drops flags is a client that signs something the operator did not
// ask for.
//
// THE RULES (the example client refuses BEFORE it talks to the daemon):
//   U1 a flag the client does not take is refused (`unknown_flag`),
//      naming the flag and the repair;
//   U2 a flag given TWICE is refused (`duplicate_flag`), naming BOTH
//      values - the client cannot know which one was meant, and last-wins
//      silently changes what is signed;
//   U3 a value flag given NO value is refused (`missing_value`);
//   U4 a switch given a value is refused (`flag_takes_no_value`);
//   U5 --dry is a PREVIEW: the daemon's verdict, no signature, no --out,
//      no journal record, no window spend;
//   U6 the falsification: an ALLOWED dry run leaves the machine untouched,
//      so the IDENTICAL request still signs for real afterwards.
//
// GUARDS (green on both trees): a plain invocation still signs, the signed
// wire still verifies under the fee payer's public key, and --out is still
// written owner-only.
//
// LIMITS: this is argument hygiene in the EXAMPLE client, not a sandbox.
// The value of a flag is judged by the daemon (the cap, the destination,
// the policy); this file only refuses shapes that must not be guessed.
// It says nothing about the wire frame - the daemon is still the judge of
// that, and the daemon's own dry contract is pinned by
// test/dry-run-surface.test.js and test/dry-consumer-falsification.test.js.

process.umask(0o077);

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair } = require('@solana/web3.js');

const { Daemon } = require('../src/daemon');
const { importKeystore } = require('../src/keystore');

const ROOT = path.resolve(__dirname, '..');
const CLIENT = path.join(ROOT, 'examples', 'user-zero-client.js');
const PASSPHRASE = 'user-zero client surface passphrase';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-client-surface-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Run the example client as a separate process; resolve with its verdict. */
function runClient(argv, { cwd = ROOT, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLIENT, ...argv], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`client timed out; saw: ${stdout.slice(0, 300)} ${stderr.slice(0, 300)}`));
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('exit', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

/** The fixture: a real daemon on a real socket, one transaction grant. */
async function fixture(t) {
  const dir = tmpDir();
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const keypair = Keypair.generate();
  const destination = Keypair.generate().publicKey.toBase58();

  const raw = path.join(dir, 'ops.raw');
  fs.writeFileSync(raw, Buffer.from(keypair.secretKey.subarray(0, 64)), { mode: 0o600 });
  const keystore = path.join(dir, 'ops.key');
  importKeystore({ file: keystore, passphrase: PASSPHRASE, from: raw });
  fs.unlinkSync(raw);

  const grantFile = path.join(dir, 'grants.json');
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: keypair.publicKey.toBase58(),
        destination,
        maxLamports: '1000',
        expiresAt: futureIso(),
        windowMaxLamports: '1000000',
        windowSeconds: '3600',
      },
    },
  }, null, 2), { mode: 0o600 });

  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const daemon = new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile,
  });
  await daemon.start();
  t.after(async () => { await daemon.stop(); });

  return {
    dir, keypair, destination, socketPath, ledgerFile,
    blockhash: Keypair.generate().publicKey.toBase58(),
  };
}

/** The argv of a correct invocation; the caller adds the shape under test. */
function argvFor(f, { lamports = '42', out = null, blockhash = f.blockhash } = {}) {
  const argv = [
    '--socket', f.socketPath,
    '--grant', 'ops',
    '--from', f.keypair.publicKey.toBase58(),
    '--to', f.destination,
    '--lamports', lamports,
    '--blockhash', blockhash,
  ];
  if (out) argv.push('--out', out);
  return argv;
}

function journalBytes(file) {
  return fs.existsSync(file) ? fs.readFileSync(file).length : 0;
}

function journalRecords(file) {
  if (!fs.existsSync(file)) return 0;
  const text = fs.readFileSync(file, 'utf8').trim();
  return text === '' ? 0 : text.split('\n').length;
}

/** The first JSON line the client printed, or null. */
function firstJson(stdout) {
  const line = (stdout.split('\n').find((l) => l.trim().startsWith('{')) || '').trim();
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
}

// ---------------------------------------------------------------------------
// U1-U4: the shapes the client must refuse BEFORE it talks to the daemon.
// ---------------------------------------------------------------------------

test('U1 a flag the client does not take is refused before anything is signed', async (t) => {
  const f = await fixture(t);
  const out = path.join(f.dir, 'signed.bin');
  const r = await runClient([...argvFor(f, { out }), '--totally-unknown', 'x']);
  assert.equal(r.code, 2, `expected a usage refusal, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /unknown_flag: --totally-unknown/,
    `the refusal must name the flag: ${r.stderr}`);
  assert.equal(firstJson(r.stdout), null, 'the client must not have signed');
  assert.equal(fs.existsSync(out), false, 'no file may be written');
  assert.equal(journalBytes(f.ledgerFile), 0, 'the journal must be untouched');
});

test('U2 a flag given twice is refused and both values are named', async (t) => {
  const f = await fixture(t);
  const r = await runClient([
    ...argvFor(f, { lamports: '22' }),
    '--lamports', '999',
  ]);
  assert.equal(r.code, 2, `expected a usage refusal, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /duplicate_flag: --lamports/,
    `the refusal must name the flag: ${r.stderr}`);
  assert.match(r.stderr, /22/, 'the refusal must name the FIRST value');
  assert.match(r.stderr, /999/, 'the refusal must name the SECOND value');
  assert.equal(firstJson(r.stdout), null, 'the client must not have signed');
  assert.equal(journalBytes(f.ledgerFile), 0, 'the journal must be untouched');
});

test('U3 a value flag given without a value is refused before anything is signed', async (t) => {
  const f = await fixture(t);
  const out = path.join(f.dir, 'signed.bin');
  const r = await runClient([...argvFor(f), '--out']);
  assert.equal(r.code, 2, `expected a usage refusal, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /missing_value: --out/,
    `the refusal must name the flag: ${r.stderr}`);
  assert.equal(firstJson(r.stdout), null, 'the client must not have signed');
  assert.equal(fs.existsSync(out), false, 'no file may be written');
  assert.equal(journalBytes(f.ledgerFile), 0, 'the journal must be untouched');
});

test('U4 a switch given a value is refused before anything is signed', async (t) => {
  const f = await fixture(t);
  const r = await runClient([...argvFor(f), '--hold', 'yes']);
  assert.equal(r.code, 2, `expected a usage refusal, got ${r.code}: ${r.stdout} ${r.stderr}`);
  assert.match(r.stderr, /flag_takes_no_value: --hold/,
    `the refusal must name the switch: ${r.stderr}`);
  assert.equal(firstJson(r.stdout), null, 'the client must not have signed');
  assert.equal(journalBytes(f.ledgerFile), 0, 'the journal must be untouched');
});

// ---------------------------------------------------------------------------
// U5/U6: --dry is a preview, and the falsification that it changes nothing.
// ---------------------------------------------------------------------------

test('U5 --dry is a preview: a verdict, no signature, no file, no journal record', async (t) => {
  const f = await fixture(t);
  const out = path.join(f.dir, 'signed.bin');
  const r = await runClient([...argvFor(f, { out }), '--dry']);
  assert.equal(r.code, 0, `the dry run must succeed: ${r.code} ${r.stdout} ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json, `the client must print a verdict: ${r.stdout}`);
  assert.equal(json.ok, true);
  assert.equal(json.dry, true, 'the verdict must say it was a dry run');
  assert.equal(json.allowed, true, 'the verdict must carry the decision');
  assert.equal(json.signature, undefined, 'a dry run must not produce a signature');
  assert.equal(fs.existsSync(out), false, 'a dry run must not write --out');
  assert.equal(journalBytes(f.ledgerFile), 0, 'a dry run must not journal');
});

test('U6 an ALLOWED dry run leaves the machine untouched: the identical request still signs for real', async (t) => {
  const f = await fixture(t);
  const out = path.join(f.dir, 'signed.bin');

  const dry = await runClient([...argvFor(f, { out }), '--dry']);
  assert.equal(dry.code, 0, `the dry run must succeed: ${dry.stdout} ${dry.stderr}`);
  assert.equal(journalRecords(f.ledgerFile), 0, 'the dry run must not journal');

  // The SAME request, now for real. If the dry run had consumed the replay
  // identity or a window slot, this run would be refused with `replay` or
  // `window_cap` - that is the falsification.
  const real = await runClient([...argvFor(f, { out })]);
  assert.equal(real.code, 0, `the real run must succeed after a dry run: ${real.stdout} ${real.stderr}`);
  const json = firstJson(real.stdout);
  assert.ok(json && json.ok === true, `the real run must sign: ${real.stdout}`);
  assert.ok(json.signature, 'the real run must produce a signature');
  assert.equal(journalRecords(f.ledgerFile), 1,
    'the journal must hold EXACTLY ONE record - the dry run added none');
});

test('U7 a dry run of an OUT-OF-SCOPE request refuses with the same reason the real path refuses', async (t) => {
  const f = await fixture(t);
  const other = Keypair.generate().publicKey.toBase58();
  const dry = await runClient([
    '--socket', f.socketPath, '--grant', 'ops',
    '--from', f.keypair.publicKey.toBase58(),
    '--to', other,
    '--lamports', '42',
    '--blockhash', f.blockhash,
    '--dry',
  ]);
  assert.equal(dry.code, 1, `an out-of-scope dry run must refuse: ${dry.stdout}`);
  const json = firstJson(dry.stdout);
  assert.ok(json && json.ok === false, `the refusal must be structured: ${dry.stdout}`);
  assert.equal(json.error, 'destination', `unexpected reason: ${JSON.stringify(json)}`);
  assert.equal(journalBytes(f.ledgerFile), 0, 'a refused dry run must not journal');
});

// ---------------------------------------------------------------------------
// GUARDS: green on both trees.
// ---------------------------------------------------------------------------

test('G1 a plain invocation still signs, writes --out owner-only, and the signature verifies', async (t) => {
  const f = await fixture(t);
  const out = path.join(f.dir, 'signed.bin');
  const r = await runClient(argvFor(f, { out }));
  assert.equal(r.code, 0, `the client must sign: ${r.stdout} ${r.stderr}`);
  const json = firstJson(r.stdout);
  assert.ok(json && json.ok === true, `the client must report success: ${r.stdout}`);
  assert.equal(json.amountLamports, '42');
  assert.equal(json.feeLamports, '5000');
  assert.equal(json.signedBytes, 215);

  assert.equal(fs.existsSync(out), true, '--out must be written');
  assert.equal(fs.statSync(out).mode & 0o777, 0o600, '--out must be owner-only');

  // Independent verification under Node's OpenSSL ed25519, not the daemon's
  // own code path.
  const { VersionedTransaction } = require('@solana/web3.js');
  const parsed = VersionedTransaction.deserialize(fs.readFileSync(out));
  const message = Buffer.from(parsed.message.serialize());
  const signature = Buffer.from(parsed.signatures[0]);
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(f.keypair.publicKey.toBytes()),
  ]);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(crypto.verify(null, message, keyObject, signature), true,
    'the signature must verify under the public key');
  assert.equal(journalRecords(f.ledgerFile), 1, 'the real sign must journal exactly one record');
});

test('G2 the switch --hold alone is still accepted (it takes no value)', async (t) => {
  const f = await fixture(t);
  const child = spawn(process.execPath, [
    CLIENT, ...argvFor(f), '--hold',
  ], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  child.stderr.on('data', () => {});
  child.stdout.on('data', (d) => { stdout += d; });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout waiting for READY_TO_SCAN')), 20000);
      const check = setInterval(() => {
        if (stdout.includes('READY_TO_SCAN')) { clearInterval(check); clearTimeout(timer); resolve(); }
      }, 50);
      child.on('exit', (code) => { clearInterval(check); clearTimeout(timer); reject(new Error(`exited ${code}: ${stdout}`)); });
    });
  } finally {
    child.kill('SIGKILL');
  }
});
