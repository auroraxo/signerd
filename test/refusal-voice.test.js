'use strict';

// THE DAEMON'S OWN VERDICT SPEAKS (2026-11-17).
//
// WHY (measured 2026-11-17, tools/measure-daemon-refusal-voice.js, on the
// v0.2.33 tree 1bab6ed):
//
//   signerd sign --socket <live> --grant ops --tx <tx-to-another-destination>
//     stdout: {"ok":false,"error":"destination","detail":{...}}
//     stderr: (0 bytes)
//
// Seven of seven refusal faces reached the operator as a machine-readable
// code on STDOUT and NOTHING ELSE. Every other refusal class this CLI owns
// - transport, client verification, unknown flag, grant file, unreadable
// input - prints the code AND a `fix:` line, and the README promises it:
// "Refusals name the flag and the fix instead of failing silently."
//
// The daemon's policy verdict is the class this product EXISTS for ("die
// Verweigerung ist das Produkt"), and it was the one surface that stayed
// mute. An agent holding a grant learns WHICH refusal happened; it does not
// learn what to do about it.
//
// THE CONTRACT:
//   D1 a daemon refusal prints its code on stderr, EXACTLY ONCE;
//   D2 it names a repair on a `fix:` line;
//   D3 the repair names a command this CLI ACTUALLY OFFERS;
//   D4 the repair carries no host path;
//   D5 the machine channel is UNCHANGED: the stdout JSON still carries
//      `ok:false` and the same `error` code (a refusal is data - the
//      example client reads answer.error);
//   D6 a LEGAL request still succeeds and stays SILENT on stderr.
//
// HOW THE TREE IS BUILT: the checkout's own CLI against a real daemon over
// a real Unix socket. No network, no key material in the test.
//
// THE LADDER: D1-D4 are RED on the pre-fix tree, D5/D6 GREEN on both.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const { Keypair } = require(path.join(ROOT, 'node_modules', '@solana', 'web3.js'));
const { buildTransferWire } = require(path.join(ROOT, 'src', 'client.js'));
const { readKeystorePublicKey } = require(path.join(ROOT, 'src', 'keystore.js'));

const DEST = 'So11111111111111111111111111111111111111112';

/** Every command this CLI offers - a repair may only name one of these. */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

function cli(args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-daemonvoice-'));
  const sb = path.join(dir, 'sb');
  fs.mkdirSync(sb, { mode: 0o700 });
  const pass = path.join(sb, 'pass');
  fs.writeFileSync(pass, 'daemon-voice passphrase\n', { mode: 0o600 });
  return { dir, sb, pass };
}

/** The code and whether a repair was named, read off stderr. */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  // The code must appear EXACTLY ONCE - as the CODE, not as a word inside
  // the repair text. `destination` is also a FLAG name (--destination) and a
  // field of the repair prose, so a naive word count reported 3 for a
  // perfectly correct line. Count the code only where it is the leading
  // token of a line (the shape the CLI prints it in).
  const occurrences = code
    ? (text.match(new RegExp(`(?:^|\\n)${code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?::|\\s|$)`, 'g')) || []).length
    : 0;
  return { code, occurrences, hasFix: /(^|\n)\s*fix:/.test(text), text };
}

/** Commands named in the repair that this CLI does not offer. */
function unknownCommandsIn(text) {
  const found = [];
  const re = /signerd\s+([a-z][a-z-]*)/g;
  let m;
  while ((m = re.exec(String(text || ''))) !== null) {
    if (!KNOWN_COMMANDS.includes(m[1])) found.push(m[1]);
  }
  return [...new Set(found)];
}

function hostPathsIn(text) {
  return /\/home\/|\/Users\/|\/root\/|\/tmp\/[A-Za-z0-9._-]+\//.test(String(text || ''));
}

/**
 * A live daemon with one transaction grant, plus the wires to talk to it:
 * `goodTx` (the grant's destination) and `badTx` (somewhere else).
 */
function fixture(t) {
  const { dir, sb, pass } = sandbox();
  const keystore = path.join(sb, 'ops.key');
  assert.strictEqual(
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]).status, 0,
    'keygen must work');
  const grants = path.join(sb, 'grants.json');
  const add = cli(['grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', DEST, '--max-lamports', '500000000',
    '--window-max-lamports', '500000000', '--window-seconds', '3600',
    '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(add.status, 0, `grant-add must work: ${add.stderr}`);

  const pubkey = readKeystorePublicKey({ file: keystore });
  const goodTx = path.join(sb, 'good.bin');
  const badTx = path.join(sb, 'bad.bin');
  fs.writeFileSync(goodTx, buildTransferWire({
    fromPubkey: pubkey, toPubkey: DEST, lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });
  fs.writeFileSync(badTx, buildTransferWire({
    fromPubkey: pubkey, toPubkey: Keypair.generate().publicKey.toBase58(), lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  }), { mode: 0o600 });

  const socketPath = path.join(sb, 'daemon.sock');
  const ledger = path.join(sb, 'journal.jsonl');
  const logFd = fs.openSync(path.join(sb, 'daemon.log'), 'a');
  const daemon = require('node:child_process').spawn(process.execPath, [
    CLI, 'run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', grants, '--ledger', ledger, '--socket', socketPath,
  ], { stdio: ['ignore', logFd, logFd], detached: false });
  t.after(() => {
    try { daemon.kill('SIGKILL'); } catch { /* already gone */ }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  for (let i = 0; i < 200 && !fs.existsSync(socketPath); i += 1) {
    spawnSync('sleep', ['0.05']);
  }
  assert.ok(fs.existsSync(socketPath), 'the daemon must bind its socket');
  spawnSync('sleep', ['0.4']);
  return { dir, sb, pass, keystore, grants, ledger, socketPath, goodTx, badTx, pubkey };
}

/**
 * The refusals under test, each with the code it must answer with. Every
 * one of them is a verdict the DAEMON produced - none of them is a
 * transport or a client-side failure, which is the point: those two classes
 * already had a voice.
 */
function refusalFaces(f) {
  return [
    {
      name: 'destination-mismatch',
      expect: 'destination',
      run: () => cli(['sign', '--socket', f.socketPath, '--grant', 'ops', '--tx', f.badTx]),
    },
    {
      name: 'unknown-grant',
      expect: 'grant_not_found',
      run: () => cli(['sign', '--socket', f.socketPath, '--grant', 'nosuch', '--tx', f.goodTx]),
    },
  ];
}

/**
 * A legal System-transfer wire that is OUTSIDE the offline-decidable
 * envelope: two instructions instead of one. src/policy.js refuses it
 * `envelope` - and `envelope` is the one code shared with the receipt
 * policy, so the repair must be the TRANSACTION one ("rebuild it with
 * signerd build-tx"), never the receipt one. That distinction is what a
 * duplicate key in the repair map silently destroyed (caught here before it
 * shipped).
 */
function twoInstructionWire(pubkey) {
  const web3 = require(path.join(ROOT, 'node_modules', '@solana', 'web3.js'));
  const from = new web3.PublicKey(pubkey);
  const transaction = new web3.Transaction();
  transaction.feePayer = from;
  transaction.recentBlockhash = Keypair.generate().publicKey.toBase58();
  for (let i = 0; i < 2; i += 1) {
    transaction.add(web3.SystemProgram.transfer({
      fromPubkey: from,
      toPubkey: new web3.PublicKey(Keypair.generate().publicKey.toBase58()),
      lamports: 1,
    }));
  }
  // The same serialization the repo's own builder uses: an unsigned
  // transaction with a zero signature slot.
  return Buffer.from(transaction.serialize({ requireAllSignatures: false, verifySignatures: false }));
}

test('D1/D2/D3/D4: a daemon refusal prints its code once and names a runnable repair', (t) => {
  const f = fixture(t);
  for (const face of refusalFaces(f)) {
    const res = face.run();
    assert.notStrictEqual(res.status, 0, `${face.name} must refuse`);
    const v = voiceOf(res.stderr);
    assert.strictEqual(v.code, face.expect,
      `${face.name}: the code must reach stderr, got: ${JSON.stringify(res.stderr)}`);
    assert.strictEqual(v.occurrences, 1,
      `${face.name}: the code must appear EXACTLY once, got ${v.occurrences}: ${res.stderr}`);
    assert.ok(v.hasFix, `${face.name}: the refusal must name a repair: ${res.stderr}`);
    const unknown = unknownCommandsIn(v.text);
    assert.deepStrictEqual(unknown, [],
      `${face.name}: the repair names a command this CLI does not offer: ${unknown.join(', ')}`);
    assert.ok(!hostPathsIn(v.text), `${face.name}: the repair must not carry a host path: ${res.stderr}`);
  }
});

test('D5: the machine channel is unchanged - stdout still carries ok:false and the code', (t) => {
  const f = fixture(t);
  const res = cli(['sign', '--socket', f.socketPath, '--grant', 'ops', '--tx', f.badTx]);
  assert.notStrictEqual(res.status, 0, 'the refusal must exit non-zero');
  let doc = null;
  try { doc = JSON.parse(res.stdout.split('\n')[0]); } catch { /* not json */ }
  assert.ok(doc !== null, `the refusal must still be JSON on stdout: ${res.stdout}`);
  assert.strictEqual(doc.ok, false, 'the refusal must still say ok:false on stdout');
  assert.strictEqual(doc.error, 'destination', 'the code must still reach stdout');
});

test('D6: a legal request still succeeds and stays silent on stderr', (t) => {
  const f = fixture(t);
  const res = cli(['sign', '--socket', f.socketPath, '--grant', 'ops', '--tx', f.goodTx]);
  assert.strictEqual(res.status, 0, `a legal sign must succeed: ${res.stderr}`);
  assert.strictEqual((res.stderr || '').trim(), '',
    `a legal sign must stay quiet on stderr, got: ${res.stderr}`);
  const doc = JSON.parse(res.stdout.split('\n')[0]);
  assert.strictEqual(doc.ok, true, 'the legal sign must answer ok:true');
});

test('the refusal names the GRANT the operator asked for', (t) => {
  const f = fixture(t);
  // A grant that does not exist: the repair may name the grant that was
  // asked for, so the operator does not have to remember which name it was.
  const res = cli(['sign', '--socket', f.socketPath, '--grant', 'nosuch', '--tx', f.goodTx]);
  assert.notStrictEqual(res.status, 0, 'the refusal must exit non-zero');
  assert.match(res.stderr, /nosuch/,
    `the refusal must name the grant that was asked for: ${res.stderr}`);
});

test('the shared `envelope` code gets the TRANSACTION repair on a transaction request', (t) => {
  const f = fixture(t);
  const out = path.join(f.sb, 'two-ix.bin');
  fs.writeFileSync(out, twoInstructionWire(f.pubkey), { mode: 0o600 });
  const res = cli(['sign', '--socket', f.socketPath, '--grant', 'ops', '--tx', out]);
  assert.notStrictEqual(res.status, 0, 'a two-instruction wire must be refused');
  const v = voiceOf(res.stderr);
  assert.strictEqual(v.code, 'envelope', `the code must reach stderr: ${res.stderr}`);
  assert.ok(v.hasFix, `the refusal must name a repair: ${res.stderr}`);
  // The receipt wording must NEVER answer a transaction refusal (and vice
  // versa): `envelope` is one code emitted by two different rules.
  assert.match(v.text, /build-tx/,
    `a transaction refusal must be repaired with build-tx: ${res.stderr}`);
  assert.doesNotMatch(v.text, /openreceipts/, 
    `the receipt wording must not answer a transaction refusal: ${res.stderr}`);
});

test('the DAEMON frame itself carries the repair (the library-consumer channel)', (t) => {
  const f = fixture(t);
  // The CLI is one consumer; a library consumer talks to the raw socket and
  // never sees stderr. The `fix` must therefore travel in the frame the
  // daemon answers with, not only in the CLI's printing.
  const net = require('node:net');
  const raw = require('node:child_process').spawnSync(process.execPath, ['-e', `
      const net = require('node:net');
      const s = net.connect(process.argv[1]);
      s.on('connect', () => s.end(JSON.stringify({ grant: 'nosuch', wire: 'AA==' }) + '\\n'));
      s.on('data', (d) => { process.stdout.write(d.toString()); s.end(); });
      setTimeout(() => process.exit(0), 3000);
    `, f.socketPath], { encoding: 'utf8', timeout: 10000 });
  let frame = null;
  try { frame = JSON.parse(String(raw.stdout || '').split('\n')[0]); } catch { /* not json */ }
  assert.ok(frame !== null, `the daemon must answer: ${raw.stdout} ${raw.stderr}`);
  assert.strictEqual(frame.ok, false, 'the frame must still be a refusal');
  // The wire is a syntactically valid base64 of ONE byte, so the frame
  // reaches the grant lookup: the code under test is the lookup's, not the
  // request parser's.
  assert.strictEqual(frame.error, 'grant_not_found', `the frame must carry the code: ${JSON.stringify(frame)}`);
  assert.ok(typeof frame.fix === 'string' && frame.fix.length > 0,
    `the frame must carry the repair for a library consumer: ${JSON.stringify(frame)}`);
  assert.deepStrictEqual(unknownCommandsIn(String(frame.fix)), [],
    'the frame\'s repair must name only commands this CLI offers');
  assert.ok(!hostPathsIn(String(frame.fix)), 'the frame\'s repair must not carry a host path');
});
