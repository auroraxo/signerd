'use strict';
// The quickstart's grant-file dead end (measured 2026-11-05).
//
// THE DEFECT FAMILY, all reproduced live on the v0.2.0 tag with the
// documented install (`npm install github:auroraxo/signerd#v0.2.0`) and the
// documented Shape block run VERBATIM under umask 0002:
//
//   1. THE DEAD END: the README's one-time setup block says it creates
//      "an encrypted keystore and a grant file", shows `signerd run
//      --grants ~/.config/signerd/grants.json` — and then never creates
//      that file. There is no grant-writing CLI command and the README
//      never shows the transaction-grant schema, so the very next
//      documented command dies with `grant_file_unreadable: ENOENT`
//      (exit 1). `test/quickstart-stranger.test.js` missed it because its
//      own e2e (E) WRITES the grant file itself — the harness silently
//      performed the step the documentation never documents.
//   2. THE BARE ERRNO: the refusal prints `grant_file_unreadable: ENOENT`
//      with no repair, although the passphrase refusal on the SAME surface
//      (bin/signerd.js readPassphrase) was already fixed (2026-11-02) to
//      name its fix (`fix: chmod 600 <path>`). Same class of first-contact
//      error, opposite treatment.
//
// WHAT THE FIX DOES (all pinned below):
//   A. `signerd grant-add` creates a valid transaction grant file
//      (mode 0600, dir 0700 when created), refusing to clobber.
//   B. `signerd sign-message ... --add-grant <name>` creates the message
//      grant the documented flow needs, then proceeds — so the documented
//      message quickstart runs end to end verbatim.
//   C. The whole README quickstart chain (keygen -> grant-add -> run ->
//      sign) runs verbatim under umask 0002 through the installed CLI and
//      yields a real, independently verified signature.
//   D. `run` on a MISSING grant file refuses with the repair command in
//      the message (fail-closed; the rule never loosens).
//   E. FALSE-POSITIVE GUARD (green on every tree): a genuinely loose
//      grant file (0664) is still refused — the fix must not weaken the
//      R3-1 rule; grant-add itself writes 0600 and must never inherit the
//      umask (the 2026-11-02 keygen loop, not repeated here).
//
// Falsification ladder: A, B, C, D are RED on the pre-fix tree (no
// grant-add command exists there). E is the guard that must stay GREEN.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');

function runWithUmask(args, umaskStr, opts = {}) {
  const cmd = `umask ${umaskStr}; exec "${process.execPath}" ${args.map((a) => `"${a}"`).join(' ')}`;
  return spawnSync('sh', ['-c', cmd], { encoding: 'utf8', timeout: 120000, ...opts });
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// A detached daemon (a foreground `run` is a server and never returns); the
// harness waits for the socket file, logs to a file, stops by recorded pid.
function startDetachedDaemon({ cfg, keystore, pass, grants, socket, umaskStr, log }) {
  const daemon = spawnSync('sh', ['-c',
    `umask ${umaskStr}; exec "${process.execPath}" "${CLI}" run --keystore "${keystore}" ` +
    `--passphrase-file "${pass}" --grants "${grants}" --ledger "${path.join(path.dirname(socket), 'journal.jsonl')}" ` +
    `--socket "${socket}" > "${log}" 2>&1 & echo $!`], { encoding: 'utf8' });
  assert.strictEqual(daemon.status, 0, `daemon launch failed: ${daemon.stderr}`);
  const daemonPid = parseInt(String(daemon.stdout).trim(), 10);
  assert.ok(Number.isInteger(daemonPid) && daemonPid > 0, 'the daemon pid must be known');
  let up = false;
  for (let i = 0; i < 100 && !up; i += 1) {
    up = fs.existsSync(socket);
    if (!up) spawnSync('sleep', ['0.1']);
  }
  return { daemonPid, up };
}

function stopDaemon(daemonPid) {
  try { process.kill(daemonPid, 'SIGTERM'); } catch { /* already gone */ }
}

// ---------------------------------------------------------------- A
test('grant-add creates a valid transaction grant file, refuses to clobber', () => {
  const root = tmpdir('signerd-grantadd-');
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const publicKey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;

  // Destination: a valid base58 pubkey distinct from the signer.
  const destination = 'So11111111111111111111111111111111111111112';

  const grants = path.join(cfg, 'grants.json');
  const res = runWithUmask([CLI, 'grant-add', '--grants', grants,
    '--name', 'ops-24h', '--signer', publicKey, '--destination', destination,
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], '0002');
  assert.strictEqual(res.status, 0, `grant-add failed: ${res.stdout}${res.stderr}`);

  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  assert.strictEqual(doc.version, 1, 'the file must be the version-1 schema');
  assert.strictEqual(doc.grants['ops-24h'].signer, publicKey);
  assert.strictEqual(doc.grants['ops-24h'].destination, destination);
  assert.strictEqual(doc.grants['ops-24h'].maxLamports, '500000000');
  assert.strictEqual(doc.grants['ops-24h'].expiresAt, '2030-01-01T00:00:00Z');

  // The file the product itself loads must accept it (the schema gate).
  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.ok(loaded.names.includes('ops-24h'), 'the created file must load');

  // Refuses to clobber: a second grant-add over an existing file exits
  // non-zero and the original bytes survive byte-for-byte.
  const before = fs.readFileSync(grants);
  const again = runWithUmask([CLI, 'grant-add', '--grants', grants,
    '--name', 'ops-24h', '--signer', publicKey, '--destination', destination,
    '--max-lamports', '1', '--window-max-lamports', '1',
    '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z'], '0002');
  assert.notStrictEqual(again.status, 0, 'grant-add must refuse to clobber an existing file');
  assert.match(again.stderr, /exists/i, 'the refusal must name the conflict');
  assert.ok(fs.readFileSync(grants).equals(before), 'the existing file must be untouched');
});

test('grant-add is the missing documented step: the quickstart chain now runs verbatim', () => {
  const root = tmpdir('signerd-grantadd-e2e-');
  const home = path.join(root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  const cfg = path.join(home, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);

  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const publicKey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;

  // The missing step, verbatim-shape: create the grant file the run step
  // points at, owner-only, under the default umask — using --keystore so no
  // paste step exists at all (the README block runs as written).
  const destination = 'So11111111111111111111111111111111111111112';
  const grants = path.join(cfg, 'grants.json');
  const add = runWithUmask([CLI, 'grant-add', '--grants', grants,
    '--name', 'ops-24h', '--keystore', path.join(cfg, 'ops.key'),
    '--destination', destination,
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], '0002');
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stdout}${add.stderr}`);
  // The derived signer must be the keystore's own public key (the daemon
  // would refuse grant_signer_mismatch otherwise — this pins the derivation).
  const addedDoc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  assert.strictEqual(addedDoc.grants['ops-24h'].signer, publicKey,
    'grant-add --keystore must derive the signer from the keystore public key');

  // owner-only file even under umask 0002 (the keygen-loop rule, again here)
  const grantsMode = fs.statSync(grants).mode & 0o777;
  assert.strictEqual(grantsMode, 0o600,
    `grant-add wrote mode ${grantsMode.toString(8)}; a grant file must be 0600`);

  const stateDir = path.join(home, '.local', 'share', 'signerd');
  const socket = path.join(stateDir, 'signerd.sock');
  const { daemonPid, up } = startDetachedDaemon({
    cfg, keystore: path.join(cfg, 'ops.key'), pass,
    grants, socket, umaskStr: '0002', log: path.join(root, 'daemon.log'),
  });
  process.on('exit', () => stopDaemon(daemonPid));
  assert.ok(up, `the daemon must start from the grant-add-created file; log: ` +
    (() => { try { return fs.readFileSync(path.join(root, 'daemon.log'), 'utf8').slice(0, 400); } catch { return '(no log)'; } })());

  // A real signature through the documented sign path, verified outside the
  // product: the full quickstart chain with no undocumented step.
  const { buildTransferWire } = require('../src/client');
  const { Keypair } = require('@solana/web3.js');
  const wire = buildTransferWire({
    fromPubkey: publicKey,
    toPubkey: destination,
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  const tx = path.join(root, 'tx.bin');
  fs.writeFileSync(tx, wire);
  const sign = runWithUmask([CLI, 'sign', '--socket', socket, '--grant', 'ops-24h',
    '--tx', tx], '0002');
  assert.strictEqual(sign.status, 0, `sign must succeed: ${sign.stdout}${sign.stderr}`);
  const answer = JSON.parse(sign.stdout);
  assert.strictEqual(answer.ok, true, `the daemon must sign: ${sign.stdout}`);

  // Independent verification (Node OpenSSL ed25519, not the product's path).
  const signedWire = Buffer.from(answer.signed, 'base64');
  const { VersionedTransaction } = require('@solana/web3.js');
  const parsed = VersionedTransaction.deserialize(signedWire);
  const message = Buffer.from(parsed.message.serialize());
  const signature = Buffer.from(parsed.signatures[0]);
  const bs58 = require('bs58');
  const crypto = require('node:crypto');
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
    bs58.decode(publicKey)]);
  const ok = crypto.verify(null, message, { key: spki, format: 'der', type: 'spki' }, signature);
  assert.ok(ok, 'the signature must verify under OpenSSL against the keystore key');
  stopDaemon(daemonPid);
});

// ---------------------------------------------------------------- B
test('sign-message --add-grant creates the message grant the documented flow needs', () => {
  const root = tmpdir('signerd-addgrant-msg-');
  const home = path.join(root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  const cfg = path.join(home, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const publicKey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;

  const body = path.join(root, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    claims: { version: '0.2.0' },
  }, null, 2));

  // The message quickstart's documented command, extended with the
  // one-flag grant bootstrap — no separate schema knowledge required.
  const stateDir = path.join(home, '.local', 'share', 'signerd');
  const socket = path.join(stateDir, 'signerd.sock');
  const grants = path.join(cfg, 'grants.json');
  const out = path.join(root, 'receipt.json');

  // The daemon is not running yet: --add-grant must STILL create the grant
  // file before the request fails on the socket (bootstrap must not depend
  // on a live daemon).
  const pre = runWithUmask([CLI, 'sign-message', '--socket', socket, '--grant', 'releases',
    '--body', body, '--out', out, '--add-grant', '--keystore', path.join(cfg, 'ops.key')], '0002');
  const preLog = `${pre.stdout}\n${pre.stderr}`;
  assert.notStrictEqual(pre.status, 0, 'the request must still fail on the missing daemon');
  assert.match(preLog, /ENOENT|no such file|connect/i, 'the failure must be the socket, not the grant file');
  assert.ok(fs.existsSync(grants), '--add-grant must create the grant file');
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  const g = doc.grants.releases;
  assert.strictEqual(g.kind, 'message', 'the bootstrap grant must be a message grant');
  assert.strictEqual(g.issuer, 'auroraxo', 'issuer must be pinned from the body');
  assert.strictEqual(g.subject, 'auroraxo/signerd', 'subject must be pinned from the body');
  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.ok(loaded.names.includes('releases'), 'the created file must load');
  assert.strictEqual(g.pubkey, Buffer.from(
    (() => { const bs58 = require('bs58'); return bs58.decode(publicKey); })(),
  ).toString('base64'), 'pubkey must be the daemon key, standard-padded base64');

  // The full documented flow: the daemon starts with an EMPTY grant file
  // (fail-closed: it refuses a MISSING one — pinned above), and the live
  // --add-grant adds the grant while the daemon is running; the daemon
  // re-reads grants per request, so the new grant takes effect immediately.
  fs.writeFileSync(grants, JSON.stringify({ version: 1, grants: {} }, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  const { daemonPid, up } = startDetachedDaemon({
    cfg, keystore: path.join(cfg, 'ops.key'), pass,
    grants, socket, umaskStr: '0002', log: path.join(root, 'daemon2.log'),
  });
  process.on('exit', () => stopDaemon(daemonPid));
  assert.ok(up, 'the daemon must start (empty grant file)');
  const sign = runWithUmask([CLI, 'sign-message', '--socket', socket, '--grant', 'releases',
    '--body', body, '--out', out, '--add-grant', '--keystore', path.join(cfg, 'ops.key')], '0002');
  assert.strictEqual(sign.status, 0, `sign-message --add-grant must work: ${sign.stdout}${sign.stderr}`);
  const receipt = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.ok(receipt.receipt && receipt.sig && receipt.pubkey, 'the artifact must carry receipt, pubkey and sig');
  stopDaemon(daemonPid);
});

// ---------------------------------------------------------------- C
test('run on a MISSING grant file refuses with the repair command, not a bare errno', () => {
  const root = tmpdir('signerd-grantmissing-');
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  const missing = path.join(cfg, 'grants.json');
  const res = runWithUmask([CLI, 'run', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass, '--grants', missing,
    '--ledger', path.join(root, 'journal.jsonl'), '--socket', path.join(root, 's.sock')], '0002');
  assert.notStrictEqual(res.status, 0, 'the daemon must still refuse a missing grant file');
  const log = `${res.stdout}\n${res.stderr}`;
  assert.match(log, /grant_file_unreadable/, 'the machine-readable reason must stay');
  assert.match(log, /grant-add/, 'the message must name the repair command');
});

// ---------------------------------------------------------------- E
// FALSE-POSITIVE GUARD: green on every tree. The R3-1 rule (no group/other
// write bits on a grant file) survives; grant-add itself never inherits the
// umask (the keygen-loop lesson).
test('a genuinely loose grant file is still refused; grant-add writes 0600 under umask 0002', () => {
  const root = tmpdir('signerd-grantloose-');
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  // A genuinely loose grant file (0664, as a bare `cat > grants.json` under
  // umask 0002 produces) must STILL be refused by `run`.
  const grants = path.join(cfg, 'grants.json');
  fs.writeFileSync(grants, JSON.stringify({ version: 1, grants: {} }), { mode: 0o664 });
  fs.chmodSync(grants, 0o664);
  const res = runWithUmask([CLI, 'run', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass, '--grants', grants,
    '--ledger', path.join(root, 'journal.jsonl'), '--socket', path.join(root, 's.sock')], '0002');
  assert.notStrictEqual(res.status, 0, 'a group/other-writable grant file must be refused');
  assert.match(`${res.stdout}${res.stderr}`, /grant_file_mode/,
    'the rule must stay (this is the guard that is green on every tree)');

  // grant-add's own write path: mode 0600 even under umask 0002 (the file is
  // security-relevant config; the keygen-loop lesson applies to it too).
  const publicKey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;
  const fresh = path.join(cfg, 'fresh.json');
  const add = runWithUmask([CLI, 'grant-add', '--grants', fresh,
    '--name', 'ops', '--signer', publicKey,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '42', '--window-max-lamports', '100000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], '0002');
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stdout}${add.stderr}`);
  const mode = fs.statSync(fresh).mode & 0o777;
  assert.strictEqual(mode, 0o600, `grant-add must write 0600, got ${mode.toString(8)}`);
});
