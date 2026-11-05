'use strict';
// The LAST dead end of the documented quickstart (measured 2026-11-05):
//
// The README Shape block ends with
//
//     signerd sign --socket ... --grant ops-24h --tx tx.bin
//
// and no documented step before it creates tx.bin. The grant-add fix
// (daa83aa) closed the grant-file half of the chain; this test pins the
// other half: a stranger who runs the block top to bottom, touching NOTHING
// but documented CLI commands, must get a real signature.
//
// Before build-tx existed, test C covered this chain by writing tx.bin
// with fs.writeFileSync — the harness performed the step the documentation
// never documents, exactly the pattern that hid the grant-file defect
// (see test/quickstart-grantfile.test.js header). D runs the whole chain
// VERBATIM through the CLI alone:
//
//   keygen -> grant-add --keystore -> run -> build-tx -> sign -> verify
//
// Ladder: D is RED on any tree without `signerd build-tx` (the unknown
// command exits non-zero with usage); GREEN here. The independent
// verification (OpenSSL ed25519 against the keystore public key) is the
// same oracle as test C, so a "signed but wrong" answer cannot pass.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120000, ...opts });
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('the README Shape block runs verbatim end to end through the CLI alone', () => {
  const root = tmpdir('signerd-shape-verbatim-');
  const home = path.join(root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  const cfg = path.join(home, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });

  // --- Shape block, as written: under the default desktop umask (0002).
  const sh = (script) => spawnSync('sh', ['-c',
    `umask 0002; HOME="${home}" exec ${script}`], { encoding: 'utf8', timeout: 120000 });

  const keygen = sh(`"${process.execPath}" "${CLI}" keygen ` +
    `--keystore "${cfg}/ops.key" --passphrase-file "${pass}"`);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);
  const publicKey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;

  const destination = 'So11111111111111111111111111111111111111112';
  const grants = path.join(cfg, 'grants.json');
  const add = sh(`"${process.execPath}" "${CLI}" grant-add --grants "${grants}" ` +
    `--name ops-24h --keystore "${cfg}/ops.key" --destination "${destination}" ` +
    `--max-lamports 500000000 --window-max-lamports 500000000 ` +
    `--window-seconds 3600 --expires 2030-01-01T00:00:00Z`);
  assert.strictEqual(add.status, 0, `grant-add failed: ${add.stdout}${add.stderr}`);
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o600, 'grant file must be 0600');

  // --- run: detached, wait for the socket (the Shape block's `signerd run`).
  const stateDir = path.join(home, '.local', 'share', 'signerd');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const socket = path.join(stateDir, 'signerd.sock');
  const log = path.join(root, 'daemon.log');
  const daemon = spawnSync('sh', ['-c',
    `umask 0002; exec "${process.execPath}" "${CLI}" run --keystore "${cfg}/ops.key" ` +
    `--passphrase-file "${pass}" --grants "${grants}" ` +
    `--ledger "${stateDir}/journal.jsonl" --socket "${socket}" > "${log}" 2>&1 & echo $!`],
    { encoding: 'utf8' });
  assert.strictEqual(daemon.status, 0, `daemon launch failed: ${daemon.stderr}`);
  const daemonPid = parseInt(String(daemon.stdout).trim(), 10);
  process.on('exit', () => { try { process.kill(daemonPid, 'SIGTERM'); } catch { /* gone */ } });
  let up = false;
  for (let i = 0; i < 100 && !up; i += 1) {
    up = fs.existsSync(socket);
    if (!up) spawnSync('sleep', ['0.1']);
  }
  assert.ok(up, `the daemon must start; log: ` +
    (() => { try { return fs.readFileSync(log, 'utf8').slice(0, 400); } catch { return '(no log)'; } })());

  // --- THE DOCUMENTED STEP THAT CREATED tx.bin, VERBATIM: build-tx.
  // No fs.writeFileSync here on purpose — the harness must not perform the
  // step the documentation performs.
  const tx = path.join(root, 'tx.bin');
  const build = sh(`"${process.execPath}" "${CLI}" build-tx ` +
    `--keystore "${cfg}/ops.key" --to "${destination}" --lamports 42 --out "${tx}"`);
  assert.strictEqual(build.status, 0,
    `build-tx must run as documented: ${build.stdout}${build.stderr}`);
  const built = JSON.parse(build.stdout.trim().split('\n').pop());
  assert.strictEqual(built.ok, true, `build-tx must report ok: ${build.stdout}`);
  assert.ok(fs.existsSync(tx), 'build-tx must create the transaction file');
  assert.ok(fs.statSync(tx).size > 0, 'the transaction file must be non-empty');
  assert.strictEqual(built.from, publicKey,
    'build-tx must derive the fee payer from the keystore public key');

  // --- the final documented line, verbatim.
  const sign = sh(`"${process.execPath}" "${CLI}" sign --socket "${socket}" ` +
    `--grant ops-24h --tx "${tx}"`);
  assert.strictEqual(sign.status, 0, `sign must succeed: ${sign.stdout}${sign.stderr}`);
  const answer = JSON.parse(sign.stdout);
  assert.strictEqual(answer.ok, true, `the daemon must sign: ${sign.stdout}`);

  // --- independent verification (OpenSSL ed25519, not the product's path).
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

  try { process.kill(daemonPid, 'SIGTERM'); } catch { /* gone */ }
});

test('build-tx refuses to sign anything: it only builds, and names its limits', () => {
  const root = tmpdir('signerd-buildtx-limits-');
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
  const keygen = run(['keygen', '--keystore', path.join(cfg, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  // Missing --to: refused with the missing flag named (the repair rule).
  const noTo = run(['build-tx', '--keystore', path.join(cfg, 'ops.key'),
    '--lamports', '42', '--out', path.join(root, 'tx.bin')]);
  assert.notStrictEqual(noTo.status, 0, 'build-tx must require --to');
  assert.match(noTo.stderr, /--to/, 'the refusal must name the missing flag');

  // Non-integer lamports: refused, no file written (fail-closed, like grant-add).
  const bad = path.join(root, 'bad.bin');
  const badLamports = run(['build-tx', '--keystore', path.join(cfg, 'ops.key'),
    '--to', 'So11111111111111111111111111111111111111112',
    '--lamports', 'forty-two', '--out', bad]);
  assert.notStrictEqual(badLamports.status, 0, 'non-integer lamports must be refused');
  assert.ok(!fs.existsSync(bad), 'no transaction file may be written on refusal');

  // Missing keystore: refused with the missing flag named.
  const noKs = run(['build-tx', '--to', 'So11111111111111111111111111111111111111112',
    '--lamports', '42', '--out', path.join(root, 'tx2.bin')]);
  assert.notStrictEqual(noKs.status, 0, 'build-tx must require --keystore');
  assert.match(noKs.stderr, /--keystore/, 'the refusal must name the missing flag');
});
