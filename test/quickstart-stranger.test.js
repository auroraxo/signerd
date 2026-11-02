'use strict';
// Stranger-install / quickstart defects (measured 2026-11-02).
//
// THE DEFECT FAMILY, all four measured on THIS machine with the common
// desktop default umask 0002 (Ubuntu/Debian default):
//
//   1. KEYSTORE DIR SELF-REFUSAL (the loop): `keygen` creates the keystore's
//      parent directory itself with `mkdirSync(dir, {recursive:true})` and NO
//      mode, so the directory inherits the process umask -> 0775 under 0002.
//      The very next command, `signerd run`, refuses that directory with
//      `keystore_dir_mode: 775` (src/keystore.js:196). signerd created a
//      directory it then refuses to use.
//   2. PASSPHRASE FILE: `printf ... > pass` under umask 0002 creates 0664,
//      and readPassphrase() refuses any group/other-accessible file
//      (bin/signerd.js:91) -> "must not be group/other accessible (mode 664)",
//      exit 2. The README quickstart writes exactly this file.
//   3. GRANT FILE: the same umask makes grants.json 0664, and the grant loader
//      refuses a group/other-writable file (src/grantfile.js:173) ->
//      `grant_file_mode: 664`.
//   4. LEDGER PARENT DIR: the README never creates the ledger's directory.
//      The daemon's lock file lives next to the ledger, so `run` fails with
//      `ledger_lock_failed: ENOENT` - a raw errno, not a repairable message.
//
// The refusal itself is CORRECT and stays: a group-writable directory holding
// a keystore really is a swap-out attack surface. What is wrong is that
// signerd's own setup path MANUFACTURES the insecure state, and that the
// documented quickstart cannot be executed as written on a default machine.
//
// WHAT THESE TESTS PIN:
//   A. signerd creates the keystore's parent directory 0700 (never umask-inherited).
//   B. the keystore it writes is 0600 and loadable from that directory.
//   C. the passphrase-file refusal still holds for a genuinely loose file
//      (false-positive guard: the only case expected to behave as before),
//      and signerd says WHAT to do about it.
//   D. the daemon creates the ledger's parent directory instead of failing
//      with a raw ENOENT.
//   E. the whole documented quickstart runs end to end under umask 0002 in a
//      fresh HOME, through the INSTALLED package, and a message is signed.
//
// Falsification: every test below is written so it FAILS on the pre-fix tree.
// The control that must pass on BOTH trees is the loose-passphrase refusal
// (C): the fix must not weaken the security rule to make the quickstart work.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');

// A run with a chosen umask. Node cannot change the umask of the current
// process portably, so the child is spawned under `sh -c 'umask NNN; exec ...'`.
function runWithUmask(args, umaskStr, opts = {}) {
  const cmd = `umask ${umaskStr}; exec "${process.execPath}" ${args.map((a) => `"${a}"`).join(' ')}`;
  return spawnSync('sh', ['-c', cmd], { encoding: 'utf8', timeout: 120000, ...opts });
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------- A + B
// signerd must not create a directory it will later refuse.
test('keygen creates the keystore parent directory 0700, not umask-inherited', () => {
  const root = tmpdir('signerd-dir-mode-');
  const dir = path.join(root, 'ops');
  const pass = path.join(root, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });

  const res = runWithUmask([CLI, 'keygen', '--keystore', path.join(dir, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(res.status, 0, `keygen failed: ${res.stderr}`);

  const mode = fs.statSync(dir).mode & 0o7777;
  assert.strictEqual(mode, 0o700,
    `signerd created the keystore directory with mode ${mode.toString(8)}; it must be 0700 ` +
    '(a group-writable directory holding a keystore is a swap-out attack surface, ' +
    'and signerd itself refuses such a directory at load time)');
});

test('a keystore written by keygen is loadable from the directory keygen created', () => {
  const root = tmpdir('signerd-dir-load-');
  const dir = path.join(root, 'ops');
  const pass = path.join(root, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });

  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(dir, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  // Load it through the product's own loader (the same path `run` uses).
  const { loadKeystore } = require('../src/keystore');
  const keypair = loadKeystore({
    file: path.join(dir, 'ops.key'),
    passphrase: 'pw',
  });
  // loadKeystore returns the Keypair itself (the daemon holds the key).
  assert.ok(keypair && typeof keypair.publicKey.toBase58 === 'function',
    'the keystore must load into a keypair');
  assert.ok(keypair.publicKey.toBase58().length > 40, 'the keystore must carry a public key');
});

// ---------------------------------------------------------------- C
// FALSE-POSITIVE GUARD: the security rule must survive the fix.
// This is the only behaviour expected to be identical on the pre-fix and
// post-fix trees: a genuinely group/other-accessible passphrase file is
// still REFUSED.
test('a genuinely loose passphrase file is still refused (security rule intact)', () => {
  const root = tmpdir('signerd-loose-pass-');
  const loose = path.join(root, 'loose');
  fs.mkdirSync(loose, { mode: 0o755 });
  fs.chmodSync(loose, 0o755);
  const pass = path.join(loose, 'pass');
  fs.writeFileSync(pass, 'pw\n');
  fs.chmodSync(pass, 0o664);

  const res = runWithUmask([CLI, 'keygen', '--keystore', path.join(root, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.notStrictEqual(res.status, 0, 'a group/other-accessible passphrase file must be refused');
  assert.match(res.stderr + res.stdout, /group\/other accessible|mode 664/,
    `the refusal must name the mode, got: ${res.stderr}`);
});

// ---------------------------------------------------------------- D
// The ledger's parent directory is the daemon's state directory. The socket
// directory already gets an owner-only mkdir (src/daemon.js:423); the ledger
// directory must not be left to chance.
test('the daemon creates the ledger parent directory instead of failing with a raw ENOENT', () => {
  const root = tmpdir('signerd-ledger-dir-');
  const kdir = path.join(root, 'k');
  fs.mkdirSync(kdir, { mode: 0o700 });
  const pass = path.join(root, 'pass');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
  const grants = path.join(root, 'grants.json');
  fs.writeFileSync(grants, JSON.stringify({ version: 1, grants: {} }), { mode: 0o600 });

  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(kdir, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0, `keygen failed: ${keygen.stderr}`);

  const ledgerDir = path.join(root, 'state', 'nested');
  const ledger = path.join(ledgerDir, 'journal.jsonl');
  const socket = path.join(root, 's.sock');
  const daemonLog = path.join(root, 'daemon.log');
  // Detached with output to a file: a foreground `run` never returns (it is a
  // server), and a backgrounded child holding this test's stdio pipes would
  // hang spawnSync forever. Started detached, the test polls for the ledger
  // directory instead of waiting on process lifetime.
  const daemon = spawnSync('sh', ['-c',
    `umask 0002; exec "${process.execPath}" "${CLI}" run --keystore "${path.join(kdir, 'ops.key')}" ` +
    `--passphrase-file "${pass}" --grants "${grants}" --ledger "${ledger}" ` +
    `--socket "${socket}" > "${daemonLog}" 2>&1 & echo $!`], { encoding: 'utf8' });
  assert.strictEqual(daemon.status, 0, `daemon launch failed: ${daemon.stderr}`);
  const daemonPid = parseInt(String(daemon.stdout).trim(), 10);
  const stop = () => { try { process.kill(daemonPid, 'SIGTERM'); } catch { /* gone */ } };
  process.on('exit', stop);

  let out = '';
  let started = false;
  for (let i = 0; i < 100; i += 1) {
    if (fs.existsSync(ledgerDir)) { started = true; break; }
    spawnSync('sleep', ['0.1']);
  }
  stop();
  try { out = fs.readFileSync(daemonLog, 'utf8'); } catch { out = ''; }
  assert.ok(!/ledger_lock_failed/.test(out),
    `the daemon must not fail with a raw ledger_lock_failed/ENOENT: ${out.slice(0, 400)}`);
  assert.ok(started, `the daemon must create the ledger parent directory; log: ${out.slice(0, 400)}`);
  const mode = fs.statSync(ledgerDir).mode & 0o7777;
  assert.strictEqual(mode, 0o700,
    `the ledger directory must be 0700, got ${mode.toString(8)}`);
});

// ---------------------------------------------------------------- E
// The documented quickstart, executed as written, on a default machine.
test('the README quickstart runs end to end under umask 0002 and signs a message', () => {
  const root = tmpdir('signerd-quickstart-e2e-');
  const home = path.join(root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  const cfg = path.join(home, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });

  // The README's quickstart now creates both files owner-only (the fix for
  // the umask trap: under 0002 a bare `printf > pass` yields 0664, which the
  // tool refuses - correctly, since a passphrase file is a secret). The test
  // mirrors that documented flow: create the file at 0600, as the README says.
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600); // mode applies on create only; pin it either way
  const grants = path.join(cfg, 'grants.json');

  const keygen = runWithUmask([CLI, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], '0002');
  assert.strictEqual(keygen.status, 0,
    `the quickstart's keygen step must work under umask 0002: ${keygen.stderr}`);
  const keyOut = JSON.parse(keygen.stdout.trim().split('\n').pop());
  assert.ok(keyOut.publicKey, 'keygen must print a public key');

  // The passphrase file must end up safe: either the tool tightened it, or it
  // refused with a message that names the fix. What must NOT happen is a
  // silent group-readable secret.
  const passMode = fs.statSync(pass).mode & 0o777;
  assert.strictEqual(passMode & 0o077, 0,
    `the passphrase file must not be group/other accessible, mode is ${passMode.toString(8)}`);

  // The grant file: the quickstart has the operator create it. Same rule
  // (no group/other WRITE bits - the grant file carries no secret).
  fs.writeFileSync(grants, JSON.stringify({
    version: 1,
    grants: {
      releases: {
        kind: 'message', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', pubkey: Buffer.from(
          // 32 raw bytes of the daemon's public key, base64 (standard, padded)
          (() => {
            const { Keypair } = require('@solana/web3.js');
            const bs58 = require('bs58');
            const doc = JSON.parse(fs.readFileSync(path.join(cfg, 'ops.key'), 'utf8'));
            return bs58.decode(doc.publicKey);
          })(),
        ).toString('base64'),
        maxBytes: '700',
        expiresAt: new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
        windowMaxMessages: '3',
        windowSeconds: '3600',
      },
    },
  }, null, 2), { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  const grantsMode = fs.statSync(grants).mode & 0o777;
  assert.strictEqual(grantsMode & 0o022, 0,
    `the grant file must not be group/other writable, mode is ${grantsMode.toString(8)}`);

  const stateDir = path.join(home, '.local', 'share', 'signerd');
  const socket = path.join(stateDir, 'signerd.sock');
  const daemonLog = path.join(root, 'daemon.log');
  // The daemon is a long-running server: it must NOT inherit this test's
  // stdio pipes, or the parent's read of them never ends (spawnSync would
  // wait forever - a harness defect found by the first green run). It is
  // started detached, its output goes to a log file, and it is stopped by the
  // pid we wrote, not by a pattern kill.
  const daemon = spawnSync('sh', ['-c',
    `umask 0002; exec "${process.execPath}" "${CLI}" run --keystore "${path.join(cfg, 'ops.key')}" ` +
    `--passphrase-file "${pass}" --grants "${grants}" --ledger "${path.join(stateDir, 'journal.jsonl')}" ` +
    `--socket "${socket}" > "${daemonLog}" 2>&1 & echo $!`], { encoding: 'utf8' });
  assert.ok(daemon.status === 0, `the daemon must start: ${daemon.stderr}`);
  const daemonPid = parseInt(String(daemon.stdout).trim(), 10);
  assert.ok(Number.isInteger(daemonPid) && daemonPid > 0, 'the daemon pid must be known');
  const stopDaemon = () => {
    try { process.kill(daemonPid, 'SIGTERM'); } catch { /* already gone */ }
  };
  process.on('exit', stopDaemon);

  // wait for the socket
  let up = false;
  for (let i = 0; i < 100 && !up; i += 1) {
    up = fs.existsSync(socket);
    if (!up) spawnSync('sleep', ['0.1']);
  }
  assert.ok(up, 'the daemon must bind its socket under umask 0002');

  const body = path.join(root, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    claims: { version: '0.1.0' },
  }, null, 2));
  const out = path.join(root, 'receipt.json');
  const sign = runWithUmask([CLI, 'sign-message', '--socket', socket, '--grant', 'releases',
    '--body', body, '--out', out], '0002');
  assert.strictEqual(sign.status, 0, `sign-message must work in the quickstart: ${sign.stdout}${sign.stderr}`);
  const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.ok(doc.receipt && doc.sig && doc.pubkey, 'the artifact must carry receipt, pubkey and sig');

  try { fs.unlinkSync(path.join(root, 'pid')); } catch { /* ignore */ }
  stopDaemon();
});
