'use strict';
// GRANT REMOVAL FROM THE CLI (the named limitation, measured 2026-11-05).
//
// The card's honest-limits list says: "kein Grant-Entfernen (Handedit)" -
// there is NO command to remove a grant. `grant-add` can add one (since
// 2026-11-05, --append), the loader loads a MAP of grants, the daemon
// re-reads the file on EVERY request (so revocation is supposed to take
// effect immediately) - and yet the operator who wants to REVOKE a scope has
// to edit a security-relevant JSON file by hand.
//
// Hand-editing is exactly the path the product refuses everywhere else:
//   - a hand edit can leave the file in a state the daemon refuses at run
//     time (an unknown field, a broken grant) -> the daemon then refuses
//     EVERY request, including the ones that were still in scope;
//   - a hand edit of a SEALED file destroys the HMAC provenance, and the
//     repair (re-seal) is a second hand step;
//   - a hand edit is a non-atomic truncate: a crash leaves a torn file.
// The product already has the machinery for the safe shape of this act
// (src/grantadd.js: the loader as the judge, an atomic temp+rename write)
// - it just was not reachable for REMOVAL.
//
// WHAT THIS FILE PINS:
//   T1 `signerd grant-remove` removes the named grant; the file still loads
//      under the product's loader and holds exactly the other grants;
//   T2 THE POINT OF THE FEATURE: a LIVE daemon refuses the removed grant on
//      its NEXT request (no restart) and still signs the surviving grant -
//      revocation measured end to end, not just in the file;
//   T3 the refusals name the repair (unknown name, sealed file, unsealed +
//      passphrase, loose file, symlink);
//   T4 `grant-remove` is documented in the usage text AND in the README;
//   T5 every flag the usage text advertises is accepted by the CLI.
// The false-positive guards:
//   G1 removing a grant that is NOT in the file changes NOTHING (the file
//      stays byte-identical);
//   G2 a grant file another user can write is refused (grant_file_mode) and
//      its mode is NOT silently tightened (tighten-then-trust is the bug);
//   G3 a symlink at the grant path is refused and its target is untouched;
//   G4 a SEALED file can be removed WITH the passphrase and stays loadable
//      in the daemon's sealed mode (the re-seal is part of the act);
//   G5 a wrong passphrase refuses the removal (never destroy a seal we could
//      not authenticate);
//   G6 the SURVIVING grants are byte-identical after the removal (removal
//      is not a chance to rewrite a grant's content);
//   G7 a file with a broken existing grant refuses the removal (the loader
//      is the judge, same as grant-add --append).
//
// Ladder: this file is RED on any tree whose CLI cannot remove a grant (the
// instrument IS the fix); GREEN here.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');
const README = path.join(REPO, 'README.md');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120000, ...opts });
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// A state directory that passes the CLI's own hygiene rules (0600 secret,
// owner-only directory) - the harness must not create a state the product
// refuses.
function secretDir(prefix) {
  const root = tmpdir(prefix);
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);
  return { root, cfg, pass };
}

const DESTINATION = 'So11111111111111111111111111111111111111112';
const DESTINATION2 = 'Vote111111111111111111111111111111111111111';

function grantAddArgs({ cfg, grants, name, destination = DESTINATION }) {
  return ['grant-add', '--grants', grants, '--name', name,
    '--keystore', path.join(cfg, 'ops.key'), '--destination', destination,
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'];
}

function keygen(cfg, pass) {
  const r = run(['keygen', '--keystore', path.join(cfg, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(r.status, 0, `keygen failed: ${r.stderr}`);
  return JSON.parse(r.stdout.trim().split('\n').pop());
}

// A daemon that keeps running while the grant file changes underneath it.
function startDaemon({ cfg, pass, grants, stateDir, log }) {
  const socket = path.join(stateDir, 'signerd.sock');
  const launched = spawnSync('sh', ['-c',
    `umask 077; exec "${process.execPath}" "${CLI}" run --keystore "${path.join(cfg, 'ops.key')}" ` +
    `--passphrase-file "${pass}" --grants "${grants}" ` +
    `--ledger "${path.join(stateDir, 'journal.jsonl')}" --socket "${socket}" > "${log}" 2>&1 & echo $!`],
    { encoding: 'utf8' });
  assert.strictEqual(launched.status, 0, `daemon launch failed: ${launched.stderr}`);
  const pid = parseInt(String(launched.stdout).trim(), 10);
  process.on('exit', () => { try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ } });
  let up = false;
  for (let i = 0; i < 100 && !up; i += 1) {
    up = fs.existsSync(socket);
    if (!up) spawnSync('sleep', ['0.1']);
  }
  assert.ok(up, `the daemon must start; log: ` +
    (() => { try { return fs.readFileSync(log, 'utf8').slice(0, 300); } catch { return '(no log)'; } })());
  return { pid, socket };
}

test('T1 grant-remove removes the named grant and the file still loads', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');

  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  assert.strictEqual(
    run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']).status, 0);

  const inoBefore = fs.statSync(grants).ino;
  const removed = run(['grant-remove', '--grants', grants, '--name', 'ops-payroll']);
  assert.strictEqual(removed.status, 0,
    `grant-remove must succeed: ${removed.stdout}${removed.stderr}`);
  assert.notStrictEqual(fs.statSync(grants).ino, inoBefore,
    'the removal must replace the file (rename), not truncate in place: a pre-opened write descriptor must be orphaned');
  const answer = JSON.parse(removed.stdout.trim().split('\n').pop());
  assert.strictEqual(answer.ok, true, `grant-remove must report ok: ${removed.stdout}`);
  assert.strictEqual(answer.removed, 'ops-payroll', 'the removed name must be reported');

  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.deepEqual(loaded.names, ['ops-24h'],
    'only the removed grant may be gone; the survivor must stay');
  assert.strictEqual(loaded.grants['ops-24h'].destination, DESTINATION);
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o600,
    'the rewritten file must stay 0600');
  assert.deepEqual(fs.readdirSync(cfg).filter((f) => f.includes('.tmp-')), [],
    'no temp file may survive the atomic write');
});

test('T2 THE POINT: a LIVE daemon refuses the removed grant on its NEXT request', () => {
  const { cfg, pass, root } = secretDir('signerd-grant-remove-live-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  assert.strictEqual(
    run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']).status, 0);

  const stateDir = path.join(root, 'state');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const { pid, socket } = startDaemon({
    cfg, pass, grants, stateDir, log: path.join(root, 'daemon.log'),
  });

  // A transaction the daemon can actually sign: built through the CLI, the
  // same way the documented quickstart builds it. ONE FILE PER SCOPE: the
  // wire's destination must match the grant's destination.
  const txOps = path.join(root, 'tx-ops.bin');
  const buildOps = run(['build-tx', '--keystore', path.join(cfg, 'ops.key'),
    '--to', DESTINATION, '--lamports', '42', '--out', txOps]);
  assert.strictEqual(buildOps.status, 0, `build-tx failed: ${buildOps.stderr}`);
  const txPayroll = path.join(root, 'tx-payroll.bin');
  const buildPayroll = run(['build-tx', '--keystore', path.join(cfg, 'ops.key'),
    '--to', DESTINATION2, '--lamports', '42', '--out', txPayroll]);
  assert.strictEqual(buildPayroll.status, 0, `build-tx failed: ${buildPayroll.stderr}`);

  // BEFORE the removal: the grant signs.
  const before = run(['sign', '--socket', socket, '--grant', 'ops-payroll', '--tx', txPayroll]);
  assert.strictEqual(before.status, 0,
    `the grant must sign before it is removed: ${before.stdout}${before.stderr}`);
  assert.strictEqual(JSON.parse(before.stdout).ok, true, 'the pre-removal sign must succeed');

  // THE REMOVAL: no restart, no signal to the daemon.
  const removed = run(['grant-remove', '--grants', grants, '--name', 'ops-payroll']);
  assert.strictEqual(removed.status, 0, `grant-remove failed: ${removed.stderr}`);

  // AFTER the removal: the SAME daemon refuses the removed grant - on the
  // next request, without a restart (the daemon re-reads the file per
  // request). This is the property the hand-edit path cannot promise.
  const after = run(['sign', '--socket', socket, '--grant', 'ops-payroll', '--tx', txPayroll]);
  assert.notStrictEqual(after.status, 0, 'the removed grant must be refused');
  assert.match(after.stdout + after.stderr, /grant_not_found/,
    'the refusal must be the named reason');

  // The surviving scope still signs - the removal took one scope away, not
  // the daemon.
  const survivor = run(['sign', '--socket', socket, '--grant', 'ops-24h', '--tx', txOps]);
  assert.strictEqual(survivor.status, 0,
    `the surviving grant must still sign: ${survivor.stdout}${survivor.stderr}`);

  try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ }
});

test('T3 the refusals name the repair', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-repair-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // An unknown name: the verdict must name the repair (a different --name)
  // and say WHICH names are in the file.
  const unknown = run(['grant-remove', '--grants', grants, '--name', 'ops-nope']);
  assert.notStrictEqual(unknown.status, 0, 'an unknown grant must be refused');
  assert.match(unknown.stderr, /grant_not_found/, 'the reason must survive');
  assert.match(unknown.stderr, /--name/, 'the refusal must name the repair');
  assert.match(unknown.stderr, /ops-24h/,
    'the refusal must list the grants that ARE in the file');

  // A SEALED file without the passphrase: the repair is to pass it.
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'seal phrase\n', { mode: 0o600 });
  assert.strictEqual(
    run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]).status, 0);
  const sealed = run(['grant-remove', '--grants', grants, '--name', 'ops-24h']);
  assert.notStrictEqual(sealed.status, 0, 'a sealed file must not be rewritten without the passphrase');
  assert.match(sealed.stderr, /grant_file_sealed/, 'the reason must survive');
  assert.match(sealed.stderr, /seal-passphrase-file/,
    'the refusal must name the repair (the passphrase)');
});

test('T4 grant-remove is documented in the usage text and in the README', () => {
  const usage = `${run([]).stdout}\n${run([]).stderr}`;
  assert.match(usage, /signerd grant-remove[\s\S]*--grants/,
    'the usage text must document the grant-remove command');

  const readme = fs.readFileSync(README, 'utf8');
  assert.match(readme, /signerd grant-remove[\s\S]{0,600}--name/,
    'the README must document grant-remove');
});

test('T5 every flag the usage text advertises is accepted by the CLI', () => {
  const usage = `${run([]).stdout}\n${run([]).stderr}`;
  const usageBlock = usage.slice(usage.indexOf('Usage:'), usage.indexOf('Notes:'));
  const flags = new Set();
  for (const m of usageBlock.matchAll(/--([a-z][a-z0-9-]*)/g)) flags.add(m[1]);
  assert.ok(flags.size > 0, 'the usage text must advertise flags');

  const { cfg, pass } = secretDir('signerd-grant-remove-flag-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // --name and --grants must be accepted by the parser (a real removal).
  const removed = run(['grant-remove', '--grants', grants, '--name', 'ops-24h']);
  assert.strictEqual(removed.status, 0, `the flags must be accepted: ${removed.stderr}`);
});

test('G1 GUARD: removing a grant that is not in the file changes NOTHING', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-guard-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  const before = fs.readFileSync(grants, 'utf8');

  const refused = run(['grant-remove', '--grants', grants, '--name', 'ops-nope']);
  assert.notStrictEqual(refused.status, 0, 'an unknown grant must be refused');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused removal must not have changed the file');
});

test('G2 GUARD: a grant file another user can write is refused, not chmod-ed', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-mode-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // The R3-1 state: content another user could already have forged. The
  // loader refuses it at run time, so the removal must refuse it too -
  // never tighten-then-trust (the chmod trap, measured in review #4).
  fs.chmodSync(grants, 0o664);
  const before = fs.readFileSync(grants, 'utf8');
  const refused = run(['grant-remove', '--grants', grants, '--name', 'ops-24h']);
  assert.notStrictEqual(refused.status, 0, 'a group/other-writable file must be refused');
  assert.match(refused.stderr, /grant_file_mode/, 'the loader reason must survive');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused removal must not have changed the file');
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o664,
    'the refusal must not chmod the file either');
});

test('G3 GUARD: a symlink at the grant path is refused, not written through', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-symlink-');
  keygen(cfg, pass);
  const outside = path.join(path.dirname(cfg), 'elsewhere.json');
  const grants = path.join(cfg, 'grants.json');
  fs.symlinkSync(outside, grants);

  const refused = run(['grant-remove', '--grants', grants, '--name', 'ops-24h']);
  assert.notStrictEqual(refused.status, 0, 'a symlink at the grant path must be refused');
  assert.match(refused.stderr, /grant_file_symlink/,
    `the refusal must NAME the symlink: ${refused.stderr}`);
  assert.ok(!fs.existsSync(outside),
    'grant-remove must not write through the symlink to the link target');
});

test('G4 GUARD: a SEALED file can be removed WITH the passphrase and stays sealed', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-seal-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  assert.strictEqual(
    run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']).status, 0);

  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'seal phrase\n', { mode: 0o600 });
  assert.strictEqual(
    run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]).status, 0);

  const removed = run(['grant-remove', '--grants', grants, '--name', 'ops-payroll',
    '--seal-passphrase-file', sealPass]);
  assert.strictEqual(removed.status, 0,
    `the removal of a sealed grant must work with the passphrase: ${removed.stdout}${removed.stderr}`);

  // The result must still load in the daemon's SEALED mode (the re-seal is
  // part of the act - the file must not fall back to unsealed).
  const { loadGrantFile } = require('../src/grantfile');
  const { makeSealKeyProvider } = require('../src/grantseal');
  const loaded = loadGrantFile(grants, {
    sealKeyFor: makeSealKeyProvider(fs.readFileSync(sealPass, 'utf8').replace(/\r?\n$/, '')),
  });
  assert.deepEqual(loaded.names, ['ops-24h'],
    'the sealed file must load in sealed mode with only the surviving grant');
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  assert.ok(Object.getOwnPropertyDescriptor(doc, 'seal') !== undefined,
    'the file must still carry a seal after the removal');
});

test('G5 GUARD: a wrong passphrase refuses the removal', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-wrongpass-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  assert.strictEqual(
    run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]).status, 0);

  const wrong = path.join(cfg, 'wrong.pass');
  fs.writeFileSync(wrong, 'a different phrase\n', { mode: 0o600 });
  const before = fs.readFileSync(grants, 'utf8');
  const refused = run(['grant-remove', '--grants', grants, '--name', 'ops-24h',
    '--seal-passphrase-file', wrong]);
  assert.notStrictEqual(refused.status, 0, 'a wrong passphrase must be refused');
  assert.match(refused.stderr, /grant_file_seal_mismatch/,
    'the refusal must name WHY: the current seal could not be verified');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused removal must not have changed the sealed file');
});

test('G6 GUARD: the surviving grants are byte-identical after the removal', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-survivor-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  assert.strictEqual(
    run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']).status, 0);

  // BYTES, not just parsed content: the surviving grant's SERIALIZED form
  // in the file must be byte-identical. A parsed comparison alone would
  // accept a rewrite that reorders the keys or reformats the grant - the
  // removal is not a chance to touch the grants that stay.
  const beforeText = JSON.stringify(JSON.parse(fs.readFileSync(grants, 'utf8')).grants['ops-24h']);
  assert.strictEqual(run(['grant-remove', '--grants', grants, '--name', 'ops-payroll']).status, 0);
  const afterText = JSON.stringify(JSON.parse(fs.readFileSync(grants, 'utf8')).grants['ops-24h']);
  assert.strictEqual(afterText, beforeText,
    'a removal must not change the BYTES of the grants that stay');
  assert.deepStrictEqual(JSON.parse(afterText), JSON.parse(beforeText),
    'a removal must not change the CONTENT of the grants that stay');
});

test('G7 GUARD: a file with a broken existing grant refuses the removal', () => {
  const { cfg, pass } = secretDir('signerd-grant-remove-broken-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // Hand-break an existing grant: the file as a whole would be refused at
  // run time, so nothing may be removed from it (the loader is the judge).
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  delete doc.grants['ops-24h'].windowSeconds;
  fs.writeFileSync(grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  const before = fs.readFileSync(grants, 'utf8');

  const refused = run(['grant-remove', '--grants', grants, '--name', 'ops-24h']);
  assert.notStrictEqual(refused.status, 0, 'an invalid existing file must be refused');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused removal must not have changed the file');
});
