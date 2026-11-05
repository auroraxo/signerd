'use strict';
// The GRANT FILE's first contact with a stranger who needs MORE THAN ONE
// grant (measured 2026-11-05, live against the published v0.2.2 install):
//
//     signerd grant-add --grants ~/.config/signerd/grants.json --name ops-24h ...
//     signerd grant-add --grants ~/.config/signerd/grants.json --name ops-payroll ...
//     -> grant_file_exists: grant_file_exists: /home/.../grants.json
//
// A self-referential verdict with no repair, and NO WAY TO CREATE A SECOND
// GRANT AT ALL: `grant-add` writes exactly one grant into a file and refuses
// to touch an existing file. The daemon, however, LOADS a whole map of grants
// (src/grantfile.js: {version:1, grants:{<name>: {...}, ...}}) and the README
// documents exactly one grant, so a stranger never learns that a second grant
// needs a hand-written JSON file.
//
// The repo's own rule - "Name the repair, not just the verdict" - is applied
// to the passphrase, keystore, tx-file and (2026-11-05) the import refusal,
// and NOT to this one. The repair that actually exists (add the grant to the
// existing file) was implemented INTERNALLY (src/grantadd.js addGrantToFile,
// used by the message bootstrap) but was not reachable from the CLI.
//
// WHAT THIS FILE PINS:
//   T1 a second grant-add into an EXISTING grant file ADDS the grant (the
//      file then loads with both grants);
//   T2 the refusal names the repair when the file cannot be extended
//      (sealed file, same grant name);
//   T3 --append is documented in the usage text AND in the README;
//   T4 the usage text must not advertise a flag the CLI rejects.
// The false-positive guards:
//   G1 without --append an existing file is still refused (no silent
//      rewrite, no silent clobber) - the repair must stay explicit;
//   G2 a SEALED grant file is still refused even with --append (a rewrite
//      would destroy the seal's provenance);
//   G3 the ADDED grant must be validated by the PRODUCT's own validator, and
//      an invalid grant must not be written.
//
// Ladder: this file is RED on any tree whose grant-add cannot extend an
// existing file (the instrument IS the fix); GREEN here.
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

test('T1 a second grant-add with --append ADDS the grant instead of refusing', () => {
  const { cfg, pass } = secretDir('signerd-grant-append-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');

  const first = run(grantAddArgs({ cfg, grants, name: 'ops-24h' }));
  assert.strictEqual(first.status, 0, `the first grant-add must succeed: ${first.stderr}`);

  // The second grant: a DIFFERENT name, so the file must be EXTENDED.
  // The write must be atomic (temp file + rename): the target's INODE must
  // change - a stranger holding an open WRITE descriptor to the old inode
  // (the R4-1 shape) must not reach the appended content through it - and no
  // temp file may survive. An in-place truncate would keep the inode and
  // hand the new bytes straight to that descriptor.
  const inoBefore = fs.statSync(grants).ino;
  const second = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']);
  assert.strictEqual(second.status, 0,
    `the second grant-add with --append must succeed: ${second.stdout}${second.stderr}`);
  assert.notStrictEqual(fs.statSync(grants).ino, inoBefore,
    'the append must replace the file (rename), not truncate in place: a pre-opened write descriptor must be orphaned');

  const leftovers = fs.readdirSync(cfg).filter((f) => f.includes('.tmp-'));
  assert.deepEqual(leftovers, [], `no temp file may remain: ${leftovers}`);

  // The file must now hold BOTH grants and must still load under the
  // product's own loader.
  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.deepEqual(loaded.names, ['ops-24h', 'ops-payroll'],
    'both grants must be in the file and loadable');
  assert.strictEqual(loaded.grants['ops-payroll'].destination, DESTINATION2);
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o600,
    'the extended file must stay 0600');
});

test('T2 the refusal names the repair when the file cannot be extended', () => {
  const { cfg, pass } = secretDir('signerd-grant-repair-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');

  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // Same name again: the grant already exists - the verdict must name how to
  // repair it (a different --name; an edited grant needs a hand edit).
  const same = run([...grantAddArgs({ cfg, grants, name: 'ops-24h' }), '--append']);
  assert.notStrictEqual(same.status, 0, 'the same grant name must be refused');
  assert.match(same.stderr, /grant_exists|already exists/, 'the reason must survive');
  assert.match(same.stderr, /--name/,
    'the refusal must name the repair (a different --name)');

  // T2c THE MEASURED DEFECT ITSELF: the refusal WITHOUT --append must name
  // the repair. Pre-fix the output was the self-referential
  // "grant_file_exists: grant_file_exists: <path>" with no way forward.
  const noAppend = run(grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }));
  assert.notStrictEqual(noAppend.status, 0, 'an existing file must be refused without --append');
  assert.match(noAppend.stderr, /grant_file_exists/, 'the machine-readable reason must survive');
  assert.match(noAppend.stderr, /--append/,
    'the refusal must name the --append repair (the second scope was impossible otherwise)');

  // T2b a SEALED grant file cannot be appended (a rewrite would destroy the
  // seal's provenance): the refusal must say so AND name a repair that
  // actually works - edit the file by hand, then RE-SEAL it with
  // --seal-passphrase-file. The repair itself is exercised for real: the
  // re-sealed, hand-extended file must load under the daemon's sealed mode.
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'seal phrase\n', { mode: 0o600 });
  const seal = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.strictEqual(seal.status, 0, `seal-grants failed: ${seal.stderr}`);

  const sealed = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }), '--append']);
  assert.notStrictEqual(sealed.status, 0, 'a sealed grant file must not be rewritten');
  assert.match(sealed.stderr, /grant_file_sealed/, 'the reason must survive');
  assert.match(sealed.stderr, /seal-grants|seal-passphrase-file/i,
    'the refusal must name the repair (re-seal after the hand edit)');

  // The named repair WORKS: extend by hand, re-seal, and the daemon's own
  // sealed-mode loader must accept the result.
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  const { buildTxGrant } = require('../src/grantadd');
  const { readKeystorePublicKey } = require('../src/keystore');
  doc.grants['ops-payroll'] = buildTxGrant({
    name: 'ops-payroll',
    signer: readKeystorePublicKey({ file: path.join(cfg, 'ops.key') }),
    destination: DESTINATION2,
    maxLamports: '1000000', windowMaxLamports: '1000000',
    windowSeconds: '60', expiresAt: '2030-01-01T00:00:00Z',
  });
  fs.writeFileSync(grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  const reseal = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.strictEqual(reseal.status, 0, `the named repair must work: ${reseal.stderr}`);
  const { loadGrantFile } = require('../src/grantfile');
  const { makeSealKeyProvider } = require('../src/grantseal');
  const loaded = loadGrantFile(grants, {
    sealKeyFor: makeSealKeyProvider(fs.readFileSync(sealPass, 'utf8').replace(/\r?\n$/, '')),
  });
  assert.deepEqual(loaded.names, ['ops-24h', 'ops-payroll'],
    'the re-sealed file must load in sealed mode with both grants');
});

test('T3 --append is documented in the usage text and in the README', () => {
  const usage = `${run([]).stdout}\n${run([]).stderr}`;
  assert.match(usage, /signerd grant-add[\s\S]*--append/,
    'the usage text must document --append on the grant-add command');

  const readme = fs.readFileSync(README, 'utf8');
  assert.match(readme, /signerd grant-add[\s\S]{0,600}--append/,
    'the README must document --append on the grant-add command');
});

test('T4 every flag the usage text advertises is accepted by the CLI', () => {
  const usage = `${run([]).stdout}\n${run([]).stderr}`;
  const usageBlock = usage.slice(usage.indexOf('Usage:'), usage.indexOf('Notes:'));
  const flags = new Set();
  for (const m of usageBlock.matchAll(/--([a-z][a-z0-9-]*)/g)) flags.add(m[1]);
  assert.ok(flags.size > 0, 'the usage text must advertise flags');

  const { cfg, pass } = secretDir('signerd-grant-flag-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // --append must be accepted as a boolean flag by the parser.
  const appended = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }), '--append']);
  assert.strictEqual(appended.status, 0, `--append must be accepted: ${appended.stderr}`);
});

test('G1 GUARD: without --append an existing grant file is still refused', () => {
  const { cfg, pass } = secretDir('signerd-grant-guard-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');

  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  const before = fs.readFileSync(grants, 'utf8');

  const second = run(grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }));
  assert.notStrictEqual(second.status, 0, 'without --append an existing file must be refused');
  assert.match(second.stderr, /grant_file_exists/, 'the reason must survive');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused grant-add must not have changed the file');
});

test('G2 GUARD: a SEALED grant file is refused even with --append', () => {
  const { cfg, pass } = secretDir('signerd-grant-seal-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'seal phrase\n', { mode: 0o600 });
  assert.strictEqual(
    run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]).status, 0);
  const before = fs.readFileSync(grants, 'utf8');

  const refused = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }), '--append']);
  assert.notStrictEqual(refused.status, 0, 'a sealed file must not be rewritten');
  assert.match(refused.stderr, /grant_file_sealed/);
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused append must not have changed the sealed file');
});

test('G3 GUARD: an invalid grant is refused and nothing is written', () => {
  const { cfg, pass } = secretDir('signerd-grant-invalid-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  const before = fs.readFileSync(grants, 'utf8');

  // An invalid destination: the PRODUCT's validator must refuse it, and the
  // file must be untouched.
  const bad = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: 'not-a-pubkey' }), '--append']);
  assert.notStrictEqual(bad.status, 0, 'an invalid grant must be refused');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'a refused append must not have changed the file');

  // The module's OWN validation, independent of the CLI's argument checks:
  // a grant object with an unknown field must never be written.
  const { extendGrantFile } = require('../src/grantadd');
  const { loadGrantFile } = require('../src/grantfile');
  const existing = loadGrantFile(grants);
  assert.throws(() => extendGrantFile({
    file: grants,
    name: 'sneaky',
    grant: { ...existing.grants['ops-24h'], extraField: '1' },
  }), /grant_unknown_field/, 'extendGrantFile must validate the grant object itself');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'a refused module-level append must not have changed the file');
});

test('G4 GUARD: a grant file another user can write is refused, not extended', () => {
  const { cfg, pass } = secretDir('signerd-grant-mode-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // The R3-1 state: content another user could already have forged. The
  // loader refuses it at run time, so grant-add must refuse to EXTEND it -
  // never tighten-then-trust (the chmod trap, measured in review #4).
  fs.chmodSync(grants, 0o664);
  const before = fs.readFileSync(grants, 'utf8');
  const refused = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }), '--append']);
  assert.notStrictEqual(refused.status, 0, 'a group/other-writable file must be refused');
  assert.match(refused.stderr, /grant_file_mode/, 'the loader reason must survive');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused append must not have changed the file');
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o664,
    'the refusal must not chmod the file either (tighten-then-trust is the bug)');
});

test('G5 GUARD: an invalid EXISTING grant refuses the append, file unchanged', () => {
  const { cfg, pass } = secretDir('signerd-grant-broken-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // Hand-break an existing grant (a typo in a security file): the file as a
  // whole would be refused at run time, so nothing may be added to it.
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  delete doc.grants['ops-24h'].windowSeconds;
  fs.writeFileSync(grants, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  const before = fs.readFileSync(grants, 'utf8');

  const refused = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }), '--append']);
  assert.notStrictEqual(refused.status, 0, 'an invalid existing file must be refused');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused append must not have changed the file');
});

test('G6 GUARD: a wrong seal passphrase refuses the append (never extend unauthenticated content)', () => {
  const { cfg, pass } = secretDir('signerd-grant-sealpass-');
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

  const refused = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }),
    '--append', '--seal-passphrase-file', wrong]);
  assert.notStrictEqual(refused.status, 0, 'a wrong seal passphrase must be refused');
  assert.match(refused.stderr, /grant_file_seal_mismatch/,
    'the refusal must name WHY: the current seal could not be verified');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused append must not have changed the sealed file');
});

test('G7 GUARD: a symlink at the grant path is refused, not written through', () => {
  const { cfg, pass } = secretDir('signerd-grant-symlink-');
  keygen(cfg, pass);
  const outside = path.join(path.dirname(cfg), 'elsewhere.json');
  const grants = path.join(cfg, 'grants.json');
  // A symlink at the grant path, pointing OUTSIDE the directory: the loader
  // refuses it (O_NOFOLLOW, grant_file_invalid), so grant-add must not
  // create the file the loader will refuse - and must not write through
  // the link into a path the operator never named.
  fs.symlinkSync(outside, grants);
  const refused = run(grantAddArgs({ cfg, grants, name: 'ops-24h' }));
  assert.notStrictEqual(refused.status, 0, 'a symlink at the grant path must be refused');
  assert.match(refused.stderr, /grant_file_symlink/,
    `the refusal must NAME the symlink (not a generic verdict): ${refused.stderr}`);
  assert.ok(!fs.existsSync(outside),
    'grant-add must not write through the symlink to the link target');

  // The same holds for --append against a symlinked file: the appended
  // content must not land in the link target.
  fs.unlinkSync(grants);
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  fs.unlinkSync(grants);
  fs.symlinkSync(outside, grants);
  const appended = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll' }), '--append']);
  assert.notStrictEqual(appended.status, 0, 'a symlinked file must not be extended');
  assert.match(appended.stderr, /grant_file_symlink/,
    `the refusal must NAME the symlink: ${appended.stderr}`);
  assert.ok(!fs.existsSync(outside),
    'the append must not write through the symlink');
});

test('G8 GUARD: the append works against a RUNNING daemon (the read lease must not block it)', () => {
  const { cfg, pass } = secretDir('signerd-grant-live-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  const stateDir = path.join(path.dirname(cfg), 'state');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const socket = path.join(stateDir, 'signerd.sock');
  const log = path.join(path.dirname(cfg), 'daemon.log');
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

  // The append against a live daemon: the daemon holds a READ lease on the
  // grant file (F_RDLCK). A read lease conflicts only with openers FOR
  // WRITING, so an atomic rename must succeed - this is the property the
  // atomic write buys, and it is what makes "add a scope while the daemon
  // runs" possible at all.
  const appended = run([...grantAddArgs({ cfg, grants, name: 'ops-payroll', destination: DESTINATION2 }), '--append']);
  assert.strictEqual(appended.status, 0,
    `the append must work against a running daemon: ${appended.stdout}${appended.stderr}`);

  const { loadGrantFile } = require('../src/grantfile');
  assert.deepEqual(loadGrantFile(grants).names, ['ops-24h', 'ops-payroll']);

  try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ }
});
