'use strict';
// THE MESSAGE BOOTSTRAP MUST JUDGE WITH THE PRODUCT'S OWN LOADER
// (measured 2026-11-11, probes /tmp/pulseT*, /tmp/pulseU*):
//
// `sign-message --add-grant` is the quickstart's one-flag grant bootstrap
// (src/grantadd.js addGrantToFile). When the grant file ALREADY EXISTS it
// hand-rolled its own JSON.parse and only checked version/seal/name — it
// never ran the file through the product's loader (src/grantfile.js), the
// judge that EVERY other write path consults:
//
//   - extendGrantFile   (`grant-add --append`):  "THE JUDGE: the product's
//     loader, ... Nothing is written until the whole file has been accepted."
//   - removeGrantFromFile (`grant-remove`):       same rule, same wording.
//
// So the bootstrap could take a file the daemon REFUSES AT START and add a
// grant to it, reporting success. Measured on this tree before the fix:
//
//   B1  a file whose existing tx grant has windowMaxLamports:"1" (a cap the
//       daemon can never honour): bootstrap printed
//       {"ok":true,...,"bootstrapped":true}; `run` then died with
//       `grant_field_invalid: broken.format`. The command manufactured a
//       state the product refuses — the keygen-loop lesson, on the grant file.
//   B2  a file with mode 0664 (group-writable: content provenance lost, R3-1):
//       `verify-grants` and `grant-add --append` both refuse with
//       `grant_file_mode: 664`; bootstrap SUCCEEDED and silently rewrote the
//       file at 0600 — tightening the mode cannot restore provenance, and the
//       silent repair clobbers the operator's own hygiene signal.
//   B4  a BROKEN file that already contains the grant name: bootstrap printed
//       {"ok":true,...,"bootstrapped":false} — a success verdict for a file
//       the daemon will refuse at start.
//
// WHAT THIS FILE PINS — the bootstrap must refuse, BEFORE writing, exactly
// what the loader refuses at run time (the same rule the append path keeps),
// and must still WORK on every file the loader accepts:
//   B1 an invalid existing grant refuses the bootstrap, file untouched;
//   B2 a group/other-writable file refuses the bootstrap, file untouched and
//      NOT chmod-repaired (tighten-then-trust is the bug);
//   B3 a symlink at the grant path is refused, never written through;
//   B4 a broken file that already holds the name is refused by the loader —
//      no ok:true for a dead-on-arrival file;
//   G1 GUARD: bootstrap into a VALID existing file still works (this is the
//      quickstart's documented path — the fix must not break it);
//   G2 GUARD: bootstrap into a MISSING file still creates it;
//   G3 GUARD: a SEALED file is still refused, seal intact.
//
// Ladder: RED on any tree whose addGrantToFile parses instead of loading;
// GREEN when the loader is the judge.
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

function secretDir(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);
  return { root, cfg, pass };
}

function keygen(cfg, pass) {
  const r = run(['keygen', '--keystore', path.join(cfg, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(r.status, 0, `keygen failed: ${r.stderr}`);
  return JSON.parse(r.stdout.trim().split('\n').pop());
}

const DESTINATION = 'So11111111111111111111111111111111111111112';

function grantAddArgs({ cfg, grants, name }) {
  return ['grant-add', '--grants', grants, '--name', name,
    '--keystore', path.join(cfg, 'ops.key'), '--destination', DESTINATION,
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'];
}

// A body for the message bootstrap (openreceipts/v1, one claim key).
function writeBody(root) {
  const body = path.join(root, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'probe', type: 'release',
    subject: 'probe/repo',
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    claims: { version: 'v1' },
  }, null, 2));
  return body;
}

// The documented one-flag bootstrap. The socket is deliberately dead: the
// grant write happens BEFORE the round trip, so the bootstrap verdict is
// fully observable without a daemon (quickstart-grantfile.test.js pins this
// ordering). On the refusal ladder the bootstrap error must surface with a
// non-zero exit and no socket errno as the FIRST failure.
function bootstrap({ cfg, grants, body, name = 'releases' }) {
  return run(['sign-message', '--socket', '/tmp/signerd-bootstrap-judge-none.sock',
    '--grant', name, '--body', body, '--out', path.join(path.dirname(body), 'out.json'),
    '--add-grant', '--keystore', path.join(cfg, 'ops.key'), '--grants', grants]);
}

function brokenFile(grantsPath, name = 'broken') {
  // An existing tx grant whose windowMaxLamports is below the base fee: the
  // loader refuses it (grant_field_invalid) and the daemon refuses the whole
  // file at start. Mode stays 0600: the ONLY defect is the value.
  const doc = { version: 1, grants: { [name]: {
    signer: DESTINATION, destination: DESTINATION, maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z', windowMaxLamports: '1', windowSeconds: '60',
  } } };
  fs.writeFileSync(grantsPath, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grantsPath, 0o600);
}

// ---------------------------------------------------------------- refusals
test('B1 an invalid EXISTING grant refuses the bootstrap, file untouched', () => {
  const { cfg, pass } = secretDir('signerd-boot-broken-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = writeBody(cfg);
  brokenFile(grants);
  const before = fs.readFileSync(grants, 'utf8');

  const r = bootstrap({ cfg, grants, body });
  const log = `${r.stdout}\n${r.stderr}`;
  assert.notStrictEqual(r.status, 0, 'the bootstrap must refuse a file the daemon refuses');
  assert.match(r.stderr, /grant_field_invalid/, `the refusal must carry the loader's reason: ${log}`);
  assert.doesNotMatch(log, /"bootstrapped":true/, 'no success verdict for a dead-on-arrival file');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused bootstrap must not have changed the file');
});

test('B2 a group/other-writable file refuses the bootstrap, not a silent chmod-repair', () => {
  const { cfg, pass } = secretDir('signerd-boot-mode-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = writeBody(cfg);
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  // The R3-1 state: content another user could already have forged. The
  // loader refuses it at run time, verify-grants refuses it, --append refuses
  // it (grant-append-surface G4) — the bootstrap must too. Tightening the
  // mode cannot restore provenance; silently rewriting at 0600 manufactures
  // trust that the rest of the product correctly refuses (measured: mode
  // after the buggy bootstrap: 600, grants: r).
  fs.chmodSync(grants, 0o664);
  const before = fs.readFileSync(grants, 'utf8');

  const r = bootstrap({ cfg, grants, body });
  assert.notStrictEqual(r.status, 0, 'a group/other-writable file must be refused');
  assert.match(r.stderr, /grant_file_mode/, 'the loader reason must survive');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused bootstrap must not have changed the bytes');
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o664,
    'the refusal must not chmod the file either (tighten-then-trust is the bug)');
});

test('B3 a symlink at the grant path is refused, never written through', () => {
  const { cfg, pass } = secretDir('signerd-boot-symlink-');
  keygen(cfg, pass);
  const body = writeBody(cfg);
  // A LINKED file whose target the loader ACCEPTS: only the lstat-first
  // refusal can catch this — parse-then-rename would swap the link for a
  // regular file and orphan the target (the same defect grant-add measured
  // 2026-11-05, pinned in grant-append-surface G7).
  const target = path.join(cfg, 'real-target.json');
  const { loadGrantFile } = require('../src/grantfile');
  void loadGrantFile; // the target must be a file the loader accepts
  assert.strictEqual(run(grantAddArgs({ cfg, grants: target, name: 'ops-24h' })).status, 0);
  const before = fs.readFileSync(target, 'utf8');
  const grants = path.join(cfg, 'grants.json');
  fs.symlinkSync(target, grants);

  const r = bootstrap({ cfg, grants, body });
  assert.notStrictEqual(r.status, 0, 'a symlink must be refused, not followed');
  assert.match(r.stderr, /grant_file_symlink/, `the refusal must name the symlink: ${r.stderr}`);
  assert.ok(fs.lstatSync(grants).isSymbolicLink(), 'the refused bootstrap must not replace the link');
  assert.strictEqual(fs.readFileSync(target, 'utf8'), before, 'the link target must be untouched');
});

test('B4 a broken file that ALREADY holds the grant name is refused by the loader', () => {
  const { cfg, pass } = secretDir('signerd-boot-exists-broken-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = writeBody(cfg);
  // The B4 probe shape: the name exists in a file the loader refuses. The
  // old short-circuit printed {"ok":true,...,"bootstrapped":false} — a
  // success verdict for a file the daemon will refuse at start. The append
  // path judges FIRST (extendGrantFile: loader, then grant_exists); the
  // bootstrap must keep the same order.
  brokenFile(grants, 'releases');
  const before = fs.readFileSync(grants, 'utf8');

  const r = bootstrap({ cfg, grants, body });
  assert.notStrictEqual(r.status, 0, 'a dead-on-arrival file must not yield ok:true');
  assert.match(r.stderr, /grant_field_invalid/, 'the loader must judge before the name check');
  assert.doesNotMatch(`${r.stdout}\n${r.stderr}`, /"ok":true/, 'no ok verdict for a refused file');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before, 'the file must be untouched');
});

// ----------------------------------------------------------------- guards
test('G1 GUARD: bootstrap into a VALID existing file still works', () => {
  const { cfg, pass } = secretDir('signerd-boot-valid-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = writeBody(cfg);
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);

  const r = bootstrap({ cfg, grants, body });
  assert.match(r.stderr, /"bootstrapped":true/,
    `the documented one-flag bootstrap must still work: ${r.stdout}\n${r.stderr}`);
  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.deepStrictEqual(loaded.names.sort(), ['ops-24h', 'releases'],
    'the file must load with the existing grant byte-identically plus the new one');
  assert.strictEqual(fs.statSync(grants).mode & 0o777, 0o600, 'the rewritten file is 0600');
});

test('G2 GUARD: bootstrap into a MISSING file still creates it', () => {
  const { cfg, pass } = secretDir('signerd-boot-missing-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = writeBody(cfg);

  const r = bootstrap({ cfg, grants, body });
  assert.match(r.stderr, /"bootstrapped":true/,
    `create must still work: ${r.stdout}\n${r.stderr}`);
  const { loadGrantFile } = require('../src/grantfile');
  const loaded = loadGrantFile(grants);
  assert.deepStrictEqual(loaded.names, ['releases']);
});

test('G3 GUARD: a SEALED grant file is still refused, seal intact', () => {
  const { cfg, pass } = secretDir('signerd-boot-sealed-');
  keygen(cfg, pass);
  const grants = path.join(cfg, 'grants.json');
  const body = writeBody(cfg);
  assert.strictEqual(run(grantAddArgs({ cfg, grants, name: 'ops-24h' })).status, 0);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  assert.strictEqual(run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]).status, 0);
  const before = fs.readFileSync(grants, 'utf8');

  const r = bootstrap({ cfg, grants, body });
  assert.notStrictEqual(r.status, 0, 'a sealed file must not be rewritten by the bootstrap');
  assert.match(r.stderr, /grant_file_sealed/);
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before, 'the seal must be intact');
});
