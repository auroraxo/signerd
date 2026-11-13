'use strict';
// The KEYSTORE path's contact with a stranger, measured 2026-11-13 against
// the PUBLISHED v0.2.21 tree (tools/measure-keystore-symlink.js):
//
//   - `signerd keygen --keystore <link> --overwrite` wrote THROUGH the link
//     and destroyed the file the link pointed at;
//   - a DANGLING link made the key document appear OUTSIDE the directory
//     the operator named;
//   - `signerd run` and the public-key reader ACCEPTED a link and reported
//     the mode of whatever the link landed on, not of the path in use.
//
// The grant path has refused a link by NAME since v0.2.20 (grant_file_symlink);
// the keystore path now carries the same rule. This file pins the CLI
// SURFACE: every command that touches the keystore must refuse a link by
// name and name the repair (house rule: "name the repair, not just the
// verdict").
//
// Ladder: RED on the published v0.2.21 tree (the instrument IS the fix),
// GREEN here.
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

function victimWithLink() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-kssym-cli-'));
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(victim, link);
  return { dir, victim, link, original };
}

test('S1 keygen onto a symlink refuses by name and names the repair', () => {
  const { cfg, pass } = secretDir('signerd-kssym-cli-');
  const { victim, link, original } = victimWithLink();
  const r = run(['keygen', '--keystore', link, '--passphrase-file', pass]);
  assert.equal(r.status, 1, `expected a refusal, got: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /keystore_symlink/, `the refusal must name the symlink: ${r.stderr}`);
  assert.match(r.stderr, /fix:/i, `the refusal must name a repair: ${r.stderr}`);
  assert.equal(fs.readFileSync(victim, 'utf8'), original, 'the link target must not be touched');
  assert.ok(fs.lstatSync(link).isSymbolicLink(), 'the link itself stands');
  void cfg;
});

test('S2 keygen --overwrite onto a symlink refuses too (not an arbitrary-overwrite primitive)', () => {
  const { pass } = secretDir('signerd-kssym-cli-');
  const { victim, link, original } = victimWithLink();
  const r = run(['keygen', '--keystore', link, '--passphrase-file', pass, '--overwrite']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /keystore_symlink/);
  assert.equal(fs.readFileSync(victim, 'utf8'), original);
});

test('S3 import onto a symlink refuses by name', () => {
  const { pass } = secretDir('signerd-kssym-cli-');
  const { victim, link, original } = victimWithLink();
  const src = path.join(path.dirname(victim), 'id.json');
  fs.writeFileSync(src, JSON.stringify(new Array(64).fill(1)));
  const r = run(['import', '--keystore', link, '--from', src, '--passphrase-file', pass]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /keystore_symlink/);
  assert.equal(fs.readFileSync(victim, 'utf8'), original);
});

test('S4 a dangling symlink gets no key document outside the named path', () => {
  const { pass } = secretDir('signerd-kssym-cli-');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-kssym-cli-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-kssym-out-'));
  const link = path.join(dir, 'ops.key');
  const hidden = path.join(outside, 'ops.key');
  fs.symlinkSync(hidden, link);
  const r = run(['keygen', '--keystore', link, '--passphrase-file', pass]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /keystore_symlink/);
  assert.equal(fs.existsSync(hidden), false, 'no key document may appear at the link target');
});

test('S5 the ordinary keygen path is unchanged (the rule does not break the happy path)', () => {
  const { pass } = secretDir('signerd-kssym-cli-');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-kssym-cli-'));
  const file = path.join(dir, 'ops.key');
  const r = run(['keygen', '--keystore', file, '--passphrase-file', pass]);
  assert.equal(r.status, 0, `keygen must still work: ${r.stderr}`);
  const out = JSON.parse(r.stdout.trim());
  assert.ok(out.publicKey, 'the public key must be reported');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(dir), ['ops.key'], 'no temp leftovers');
});
