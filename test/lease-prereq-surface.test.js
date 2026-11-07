'use strict';

// THE COMPILER-PREREQUISITE REFUSAL: a stranger who cannot build the lease
// helper must be told WHAT is missing and HOW to repair it.
//
// WHY (measured 2026-11-07, live, against the PUBLISHED tag v0.2.7
// installed from an empty directory with
// `npm install github:auroraxo/signerd#v0.2.7`):
//
//   The daemon needs a small C helper (`tools/leasecheck.c`) for the
//   kernel-enforced read lease that guards the grant file. The tarball
//   ships the SOURCE, not the binary (a checked-in binary would be an
//   opaque trust dependency - stated in the README), so the helper is
//   compiled at runtime with `cc`.
//
//   On a machine without a C compiler, the stranger's first hour goes:
//
//     keygen        -> exit 0
//     grant-add     -> exit 0
//     signerd run   -> exit 1
//                      grant_file_lease_unavailable: grant_file_lease_unavailable: spawnSync cc ENOENT
//
//   Three defects in ONE refusal:
//
//   D1 THE VERDICT IS DOUBLED. The code appears twice. The CLI prints
//      `${err.code}: ${err.message}` and `fail()` builds the message as
//      `${code}: ${detail}`, so a message that already carries the code
//      prints it twice - every OTHER refusal prints it once.
//   D2 THE DETAIL IS AN INTERNAL NAME. "spawnSync cc ENOENT" is Node's
//      internal API name: the stranger does not know that `cc` is the
//      compiler, that it is MISSING rather than broken, or what needs it.
//   D3 THERE IS NO REPAIR. Every other first-contact refusal names its
//      fix on a `fix:` line. This one does not, so installing a compiler
//      (or pointing CC at one) is undiscoverable.
//
//   Second failure mode, same day, same family: the install directory is
//   READ-ONLY (root-owned global npm prefix, read-only container layer),
//   the compile fails, and the refusal is two lines of a raw ld dump -
//   `collect2: error: ld returned 1 exit status` - with the real cause
//   (the helper must be written somewhere writable) never stated.
//
// THE CONTRACT:
//   C1 the refusal names the repair on a `fix:` line: a C compiler is
//      required, CC selects it, and the helper is built from the shipped
//      source.
//   C2 the machine-readable code appears EXACTLY ONCE - no doubled
//      verdict - and the first field is still `grant_file_*`/`ledger_*`.
//   C3 the detail speaks the stranger's terms: the COMPILER is missing or
//      unusable - not "spawnSync cc ENOENT", and no raw ld/cc dump.
//   C4 the refusal names the helper it could not build (leasecheck), so
//      an operator with a read-only install dir sees WHICH path.
//   C5 the read-only-install failure gets its own repair (build the helper
//      where it is writable) instead of a leaked compiler dump.
//   C6 GUARD (green on both trees): with a working compiler the daemon
//      starts and signs - the fix must not weaken the lease rules.
//   C7 GUARD (green on both trees): a MISSING grant file still refuses
//      with `grant_file_unreadable` and its own repair.
//
// HOW THE STRANGER TREE IS BUILT (offline, no network):
//   A fresh directory containing exactly what the tarball ships - bin/,
//   src/, examples/, tools/leasecheck.c, package.json - with the COMPILED
//   helper deliberately absent (that is the stranger's tree: the tarball
//   never contains it) and node_modules linked from the checkout. The
//   daemon therefore has to compile the helper at runtime, which is
//   exactly the step that fails.
//
// The ladder: C1-C5 RED on the pre-fix tree, C6/C7 GREEN on both.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI_REL = path.join('bin', 'signerd.js');

// `files` in package.json, minus the compiled helper: what the tarball ships.
const SHIPPED_DIRS = ['bin', 'src', 'examples'];
const SHIPPED_FILES = ['package.json', 'LICENSE', 'README.md'];

// CC is read by src/lease.js; pointing it at a path that cannot exist is
// the deterministic, PATH-independent way to reach "no compiler".
const MISSING_CC = path.join(os.tmpdir(), 'signerd-no-such-compiler-for-measurement');

function copyShippedTree(dest, { readOnlyTools }) {
  for (const d of SHIPPED_DIRS) {
    fs.cpSync(path.join(ROOT, d), path.join(dest, d), { recursive: true });
  }
  for (const f of SHIPPED_FILES) {
    fs.copyFileSync(path.join(ROOT, f), path.join(dest, f));
  }
  fs.mkdirSync(path.join(dest, 'tools'), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'tools', 'leasecheck.c'), path.join(dest, 'tools', 'leasecheck.c'));
  // The compiled helper must NOT exist: the tarball never ships it.
  assert.ok(!fs.existsSync(path.join(dest, 'tools', 'leasecheck')),
    'the stranger tree must not carry a prebuilt helper');
  // node_modules from the checkout (offline; the dependency set is the same).
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dest, 'node_modules'), 'dir');
  if (readOnlyTools) fs.chmodSync(path.join(dest, 'tools'), 0o555);
  return path.join(dest, CLI_REL);
}

function strangerSandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lease-sb-'));
  const sb = path.join(dir, 'sb');
  fs.mkdirSync(sb, { mode: 0o700 });
  const pass = path.join(sb, 'pass');
  fs.writeFileSync(pass, 'lease-prereq passphrase\n', { mode: 0o600 });
  return { root: dir, sb, pass };
}

function cli(tree, args, env) {
  const res = spawnSync(process.execPath, [tree, ...args], {
    encoding: 'utf8', timeout: 60000, env: { ...process.env, ...env },
  });
  return { status: res.status, stderr: res.stderr || '', stdout: res.stdout || '' };
}

function makeInputs(tree, sb, pass) {
  const keygen = cli(tree, ['keygen', '--keystore', path.join(sb, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen must work: ${keygen.stderr}`);
  const add = cli(tree, ['grant-add',
    '--grants', path.join(sb, 'grants.json'), '--name', 'ops-24h',
    '--keystore', path.join(sb, 'ops.key'),
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000', '--window-max-lamports', '500000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(add.status, 0, `grant-add must work: ${add.stderr}`);
}

function runArgs(sb) {
  return ['run',
    '--keystore', path.join(sb, 'ops.key'),
    '--passphrase-file', path.join(sb, 'pass'),
    '--grants', path.join(sb, 'grants.json'),
    '--ledger', path.join(sb, 'journal.jsonl'),
    '--socket', path.join(sb, 'signerd.sock')];
}

test('C1/C3/C4: the no-compiler refusal names the repair, the code once, and the helper', () => {
  const tree = copyShippedTree(fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lease-nocc-')),
    { readOnlyTools: false });
  const { sb, pass } = strangerSandbox();
  makeInputs(tree, sb, pass);

  const res = cli(tree, runArgs(sb), { CC: MISSING_CC });
  assert.notStrictEqual(res.status, 0, 'the daemon must not start without its lease helper');

  // C1: name the repair.
  assert.match(res.stderr, /fix:/, `the refusal must name the repair, got: ${res.stderr}`);
  assert.match(res.stderr, /CC=/, `the fix must name the CC knob, got: ${res.stderr}`);
  assert.match(res.stderr, /compiler/i,
    `the fix must say a COMPILER is missing, got: ${res.stderr}`);

  // C2: the code appears exactly once and is the first field.
  const first = res.stderr.split('\n')[0] || '';
  const code = (first.split(':')[0] || '').trim();
  assert.match(code, /^(grant_file|ledger)_[a-z_]+$/,
    `the first field must be the machine-readable code, got: ${first}`);
  const escaped = code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const occurrences = (res.stderr.match(new RegExp(escaped, 'g')) || []).length;
  assert.strictEqual(occurrences, 1,
    `the code must appear exactly once, got ${occurrences}: ${res.stderr}`);

  // C3: stranger's terms, no internals.
  assert.doesNotMatch(res.stderr, /spawnSync/,
    `the internal Node API name must not reach the stranger: ${res.stderr}`);
  assert.doesNotMatch(res.stderr, /collect2|ld: cannot open output file/,
    `a raw compiler dump must not reach the stranger: ${res.stderr}`);
  assert.match(res.stderr, /compiler/i, `the refusal must name the compiler: ${res.stderr}`);

  // C4: name the helper that could not be built.
  assert.match(res.stderr, /leasecheck/,
    `the refusal must name the helper, got: ${res.stderr}`);
});

test('C5: a READ-ONLY install dir gets its own repair, not a leaked ld dump', () => {
  const tree = copyShippedTree(fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lease-ro-')),
    { readOnlyTools: true });
  const { sb, pass } = strangerSandbox();
  makeInputs(tree, sb, pass);

  const res = cli(tree, runArgs(sb), {});
  assert.notStrictEqual(res.status, 0, 'the daemon must not start without its lease helper');

  // The leak that was measured live: two lines of compiler internals.
  assert.doesNotMatch(res.stderr, /collect2/,
    `a raw compiler dump must not reach the stranger: ${res.stderr}`);
  assert.doesNotMatch(res.stderr, /ld: cannot open output file/,
    `a raw ld dump must not reach the stranger: ${res.stderr}`);
  assert.doesNotMatch(res.stderr, /spawnSync/,
    `the internal Node API name must not reach the stranger: ${res.stderr}`);

  // It must still be recognisably the lease refusal, and it must repair.
  assert.match(res.stderr, /leasecheck/,
    `the refusal must name the helper, got: ${res.stderr}`);
  assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
  const first = res.stderr.split('\n')[0] || '';
  const code = (first.split(':')[0] || '').trim();
  assert.strictEqual((res.stderr.match(new RegExp(code, 'g')) || []).length, 1,
    `the code must appear exactly once, got: ${res.stderr}`);
});

test('C6 GUARD: with a working compiler the daemon starts (green on both trees)', async (t) => {
  // Uses the CHECKOUT tree, where pretest has built the helper - the
  // ordinary path the fix must not disturb.
  const helper = path.join(ROOT, 'tools', 'leasecheck');
  if (!fs.existsSync(helper)) {
    const build = spawnSync('cc', ['-O2', '-o', helper, path.join(ROOT, 'tools', 'leasecheck.c')],
      { encoding: 'utf8', timeout: 60000 });
    if (build.status !== 0) t.skip('no C compiler on this host to build the helper');
  }
  const tree = path.join(ROOT, CLI_REL);
  const { sb, pass } = strangerSandbox();
  makeInputs(tree, sb, pass);

  const res = spawnSync(process.execPath, [tree, ...runArgs(sb)], {
    encoding: 'utf8', timeout: 20000, env: process.env,
  });
  // A successful start prints {"ok":true,...} and then the process BLOCKS
  // serving the socket; on timeout the daemon was running.
  const started = (res.status === 0 && /"ok"\s*:\s*true/.test(res.stdout)) ||
    res.error?.code === 'ETIMEDOUT' || res.signal === 'SIGTERM';
  assert.ok(started,
    `the daemon must start when the helper can be built: status=${res.status} ${res.stderr}`);
  fs.rmSync(sb, { recursive: true, force: true });
});

test('C7 GUARD: a MISSING grant file still refuses with its own code and repair', () => {
  // Green on both trees: the lease-specific handling must not swallow the
  // ordinary missing-grant-file refusal (quickstart-grantfile pins it).
  const tree = copyShippedTree(fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lease-miss-')),
    { readOnlyTools: false });
  const { sb, pass } = strangerSandbox();
  const keygen = cli(tree, ['keygen', '--keystore', path.join(sb, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen must work: ${keygen.stderr}`);

  const res = cli(tree, ['run',
    '--keystore', path.join(sb, 'ops.key'), '--passphrase-file', pass,
    '--grants', path.join(sb, 'absent.json'),
    '--ledger', path.join(sb, 'journal.jsonl'),
    '--socket', path.join(sb, 'signerd.sock')]);
  assert.notStrictEqual(res.status, 0, 'a missing grant file must refuse');
  assert.match(res.stderr, /grant_file_unreadable/,
    `the machine-readable reason must stay, got: ${res.stderr}`);
  assert.match(res.stderr, /fix:/,
    `the refusal must still name the repair, got: ${res.stderr}`);
});
