'use strict';

// THE GRANT-FILE REFUSALS SPEAK IN ONE VOICE (2026-11-08).
//
// WHY (measured 2026-11-08, live, on this tree):
//
//   The lease-helper fix (test/lease-prereq-surface.test.js) established
//   the house rule for a refusal: the machine-readable code appears
//   EXACTLY ONCE, and the refusal names its repair on a `fix:` line.
//   Measured against the same tree, the GRANT-file refusals did not:
//
//   G1 DOUBLED VERDICT. `grant-add --append` into a grant file another
//      user can write refused with:
//
//        grant_file_mode: grant_file_mode: 666
//
//      and `grant-remove` on a missing file with:
//
//        grant_file_unreadable: grant_file_unreadable: ENOENT
//
//      Same shape as the lease defect: every `fail()` helper builds the
//      message as `${code}: ${detail}`, and every printer writes
//      `${err.code}: ${err.message}` - so the code is printed twice.
//      A log parser reading the first field is fine; a human reading
//      the line sees a corrupted verdict.
//
//   G2 NO CODE, NO REPAIR. `grant-add` into a READ-ONLY directory (a
//      root-owned config dir, a read-only container layer - the same
//      shape as the read-only npm install dir measured for the lease
//      helper) refused with a bare errno and nothing else:
//
//        EACCES: permission denied, open '/tmp/.../ro/g.json'
//
//      No machine-readable code, no `fix:` line, and the reason the
//      command exists for - the directory is not writable - never
//      stated. The APPEND path already had this repair
//      (`grant_file_write_failed` -> "check the directory is writable
//      and has space"); the CREATE path did not, because it wrote the
//      file with a raw `fs.writeFileSync` outside the atomic writer.
//
// THE CONTRACT:
//   C1 the code appears EXACTLY ONCE in every grant-file refusal -
//      grant_file_mode, grant_file_unreadable, grant_file_dir_mode,
//      grant_file_write_failed.
//   C2 every grant-file refusal carries a `fix:` line.
//   C3 a refusal to WRITE the grant file (read-only directory) names
//      the machine-readable code `grant_file_write_failed` - not a bare
//      errno - and says the directory is not writable.
//   C4 GUARD (green on both trees): a grant file another user can write
//      is still refused `grant_file_mode` - the fix must not loosen it.
//   C5 GUARD (green on both trees): the daemon still refuses a grant
//      file it cannot read, with its own code.
//
// HOW THE TREE IS BUILT: the checkout's own CLI (the ordinary path a
// stranger walks), in a temp sandbox. No network, no daemon needed for
// the refusals; the guards use the loader directly.
//
// THE LADDER: C1-C3 are RED on the pre-fix tree, C4/C5 GREEN on both.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-grantvoice-'));
  const sb = path.join(dir, 'sb');
  fs.mkdirSync(sb, { mode: 0o700 });
  const pass = path.join(sb, 'pass');
  fs.writeFileSync(pass, 'grant-voice passphrase\n', { mode: 0o600 });
  return { dir, sb, pass };
}

function cli(args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

const DEST = 'So11111111111111111111111111111111111111112';

function keygen(sb, pass) {
  const r = cli(['keygen', '--keystore', path.join(sb, 'ops.key'), '--passphrase-file', pass]);
  assert.strictEqual(r.status, 0, `keygen must work: ${r.stderr}`);
}

function addArgs(sb, grants, name = 'ops-24h') {
  return ['grant-add', '--grants', grants, '--name', name,
    '--keystore', path.join(sb, 'ops.key'),
    '--destination', DEST,
    '--max-lamports', '500000', '--window-max-lamports', '500000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'];
}

/** The machine-readable code, and how many times it occurs. */
function verdictOf(out) {
  const first = (out.split('\n')[0] || '').trim();
  const code = (first.split(':')[0] || '').trim();
  const occurrences = code
    ? (out.match(new RegExp(code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length
    : 0;
  return { code, occurrences };
}

test('C1/C2: the grant-file refusals print their code ONCE and name a repair', () => {
  const { sb, pass } = sandbox();
  keygen(sb, pass);
  const grants = path.join(sb, 'grants.json');

  // 1. grant-remove on a MISSING file (the doubled grant_file_unreadable).
  const missing = cli(['grant-remove', '--grants', path.join(sb, 'absent.json'), '--name', 'ops-24h']);
  assert.notStrictEqual(missing.status, 0, 'a missing grant file must refuse');
  {
    const { code, occurrences } = verdictOf(`${missing.stdout}${missing.stderr}`);
    assert.match(code, /^grant_file_[a-z_]+$/, `the first field must be the code, got: ${code}`);
    assert.strictEqual(occurrences, 1,
      `the code must appear exactly once, got ${occurrences}: ${missing.stderr}`);
    assert.match(missing.stderr, /\bfix:/, `the refusal must name the repair: ${missing.stderr}`);
  }

  // 2. grant-add --append into a file another user can write
  //    (the doubled grant_file_mode).
  assert.strictEqual(cli(addArgs(sb, grants)).status, 0, 'the first grant must be written');
  fs.chmodSync(grants, 0o666);
  const mode = cli(['grant-add', '--append', ...addArgs(sb, grants).slice(1)]);
  assert.notStrictEqual(mode.status, 0, 'a group-writable grant file must be refused');
  {
    const { code, occurrences } = verdictOf(`${mode.stdout}${mode.stderr}`);
    assert.match(code, /^grant_file_[a-z_]+$/, `the first field must be the code, got: ${code}`);
    assert.strictEqual(occurrences, 1,
      `the code must appear exactly once, got ${occurrences}: ${mode.stderr}`);
    assert.match(mode.stderr, /\bfix:/, `the refusal must name the repair: ${mode.stderr}`);
  }
  fs.chmodSync(grants, 0o600);
});

test('C3: a read-only grant directory refuses with grant_file_write_failed and a repair', () => {
  const { sb, pass } = sandbox();
  keygen(sb, pass);
  const ro = path.join(sb, 'ro');
  fs.mkdirSync(ro);
  fs.chmodSync(ro, 0o555);

  const res = cli(addArgs(sb, path.join(ro, 'grants.json')));
  assert.notStrictEqual(res.status, 0, 'a read-only directory must refuse');

  const out = `${res.stdout}${res.stderr}`;
  const { code, occurrences } = verdictOf(out);
  assert.strictEqual(code, 'grant_file_write_failed',
    `the refusal must carry the machine-readable code, got: ${out}`);
  assert.strictEqual(occurrences, 1,
    `the code must appear exactly once, got ${occurrences}: ${out}`);
  assert.match(res.stderr, /\bfix:/, `the refusal must name the repair: ${out}`);
  assert.match(out, /writable/i,
    `the refusal must say the directory is not writable: ${out}`);
  assert.doesNotMatch(out, /^EACCES/m,
    `a bare errno must not be the verdict: ${out}`);

  fs.chmodSync(ro, 0o755);
});

test('C4 GUARD: a group-writable grant file is still refused grant_file_mode (green on both trees)', () => {
  const { sb, pass } = sandbox();
  keygen(sb, pass);
  const grants = path.join(sb, 'grants.json');
  assert.strictEqual(cli(addArgs(sb, grants)).status, 0, 'the first grant must be written');
  fs.chmodSync(grants, 0o666);

  const res = cli(['grant-add', '--append', ...addArgs(sb, grants).slice(1)]);
  assert.notStrictEqual(res.status, 0, 'a group-writable grant file must be refused');
  assert.match(`${res.stdout}${res.stderr}`, /grant_file_mode/,
    'the machine-readable reason must stay');
  fs.chmodSync(grants, 0o600);
});

test('C5 GUARD: the loader still refuses an unreadable grant file with its own code', () => {
  const { loadGrantFile } = require(path.join(ROOT, 'src', 'grantfile.js'));
  const { sb } = sandbox();
  assert.throws(
    () => loadGrantFile(path.join(sb, 'absent.json')),
    (err) => err.code === 'grant_file_unreadable',
    'a missing grant file must refuse with grant_file_unreadable');
});
