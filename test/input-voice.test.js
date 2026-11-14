'use strict';

// OPERATOR-INPUT REFUSAL VOICE: an input file the CLI cannot read must be
// refused BY NAME, with a repair, and with the exit code that says what
// happened.
//
// WHY (measured 2026-11-14 against the PUBLISHED v0.2.22 tree, npm
// signerd@0.2.22):
//
//   The product's contract (docs/GUIDE.md, "The exit code says what
//   happened"):
//
//     exit 0  signed and delivered
//     exit 1  the daemon or the POLICY refused (no signature was made)
//     exit 2  a usage / preflight refusal (no signature was made)
//
//   and the house rule: every refusal names a repair, because "the
//   refusal is the product".
//
//   Three OPERATOR-INPUT read paths did not honour it. A path that could
//   not be read escaped the CLI as a raw Node errno:
//
//     run --passphrase-file <missing>   -> "ENOENT: no such file or
//                                           directory, lstat '...'", exit 1
//     run --passphrase-file <mode 000>  -> "EACCES: permission denied,
//                                           open '...'", exit 1
//     sign --tx <a directory>           -> "EISDIR: illegal operation on
//                                           a directory, read", exit 1
//     sign --tx <mode 000>              -> "EACCES: ...", exit 1
//     sign-message --body <missing>     -> "ENOENT: ...", exit 1
//     sign-message --body <a directory> -> "EISDIR: ...", exit 1
//     sign-message --body <mode 000>    -> "EACCES: ...", exit 1
//
//   A mistyped path is a USAGE refusal (exit 2), not a policy refusal, and
//   a raw errno names no reason the operator can act on. The `--tx`
//   MISSING case already had the product's voice (tx_missing, 2026-11-05);
//   the rest of the class was never swept.
//
// THE CONTRACT (measured, not asserted):
//
//   I1 a MISSING passphrase file is refused by name, with a fix, exit 2
//   I2 an UNREADABLE (mode 000) passphrase file is refused by name, exit 2
//   I3 a passphrase path that is a DIRECTORY is refused by name, exit 2
//   I4 a --tx path that is a DIRECTORY is refused by name, exit 2
//   I5 an UNREADABLE --tx file is refused by name, exit 2
//   I6 a MISSING / DIRECTORY / UNREADABLE --body is refused by name, exit 2
//   I7 NO raw errno ever reaches the operator on these paths (the class of
//      the failure is named, the errno is not the message)
//   G1 GUARD: a readable passphrase file is still refused by the MODE rule
//      with its own reason (not swallowed into the new read voice)
//   G2 GUARD: a --tx that is a LINK to a regular file is still read THROUGH
//      (the link is not the defect)
//   G3 GUARD: the `tx_missing` voice (2026-11-05) is unchanged
//   G4 GUARD: a --body that is a LINK to a regular file is still read
//      THROUGH (the link is not the defect)
//
// No network. No writes outside os.tmpdir(). No real key or daemon needed
// for the refusal faces; the guards use the shipped CLI.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-input-voice-'));
}

function sh(args, opts = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', timeout: 30000, ...opts,
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/** A file nobody may read (mode 000). Skipped where the OS ignores modes. */
function unreadable(dir, name) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, 'secret\n');
  fs.chmodSync(p, 0o000);
  // If the mode does not bite (running as root), the face cannot be tested.
  try {
    fs.readFileSync(p);
    return null;
  } catch {
    return p;
  }
}

// ---------------------------------------------------------------------------
// The refusal faces.

test('I1 a MISSING passphrase file is refused by name with a fix and exit 2', () => {
  const dir = tmpDir();
  try {
    const res = sh(['run', '--keystore', path.join(dir, 'ops.key'),
      '--passphrase-file', path.join(dir, 'no-such.pass'),
      '--grants', path.join(dir, 'grants.json'),
      '--ledger', path.join(dir, 'journal.jsonl'),
      '--socket', path.join(dir, 's.sock')]);
    assert.strictEqual(res.status, 2,
      `a usage refusal must exit 2, got ${res.status}: ${res.stderr}`);
    assert.match(res.stderr, /^passphrase_file_missing:/m,
      `the refusal must be named: ${res.stderr}`);
    assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('I2 an UNREADABLE passphrase file is refused by name with exit 2', () => {
  const dir = tmpDir();
  try {
    const pass = unreadable(dir, 'locked.pass');
    if (!pass) return; // the mode does not bite here
    const res = sh(['run', '--keystore', path.join(dir, 'ops.key'),
      '--passphrase-file', pass,
      '--grants', path.join(dir, 'grants.json'),
      '--ledger', path.join(dir, 'journal.jsonl'),
      '--socket', path.join(dir, 's.sock')]);
    assert.strictEqual(res.status, 2,
      `a usage refusal must exit 2, got ${res.status}: ${res.stderr}`);
    assert.match(res.stderr, /^passphrase_file_unreadable:/m,
      `the refusal must be named: ${res.stderr}`);
    assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('I3 a passphrase path that is a DIRECTORY is refused by name with exit 2', () => {
  const dir = tmpDir();
  try {
    const sub = path.join(dir, 'a-directory');
    fs.mkdirSync(sub);
    const res = sh(['run', '--keystore', path.join(dir, 'ops.key'),
      '--passphrase-file', sub,
      '--grants', path.join(dir, 'grants.json'),
      '--ledger', path.join(dir, 'journal.jsonl'),
      '--socket', path.join(dir, 's.sock')]);
    assert.strictEqual(res.status, 2,
      `a usage refusal must exit 2, got ${res.status}: ${res.stderr}`);
    assert.match(res.stderr, /^passphrase_file_not_a_file:/m,
      `the refusal must be named: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('I4 a --tx path that is a DIRECTORY is refused by name with exit 2', () => {
  const dir = tmpDir();
  try {
    const sub = path.join(dir, 'a-directory');
    fs.mkdirSync(sub);
    const res = sh(['sign', '--socket', path.join(dir, 's.sock'),
      '--grant', 'ops-24h', '--tx', sub]);
    assert.strictEqual(res.status, 2,
      `a usage refusal must exit 2, got ${res.status}: ${res.stderr}`);
    assert.match(res.stderr, /^tx_not_a_file:/m,
      `the refusal must be named: ${res.stderr}`);
    assert.match(res.stderr, /fix:/, `the refusal must name the repair: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('I5 an UNREADABLE --tx file is refused by name with exit 2', () => {
  const dir = tmpDir();
  try {
    const tx = unreadable(dir, 'locked.bin');
    if (!tx) return; // the mode does not bite here
    const res = sh(['sign', '--socket', path.join(dir, 's.sock'),
      '--grant', 'ops-24h', '--tx', tx]);
    assert.strictEqual(res.status, 2,
      `a usage refusal must exit 2, got ${res.status}: ${res.stderr}`);
    assert.match(res.stderr, /^tx_unreadable:/m,
      `the refusal must be named: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('I6 a --body that cannot be read is refused by name with exit 2', () => {
  const dir = tmpDir();
  try {
    const faces = [
      ['body_missing', path.join(dir, 'no-such.json')],
      ['body_not_a_file', (() => {
        const d = path.join(dir, 'a-directory');
        fs.mkdirSync(d, { recursive: true });
        return d;
      })()],
    ];
    const locked = unreadable(dir, 'locked.json');
    if (locked) faces.push(['body_unreadable', locked]);
    for (const [code, body] of faces) {
      const res = sh(['sign-message', '--socket', path.join(dir, 's.sock'),
        '--grant', 'ops-24h', '--body', body]);
      assert.strictEqual(res.status, 2,
        `${code}: a usage refusal must exit 2, got ${res.status}: ${res.stderr}`);
      assert.match(res.stderr, new RegExp(`^${code}:`, 'm'),
        `${code}: the refusal must be named: ${res.stderr}`);
      assert.match(res.stderr, /fix:/,
        `${code}: the refusal must name the repair: ${res.stderr}`);
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('I7 no raw errno ever reaches the operator on these paths', () => {
  const dir = tmpDir();
  try {
    const locked = unreadable(dir, 'locked.bin');
    const sub = path.join(dir, 'a-directory');
    fs.mkdirSync(sub, { recursive: true });
    const runs = [
      ['run', '--keystore', path.join(dir, 'ops.key'),
        '--passphrase-file', path.join(dir, 'no-such.pass'),
        '--grants', path.join(dir, 'g.json'),
        '--ledger', path.join(dir, 'j.jsonl'), '--socket', path.join(dir, 's.sock')],
      ['sign', '--socket', path.join(dir, 's.sock'), '--grant', 'g', '--tx', sub],
      ['sign-message', '--socket', path.join(dir, 's.sock'), '--grant', 'g',
        '--body', path.join(dir, 'no-such.json')],
    ];
    if (locked) {
      runs.push(['sign', '--socket', path.join(dir, 's.sock'), '--grant', 'g', '--tx', locked]);
    }
    for (const args of runs) {
      const res = sh(args);
      const out = `${res.stdout}${res.stderr}`;
      assert.doesNotMatch(out, /^(ENOENT|EACCES|EISDIR|ELOOP):/m,
        `a raw errno must never be the message: ${out}`);
      assert.doesNotMatch(out, /no such file or directory/,
        `the raw errno text must never reach the operator: ${out}`);
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------------------
// The guards: the fix must not break the flows that work today.

test('G1 a readable passphrase file is still accepted (the mode rules still bite)', () => {
  const dir = tmpDir();
  try {
    const pass = path.join(dir, 'pass');
    fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });
    // A passphrase file that is group-readable is refused by the R6-6 MODE
    // rule (a different reason, a different voice) - it must not be
    // swallowed by the new read classification.
    fs.chmodSync(pass, 0o640);
    const res = sh(['run', '--keystore', path.join(dir, 'ops.key'),
      '--passphrase-file', pass,
      '--grants', path.join(dir, 'grants.json'),
      '--ledger', path.join(dir, 'journal.jsonl'),
      '--socket', path.join(dir, 's.sock')]);
    assert.notStrictEqual(res.status, 0,
      `the mode refusal must still bite: ${res.stderr}`);
    assert.match(res.stderr, /group\/other accessible/,
      `the mode rule must still speak: ${res.stderr}`);
    // ... and it must NOT be swallowed into the new read-classification
    // voice: the reason (mode) is unchanged, only errno faces changed.
    assert.doesNotMatch(res.stderr, /^passphrase_file_(missing|unreadable|not_a_file):/m,
      `the mode rule has its own voice: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G3 the tx_missing voice (2026-11-05) is unchanged', () => {
  const dir = tmpDir();
  try {
    const res = sh(['sign', '--socket', path.join(dir, 's.sock'),
      '--grant', 'ops-24h', '--tx', path.join(dir, 'no-tx.bin')]);
    assert.strictEqual(res.status, 2, `tx_missing must exit 2: ${res.stderr}`);
    assert.match(res.stderr, /^tx_missing:/m,
      `the established voice must not change: ${res.stderr}`);
    assert.match(res.stderr, /build-tx/,
      `the repair must stay the build-tx command: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G2 a --tx that is a LINK to a regular file is still read THROUGH', () => {
  const dir = tmpDir();
  try {
    const real = path.join(dir, 'real.bin');
    fs.writeFileSync(real, Buffer.alloc(215, 7));
    const link = path.join(dir, 'link.bin');
    fs.symlinkSync(real, link);
    const res = sh(['sign', '--socket', path.join(dir, 's.sock'),
      '--grant', 'ops-24h', '--tx', link]);
    assert.doesNotMatch(res.stderr, /^tx_not_a_file:/m,
      `a link to a regular file must be read through: ${res.stderr}`);
    assert.doesNotMatch(res.stderr, /^tx_unreadable:/m,
      `a link to a regular file must be read through: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G4 a --body that is a LINK to a regular file is still read THROUGH', () => {
  const dir = tmpDir();
  try {
    const real = path.join(dir, 'real.json');
    fs.writeFileSync(real, '{"schema":"openreceipts/v1"}\n');
    const link = path.join(dir, 'link.json');
    fs.symlinkSync(real, link);
    const res = sh(['sign-message', '--socket', path.join(dir, 's.sock'),
      '--grant', 'ops-24h', '--body', link]);
    // The link must NOT be refused as "not a file": it is read through and
    // the failure that comes next is the daemon/socket one (no daemon here).
    assert.doesNotMatch(res.stderr, /^body_not_a_file:/m,
      `a link to a regular file must be read through: ${res.stderr}`);
    assert.doesNotMatch(res.stderr, /^body_unreadable:/m,
      `a link to a regular file must be read through: ${res.stderr}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
