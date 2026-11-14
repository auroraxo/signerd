'use strict';

// PIN: the migration path's SOURCE file must refuse like every other
// operator input.
//
// WHY (measured 2026-11-14 against the PUBLISHED v0.2.23 tree): the
// 2026-11-14 sweep of the operator-input voice covered --passphrase-file,
// --tx and --body (research/input-voice-v0.2.22-2026-11-14.json and
// research/input-voice-fixed-2026-11-14.json). The source file that the
// migration path EXISTS for - the plaintext key a developer already holds
// and hands to `import --from` - was never swept. Measured on the
// published tree:
//
//   import --from <missing>   -> "import_source_unreadable: ENOENT",  exit 1
//   import --from <directory> -> "import_source_unreadable: EISDIR",  exit 1
//   import --from <mode 000>  -> "import_source_unreadable: EACCES",  exit 1
//
// A bare errno names nothing the operator can act on (was the file
// missing, a directory, or forbidden?), there is no repair, and exit 1 is
// reserved for "the daemon or the policy refused" - a mistyped path is a
// USAGE refusal (exit 2), the same contract the three swept families
// already honour.
//
// WHAT THIS TEST CHECKS, WITHOUT re-running the measurement (it needs the
// unpacked npm tarball of the published tag):
//   P1 both artifacts parse and carry their face list;
//   P2 the pre-fix artifact shows the DEFECT: verdict `violations-present`,
//      raw errno leaking, exit 1, no repair line;
//   P3 the fixed artifact shows the contract: verdict `refusals-present`,
//      0 violations, every face named after itself with a `fix:` line and
//      exit 2;
//   P4 the two artifacts cover the SAME faces (the comparison is fair);
//   P5 no host path leaks into either artifact.
//
// LADDER: P2/P3 are RED on the pre-fix tree and GREEN on the fixed one.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const FIXED = path.join(__dirname, '..', 'research', 'import-source-voice-fixed-2026-11-14.json');
const PREFIX = path.join(__dirname, '..', 'research', 'import-source-voice-v0.2.23-2026-11-14.json');
const CLI = path.join(__dirname, '..', 'bin', 'signerd.js');

function report(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('P1 both artifacts parse and carry their face list', () => {
  for (const p of [FIXED, PREFIX]) {
    const r = report(p);
    assert.strictEqual(typeof r.measuredAt, 'string', `${p}: measuredAt`);
    assert.ok(Array.isArray(r.rows) && r.rows.length === 3, `${p}: three faces`);
    assert.strictEqual(r.faces, 3, `${p}: faces count`);
  }
});

test('P2 the published v0.2.23 tree shows the defect', () => {
  const r = report(PREFIX);
  assert.strictEqual(r.verdict, 'violations-present', 'the pre-fix tree must violate');
  assert.strictEqual(r.violations, 3, 'all three faces must violate');
  for (const row of r.rows) {
    assert.strictEqual(row.ok, false, `${row.id}: pre-fix must be a violation`);
    assert.strictEqual(row.rawErrno, true, `${row.id}: a raw errno must be what leaked`);
    assert.strictEqual(row.hasFix, false, `${row.id}: the repair line was missing`);
    assert.strictEqual(row.exit, 1,
      `${row.id}: the errno escape used exit 1, not the usage code 2`);
  }
});

test('P3 the fixed tree honours the contract on every face', () => {
  const r = report(FIXED);
  assert.strictEqual(r.verdict, 'refusals-present', 'the fixed tree must refuse by name');
  assert.strictEqual(r.violations, 0, 'the fixed tree must have no violation');
  for (const row of r.rows) {
    assert.strictEqual(row.ok, true, `${row.id}: must be ok`);
    assert.strictEqual(row.named, true, `${row.id}: must be named`);
    assert.strictEqual(row.hasFix, true, `${row.id}: must carry a repair`);
    assert.strictEqual(row.exit, 2, `${row.id}: a usage refusal exits 2`);
    assert.strictEqual(row.rawErrno, false, `${row.id}: no raw errno`);
    assert.ok(row.id === row.firstLine.split(':')[0],
      `${row.id}: the refusal must name itself (first line: ${row.firstLine})`);
  }
});

test('P4 both artifacts cover the same faces (a fair comparison)', () => {
  const fixed = report(FIXED).rows.map((row) => row.id).sort();
  const prefix = report(PREFIX).rows.map((row) => row.id).sort();
  assert.deepStrictEqual(fixed, prefix, 'the two trees must be probed with the same faces');
});

test('P5 no host path leaks into either artifact', () => {
  for (const p of [FIXED, PREFIX]) {
    const text = fs.readFileSync(p, 'utf8');
    assert.doesNotMatch(text, /\/home\/[a-z]+\//, `${p}: host home path leaked`);
    assert.doesNotMatch(text, /signerd-import-voice-measure-[A-Za-z0-9]{6,}/,
      `${p}: a tmpdir name leaked into the artifact`);
  }
});

// The LIVE face: run this tree's own CLI. No network, no published
// tarball - the artifact pair can only ever be a snapshot; this is the
// thing it claims about.
const { spawnSync } = require('node:child_process');
const os = require('node:os');

function runImport(argv) {
  return spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', timeout: 60000 });
}

function secretDir(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);
  return { root, cfg, pass, keystore: path.join(cfg, 'ops.key') };
}

test('P6 LIVE: every source face names itself, repairs, and exits 2', () => {
  const { root, cfg, pass, keystore } = secretDir('signerd-import-source-voice-');

  const cases = [
    { id: 'import_source_missing', from: path.join(root, 'missing.json') },
    { id: 'import_source_not_a_file', from: cfg },
  ];
  const locked = path.join(root, 'locked.json');
  fs.writeFileSync(locked, '[]\n', { mode: 0o600 });
  fs.chmodSync(locked, 0o000);
  let bites = true;
  try { fs.readFileSync(locked); bites = false; } catch { /* as intended */ }
  if (bites) cases.push({ id: 'import_source_unreadable', from: locked });

  for (const c of cases) {
    const r = runImport(['import', '--keystore', keystore,
      '--passphrase-file', pass, '--from', c.from]);
    const first = (r.stderr || '').split('\n').find((l) => l.trim()) || '';
    assert.ok(first.startsWith(`${c.id}:`),
      `${c.id}: first line must name the face, got ${JSON.stringify(first)}`);
    assert.match(r.stderr, /^\s+fix: /m, `${c.id}: must carry a repair line`);
    assert.strictEqual(r.status, 2, `${c.id}: a usage refusal exits 2 (got ${r.status})`);
    assert.doesNotMatch(r.stderr, /\bENOENT\b|\bEACCES\b|\bEISDIR\b|\bENOTDIR\b/,
      `${c.id}: no raw errno may reach the operator`);
    assert.ok(!fs.existsSync(keystore),
      `${c.id}: a refused import must write nothing`);
  }
});

test('P7 GUARD: a real source still imports, and a symlink source reads through', () => {
  const { root, cfg, pass, keystore } = secretDir('signerd-import-source-guard-');
  const src = path.join(root, 'id.json');
  const { Keypair } = require('@solana/web3.js');
  const kp = Keypair.generate();
  fs.writeFileSync(src, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
  fs.chmodSync(src, 0o600);

  const ok = runImport(['import', '--keystore', keystore, '--passphrase-file', pass,
    '--from', src]);
  assert.strictEqual(ok.status, 0, `the happy path must still work: ${ok.stderr}`);

  // A LINK to a regular key file is read through (the link is not the
  // defect) - the preflight must not turn into a symlink refusal here.
  const linked = path.join(cfg, 'link.json');
  fs.symlinkSync(src, linked);
  const second = runImport(['import', '--keystore', path.join(cfg, 'two.key'),
    '--passphrase-file', pass, '--from', linked, '--overwrite']);
  assert.strictEqual(second.status, 0, `a linked source must import: ${second.stderr}`);

  const { readKeystorePublicKey } = require('../src/keystore');
  assert.strictEqual(readKeystorePublicKey({ file: keystore }), kp.publicKey.toBase58(),
    'the imported keystore holds the imported key');
});
