'use strict';
// THE SEAL COMMAND MUST JUDGE WITH THE PRODUCT'S OWN LOADER
// (measured 2026-11-13, live, on this tree before the fix):
//
// `signerd seal-grants` is the ONE write path to the grant file that does
// NOT consult the product's loader (src/grantfile.js) — the judge every
// other write path consults:
//
//   - extendGrantFile   (`grant-add --append`):  "THE JUDGE: the product's
//     loader, ... Nothing is written until the whole file has been accepted."
//   - removeGrantFromFile (`grant-remove`):       same rule, same wording.
//   - addGrantToFile      (`sign-message --add-grant`): fixed for exactly
//     this class on 2026-11-11 (v0.2.17, the bootstrap-judge release).
//
// seal-grants was left behind. It hand-parses the document (JSON.parse plus
// a shape check on `version`/`grants`) and seals whatever it finds. Measured
// live on this tree, `seal-grants` exited 0 and printed
// {"ok":true,...} on FOUR states the loader refuses:
//
//   S1  an existing grant the loader refuses (windowMaxLamports:"1" — a cap
//       below the 5000-lamport base fee, so the daemon can never honour it):
//       seal-grants exit 0, {"ok":true}; `status` (the loader) exit 1,
//       `grant_field_invalid: releases.format`; `grant-remove` exit 1, the
//       same reason. The command reported success on a file the daemon
//       refuses at start — the keygen-loop lesson, on the grant file.
//   S2  a grant with a TYPO in a field name (maxLamport instead of
//       maxLamports): seal-grants exit 0; the loader refuses
//       `grant_unknown_field: releases.maxLamport`. The seal made the
//       typo AUTHENTIC: from then on the file carries a valid HMAC over a
//       document the daemon refuses — the seal says "the operator sealed
//       this", the loader says "this is not a grant file".
//   S3  a grant with a RESERVED name ("__proto__"): seal-grants exit 0 and
//       reported `grants:[]` — the reserved name silently vanished from the
//       summary while the loader refuses it (`grant_name_invalid`).
//   S4  a SYMLINK at the grant path: seal-grants exit 0 and wrote THROUGH
//       the link (the loader refuses a symlink with O_NOFOLLOW; the append
//       path refuses it as grant_file_symlink).
//
// WHAT THIS FILE PINS — seal-grants must refuse, BEFORE writing, exactly
// what the loader refuses at run time (the rule the other write paths
// already keep), and must still WORK on every file the loader accepts:
//   S1 an invalid existing grant refuses the seal, file untouched;
//   S2 a typo'd field refuses the seal, file untouched (the seal must not
//      make an unloadable document authentic);
//   S3 a reserved grant name refuses the seal, file untouched;
//   S4 a symlink at the grant path is refused, never written through;
//   G1 GUARD: sealing a VALID file still works, and the sealed file loads
//      in the daemon's sealed mode (the documented repair path);
//   G2 GUARD: RE-SEALING an already sealed valid file still works (the
//      documented "edit by hand, then re-seal" repair);
//   G3 GUARD: `seal-grants --out <other path>` on a valid file still works.
//
// Ladder: RED on any tree whose seal-grants parses instead of loading;
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
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'a separate seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return { root, cfg, pass, sealPass };
}

const DESTINATION = 'So11111111111111111111111111111111111111112';
const SIGNER = '11111111111111111111111111111111';

function validDoc() {
  return { version: 1, grants: { releases: {
    signer: SIGNER, destination: DESTINATION, maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z', windowMaxLamports: '500000000',
    windowSeconds: '3600',
  } } };
}

function writeDoc(grantsPath, doc) {
  fs.writeFileSync(grantsPath, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grantsPath, 0o600);
}

function seal(s, grantsPath) {
  return run(['seal-grants', '--grants', grantsPath, '--seal-passphrase-file', s.sealPass]);
}

// The loader's own verdict on the same file, so the test compares the seal
// command against the JUDGE rather than against a hard-coded reason.
function loaderVerdict(s, grantsPath) {
  return run(['status', '--grants', grantsPath, '--ledger', path.join(s.root, 'ledger.jsonl')]);
}

// ---------------------------------------------------------------------------
// S1: a grant the loader refuses must not be sealed.
// ---------------------------------------------------------------------------

test('S1 a grant the loader refuses is refused by seal-grants, file untouched', () => {
  const s = secretDir('signerd-seal-judge-s1-');
  const grants = path.join(s.cfg, 'grants.json');
  const doc = validDoc();
  // A cap below the 5000-lamport base fee: the loader refuses it
  // (grant_field_invalid) and the daemon refuses the whole file at start.
  doc.grants.releases.windowMaxLamports = '1';
  writeDoc(grants, doc);
  const before = fs.readFileSync(grants);

  const judge = loaderVerdict(s, grants);
  assert.notStrictEqual(judge.status, 0,
    'the loader must refuse this file (the test premise)');

  const r = seal(s, grants);
  assert.notStrictEqual(r.status, 0,
    `seal-grants must refuse a file the loader refuses: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /grant_field_invalid/,
    `the refusal must carry the loader's reason: ${r.stderr}`);
  assert.deepStrictEqual(fs.readFileSync(grants), before,
    'the file must be byte-identical: a refused seal writes nothing');
});

// ---------------------------------------------------------------------------
// S2: a typo'd field must not be sealed (the seal must not make an
// unloadable document authentic).
// ---------------------------------------------------------------------------

test('S2 a grant with a typo\'d field is refused by seal-grants, file untouched', () => {
  const s = secretDir('signerd-seal-judge-s2-');
  const grants = path.join(s.cfg, 'grants.json');
  const doc = validDoc();
  // maxLamport instead of maxLamports: an unknown field the loader refuses.
  doc.grants.releases.maxLamport = '500000000';
  writeDoc(grants, doc);
  const before = fs.readFileSync(grants);

  const judge = loaderVerdict(s, grants);
  assert.notStrictEqual(judge.status, 0,
    'the loader must refuse this file (the test premise)');
  assert.match(judge.stderr, /grant_unknown_field/,
    `the premise is an unknown field: ${judge.stderr}`);

  const r = seal(s, grants);
  assert.notStrictEqual(r.status, 0,
    `seal-grants must refuse a file the loader refuses: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /grant_unknown_field/,
    `the refusal must carry the loader's reason: ${r.stderr}`);
  assert.deepStrictEqual(fs.readFileSync(grants), before,
    'the file must be byte-identical: a refused seal writes nothing');
  // The seal must NOT have been written: the document is still unsealed.
  const doc2 = JSON.parse(fs.readFileSync(grants, 'utf8'));
  assert.strictEqual(doc2.seal, undefined,
    'no seal may be written for a document the loader refuses');
});

// ---------------------------------------------------------------------------
// S3: a reserved grant name must not be sealed.
// ---------------------------------------------------------------------------

test('S3 a reserved grant name is refused by seal-grants, file untouched', () => {
  const s = secretDir('signerd-seal-judge-s3-');
  const grants = path.join(s.cfg, 'grants.json');
  // A reserved name, written as RAW JSON text: a JS-side assignment
  // (`doc.grants['__proto__'] = ...`) would hit the prototype setter and
  // never serialize. JSON.parse DOES create an own data property for
  // __proto__ — that is the case the loader's RESERVED check exists for.
  const grantJson = JSON.stringify(validDoc().grants.releases);
  fs.writeFileSync(grants,
    `{"version": 1, "grants": {"__proto__": ${grantJson}}}\n`, { mode: 0o600 });
  fs.chmodSync(grants, 0o600);
  const before = fs.readFileSync(grants);

  const judge = loaderVerdict(s, grants);
  assert.notStrictEqual(judge.status, 0,
    'the loader must refuse this file (the test premise)');

  const r = seal(s, grants);
  assert.notStrictEqual(r.status, 0,
    `seal-grants must refuse a file the loader refuses: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /grant_name_invalid/,
    `the refusal must carry the loader's reason: ${r.stderr}`);
  assert.deepStrictEqual(fs.readFileSync(grants), before,
    'the file must be byte-identical: a refused seal writes nothing');
});

// ---------------------------------------------------------------------------
// S4: a symlink at the grant path must not be written through.
// ---------------------------------------------------------------------------

test('S4 a symlink at the grant path is refused by seal-grants, target untouched', () => {
  const s = secretDir('signerd-seal-judge-s4-');
  const real = path.join(s.cfg, 'grants.json');
  const link = path.join(s.cfg, 'link.json');
  writeDoc(real, validDoc());
  const before = fs.readFileSync(real);
  fs.symlinkSync(real, link);

  const r = seal(s, link);
  assert.notStrictEqual(r.status, 0,
    `seal-grants must refuse a symlink: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /grant_file_symlink/,
    `the refusal must NAME the symlink (the same voice grant-add uses): ${r.stderr}`);
  assert.deepStrictEqual(fs.readFileSync(real), before,
    'the target must be byte-identical: a refused seal writes nothing');
});

// ---------------------------------------------------------------------------
// Guards: the documented repair paths must still work.
// ---------------------------------------------------------------------------

test('G1 sealing a valid file still works, and the sealed file loads in sealed mode', () => {
  const s = secretDir('signerd-seal-judge-g1-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, validDoc());

  const r = seal(s, grants);
  assert.strictEqual(r.status, 0, `seal-grants must still work: ${r.stderr}`);
  assert.match(r.stdout, /"ok":true/, `the verdict must be ok:true: ${r.stdout}`);
  assert.match(r.stdout, /"name":"releases"/,
    `the summary must name what was sealed: ${r.stdout}`);

  const { loadGrantFile } = require('../src/grantfile');
  const { makeSealKeyProvider } = require('../src/grantseal');
  const passphrase = fs.readFileSync(s.sealPass, 'utf8').replace(/\r?\n$/, '');
  const loaded = loadGrantFile(grants, { sealKeyFor: makeSealKeyProvider(passphrase) });
  assert.deepStrictEqual(loaded.names, ['releases'],
    'the sealed file must load in the daemon\'s sealed mode');
});

test('G2 re-sealing an already sealed valid file still works (the documented repair)', () => {
  const s = secretDir('signerd-seal-judge-g2-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, validDoc());
  assert.strictEqual(seal(s, grants).status, 0, 'the first seal must work');

  const r = seal(s, grants);
  assert.strictEqual(r.status, 0, `re-sealing must still work: ${r.stderr}`);
  const { loadGrantFile } = require('../src/grantfile');
  const { makeSealKeyProvider } = require('../src/grantseal');
  const passphrase = fs.readFileSync(s.sealPass, 'utf8').replace(/\r?\n$/, '');
  const loaded = loadGrantFile(grants, { sealKeyFor: makeSealKeyProvider(passphrase) });
  assert.deepStrictEqual(loaded.names, ['releases'],
    'the re-sealed file must load in the daemon\'s sealed mode');
});

test('G3 seal-grants --out <other path> on a valid file still works', () => {
  const s = secretDir('signerd-seal-judge-g3-');
  const grants = path.join(s.cfg, 'grants.json');
  const out = path.join(s.cfg, 'sealed.json');
  writeDoc(grants, validDoc());

  const r = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', s.sealPass, '--out', out]);
  assert.strictEqual(r.status, 0, `seal-grants --out must still work: ${r.stderr}`);
  assert.ok(fs.existsSync(out), 'the sealed copy must exist');
  const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.ok(doc.seal, 'the copy must carry the seal');
});
