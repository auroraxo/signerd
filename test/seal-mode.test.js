'use strict';
// A SEALED GRANT FILE IS NOT READABLE WITHOUT ITS PASSPHRASE
// (measured 2026-11-16, live, on the published v0.2.27 tree 41cd128).
//
// The product has ONE seal and TWO halves, and the two halves disagreed
// about what a seal IS:
//
//   JOURNAL half - refuses. `ledger_sealed` has existed since sealed mode
//     did: a journal with a seal floor and no passphrase is not readable,
//     because its history cannot be verified. "Never degraded."
//   GRANT half   - DEGRADED. loadGrantFile(src/grantfile.js) only looked at
//     the `seal` field when a key provider was passed in, so WITHOUT a key
//     a sealed grant file was read as if it were an ordinary unsealed one:
//
//       seal-grants                  -> exit 0, the file now carries a seal
//       tamper grants.ops.destination
//       verify-grants <right pass>   -> grant_file_seal_mismatch, exit 1
//       loadGrantFile(file)          -> LOADED, with the TAMPERED destination
//       status --grants <file>       -> {"ok":true,...,"sealed":false}, exit 0
//
// The same file was simultaneously "this content is authenticated" (with
// the passphrase) and "nothing here needs checking" (without it). The seal
// was decorative: it protected the file from exactly the readers who did
// not ask for the key. And a daemon started WITHOUT the grant passphrase on
// a sealed+tampered file SERVED it (F3 in the measurement) - so the forged
// destination was live.
//
// WHAT THIS FILE PINS - the grant half now refuses exactly where the
// journal half always did:
//   S1 the loader reads a sealed file without a passphrase -> refused
//      with `grant_file_sealed` (not loaded, and never the tampered
//      content);
//   S2 `status` on a sealed file without a passphrase -> refused, exit 1,
//      instead of {"ok":true,"sealed":false};
//   S3 a daemon started without the grant passphrase on a sealed file
//      refuses to start instead of serving;
//   S4 a sealed file whose seal block is SHAPE-BROKEN still refuses, and
//      names the seal itself (grant_file_seal_invalid), not the missing
//      passphrase - the reason must stay the real one;
//   S5 a sealed file loaded WITH the passphrase still verifies and still
//      refuses tampered content (grant_file_seal_mismatch);
//   G1 GUARD: an UNSEALED file still loads without a passphrase (the
//      legacy path that made sealed mode opt-in is untouched);
//   G2 GUARD: the documented "edit by hand, then re-seal" repair still
//      works - seal-grants may judge a sealed payload without a key;
//   G3 GUARD: `grant-add --append` and `grant-remove` on a sealed file
//      still refuse with their own write-path reason (grant_file_sealed)
//      and still re-seal with the passphrase;
//   G4 GUARD: the journal half still refuses (ledger_sealed) - one rule
//      for both halves means neither half may become laxer.
//
// LADDER: S1-S4 are RED on the pre-fix tree (v0.2.27, 41cd128) and GREEN
// here; S5 and G1-G4 are green on BOTH trees.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');

const DESTINATION = 'So11111111111111111111111111111111111111112';
const TAMPERED = '11111111111111111111111111111111';
const PUBKEY_B64 = Buffer.alloc(32, 1).toString('base64');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120000 });
}

function secretDir(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'a separate seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return { root, cfg, sealPass };
}

function writeDoc(grantsPath, doc) {
  fs.writeFileSync(grantsPath, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grantsPath, 0o600);
}

function txDoc(overrides = {}) {
  return {
    version: 1,
    grants: {
      ops: Object.assign({
        signer: '11111111111111111111111111111111',
        destination: DESTINATION,
        maxLamports: '1000',
        expiresAt: '2030-01-01T00:00:00Z',
        windowMaxLamports: '1000000',
        windowSeconds: '3600',
      }, overrides),
    },
  };
}

function seal(s, grantsPath) {
  return run(['seal-grants', '--grants', grantsPath, '--seal-passphrase-file', s.sealPass]);
}

function tamper(grantsPath) {
  const doc = JSON.parse(fs.readFileSync(grantsPath, 'utf8'));
  doc.grants.ops.destination = TAMPERED;
  writeDoc(grantsPath, doc);
}

/** The sealed+tampered fixture the S-cases all use. */
function sealedTampered(prefix) {
  const s = secretDir(prefix);
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, txDoc());
  assert.strictEqual(seal(s, grants).status, 0, 'the fixture must seal (test premise)');
  tamper(grants);
  return { ...s, grants };
}

/** The loader's own verdict, in-process: may this file be read keylessly? */
function keylessLoad(grantsPath) {
  const { loadGrantFile } = require('../src/grantfile');
  try {
    const loaded = loadGrantFile(grantsPath);
    return { loaded: true, destination: loaded.grants.ops.destination, code: null };
  } catch (err) {
    return { loaded: false, code: err.code || 'error' };
  }
}

// ---------------------------------------------------------------------------
// S1: the loader must not read a sealed file without a passphrase - and
// must never hand back the tampered content.
// ---------------------------------------------------------------------------

test('S1 a sealed grant file without a passphrase is refused, not read (and the tampered grant never comes back)', () => {
  const { grants } = sealedTampered('signerd-sealmode-s1-');

  const v = keylessLoad(grants);
  assert.strictEqual(v.loaded, false,
    `the loader must REFUSE a sealed file without a key; it returned: ${JSON.stringify(v)}`);
  assert.strictEqual(v.code, 'grant_file_sealed',
    `the refusal must be named grant_file_sealed: ${v.code}`);
  assert.notStrictEqual(v.destination, TAMPERED,
    'the tampered destination must never reach a caller who has no key');
});

// ---------------------------------------------------------------------------
// S2: `status` must not report a sealed file as fine and unsealed.
// ---------------------------------------------------------------------------

test('S2 status on a sealed file without a passphrase refuses with exit 1, never {"ok":true,"sealed":false}', () => {
  const { root, cfg, grants } = sealedTampered('signerd-sealmode-s2-');
  const r = run(['status', '--grants', grants, '--ledger', path.join(root, 'journal.jsonl')]);

  assert.notStrictEqual(r.status, 0,
    `status must refuse a sealed file it cannot verify: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /grant_file_sealed/,
    `the refusal must carry the reason: ${r.stderr}`);
  assert.doesNotMatch(r.stdout, /"ok":true/,
    `status must not report ok:true for a file it could not verify: ${r.stdout}`);
  assert.doesNotMatch(r.stdout, /"sealed":false/,
    `status must not report sealed:false for a file that IS sealed: ${r.stdout}`);
});

// ---------------------------------------------------------------------------
// S3: the daemon must refuse to START, not serve the tampered file.
// ---------------------------------------------------------------------------

test('S3 a daemon without the grant passphrase refuses to start on a sealed grant file', () => {
  const s = secretDir('signerd-sealmode-s3-');
  const grants = path.join(s.cfg, 'grants.json');
  const keystore = path.join(s.cfg, 'ops.key');
  const pass = path.join(s.cfg, 'pass');
  fs.writeFileSync(pass, 'keystore phrase\n', { mode: 0o600 });

  // A grant the daemon's OWN key can satisfy, or it would refuse for
  // grant_signer_mismatch and the test would prove nothing about the seal.
  const keygen = run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(keygen.status, 0, `keygen must work: ${keygen.stderr}`);
  const pub = JSON.parse(keygen.stdout).publicKey;
  writeDoc(grants, txDoc({ signer: pub }));
  assert.strictEqual(seal(s, grants).status, 0, 'the fixture must seal');
  tamper(grants);

  const r = run(['run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', grants, '--ledger', path.join(s.root, 'journal.jsonl'),
    '--socket', path.join(s.root, 'signerd.sock')]);

  assert.notStrictEqual(r.status, 0,
    `the daemon must refuse to start: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /grant_file_sealed/,
    `the refusal must name the seal: ${r.stderr}`);
  assert.doesNotMatch(r.stdout, /"ok":true/,
    `the daemon must not report it is serving: ${r.stdout}`);
});

// ---------------------------------------------------------------------------
// S4: a SHAPE-BROKEN seal block must be reported as the broken seal it is -
// the missing passphrase is not the reason, and the reason must be the
// real one (the same one a keyed read gives).
// ---------------------------------------------------------------------------

test('S4 a sealed file whose seal block is shape-broken still refuses, naming the seal itself', () => {
  const s = secretDir('signerd-sealmode-s4-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, txDoc());
  assert.strictEqual(seal(s, grants).status, 0, 'the fixture must seal');

  // Break the seal block (drop its algorithm). The file still carries a
  // `seal`, so it must still be refused - and the reason must be the
  // broken seal, not the missing passphrase.
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  doc.seal.alg = 'not-hmac-sha256';
  writeDoc(grants, doc);

  const v = keylessLoad(grants);
  assert.strictEqual(v.loaded, false, 'a broken seal block must never be read');
  assert.strictEqual(v.code, 'grant_file_seal_invalid',
    `the reason must stay the real one: ${v.code}`);

  // And the SAME reason from the keyed path: one file, one reason.
  const { makeSealKeyProvider } = require('../src/grantseal');
  const passphrase = fs.readFileSync(s.sealPass, 'utf8').replace(/\r?\n$/, '');
  const { loadGrantFile } = require('../src/grantfile');
  assert.throws(() => loadGrantFile(grants, { sealKeyFor: makeSealKeyProvider(passphrase) }),
    (err) => err.code === 'grant_file_seal_invalid',
    'the keyed read must name the same reason');
});

// ---------------------------------------------------------------------------
// S5 (green on both trees): WITH the passphrase nothing changed - the seal
// verifies, and tampered content is still refused.
// ---------------------------------------------------------------------------

test('S5 with the passphrase the sealed file still verifies and tampered content is still refused', () => {
  const { grants, sealPass } = sealedTampered('signerd-sealmode-s5-');
  const r = run(['verify-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.notStrictEqual(r.status, 0, 'a tampered file must still be refused WITH the key');
  assert.match(r.stderr, /grant_file_seal_mismatch/, `${r.stdout}${r.stderr}`);

  // An untampered sealed file verifies.
  const s = secretDir('signerd-sealmode-s5b-');
  const ok = path.join(s.cfg, 'grants.json');
  writeDoc(ok, txDoc());
  assert.strictEqual(seal(s, ok).status, 0);
  const v = run(['verify-grants', '--grants', ok, '--seal-passphrase-file', s.sealPass]);
  assert.strictEqual(v.status, 0, `an honest seal must still verify: ${v.stderr}`);
});

// ---------------------------------------------------------------------------
// G1 (guard): an UNSEALED file still loads without a passphrase - the
// legacy path that makes sealed mode opt-in.
// ---------------------------------------------------------------------------

test('G1 GUARD: an unsealed grant file still loads without a passphrase (green on both trees)', () => {
  const s = secretDir('signerd-sealmode-g1-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, txDoc());

  const v = keylessLoad(grants);
  assert.strictEqual(v.loaded, true, `an unsealed file must still load: ${v.code}`);
  assert.strictEqual(v.destination, DESTINATION);

  const r = run(['status', '--grants', grants, '--ledger', path.join(s.root, 'j.jsonl')]);
  assert.strictEqual(r.status, 0, `status must work on an unsealed file: ${r.stderr}`);
  assert.match(r.stdout, /"ok":true/, r.stdout);
  assert.match(r.stdout, /"sealed":false/, r.stdout);
});

// ---------------------------------------------------------------------------
// G2 (guard): the documented "edit by hand, then re-seal" repair must keep
// working - this is the ONE path that may judge a sealed payload without a
// key, and it must not break.
// ---------------------------------------------------------------------------

test('G2 GUARD: re-sealing after a hand edit still works (the documented repair)', () => {
  const { grants, sealPass } = sealedTampered('signerd-sealmode-g2-');

  // The hand edit: the operator fixes the destination by hand; the seal is
  // now stale, which is exactly why they are re-sealing.
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  doc.grants.ops.destination = DESTINATION;
  writeDoc(grants, doc);

  const r = run(['seal-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.strictEqual(r.status, 0, `re-sealing must still work: ${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /"ok":true/, `the verdict must be ok:true: ${r.stdout}`);

  const v = run(['verify-grants', '--grants', grants, '--seal-passphrase-file', sealPass]);
  assert.strictEqual(v.status, 0, `the new seal must verify: ${v.stdout}${v.stderr}`);
});

// ---------------------------------------------------------------------------
// G3 (guard): the WRITE paths keep their own reasons - the new refusal must
// not take over a surface that already had one.
// ---------------------------------------------------------------------------

test('G3 GUARD: grant-add --append and grant-remove on a sealed file keep their write-path reasons', () => {
  // A SEALED file (not tampered - the write paths re-seal as part of the
  // act, so the fixture must be one whose seal still holds).
  const s = secretDir('signerd-sealmode-g3-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, txDoc());
  assert.strictEqual(seal(s, grants).status, 0, 'the fixture must seal');
  const sealPass = s.sealPass;

  // --signer, not --keystore: the keystore would be read BEFORE the grant
  // file is judged, and its refusal would hide the seal's own reason.
  const addArgs = (extra) => ['grant-add', '--grants', grants, '--name', 'ops-24h',
    '--signer', '11111111111111111111111111111111', '--destination', DESTINATION,
    '--max-lamports', '1000', '--window-max-lamports', '1000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z', ...extra];

  const append = run(addArgs(['--append']));
  assert.notStrictEqual(append.status, 0, 'appending to a sealed file without the key must refuse');
  assert.match(append.stderr, /grant_file_sealed/, append.stderr);

  const remove = run(['grant-remove', '--grants', grants, '--name', 'ops']);
  assert.notStrictEqual(remove.status, 0, 'removing from a sealed file without the key must refuse');
  assert.match(remove.stderr, /grant_file_sealed/, remove.stderr);

  // And with the passphrase the same command still works (it re-seals as
  // part of the act) - the seal must no longer be the reason.
  const append2 = run(addArgs(['--append', '--seal-passphrase-file', sealPass]));
  assert.strictEqual(append2.status, 0,
    `the append with the passphrase must still work: ${append2.stdout}${append2.stderr}`);
  assert.doesNotMatch(append2.stderr, /grant_file_sealed/,
    'with the passphrase, the seal must no longer be the reason');

  // The result is still sealed (the append re-sealed it, never downgraded).
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  assert.ok(doc.seal, 'the appended file must still carry a seal');
  assert.deepStrictEqual(Object.keys(doc.grants).sort(), ['ops', 'ops-24h'],
    'the new grant must be there');
});

// ---------------------------------------------------------------------------
// G4 (guard): the JOURNAL half still refuses - one rule for both halves
// means neither half may become laxer.
// ---------------------------------------------------------------------------

test('G4 GUARD: the journal half still refuses without a passphrase (ledger_sealed)', () => {
  const s = secretDir('signerd-sealmode-g4-');
  const ledger = path.join(s.root, 'journal.jsonl');
  fs.writeFileSync(`${ledger}.anchor`, JSON.stringify({
    v: 1, alg: 'hmac-sha256', count: 0, head: '0'.repeat(64), mac: '0'.repeat(64),
  }) + '\n', { mode: 0o600 });
  fs.chmodSync(`${ledger}.anchor`, 0o600);

  const r = run(['status', '--grants', path.join(s.cfg, 'absent.json'), '--ledger', ledger]);
  // The journal refusal happens inside the Ledger constructor, which status
  // reaches only after the grant file loads - so use the ledger directly.
  const { Ledger } = require('../src/ledger');
  assert.throws(() => new Ledger({ file: ledger }),
    (err) => err.code === 'ledger_sealed',
    'the journal half must still refuse a sealed journal without a passphrase');
  void r;
});
