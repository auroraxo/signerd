'use strict';

// THE DUPLICATE-KEY VOICE: a grant document that names the same key twice
// is refused by name, at every reader, instead of being read last-wins
// (2026-11-19, measured on the pre-fix tree of v0.2.41).
//
// WHY (measured 2026-11-19, tree 260384b, tools/measure-duplicate-key.js):
// JSON.parse collapses duplicate keys silently - the LAST spelling wins -
// so a hand edit that leaves one block behind answers differently than the
// file displays:
//
//     { "grants": { "ops": { "maxLamports": "5000" },       <- what you read
//                    "ops": { "maxLamports": "500000000" } } <- what runs
//
//   the loader enforced 500000000, `signerd status` said {"ok":true} on
//   the same file, `grant-add --append` accepted the file and wrote it
//   back WITHOUT the duplicate (the repair erased the operator's file
//   silently), and the daemon STARTED and served the hidden cap. Every
//   other typo in a security file is refused by name: an unknown FIELD
//   fails grant_unknown_field ("a typo in a security file is never an
//   extra rule"), a bad VALUE fails its own code, a CLI flag given twice
//   fails duplicate_flag (src/cli-flags.js), a grant name twice fails
//   grant_exists at creation. The document-KEY level was the one place the
//   file could say one thing and run another.
//
// The fix is ONE judge: src/grantfile.js loadGrantFile refuses the
// duplicate (grant_duplicate_key, detail names the path and which
// occurrence would be dropped) right after the parse and BEFORE the shape
// and seal branches, so every surface inherits it: the daemon's per-request
// reload and its startup, status, verify-grants, seal-grants (which must
// not authenticate an ambiguous document), grant-add --append and
// grant-remove (which must not rewrite one). The repair lives in the ONE
// map (src/refusal-voice.js) like every other grant-file reason.
//
// THE CONTRACT (D = defect face, RED on the pre-fix tree; G = guard, green
// on BOTH trees):
//   D1 the loader refuses a duplicate grant key with code
//      grant_duplicate_key (not silent last-wins);
//   D2 the refusal names the duplicated key/grant;
//   D3 the refusal says the file names it TWICE (the operator learns a
//      spelling would be dropped, not just "invalid");
//   D4 status --grants refuses the same file (the reader surface a script
//      polls) instead of {"ok":true};
//   D5 verify-grants names grant_duplicate_key (a passphrase on a file
//      whose real problem is a duplicate must not be sent down the seal
//      dead end);
//   D6 grant-add --append refuses the file instead of accepting it and
//      writing back a silently rewritten document;
//   D7 the CLI refusal carries a fix: line (the generic tail looks it up
//      in the ONE map, src/refusal-voice.js);
//   D8 no host path in the detail or the fix (the file is already named by
//      --grants on the operator's command line);
//   D9 the refusal exits 1 (working-channel refusal, not usage 2, not 0);
//   D10 the daemon refuses to START on the file (pre-fix it started and
//      served the hidden cap - the security face of this class);
//   G1 guard: a legal file still loads - status ok:true, the grant named;
//   G2 guard: a legal file still adds with --append (the happy path of
//      the writer D6 guards);
//   G3 guard: an unknown FIELD inside a grant is still refused
//      (grant_unknown_field) - this fix must not weaken the field rule;
//   G4 guard: a re-sorted legal file still verifies - the seal MAC covers
//      the canonical payload (canonicalJson contract unchanged);
//   G5 guard: MAX_GRANTS unchanged - 1000 grants still load (and the
//      scanner must not see REPEATED FIELD NAMES across distinct grants
//      as duplicates);
//   G6 guard: reserved/invalid names still refuse with their own code
//      (grant_name_invalid) - the duplicate check must not swallow them;
//   G7 guard: the daemon still STARTS on a legal file (the scanner runs
//      on every startup and reload - a false positive would brick it).
//
// HOW: the checkout's own CLI in a temp sandbox; the duplicate document is
// built from a real grant-add file by splicing a second spelling (a JSON
// writer cannot emit one). No network.
// LADDER: tools/mutation-ladder-duplicate-key.sh; INSTRUMENT:
// tools/measure-duplicate-key.js (two trees: pre-fix last-wins vs
// post-fix refused).
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-dupkey-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function cli(argv) {
  return spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8' });
}

/**
 * A real grant file whose document names the same grant TWICE: the FIRST
 * spelling shows LOW caps (what the operator believes they wrote), the
 * LAST spelling carries HIGH caps (what JSON.parse silently enforced
 * pre-fix). Built by splicing the second spelling into the output of the
 * product's own grant-add, because no JSON writer can emit a duplicate.
 *
 * Asserts the two facts the defect needs before returning: the document
 * parses, and the HIDDEN (last) cap is the one a reader would enforce.
 */
function writeDupFile(dir, name) {
  const keystore = path.join(dir, 'k.key');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
  const kg = cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(kg.status, 0, `keygen must succeed: ${kg.stderr}`);
  const grants = path.join(dir, 'g.json');
  const add = cli(['grant-add', '--grants', grants, '--name', name,
    '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '5000', '--window-max-lamports', '5000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(add.status, 0, `grant-add must succeed: ${add.stderr}`);
  const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
  const grant = doc.grants[name];
  const low = { ...grant, maxLamports: '5000', windowMaxLamports: '5000' };
  const high = { ...grant, maxLamports: '500000000', windowMaxLamports: '500000000' };
  const ind = (obj) => JSON.stringify(obj, null, 4).replace(/\n/g, '\n    ');
  const dup = `{
  "version": 1,
  "grants": {
    "${name}": ${ind(low)},
    "${name}": ${ind(high)}
  }
}
`;
  // THE FIXTURE MUST DEMONSTRATE THE DEFECT, not merely contain a pattern:
  // it parses (duplicate keys are legal JSON grammar) and the LAST
  // spelling - the one the operator does NOT see first - is the cap a
  // reader enforces.
  const reparsed = JSON.parse(dup);
  assert.strictEqual(reparsed.grants[name].maxLamports, '500000000',
    'the fixture must demonstrate last-wins: the hidden cap is what runs');
  assert.strictEqual(dup.split(`"${name}":`).length - 1, 2,
    'the fixture must spell the grant name exactly twice');
  fs.writeFileSync(grants, dup, { mode: 0o600 });
  return { grants, keystore, pass };
}

test('D1: the loader refuses a duplicate grant key (code grant_duplicate_key)', () => {
  const sb = sandbox();
  try {
    const { grants } = writeDupFile(sb, 'ops');
    const { loadGrantFile } = require(path.join(ROOT, 'src', 'grantfile.js'));
    let err = null;
    try {
      loadGrantFile(grants);
    } catch (e) { err = e; }
    assert.ok(err, 'the loader must refuse a duplicate-key document');
    assert.strictEqual(err.code, 'grant_duplicate_key');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D2+D3: the refusal names the duplicated key and says it is written twice', () => {
  const sb = sandbox();
  try {
    const { grants } = writeDupFile(sb, 'ops');
    const { loadGrantFile } = require(path.join(ROOT, 'src', 'grantfile.js'));
    let err = null;
    try {
      loadGrantFile(grants);
    } catch (e) { err = e; }
    assert.ok(err, 'the loader must refuse');
    assert.match(err.message, /\bops\b/, 'the detail names the duplicated key');
    assert.match(err.message, /twice/i, 'the detail says the key is written twice');
    assert.match(err.message, /last/i, 'the detail says WHICH spelling would run');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D4: status --grants refuses the duplicate file (reader surface)', () => {
  const sb = sandbox();
  try {
    const { grants } = writeDupFile(sb, 'ops');
    const ledger = path.join(sb, 'l.jsonl');
    const r = cli(['status', '--grants', grants, '--ledger', ledger]);
    assert.notStrictEqual(r.status, 0, 'status must not say ok:true on a duplicate-key file');
    assert.match(r.stderr, /grant_duplicate_key/, 'status names the duplicate');
    const parsed = JSON.parse(r.stdout || '{}');
    assert.notStrictEqual(parsed.ok, true, 'stdout must not claim ok');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D5: verify-grants names grant_duplicate_key, not the seal dead end', () => {
  const sb = sandbox();
  try {
    const { grants, pass } = writeDupFile(sb, 'ops');
    const r = cli(['verify-grants', '--grants', grants,
      '--seal-passphrase-file', pass]);
    assert.match(r.stderr, /grant_duplicate_key/, 'verify-grants names the duplicate');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D6: grant-add --append refuses the duplicate file (no silent rewrite)', () => {
  const sb = sandbox();
  try {
    const { grants, keystore } = writeDupFile(sb, 'ops');
    const before = fs.readFileSync(grants, 'utf8');
    const r = cli(['grant-add', '--grants', grants, '--name', 'second', '--append',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '7000', '--window-max-lamports', '7000',
      '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z']);
    assert.notStrictEqual(r.status, 0, 'grant-add --append must refuse the duplicate file');
    assert.match(r.stderr, /grant_duplicate_key/, 'grant-add names the duplicate');
    assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
      'the file must be byte-identical (no silent rewrite)');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D7+D8: the CLI refusal carries a fix line, names a real command, and has no host path', () => {
  const sb = sandbox();
  try {
    const { grants } = writeDupFile(sb, 'ops');
    const ledger = path.join(sb, 'l.jsonl');
    const r = cli(['status', '--grants', grants, '--ledger', ledger]);
    assert.match(r.stderr, /^\s*fix: /m, 'a repair line reaches the operator');
    // Rule F3 of the refusal voice: a repair may only name a command this
    // CLI actually offers - a repair that names a command that does not
    // exist sends the operator to a dead end (mutation ladder M7).
    const { COMMAND_FLAGS } = require(path.join(ROOT, 'src', 'cli-flags.js'));
    const fixLine = r.stderr.split('\n').find((l) => /^\s*fix:/.test(l)) || '';
    const known = Object.keys(COMMAND_FLAGS);
    assert.ok(known.some((c) => fixLine.includes(`signerd ${c}`)),
      `the repair must name a real command (${known.join(', ')}); got: ${fixLine}`);
    for (const line of r.stderr.split('\n')) {
      assert.ok(!line.includes(sb), `no host path in output: ${line}`);
    }
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D9: the refusal exits 1 (working-channel refusal, not usage)', () => {
  const sb = sandbox();
  try {
    const { grants } = writeDupFile(sb, 'ops');
    const ledger = path.join(sb, 'l.jsonl');
    const r = cli(['status', '--grants', grants, '--ledger', ledger]);
    assert.strictEqual(r.status, 1, 'a data refusal exits 1, not 0 or 2');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('D10: the daemon refuses to START on the duplicate-key file', () => {
  const sb = sandbox();
  try {
    const { grants, keystore, pass } = writeDupFile(sb, 'ops');
    const r = spawnSync(process.execPath, [CLI, 'run',
      '--keystore', keystore, '--passphrase-file', pass,
      '--grants', grants,
      '--ledger', path.join(sb, 'l.jsonl'),
      '--socket', path.join(sb, 's.sock')], {
      encoding: 'utf8', timeout: 4000,
    });
    assert.strictEqual(r.status, 1,
      `the daemon must refuse to start (pre-fix: blocked until SIGTERM, status=${r.status}, signal=${r.signal})`);
    assert.match(r.stderr, /grant_duplicate_key/, 'the daemon names the duplicate');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G1: a legal file still loads and status says ok:true', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    const add = cli(['grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    assert.strictEqual(add.status, 0, add.stderr);
    const r = cli(['status', '--grants', grants, '--ledger', path.join(sb, 'l.jsonl')]);
    assert.strictEqual(r.status, 0, r.stderr);
    const report = JSON.parse(r.stdout);
    assert.strictEqual(report.ok, true);
    assert.deepStrictEqual(report.grants, ['ops']);
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G2: a legal file still accepts grant-add --append', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    cli(['grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    const r = cli(['grant-add', '--grants', grants, '--name', 'second', '--append',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '7000', '--window-max-lamports', '7000',
      '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z']);
    assert.strictEqual(r.status, 0, r.stderr);
    const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
    assert.deepStrictEqual(Object.getOwnPropertyNames(doc.grants).sort(), ['ops', 'second']);
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G3: an unknown FIELD inside a grant is still refused', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    cli(['grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
    doc.grants.ops.nolimit = true; // a typo that reads like a rule
    fs.writeFileSync(grants, JSON.stringify(doc, null, 2), { mode: 0o600 });
    const r = cli(['status', '--grants', grants, '--ledger', path.join(sb, 'l.jsonl')]);
    assert.notStrictEqual(r.status, 0, 'the unknown field must still be refused');
    assert.match(r.stderr, /grant_unknown_field/, 'the field rule keeps its own code');
    assert.ok(!/grant_duplicate_key/.test(r.stderr), 'the field refusal must not be reclassified');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G4: re-sorted legal file still verifies (seal canonical payload)', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    cli(['grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    const seal = cli(['seal-grants', '--grants', grants,
      '--seal-passphrase-file', pass]);
    assert.strictEqual(seal.status, 0, seal.stderr);
    // a REORDER of the same content is the same canonical payload
    const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
    const reordered = JSON.stringify(
      { grants: doc.grants, version: doc.version, seal: doc.seal }, null, 2);
    fs.writeFileSync(grants, reordered, { mode: 0o600 });
    const v = cli(['verify-grants', '--grants', grants,
      '--seal-passphrase-file', pass]);
    assert.strictEqual(v.status, 0, `re-sort must not break the MAC: ${v.stderr}`);
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G5: 1000 grants still load - repeated FIELD names across grants are not duplicates', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    cli(['grant-add', '--grants', grants, '--name', 'g0',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
    for (let i = 1; i < 1000; i++) {
      doc.grants[`g${i}`] = { ...doc.grants.g0 };
    }
    fs.writeFileSync(grants, JSON.stringify(doc), { mode: 0o600 });
    const { loadGrantFile } = require(path.join(ROOT, 'src', 'grantfile.js'));
    const loaded = loadGrantFile(grants);
    assert.strictEqual(loaded.names.length, 1000,
      '1000 grants load; every one repeats every field name of every other');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G6: reserved and invalid names keep their own refusal codes', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    cli(['grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
    const bad = { version: 1, grants: { ...doc.grants, 'a b': doc.grants.ops } };
    fs.writeFileSync(grants, JSON.stringify(bad), { mode: 0o600 });
    const r = cli(['status', '--grants', grants, '--ledger', path.join(sb, 'l.jsonl')]);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /grant_name_invalid/, 'the invalid name keeps its code');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});

test('G7: the daemon still STARTS on a legal file (scanner false-positive guard)', () => {
  const sb = sandbox();
  try {
    const pass = path.join(sb, 'pass');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const keystore = path.join(sb, 'k.key');
    cli(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
    const grants = path.join(sb, 'g.json');
    cli(['grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '5000', '--window-max-lamports', '5000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    const r = spawnSync(process.execPath, [CLI, 'run',
      '--keystore', keystore, '--passphrase-file', pass,
      '--grants', grants,
      '--ledger', path.join(sb, 'l.jsonl'),
      '--socket', path.join(sb, 's.sock')], {
      encoding: 'utf8', timeout: 2500,
    });
    // A daemon that answered by printing {"ok":true} on stdout and staying
    // up until spawnSync's timeout sent SIGTERM STARTED. A refusal exits 1
    // with grant_duplicate_key instead (D10).
    assert.match(r.stdout || '', /\"ok\":true/,
      `the daemon must start on a legal file (status=${r.status}, signal=${r.signal}, stderr=${r.stderr}, stdout=${r.stdout})`);
    assert.ok(!/grant_duplicate_key/.test(r.stderr || ''),
      'a legal file must not be misread as a duplicate');
  } finally { fs.rmSync(sb, { recursive: true, force: true }); }
});
