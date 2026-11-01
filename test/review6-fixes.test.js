'use strict';
// REGRESSION TESTS (review #6, fixes 3-5)
//
// Findings covered (each measured against the pre-fix tree 1655883 by
// research/review6/p4 + p6; those probes are the pre-fix measurement, these
// tests pin the fixed behaviour):
//
//   R6-4  seal-journal never launders a floor: a forged journal handed to the
//         recovery tool beside the operator's genuine floor is refused with
//         ledger_anchor_mismatch instead of having the floor rewritten to
//         witness the forgery (p4 case5), and the old floor survives
//         unchanged when a legitimate reseal replaces it.
//   R6-5  seal-journal repairs a MISSING floor on an already-sealed journal
//         (p4 case3): the daemon refuses that state with ledger_anchor_missing
//         and the recovery tool used to print already_sealed and leave the
//         brick in place.
//   R6-6  passphrase file hygiene: readPassphrase refuses a symlink, a
//         group/other-accessible file, and a world-writable directory
//         (p6 Q1/Q3; Q2's foreign-owner arm runs only as root).
//   R6-7  sealing a 0-record journal yields a valid empty sealed journal,
//         not ledger_corrupt on a lone newline (p4 case1).
//
// Controls (MUST pass on the pre-fix tree too): an honest reseal with a
// matching floor succeeds, and a well-formed passphrase file in a private
// directory is read normally.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');

const { parseJournal, SEALED_JOURNAL_FORMAT, chainHash, GENESIS_HASH, Ledger } = require('../src/ledger');
const seal = require('../src/journalseal');
const { sealExistingJournal } = require('../src/journalseal-ops');

const PASS = 'journal seal passphrase review6-reg';
const BIN = path.join(__dirname, '..', 'bin', 'signerd.js');

function tmpDir(prefix = 'signerd-r6-fix-') {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(d, 0o700);
  return d;
}

/** A genuine sealed journal with `n` records + matching floor. Returns heads. */
function buildSealed(file, n = 2) {
  const key = seal.deriveJournalKey(PASS);
  const lines = [];
  const heads = [];
  let prevH = GENESIS_HASH;
  let prevX = seal.genesisMac(key);
  for (let i = 1; i <= n; i++) {
    const body = {
      v: SEALED_JOURNAL_FORMAT, s: i, t: 1700000000000 + i,
      w: i.toString(16).padStart(64, '0'), m: null, a: '42', f: '5000', k: 'scope',
    };
    const rec = { ...body, h: chainHash(prevH, body) };
    rec.x = seal.chainMac(key, prevX, rec.h);
    prevH = rec.h;
    prevX = rec.x;
    heads.push(rec.x);
    lines.push(JSON.stringify(rec));
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  fs.chmodSync(file, 0o600);
  seal.writeAnchor(`${file}.anchor`, seal.sealAnchor(key, { count: n, head: heads[n - 1] }));
  fs.chmodSync(`${file}.anchor`, 0o600);
  return { key, heads };
}

/** An unsealed (v3) journal with `n` records whose unkeyed chain verifies. */
function buildUnsealed(file, n = 1, mutate = null) {
  const lines = [];
  let prevH = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const body = {
      v: 3, s: i, t: 1700000000000 + i,
      w: ((mutate && mutate.w) || i).toString(16).padStart(64, '0'),
      m: null, a: '42', f: '5000', k: (mutate && mutate.k) || 'scope',
    };
    const rec = { ...body, h: chainHash(prevH, body) };
    prevH = rec.h;
    lines.push(JSON.stringify(rec));
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  fs.chmodSync(file, 0o600);
  return lines;
}

test('DEFECT R6-4: seal-journal refuses a forged journal beside a genuine floor (no laundering)', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'c5.jsonl');
    // Genuine sealed journal + floor first...
    const { heads } = buildSealed(j, 1);
    const floorBefore = fs.readFileSync(`${j}.anchor`, 'utf8');
    // ...then the attacker's replacement: an UNSEALED journal with a
    // different chain, same length (p4 case5's shape).
    buildUnsealed(j, 1, { w: 'f', k: 'attacker' });
    assert.throws(
      () => sealExistingJournal({ journalFile: j, passphrase: PASS }),
      (err) => {
        assert.equal(err.code, 'ledger_anchor_mismatch',
          `expected ledger_anchor_mismatch, got: ${err.code || err.message}`);
        return true;
      },
      'a journal whose keyed chain disagrees with the existing floor must be refused',
    );
    // The operator's floor must be untouched.
    assert.equal(fs.readFileSync(`${j}.anchor`, 'utf8'), floorBefore,
      'the genuine floor must survive the refused reseal byte-identically');
    assert.ok(heads[0], 'fixture sanity: one head');
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('CONTROL (holds pre-fix): honest fresh seal, then a no-op reseal, leaves the journal byte-identical', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'ok.jsonl');
    buildUnsealed(j, 2);
    const first = sealExistingJournal({ journalFile: j, passphrase: PASS });
    assert.equal(first.sealed, true, 'a clean journal seals');
    assert.equal(first.floor.count, 2);
    const bytesAfterSeal = fs.readFileSync(j);
    const again = sealExistingJournal({ journalFile: j, passphrase: PASS });
    assert.equal(again.reason, 'already_sealed');
    assert.ok(bytesAfterSeal.equals(fs.readFileSync(j)),
      'the already-sealed no-op must not touch the journal');
    const parsed = parseJournal(bytesAfterSeal, { macKey: seal.deriveJournalKey(PASS) });
    assert.equal(parsed.seq, 2, 'journal unchanged by the no-op');
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// Post-fix pinned (expected RED on the pre-fix tree, where the floor was
// overwritten silently): a genuine STALE floor (count 1 of 2, head agrees at
// count) is accepted and reported as floorOverwritten=true.
test('honest reseal over a stale-but-genuine floor succeeds and reports floorOverwritten', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'stale.jsonl');
    buildUnsealed(j, 2);
    // Project the sealed chain exactly like the tool does, then lay down a
    // floor that witnessed only the first record (the stale shape p4/c4).
    const key = seal.deriveJournalKey(PASS);
    let prevH = GENESIS_HASH;
    let prevX = seal.genesisMac(key);
    let head0 = null;
    for (let i = 1; i <= 2; i++) {
      const body = {
        v: SEALED_JOURNAL_FORMAT, s: i, t: 1700000000000 + i,
        w: i.toString(16).padStart(64, '0'), m: null, a: '42', f: '5000', k: 'scope',
      };
      const rec = { ...body, h: chainHash(prevH, body) };
      rec.x = seal.chainMac(key, prevX, rec.h);
      prevH = rec.h;
      prevX = rec.x;
      if (i === 1) head0 = rec.x;
    }
    seal.writeAnchor(`${j}.anchor`, seal.sealAnchor(key, { count: 1, head: head0 }));
    fs.chmodSync(`${j}.anchor`, 0o600);
    const res = sealExistingJournal({ journalFile: j, passphrase: PASS });
    assert.equal(res.sealed, true, 'the stale floor matches the chain at count 1: reseal is honest');
    assert.equal(res.floorOverwritten, true, 'the floor replacement must be reported');
    const res2 = sealExistingJournal({ journalFile: j, passphrase: PASS });
    assert.equal(res2.reason, 'already_sealed');
    assert.equal(res2.floorOverwritten, undefined);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('DEFECT R6-5: seal-journal repairs a MISSING floor on an already-sealed journal', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'c3.jsonl');
    buildSealed(j, 2);
    fs.unlinkSync(`${j}.anchor`); // the brick: daemon refuses ledger_anchor_missing
    // The daemon indeed refuses:
    assert.throws(
      () => new Ledger({ file: j, sealPassphrase: PASS }),
      (err) => {
        assert.equal(err.code, 'ledger_anchor_missing',
          `expected the brick, got: ${err.code || err.message}`);
        return true;
      },
      'precondition: the daemon must refuse the missing floor',
    );
    const res = sealExistingJournal({ journalFile: j, passphrase: PASS });
    assert.equal(res.reason, 'already_sealed');
    assert.equal(res.floorRepaired, true, 'the tool must report that it created the floor');
    assert.ok(fs.existsSync(`${j}.anchor`), 'the floor must now exist');
    // The daemon loads again.
    const led = new Ledger({ file: j, sealPassphrase: PASS });
    assert.equal(led.seq, 2, 'daemon accepts the repaired state with full history');
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('DEFECT R6-7: sealing a 0-record journal produces a valid empty sealed journal', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'empty.jsonl');
    fs.writeFileSync(j, ''); fs.chmodSync(j, 0o600);
    const res = sealExistingJournal({ journalFile: j, passphrase: PASS });
    assert.equal(res.sealed, true, 'an empty journal is a legitimate fresh state');
    assert.equal(res.records, 0);
    const led = new Ledger({ file: j, sealPassphrase: PASS });
    assert.equal(led.seq, 0, 'the sealed empty journal loads');
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// --- R6-6: passphrase file hygiene (CLI-level, through bin/signerd.js) -----

function cliStatus(args) {
  const r = spawnSync(process.execPath, [BIN, 'status', ...args], { encoding: 'utf8', timeout: 30000 });
  return { status: r.status, stderr: (r.stderr || '').trim().slice(0, 300) };
}

function cliFixture(dir) {
  const keystore = path.join(dir, 'ops.key');
  spawnSync(process.execPath, [BIN, 'keygen', '--keystore', keystore,
    '--passphrase-file', writePass(dir, 'ks.pass', 'ks passphrase r6')], { encoding: 'utf8' });
  return keystore;
}

function writePass(dir, name, content) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  fs.chmodSync(p, 0o600);
  return p;
}

test('DEFECT R6-6: a symlinked passphrase path is refused (ELOOP), not followed', () => {
  const dir = tmpDir();
  try {
    const target = writePass(dir, 'real.pass', 'seal passphrase r6');
    const link = path.join(dir, 'link.pass');
    fs.symlinkSync(target, link);
    const out = cliStatus(['--keystore', cliFixture(dir),
      '--passphrase-file', path.join(dir, 'ks.pass'), '--grant-seal-passphrase-file', link]);
    assert.notEqual(out.status, 0, `symlinked passphrase must be refused, got: ${out.stderr}`);
    assert.match(out.stderr, /regular file|ENOENT|ELOOP/,
      `expected a symlink refusal, got: ${out.stderr}`);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('DEFECT R6-6: a world-writable directory holding the passphrase is refused', () => {
  const dir = tmpDir();
  try {
    const wdir = path.join(dir, 'writable');
    fs.mkdirSync(wdir, 0o777);
    fs.chmodSync(wdir, 0o777);
    const pass = path.join(wdir, 'seal.pass');
    fs.writeFileSync(pass, 'seal passphrase r6');
    fs.chmodSync(pass, 0o600);
    const out = cliStatus(['--keystore', cliFixture(dir),
      '--passphrase-file', path.join(dir, 'ks.pass'), '--grant-seal-passphrase-file', pass]);
    assert.notEqual(out.status, 0, `world-writable passphrase dir must be refused, got: ${out.stderr}`);
    assert.match(out.stderr, /directory/,
      `expected a directory refusal, got: ${out.stderr}`);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('DEFECT R6-6: a group/other-accessible passphrase file is still refused', () => {
  const dir = tmpDir();
  try {
    const pass = writePass(dir, 'loose.pass', 'seal passphrase r6');
    fs.chmodSync(pass, 0o644);
    const out = cliStatus(['--keystore', cliFixture(dir),
      '--passphrase-file', path.join(dir, 'ks.pass'), '--grant-seal-passphrase-file', pass]);
    assert.notEqual(out.status, 0, 'mode 0644 passphrase must be refused');
    assert.match(out.stderr, /group\/other accessible/,
      `expected the mode refusal, got: ${out.stderr}`);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('CONTROL (holds pre-fix): a well-formed 0600 passphrase in a private directory is read', (t) => {
  const dir = tmpDir();
  try {
    const keystore = cliFixture(dir);
    const pass = writePass(dir, 'seal.pass', 'seal passphrase r6');
    const out = cliStatus(['--keystore', keystore,
      '--passphrase-file', path.join(dir, 'ks.pass'), '--grant-seal-passphrase-file', pass]);
    // seal-grants on an UNSEALED doc is grant_file_unsealed, not a hygiene
    // error: the point is that readPassphrase ACCEPTED the file.
    assert.doesNotMatch(out.stderr, /group\/other|regular file|directory/,
      `hygiene must accept this file, got: ${out.stderr}`);
    assert.ok(!/must not|must be/.test(out.stderr),
      `no hygiene complaint expected, got: ${out.stderr}`);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
