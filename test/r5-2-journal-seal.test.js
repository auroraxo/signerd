'use strict';

// Falsification tests for the R5-2 JOURNAL HALF (keyed journal MAC + seal
// floor), against probes p3 (truncate), p15 (re-chain forgery), p10
// (past-write through a retained mapping).
//
// The ladder (same pattern as r5-2-seal.test.js): every ENFORCEMENT test
// fails against the pre-fix tree (the sealed journal simply does not exist
// there, so the attack loads), while the FALSE-POSITIVE GUARDS pass on BOTH
// trees - a fix that refuses everything is not a fix.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Ledger, chainHash, GENESIS_HASH, parseJournal } = require('../src/ledger');
const seal = require('../src/journalseal');

const PASSPHRASE = 'journal-seal-test-passphrase';

function tmpJournal() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r5j-'));
  fs.chmodSync(dir, 0o755);
  return { dir, file: path.join(dir, 'journal.jsonl') };
}

const GRANT = {
  signer: 'x'.repeat(44), destination: 'y'.repeat(44),
  maxLamports: '10000000', expiresAt: '2099-01-01T00:00:00Z',
  windowMaxLamports: '10000000', windowSeconds: '3600',
};

function wireFor(tag) { return Buffer.from(`wire-${tag}-${crypto.randomUUID()}`); }

function approve(ledger, wire) {
  return ledger.approve({ wire, amountLamports: '42', grant: GRANT, now: new Date() });
}

// ---------------------------------------------------------------------------
// GUARD (must pass on BOTH trees): an unsealed journal behaves exactly as
// before the feature existed - loads without a passphrase, appends, reloads.
// ---------------------------------------------------------------------------
test('guard: unsealed journal works without any passphrase (both trees)', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file });
  const w1 = wireFor('u1');
  assert.equal(approve(l, w1).allowed, true);
  const reopened = new Ledger({ file });
  assert.equal(reopened.snapshot().records, 1);
  assert.equal(approve(reopened, w1).refused, 'replay');
  // No floor file may appear: an unsealed daemon never claims a floor.
  assert.equal(fs.existsSync(`${file}.anchor`), false);
});

// ---------------------------------------------------------------------------
// GUARD (must pass on BOTH trees): a sealed daemon signs and survives
// restarts; the plain chain keeps working under the seal.
// ---------------------------------------------------------------------------
test('guard: sealed daemon approves, reloads, and replays are still refused', () => {
  const { file } = tmpJournal();
  const l1 = new Ledger({ file, sealPassphrase: PASSPHRASE });
  const w1 = wireFor('s1');
  assert.equal(approve(l1, w1).allowed, true);
  assert.equal(approve(l1, wireFor('s2')).allowed, true);
  const l2 = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(l2.snapshot().records, 2);
  assert.equal(approve(l2, w1).refused, 'replay');
  assert.equal(approve(l2, wireFor('s3')).allowed, true);
  // format 4 on disk with the keyed chain field
  const recs = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  for (const r of recs) {
    assert.equal(r.v, 4);
    assert.match(r.x, /^[0-9a-f]{64}$/);
  }
});

// ---------------------------------------------------------------------------
// p3: TRUNCATION. A valid prefix of a valid chain is a valid chain - only the
// seal floor can see it. (Pre-fix: loads.)
// ---------------------------------------------------------------------------
test('p3 truncate: journal shorter than its floor is refused', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('t1')).allowed, true);
  assert.equal(approve(l, wireFor('t2')).allowed, true);
  // stranger truncates to the first record while the daemon is down
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  fs.writeFileSync(file, `${lines[0]}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => err.code === 'ledger_mac_short' || /ledger_mac_short/.test(err.message),
    'truncated journal must not load',
  );
});

test('p3 truncate-to-empty: a deleted journal with a floor is not a fresh start', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('t3')).allowed, true);
  fs.unlinkSync(file);
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => err.code === 'ledger_mac_short' || /ledger_mac_short/.test(err.message),
    'missing journal with a non-empty floor must not restart fresh',
  );
});

test('p3 truncate: the floor itself cannot be shrunk without the key', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('t4')).allowed, true);
  assert.equal(approve(l, wireFor('t5')).allowed, true);
  // attacker edits the floor's count down to 1 (keeps the old mac)
  const anchorFile = `${file}.anchor`;
  const anchor = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  anchor.count = 1;
  fs.writeFileSync(anchorFile, `${JSON.stringify(anchor)}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_anchor_mismatch/.test(err.message),
    'an edited floor must not verify',
  );
});

// ---------------------------------------------------------------------------
// p15: RE-CHAIN FORGERY. Recomputing the unkeyed chain is exactly what the
// attacker can do; the keyed MAC `x` is what they cannot. (Pre-fix: loads.)
// ---------------------------------------------------------------------------
test('p15 re-chain: forged amount with recomputed unkeyed chain is refused', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('f1')).allowed, true);
  assert.equal(approve(l, wireFor('f2')).allowed, true);
  const recs = fs.readFileSync(file, 'utf8').trim().split('\n').map((x) => JSON.parse(x));
  // The attacker lowers the recorded spend and recomputes every unkeyed
  // chain hash - exactly what p15 does. The keyed `x` is kept as-is: it
  // cannot be recomputed without the key, so it is now stale and every
  // record after the edit fails its MAC check.
  recs[0].a = '41';
  let prev = GENESIS_HASH;
  for (const r of recs) {
    r.h = chainHash(prev, r);
    prev = r.h;
  }
  fs.writeFileSync(file, `${recs.map((r) => JSON.stringify(r)).join('\n')}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_mac_invalid|ledger_tampered/.test(err.message),
    'a re-chained forgery must not load',
  );
  // ...and a forger who instead DELETES the keyed field cannot pass the
  // structural check either: a format-4 record without `x` is not a record.
  const stripped = fs.readFileSync(file, 'utf8').trim().split('\n').map((x) => JSON.parse(x));
  for (const r of stripped) delete r.x;
  fs.writeFileSync(file, `${stripped.map((r) => JSON.stringify(r)).join('\n')}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_corrupt|ledger_mac_invalid/.test(err.message),
    'a journal with its keyed field stripped must not load',
  );
  // ...and splicing an UNSEALED record in is refused too: the attacker
  // recomputes the unkeyed chain (as they always can), deletes `x`, and
  // writes a format-3-shaped record. Structure and unkeyed chain both pass;
  // only the sealed-mode rule "all or nothing" stops it.
  const spliced = fs.readFileSync(file, 'utf8').trim().split('\n').map((x) => JSON.parse(x));
  delete spliced[1].x;
  spliced[1].v = 3;
  let prev2 = GENESIS_HASH;
  for (const r of spliced) {
    r.h = chainHash(prev2, r);
    prev2 = r.h;
  }
  fs.writeFileSync(file, `${spliced.map((r) => JSON.stringify(r)).join('\n')}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_mac_invalid|ledger_corrupt|ledger_tampered/.test(err.message),
    'an unsealed record spliced into a sealed chain must not load',
  );
});

test('p15 drop-record: dropping a record and renumbering is refused', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  const w1 = wireFor('d1');
  assert.equal(approve(l, w1).allowed, true);
  assert.equal(approve(l, wireFor('d2')).allowed, true);
  // Attacker drops the FIRST record (its message is already signed - they
  // want it re-approvable) and renumbers the survivor to seq 1 with a
  // recomputed unkeyed chain. The stale keyed `x` no longer matches.
  const records = fs.readFileSync(file, 'utf8').trim().split('\n').map((x) => JSON.parse(x));
  const survivor = { ...records[1] };
  survivor.s = 1;
  survivor.h = chainHash(GENESIS_HASH, survivor);
  fs.writeFileSync(file, `${JSON.stringify(survivor)}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_mac_invalid|ledger_mac_short|ledger_anchor_mismatch|ledger_corrupt/.test(err.message),
    'a journal with a record dropped must not load',
  );
  // And the dropped message must not be re-approvable even if the attacker
  // ALSO deletes the floor: a sealed journal without its floor is refused,
  // so the forgery never becomes a loadable "fresh" history.
  fs.writeFileSync(file, `${records.map((r) => JSON.stringify(r)).join('\n')}\n`, { mode: 0o600 });
  fs.unlinkSync(`${file}.anchor`);
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_anchor_missing/.test(err.message),
    'a sealed journal without its floor must not load',
  );
});

// ---------------------------------------------------------------------------
// p10: PAST-WRITE / in-place edit. A write through a retained mapping is a
// byte change like any other; the keyed chain catches it even when the
// attacker recomputes the unkeyed chain (covered above). Here: an in-place
// same-size edit (the classic blind spot of size-only checks).
// ---------------------------------------------------------------------------
test('p10 in-place: a same-size byte edit inside a sealed record is refused', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('m1')).allowed, true);
  const raw = fs.readFileSync(file, 'utf8');
  const tampered = raw.replace('"a":"42"', '"a":"41"');
  assert.notEqual(tampered, raw, 'the tamper must actually change bytes');
  fs.writeFileSync(file, tampered, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_tampered|ledger_mac_invalid/.test(err.message),
    'an in-place edit must not load',
  );
});

// ---------------------------------------------------------------------------
// Mode enforcement: sealed <-> unsealed are never mixed.
// ---------------------------------------------------------------------------
test('sealed journal without the passphrase is refused (never degraded)', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('n1')).allowed, true);
  assert.throws(
    () => new Ledger({ file }),
    (err) => err.code === 'ledger_sealed' || /ledger_sealed/.test(err.message),
    'unkeyed load of a sealed journal must refuse',
  );
});

test('sealed daemon on an unsealed journal refuses and names seal-journal', () => {
  const { file } = tmpJournal();
  const plain = new Ledger({ file });
  assert.equal(approve(plain, wireFor('p1')).allowed, true);
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => (err.code || '').includes('ledger_unsealed') || /seal-journal/.test(err.message),
    'sealed daemon must not silently trust unsealed history',
  );
});

// ---------------------------------------------------------------------------
// Crash window: journal AHEAD of floor (record durable, anchor not yet) must
// LOAD - the caller never saw that approval, so the shape is benign. The
// reverse (floor ahead) is truncation and must refuse.
// ---------------------------------------------------------------------------
test('guard: journal ahead of its floor still loads (crash window)', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('c1')).allowed, true);
  // simulate the crash: floor still at count 0 is impossible (first append
  // writes both), so drop the floor back by rewriting it to count 0/genesis
  // with the correct key - exactly what a crash after record 1 would leave.
  const key = seal.deriveJournalKey(PASSPHRASE);
  fs.writeFileSync(`${file}.anchor`,
    `${JSON.stringify(seal.sealAnchor(key, { count: 0, head: seal.genesisMac(key) }))}\n`,
    { mode: 0o600 });
  const reopened = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(reopened.snapshot().records, 1, 'the ahead-of-floor record must be kept');
  // and the floor catches up on the next approval
  assert.equal(approve(reopened, wireFor('c2')).allowed, true);
  const anchor = JSON.parse(fs.readFileSync(`${file}.anchor`, 'utf8'));
  assert.equal(anchor.count, 2, 'the floor must catch up after the next append');
});

test('floor ahead of the journal (truncation shape) is refused', () => {
  const { file } = tmpJournal();
  const l = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(approve(l, wireFor('h1')).allowed, true);
  // attacker appends NOTHING but rewrites the floor to claim 2 records
  const key = seal.deriveJournalKey(PASSPHRASE);
  const forged = seal.sealAnchor(key, { count: 2, head: 'a'.repeat(64) });
  fs.writeFileSync(`${file}.anchor`, `${JSON.stringify(forged)}\n`, { mode: 0o600 });
  assert.throws(
    () => new Ledger({ file, sealPassphrase: PASSPHRASE }),
    (err) => /ledger_anchor_mismatch|ledger_mac_short/.test(err.message),
    'a floor ahead of the journal must not load',
  );
});

// ---------------------------------------------------------------------------
// seal-journal: sealing an existing (valid) journal, and its refusals.
// ---------------------------------------------------------------------------
test('seal-journal seals an existing valid journal and prints what it sealed', async () => {
  const { sealExistingJournal } = require('../src/journalseal-ops');
  const { file } = tmpJournal();
  const plain = new Ledger({ file });
  const w1 = wireFor('x1');
  const w2 = wireFor('x2');
  assert.equal(approve(plain, w1).allowed, true);
  assert.equal(approve(plain, w2).allowed, true);

  const result = sealExistingJournal({ journalFile: file, passphrase: PASSPHRASE });
  assert.equal(result.sealed, true);
  assert.equal(result.records, 2);
  assert.equal(result.seqTo, 2);
  // the operator-facing report names exactly the wires that were sealed
  const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
  assert.deepEqual(result.wireSha256.slice().sort(), [sha256(w1), sha256(w2)].sort());

  // the sealed journal now loads ONLY with the passphrase
  const sealed = new Ledger({ file, sealPassphrase: PASSPHRASE });
  assert.equal(sealed.snapshot().records, 2);
  assert.equal(approve(sealed, w1).refused, 'replay');
  assert.throws(() => new Ledger({ file }),
    (err) => /ledger_sealed/.test(err.message));

  // idempotent: sealing again reports already_sealed
  const again = sealExistingJournal({ journalFile: file, passphrase: PASSPHRASE });
  assert.equal(again.sealed, false);
  assert.equal(again.reason, 'already_sealed');
});

test('seal-journal refuses a journal whose chain does not parse (forges stay unsealed)', async () => {
  const { sealExistingJournal } = require('../src/journalseal-ops');
  const { file } = tmpJournal();
  const plain = new Ledger({ file });
  assert.equal(approve(plain, wireFor('g1')).allowed, true);
  // forge: change a byte without re-chaining
  const raw = fs.readFileSync(file, 'utf8');
  fs.writeFileSync(file, raw.replace('"a":"42"', '"a":"41"'), { mode: 0o600 });
  assert.throws(
    () => sealExistingJournal({ journalFile: file, passphrase: PASSPHRASE }),
    (err) => /ledger_tampered|ledger_corrupt/.test(err.message),
    'sealing must refuse a forged journal instead of making it valid',
  );
});

test('seal-journal refuses while a daemon holds the journal lock', async () => {
  const { sealExistingJournal } = require('../src/journalseal-ops');
  const { file } = tmpJournal();
  const plain = new Ledger({ file });
  assert.equal(approve(plain, wireFor('l1')).allowed, true);
  // a running daemon holds <journal>.lock
  fs.writeFileSync(`${file}.lock`, JSON.stringify({ pid: process.pid, token: 'live' }), { mode: 0o600 });
  try {
    assert.throws(
      () => sealExistingJournal({ journalFile: file, passphrase: PASSPHRASE }),
      (err) => err.code === 'ledger_locked',
      'sealing must refuse while the daemon runs',
    );
  } finally {
    fs.unlinkSync(`${file}.lock`);
  }
});
