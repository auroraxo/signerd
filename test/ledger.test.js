'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { evaluate } = require('../src/policy');
const { Ledger, gate, BASE_FEE_LAMPORTS } = require('../src/ledger');
const { loadGrantFile } = require('../src/grantfile');

const signer = Keypair.generate();
const recipient = Keypair.generate().publicKey;
const blockhash = Keypair.generate().publicKey.toBase58();
const now = new Date('2026-10-27T10:00:00.000Z');
const grant = {
  signer: signer.publicKey.toBase58(),
  destination: recipient.toBase58(),
  maxLamports: '42',
  expiresAt: '2026-10-28T10:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

function transfer(to = recipient, lamports = 42, from = signer.publicKey) {
  return SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports });
}
function legacy(...instructions) {
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = blockhash;
  for (const ix of instructions) tx.add(ix);
  tx.sign(signer); // disposable test key; policy does not verify signatures
  return tx.serialize();
}
function tmpLedger() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-ledger-'));
  return new Ledger({ file: path.join(dir, 'journal.jsonl') });
}

test('policy verdict alone is refused without a ledger (fail closed)', () => {
  const wire = legacy(transfer());
  assert.equal(evaluate(wire, grant, now).allowed, true);
  assert.deepEqual(gate(wire, grant, now), { allowed: false, refused: 'ledger_unavailable' });
});

test('approve charges amount plus fixed base fee against the window', () => {
  const ledger = tmpLedger();
  const wire = legacy(transfer());
  const verdict = gate(wire, grant, now, ledger);
  assert.deepEqual(verdict, {
    allowed: true,
    amountLamports: '42',
    feeLamports: BASE_FEE_LAMPORTS.toString(),
    totalLamports: (42n + BASE_FEE_LAMPORTS).toString(),
    wireSha256: require('node:crypto').createHash('sha256').update(wire).digest('hex'),
    messageSha256: require('node:crypto').createHash('sha256')
      .update(wire.subarray(1 + 64)).digest('hex'),
    seq: 1,
    windowSpentLamports: (42n + BASE_FEE_LAMPORTS).toString(),
    windowRemainingLamports: (100000n - 42n - BASE_FEE_LAMPORTS).toString(),
  });
  // Durable before returned: the journal line exists on disk.
  const lines = fs.readFileSync(ledger.file, 'utf8').trimEnd().split('\n');
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).s, 1);
});

test('the same wire is approved exactly once, ever (replay)', () => {
  const ledger = tmpLedger();
  const wire = legacy(transfer());
  assert.equal(gate(wire, grant, now, ledger).allowed, true);
  const second = gate(wire, grant, now, ledger);
  assert.equal(second.allowed, false);
  assert.equal(second.refused, 'replay');
  // Reload from disk: the replay set survives restart.
  const reopened = new Ledger({ file: ledger.file });
  const third = gate(wire, grant, now, reopened);
  assert.equal(third.refused, 'replay');
  assert.deepEqual(reopened.snapshot(), { records: 1, seq: 1, fingerprints: 1 });
});

test('window cap bounds cumulative spending across distinct transactions', () => {
  const ledger = tmpLedger();
  // Same policy-valid shape, fresh blockhash each time -> distinct wires.
  const wires = Array.from({ length: 40}, (_, i) => {
    const tx = new Transaction();
    tx.feePayer = signer.publicKey;
    tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
    tx.add(transfer());
    tx.sign(signer);
    return tx.serialize();
  });
  const perTx = 42n + BASE_FEE_LAMPORTS; // 5042
  const cap = grant.windowMaxLamports;
  const affordable = Number(BigInt(cap) / perTx); // 19 full approvals fit
  let approved = 0;
  let lastRefusal = null;
  for (const wire of wires) {
    const verdict = gate(wire, grant, now, ledger);
    if (verdict.allowed) approved += 1;
    else lastRefusal = verdict;
  }
  assert.equal(approved, affordable);
  assert.equal(lastRefusal.refused, 'window_cap');
  assert.equal(lastRefusal.windowSpentLamports, (BigInt(approved) * perTx).toString());
  // Each wire individually passes policy: only the ledger stops it.
  for (const wire of wires.slice(approved)) {
    assert.equal(evaluate(wire, grant, now).allowed, true);
  }
});

test('window refuses when only the fee (not the amount) would exceed the cap', () => {
  const ledger = tmpLedger();
  // Window has exactly 5041 lamports left after one approval of amount 0.
  const tight = { ...grant, windowMaxLamports: '5041' };
  const w1 = legacy(transfer(recipient, 0));
  const first = gate(w1, tight, now, ledger);
  assert.equal(first.allowed, true); // amount 0 + fee 5000 <= 5041
  const w2 = legacy(transfer(recipient, 42));
  assert.equal(evaluate(w2, tight, now).allowed, true); // policy sees only 42 <= 42
  const second = gate(w2, tight, now, ledger);
  assert.equal(second.allowed, false);
  assert.equal(second.refused, 'window_cap');
});

test('expired and invalid-grant refusals happen before any journal write', () => {
  const ledger = tmpLedger();
  const expired = { ...grant, expiresAt: now.toISOString() };
  assert.equal(gate(legacy(transfer()), expired, now, ledger).refused, 'expired');
  const noWindow = { ...grant };
  delete noWindow.windowSeconds;
  assert.equal(gate(legacy(transfer()), noWindow, now, ledger).refused, 'invalid_grant_window');
  const floatWindow = { ...grant, windowSeconds: '1.5' };
  assert.equal(gate(legacy(transfer()), floatWindow, now, ledger).refused, 'invalid_grant_window');
  assert.deepEqual(ledger.snapshot(), { records: 0, seq: 0, fingerprints: 0 });
  assert.equal(fs.existsSync(ledger.file), false);
});

test('rolling window: old approvals age out', () => {
  const ledger = tmpLedger();
  const shortGrant = { ...grant, windowMaxLamports: '5042', windowSeconds: '60' };
  const t0 = now;
  const w1 = legacy(transfer());
  assert.equal(gate(w1, shortGrant, t0, ledger).allowed, true);
  const w2 = legacy(transfer(recipient, 41));
  const inWindow = gate(w2, shortGrant, new Date(t0.getTime() + 30_000), ledger);
  assert.equal(inWindow.refused, 'window_cap'); // 5042 spent, 60s window
  const afterWindow = gate(w2, shortGrant, new Date(t0.getTime() + 61_000), ledger);
  assert.equal(afterWindow.allowed, true); // t0 approval aged out
});

test('a torn final journal line is dropped, complete records are kept', () => {
  const ledger = tmpLedger();
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);
  // Simulate a crash mid-append: partial JSON, no trailing newline.
  fs.appendFileSync(ledger.file, '{"s":2,"t":1793100000000,"w":"abc');
  const reopened = new Ledger({ file: ledger.file });
  assert.deepEqual(reopened.snapshot(), { records: 1, seq: 1, fingerprints: 1 });
  // Repair happened: next append is a clean line and loads again.
  const w2 = legacy(transfer(recipient, 41));
  assert.equal(gate(w2, grant, new Date(now.getTime() + 1000), reopened).allowed, true);
  const again = new Ledger({ file: ledger.file });
  assert.deepEqual(again.snapshot(), { records: 2, seq: 2, fingerprints: 2 });
});

test('a failed rollback poisons the ledger and every later approval is refused', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-ledger-'));
  const file = path.join(dir, 'journal.jsonl');
  const ledger = new Ledger({ file });
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);

  // Simulate BOTH the append failing and the rollback failing: the file is
  // then in a state the ledger cannot account for, so it must refuse every
  // further approval instead of appending into unknown bytes.
  const realWrite = fs.writeSync;
  const realFtruncate = fs.ftruncateSync;
  fs.writeSync = (fd, ...args) => {
    realWrite.call(fs, fd, args[0], 0, 20);
    const err = new Error('simulated ENOSPC');
    err.code = 'ENOSPC';
    throw err;
  };
  fs.ftruncateSync = () => {
    const err = new Error('simulated EIO on rollback');
    err.code = 'EIO';
    throw err;
  };
  let verdict;
  try {
    verdict = gate(legacy(transfer(recipient, 41)), grant, now, ledger);
  } finally {
    fs.writeSync = realWrite;
    fs.ftruncateSync = realFtruncate;
  }
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.refused, 'ledger_inconsistent',
    'an unrollbackable append must be reported as inconsistent, not as a plain write failure');

  // Every later approval is refused too, even though the disk works again:
  // the ledger knows it lost track of the file and refuses to guess.
  const later = gate(legacy(transfer(recipient, 41)), grant, new Date(now.getTime() + 1000), ledger);
  assert.equal(later.allowed, false);
  assert.equal(later.refused, 'ledger_inconsistent');
  assert.equal(later.seq, undefined, 'a poisoned ledger must not report an approval');
});

test('a corrupt complete line makes the ledger refuse to load', () => {
  const ledger = tmpLedger();
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);
  fs.appendFileSync(ledger.file, 'not json\n');
  assert.throws(() => new Ledger({ file: ledger.file }), /ledger_corrupt/);
  // A valid-looking line with a wrong sequence also fails closed.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-ledger-'));
  const file = path.join(dir, 'journal.jsonl');
  fs.writeFileSync(file, JSON.stringify({ s: 5, t: 1, w: 'a'.repeat(64), a: '1', f: '5000' }) + '\n');
  // The journal is the replay set: it is only trusted when it is owner-only.
  // A handcrafted file is written with the default umask (0644), which the
  // loader refuses BEFORE it reads a single record - so the mode is fixed
  // here to get past the hygiene check and reach the corruption check.
  fs.chmodSync(file, 0o600);
  assert.throws(() => new Ledger({ file }), /ledger_corrupt/);
});

test('an unwritable journal refuses approval and leaves no state behind', () => {
  const ledger = tmpLedger();
  // Make the directory unreadable/unwritable for the append.
  fs.chmodSync(path.dirname(ledger.file), 0o500);
  try {
    const verdict = gate(legacy(transfer()), grant, now, ledger);
    assert.equal(verdict.allowed, false);
    assert.equal(verdict.refused, 'ledger_write_failed');
    assert.deepEqual(ledger.snapshot(), { records: 0, seq: 0, fingerprints: 0 });
  } finally {
    fs.chmodSync(path.dirname(ledger.file), 0o700);
  }
  // After restoring writability the same wire can be approved: the failed
  // attempt truly recorded nothing.
  const verdict = gate(legacy(transfer()), grant, now, ledger);
  assert.equal(verdict.allowed, true);
});

test('two grants for the SAME destination share one window budget', () => {
  const ledger = tmpLedger();
  const grantA = { ...grant, windowMaxLamports: '10084' }; // two approvals fit
  const grantB = { ...grant, windowMaxLamports: '10084' }; // same signer+dest
  const w1 = legacy(transfer());
  assert.equal(gate(w1, grantA, now, ledger).allowed, true);
  const w2 = legacy(transfer(recipient, 41));
  assert.equal(gate(w2, grantB, now, ledger).allowed, true);
  // Third must be stopped by grant B even though grant B itself approved
  // nothing beyond w2: the budget belongs to the scope, not the grant object.
  const w3 = legacy(transfer(recipient, 40));
  const third = gate(w3, grantB, now, ledger);
  assert.equal(third.refused, 'window_cap');
});

test('grants for DIFFERENT destinations keep independent budgets', () => {
  const ledger = tmpLedger();
  const otherDest = Keypair.generate().publicKey;
  const grantOther = { ...grant, destination: otherDest.toBase58(), windowMaxLamports: '5042' };
  const w1 = legacy(transfer(recipient, 0));
  assert.equal(gate(w1, { ...grant, windowMaxLamports: '5042' }, now, ledger).allowed, true);
  const w2 = legacy(transfer(otherDest, 0));
  assert.equal(gate(w2, grantOther, now, ledger).allowed, true); // other scope untouched
});

test('a window of zero seconds is refused: it would never engage the cap', () => {
  const ledger = tmpLedger();
  const zero = { ...grant, windowSeconds: '0', windowMaxLamports: '5042' };
  // cutoff = now would exclude every record at or before now, so the cap
  // would silently never fire. Refuse the grant instead.
  assert.equal(gate(legacy(transfer()), zero, now, ledger).refused, 'invalid_grant_window');
  assert.equal(ledger.snapshot().records, 0);
  // The grant file refuses it too, before the daemon ever starts.
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-g-')), 'g.json');
  fs.writeFileSync(file, JSON.stringify({
    version: 1,
    grants: { ops: { ...grant, windowSeconds: '0' } },
  }));
  assert.throws(() => loadGrantFile(file), /grant_field_invalid/);
});

test('a failed append never leaves a partial line that bricks the journal', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-ledger-'));
  const file = path.join(dir, 'journal.jsonl');
  const ledger = new Ledger({ file });
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);
  const good = fs.readFileSync(file, 'utf8');

  // Simulate a partial write: some bytes reach the file, then it fails.
  const realWrite = fs.writeSync;
  fs.writeSync = (fd, ...args) => {
    const buffer = args[0];
    realWrite.call(fs, fd, buffer, 0, 20);
    const err = new Error('simulated ENOSPC');
    err.code = 'ENOSPC';
    throw err;
  };
  let verdict;
  try {
    verdict = gate(legacy(transfer(recipient, 41)), grant, now, ledger);
  } finally {
    fs.writeSync = realWrite;
  }
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.refused, 'ledger_write_failed');
  // The journal must still be byte-identical to the last durable state: the
  // half-written line was rolled back, so no load can ever see it.
  assert.equal(fs.readFileSync(file, 'utf8'), good);
  const reopened = new Ledger({ file });
  assert.deepEqual(reopened.snapshot(), { records: 1, seq: 1, fingerprints: 1 });
  // And the next approval still works.
  assert.equal(gate(legacy(transfer(recipient, 41)), grant, new Date(now.getTime() + 1000), ledger).allowed, true);
  const again = new Ledger({ file });
  assert.deepEqual(again.snapshot(), { records: 2, seq: 2, fingerprints: 2 });
});

test('an external write into the journal is refused, never merged with', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-ledger-'));
  const file = path.join(dir, 'journal.jsonl');
  const ledger = new Ledger({ file });
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);
  const good = fs.readFileSync(file, 'utf8');
  // Another process (or a stray shell) writes bytes the daemon did not.
  fs.appendFileSync(file, '{"s":2,"t":1793');
  const verdict = gate(legacy(transfer(recipient, 41)), grant, now, ledger);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.refused, 'ledger_changed');
  assert.equal(verdict.signed, undefined);
  // The foreign bytes are left untouched and the daemon keeps refusing:
  // an operator must reconcile the journal, the daemon must never append
  // after bytes it did not write.
  assert.equal(fs.readFileSync(file, 'utf8'), good + '{"s":2,"t":1793');
  const again = gate(legacy(transfer(recipient, 40)), grant, now, ledger);
  assert.equal(again.refused, 'ledger_changed');
  // It still LOADS: the foreign bytes form an incomplete final line, which
  // the loader drops and repairs (a torn tail was never a durable record).
  const reloaded = new Ledger({ file });
  assert.deepEqual(reloaded.snapshot(), { records: 1, seq: 1, fingerprints: 1 });
});

test('hostile clock and prototype-polluted window fields are refused', () => {
  const ledger = tmpLedger();
  class FakeNow extends Date { getTime() { return now.getTime(); } }
  const expired = { ...grant, expiresAt: '2026-10-26T10:00:00Z' };
  assert.equal(gate(legacy(transfer()), expired, new FakeNow(), ledger).refused, 'invalid_clock');
  // window cap sitting on Object.prototype must not be usable
  const partial = { signer: grant.signer, destination: grant.destination,
    maxLamports: '42', expiresAt: grant.expiresAt, windowSeconds: '3600' };
  const saved = Object.prototype.windowMaxLamports;
  Object.prototype.windowMaxLamports = '999999999999';
  try {
    assert.equal(gate(legacy(transfer()), partial, now, ledger).refused, 'invalid_grant_window');
  } finally {
    if (saved === undefined) delete Object.prototype.windowMaxLamports;
    else Object.prototype.windowMaxLamports = saved;
  }
  assert.deepEqual(ledger.snapshot(), { records: 0, seq: 0, fingerprints: 0 });
});

test('clock regressions cannot shrink the window spend', () => {
  const ledger = tmpLedger();
  const t0 = now;
  assert.equal(gate(legacy(transfer()), grant, t0, ledger).allowed, true);
  // Clock jumps backwards 10 minutes: the t0 record is still inside the window
  // because cutoff = t-10min - 3600s < t0.
  const backClock = new Date(t0.getTime() - 600_000);
  const w2 = legacy(transfer(recipient, 41));
  const verdict = gate(w2, { ...grant, windowMaxLamports: '6000' }, backClock, ledger);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.refused, 'window_cap');
});

// ---------------------------------------------------------------------------
// Regression tests from the 27.10. independent adversarial review (run
// 24d92c08): the suite was green while these defects existed. Each test below
// fails against the reviewed code and passes only after the fix.
// ---------------------------------------------------------------------------

// Fixture builder: the ledger stores a per-record hash chain, so handcrafted
// journal records must carry a valid `h` or the load fails closed.
function chained(record, prevHash) {
  const body = [record.s, record.t, record.w, record.a, record.f, record.k].join('\u0000');
  const h = require('node:crypto').createHash('sha256')
    .update(prevHash + '\u0000' + body).digest('hex');
  return { ...record, h };
}
const GENESIS = '0'.repeat(64);

test('review #5: an invalid-UTF-8 journal tail never destroys a durable record', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-u8-'));
  const file = path.join(dir, 'journal.jsonl');
  const r1 = JSON.stringify(chained({ s: 1, t: 1000, w: 'a'.repeat(64), a: '42', f: '5000', k: 'k1' }, GENESIS)) + '\n';
  const r2 = JSON.stringify(chained({ s: 2, t: 2000, w: 'b'.repeat(64), a: '43', f: '5000', k: 'k1' },
    require('node:crypto').createHash('sha256').update(GENESIS + '\u0000' +
      [1, 1000, 'a'.repeat(64), '42', '5000', 'k1'].join('\u0000')).digest('hex'))) + '\n';
  const valid = Buffer.from(r1 + r2, 'utf8');
  // 1 invalid byte appended (a torn tail from binary garbage): decoding turns
  // it into a 3-byte U+FFFD, so measuring the tail AFTER decoding truncates
  // 2 bytes INTO record 2 and silently drops an fsynced approval.
  fs.writeFileSync(file, Buffer.concat([valid, Buffer.from([0xff])]));
  // The journal is only trusted when it is owner-only; the handcrafted file
  // above was written with the default umask (0644).
  fs.chmodSync(file, 0o600);

  const reopened = new Ledger({ file });
  assert.deepEqual(reopened.snapshot(), { records: 2, seq: 2, fingerprints: 2 },
    'both durable records must survive the repair of an invalid tail');
  assert.equal(fs.readFileSync(file).length, valid.length,
    'the repair must truncate exactly the torn byte, never into the last record');
  assert.ok(fs.readFileSync(file, 'utf8').includes(r2.trim()),
    'record 2 must still be present after repair');

  // The dropped tail was never approved, so the ledger keeps appending cleanly.
  const ledger = reopened;
  const wire = legacy(transfer(recipient, 40));
  const verdict = gate(wire, { ...grant, windowMaxLamports: '100000' },
    new Date(now.getTime() + 1000), ledger);
  assert.equal(verdict.allowed, true, `expected an approval, got ${verdict.refused}`);
  assert.equal(verdict.seq, 3);
  const reloaded = new Ledger({ file });
  assert.deepEqual(reloaded.snapshot(), { records: 3, seq: 3, fingerprints: 3 });
});

test('review #6: a same-size in-place tamper is refused, not only an appended one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sz-'));
  const file = path.join(dir, 'journal.jsonl');
  const ledger = new Ledger({ file });
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);

  const before = fs.readFileSync(file, 'utf8');
  // Change the recorded SPEND in place, keeping the byte length identical:
  // the reviewed code only compared statSync().size, so this passed silently
  // and the tampered figure was then trusted on reload.
  const after = before.replace('"a":"42"', '"a":"12"');
  assert.notEqual(after, before, 'the tamper must be same-length to be meaningful');
  assert.equal(after.length, before.length, 'precondition: byte length unchanged');
  fs.writeFileSync(file, after);

  const verdict = gate(legacy(transfer(recipient, 41)), grant, now, ledger);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.refused, 'ledger_changed',
    'a content change with an identical size must still be detected');
  assert.equal(fs.readFileSync(file, 'utf8'), after, 'the journal is left untouched for an operator');

  // And the tampered file must not be trusted as a fresh baseline either:
  // the per-record hash chain no longer matches, so loading fails closed
  // instead of handing the forged spend to a new process.
  assert.throws(() => new Ledger({ file }), /ledger_tampered/);
});
