'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { evaluate } = require('../src/policy');
const { Ledger, gate, BASE_FEE_LAMPORTS } = require('../src/ledger');

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

test('a corrupt complete line makes the ledger refuse to load', () => {
  const ledger = tmpLedger();
  assert.equal(gate(legacy(transfer()), grant, now, ledger).allowed, true);
  fs.appendFileSync(ledger.file, 'not json\n');
  assert.throws(() => new Ledger({ file: ledger.file }), /ledger_corrupt/);
  // A valid-looking line with a wrong sequence also fails closed.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-ledger-'));
  const file = path.join(dir, 'journal.jsonl');
  fs.writeFileSync(file, JSON.stringify({ s: 5, t: 1, w: 'a'.repeat(64), a: '1', f: '5000' }) + '\n');
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
