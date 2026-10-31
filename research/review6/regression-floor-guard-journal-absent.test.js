'use strict';
// REGRESSION TEST (review #6, finding 2)
//
// Defect: the no-passphrase downgrade guard (#refuseIfSealFloorExists) is only
// consulted on the SUCCESS path of Ledger#load(), i.e. only when the journal
// file EXISTS. A journal file that has been DELETED while its seal floor
// (<journal>.anchor) still claims history makes an UNSEALED daemon start
// fresh with an empty replay set - the exact "looked like a first start"
// downgrade the guard exists to prevent - and the same message is then signed
// a second time (double-sign).
//
// Controls that already hold on c1b1c09 and are asserted here too:
//   * sealed daemon + journal deleted + anchor present -> ledger_mac_short
//   * unsealed daemon + journal empty (not deleted) + anchor -> ledger_sealed
//
// Expected: an unsealed daemon must refuse when a seal floor exists, whether
// the journal is empty, truncated, or ABSENT.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { Ledger, SEALED_JOURNAL_FORMAT, chainHash, GENESIS_HASH } = require('../../src/ledger');
const seal = require('../../src/journalseal');

const PASS = 'journal seal passphrase reg2';

function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r6-reg2-'));
  fs.chmodSync(d, 0o700);
  return d;
}

/** One genuine sealed record + matching floor. */
function buildSealed(file) {
  const key = seal.deriveJournalKey(PASS);
  const body = {
    v: SEALED_JOURNAL_FORMAT, s: 1, t: 1700000000001,
    w: 'a'.repeat(64), m: 'b'.repeat(64), a: '42', f: '5000', k: 'scope',
  };
  const rec = { ...body, h: chainHash(GENESIS_HASH, body) };
  rec.x = seal.chainMac(key, seal.genesisMac(key), rec.h);
  fs.writeFileSync(file, JSON.stringify(rec) + '\n');
  fs.chmodSync(file, 0o600);
  seal.writeAnchor(`${file}.anchor`, seal.sealAnchor(key, { count: 1, head: rec.x }));
  fs.chmodSync(`${file}.anchor`, 0o600);
  return rec;
}

test('CONTROL (holds on c1b1c09): sealed daemon refuses a deleted journal whose floor claims history', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'j.jsonl');
    buildSealed(j);
    fs.unlinkSync(j);
    assert.throws(
      () => new Ledger({ file: j, sealPassphrase: PASS }),
      (err) => {
        assert.equal(err.code, 'ledger_mac_short',
          `expected ledger_mac_short, got: ${err.code || err.message}`);
        return true;
      },
      'sealed daemon must refuse a deleted journal whose floor claims history',
    );
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('CONTROL (holds on c1b1c09): unsealed daemon refuses an EMPTY journal whose floor exists', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'j.jsonl');
    buildSealed(j);
    fs.writeFileSync(j, ''); fs.chmodSync(j, 0o600);
    assert.throws(
      () => new Ledger({ file: j }),
      (err) => {
        assert.equal(err.code, 'ledger_sealed',
          `expected ledger_sealed, got: ${err.code || err.message}`);
        return true;
      },
      'unsealed daemon must refuse an empty journal whose floor exists',
    );
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('DEFECT: unsealed daemon must refuse a DELETED journal whose floor exists', () => {
  const dir = tmpDir();
  try {
    const j = path.join(dir, 'j.jsonl');
    buildSealed(j);
    fs.unlinkSync(j); // the journal is gone; the seal floor still claims 1 record
    assert.ok(fs.existsSync(`${j}.anchor`), 'fixture: the floor must survive');

    // c1b1c09: no throw - the daemon starts fresh (fail-open downgrade).
    assert.throws(
      () => new Ledger({ file: j }),
      (err) => {
        assert.ok(['ledger_sealed', 'ledger_mac_short', 'ledger_anchor_missing'].includes(err.code),
          `refusal must be a seal-related code, got: ${err.code || err.message}`);
        return true;
      },
      'an unsealed daemon must refuse when a seal floor exists, journal absent',
    );
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
