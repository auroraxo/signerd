'use strict';

// Review #3 regressions (R3-2): the format 1 -> current journal migration.
//   R3-2  a format-1 journal used to load with NO message identity, so a
//         message approved before the upgrade was approved again with a
//         different client-chosen signature slot. It must now fail closed
//         and migrate only explicitly.
// Fixtures are GENUINE format-1 bytes written by the legacy checkout 90ac545.

process.umask(0o077);
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Ledger } = require('../src/ledger');
const { migrateJournal } = require('../src/migrate');

const FIX = path.join(__dirname, 'fixtures');
const wire1 = fs.readFileSync(path.join(FIX, 'format1-wire1.bin'));
const wire2 = fs.readFileSync(path.join(FIX, 'format1-wire2.bin'));
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-mig-'));
  const file = path.join(dir, 'ledger.jsonl');
  fs.copyFileSync(path.join(FIX, 'format1-ledger.jsonl'), file);
  fs.chmodSync(file, 0o600);
  const wires = path.join(dir, 'wires');
  fs.mkdirSync(wires);
  return { dir, file, wires };
}
function withSlot(wire, byte) {
  const out = Buffer.from(wire);
  out.fill(byte, 1, 65);
  return out;
}
const scope = JSON.parse(fs.readFileSync(path.join(FIX, 'format1-ledger.jsonl'), 'utf8').split('\n')[0]).k;
const [signer, destination] = scope.split('\u0000');
const grant = {
  signer, destination, maxLamports: '1000', windowMaxLamports: '100000',
  windowSeconds: '31536000', expiresAt: '2999-01-01T00:00:00Z',
};
const approve = (ledger, wire, amount = '1') =>
  ledger.approve({ wire, amountLamports: amount, grant, now: new Date() });

test('R3-2: a format-1 journal is refused at load, not silently loaded without message identity', () => {
  const { file } = setup();
  assert.throws(() => new Ledger({ file }), /ledger_legacy_format/);
});

test('R3-2: migration with the original wires restores message-level replay across the upgrade', () => {
  const { file, wires } = setup();
  fs.writeFileSync(path.join(wires, 'a.bin'), wire1);
  fs.writeFileSync(path.join(wires, 'b.bin'), wire2);
  const result = migrateJournal({ file, wiresDir: wires });
  assert.equal(result.migrated, true);
  assert.equal(result.legacyRecords, 2);
  assert.ok(fs.existsSync(`${file}.pre-migrate.bak`));

  const ledger = new Ledger({ file });
  assert.equal(ledger.snapshot().records, 2);
  assert.equal(ledger.legacyState().unknownMessageRecords, 0);
  // THE exploit from the measurement: same message, different signature slot.
  assert.equal(approve(ledger, withSlot(wire1, 0xaa)).refused, 'replay');
  assert.equal(approve(ledger, withSlot(wire2, 0xbb)).refused, 'replay');
  assert.equal(approve(ledger, wire1).refused, 'replay');
  // Reload keeps it.
  assert.equal(approve(new Ledger({ file }), withSlot(wire1, 0xcc)).refused, 'replay');
});

test('R3-2: the migration refuses and writes nothing when a legacy wire is missing or no mode is chosen', () => {
  const { file, wires } = setup();
  const before = fs.readFileSync(file);
  fs.writeFileSync(path.join(wires, 'a.bin'), wire1);
  assert.throws(() => migrateJournal({ file, wiresDir: wires }), /legacy_wire_missing/);
  assert.throws(() => migrateJournal({ file }), /legacy_wire_required/);
  assert.ok(fs.readFileSync(file).equals(before), 'journal must be untouched');
  assert.equal(fs.existsSync(`${file}.pre-migrate.bak`), false);
});

test('R3-2: --discard-legacy keeps window spend but reports the accepted message-identity gap', () => {
  const { file } = setup();
  const result = migrateJournal({ file, discardLegacy: true });
  assert.equal(result.unknownMessageRecords, 2);
  const ledger = new Ledger({ file });
  assert.equal(ledger.legacyState().unknownMessageRecords, 2);
  // Spend still counts: legacy rows are inside the window, so a cap below
  // their total is hit.
  const tight = { ...grant, windowMaxLamports: '1' };
  const verdict = ledger.approve({ wire: withSlot(wire1, 0xdd), amountLamports: '1', grant: tight, now: new Date() });
  assert.equal(verdict.refused, 'window_cap');
  // Documented residual gap the operator explicitly accepted: message identity is unknown.
  assert.equal(approve(ledger, withSlot(wire1, 0xdd)).allowed, true);
});

test('R3-2: migration is idempotent and a daemon lock blocks it', () => {
  const { file, wires } = setup();
  fs.writeFileSync(path.join(wires, 'a.bin'), wire1);
  fs.writeFileSync(path.join(wires, 'b.bin'), wire2);
  fs.writeFileSync(`${file}.lock`, '{}');
  assert.throws(() => migrateJournal({ file, wiresDir: wires }), /ledger_locked/);
  fs.unlinkSync(`${file}.lock`);
  assert.equal(migrateJournal({ file, wiresDir: wires }).migrated, true);
  assert.equal(migrateJournal({ file, wiresDir: wires }).migrated, false);
  assert.equal(sha(fs.readFileSync(path.join(FIX, 'format1-wire1.bin'))), sha(wire1));
});
