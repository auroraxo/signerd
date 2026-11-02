'use strict';

// Version-1 wire must be refused with the NAMED version reason, not with the
// generic parse failure.
//
// WHY (measured 2026-11-02): version 1 is ~44% of live traffic, and the pinned
// @solana/web3.js 1.98.4 cannot deserialize it, so `evaluate()` used to answer
// `invalid_wire` - the same reason a caller gets for three corrupt bytes. A
// caller could not tell "your message format is not implemented" apart from
// "your payload is corrupt", and the answer depended on which library happened
// to be installed (under 3.1.1 the same wire was refused `version_or_alt`).
//
// THE RULE THIS TEST PINS, measured on two independent samples of pairing-
// verified live transactions (4 finalized blocks each, 4,465 total,
// research/first-byte-distribution-2026-11-02.json):
//   * version 1: byte 0 is 0x81 in 2005/2005 transactions;
//   * legacy and v0: byte 0 is the compact-u16 signature count, 0x01..0x05 in
//     2460/2460 - and inside the policy's 1232-byte cap at most 17 signatures
//     fit, so that count can never reach 0x80.
// Therefore byte 0 >= 0x80 inside the cap cannot be legacy or v0 wire: it is
// either a versioned message or corrupt bytes, and both must refuse.
//
// The ladder: this file is RED on the tree before the fix (every under-cap
// version-1 row answers `invalid_wire`) and GREEN after it. The guard cases
// below are GREEN ON BOTH TREES - they are the false-positive guards that keep
// a legacy transfer, a v0 transaction and three corrupt bytes behaving exactly
// as before.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const bs58 = require('bs58');
const { Keypair, SystemProgram, Transaction, TransactionMessage, VersionedTransaction } =
  require('@solana/web3.js');
const { evaluate } = require('../src/policy');

const FIXTURE = path.join(__dirname, 'fixtures', 'v1-wire-2026-11-02.json');
const POLICY_MAX_WIRE_BYTES = 1232;
const NOW = new Date('2026-11-02T12:00:00.000Z');

function grantFor(row) {
  // Best case, exactly like tools/policy-traffic.mjs: for shape-eligible rows
  // the keys come from the transaction's own json view; otherwise constant
  // VALID keys, so the verdict can only be about wire and version handling.
  if (row.json && Array.isArray(row.json.accountKeys) && row.json.accountKeys.length >= 2) {
    return {
      signer: row.json.accountKeys[0],
      destination: row.json.accountKeys[1],
      maxLamports: '18446744073709551615',
      expiresAt: '2099-01-01T00:00:00Z',
    };
  }
  return {
    signer: '11111111111111111111111111111112',
    destination: '11111111111111111111111111111113',
    maxLamports: '18446744073709551615',
    expiresAt: '2099-01-01T00:00:00Z',
  };
}

function fixture() {
  const f = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  assert.ok(Array.isArray(f.rows) && f.rows.length > 0, 'fixture must hold rows');
  return f;
}

function legacyTransfer(lamports = 42, extra) {
  const signer = Keypair.generate();
  const destination = Keypair.generate().publicKey;
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: destination, lamports }));
  if (extra) tx.add(extra);
  tx.sign(signer);
  return { wire: tx.serialize(), signer, destination };
}

test('the committed version-1 fixture is pairing-verified, not assumed', () => {
  const f = fixture();
  for (const row of f.rows) {
    assert.equal(String(row.version), '1', 'the fixture is about version 1');
    const wire = Buffer.from(row.wireBase64, 'base64');
    const sig = Buffer.from(bs58.decode(row.signature));
    assert.ok(wire.includes(sig), `row ${row.slot}/${row.index}: json signature not in wire bytes`);
    assert.equal(wire[0], 0x81, `row ${row.slot}/${row.index}: expected the measured 0x81 prefix`);
  }
});

test('version-1 wire is refused as version_or_alt, never as a parse failure', () => {
  const f = fixture();
  const underCap = f.rows.filter(r => r.wireLen <= POLICY_MAX_WIRE_BYTES);
  assert.ok(underCap.length >= 10, 'fixture must hold enough under-cap rows to matter');
  for (const row of underCap) {
    const wire = Buffer.from(row.wireBase64, 'base64');
    const verdict = evaluate(wire, grantFor(row), NOW);
    assert.deepEqual(
      verdict,
      { allowed: false, refused: 'version_or_alt' },
      `row ${row.slot}/${row.index}: version-1 wire must carry the named version refusal`,
    );
  }
});

test('the verdict no longer depends on which web3.js is installed', () => {
  // Under the pinned 1.98.4 the library cannot even parse this wire, and under
  // 3.1.1 it parses and round-trips it - the reason a caller sees must be the
  // same either way. The check runs before any parsing, so no library can
  // change the answer.
  const f = fixture();
  const row = f.rows.find(r => r.wireLen <= POLICY_MAX_WIRE_BYTES && r.shape);
  assert.ok(row, 'fixture must contain a shape-eligible row');
  const wire = Buffer.from(row.wireBase64, 'base64');
  assert.equal(wire[0], 0x81, 'the classifier decision comes from byte 0');
  assert.deepEqual(evaluate(wire, grantFor(row), NOW), { allowed: false, refused: 'version_or_alt' });
});

test('a corrupt buffer that starts with the version prefix refuses, never allows', () => {
  // The new rule reclassifies SOME corrupt bytes (byte 0 >= 0x80) from
  // invalid_wire to version_or_alt. Both are refusals; this pins that the
  // reclassification can never turn into an approval, and that the lib cannot
  // parse its way to `allowed`.
  const signer = Keypair.generate().publicKey.toBase58();
  const destination = Keypair.generate().publicKey.toBase58();
  const grant = { signer, destination, maxLamports: '1000000000', expiresAt: '2099-01-01T00:00:00Z' };
  const cases = [
    Buffer.from([0x81]),
    Buffer.from([0x81, 0x01, 0x00]),
    Buffer.from([0xff, 0x02, 0x03, 0x04]),
    Buffer.alloc(POLICY_MAX_WIRE_BYTES, 0x81),
  ];
  for (const wire of cases) {
    const verdict = evaluate(wire, grant, NOW);
    assert.equal(verdict.allowed, false, `byte 0 0x${wire[0].toString(16)} must never be allowed`);
    assert.ok(
      verdict.refused === 'version_or_alt' || verdict.refused === 'invalid_wire',
      `unexpected reason ${verdict.refused}`,
    );
  }
  // Over the cap the SIZE rule still wins, whatever byte 0 says: the size
  // check runs first and is the reason a caller gets.
  const over = Buffer.alloc(POLICY_MAX_WIRE_BYTES + 1, 0x81);
  assert.deepEqual(evaluate(over, grant, NOW), { allowed: false, refused: 'invalid_wire' });
});

test('guard: a legacy transfer is still allowed (false-positive guard, green on both trees)', () => {
  const { wire, signer, destination } = legacyTransfer();
  const verdict = evaluate(wire, {
    signer: signer.publicKey.toBase58(),
    destination: destination.toBase58(),
    maxLamports: '42',
    expiresAt: '2099-01-01T00:00:00Z',
  }, NOW);
  assert.deepEqual(verdict, { allowed: true, amountLamports: '42' });
});

test('guard: a v0 transaction still refuses version_or_alt through the parser (green on both trees)', () => {
  const signer = Keypair.generate();
  const destination = Keypair.generate().publicKey;
  const msg = new TransactionMessage({
    payerKey: signer.publicKey,
    recentBlockhash: Keypair.generate().publicKey.toBase58(),
    instructions: [SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: destination, lamports: 42 })],
  });
  const tx = new VersionedTransaction(msg.compileToV0Message());
  tx.sign([signer]);
  const wire = tx.serialize();
  // byte 0 is the signature count for v0, so the new rule must not touch it
  assert.ok(wire[0] < 0x80, 'v0 wire byte 0 must stay a signature count');
  const verdict = evaluate(wire, {
    signer: signer.publicKey.toBase58(),
    destination: destination.toBase58(),
    maxLamports: '42',
    expiresAt: '2099-01-01T00:00:00Z',
  }, NOW);
  assert.deepEqual(verdict, { allowed: false, refused: 'version_or_alt' });
});

test('guard: three corrupt bytes and a JSON body still refuse invalid_wire (green on both trees)', () => {
  const { signer, destination } = legacyTransfer();
  const grant = {
    signer: signer.publicKey.toBase58(),
    destination: destination.toBase58(),
    maxLamports: '42',
    expiresAt: '2099-01-01T00:00:00Z',
  };
  assert.deepEqual(evaluate(Buffer.from([1, 2, 3]), grant, NOW),
    { allowed: false, refused: 'invalid_wire' });
  const body = Buffer.from('{"schema":"openreceipts/v1"}', 'utf8');
  assert.equal(body[0], 0x7b, 'a JSON body starts below the version prefix');
  assert.deepEqual(evaluate(body, grant, NOW), { allowed: false, refused: 'invalid_wire' });
});
