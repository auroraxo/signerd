// Controls for the envelope-traffic classifier's two measured defects
// (2026-11-02). The README traffic table was produced by this classifier,
// and both defects moved its headline number:
//
//   D1  decodeBase58 counted TRAILING '1' characters instead of LEADING ones
//       and started from bytes=[0], so any base58 string ending in '1'
//       gained a spurious 0x00 prefix and true leading-zero payloads lost
//       their zero byte. Real System-transfer payloads whose base58 ends in
//       '1' (about 1 in 58 of them) were mis-sized to len 13/14 and pushed
//       out of v0_fit into legacy_other - the share was UNDERCOUNTED.
//       Measured on live slots: 11 of 192 product-approved transfers were
//       hidden by exactly this defect (research/policy-traffic-2026-11-02).
//
//   D2  classify() is version-blind: a version-1 message (transactionConfig
//       in the json view, signatures at the END of the wire) has
//       message.version undefined, passes the legacy check, and is scored
//       against the v0 envelope - so v1 wire that the daemon cannot even
//       parse was counted as v0_fit (2 live cases), while the rest of v1
//       traffic (36-44% of blocks on 2026-11-02) folded silently into
//       legacy_other, the bucket documented as "CPI, DEX, compute budget".
//
// Both tests are RED on the pre-fix tree by construction: they pin concrete
// byte truth against the bs58 oracle and against the product's own refusal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const bs58 = require('bs58');
const { classify, decodeBase58 } = await import(
  new URL('../tools/envelope-traffic.mjs', import.meta.url)
);

test('D1: decodeBase58 matches the bs58 oracle on strings ending in 1', () => {
  // Pinned live case: a real approved System-transfer payload whose base58
  // ends in '1'. True bytes are 12 (tag 2 + u64 amount); the defective
  // decoder returned 13 bytes with a spurious leading 0x00.
  const s = '3Bxs4VZ8Jo4jEgP1';
  const oracle = Buffer.from(bs58.decode(s));
  assert.equal(oracle.length, 12);
  assert.equal(oracle.readUInt32LE(0), 2, 'the pinned case must be a System transfer');
  const got = Buffer.from(decodeBase58(s));
  assert.ok(got.equals(oracle), `decodeBase58("${s}") = ${got.toString('hex')}, oracle ${oracle.toString('hex')}`);
  // Leading '1' characters are leading zero BYTES (compare against the bs58
  // oracle, never hand-typed alphabet values): "112" -> [0, 0, 1].
  assert.deepEqual(Buffer.from(decodeBase58('112')), Buffer.from(bs58.decode('112')));
  assert.deepEqual(Buffer.from(decodeBase58('112')), Buffer.from([0, 0, 1]));
  assert.deepEqual(Buffer.from(decodeBase58('2')), Buffer.from(bs58.decode('2')));
});

test('D1: decodeBase58 equals the oracle over 200 random payloads', () => {
  let checked = 0;
  for (let i = 0; i < 200; i++) {
    const len = 1 + Math.floor(Math.random() * 20);
    const bytes = Buffer.alloc(len);
    require('node:crypto').randomFillSync(bytes);
    const s = bs58.encode(bytes);
    const got = Buffer.from(decodeBase58(s));
    if (!got.equals(bytes)) {
      assert.fail(`decodeBase58 roundtrip failed for ${s}: got ${got.toString('hex')}, want ${bytes.toString('hex')}`);
    }
    checked++;
  }
  assert.ok(checked === 200);
});

test('D2: a version-1 message is never scored as v0_fit', () => {
  const tx = {
    signatures: ['y'.repeat(87)],
    message: {
      accountKeys: ['A'.repeat(43), 'S'.repeat(43), '11111111111111111111111111111111'],
      header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1 },
      instructions: [{ programIdIndex: 2, accounts: [0, 1], data: '3Bxs4VZ8Jo4jEgP1' }],
      recentBlockhash: 'B'.repeat(43),
      // The json view's only version marker for v1: the transactionConfig
      // block. message.version is undefined, exactly as mainnet serves it.
      transactionConfig: { computeUnitLimit: 150000, priorityFee: 5000 },
    },
  };
  const got = classify(tx);
  assert.notEqual(got.bucket, 'v0_fit',
    `version-1 wire must never be counted as envelope-fit (got ${JSON.stringify(got)})`);
  assert.equal(got.bucket, 'v1', `expected the named v1 bucket, got ${JSON.stringify(got)}`);
});

//
// D3 (measured 2026-11-02, same reconciliation): a v0 transaction WITHOUT
// ALTs carries its version on the getBlock ENTRY, which main() unwraps away
// before classify() sees it - so the versioned wire was scored v0_fit (7 of
// 201 candidates on the probe window; the product refuses them all as
// version_or_alt). classify() must honour a version passed on the tx itself.
test('D3: a v0 entry whose wrapper version was dropped is never v0_fit', () => {
  // Exactly the control fixture's legacy shape, but with the getBlock
  // wrapper's version field preserved onto the tx: versioned wire must not
  // fall through to v0_fit.
  const bare = {
    version: 0,
    signatures: ['y'.repeat(87)],
    message: {
      accountKeys: ['A'.repeat(43), 'S'.repeat(43), '11111111111111111111111111111111'],
      header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1 },
      instructions: [{ programIdIndex: 2, accounts: [0, 1], data: '3Bxs47t7W4Tyww5H' }],
      recentBlockhash: 'B'.repeat(43),
    },
  };
  assert.notEqual(classify(bare).bucket, 'v0_fit',
    'version 0 wire must not be scored v0_fit');
  assert.equal(classify(bare).bucket, 'vtx');
});

test('control: the legacy v0_fit fixture still classifies as v0_fit', () => {
  // False-positive guard: the D2 guard must not swallow genuine legacy
  // transactions (no transactionConfig in their json view). Payload chosen
  // WITHOUT a trailing '1' so it is decodable by both the fixed and the
  // defective decoder - the control pins the classification rule only.
  const tx = {
    signatures: ['y'.repeat(87)],
    message: {
      accountKeys: ['A'.repeat(43), 'S'.repeat(43), '11111111111111111111111111111111'],
      header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1 },
      instructions: [{ programIdIndex: 2, accounts: [0, 1], data: '3Bxs47t7W4Tyww5H' }],
      recentBlockhash: 'B'.repeat(43),
    },
  };
  const got = classify(tx);
  assert.equal(got.bucket, 'v0_fit', `legacy fit must stay v0_fit, got ${JSON.stringify(got)}`);
});
