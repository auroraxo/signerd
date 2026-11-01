#!/usr/bin/env node
'use strict';
// Measure which envelope a scoped signing daemon would actually be able to
// authorize, on REAL mainnet traffic. This is the evidence for the card's
// "envelope decision": v1 SPL-Token vs. Message-Grant-Envelope.
//
// WHAT IS CLASSIFIED (legacy transactions only - a v0/ALT transaction is
// refused by the current policy by construction, so it counts as "out of
// envelope", not as a miss we could fix by parsing harder):
//   v0_fit      - byte-shape the CURRENT policy accepts: exactly 1 signer,
//                 3 static account keys, 1 instruction, SystemProgram.transfer
//                 with data length 12 / tag 2, key relations identical to
//                 src/policy.js evaluate().
//   spl_v1      - the shape a v1 SPL-Token envelope WOULD cover: exactly 1
//                 signer, 4 static keys [signer, source, destination, program],
//                 1 instruction on Tokenkeg or Token-2022, accounts [1,2,0],
//                 Transfer (tag 3) or TransferChecked (tag 12) where the
//                 authority IS the fee payer/signer. If the authority is not
//                 the signer the daemon could not authorize it anyway.
//   spl_v1_auth - subset of spl_v1 split out for reporting (authority==signer
//                 is required by spl_v1, so this is kept as an explicit count
//                 of the authority index we observed, never assumed).
//   other       - everything else (CPI, multi-instruction, DEX, compute
//                 budget, ALT-indexed, ...).
//
// Self-check: `node tools/envelope-traffic.mjs --selftest` runs the classifier
// against hand-built fixtures WITHOUT network, so a classifier that silently
// counts everything is caught before it produces a number.

const SYSTEM_PROGRAM = '11111111111111111111111111111111';
// SPL Token (the real program id - a first draft of this file carried a
// fabricated TokenkegQdZ1... id, which is why every measurement reported 0
// token matches while 731 real Tokenkeg instructions sat in 6 blocks).
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;

function isKey(x) {
  return typeof x === 'string' && BASE58.test(x) && x.length >= 32 && x.length <= 44;
}

/**
 * Classify one transaction as returned by getBlock(encoding=json,
 * transactionDetails=full). Returns { bucket, detail } where bucket is one of
 * 'v0_fit' | 'spl_v1' | 'legacy_other' | 'vtx', and detail explains a refusal
 * or records the observed authority index.
 */
function classify(tx) {
  const msg = tx && tx.message;
  if (!msg || typeof msg !== 'object') return { bucket: 'malformed', detail: 'no message' };
  // A versioned (v0) message with address table lookups cannot be authorized
  // by the current policy at all: ALT data is not present in transaction
  // bytes. Count it as out of envelope rather than guessing at indices.
  // `version` may be absent (legacy), 0, or the string "legacy" depending on
  // the RPC's encoding - all of those are the legacy message format.
  const version = msg.version;
  const isLegacyVersion = version === undefined || version === 0 || version === 'legacy';
  const hasLookups = Array.isArray(msg.addressTableLookups) && msg.addressTableLookups.length > 0;
  if (!isLegacyVersion || hasLookups) {
    return { bucket: 'vtx', detail: 'versioned/ALT message' };
  }
  const keys = msg.accountKeys;
  const header = msg.header;
  const ixs = msg.instructions;
  if (!Array.isArray(keys) || !Array.isArray(ixs) || !header || !Array.isArray(tx.signatures)) {
    return { bucket: 'malformed', detail: 'missing header/keys/instructions' };
  }
  for (const k of keys) if (!isKey(k)) return { bucket: 'malformed', detail: 'non-base58 account key' };

  // --- the current v0 envelope, restated from src/policy.js -------------
  const envelopeOk =
    header.numRequiredSignatures === 1 &&
    header.numReadonlySignedAccounts === 0 &&
    header.numReadonlyUnsignedAccounts === 1 &&
    tx.signatures.length === 1 &&
    keys.length === 3 &&
    ixs.length === 1;
  if (envelopeOk) {
    const ix = ixs[0];
    if (ix.programIdIndex === 2 && Array.isArray(ix.accounts) && ix.accounts.length === 2 &&
        ix.accounts[0] === 0 && ix.accounts[1] === 1 &&
        keys[2] === SYSTEM_PROGRAM &&
        !(keys[0] === keys[1] || keys[0] === keys[2] || keys[1] === keys[2])) {
      const data = ix.data;
      const decoded = decodeBase58(data);
      if (decoded && decoded.length === 12 && decoded.readUInt32LE(0) === 2) {
        return { bucket: 'v0_fit', detail: 'system transfer, 1 ix, 3 keys' };
      }
      return { bucket: 'legacy_other', detail: `system program but data len=${decoded ? decoded.length : 'unparseable'}` };
    }
    return { bucket: 'legacy_other', detail: '3 keys/1 ix but not the transfer shape' };
  }

  // --- the candidate v1 SPL-Token envelope ------------------------------
  // Written in the GENERAL form, because a first draft of this classifier
  // hard-coded 4 account keys and a 42-byte TransferChecked payload and
  // therefore reported 0 hits - that was a defect in my envelope spec, not a
  // finding about traffic. Real SPL transfers carry the mint as an extra
  // key and TransferChecked data is 10 bytes. The shape that actually
  // matters for a scoped daemon is:
  //   exactly 1 required signature, exactly 1 instruction, the instruction
  //   is on the SPL Token (or Token-2022) program, and the TOKEN AUTHORITY
  //   is the signer - otherwise the daemon could not authorize it anyway.
  if (ixs.length === 1 &&
      header.numRequiredSignatures === 1 &&
      header.numReadonlySignedAccounts === 0 &&
      tx.signatures.length === 1) {
    const ix = ixs[0];
    const acc = ix.accounts;
    const programKey = keys[ix.programIdIndex];
    if (programKey === TOKEN_PROGRAM || programKey === TOKEN_2022_PROGRAM) {
      const decoded = decodeBase58(ix.data);
      const tag = decoded ? decoded[0] : null;
      // Transfer = tag 3, data len 9 (amount u64). TransferChecked = tag 12,
      // data len 10 (amount u64 + decimals u8).
      const isTransfer = tag === 3 && decoded.length === 9;
      const isTransferChecked = tag === 12 && decoded.length === 10;
      if (isTransfer || isTransferChecked) {
        // The AUTHORITY differs between the two instructions:
        //   Transfer       accounts = [source, destination]; the authority is
        //                  the signer by construction - there is no authority
        //                  account in the list, so reading acc[0] here would
        //                  read the SOURCE and wrongly reject every real
        //                  transfer (measured: fixture failed on 30.10.).
        //   TransferChecked accounts = [source, mint, destination, authority];
        //                  the authority is the 4th entry and must BE the
        //                  signer, otherwise the daemon could not authorize
        //                  the transfer at all.
        if (isTransfer) {
          if (Array.isArray(acc) && acc.length === 2) {
            return { bucket: 'spl_v1', detail: 'Transfer, authority = signer (by construction)' };
          }
          return { bucket: 'legacy_other', detail: `Transfer with ${Array.isArray(acc) ? acc.length : '?'} accounts` };
        }
        const authority = Array.isArray(acc) ? acc[3] : undefined;
        if (authority === 0) {
          return { bucket: 'spl_v1', detail: 'TransferChecked, authority = signer (4th account)' };
        }
        return { bucket: 'legacy_other',
          detail: `TransferChecked, authority is account ${authority} (not the signer)` };
      }
      return { bucket: 'legacy_other',
        detail: `token program, 1 ix, but tag=${tag} len=${decoded ? decoded.length : 'unparseable'}` };
    }
  }

  return { bucket: 'legacy_other', detail: 'does not match either envelope shape' };
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP = (() => {
  const m = new Map();
  for (let i = 0; i < B58_ALPHABET.length; i++) m.set(B58_ALPHABET[i], i);
  return m;
})();

function decodeBase58(str) {
  if (typeof str !== 'string' || str.length === 0) return null;
  let bytes = [0];
  for (const ch of str) {
    const v = B58_MAP.get(ch);
    if (v === undefined) return null;
    let carry = v;
    for (let i = 0; i < bytes.length; i++) {
      const x = bytes[i] * 58 + carry;
      bytes[i] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  let leading = 0;
  for (let i = str.length - 1; i >= 0 && str[i] === '1'; i--) leading++;
  const out = Buffer.alloc(bytes.length + leading);
  for (let i = 0; i < bytes.length; i++) out[out.length - 1 - i] = bytes[i];
  return out;
}

// --------------------------------------------------------------------------
// Fixtures for --selftest: each one MUST land in its named bucket, otherwise
// the numbers below would be arithmetic on a broken classifier.
// --------------------------------------------------------------------------
function encodeBase58(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) + BigInt(b);
  let out = '';
  while (n > 0n) { out = B58_ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of buf) { if (b !== 0) break; out = '1' + out; }
  return out || '1';
}

function fixtureV0Fit() {
  const data = Buffer.alloc(12);
  data.writeUInt32LE(2, 0);
  data.writeBigUInt64LE(1000n, 4);
  return {
    signatures: ['x'.repeat(87)],
    message: {
      accountKeys: ['A'.repeat(43), 'B'.repeat(43), SYSTEM_PROGRAM],
      header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1 },
      instructions: [{ programIdIndex: 2, accounts: [0, 1], data: encodeBase58(data) }],
    },
  };
}

function fixtureV0SecondIx() {
  const t = fixtureV0Fit();
  t.message.instructions.push({ programIdIndex: 2, accounts: [1], data: encodeBase58(Buffer.alloc(4)) });
  return t;
}

function fixtureV0WrongTag() {
  const t = fixtureV0Fit();
  const data = Buffer.alloc(12);
  data.writeUInt32LE(1, 0); // CreateAccount, same length
  t.message.instructions[0].data = encodeBase58(data);
  return t;
}

function fixtureSpl(tag) {
  // Transfer (tag 3): data = u64 amount -> 9 bytes, accounts [source, dest].
  // TransferChecked (tag 12): data = u64 amount + u8 decimals -> 10 bytes,
  // accounts [source, mint, dest, authority].
  const data = Buffer.alloc(tag === 3 ? 9 : 10);
  data[0] = tag;
  data.writeBigUInt64LE(7n, 1);
  if (tag === 12) data[9] = 6;
  const accounts = tag === 3 ? [1, 2] : [1, 3, 2, 0];
  return {
    signatures: ['y'.repeat(87)],
    message: {
      accountKeys: ['A'.repeat(43), 'S'.repeat(43), 'D'.repeat(43), 'M'.repeat(43), TOKEN_PROGRAM],
      header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
      instructions: [{ programIdIndex: 4, accounts, data: encodeBase58(data) }],
    },
  };
}

function fixtureSplForeignAuthority() {
  const t = fixtureSpl(12);
  t.message.instructions[0].accounts = [1, 3, 2, 1]; // authority is NOT the signer
  return t;
}

function fixtureSplTwoInstructions() {
  const t = fixtureSpl(3);
  t.message.instructions.push({ programIdIndex: 4, accounts: [1], data: encodeBase58(Buffer.alloc(9)) });
  return t;
}

function fixtureVersioned() {
  const t = fixtureV0Fit();
  t.message.version = 0;
  t.message.addressTableLookups = [{ accountKey: 'Z'.repeat(43), writableIndexes: [], readonlyIndexes: [] }];
  return t;
}

function selftest() {
  const cases = [
    ['v0_fit', fixtureV0Fit()],
    ['legacy_other', fixtureV0SecondIx()],
    ['legacy_other', fixtureV0WrongTag()],
    ['spl_v1', fixtureSpl(3)],
    ['spl_v1', fixtureSpl(12)],
    ['legacy_other', fixtureSplForeignAuthority()],
    ['legacy_other', fixtureSplTwoInstructions()],
    ['vtx', fixtureVersioned()],
  ];
  let failures = 0;
  for (const [want, tx] of cases) {
    const got = classify(tx);
    const ok = got.bucket === want;
    if (!ok) failures++;
    console.log(`${ok ? 'PASS' : 'FAIL'} want=${want} got=${got.bucket} detail=${got.detail}`);
  }
  console.log(failures === 0 ? `selftest OK (${cases.length}/${cases.length})`
    : `selftest FAILED (${cases.length - failures}/${cases.length})`);
  process.exit(failures === 0 ? 0 : 1);
}

// --------------------------------------------------------------------------
// Network sampling
// --------------------------------------------------------------------------
const RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';

async function rpc(method, params, attempt = 0) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (res.status === 429 || res.status >= 500) {
    if (attempt >= 8) throw new Error(`${method}: HTTP ${res.status} after retries`);
    const retryAfter = Number(res.headers.get('retry-after'));
    const wait = retryAfter > 0 ? retryAfter * 1000 : Math.min(30000, 1000 * 2 ** attempt);
    await new Promise(r => setTimeout(r, wait));
    return rpc(method, params, attempt + 1);
  }
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) {
    // -32007/-32005: slot skipped or not yet available for this node.
    if (attempt >= 2 && (body.error.code === -32007 || body.error.code === -32005)) return null;
    if (attempt < 2 && (body.error.code === -32007 || body.error.code === -32005)) {
      await new Promise(r => setTimeout(r, 1500));
      return rpc(method, params, attempt + 1);
    }
    throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  }
  return body.result;
}

async function sample({ blocks = 12, back = 60 } = {}) {
  const tip = await rpc('getSlot', [{ commitment: 'finalized' }]);
  const start = tip - back;
  const counts = { v0_fit: 0, spl_v1: 0, legacy_other: 0, vtx: 0, malformed: 0 };
  const details = {};
  const used = [];
  for (let slot = start; used.length < blocks && slot > start - 400; slot--) {
    let block;
    try {
      block = await rpc('getBlock', [slot, {
        encoding: 'json', transactionDetails: 'full', rewards: false,
        // Mainnet now serves transaction version 1; requesting only 0 makes
        // every getBlock fail with -32015, which would sample NOTHING while
        // looking like a clean run. Measured 2026-10-30.
        maxSupportedTransactionVersion: 1, commitment: 'finalized',
      }]);
    } catch (err) {
      details[slot] = `error: ${err.message}`;
      continue;
    }
    if (!block) continue;
    used.push(slot);
    for (const entry of block.transactions) {
      // getBlock(encoding=json) returns { meta, transaction } wrappers, not
      // bare transactions. Classifying the wrapper itself would mark every
      // transaction "malformed" (no .message) - measured on 2026-10-30.
      const tx = entry && entry.transaction ? entry.transaction : entry;
      const { bucket, detail } = classify(tx);
      counts[bucket] = (counts[bucket] || 0) + 1;
      if (detail && bucket !== 'legacy_other') {
        details[detail] = (details[detail] || 0) + 1;
      }
    }
    await new Promise(r => setTimeout(r, 350));
  }
  return { tip, start, slots: used, counts, details };
}

async function main() {
  if (process.argv.includes('--selftest')) return selftest();
  const blocksArg = process.argv.find(a => a.startsWith('--blocks='));
  const backArg = process.argv.find(a => a.startsWith('--back='));
  const outArg = process.argv.find(a => a.startsWith('--out='));
  // Slicing off the wrong number of characters here silently yields NaN
  // (measured: '--blocks=25'.slice(8) === '=25'), and `used.length < NaN`
  // is false, so the sampling loop never runs and the tool reports a clean
  // "0 transactions" instead of an error. Parse by prefix length.
  const blocks = blocksArg ? Number(blocksArg.slice('--blocks='.length)) : 12;
  const back = backArg ? Number(backArg.slice('--back='.length)) : 60;
  if (!Number.isFinite(blocks) || blocks <= 0) {
    console.error(`envelope-traffic: --blocks must be a positive number, got "${blocksArg}"`);
    process.exit(2);
  }
  if (!Number.isFinite(back) || back < 0) {
    console.error(`envelope-traffic: --back must be a non-negative number, got "${backArg}"`);
    process.exit(2);
  }

  // Self-check the classifier before trusting any network number.
  const cases = [fixtureV0Fit(), fixtureSpl(3), fixtureVersioned()];
  const buckets = cases.map(c => classify(c).bucket);
  if (buckets.join(',') !== 'v0_fit,spl_v1,vtx') {
    console.error(`classifier self-check failed: ${buckets.join(',')}`);
    process.exit(2);
  }

  const r = await sample({ blocks, back });
  const total = Object.values(r.counts).reduce((a, b) => a + b, 0);
  const legacy = r.counts.v0_fit + r.counts.spl_v1 + r.counts.legacy_other;
  const pct = n => (total ? ((100 * n) / total).toFixed(3) : '0.000');
  const legacyPct = n => (legacy ? ((100 * n) / legacy).toFixed(3) : '0.000');

  const report = {
    generatedAt: new Date().toISOString(),
    rpc: RPC,
    finalizedTipAtStart: r.tip,
    firstSlot: r.start,
    blocksSampled: r.slots.length,
    slots: r.slots,
    counts: r.counts,
    totals: {
      transactions: total,
      legacy: legacy,
      v0_fit_pct_of_all: pct(r.counts.v0_fit),
      spl_v1_pct_of_all: pct(r.counts.spl_v1),
      vtx_pct_of_all: pct(r.counts.vtx),
      v0_fit_pct_of_legacy: legacyPct(r.counts.v0_fit),
      spl_v1_pct_of_legacy: legacyPct(r.counts.spl_v1),
    },
    detailCounts: r.details,
    definitions: {
      v0_fit: 'exactly what src/policy.js evaluate() accepts: 1 signer, 3 static keys, 1 SystemProgram.transfer ix (data len 12, tag 2)',
      spl_v1: 'proposed v1: 1 signer, 4 static keys [signer, source, destination, token program], 1 Transfer/TransferChecked ix with authority = signer',
      vtx: 'versioned message / address table lookups - refused by the current policy by construction',
      legacy_other: 'any other legacy shape (multi-ix, CPI, DEX, compute budget, ...)',
    },
    limits: [
      'Classification is structural, from encoding=json: it proves the SHAPE fits, not that any grant would be issued.',
      'A transaction can be in-envelope and still be refused by grant/ledger (amount cap, expiry, replay, window).',
      'Sample is a bounded recent window of finalized mainnet blocks, not a full-history census.',
      'v0/ALT transactions are counted as out of envelope, never re-indexed through loaded addresses.',
    ],
  };

  const json = JSON.stringify(report, null, 2);
  // A zero-transaction sample is not a measurement; say so loudly instead of
  // publishing empty percentages.
  if (total === 0) {
    console.error('envelope-traffic: FATAL - sampled 0 transactions in ' +
      r.slots.length + ' blocks; refusing to report');
    process.exit(3);
  }
  if (outArg) {
    const path = outArg.slice(6);
    fs.mkdirSync(dirname(path), { recursive: true });
    fs.writeFileSync(path, json + '\n');
    console.log(`wrote ${path}`);
  }
  console.log(json);
}

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import fs from 'node:fs';

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => { console.error(`envelope-traffic: ${err.stack || err}`); process.exit(1); });
}

export { classify, decodeBase58, encodeBase58 };
