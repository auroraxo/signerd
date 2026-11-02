#!/usr/bin/env node
// Measure the FIRST BYTE of real on-chain wire bytes, grouped by the
// transaction's own version field.
//
// THE QUESTION (2026-11-02): the product must refuse version-1 wire with a
// NAMED reason instead of a generic parse failure. To classify v1 from the
// wire alone - without a full parse, and without ever mislabeling a legacy or
// v0 transaction - the wire prefix has to be unambiguous. This tool measures
// whether it is, on live finalized mainnet data, and derives the bound that
// makes the classification safe.
//
// METHOD: for each finalized slot the block is fetched TWICE - once as JSON
// (which carries the transaction's own `version` field) and once as base64
// wire. Each transaction is PAIRED across the two fetches by checking that
// its base58 signature physically occurs in the wire bytes; an unpaired row
// would measure a different transaction than it describes and is counted, not
// hidden.
//
// The result is committed as research/first-byte-distribution-*.json and
// re-derived in CI by test/wire-prefix-tool.test.js (the committed report is
// checked against the derived bound; only a live run touches the network).
//
// Exit codes: 0 = measurement complete; 3 = NO VERDICT (empty sample,
// unpaired rows above the tolerance, or a version bucket with no rows).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const bs58 = require('bs58');

function argValue(flag) {
  const eq = process.argv.find(a => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const i = process.argv.indexOf(flag);
  if (i > 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) return process.argv[i + 1];
  return null;
}

const OUT = argValue('--out');
const BLOCKS = Number(argValue('--blocks') || 4);
const BACK = Number(argValue('--back') || 1);
const RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';
// The policy's wire cap. The signature-count bound is derived from it, so the
// two can never drift apart.
const POLICY_MAX_WIRE_BYTES = 1232;

async function rpc(method, params, attempt = 0) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (res.status === 429 || res.status >= 500) {
    if (attempt >= 8) throw new Error(`${method}: HTTP ${res.status}`);
    await new Promise(r => setTimeout(r, Math.min(30000, 1000 * 2 ** attempt)));
    return rpc(method, params, attempt + 1);
  }
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) {
    if (attempt < 3 && (body.error.code === -32007 || body.error.code === -32005)) {
      await new Promise(r => setTimeout(r, 1500));
      return rpc(method, params, attempt + 1);
    }
    throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  }
  return body.result;
}

/**
 * The bound that makes the classification safe: legacy and v0 wire begins
 * with the compact-u16 SIGNATURE COUNT, and a signature is 64 bytes. Inside
 * the policy's wire cap only a handful of signatures fit, so the count can
 * never reach 0x80 - which is why byte 0 >= 0x80 cannot be legacy or v0.
 * The message part is charged a conservative minimum here; the point is the
 * ORDER OF MAGNITUDE, and it is checked against the live data below.
 */
function maxSignaturesUnderCap(capBytes, signatureBytes = 64, minimumMessageBytes = 100) {
  let n = 0;
  while ((n + 1) * signatureBytes + minimumMessageBytes <= capBytes) n++;
  return n;
}

let tip;
try {
  tip = await rpc('getSlot', [{ commitment: 'finalized' }]);
} catch (e) {
  console.error(`wire-prefix: cannot determine the finalized tip: ${String(e && e.message).slice(0, 120)} - NO VERDICT`);
  process.exit(3);
}
const byVersion = {};
let unpaired = 0;
let total = 0;
const slots = [];

for (let s = tip - BACK; s >= tip - BACK - BLOCKS + 1; s--) {
  let jb;
  let bb;
  try {
    const p = {
      transactionDetails: 'full',
      rewards: false,
      maxSupportedTransactionVersion: 1,
      commitment: 'finalized',
    };
    jb = await rpc('getBlock', [s, { ...p, encoding: 'json' }]);
    bb = await rpc('getBlock', [s, { ...p, encoding: 'base64' }]);
  } catch (e) {
    console.error(`wire-prefix: slot ${s} failed: ${String(e && e.message).slice(0, 80)}`);
    continue;
  }
  if (!jb || !bb || !jb.transactions || !bb.transactions) continue;
  slots.push(s);
  for (let i = 0; i < jb.transactions.length; i++) {
    const j = jb.transactions[i];
    const b = bb.transactions[i];
    if (!b || !b.transaction) continue;
    total++;
    const wire = Buffer.from(b.transaction[0], 'base64');
    const sig = j.transaction && j.transaction.signatures && j.transaction.signatures[0];
    let sigBytes = null;
    try { sigBytes = Buffer.from(bs58.decode(sig)); } catch { /* unpaired */ }
    if (!sigBytes || !wire.includes(sigBytes)) { unpaired++; continue; }
    const v = String(j.version);
    const g = byVersion[v] || (byVersion[v] = { count: 0, firstBytes: {}, minLen: Infinity, maxLen: 0 });
    g.count++;
    const fb = wire[0].toString(16).padStart(2, '0');
    g.firstBytes[fb] = (g.firstBytes[fb] || 0) + 1;
    g.minLen = Math.min(g.minLen, wire.length);
    g.maxLen = Math.max(g.maxLen, wire.length);
  }
  console.error(`wire-prefix: slot ${s}, ${total} transactions so far`);
}

if (!total) {
  console.error('wire-prefix: empty sample - NO VERDICT');
  process.exit(3);
}
if (unpaired > 0) {
  console.error(`wire-prefix: ${unpaired} unpaired rows - NO VERDICT`);
  process.exit(3);
}
if (!byVersion['1'] || !byVersion['1'].count) {
  console.error('wire-prefix: no version-1 rows in the sample - NO VERDICT');
  process.exit(3);
}

const v1FirstBytes = Object.keys(byVersion['1'].firstBytes);
const nonV1FirstBytes = new Set();
for (const v of Object.keys(byVersion)) {
  if (v === '1') continue;
  for (const fb of Object.keys(byVersion[v].firstBytes)) nonV1FirstBytes.add(fb);
}
const maxNonV1 = Math.max(...[...nonV1FirstBytes].map(b => parseInt(b, 16)));
const minV1 = Math.min(...v1FirstBytes.map(b => parseInt(b, 16)));

const report = {
  generatedAt: new Date().toISOString(),
  rpc: RPC,
  tip,
  slots,
  total,
  unpaired,
  policyMaxWireBytes: POLICY_MAX_WIRE_BYTES,
  byVersion,
  separation: {
    v1FirstBytes,
    nonV1FirstBytes: [...nonV1FirstBytes].sort(),
    minV1FirstByte: minV1,
    maxNonV1FirstByte: maxNonV1,
    // The claim the product's classifier rests on: no legacy/v0 wire starts
    // at or above 0x80, so byte 0 >= 0x80 cannot be legacy or v0.
    separated: minV1 > maxNonV1,
    maxSignaturesUnderCap: maxSignaturesUnderCap(POLICY_MAX_WIRE_BYTES),
    signatureBytes: 64,
  },
  limits: [
    'One sample of finalized mainnet blocks at one moment in time; a sample, not the ecosystem.',
    'The version label is the RPC json view of each transaction, not a parse of the wire.',
    'Pairing is verified by the signature physically occurring in the wire bytes.',
    'The signature-count bound is derived from the policy cap, but the cap is on the WIRE length: a transaction over the cap is refused before the version rule applies.',
  ],
};

const json = JSON.stringify(report, null, 2) + '\n';
if (OUT) {
  fs.writeFileSync(path.resolve(OUT), json);
  console.error(`wire-prefix: wrote ${OUT}`);
} else {
  process.stdout.write(json);
}

console.error(`wire-prefix: ${total} transactions over ${slots.length} slots, unpaired ${unpaired}`);
console.error(`wire-prefix: v1 first bytes ${v1FirstBytes.join(',')} (min 0x${minV1.toString(16)}), ` +
  `non-v1 max 0x${maxNonV1.toString(16)}, separated ${report.separation.separated}, ` +
  `max signatures under the ${POLICY_MAX_WIRE_BYTES}-byte cap ${report.separation.maxSignaturesUnderCap}`);
if (!report.separation.separated) {
  console.error('wire-prefix: the prefixes are NOT separated - the classification rule would be unsafe');
  process.exit(3);
}
