// One-off reconciliation: fixed tools/envelope-traffic.mjs classify() vs the
// committed product decisions in research/policy-traffic-2026-11-02-rows.json
// over the SAME six slots (464588085..464588090). Not part of the suite; the
// committed controls live in test/envelope-traffic-classifier.test.mjs.
import fs from 'node:fs';
import { classify } from '../tools/envelope-traffic.mjs';

const rowsDoc = JSON.parse(fs.readFileSync(new URL('../research/policy-traffic-2026-11-02-rows.json', import.meta.url), 'utf8'));
const rows = rowsDoc.rows;
const bySig = new Map(rows.filter(r => r.paired).map(r => [r.signature, r]));

const RPC = 'https://api.mainnet-beta.solana.com';
const slots = [...new Set(rows.map(r => r.slot))].sort((a, b) => a - b);

const cross = new Map();
let fetched = 0;
for (const slot of slots) {
  const body = { jsonrpc: '2.0', id: 1, method: 'getBlock', params: [slot, { encoding: 'json', transactionDetails: 'full', rewards: false, maxSupportedTransactionVersion: 1 }] };
  const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await res.json();
  if (!j.result) { console.error('rpc error slot', slot, JSON.stringify(j.error)); process.exit(2); }
  for (const entry of j.result.transactions) {
    const tx = entry && entry.transaction
      ? { ...entry.transaction, version: entry.version } // mirror fixed main()
      : entry;
    const sig = (tx.signatures && tx.signatures[0]) || '';
    const prod = bySig.get(sig);
    if (!prod) continue;
    fetched++;
    const c = classify(tx);
    const verdict = prod.candidate
      ? (prod.allowed ? 'approved' : `refused:${prod.refused}`)
      : `gate:${prod.reason}`;
    const key = `${c.bucket} | product:${verdict}`;
    cross.set(key, (cross.get(key) || 0) + 1);
  }
}

console.log('reconciled signatures:', fetched, 'of', bySig.size);
for (const [k, n] of [...cross.entries()].sort((a, b) => b[1] - a[1])) console.log(String(n).padStart(5), k);

// headline counts under the fixed classifier on these slots
const counts = {};
for (const r of rows) counts[r.candidate && r.reason === undefined ? 'product_approved' : 'other'] = (counts[r.candidate && r.reason === undefined ? 'product_approved' : 'other'] || 0) + 1;
console.log('product rows:', JSON.stringify(counts));
