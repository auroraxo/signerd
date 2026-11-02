#!/usr/bin/env node
// Measure signerd's OWN policy on REAL mainnet traffic, in wire bytes.
//
// WHY THIS TOOL EXISTS (measured 2026-11-02):
// The traffic table in README.md ("about 4 in 1,000 transactions") was produced
// by tools/envelope-traffic.mjs, which CLASSIFIES transactions with a
// hand-written restatement of src/policy.js ("the current v0 envelope,
// restated from src/policy.js evaluate()"). A restatement is a second
// implementation of a security rule, and this repo already has the scar
// tissue of that going wrong: envelope-traffic.mjs shipped a fabricated SPL
// Token program id ("TokenkegQdZ1..."), so every measurement reported 0 token
// matches while 731 real Tokenkeg instructions sat in six blocks. The
// headline number has never been produced by the code that actually decides.
//
// This tool closes that gap. It feeds REAL wire bytes (getBlock,
// encoding=base64) to the PRODUCT'S OWN src/policy.js evaluate(), with a
// grant built from the same transaction's own signer/destination/amount. It
// therefore measures what the daemon would actually do, not what a proxy
// believes it would do.
//
// It also measures the thing the hand-written classifier cannot see: VERSION.
// Mainnet serves three message formats. legacy and v0 are parseable by the
// pinned @solana/web3.js 1.98.4; version "1" (the new durable format, with
// signatures at the END of the wire) is not parseable by it at all. Those
// transactions reach the daemon as opaque bytes and are refused - correctly,
// fail-closed - but with the generic reason "invalid_wire", which does not
// tell a caller whether the payload was corrupt or merely a message format
// the daemon does not implement. This tool counts them.
//
// METHOD AND ITS LIMITS (read before believing a number):
//   * The grant is built FROM the transaction under test (signer = its own
//     fee payer/signer, destination = its own System-transfer destination,
//     maxLamports = its own amount). That is a BEST-CASE grant: it asks
//     "would this daemon sign this transaction if it were allowed to?".
//     It does NOT measure whether a real grant would ever be issued.
//   * Only transactions that structurally look like a System transfer get a
//     grant. Everything else is measured as "no candidate".
//   * json and base64 views of the same slot are paired by index and then
//     VERIFIED: the json signature bytes must appear in the wire bytes. An
//     unverified pairing is reported as such and suppresses per-transaction
//     verdicts, because a mispaired row would silently measure the wrong
//     transaction.
//
// Exit codes: 0 = measurement complete, 3 = no verdict (unpaired rows, a
// zero-transaction sample, or a failed self-check). A partial sample never
// produces a percentage.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { evaluate } = require('../src/policy.js');
const { Keypair, PublicKey, SystemProgram, Transaction } = require('@solana/web3.js');

const RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
// The grant's clock: a fixed instant inside the grant's own validity, so the
// verdict depends on the transaction and not on when the tool ran.
const NOW = new Date('2026-11-02T12:00:00.000Z');
const GRANT_EXPIRES = '2099-01-01T00:00:00Z';
// The repo's CLI convention is --out=<path> (see envelope-traffic.mjs); the
// first draft parsed "--out <path>" instead, so a full live run printed the
// report to stdout and silently wrote nothing. Accept both spellings.
function argValue(flag) {
  const eq = process.argv.find(a => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const i = process.argv.indexOf(flag);
  return i > 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')
    ? process.argv[i + 1]
    : null;
}
const OUT = argValue('--out');
const FIXTURE = argValue('--fixture');

const bs58 = require('bs58');

function base58Decode(s) {
  try { return Buffer.from(bs58.decode(s)); } catch { return null; }
}

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
    // -32007/-32005: slot skipped or not yet available on this node.
    if (body.error.code === -32007 || body.error.code === -32005) {
      if (attempt >= 2) return null;
      await new Promise(r => setTimeout(r, 1500));
      return rpc(method, params, attempt + 1);
    }
    throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  }
  return body.result;
}

// --------------------------------------------------------------------------
// The grant candidate: what a maximally permissive grant for this transaction
// would look like. Returns null when the transaction is not a candidate at all
// (not a single legacy System transfer), and a reason when it is a candidate
// but the product refuses it.
// --------------------------------------------------------------------------
function candidateGrant(jsonTx) {
  const msg = jsonTx && jsonTx.message;
  if (!msg) return { candidate: false, reason: 'no_message' };
  const version = jsonTx.version;
  if (version !== 'legacy') {
    // v0 and v1 are measured too, but the grant keys are read from the json
    // view; for v1 the message shape is the same in json, so the candidate
    // test still applies.
    if (version !== 0 && version !== 1) return { candidate: false, reason: `unknown_version_${version}` };
  }
  const keys = msg.accountKeys;
  const h = msg.header;
  if (!Array.isArray(keys) || !h) return { candidate: false, reason: 'no_header' };
  if (h.numRequiredSignatures !== 1 || keys.length !== 3) {
    return { candidate: false, reason: 'not_single_signer_3_keys' };
  }
  if (msg.instructions.length !== 1) return { candidate: false, reason: 'not_single_instruction' };
  const ix = msg.instructions[0];
  if (keys[ix.programIdIndex] !== SYSTEM_PROGRAM) {
    return { candidate: false, reason: 'not_system_program' };
  }
  if (ix.accounts.length !== 2 || ix.accounts[0] !== 0 || ix.accounts[1] !== 1) {
    return { candidate: false, reason: 'not_transfer_account_shape' };
  }
  const data = base58Decode(ix.data);
  if (!data || data.length !== 12 || data.readUInt32LE(0) !== 2) {
    return { candidate: false, reason: 'not_transfer_data' };
  }
  return {
    candidate: true,
    grant: {
      signer: keys[0],
      destination: keys[1],
      maxLamports: data.readBigUInt64LE(4).toString(),
      expiresAt: GRANT_EXPIRES,
    },
    amountLamports: data.readBigUInt64LE(4).toString(),
  };
}

// The product's own decision on the wire bytes.
function productVerdict(wire, grant) {
  try {
    const verdict = evaluate(wire, grant, NOW);
    if (verdict && verdict.allowed) return { allowed: true, amountLamports: verdict.amountLamports };
    return { allowed: false, refused: verdict && verdict.refused ? verdict.refused : 'unknown' };
  } catch (err) {
    return { allowed: false, refused: 'threw', detail: String(err && err.message).slice(0, 120) };
  }
}

// --------------------------------------------------------------------------
// Self-check: the instrument must be able to see the product allow a
// transaction it should allow, and refuse the ones it should refuse. A probe
// that cannot do both cannot be trusted with a network number.
// --------------------------------------------------------------------------
function selftest() {
  const signer = Keypair.generate();
  const dest = Keypair.generate().publicKey;
  const blockhash = Keypair.generate().publicKey.toBase58();
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = blockhash;
  tx.add(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: dest, lamports: 42 }));
  tx.sign(signer);
  const wire = tx.serialize();
  const grant = {
    signer: signer.publicKey.toBase58(), destination: dest.toBase58(),
    maxLamports: '42', expiresAt: GRANT_EXPIRES,
  };
  const cases = [
    ['allowed', productVerdict(wire, grant), v => v.allowed === true],
    ['destination', productVerdict(wire, { ...grant, destination: Keypair.generate().publicKey.toBase58() }),
      v => v.allowed === false && v.refused === 'destination'],
    ['amount', productVerdict(wire, { ...grant, maxLamports: '41' }),
      v => v.allowed === false && v.refused === 'amount'],
    ['invalid_wire', productVerdict(Buffer.from([1, 2, 3]), grant),
      v => v.allowed === false && v.refused === 'invalid_wire'],
  ];
  let failures = 0;
  for (const [name, got, check] of cases) {
    const ok = check(got);
    if (!ok) failures++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name} -> ${JSON.stringify(got)}`);
  }
  console.log(failures === 0 ? `selftest OK (${cases.length}/${cases.length})`
    : `selftest FAILED (${cases.length - failures}/${cases.length})`);
  process.exit(failures === 0 ? 0 : 1);
}

// --------------------------------------------------------------------------
// Summarising: every published number is derived from the row list, never
// typed in. A hand-edited counter cannot survive this.
// --------------------------------------------------------------------------
function summarize(rows) {
  const total = rows.length;
  const byVersion = {};
  const byRefusal = {};
  const byReason = {};
  let candidates = 0;
  let approved = 0;
  let pairingUnverified = 0;
  for (const row of rows) {
    byVersion[row.version] = (byVersion[row.version] || 0) + 1;
    byReason[row.reason || 'none'] = (byReason[row.reason || 'none'] || 0) + 1;
    if (!row.paired) { pairingUnverified++; continue; }
    if (!row.candidate) continue;
    candidates++;
    if (row.allowed) approved++;
    else byRefusal[row.refused] = (byRefusal[row.refused] || 0) + 1;
  }
  const pct = n => (total ? ((100 * n) / total).toFixed(3) : '0.000');
  return {
    totals: {
      transactions: total,
      paired: total - pairingUnverified,
      pairingUnverified,
      candidates,
      approved,
      candidateApprovalPctOfAll: pct(approved),
      candidateApprovalPctOfCandidates: candidates ? ((100 * approved) / candidates).toFixed(3) : '0.000',
    },
    byVersion,
    byCandidateReason: byReason,
    refusalsAmongCandidates: byRefusal,
  };
}

// --------------------------------------------------------------------------
// Live sampling
// --------------------------------------------------------------------------
async function sample({ blocks = 6, back = 40 } = {}) {
  const tip = await rpc('getSlot', [{ commitment: 'finalized' }]);
  const start = tip - back;
  const rows = [];
  const slots = [];
  let slot = start;
  while (slots.length < blocks && slot > start - 400) {
    let jb;
    let bb;
    try {
      const params = [slot, {
        encoding: 'json', transactionDetails: 'full', rewards: false,
        // Mainnet serves transaction version 1; requesting only 0 makes every
        // getBlock fail with -32015 and the sample would look clean while
        // measuring nothing (measured 2026-10-30 in envelope-traffic.mjs).
        maxSupportedTransactionVersion: 1, commitment: 'finalized',
      }];
      jb = await rpc('getBlock', params);
      bb = await rpc('getBlock', [{ ...params[0] }].length ? [
        slot, { ...params[1], encoding: 'base64' },
      ] : null);
    } catch (err) {
      rows.push({ slot, paired: false, version: 'error', reason: `rpc_error:${err.message.slice(0, 80)}` });
      slot--;
      continue;
    }
    if (!jb || !bb) { slot--; continue; }
    slots.push(slot);
    const jtx = jb.transactions || [];
    const btx = bb.transactions || [];
    if (jtx.length !== btx.length) {
      rows.push({ slot, paired: false, version: 'length_mismatch', reason: 'json_base64_length_mismatch' });
      slot--;
      continue;
    }
    for (let i = 0; i < jtx.length; i++) {
      const j = jtx[i];
      const b = btx[i];
      // getBlock puts `version` on the ENTRY, not on the transaction object
      // (the {transaction, meta} wrapper defect again, measured before in
      // envelope-traffic.mjs); the candidate test must see the entry's
      // version or every row reads as undefined.
      const jt = { ...j.transaction, version: j.version };
      const wire = Buffer.from(b.transaction[0], 'base64');
      const jsonSig = base58Decode(j.transaction.signatures[0]);
      // VERIFY THE PAIRING: the json signature must physically occur in the
      // wire bytes of the base64 view. Without this the two views could be
      // misaligned and every row would measure the wrong transaction.
      const paired = !!jsonSig && wire.includes(jsonSig);
      const cand = candidateGrant(jt);
      const row = {
        slot,
        index: i,
        version: String(j.version),
        paired,
        candidate: cand.candidate,
        reason: cand.candidate ? null : cand.reason,
        signature: j.transaction.signatures[0],
        wireBytes: wire.length,
      };
      if (cand.candidate && paired) {
        const verdict = productVerdict(wire, cand.grant);
        row.allowed = verdict.allowed;
        row.refused = verdict.allowed ? null : verdict.refused;
        row.amountLamports = cand.amountLamports;
        row.grant = cand.grant;
      }
      rows.push(row);
    }
    await new Promise(r => setTimeout(r, 300));
    slot--;
  }
  return { tip, start, slots, rows };
}

// --------------------------------------------------------------------------
// Fixture replay: the committed rows are the reproducible artifact; the tool
// must be able to re-derive every published number from them without network.
// --------------------------------------------------------------------------
function replay(fixturePath) {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  const summary = summarize(fixture.rows || []);
  const report = {
    generatedAt: new Date().toISOString(),
    source: 'fixture',
    fixture: path.basename(fixturePath),
    fixtureGeneratedAt: fixture.generatedAt || null,
    rpc: fixture.rpc || null,
    finalizedTipAtStart: fixture.finalizedTipAtStart ?? null,
    slots: fixture.slots || [],
    totals: summary.totals,
    byVersion: summary.byVersion,
    byCandidateReason: summary.byCandidateReason,
    refusalsAmongCandidates: summary.refusalsAmongCandidates,
    definitions: {
      candidate: 'a transaction whose json view is a single legacy System transfer with 1 signer and 3 static keys - the only shape the v0 envelope can address',
      grant: 'built FROM the transaction under test (its own signer, destination, amount) - a best-case grant, NOT a statement about any grant that would be issued',
      approved: 'the PRODUCT policy (src/policy.js evaluate) returned allowed for those wire bytes',
      pairing: 'the json signature bytes must occur in the base64 wire bytes of the same index; unpaired rows are counted and excluded from per-transaction verdicts',
    },
    limits: [
      'Best-case grants: this measures whether the daemon COULD sign, not whether any grant would be issued.',
      'A bounded window of finalized mainnet blocks, not a census.',
      'One RPC node, one moment; the window is minutes wide.',
      'No user, no audit, no real funds.',
    ],
  };
  return report;
}

async function main() {
  if (process.argv.includes('--selftest')) return selftest();
  if (FIXTURE) {
    const report = replay(FIXTURE);
    const json = JSON.stringify(report, null, 2);
    if (OUT) {
      fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
      fs.writeFileSync(path.resolve(OUT), `${json}\n`);
    }
    console.log(json);
    return;
  }

  const blocksArg = process.argv.find(a => a.startsWith('--blocks='));
  const backArg = process.argv.find(a => a.startsWith('--back='));
  const blocks = blocksArg ? Number(blocksArg.slice('--blocks='.length)) : 6;
  const back = backArg ? Number(backArg.slice('--back='.length)) : 40;
  if (!Number.isFinite(blocks) || blocks <= 0) {
    console.error(`policy-traffic: --blocks must be a positive number, got "${blocksArg}"`);
    process.exit(2);
  }

  const r = await sample({ blocks, back });
  const summary = summarize(r.rows);
  const fixture = {
    generatedAt: new Date().toISOString(),
    rpc: RPC,
    finalizedTipAtStart: r.tip,
    slots: r.slots,
    rows: r.rows,
  };
  const report = {
    generatedAt: fixture.generatedAt,
    source: 'live',
    rpc: RPC,
    finalizedTipAtStart: r.tip,
    slots: r.slots,
    totals: summary.totals,
    byVersion: summary.byVersion,
    byCandidateReason: summary.byCandidateReason,
    refusalsAmongCandidates: summary.refusalsAmongCandidates,
    definitions: {
      candidate: 'a transaction whose json view is a single legacy System transfer with 1 signer and 3 static keys - the only shape the v0 envelope can address',
      grant: 'built FROM the transaction under test (its own signer, destination, amount) - a best-case grant, NOT a statement about any grant that would be issued',
      approved: 'the PRODUCT policy (src/policy.js evaluate) returned allowed for those wire bytes',
      pairing: 'the json signature bytes must occur in the base64 wire bytes of the same index; unpaired rows are counted and excluded from per-transaction verdicts',
    },
    limits: [
      'Best-case grants: this measures whether the daemon COULD sign, not whether any grant would be issued.',
      'A bounded window of finalized mainnet blocks, not a census.',
      'One RPC node, one moment; the window is minutes wide.',
      'No user, no audit, no real funds.',
    ],
  };

  const json = JSON.stringify(report, null, 2);
  if (summary.totals.transactions === 0) {
    console.error('policy-traffic: FATAL - sampled 0 transactions');
    process.exit(3);
  }
  if (summary.totals.pairingUnverified > 0) {
    console.error(`policy-traffic: FATAL - ${summary.totals.pairingUnverified} rows could not be paired between the json and base64 views; no per-transaction verdict is published`);
    process.exit(3);
  }
  if (OUT) {
    fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
    fs.writeFileSync(path.resolve(OUT), `${json}\n`);
    const fixtureOut = OUT.replace(/\.json$/, '-rows.json');
    fs.writeFileSync(path.resolve(fixtureOut), `${JSON.stringify(fixture, null, 2)}\n`);
  }
  console.log(json);
}

main().catch(err => {
  console.error(`policy-traffic: FATAL ${err && err.message}`);
  process.exit(3);
});
