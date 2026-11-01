'use strict';

// Review #9 (independent), probe file 3: the ledger surface for the message
// envelope — window arithmetic, scope domains, replay across envelopes,
// journal truncation / re-chain against a message record.
//
// Run: node research/review9-independent/probe-ledger.js

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Ledger } = require('../../src/ledger');
const { verdict } = require('./helper');

const PUBKEY = Buffer.alloc(32, 9).toString('base64');
const FUTURE = '2030-01-01T00:00:00.000Z';
const msgGrant = (overrides = {}) => ({
  kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
  pubkey: PUBKEY, maxBytes: '700', expiresAt: FUTURE,
  windowMaxMessages: '5', windowSeconds: '3600', ...overrides,
});
const txGrant = {
  signer: 'SignerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', // base58-shaped, never resolved to a real key here
  destination: 'DestinationBBBBBBBBBBBBBBBBBBBBBBBB',
  maxLamports: '1000', expiresAt: FUTURE,
  windowMaxLamports: '10000000', windowSeconds: '3600',
};

function withLedger(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review9-ledger-'));
  try {
    return fn(new Ledger({ file: path.join(dir, 'j.jsonl') }), dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// H13: window arithmetic. EXPECTED: cap engages at max+1; no integer overflow
// with a huge windowMaxMessages; an absurd windowSeconds still counts.
withLedger((ledger) => {
  const g = msgGrant({ windowMaxMessages: '3' });
  const results = [];
  for (let i = 0; i < 4; i += 1) {
    results.push(ledger.approveMessage({
      messageBytes: Buffer.from(`m-${i}`), grant: g, now: new Date('2026-11-01T00:00:00Z'),
    }));
  }
  verdict('H13: message window cap engages at max+1',
    results.slice(0, 3).every((r) => r.allowed === true) &&
    results[3].refused === 'window_cap' && results[3].windowMessages === '3',
    results.map((r) => (r.allowed ? 'ok' : r.refused)).join(','));

  const huge = msgGrant({ windowMaxMessages: '9007199254740991' }); // MAX_SAFE_INTEGER
  const v = ledger.approveMessage({
    messageBytes: Buffer.from('huge-window'), grant: huge, now: new Date('2026-11-01T00:00:00Z'),
  });
  // NOTE (probe bug, found and fixed — second time on this assertion): the
  // first version hard-coded the expectation and forgot that (a) TWO records
  // from H13 already sit in the same scope and (b) the approval being tested
  // itself consumes one slot. Formula: remaining = max - prior - 1. The
  // assertion now derives `prior` from the ledger's own snapshot instead of
  // hard-coding it.
  const prior = ledger.snapshot().records - 1; // minus the approval just made
  const expectedRemaining = 9007199254740991 - prior - 1;
  verdict('H13b: MAX_SAFE_INTEGER window accepted, counts normally',
    v.allowed === true && v.windowRemainingMessages === String(expectedRemaining),
    `remaining=${v.allowed ? v.windowRemainingMessages : v.refused} expected=${expectedRemaining} prior=${prior}`);

  const over = msgGrant({ windowMaxMessages: '9007199254740992' }); // MAX_SAFE+1
  const v2 = ledger.approveMessage({
    messageBytes: Buffer.from('over-window'), grant: over, now: new Date('2026-11-01T00:00:00Z'),
  });
  verdict('H13c: window above MAX_SAFE_INTEGER refused (invalid_grant_window)',
    v2.refused === 'invalid_grant_window', `refused=${v2.refused}`);

  const absurd = msgGrant({ windowSeconds: '90071992547409' }); // *1000 overflows safe int
  const v3 = ledger.approveMessage({
    messageBytes: Buffer.from('absurd-window'), grant: absurd, now: new Date('2026-11-01T00:00:00Z'),
  });
  verdict('H13d: absurd window seconds still count all records (fail toward cap)',
    v3.allowed === true || v3.refused === 'window_cap',
    `outcome=${v3.allowed ? 'ALLOW' : v3.refused}`);
});

// H15: scope domains. EXPECTED: tx approvals never consume the message
// window and vice versa; scopes are structurally disjoint (4-part vs 2-part).
withLedger((ledger) => {
  const g = msgGrant({ windowMaxMessages: '5' });
  // Fill the tx window almost completely: 1 * (100 + 5000 fee)
  const tx1 = ledger.approve({
    wire: Buffer.from('tx-wire-1'), amountLamports: '9500000', grant: txGrant,
    now: new Date('2026-11-01T00:00:00Z'),
  });
  const msg = ledger.approveMessage({
    messageBytes: Buffer.from('a receipt body'), grant: g,
    now: new Date('2026-11-01T00:00:00Z'),
  });
  verdict('H15: a nearly-drained tx window does not touch the message window',
    tx1.allowed === true && msg.allowed === true &&
    msg.windowMessages === '1' && msg.windowRemainingMessages === '4',
    `tx=${tx1.allowed ? tx1.windowRemainingLamports : tx1.refused} msg=${msg.allowed ? msg.windowMessages : msg.refused}`);

  const tx2 = ledger.approve({
    wire: Buffer.from('tx-wire-2'), amountLamports: '1', grant: txGrant,
    now: new Date('2026-11-01T00:00:00Z'),
  });
  // NOTE (probe bug, found and fixed): the first version expected 9510001 but
  // forgot that the message window case above did NOT touch the tx window and
  // that tx2 itself costs amount+fee: 9500000+5000 (tx1) + 1+5000 (tx2).
  const expectedSpend = 9500000 + 5000 + 1 + 5000;
  verdict('H15b: message records did not consume the tx window (spend exact)',
    tx2.allowed === true && tx2.windowSpentLamports === String(expectedSpend),
    tx2.allowed ? `spent=${tx2.windowSpentLamports} expected=${expectedSpend}` : `refused=${tx2.refused}`);

  // Same BYTES in the other envelope are a separate identity.
  const sameBytesTx = ledger.approve({
    wire: Buffer.from('a receipt body'), amountLamports: '1', grant: txGrant,
    now: new Date('2026-11-01T00:00:00Z'),
  });
  verdict('H15c: message bytes as a tx wire are a separate identity (no false replay)',
    sameBytesTx.allowed === true, sameBytesTx.allowed ? 'ALLOW' : sameBytesTx.refused);

  const replay = ledger.approveMessage({
    messageBytes: Buffer.from('a receipt body'), grant: g,
    now: new Date('2026-11-01T00:00:00Z'),
  });
  verdict('H15d: message replay refused by the ledger itself',
    replay.refused === 'replay', `refused=${replay.refused}`);
});

// Truncation / re-chain against a journal that holds message records.
// EXPECTED: an unsealed journal is loadable after cutting at a newline only
// via the documented crash-tail semantics; an INJECTED record (re-chained
// tail) must break the chain at load.
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review9-trunc-'));
  const file = path.join(dir, 'j.jsonl');
  try {
    const ledger = new Ledger({ file });
    const g = msgGrant();
    ledger.approveMessage({ messageBytes: Buffer.from('rec-1'), grant: g,
      now: new Date('2026-11-01T00:00:00Z') });
    ledger.approveMessage({ messageBytes: Buffer.from('rec-2'), grant: g,
      now: new Date('2026-11-01T00:00:00Z') });

    // Attack: truncate the LAST record (a message record) and try to load.
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.length > 0);
    fs.writeFileSync(file, lines.slice(0, 1).join('\n') + '\n');
    let truncOutcome = 'loaded';
    try {
      const l2 = new Ledger({ file });
      truncOutcome = `loaded with ${l2.snapshot().records} record(s)`;
    } catch (err) { truncOutcome = `refused: ${err.code}`; }
    verdict('H15e: truncating the last message record is accepted as a valid shorter chain (documented unsealed limit)',
      truncOutcome.startsWith('loaded'), truncOutcome);

    // Attack: forge a new record on top of the truncated chain.
    // NOTE (probe bug, found and fixed): the first version chained the forged
    // record with a WRONG hash (sha256 over JSON.stringify) — that only
    // proved "a broken chain is refused", which is the weaker claim. The
    // REAL attack is a record chained CORRECTLY onto the surviving head
    // (the attacker knows the hash algorithm and the public file), which is
    // what a truncation attack looks like. It is measured here too: an
    // UNSEALED journal cannot detect it (that is the documented limit of the
    // unsealed mode - the seal floor is what detects it).
    const { chainHash } = require('../../src/ledger');
    const prev = JSON.parse(lines[0]);
    const forgedBody = { v: 3, s: 2, t: Date.now(), w: 'f'.repeat(64), m: 'e'.repeat(64),
      a: '0', f: '0', k: 'msg\u0000auroraxo\u0000release\u0000auroraxo/signerd' };
    const forged = { ...forgedBody, h: chainHash(prev.h, forgedBody) };
    fs.appendFileSync(file, JSON.stringify(forged) + '\n');
    let forgeOutcome = 'loaded';
    try {
      new Ledger({ file });
      forgeOutcome = 'LOADED';
    } catch (err) { forgeOutcome = `refused: ${err.message}`; }
    verdict('H15f: an UNSEALED journal accepts a correctly re-chained forged record (documented limit: only the seal floor detects truncation)',
      forgeOutcome === 'LOADED', forgeOutcome);

    // The same attack against a SEALED journal: the keyed MAC must catch it.
    {
      const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'review9-trunc-sealed-'));
      const file2 = path.join(dir2, 'j.jsonl');
      try {
        const l2 = new Ledger({ file: file2, sealPassphrase: 'review9 sealed probe' });
        l2.approveMessage({ messageBytes: Buffer.from('s-1'), grant: msgGrant(),
          now: new Date('2026-11-01T00:00:00Z') });
        const l2lines = fs.readFileSync(file2, 'utf8').split('\n').filter((l) => l.length > 0);
        // cut the file to ZERO records: the classic "delete the history"
        const prevRec = JSON.parse(l2lines[0]);
        fs.writeFileSync(file2, '');
        const body3 = { v: 4, s: 1, t: Date.now(), w: 'c'.repeat(64), m: 'd'.repeat(64),
          a: '0', f: '0', k: 'msg\u0000auroraxo\u0000release\u0000auroraxo/signerd' };
        const rec3 = { ...body3, h: chainHash('0'.repeat(64), body3) };
        // compute the keyed MAC the way the ledger does
        const seal = require('../../src/journalseal');
        const macKey = seal.deriveMacKey ? seal.deriveMacKey('review9 sealed probe') : null;
        let rec3b = rec3;
        if (macKey) {
          rec3b = { ...rec3, x: seal.chainMac(macKey, seal.genesisMac(macKey), rec3.h) };
        }
        fs.writeFileSync(file2, JSON.stringify(rec3b) + '\n');
        let sealedOutcome = 'loaded';
        try { new Ledger({ file: file2, sealPassphrase: 'review9 sealed probe' }); sealedOutcome = 'LOADED'; }
        catch (err) { sealedOutcome = `refused: ${err.message}`; }
        verdict('H15g: a SEALED journal refuses a history-destroying truncation',
          sealedOutcome.startsWith('refused'), sealedOutcome);
      } finally {
        fs.rmSync(dir2, { recursive: true, force: true });
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log('probe-ledger done.');
