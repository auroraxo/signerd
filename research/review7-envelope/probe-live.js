'use strict';

// Review #7 (message-grant envelope), probe file 2: the LIVE path and the
// ledger's cross-budget claim. A real daemon signs through the socket; the
// interop check runs the REAL openreceipts verifiers on the artifact.
// Run directly: node research/review7-envelope/probe-live.js

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Ledger, chainHash } = require('../../src/ledger');
const { fixture, body, verdict, opensslVerifies } = require('./helper');

const OPENRECEIPTS = path.resolve(__dirname, '..', '..', '..', 'openreceipts');

function consumerVerifiers(receiptFile, pinnedFile) {
  const results = {};
  if (fs.existsSync(path.join(OPENRECEIPTS, 'receipt.py'))) {
    const args = [path.join(OPENRECEIPTS, 'receipt.py'), 'verify', receiptFile];
    if (pinnedFile) args.push('--key', pinnedFile);
    const py = spawnSync('python3', args, { encoding: 'utf8' });
    results.python = py.status;
    if (py.status !== 0) results.pythonErr = (py.stderr || py.stdout || '').trim().split('\n').slice(-2).join(' | ');
  }
  if (fs.existsSync(path.join(OPENRECEIPTS, 'verify.mjs'))) {
    const args = [path.join(OPENRECEIPTS, 'verify.mjs'), receiptFile];
    if (pinnedFile) args.push('--key', pinnedFile);
    const js = spawnSync('node', args, { encoding: 'utf8' });
    results.node = js.status;
    if (js.status !== 0) results.nodeErr = (js.stderr || js.stdout || '').trim().split('\n').slice(-2).join(' | ');
  }
  return results;
}

async function main() {
  const f = await fixture();
  try {
    // ---- R7-1 live: a body without issued_at is refused, not signed ----
    const noIssued = body(); delete noIssued.issued_at;
    const r1 = await f.sign('releases', noIssued);
    verdict('R7-1 live: missing issued_at refused over the socket',
      r1.ok === false && r1.error === 'envelope', `error=${r1.error}`);

    // ---- R7-2a live: impossible calendar date refused ----
    const r2 = await f.sign('releases', body({ issued_at: '2026-02-30T00:00:00+00:00' }));
    verdict('R7-2a live: Feb 30 refused over the socket',
      r2.ok === false && r2.error === 'envelope', `error=${r2.error}`);

    // ---- R7-3 live: 2030 refused; the measured consumer stamp (+21.4h)
    //      still signs, and the signature verifies under OpenSSL ----
    const r3 = await f.sign('releases', body({ issued_at: '2030-01-01T00:00:00+00:00' }));
    verdict('R7-3 live: 2030-dated receipt refused',
      r3.ok === false && r3.error === 'issued_at_in_future', `error=${r3.error}`);

    const consumerStamp = body({
      issued_at: new Date(Date.now() + 21.4 * 3600 * 1000).toISOString()
        .replace(/\.\d+Z$/, '+00:00'),
    });
    const r4 = await f.sign('releases', consumerStamp);
    verdict('R7-3 guard live: consumer stamp (+21.4h, measured Tag-2 shape) signs and verifies',
      r4.ok === true && opensslVerifies(f.keypair, consumerStamp, r4.signature),
      r4.ok ? `seq=${r4.seq}` : `error=${r4.error}`);

    // ---- Guards: replay, window cap, journal scope shape ----
    const r5 = await f.sign('releases', consumerStamp);
    verdict('guard live: identical bytes replay-refused', r5.error === 'replay', `error=${r5.error}`);

    let last = null;
    for (let i = 0; i < 5; i += 1) {
      last = await f.sign('releases', body({
        issued_at: new Date(Date.now() - (i + 1) * 60000).toISOString().replace(/\.\d+Z$/, '+00:00'),
        claims: { version: 'v0.1.0', channel: 'dev', run: String(i) },
      }));
    }
    verdict('guard live: window cap still engages after the fix', last.error === 'window_cap',
      `error=${last.error}`);

    const records = fs.readFileSync(f.ledgerFile, 'utf8').trim().split('\n')
      .map((line) => JSON.parse(line));
    const msgScopes = records.map((r) => r.k);
    verdict('guard live: every message journal record carries the 4-part msg scope',
      msgScopes.length > 0 && msgScopes.every((k) =>
        k.startsWith('msg\u0000') && k.split('\u0000').length === 4),
      msgScopes.map((s) => JSON.stringify(s)).join(', '));
  } finally {
    f.cleanup();
  }

  // ---- Ledger cross-budget claim (ledger.js comment: "the two window
  // budgets can never be charged against each other") ----
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review7-budget-'));
    try {
      const ledger = new Ledger({ file: path.join(dir, 'j.jsonl') });
      const txGrant = {
        signer: 'SignerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        destination: 'DestinationBBBBBBBBBBBBBBBBBBBBBBBBBB',
        maxLamports: '1000', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxLamports: '10000000', windowSeconds: '3600',
      };
      const msgGrant = {
        kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
        pubkey: 'A'.repeat(43) + '=', maxBytes: '700',
        expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxMessages: '5', windowSeconds: '3600',
      };
      // Three transaction approvals spend on the tx scope: 3*(100+5000).
      const txs = [];
      for (let i = 0; i < 3; i += 1) {
        txs.push(ledger.approve({
          wire: Buffer.from(`tx-wire-${i}`), amountLamports: '100', grant: txGrant,
        }));
      }
      const msg = ledger.approveMessage({
        messageBytes: Buffer.from('a receipt body'), grant: msgGrant,
      });
      verdict('guard ledger: transaction approvals did not consume the message window',
        txs.every((t) => t.allowed === true) && msg.allowed === true &&
          msg.windowMessages === '1' && msg.windowRemainingMessages === '4',
        `msg window=${msg.allowed ? `${msg.windowMessages}/5` : msg.refused}`);

      // Reverse direction: the message record that now sits in the same
      // journal must not charge the transaction window. LIMIT, stated
      // honestly: message records are written a='0'/f='0', so scope leakage
      // would be lamport-INVISIBLE here; the charge is pinned exactly and
      // the scope-string shape probes (4-part msg vs 2-part tx, live journal)
      // are what actually pin disjointness.
      const after = ledger.approve({
        wire: Buffer.from('tx-wire-after'), amountLamports: '100', grant: txGrant,
      });
      verdict('guard ledger: message records did not consume the transaction window',
        after.allowed === true && after.windowSpentLamports === '20400',
        after.allowed ? `spent=${after.windowSpentLamports} (expected 20400)` : `refused=${after.refused}`);

      // Replay across both identity spaces: same message bytes again, plus
      // a transaction wire that EQUALS the message body bytes (same bytes,
      // different envelope) must be judged on its own identities.
      const replay = ledger.approveMessage({
        messageBytes: Buffer.from('a receipt body'), grant: msgGrant,
      });
      verdict('guard ledger: message replay refused by the ledger itself',
        replay.refused === 'replay', `refused=${replay.refused}`);
      const sameBytesTx = ledger.approve({
        wire: Buffer.from('a receipt body'), amountLamports: '1', grant: txGrant,
      });
      verdict('guard ledger: same bytes in the OTHER envelope are a separate identity, not a false replay',
        sameBytesTx.allowed === true, `outcome=${sameBytesTx.allowed ? 'allowed' : sameBytesTx.refused}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  // ---- Real consumer interop on an artifact signed through the daemon ----
  {
    const f2 = await fixture();
    try {
      const receiptFile = path.join(f2.dir, 'receipt.json');
      const { writeFileSync } = require('node:fs');
      const b = body();
      const r = await f2.sign('releases', b);
      if (r.ok) {
        const ordered = {};
        for (const key of Object.keys(b).sort()) ordered[key] = b[key];
        // Pin against the DAEMON's fixture key (the auroraxo site key would
        // mismatch by construction - receipt.py fails on pin mismatch, and
        // that is its job).
        const pinned = path.join(f2.dir, 'pinned.pub');
        writeFileSync(pinned, f2.pubB64 + '\n', { mode: 0o600 });
        writeFileSync(receiptFile, JSON.stringify({
          schema: 'openreceipts/v1', receipt: ordered,
          pubkey: f2.pubB64, sig: r.signature,
        }, null, 2));
        const statuses = consumerVerifiers(receiptFile, pinned);
        verdict('guard interop: both openreceipts verifiers accept the signed artifact',
          statuses.python === 0 && statuses.node === 0,
          JSON.stringify(statuses));
      } else {
        verdict('guard interop: both openreceipts verifiers accept the signed artifact',
          false, `daemon refused: ${r.error}`);
      }
    } finally {
      f2.cleanup();
    }
  }

  process.exit(0);
}

main().catch((err) => { console.error('HARNESS ERROR', err); process.exit(3); });
