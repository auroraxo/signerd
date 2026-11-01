'use strict';

// Review #9 (independent), probe file 5: envelope confusion over the LIVE
// socket (tx grant + message body and back), poisoned/grant-shape attacks,
// and the sealed-journal truncation under a CORRECTLY computed MAC.
//
// Run: node research/review9-independent/probe-envelope.js

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { request, Daemon } = require('../../src/daemon');
const { Ledger, chainHash } = require('../../src/ledger');
const seal = require('../../src/journalseal');
const { importKeystore } = require('../../src/keystore');
const { fixture, body, verdict } = require('./helper');
const { Keypair } = require('@solana/web3.js');

const PUBKEY = Buffer.alloc(32, 9).toString('base64');

async function main() {
  // ---- envelope confusion: a message grant used for a tx wire and back ----
  {
    // One daemon with BOTH grant kinds. The tx grant is shaped exactly like
    // an operator would write it (the signer is the daemon's own key).
    const f = await fixture();
    try {
      // rewrite the grant file with both kinds: message + tx
      const txSigner = f.keypair.publicKey.toBase58();
      const grants = {
        releases: f.messageGrant(),
        transfers: {
          signer: txSigner,
          destination: 'DestinationBBBBBBBBBBBBBBBBBBBBBBBBB',
          maxLamports: '1000', expiresAt: '2030-01-01T00:00:00.000Z',
          windowMaxLamports: '100000', windowSeconds: '3600',
        },
      };
      fs.writeFileSync(f.grantFile,
        JSON.stringify({ version: 1, grants }, null, 2), { mode: 0o600 });

      // 1. a MESSAGE BODY on the tx grant
      const r1 = await request({ socketPath: f.socketPath, grant: 'transfers',
        body: JSON.stringify(body()) });
      verdict('env: message body on a transaction grant refused (grant_kind_mismatch)',
        r1.ok === false && r1.error === 'grant_kind_mismatch', `error=${r1.error}`);

      // 2. a TX WIRE on the message grant
      const fakeWire = Buffer.alloc(65 + 10, 7).toString('base64');
      const r2 = await request({ socketPath: f.socketPath, grant: 'releases',
        wire: fakeWire });
      verdict('env: transaction wire on a message grant refused (grant_kind_mismatch)',
        r2.ok === false && r2.error === 'grant_kind_mismatch', `error=${r2.error}`);

      // 3. BOTH wire and body in one frame.
      // NOTE (probe bug, found and fixed): the first version used the
      // request() helper, which picks body OR wire — so the frame never
      // carried both and the daemon was never asked the question. The raw
      // socket below sends the frame the helper would refuse to build.
      const rawFrame = JSON.stringify({
        grant: 'releases',
        wire: fakeWire,
        body: JSON.stringify(body()),
      }) + '\n';
      const r3 = await new Promise((resolve) => {
        const net = require('node:net');
        const sock = net.connect(f.socketPath);
        let buf = '';
        sock.on('connect', () => sock.write(rawFrame));
        sock.on('data', (d) => { buf += d.toString(); sock.end(); });
        sock.on('close', () => {
          try { resolve(JSON.parse(buf.split('\n')[0])); }
          catch { resolve({ ok: false, error: 'unparseable' }); }
        });
        sock.on('error', () => resolve({ ok: false, error: 'socket_error' }));
      });
      verdict('env: wire+body in one frame refused (request_invalid)',
        r3.ok === false && r3.error === 'request_invalid', `error=${r3.error}`);

      // 4. the message grant still signs after the confusion attempts
      const r4 = await f.sign('releases', body({ claims: { version: 'post-confusion' } }));
      verdict('env: the message grant still signs after three confusion attempts',
        r4.ok === true, `error=${r4.error}`);
    } finally {
      f.cleanup();
    }
  }

  // ---- grant-shape attacks at load time (kind field confused) ----
  {
    const { validateGrant } = require('../../src/grantfile');
    const cases = [
      ['kind=message with tx fields', { kind: 'message', issuer: 'a', type: 'b', subject: 'c',
        pubkey: PUBKEY, maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxMessages: '5', windowSeconds: '3600', destination: 'X' }],
      ['kind=message missing pubkey', { kind: 'message', issuer: 'a', type: 'b', subject: 'c',
        maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxMessages: '5', windowSeconds: '3600' }],
      ['kind=tx (not message)', { kind: 'tx', signer: 'S', destination: 'D',
        maxLamports: '1', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxLamports: '1', windowSeconds: '3600' }],
      ['message with kind missing (falls into tx validation)', { issuer: 'a', type: 'b',
        subject: 'c', pubkey: PUBKEY, maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxMessages: '5', windowSeconds: '3600' }],
      ['message maxBytes over the envelope cap', { kind: 'message', issuer: 'a', type: 'b',
        subject: 'c', pubkey: PUBKEY, maxBytes: '9999', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxMessages: '5', windowSeconds: '3600' }],
      ['message windowSeconds zero (cap would never engage)', { kind: 'message', issuer: 'a',
        type: 'b', subject: 'c', pubkey: PUBKEY, maxBytes: '700',
        expiresAt: '2030-01-01T00:00:00.000Z', windowMaxMessages: '5', windowSeconds: '0' }],
      ['valid message grant', { kind: 'message', issuer: 'a', type: 'b', subject: 'c',
        pubkey: PUBKEY, maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
        windowMaxMessages: '5', windowSeconds: '3600' }],
    ];
    const outcomes = cases.map(([label, g]) => {
      try { validateGrant('g', g); return [label, 'ACCEPTED']; }
      catch (err) { return [label, `refused:${err.code}`]; }
    });
    const allButLastRefused = outcomes.slice(0, -1).every(([, o]) => o.startsWith('refused:'));
    const lastAccepted = outcomes[outcomes.length - 1][1] === 'ACCEPTED';
    verdict('env: every confused/malformed grant shape is refused at load, the valid one loads',
      allButLastRefused && lastAccepted,
      outcomes.map(([l, o]) => `${l.slice(0, 30)}=${o}`).join(' | '));
  }

  // ---- sealed truncation, now with a CORRECTLY computed keyed MAC ----
  // (the first attempt in probe-ledger refused for the weak reason "sealed
  // record without x"; this version forges the MAC itself so only the ANCHOR
  // can catch it — if anything can.)
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review9-sealed-mac-'));
    const file = path.join(dir, 'j.jsonl');
    try {
      const passphrase = 'review9 sealed mac probe';
      const l = new Ledger({ file, sealPassphrase: passphrase });
      l.approveMessage({ messageBytes: Buffer.from('sealed-1'),
        grant: { kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
          pubkey: PUBKEY, maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
          windowMaxMessages: '5', windowSeconds: '3600' },
        now: new Date('2026-11-01T00:00:00Z') });

      // The attacker knows the passphrase in this model? No: model two cases.
      // (a) attacker WITHOUT the passphrase: must be caught by the keyed MAC.
      // (b) attacker WITH the passphrase (i.e. the operator): caught by the
      //     anchor floor (count/head), which is the documented R5-2 guarantee.
      const key = seal.deriveJournalKey(passphrase);
      const body1 = { v: 4, s: 1, t: Date.now(), w: '1'.repeat(64), m: '2'.repeat(64),
        a: '0', f: '0', k: 'msg\u0000auroraxo\u0000release\u0000auroraxo/signerd' };
      const forged = { ...body1, h: chainHash('0'.repeat(64), body1) };
      forged.x = seal.chainMac(key, seal.genesisMac(key), forged.h);

      // (a) replace the whole history with the attacker's own record
      fs.writeFileSync(file, JSON.stringify(forged) + '\n');
      let a;
      try { new Ledger({ file, sealPassphrase: passphrase }); a = 'LOADED (bad)'; }
      catch (err) { a = `refused: ${err.message.slice(0, 70)}`; }
      verdict('sealed: an attacker without the passphrase cannot replace history (keyed MAC or anchor catches it)',
        a.startsWith('refused'), a);

      // (b) truncate: remove the only record but keep the (still valid) anchor
      //     — the floor claims 1 record, the journal holds 0.
      fs.writeFileSync(file, '');
      let b;
      try { new Ledger({ file, sealPassphrase: passphrase }); b = 'LOADED (bad)'; }
      catch (err) { b = `refused: ${err.message.slice(0, 70)}`; }
      verdict('sealed: truncating the journal to zero records is refused by the seal floor',
        b.startsWith('refused'), b);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  process.exit(0);
}

main().catch((err) => { console.error('HARNESS ERROR', err); process.exit(3); });
