'use strict';
// P15b: the p15 forgery timeline (edit the records and recompute the UNKEYED
// chain) against a SEALED daemon (R5-2 journal half).
//
//   Pre-fix (p15, unsealed): the forged journal loads, the window budget is
//   whatever the forger wrote, and the dropped message is signed again.
//   Post-fix (sealed): the keyed chain MAC cannot be recomputed without the
//   passphrase, so daemon #3 REFUSES to start (ledger_mac_invalid).
//
// Two forgery shapes are probed separately, each against a pristine copy of
// the genuine journal:
//   f1 EDIT  : lower the recorded spend, recompute the unkeyed chain
//              (the budget-reset attack)
//   f2 DROP  : drop the record of an already-signed message, renumber the
//              survivor, recompute the unkeyed chain (the double-sign attack)
const fs = require('node:fs');
const path = require('node:path');
const {
  tmpdir, grantDoc, writeGrants, makeWire, request, Keypair,
} = require('./common');
const { Daemon } = require('../../src/daemon');
const { chainHash, GENESIS_HASH } = require('../../src/ledger');

(async () => {
  const dir = tmpdir('signerd-r5-p15b-');
  fs.chmodSync(dir, 0o755);
  const out = {};
  const keypair = Keypair.generate();
  const recipient = Keypair.generate().publicKey;
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58(),
    { windowMaxLamports: '1000000000', windowSeconds: '3600' }));
  const socketPath = path.join(dir, 'p15b.sock');
  const ledgerFile = path.join(dir, 'p15b-journal.jsonl');
  const PASSPHRASE = 'probe-passphrase';

  // 1. sealed daemon signs two messages
  const d1 = new Daemon({
    socketPath, keypair, grantFile: grantsFile, ledgerFile,
    journalSealPassphrase: PASSPHRASE,
  });
  await d1.start();
  const wireA = makeWire(keypair, recipient, 42);
  const wireB = makeWire(keypair, recipient, 43);
  const firstA = await request({ socketPath, grant: 'ops', wire: wireA });
  const firstB = await request({ socketPath, grant: 'ops', wire: wireB });
  out.signs = {
    A: { ok: firstA.ok, seq: firstA.seq },
    B: { ok: firstB.ok, seq: firstB.seq },
  };
  await d1.stop();
  const genuine = fs.readFileSync(ledgerFile);
  out.records = genuine.toString('utf8').trim().split('\n').length;

  const tryRestart = async () => {
    try {
      const d = new Daemon({
        socketPath, keypair, grantFile: grantsFile, ledgerFile,
        journalSealPassphrase: PASSPHRASE,
      });
      await d.start();
      const resend = await request({
        socketPath, grant: 'ops', wire: Buffer.from(firstA.signed, 'base64'),
      });
      await d.stop();
      return { verdict: 'ACCEPTED (FIX_FAILED)', resend };
    } catch (err) {
      return { verdict: `REFUSED ${err.code || err.message}`, doubleSignPrevented: true };
    }
  };

  // f1 EDIT: lower the spend and recompute the unkeyed chain.
  {
    const recs = genuine.toString('utf8').trim().split('\n').map((l) => JSON.parse(l));
    recs[0].a = '1';
    let prev = GENESIS_HASH;
    for (const r of recs) {
      r.h = chainHash(prev, r);
      prev = r.h;
    }
    fs.writeFileSync(ledgerFile, `${recs.map((r) => JSON.stringify(r)).join('\n')}\n`, { mode: 0o600 });
    out.f1_edit_and_rechain = await tryRestart();
  }

  // f2 DROP: drop the record of the already-signed message A.
  {
    fs.writeFileSync(ledgerFile, genuine, { mode: 0o600 });
    const recs = genuine.toString('utf8').trim().split('\n').map((l) => JSON.parse(l));
    const survivor = { ...recs[1] };
    survivor.s = 1;
    survivor.h = chainHash(GENESIS_HASH, survivor);
    fs.writeFileSync(ledgerFile, `${JSON.stringify(survivor)}\n`, { mode: 0o600 });
    out.f2_drop_and_rechain = await tryRestart();
  }

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
