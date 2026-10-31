'use strict';
// P3b: the p3 timeline (truncate the journal while writable, operator
// tightens, daemon restarts) against a SEALED daemon (R5-2 journal half).
//
//   Pre-fix (p3, unsealed): the truncated journal loads as "valid" history,
//   the replay set is empty and the already-signed message is signed AGAIN.
//   Post-fix (sealed): daemon #2 REFUSES to start on the truncated journal
//   (ledger_mac_short). No second signature. No fresh start.
const fs = require('node:fs');
const path = require('node:path');
const {
  tmpdir, grantDoc, writeGrants, makeWire, request, Keypair,
} = require('./common');
const { Daemon } = require('../../src/daemon');

(async () => {
  const dir = tmpdir('signerd-r5-p3b-');
  fs.chmodSync(dir, 0o755);
  const out = {};
  const keypair = Keypair.generate();
  const recipient = Keypair.generate().publicKey;
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()));
  const socketPath = path.join(dir, 'p3b.sock');
  const ledgerFile = path.join(dir, 'p3b-journal.jsonl');
  const PASSPHRASE = 'probe-passphrase';

  // 1. sealed daemon #1 signs message M
  const d1 = new Daemon({
    socketPath, keypair, grantFile: grantsFile, ledgerFile,
    journalSealPassphrase: PASSPHRASE,
  });
  await d1.start();
  const wire = makeWire(keypair, recipient, 42);
  const first = await request({ socketPath, grant: 'ops', wire });
  out.first_sign = { ok: first.ok, seq: first.seq, messageSha256: first.messageSha256 };
  out.sealed_record = JSON.parse(fs.readFileSync(ledgerFile, 'utf8').trim()).v === 4;
  out.floor_exists = fs.existsSync(`${ledgerFile}.anchor`);
  await d1.stop();

  // 2. stranger truncates the journal while it is writable, then closes
  fs.chmodSync(ledgerFile, 0o666);
  fs.writeFileSync(ledgerFile, '');
  fs.chmodSync(ledgerFile, 0o600);
  out.after_truncate = { size: fs.statSync(ledgerFile).size };

  // 3. daemon #2 restarts on the tightened journal: must REFUSE (p3 closed)
  try {
    const d2 = new Daemon({
      socketPath, keypair, grantFile: grantsFile, ledgerFile,
      journalSealPassphrase: PASSPHRASE,
    });
    await d2.start();
    // If we get here, the truncation was accepted - the attack still works.
    out.sealed_restart_after_truncate = 'ACCEPTED (FIX_FAILED)';
    out.resend_signed = await request({ socketPath, grant: 'ops', wire });
    await d2.stop();
  } catch (err) {
    out.sealed_restart_after_truncate = `REFUSED ${err.code || err.message}`;
    out.double_sign_prevented = true;
  }

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
