'use strict';
// P3: R2-3/R4-2 residual — journal TRUNCATED by a stranger while it was
// writable, before the daemon ever read it. The chain hash cannot see it
// (an empty/prefix journal is a VALID chain), the mode/owner checks pass after
// the operator tightens, and no lease is held -> the replay set is empty and
// an already-signed message is signed AGAIN (double-sign).
//
// Controls: (i) resending the signed artifact with intact history -> 'replay';
// (ii) stranger holding the fd at read time -> ledger_held_writer (R4-2 works).
const fs = require('node:fs');
const path = require('node:path');
const {
  tmpdir, hold, asNobody, grantDoc, writeGrants, makeWire, request, Keypair,
} = require('./common');
const { Daemon } = require('../../src/daemon');

(async () => {
  const dir = tmpdir('signerd-r5-p3-');
  fs.chmodSync(dir, 0o755);
  const out = {};
  const keypair = Keypair.generate();
  const recipient = Keypair.generate().publicKey;
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()));
  const socketPath = path.join(dir, 'p3.sock');
  const ledgerFile = path.join(dir, 'p3-journal.jsonl');

  // 1. daemon #1 signs message M
  const d1 = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile });
  await d1.start();
  const wire = makeWire(keypair, recipient, 42);
  const first = await request({ socketPath, grant: 'ops', wire });
  out.first_sign = { ok: first.ok, seq: first.seq, messageSha256: first.messageSha256 };
  const signedArtifact = Buffer.from(first.signed, 'base64');
  out.journal_after_first = fs.readFileSync(ledgerFile, 'utf8').trim().split('\n').length;

  // 2. CONTROL (i): hand the signed artifact back -> replay refused
  out.control_resend_signed_with_intact_journal =
    await request({ socketPath, grant: 'ops', wire: signedArtifact });
  await d1.stop();

  // 3. stranger truncates the journal while it is writable, then closes
  fs.chmodSync(ledgerFile, 0o666);
  const trunc = asNobody(`
import os
fd = os.open(${JSON.stringify(ledgerFile)}, os.O_WRONLY | os.O_TRUNC)
os.close(fd)
print('size now', os.path.getsize(${JSON.stringify(ledgerFile)}), flush=True)
`);
  out.stranger_truncate = trunc.stdout.trim() || trunc.stderr.trim();
  fs.chmodSync(ledgerFile, 0o600);
  out.journal_stat_after = {
    size: fs.statSync(ledgerFile).size,
    mode: (fs.statSync(ledgerFile).mode & 0o777).toString(8),
    uid: fs.statSync(ledgerFile).uid,
    dir_mode: (fs.statSync(dir).mode & 0o7777).toString(8),
  };

  // 4. daemon #2 restarts on the tightened journal: all path checks pass
  const d2 = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile });
  await d2.start();
  out.daemon2_snapshot_at_start = d2.ledger.snapshot();

  // 5. ATTACK: the same signed artifact again -> is it signed twice?
  out.attack_resend_signed_after_truncate =
    await request({ socketPath, grant: 'ops', wire: signedArtifact });
  await d2.stop();

  // Control (ii): stranger opens while the journal is writable, operator
  // tightens, holder keeps the fd -> R4-2 must refuse construction.
  fs.chmodSync(ledgerFile, 0o666);
  const holder = hold(ledgerFile, 'w');
  await holder.ready;
  fs.chmodSync(ledgerFile, 0o600);
  try {
    new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile });
    out.control_journal_writer_held = 'ACCEPTED (unexpected)';
  } catch (err) {
    out.control_journal_writer_held = `REFUSED ${err.code || err.message}`;
  }
  await holder.stop();

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
