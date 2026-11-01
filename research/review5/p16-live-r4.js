'use strict';
// P16: live-daemon statements of R4-1/R4-2 (the README's e2e claims):
//   (i)   writer holds the JOURNAL -> request refused, reason passed through
//         VERBATIM (ledger_held_writer, not flattened to ledger_write_failed)
//   (ii)  writer holds the GRANT FILE -> request refused grant_file_held_writer
//   (iii) both held only for READING -> request still succeeds (false-positive
//         guard: a reader must never brick the daemon)
//   (iv)  after the writer leaves -> request succeeds again (no poisoning)
const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, hold, makeWire, startDaemon, request } = require('./common');

(async () => {
  const dir = tmpdir('signerd-r5-p16-');
  // The holders run as uid nobody and must traverse this directory; 0700
  // (the tmpdir default) makes every hold() fail with EACCES instead of
  // testing the lease at all.
  fs.chmodSync(dir, 0o755);
  const out = {};
  const { daemon, socketPath, keypair, recipient, grantsFile, ledgerFile } =
    await startDaemon(dir, { name: 'p16' });
  const send = (n) => request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 60 + n) });

  out.i_baseline = { ok: (await send(0)).ok };

  // (i) journal held for WRITING (open while 0666, then tighten: the real sequence)
  fs.chmodSync(ledgerFile, 0o666);
  const hj = hold(ledgerFile, 'w');
  await hj.ready;
  fs.chmodSync(ledgerFile, 0o600);
  out.ii_journal_writer = await send(1);
  await hj.stop();

  // (ii) grant file held for WRITING
  fs.chmodSync(grantsFile, 0o666);
  const hg = hold(grantsFile, 'w');
  await hg.ready;
  fs.chmodSync(grantsFile, 0o600);
  out.iii_grant_writer = await send(2);
  await hg.stop();

  // (iii) both held for READING by us
  const rj = hold(ledgerFile, 'r', 'self');
  const rg = hold(grantsFile, 'r', 'self');
  await Promise.all([rj.ready, rg.ready]);
  out.iv_both_readers = await send(3);
  await Promise.all([rj.stop(), rg.stop()]);

  // (iv) after release
  out.v_recovered = await send(4);

  // final: journal still has exactly the expected number of records
  out.records = daemon.ledger.snapshot().records;

  await daemon.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
