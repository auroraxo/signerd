'use strict';
// P6: R2-2 — "the replay identity is the MESSAGE, not the client-controlled
// signature slot". Falsification attempts: two wires differing only in the
// 64-byte signature slot, the returned signed artifact handed back, and the
// signature slot sent FIRST then the original.
const fs = require('node:fs');
const { tmpdir, makeWire, startDaemon, request, Keypair } = require('./common');

(async () => {
  const dir = tmpdir('signerd-r5-p6-');
  const out = {};
  const { daemon, socketPath, recipient, ledgerFile } = await startDaemon(dir, { name: 'p6' });
  const kp = daemon.keypair;
  const records = () => daemon.ledger.snapshot().records;

  const base = makeWire(kp, recipient, 77);
  const baseB64 = Buffer.from(base).toString('base64');

  // variant: identical message, signature slot (bytes 1..64) replaced
  const variant = Buffer.from(base);
  for (let i = 1; i <= 64; i += 1) variant[i] = 0x11;
  const variantB64 = Buffer.from(variant).toString('base64');
  out.slot_variant_differs_only_in_sig_slot =
    base.length === variant.length &&
    Buffer.compare(base.subarray(0, 1), variant.subarray(0, 1)) === 0 &&
    Buffer.compare(base.subarray(65), variant.subarray(65)) === 0;

  // 1. original first
  out.original = await request({ socketPath, grant: 'ops', wire: base });
  out.slot_variant_after_original = await request({ socketPath, grant: 'ops', wire: variant });
  out.signed_artifact_resubmitted = await request({ socketPath, grant: 'ops', wire: Buffer.from(out.original.signed, 'base64') });

  // 2. reverse order with a FRESH message: variant first, original second
  const base2 = makeWire(kp, recipient, 78);
  const variant2 = Buffer.from(base2);
  for (let i = 1; i <= 64; i += 1) variant2[i] = 0x22;
  out.variant_first = await request({ socketPath, grant: 'ops', wire: variant2 });
  out.original_after_variant = await request({ socketPath, grant: 'ops', wire: base2 });

  // 3. control: a genuinely different message (different blockhash) still signs
  out.control_distinct_message = await request({ socketPath, grant: 'ops', wire: makeWire(kp, recipient, 77) });

  out.final_records = records();
  out.final_journal_lines = fs.readFileSync(ledgerFile, 'utf8').trim().split('\n').length;
  out.all_message_sha_reported =
    [out.original, out.variant_first, out.control_distinct_message]
      .every((r) => typeof r.messageSha256 === 'string' && r.messageSha256.length === 64);

  await daemon.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
