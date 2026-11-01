'use strict';
// P9: cost claims made in the R4-1/R4-2 fix commits and README:
//   lease.js:      "F_SETLEASE answers the same question in ~0.01 ms"
//   R4-1 commit:   "the lease probe is ~5.8 ms incl. the helper process"
//   R4-2 commit:   "17.5 ms per append vs 9.2 ms before (6.4 ms of that is the
//                   lease probe)" and "~5.8 ms/req the grant-file lease already
//                   costs"
// Measured here on this host; reported only if materially different.
const fs = require('node:fs');
const path = require('node:path');
const { readUnderLease } = require('../../src/lease');
const { tmpdir, makeWire, startDaemon, request, Keypair } = require('./common');

const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  return {
    n: s.length,
    mean_ms: +mean.toFixed(3),
    p50_ms: +s[Math.floor(s.length / 2)].toFixed(3),
    max_ms: +s[s.length - 1].toFixed(3),
  };
};

(async () => {
  const dir = tmpdir('signerd-r5-p9-');
  const out = {};
  const small = path.join(dir, 'small.json');
  fs.writeFileSync(small, JSON.stringify({ hello: 'x'.repeat(500) }));
  fs.chmodSync(small, 0o600);

  // (a) one readUnderLease call (the "lease probe" = helper process spawn + fcntl)
  const leaseTimes = [];
  for (let i = 0; i < 60; i += 1) {
    const t = process.hrtime.bigint();
    readUnderLease(small);
    leaseTimes.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  out.lease_probe = stats(leaseTimes);

  // (b) fcntl-only baseline: the helper itself, no node involved
  const helper = path.join(__dirname, '..', '..', 'tools', 'leasecheck');
  const { spawnSync } = require('node:child_process');
  const helperTimes = [];
  for (let i = 0; i < 40; i += 1) {
    const t = process.hrtime.bigint();
    spawnSync(helper, [small]);
    helperTimes.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  out.helper_process_total = stats(helperTimes);

  // (c) full request round trip on a live daemon (grant lease + ledger read lease + fsync)
  const { daemon, socketPath, recipient } = await startDaemon(dir, { name: 'p9' });
  const kp = daemon.keypair;
  const dest = recipient;
  const rt = [];
  for (let i = 0; i < 25; i += 1) {
    const t = process.hrtime.bigint();
    const r = await request({ socketPath, grant: 'ops', wire: makeWire(kp, dest, 10 + i) });
    rt.push(Number(process.hrtime.bigint() - t) / 1e6);
    if (!r.ok) { out.request_error = r; break; }
  }
  out.full_request_round_trip = stats(rt);

  // (d) approve() alone (ledger read-under-lease + append + fsync)
  const { gate } = require('../../src/ledger');
  const grant = {
    signer: kp.publicKey.toBase58(),
    destination: dest.toBase58(),
    maxLamports: '1000000000',
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    windowMaxLamports: '1000000000',
    windowSeconds: '3600',
  };
  const ap = [];
  for (let i = 0; i < 25; i += 1) {
    const t = process.hrtime.bigint();
    const v = gate(makeWire(kp, dest, 300 + i), grant, new Date(), daemon.ledger);
    ap.push(Number(process.hrtime.bigint() - t) / 1e6);
    if (!v.allowed) { out.append_error = v; break; }
  }
  out.gate_append_including_lease = stats(ap);

  out.claims = {
    lease_js_comment_0_01ms_fcntl_only: true,
    r4_1_commit_lease_probe_5_8ms: true,
    r4_2_commit_17_5ms_per_append: true,
  };
  out.journal_size_bytes_at_end = fs.existsSync(`${daemon.ledgerFile}`)
    ? fs.statSync(`${daemon.ledgerFile}`).size : 0;

  await daemon.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
