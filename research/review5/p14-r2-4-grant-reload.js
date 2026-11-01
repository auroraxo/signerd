'use strict';
// P14: R2-4 — "the grant file is re-read on EVERY request, so revocation is
// immediate". Behaviour matrix against a LIVE daemon, plus fail-closed checks
// on a broken grant file.
//
//   m1 edit a grant's maxLamports      -> the NEXT request must use the new cap
//   m2 delete a grant                  -> the next request must be refused
//   m3 add a grant                     -> the next request must be honoured
//   m4 corrupt the grant file (JSON)   -> the next request must be REFUSED
//   m5 replace the grant file by a symlink -> the next request must be REFUSED
//   m6 make the grant file group-writable  -> the next request must be REFUSED
//   m7 a grant for a DIFFERENT signer   -> the whole file must be refused
const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, makeWire, startDaemon, request, writeGrants, grantDoc, Keypair } = require('./common');

(async () => {
  const dir = tmpdir('signerd-r5-p14-');
  const out = {};
  const { daemon, socketPath, keypair, recipient, grantsFile } = await startDaemon(dir, { name: 'p14' });

  const doc = () => JSON.parse(fs.readFileSync(grantsFile, 'utf8'));

  // m1: raise/lower the cap
  const d = doc();
  d.grants.ops.maxLamports = '1';
  writeGrants(grantsFile, d, 0o600);
  out.m1_lowered_cap_to_1_lamport =
    await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 42) });

  d.grants.ops.maxLamports = '1000000000';
  writeGrants(grantsFile, d, 0o600);
  out.m1_restored_cap =
    await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 43) });

  // m2: delete the grant
  writeGrants(grantsFile, { version: 1, grants: {} }, 0o600);
  out.m2_grant_deleted = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 44) });

  // m3: re-add it
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()), 0o600);
  out.m3_grant_readded = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 45) });

  // m4: corrupt JSON
  fs.writeFileSync(grantsFile, '{not json');
  fs.chmodSync(grantsFile, 0o600);
  out.m4_corrupt = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 46) });

  // m5: symlink replacement
  const real = path.join(dir, 'real-grants.json');
  writeGrants(real, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()), 0o600);
  fs.unlinkSync(grantsFile);
  fs.symlinkSync(real, grantsFile);
  out.m5_symlink = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 47) });

  // m6: group-writable
  fs.unlinkSync(grantsFile);
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()), 0o666);
  out.m6_group_writable = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 48) });

  // m7: a grant for another signer in the same file
  const d2 = grantDoc(keypair.publicKey.toBase58(), recipient.toBase58());
  d2.grants.other = { ...d2.grants.ops, signer: Keypair.generate().publicKey.toBase58() };
  writeGrants(grantsFile, d2, 0o600);
  out.m7_foreign_signer_grant = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 49) });

  // m8: unknown field in a grant -> refused?
  const d3 = grantDoc(keypair.publicKey.toBase58(), recipient.toBase58());
  d3.grants.ops.extraField = 'x';
  writeGrants(grantsFile, d3, 0o600);
  out.m8_unknown_field = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 50) });

  await daemon.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
