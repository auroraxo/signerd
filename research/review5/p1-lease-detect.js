'use strict';
// P1: R4-1 / R4-2 core claims + false-positive checks.
// (a) grant file held open for writing by a FOREIGN uid (nobody) after a
//     chmod 0600 -> loadGrantFile must refuse.
// (b) journal same dance -> new Ledger must refuse.
// (c) a mere READER holds the grant/journal -> must still load (false-positive
//     guard: F_RDLCK must not conflict with readers).
// (d) root-owned 0644 grant file -> the owner check explicitly ALLOWS uid 0;
//     does the lease agree, or does it refuse a file the policy permits?
// (e) root-owned 0644 journal -> observe which refusal appears.
const fs = require('node:fs');
const path = require('node:path');
const { loadGrantFile } = require('../../src/grantfile');
const { Ledger } = require('../../src/ledger');
const { tmpdir, hold, grantDoc, writeGrants, Keypair } = require('./common');
const { spawnSync } = require('node:child_process');

const signer = Keypair.generate();
const dest = Keypair.generate().publicKey;
const out = {};
const label = (name, fn) => {
  try { out[name] = { observed: 'ACCEPTED/loaded', result: fn() }; }
  catch (err) { out[name] = { observed: 'REFUSED', code: err.code || String(err.message) }; }
};

(async () => {
  const dir = tmpdir('signerd-r5-p1-');
  fs.chmodSync(dir, 0o755); // reachable by nobody, still not group/other writable

  // (a) grant file: nobody opens for writing while 0666, operator tightens.
  const g = path.join(dir, 'grants.json');
  writeGrants(g, grantDoc(signer.publicKey.toBase58(), dest.toBase58()), 0o666);
  const holdA = hold(g, 'w');
  await holdA.ready;
  fs.chmodSync(g, 0o600);
  label('a_grant_held_writer_foreign_uid', () => loadGrantFile(g).names);
  await holdA.stop();

  // (c) grant file held for READING (by us) -> must load.
  const holdC = hold(g, 'r', 'self');
  await holdC.ready;
  label('c_grant_held_reader', () => loadGrantFile(g).names);
  await holdC.stop();

  // (d) root-owned, world-readable grant file: owner check allows uid 0.
  const gRoot = path.join(dir, 'grants-root.json');
  writeGrants(gRoot, grantDoc(signer.publicKey.toBase58(), dest.toBase58()), 0o644);
  spawnSync('sudo', ['-n', 'chown', 'root:root', gRoot], { encoding: 'utf8' });
  label('d_grant_root_owned_0644', () => loadGrantFile(gRoot).names);

  // (b) journal: nobody opens for writing while 0666, tighten, then load.
  const j = path.join(dir, 'journal.jsonl');
  fs.writeFileSync(j, ''); // empty journal = valid fresh state
  fs.chmodSync(j, 0o666);
  const holdB = hold(j, 'w');
  await holdB.ready;
  fs.chmodSync(j, 0o600);
  label('b_journal_held_writer_foreign_uid', () => new Ledger({ file: j }).snapshot());
  await holdB.stop();

  // (c2) journal held for READING by us -> must load.
  const holdC2 = hold(j, 'r', 'self');
  await holdC2.ready;
  label('c2_journal_held_reader', () => new Ledger({ file: j }).snapshot());
  await holdC2.stop();

  // (e) root-owned world-readable journal (fresh file, no records).
  const jRoot = path.join(dir, 'journal-root.jsonl');
  fs.writeFileSync(jRoot, '');
  fs.chmodSync(jRoot, 0o644);
  spawnSync('sudo', ['-n', 'chown', 'root:root', jRoot], { encoding: 'utf8' });
  label('e_journal_root_owned_0644', () => new Ledger({ file: jRoot }).snapshot());

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
