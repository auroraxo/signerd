'use strict';
// P2b: the R5-2 past-write attack AGAINST the sealed-grant workflow (2026-10-31).
//
// p2 proved that after a stranger's finished write + chmod 0600, every check
// the daemon makes passes and the attacker's destination is signed. p2b runs
// the same timeline with the seal in the operator's workflow:
//   1. operator creates the honest grants.json and SEALS it (seal-grants)
//   2. uid nobody overwrites the file with forged grants (0666 window)
//   3. operator tightens to 0600 - the documented remediation
//   4. daemon starts with --grant-seal-passphrase-file
//   Expected: the daemon REFUSES to start (grant_file_seal_mismatch). Without
//   the seal it would sign the attacker's destination (that is p2).
//
// Controls:
//   (i)  honest sealed file, no forgery: the daemon starts and signs ONLY the
//        legit destination (false-positive guard);
//   (ii) forgery WITHOUT a seal (seal stripped): refused grant_file_unsealed;
//   (iii) loadGrantFile without seal mode still loads (opt-in unchanged).
const fs = require('node:fs');
const path = require('node:path');
const { loadGrantFile } = require('../../src/grantfile');
const { sealDocument, makeSealKeyProvider } = require('../../src/grantseal');
const {
  tmpdir, asNobody, grantDoc, writeGrants, makeWire, request, Keypair,
} = require('./common');

const PASSPHRASE = fs.readFileSync(process.env.SIGNERD_SEAL_PASSPHRASE_FILE, 'utf8')
  .replace(/\r?\n$/, '');

(async () => {
  const dir = tmpdir('signerd-r5-p2b-');
  fs.chmodSync(dir, 0o755);

  const attackerDest = Keypair.generate().publicKey.toBase58();
  const legitDest = Keypair.generate().publicKey.toBase58();
  const keypair = Keypair.generate();
  const out = {};

  const grantsFile = path.join(dir, 'grants.json');
  // 1. honest grants, sealed (the operator's workflow; mode tight from the start)
  writeGrants(grantsFile, sealDocument(
    grantDoc(keypair.publicKey.toBase58(), legitDest), PASSPHRASE), 0o600);
  out.sealed_honest = loadGrantFile(grantsFile, {
    sealKeyFor: makeSealKeyProvider(PASSPHRASE),
  }).names;

  // 2. stranger forges the grants, closes the fd (same window as p2: make the
  // file briefly writable exactly like p2 measured, then the operator tightens)
  fs.chmodSync(grantsFile, 0o666);
  const forged = grantDoc(keypair.publicKey.toBase58(), attackerDest, {
    maxLamports: '1000000000', windowMaxLamports: '1000000000',
  });
  const writeRes = asNobody(`
import os, json
p = ${JSON.stringify(grantsFile)}
b = json.dumps(${JSON.stringify(forged)}).encode()
fd = os.open(p, os.O_WRONLY)
os.write(fd, b)
os.ftruncate(fd, len(b))
os.close(fd)
print('wrote', os.path.getsize(p), flush=True)
`);
  if (writeRes.status !== 0) {
    out.error = 'stranger write failed'; out.writeRes = writeRes;
    console.log(JSON.stringify(out, null, 2)); process.exit(1);
  }
  out.stranger_write = writeRes.stdout.trim();

  // 3. operator tightens to 0600 (the documented remediation)
  fs.chmodSync(grantsFile, 0o600);
  out.file_mode = (fs.statSync(grantsFile).mode & 0o777).toString(8);

  // 4. daemon starts WITH the seal passphrase: the forgery must stop it.
  // Note the honest reason depends on what the stranger left behind: their
  // overwrite replaced the whole document (seal included) -> unsealed; an
  // edit UNDER a preserved seal would be a mismatch. Either way: REFUSED.
  const { Daemon } = require('../../src/daemon');
  const socketPath = path.join(dir, 'p2b.sock');
  const ledgerFile = path.join(dir, 'p2b-journal.jsonl');
  let refused = null;
  try {
    new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile,
      grantSealPassphrase: PASSPHRASE });
    out.forged_signed = 'daemon constructed without refusal (FIX FAILED)';
  } catch (err) {
    refused = err.code || err.message;
  }
  out.sealed_forgery_refused_with = refused;

  // 5. seal stripped entirely (the simpler forgery)
  const stripped = JSON.parse(fs.readFileSync(grantsFile, 'utf8'));
  delete stripped.seal;
  fs.writeFileSync(grantsFile, JSON.stringify(stripped, null, 2));
  fs.chmodSync(grantsFile, 0o600);
  let refused2 = null;
  try {
    new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile,
      grantSealPassphrase: PASSPHRASE });
    out.stripped_signed = 'daemon constructed without refusal (FIX FAILED)';
  } catch (err) {
    refused2 = err.code || err.message;
  }
  out.stripped_forgery_refused_with = refused2;

  // 6. re-seal by the attacker with THEIR OWN passphrase: still refused
  // (their seal does not verify under the operator's key).
  const attackerSealed = sealDocument(
    grantDoc(keypair.publicKey.toBase58(), attackerDest), 'attacker passphrase');
  writeGrants(grantsFile, attackerSealed, 0o600);
  let refused3 = null;
  try {
    new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile,
      grantSealPassphrase: PASSPHRASE });
    out.attacker_reseal_signed = 'daemon constructed without refusal (FIX FAILED)';
  } catch (err) {
    refused3 = err.code || err.message;
  }
  out.attacker_reseal_refused_with = refused3;

  // Control (i): honest sealed file -> daemon starts, signs ONLY legit.
  const honestFile = path.join(dir, 'honest.json');
  writeGrants(honestFile, sealDocument(
    grantDoc(keypair.publicKey.toBase58(), legitDest), PASSPHRASE), 0o600);
  const honestSocket = path.join(dir, 'p2b-honest.sock');
  const daemon = new Daemon({ socketPath: honestSocket, keypair,
    grantFile: honestFile, ledgerFile: path.join(dir, 'p2b-honest.jsonl'),
    grantSealPassphrase: PASSPHRASE });
  await daemon.start();
  out.control_honest_sealed_signs =
    await request({ socketPath: honestSocket, grant: 'ops', wire: makeWire(keypair, legitDest, 42) });
  out.control_attack_dest_refused =
    await request({ socketPath: honestSocket, grant: 'ops', wire: makeWire(keypair, attackerDest, 42) });
  await daemon.stop();

  // Control (iii): without seal mode, behaviour is unchanged (opt-in).
  out.unsealed_mode_still_loads = loadGrantFile(honestFile).names;

  const isSealRefusal = (reason) => reason === 'grant_file_unsealed' ||
    reason === 'grant_file_seal_mismatch' || reason === 'grant_file_seal_invalid';
  const verdict = isSealRefusal(out.sealed_forgery_refused_with) &&
    isSealRefusal(out.stripped_forgery_refused_with) &&
    out.attacker_reseal_refused_with === 'grant_file_seal_mismatch' &&
    out.control_honest_sealed_signs.ok === true &&
    out.control_attack_dest_refused.ok === false &&
    JSON.stringify(out.unsealed_mode_still_loads) === JSON.stringify(['ops']);
  console.log(JSON.stringify({ verdict: verdict ? 'SEALED_PAST_WRITE_REFUSED' : 'FIX_FAILED', ...out }, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(verdict ? 0 : 1);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
