'use strict';
// P2: R3-1/R4-1 residual — a stranger's write that FINISHED before the daemon
// ever looked at the file. Timeline (this is exactly the premise of R3-1/R4-1:
// "the file was writable when the attacker wrote it"):
//   1. grants.json exists 0666, owned by us, dir 0755 (all checks pass once
//      tightened),
//   2. uid nobody writes a FORGED grant and closes the fd,
//   3. operator tightens to 0600 (the documented remediation),
//   4. daemon starts: owner/mode/directory/lease checks all pass,
//   5. a transaction paying the attacker's destination is SIGNED.
// Controls: (i) with nobody still HOLDING the fd the daemon refuses (R4-1
// works); (ii) with the original (unforged) file the daemon pays only the
// legit destination.
const fs = require('node:fs');
const path = require('node:path');
const { loadGrantFile } = require('../../src/grantfile');
const {
  tmpdir, hold, asNobody, grantDoc, writeGrants, startDaemon, makeWire,
  request, Keypair,
} = require('./common');

(async () => {
  const dir = tmpdir('signerd-r5-p2-');
  fs.chmodSync(dir, 0o755);

  const attackerDest = Keypair.generate().publicKey.toBase58();
  const legitDest = Keypair.generate().publicKey.toBase58();
  const keypair = Keypair.generate();
  const out = {};

  // 1. legit grant file, group/other-writable
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), legitDest), 0o666);

  // 2. stranger forges the grants (destination = attacker, huge caps), closes fd
  const forged = grantDoc(keypair.publicKey.toBase58(), attackerDest, {
    maxLamports: '1000000000', windowMaxLamports: '1000000000',
  });
  const writeRes = asNobody(`
import os, json
p = ${JSON.stringify(grantsFile)}
fd = os.open(p, os.O_WRONLY)
os.write(fd, json.dumps(${JSON.stringify(forged)}).encode())
os.close(fd)
print('wrote', os.path.getsize(p), flush=True)
`);
  if (writeRes.status !== 0) {
    out.error = 'stranger write failed'; out.writeRes = writeRes;
    console.log(JSON.stringify(out, null, 2)); process.exit(1);
  }
  out.stranger_write = writeRes.stdout.trim();

  // 3. operator tightens to 0600
  fs.chmodSync(grantsFile, 0o600);
  out.after_chmod = (fs.statSync(grantsFile).mode & 0o777).toString(8);
  out.all_stat_checks = {
    owner_is_us: fs.statSync(grantsFile).uid === process.getuid(),
    dir_owner_is_us: fs.statSync(dir).uid === process.getuid(),
    dir_mode: (fs.statSync(dir).mode & 0o7777).toString(8),
    file_mode: (fs.statSync(grantsFile).mode & 0o777).toString(8),
  };

  // 4. daemon starts on the forged-but-tight file
  const socketPath = path.join(dir, 'p2.sock');
  const ledgerFile = path.join(dir, 'p2-journal.jsonl');
  const { Daemon } = require('../../src/daemon');
  const daemon = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile });
  await daemon.start();
  out.daemon_started = true;

  // 5a. CONTROL: payment to the legit destination (was in the ORIGINAL file)
  const wireLegit = makeWire(keypair, legitDest, 42);
  out.request_to_orig_destination =
    await request({ socketPath, grant: 'ops', wire: wireLegit });

  // 5b. ATTACK: payment to the attacker's destination from the forged content
  const wireAttack = makeWire(keypair, attackerDest, 42);
  out.request_to_attacker_destination =
    await request({ socketPath, grant: 'ops', wire: wireAttack });

  out.loaded_grant_destination_now =
    loadGrantFile(grantsFile).grants.ops.destination;

  // Control (i): the actual R4-1 sequence — stranger opens while the file is
  // still writable, operator tightens, holder keeps the descriptor.
  fs.chmodSync(grantsFile, 0o666);
  const holder = hold(grantsFile, 'w');
  await holder.ready;
  fs.chmodSync(grantsFile, 0o600);
  out.with_writer_holding_fd =
    await request({ socketPath, grant: 'ops', wire: makeWire(keypair, legitDest, 43) });
  await holder.stop();

  await daemon.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
