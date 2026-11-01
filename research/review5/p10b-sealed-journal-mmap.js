'use strict';
// P10b: the journal side of p10 - a PAST WRITE through a retained writable
// MMAP (the fd is closed, so no lease can ever see it) against a SEALED
// daemon (R5-2 journal half).
//
// The attacker mmaps the journal MAP_SHARED/PROT_WRITE while it is writable
// and closes the descriptor. The mapping survives. Later the attacker writes
// forged bytes THROUGH the mapping - with no descriptor open anywhere, so
// F_SETLEASE has nothing to catch and no stat shows anything.
//
//   Pre-fix (unsealed): the forged bytes are a valid chain (the attacker
//   recomputes it) -> the daemon loads them -> the budget is the forger's.
//   Post-fix (sealed): the keyed chain MAC covers the bytes -> the forged
//   journal fails its MAC check -> the daemon refuses (ledger_mac_invalid).
//
// Phase A: while the mapping is alive the daemon must also refuse (the
// journal's own path checks see a writable journal).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  tmpdir, grantDoc, writeGrants, makeWire, request, Keypair,
} = require('./common');
const { Daemon } = require('../../src/daemon');
const { chainHash, GENESIS_HASH } = require('../../src/ledger');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const dir = tmpdir('signerd-r5-p10b-');
  fs.chmodSync(dir, 0o755);
  const out = {};
  const keypair = Keypair.generate();
  const recipient = Keypair.generate().publicKey;
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()));
  const socketPath = path.join(dir, 'p10b.sock');
  const ledgerFile = path.join(dir, 'p10b-journal.jsonl');
  const PASSPHRASE = 'probe-passphrase';

  // 1. a sealed daemon signs one message, so the journal has real content
  const d1 = new Daemon({
    socketPath, keypair, grantFile: grantsFile, ledgerFile,
    journalSealPassphrase: PASSPHRASE,
  });
  await d1.start();
  const first = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 42) });
  out.first_sign = { ok: first.ok, seq: first.seq };
  await d1.stop();

  // 2. the attacker mmaps the journal MAP_SHARED/PROT_WRITE and closes the
  //    descriptor: from now on NO descriptor exists - only the mapping.
  const genuine = fs.readFileSync(ledgerFile, 'utf8');
  fs.chmodSync(ledgerFile, 0o666);
  const mmapScript = `
import mmap, os, sys, time
path = sys.argv[1]
size = os.path.getsize(path)
fd = os.open(path, os.O_RDWR)
m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_WRITE)
os.close(fd)            # the descriptor is GONE: no lease can see it
sys.stdout.write('mapped\\n'); sys.stdout.flush()
sys.stdin.readline()    # wait for the go signal
m.close()
`;
  const attacker = spawn('python3', ['-c', mmapScript, ledgerFile], {
    stdio: ['pipe', 'pipe', 'inherit'],
  });
  await new Promise((resolve) => {
    attacker.stdout.on('data', (d) => { if (String(d).includes('mapped')) resolve(); });
  });
  out.mapping_alive = true;

  // 3. write the FORGED record through a mapping (the fd is closed, so no
  //    lease exists anywhere - only the mapping carries the write). The
  //    forged record lowers the spend and recomputes the unkeyed chain, but
  //    cannot recompute the keyed `x`.
  const rec = JSON.parse(genuine.trim().split('\n')[0]);
  rec.a = '1';
  rec.h = chainHash(GENESIS_HASH, rec);
  // Overwrite the file's ENTIRE length through the mapping: a shorter write
  // would leave a garbage tail and the journal would be refused as corrupt
  // for the wrong reason (a false pass for this probe on a tree without the
  // seal). Pad with spaces so the file stays exactly one valid JSON line.
  const json = JSON.stringify(rec);
  const forgedBytes = json + ' '.repeat(genuine.length - json.length - 1) + '\n';
  if (forgedBytes.length !== genuine.length) {
    throw new Error(`probe setup error: forged ${forgedBytes.length} vs genuine ${genuine.length}`);
  }
  const writeThrough = spawn('python3', ['-c', `
import mmap, os, sys
path = sys.argv[1]; data = sys.argv[2].encode()
fd = os.open(path, os.O_RDWR)
m = mmap.mmap(fd, len(data), mmap.MAP_SHARED, mmap.PROT_WRITE)
m.write(data); m.flush(); m.close(); os.close(fd)
print('written', flush=True)
`, ledgerFile, forgedBytes], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve) => {
    writeThrough.stdout.on('data', (d) => { if (String(d).includes('written')) resolve(); });
  });
  await sleep(200);
  attacker.kill('SIGKILL');
  fs.chmodSync(ledgerFile, 0o600);

  out.journal_after_forgery = fs.readFileSync(ledgerFile, 'utf8').trim().split('\n').length;

  // 4. the daemon restarts: the forged journal must be refused.
  try {
    const d2 = new Daemon({
      socketPath, keypair, grantFile: grantsFile, ledgerFile,
      journalSealPassphrase: PASSPHRASE,
    });
    await d2.start();
    out.sealed_restart_after_mmap_write = 'ACCEPTED (FIX_FAILED)';
    await d2.stop();
  } catch (err) {
    out.sealed_restart_after_mmap_write = `REFUSED ${err.code || err.message}`;
    out.forgery_rejected = true;
  }

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
