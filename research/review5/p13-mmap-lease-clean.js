'use strict';
// P13: clean measurement of the F_SETLEASE blind spot for a RETAINED WRITABLE
// MMAP (the fd closed, only the MAP_SHARED/PROT_WRITE mapping alive).
//
// Every holder is killed and reaped BEFORE the next measurement, so no
// leftover O_WRONLY descriptor can contaminate the result.
//
//   c1 plain file                      -> exit 0  (no writer)
//   c2 open O_WRONLY fd (alive)        -> exit 3  (held_writer: DETECTED)
//   t1 mmap alive, fd closed           -> exit ?  (the question)
//   c3 after everything is gone        -> exit 0  (sanity)
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');

const HELPER = path.join(__dirname, '..', '..', 'tools', 'leasecheck');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-p13-'));
fs.chmodSync(dir, 0o755);
const target = path.join(dir, 'f.json');
fs.writeFileSync(target, 'x'.repeat(500));
fs.chmodSync(target, 0o666);

const run = () => {
  const r = spawnSync(HELPER, [target], { encoding: 'utf8' });
  return { exit: r.status, meta: (r.stdout || '').split('\n')[0] };
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startNobody(code, readyMarker) {
  const c = spawn('sudo', ['-n', '-u', 'nobody', 'python3', '-c', code],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let err = '';
  c.stderr.on('data', (d) => { err += d.toString(); });
  if (readyMarker) {
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`holder not ready: ${err}`)), 15000);
      const iv = setInterval(() => {
        if (err.includes(readyMarker)) { clearTimeout(t); clearInterval(iv); resolve(); }
      }, 50);
    });
  }
  return {
    proc: c,
    async kill() {
      // kill the whole sudo/python tree
      spawnSync('sudo', ['-n', 'pkill', '-f', 'r5-p13-holder']);
      c.kill('SIGKILL');
      await sleep(600);
      // verify no process still holds the file
      const lsof = spawnSync('bash', ['-lc',
        `ls -l /proc/*/fd 2>/dev/null | grep -c "${target}" || true`], { encoding: 'utf8' });
      return (lsof.stdout || '').trim();
    },
  };
}

(async () => {
  const out = {};
  const marker = `p = ${JSON.stringify(target)}`;
  void marker;

  out.c1_plain = run();

  // c2: O_WRONLY descriptor held
  const wCode = `
# r5-p13-holder
import os, time
fd = os.open(${JSON.stringify(target)}, os.O_WRONLY)
syserr = 1
import sys; sys.stderr.write('held\\n'); sys.stderr.flush()
t = time.time() + 25
while time.time() < t: time.sleep(0.2)
`;
  const w = await startNobody(wCode, 'held');
  out.c2_open_write_fd = run();
  await w.kill();
  out.c2_after_kill = run();

  // t1: mmap alive, fd closed
  const mCode = `
# r5-p13-holder
import mmap, os, sys, time
fd = os.open(${JSON.stringify(target)}, os.O_RDWR)
size = os.fstat(fd).st_size
m = mmap.mmap(fd, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
os.close(fd)
sys.stderr.write('mapped\\n'); sys.stderr.flush()
t = time.time() + 25
while time.time() < t: time.sleep(0.2)
`;
  const m = await startNobody(mCode, 'mapped');
  out.t1_mmap_alive_fd_closed = [];
  for (let i = 0; i < 5; i += 1) { out.t1_mmap_alive_fd_closed.push(run()); await sleep(300); }
  // can the daemon-side primitive still read it?
  try {
    const { readUnderLease } = require('../../src/lease');
    const r = readUnderLease(target);
    out.t1_readUnderLease = `ACCEPTED, ${r.bytes.length} bytes, lease=${r.meta.lease}`;
  } catch (err) {
    out.t1_readUnderLease = `REFUSED ${err.code}`;
  }
  await m.kill();
  out.c3_after_mapping_gone = run();

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((e) => { console.error('PROBE ERROR', e); process.exit(1); });
