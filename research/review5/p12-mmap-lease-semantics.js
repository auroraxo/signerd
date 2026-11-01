'use strict';
// P12: settle the exact semantics — does F_SETLEASE (tools/leasecheck) see a
// RETAINED writable mmap whose fd has been closed?
//
// Controls: (1) open O_WRONLY fd  -> must exit 3 (held_writer);
//           (2) plain file        -> must exit 0;
//           (3) mmap MAP_SHARED PROT_WRITE with the fd CLOSED, mapping alive
//               -> this is the question: exit 3 (detected) or 0 (invisible)?
// Run the mmap case repeatedly to catch timing nondeterminism.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');

const HELPER = path.join(__dirname, '..', '..', 'tools', 'leasecheck');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-p12-'));
const target = path.join(dir, 'f.json');
fs.writeFileSync(target, 'x'.repeat(500));
fs.chmodSync(target, 0o666);
fs.chmodSync(dir, 0o755);

const run = (args = [target]) => {
  const r = spawnSync(HELPER, args, { encoding: 'utf8' });
  return { exit: r.status, meta: (r.stdout || '').split('\n')[0], stderr: (r.stderr || '').trim() };
};

(async () => {
const out = {};
out.control_plain = run();

// (1) open O_WRONLY fd held by nobody
const holdCode = `
import os,time
fd = os.open(${JSON.stringify(target)}, os.O_WRONLY)
print('held', flush=True)
t = time.time() + 30
while time.time() < t:
    time.sleep(0.2)
`;
function background(py) {
  const c = spawn('sudo', ['-n', '-u', 'nobody', 'python3', '-c', py],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  return c;
}
{
  const c = background(holdCode);
  await new Promise((r) => setTimeout(r, 700));
  out.control_open_write_fd = run();
  c.kill('SIGKILL');
  await new Promise((r) => setTimeout(r, 300));
}

// (3) mmap alive, fd closed
const mmapCode = `
import mmap, os, time, sys
fd = os.open(${JSON.stringify(target)}, os.O_RDWR)
size = os.fstat(fd).st_size
m = mmap.mmap(fd, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
os.close(fd)
sys.stderr.write('mapped-and-closed\\n')
t = time.time() + 30
while time.time() < t:
    time.sleep(0.2)
`;
{
  let err = '';
  const c = spawn('sudo', ['-n', '-u', 'nobody', 'python3', '-c', mmapCode],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  c.stderr.on('data', (d) => { err += d.toString(); });
  // wait for mapped-and-closed
  const ready = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`mmap holder not ready: ${err}`)), 15000);
    const iv = setInterval(() => {
      if (err.includes('mapped-and-closed')) { clearTimeout(t); clearInterval(iv); resolve(); }
    }, 50);
  });
  void ready;

  out.mmap_alive_trials = [];
  for (let i = 0; i < 5; i += 1) {
    out.mmap_alive_trials.push(run());
    await new Promise((r) => setTimeout(r, 250));
  }
  // also: does the daemon-side primitive (readUnderLease) agree?
  try {
    const { readUnderLease } = require('../../src/lease');
    readUnderLease(target);
    out.mmap_alive_readUnderLease = 'ACCEPTED (blind to the mapping)';
  } catch (err2) {
    out.mmap_alive_readUnderLease = `REFUSED ${err2.code}`;
  }
  c.kill('SIGKILL');
  await new Promise((r) => setTimeout(r, 300));
}

// (4) after the mapping is gone, normal again
out.after_mapping_gone = run();

console.log(JSON.stringify(out, null, 2));
fs.rmSync(dir, { recursive: true, force: true });
process.exit(0);
})().catch((e) => { console.error('PROBE ERROR', e); process.exit(1); });
