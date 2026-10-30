'use strict';
// P4: R2-1 — "a failed start()/never-started stop() no longer unlinks a LIVE
// daemon's socket" and "socket_in_use with the socket intact".
//
// The stale-socket probe is: net.connect + 500ms timeout; alive -> refuse,
// dead -> unlink the path. If the probe can report 'dead' for a LIVE daemon,
// a second start() deletes a live daemon's socket and binds its own at the
// documented client path.
//
//   control:  A alive and accepting -> B must refuse socket_in_use, socket intact.
//   attack:   A SIGSTOPped and its accept queue saturated -> B's probe times out
//             -> B starts. Observe whether A's socket (which A created) was unlinked.
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { Keypair } = require('@solana/web3.js');
const { createKeystore } = require('../../src/keystore');
const { Daemon } = require('../../src/daemon');
const { tmpdir, grantDoc, writeGrants } = require('./common');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function inodeOf(p) {
  try { return fs.statSync(p).ino; } catch { return null; }
}

function readLine(child, ms = 5000) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('child produced no output')), ms);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const nl = buf.indexOf('\n');
      if (nl >= 0) { clearTimeout(timer); resolve(buf.slice(0, nl)); }
    });
    child.on('exit', (c) => { clearTimeout(timer); reject(new Error(`child exited ${c}`)); });
  });
}

async function fillBacklog(sockPath, max = 1500) {
  const held = [];
  const stats = { connected: 0, errored: 0 };
  let launched = 0;
  await new Promise((resolve) => {
    let settled = 0;
    const launch = () => {
      while (launched < max) {
        launched += 1;
        const s = net.connect(sockPath);
        held.push(s);
        const done = () => {
          settled += 1;
          if (settled >= max) resolve();
          else if (settled % 200 === 0) launch();
        };
        s.on('connect', () => { stats.connected += 1; done(); });
        s.on('error', () => { stats.errored += 1; done(); });
      }
    };
    launch();
    setTimeout(resolve, 8000); // safety
  });
  return { held, stats, launched };
}

(async () => {
  const dir = tmpdir('signerd-r5-p4-');
  const out = {};
  const recipient = Keypair.generate().publicKey;
  const keystore = path.join(dir, 'k.key');
  createKeystore({ file: keystore, passphrase: 'p4-pass' });
  const { loadKeystore } = require('../../src/keystore');
  const keypair = loadKeystore({ file: keystore, passphrase: 'p4-pass' });
  const passFile = path.join(dir, 'pass.txt');
  fs.writeFileSync(passFile, 'p4-pass\n');
  fs.chmodSync(passFile, 0o600);
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()));
  const socketPath = path.join(dir, 'a.sock');
  const ledgerA = path.join(dir, 'a-journal.jsonl');
  const ledgerB = path.join(dir, 'b-journal.jsonl');

  // Daemon A runs in a child process so it can be SIGSTOPped.
  const child = spawn(process.execPath, [
    path.join(__dirname, '..', '..', 'bin', 'signerd.js'), 'run',
    '--keystore', keystore, '--passphrase-file', passFile,
    '--grants', grantsFile, '--ledger', ledgerA, '--socket', socketPath,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let childErr = '';
  child.stderr.on('data', (d) => { childErr += d.toString(); });
  const ready = await readLine(child);
  out.A_started = JSON.parse(ready);
  out.socket_inode_A = inodeOf(socketPath);
  out.socket_mode_A = (fs.statSync(socketPath).mode & 0o777).toString(8);

  // ---- control 1: A alive + accepting; B (other journal) must be refused ----
  const ledgerB2 = path.join(dir, 'b2-journal.jsonl');
  const B = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile: ledgerB2 });
  try {
    await B.start();
    out.control1_B_started = 'UNEXPECTED SUCCESS';
    await B.stop();
  } catch (err) {
    out.control1_B_started = `refused: ${err.code || err.message}`;
  }
  out.control1_socket_inode_after = inodeOf(socketPath);
  out.control1_socket_still_intact =
    inodeOf(socketPath) === out.socket_inode_A && fs.existsSync(socketPath);
  try { await B.stop(); } catch { /* never started */ }

  // ---- attack: stop A, saturate its accept queue, start B2 ----
  process.kill(child.pid, 'SIGSTOP');
  await sleep(200);
  out.A_state = fs.readFileSync(`/proc/${child.pid}/stat`, 'utf8').split(') ')[1][0]; // T = stopped
  const fill = await fillBacklog(socketPath);
  out.backlog_fill = fill.stats;
  out.backlog_fill.launched = fill.launched;

  const ledgerB3 = path.join(dir, 'b3-journal.jsonl');
  const B2 = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile: ledgerB3 });
  try {
    await B2.start();
    out.attack_B2_started = 'YES (second daemon accepted the start)';
    out.attack_socket_inode_after = inodeOf(socketPath);
    out.attack_socket_inode_changed =
      inodeOf(socketPath) !== out.socket_inode_A;
    out.attack_A_process_still_alive = (() => {
      try { process.kill(child.pid, 0); return true; } catch { return false; }
    })();
    // who answers on the documented client path now?
    const statusReq = net.connect(socketPath);
    out.attack_path_now_serves =
      await new Promise((resolve) => {
        statusReq.on('connect', () => resolve('a socket that accepted the connect'));
        statusReq.on('error', (e) => resolve(`error ${e.code}`));
        setTimeout(() => resolve('timeout'), 800);
      });
    statusReq.destroy();
    await B2.stop();
  } catch (err) {
    out.attack_B2_started = `refused: ${err.code || err.message}`;
    out.attack_socket_inode_after = inodeOf(socketPath);
  }

  // ---- cleanup ----
  try { process.kill(child.pid, 'SIGCONT'); } catch { /* gone */ }
  for (const s of fill.held) { try { s.destroy(); } catch { /* closed */ } }
  child.kill('SIGKILL');
  await sleep(300);
  out.final_socket_exists = fs.existsSync(socketPath);
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
