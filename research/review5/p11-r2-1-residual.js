'use strict';
// P11: R2-1 residual checks.
//  (a) a never-started stop() must not unlink a live daemon's socket
//  (b) a start() that failed for a reason OTHER than socket_in_use must not
//      unlink a live daemon's socket either
//  (c) second daemon on the same journal must be refused by the lock (so the
//      socket probe is never even reached with the same ledger)
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { Keypair } = require('@solana/web3.js');
const { Daemon } = require('../../src/daemon');
const { tmpdir, grantDoc, writeGrants, startDaemon } = require('./common');

(async () => {
  const dir = tmpdir('signerd-r5-p11-');
  const out = {};

  const f = await startDaemon(dir, { name: 'live' });
  out.socket_exists_after_start = fs.existsSync(f.socketPath);
  const inode = fs.statSync(f.socketPath).ino;

  // (a) a second Daemon object that never starts, then stop()
  const other = new Daemon({
    socketPath: f.socketPath,
    keypair: f.keypair,
    grantFile: f.grantsFile,
    ledgerFile: path.join(dir, 'other-journal.jsonl'),
  });
  await other.stop(); // never started
  out.a_never_started_stop_socket_intact =
    fs.existsSync(f.socketPath) && fs.statSync(f.socketPath).ino === inode;

  // (b) a start() that fails AFTER acquiring its own lock, e.g. socket dir mode
  const badDir = path.join(dir, 'baddir');
  fs.mkdirSync(badDir);
  fs.chmodSync(badDir, 0o777); // not sticky -> socket_dir_mode
  const bad = new Daemon({
    socketPath: path.join(badDir, 'x.sock'),
    keypair: f.keypair,
    grantFile: f.grantsFile,
    ledgerFile: path.join(dir, 'bad-journal.jsonl'),
  });
  let badErr = null;
  try { await bad.start(); } catch (err) { badErr = err.code || err.message; }
  out.b_failed_start_reason = badErr;
  await bad.stop();
  out.b_live_socket_intact =
    fs.existsSync(f.socketPath) && fs.statSync(f.socketPath).ino === inode;
  fs.chmodSync(badDir, 0o755);

  // (c) same journal as the live daemon -> must be refused by the LOCK
  const c = new Daemon({
    socketPath: path.join(dir, 'c.sock'),
    keypair: f.keypair,
    grantFile: f.grantsFile,
    ledgerFile: f.ledgerFile,
  });
  let cErr = null;
  try { await c.start(); } catch (err) { cErr = err.code || err.message; }
  out.c_same_journal_second_daemon = cErr;
  await c.stop();
  out.c_live_socket_intact =
    fs.existsSync(f.socketPath) && fs.statSync(f.socketPath).ino === inode;

  // (d) socket file replaced by a regular file while daemon runs? (probe sees
  // a non-socket path) - only possible if the dir lets us; dir is ours.
  // Skip: same uid can unlink anyway.

  // (e) client can still talk to the live daemon
  out.e_live_daemon_still_serves =
    (await require('../../src/daemon').request({
      socketPath: f.socketPath, grant: 'ops', wire: require('./common').makeWire(f.keypair, f.recipient, 9),
    })).ok;

  await f.daemon.stop();
  await other.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
