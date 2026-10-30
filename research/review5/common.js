'use strict';
// Shared helpers for review-5 adversarial probes. Read-only against src/ .
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Daemon, request } = require('../../src/daemon');

function futureIso(hours = 48) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function makeWire(kp, dest, lamports = 42, blockhash) {
  const tx = new Transaction();
  tx.feePayer = kp.publicKey;
  tx.recentBlockhash = blockhash || Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: dest, lamports }));
  tx.sign(kp);
  return tx.serialize();
}

function grantDoc(signer, dest, opts = {}) {
  return {
    version: 1,
    grants: {
      ops: {
        signer,
        destination: dest,
        maxLamports: opts.maxLamports || '1000000000',
        expiresAt: opts.expiresAt || futureIso(),
        windowMaxLamports: opts.windowMaxLamports || '1000000000',
        windowSeconds: opts.windowSeconds || '3600',
      },
    },
  };
}

function writeGrants(file, doc, mode = 0o600) {
  fs.writeFileSync(file, JSON.stringify(doc));
  fs.chmodSync(file, mode);
}

function tmpdir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(d, 0o700);
  return d;
}

/**
 * Hold `file` open with `access` ('r' | 'w') as uid nobody (or root) until a
 * release flag file appears. Prints 'held' on stdout once the fd is open.
 */
function hold(file, mode, as = 'nobody') {
  const access = mode === 'w' ? 'O_WRONLY' : 'O_RDONLY';
  const release = `${file}.release.${process.pid}.${Math.random().toString(16).slice(2, 8)}`;
  const code = [
    'import os,time',
    `fd=os.open(${JSON.stringify(file)}, os.${access} | (0 if '${mode}'=='w' else 0))`,
    `release=${JSON.stringify(release)}`,
    "print('held',flush=True)",
    'deadline=time.time()+40',
    'while not os.path.exists(release) and time.time()<deadline:',
    '    time.sleep(0.02)',
    'try:',
    '    os.unlink(release)',
    'except OSError:',
    '    pass',
  ].join('\n');
  const argv = as === 'nobody'
    ? ['sudo', '-n', '-u', 'nobody', 'python3', '-c', code]
    : as === 'self' || as === 'aurora'
      ? ['python3', '-c', code]
      : ['sudo', '-n', '-u', as, 'python3', '-c', code];
  const { spawn } = require('node:child_process');
  const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
  let errBuf = '';
  child.stderr.on('data', (d) => { errBuf += d.toString(); });
  const ready = new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error(`holder not ready: ${errBuf}`)), 15000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('held')) { clearTimeout(timer); resolve(); }
    });
    child.on('error', reject);
    child.on('exit', (c) => { clearTimeout(timer); reject(new Error(`holder exited ${c}: ${errBuf}`)); });
  });
  const stop = async () => {
    try { fs.writeFileSync(release, 'go'); } catch { /* self-timeout still ends it */ }
    await new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('exit', resolve);
      setTimeout(resolve, 6000);
    });
  };
  return { ready, stop };
}

/** Run `sudo -n -u nobody python3 -c <code>` synchronously; return exit/stdout. */
function asNobody(pyCode) {
  const { spawnSync } = require('node:child_process');
  const res = spawnSync('sudo', ['-n', '-u', 'nobody', 'python3', '-c', pyCode],
    { encoding: 'utf8', timeout: 15000 });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

async function startDaemon(dir, opts = {}) {
  const keypair = opts.keypair || Keypair.generate();
  const recipient = opts.recipient || Keypair.generate().publicKey;
  const grantsFile = path.join(dir, opts.grantsName || 'grants.json');
  writeGrants(grantsFile, opts.doc || grantDoc(keypair.publicKey.toBase58(), recipient.toBase58()));
  const socketPath = path.join(dir, `${opts.name || 'a'}.sock`);
  const ledgerFile = path.join(dir, `${opts.name || 'a'}-journal.jsonl`);
  const daemon = new Daemon({
    socketPath,
    keypair,
    grantFile: opts.grantsFile || grantsFile,
    ledgerFile,
  });
  await daemon.start();
  return { daemon, keypair, recipient, grantsFile, socketPath, ledgerFile };
}

module.exports = {
  futureIso, makeWire, grantDoc, writeGrants, tmpdir, hold, asNobody, startDaemon,
  Daemon, request, Keypair, SystemProgram, Transaction,
};
