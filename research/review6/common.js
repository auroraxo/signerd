'use strict';
// Shared helpers for review-6 adversarial probes (read-only against src/).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Daemon, request } = require('../../src/daemon');

const KSPASS = 'keystore passphrase review6';
const SEALPASS = 'grant seal passphrase review6';
const JSEALPASS = 'journal seal passphrase review6';

function futureIso(hours = 48) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function makeWire(kp, dest, lamports = 42) {
  const tx = new Transaction();
  tx.feePayer = kp.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
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
        maxLamports: opts.maxLamports || '1000000',
        expiresAt: opts.expiresAt || futureIso(),
        windowMaxLamports: opts.windowMaxLamports || '1000000',
        windowSeconds: opts.windowSeconds || '3600',
      },
    },
  };
}

function writeJson(file, obj, mode = 0o600) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n');
  fs.chmodSync(file, mode);
  return file;
}

function writeFile(file, text, mode = 0o600) {
  fs.writeFileSync(file, text);
  fs.chmodSync(file, mode);
  return file;
}

function tmpdir(prefix = 'signerd-r6-') {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(d, 0o700);
  return d;
}

/**
 * A complete local fixture: keystore, keypair, two recipients (honest +
 * attacker), grant file, ledger path, socket path. No network, no real keys.
 */
function fixture(dir, opts = {}) {
  const keystore = path.join(dir, 'ops.key');
  if (!fs.existsSync(keystore)) {
    require('../../src/keystore').createKeystore({ file: keystore, passphrase: KSPASS });
  }
  const { loadKeystore } = require('../../src/keystore');
  const keypair = loadKeystore({ file: keystore, passphrase: KSPASS });
  const honest = Keypair.generate().publicKey.toBase58();
  const attacker = Keypair.generate().publicKey.toBase58();
  const grantFile = path.join(dir, opts.grantName || 'grants.json');
  if (!fs.existsSync(grantFile)) writeJson(grantFile, grantDoc(keypair.publicKey.toBase58(), honest));
  return {
    keystore,
    keypair,
    honest,
    attacker,
    grantFile,
    ledgerFile: path.join(dir, opts.ledgerName || 'journal.jsonl'),
    socketPath: path.join(dir, opts.socketName || 'signerd.sock'),
    sealPassFile: path.join(dir, 'seal.pass'),
    jsealPassFile: path.join(dir, 'jseal.pass'),
  };
}

/** Start a daemon with a delay-free stop; returns {daemon, socketPath}. */
async function start(f, extra = {}) {
  const daemon = new Daemon({
    socketPath: f.socketPath,
    keystorePath: f.keystore,
    passphrase: KSPASS,
    grantFile: f.grantFile,
    ledgerFile: f.ledgerFile,
    ...extra,
  });
  await daemon.start();
  return daemon;
}

async function stop(daemon) {
  if (daemon) { try { await daemon.stop(); } catch { /* already stopped */ } }
}

function verdict(o) {
  process.stdout.write(JSON.stringify(o, null, 2) + '\n');
  return o;
}

module.exports = {
  KSPASS, SEALPASS, JSEALPASS,
  futureIso, makeWire, grantDoc, writeJson, writeFile, tmpdir, fixture,
  start, stop, verdict, Daemon, request,
};
