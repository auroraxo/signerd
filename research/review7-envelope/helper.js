'use strict';

// Shared fixture for the review #7 (message-grant envelope) probes:
// a LIVE daemon over a Unix socket, built the same way the message e2e
// test builds it, so every probe measures the product path, not a mock.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Keypair } = require('@solana/web3.js');

const { Daemon, request } = require('../../src/daemon');
const { importKeystore } = require('../../src/keystore');
const { canonicalReceiptBytes } = require('../../src/receipt-identity');

const PASSPHRASE = 'review7 envelope probe passphrase';

function futureIso(seconds = 3600) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

/** Ed25519 public key as base64, via OpenSSL (not the product code). */
function publicKeyB64(keypair) {
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    keypair.publicKey.toBytes(),
  ]);
  const jwk = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })
    .export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

function body(overrides = {}) {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-01T00:00:00+00:00',
    claims: { version: 'v0.1.0', channel: 'dev' },
    ...overrides,
  };
}

async function fixture({ grantOverrides = {}, grants } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-review7-'));
  const keypair = Keypair.generate();
  const rawSecret = path.join(dir, 'secret.raw');
  fs.writeFileSync(rawSecret, Buffer.from(keypair.secretKey.subarray(0, 64)), { mode: 0o600 });

  const keystore = path.join(dir, 'ops.key');
  importKeystore({ file: keystore, passphrase: PASSPHRASE, from: rawSecret });

  const pubB64 = publicKeyB64(keypair);
  const grantFile = path.join(dir, 'grants.json');
  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');

  const messageGrant = (overrides = {}) => ({
    kind: 'message',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    pubkey: pubB64,
    maxBytes: '700',
    expiresAt: futureIso(),
    windowMaxMessages: '5',
    windowSeconds: '3600',
    ...grantOverrides,
    ...overrides,
  });

  const grantDoc = grants || { releases: messageGrant() };
  fs.writeFileSync(grantFile,
    JSON.stringify({ version: 1, grants: grantDoc }, null, 2), { mode: 0o600 });

  const daemon = new Daemon({
    socketPath, keystorePath: keystore, passphrase: PASSPHRASE, grantFile, ledgerFile,
  });
  await daemon.start();

  const stop = () => { try { daemon.stop(); } catch { /* already stopped */ } };
  return {
    dir, keypair, pubB64, daemon, stop, socketPath, ledgerFile,
    sign: (grant, b) => request({ socketPath, grant, body: JSON.stringify(b) }),
    messageGrant, grantFile,
    cleanup: () => { stop(); fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

function verdict(label, ok, detail) {
  console.log(`${ok ? 'PASS' : 'VIOLATION'}  ${label}${detail ? ` -- ${detail}` : ''}`);
  return ok;
}

/** OpenSSL verify of a daemon response's signature over canonical bytes. */
function opensslVerifies(keypair, b, signatureB64) {
  return crypto.verify(
    null,
    canonicalReceiptBytes(b),
    crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        keypair.publicKey.toBytes(),
      ]),
      format: 'der',
      type: 'spki',
    }),
    Buffer.from(signatureB64, 'base64'),
  );
}

module.exports = {
  fixture, body, futureIso, publicKeyB64, canonicalReceiptBytes, verdict,
  opensslVerifies, PASSPHRASE,
};
