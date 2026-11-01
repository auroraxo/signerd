'use strict';

// Independent review #9 — shared fixture (my own; NOT the review-7 helper).
//
// A LIVE signerd daemon over a real Unix socket, built the same way the
// message e2e test builds it, so every probe measures the product path
// (real socket, real ledger, real signer), never a mock.
//
// Everything here is MY code: the review-7 helper was NOT used, so a bug in
// the author's harness cannot mask or manufacture a finding.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Keypair } = require('@solana/web3.js');

const { Daemon, request } = require('../../src/daemon');
const { importKeystore } = require('../../src/keystore');
const { canonicalReceiptBytes } = require('../../src/receipt-identity');

const PASSPHRASE = 'independent review9 envelope passphrase';

/** Ed25519 public key as base64 (the openreceipts encoding). */
function publicKeyB64(keypair) {
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    keypair.publicKey.toBytes(),
  ]);
  const jwk = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })
    .export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

function futureIso(seconds = 3600) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

/** A grant with the daemon's own key pinned, valid for `seconds`. */
function messageGrant(pubB64, overrides = {}) {
  return {
    kind: 'message',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    pubkey: pubB64,
    maxBytes: '700',
    expiresAt: futureIso(),
    windowMaxMessages: '5',
    windowSeconds: '3600',
    ...overrides,
  };
}

/** A valid receipt body. */
function body(overrides = {}) {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, '+00:00'),
    claims: { version: 'v0.1.0', channel: 'dev' },
    ...overrides,
  };
}

async function fixture({ grantOverrides = {}, grants } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-review9-'));
  const keypair = Keypair.generate();
  const rawSecret = path.join(dir, 'secret.raw');
  fs.writeFileSync(rawSecret, Buffer.from(keypair.secretKey.subarray(0, 64)), { mode: 0o600 });

  const keystore = path.join(dir, 'ops.key');
  importKeystore({ file: keystore, passphrase: PASSPHRASE, from: rawSecret });

  const pubB64 = publicKeyB64(keypair);
  const grantFile = path.join(dir, 'grants.json');
  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');

  const grantDoc = grants || { releases: messageGrant(pubB64, grantOverrides) };
  fs.writeFileSync(grantFile,
    JSON.stringify({ version: 1, grants: grantDoc }, null, 2), { mode: 0o600 });

  const daemon = new Daemon({
    socketPath, keystorePath: keystore, passphrase: PASSPHRASE, grantFile, ledgerFile,
  });
  await daemon.start();

  const stop = () => { try { daemon.stop(); } catch { /* already stopped */ } };
  return {
    dir, keypair, pubB64, daemon, stop, socketPath, ledgerFile, grantFile,
    sign: (grant, b) => request({ socketPath, grant, body: JSON.stringify(b) }),
    signText: (grant, text) => request({ socketPath, grant, body: text }),
    messageGrant: (o) => messageGrant(pubB64, o),
    cleanup: () => { stop(); fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

/** PASS = the claimed guarantee holds. VIOLATION = it does not, on THIS tree. */
function verdict(label, ok, detail) {
  console.log(`${ok ? 'PASS' : 'VIOLATION'}  ${label}${detail ? ` -- ${detail}` : ''}`);
  return ok;
}

/** OpenSSL verify of a daemon response's signature over the canonical bytes. */
function opensslVerifies(keypair, b, signatureB64) {
  try {
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
  } catch {
    return false;
  }
}

module.exports = {
  fixture, body, futureIso, publicKeyB64, canonicalReceiptBytes, verdict,
  opensslVerifies, messageGrant, PASSPHRASE,
};
