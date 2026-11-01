'use strict';

const crypto = require('node:crypto');
const { evaluateMessage } = require('./policy-message');
const { rawPublicKeyFromJwk } = require('./receipt-identity');

// The message-path twin of src/signer.js: evaluate a receipt body, spend the
// ledger approval, sign the canonical bytes, verify independently, and only
// then hand the signature out. Same deliberate order, same conservative
// failure direction:
//   1. key/grant mismatch is refused BEFORE any ledger write;
//   2. the ledger makes the exact message unforgeable-twice and fsyncs
//      BEFORE signing;
//   3. signing and independent verification happen AFTER the budget is
//      durably recorded — if they fail, the replay entry is burned and
//      nothing is signed (the conservative direction: the same bytes can
//      never silently succeed on a later attempt).
//
// The signature is produced with @noble/curves' ed25519 (the implementation
// @solana/web3.js itself depends on) and verified under Node's OpenSSL
// ed25519 — two independent implementations must agree before a signature
// leaves this function.
const { ed25519 } = require('@noble/curves/ed25519.js');

const SEED_BYTES = 32;

function refused(reason, extra) {
  return extra === undefined
    ? { allowed: false, refused: reason }
    : { allowed: false, refused: reason, ...extra };
}

/**
 * The raw 32-byte Ed25519 public key this daemon holds, derived from the
 * keystore's seed (web3.js secretKey layout: 32-byte seed, then public key).
 * Returned as base64 — the same encoding openreceipts writes into
 * `"pubkey"` and the same encoding the grant pins in `pubkey`.
 */
function messagePublicKey(keypair) {
  if (keypair === null || typeof keypair !== 'object' ||
      keypair.secretKey === undefined) return null;
  const secret = Buffer.from(keypair.secretKey);
  if (secret.length !== 64) return null;
  return Buffer.from(ed25519.getPublicKey(secret.subarray(0, SEED_BYTES))).toString('base64');
}

/**
 * The grant's pinned public key as a KeyObject, or null when it does not
 * decode / does not match the daemon key's actual public key.
 */
function grantPublicKeyObject(keypair, pubkeyB64) {
  const actual = messagePublicKey(keypair);
  if (actual === null || actual !== pubkeyB64) return null;
  try {
    return rawPublicKeyFromJwk(Buffer.from(pubkeyB64, 'base64'));
  } catch {
    return null;
  }
}

/**
 * Sign one already grant-verified receipt body.
 *
 * `body` is the parsed receipt object; the canonical bytes signed are the
 * ones policy-message derives, so the caller cannot choose different bytes
 * than the ones the grant was checked against.
 */
function signMessageApproved({ body, grant, ledger, keypair, now = new Date() }) {
  const pubkey = messagePublicKey(keypair);
  if (pubkey === null) return refused('signer_unavailable');
  const pinned = grant && typeof grant === 'object'
    ? Object.getOwnPropertyDescriptor(grant, 'pubkey') : undefined;
  if (!pinned || !('value' in pinned) || typeof pinned.value !== 'string') {
    return refused('invalid_grant');
  }
  const publicKeyObject = grantPublicKeyObject(keypair, pinned.value);
  // Refuse BEFORE spending budget: a grant this key cannot satisfy must
  // never reach the ledger (same direction as signer.js).
  if (publicKeyObject === null) return refused('signer_key_mismatch');

  const verdict = evaluateMessage(body, grant, now);
  if (!verdict.allowed) return verdict;

  const approval = ledger.approveMessage({
    messageBytes: verdict.messageBytes,
    messageSha256: verdict.messageSha256,
    grant, now,
  });
  if (!approval.allowed) return approval;

  let signature;
  try {
    const seed = Buffer.from(keypair.secretKey).subarray(0, SEED_BYTES);
    signature = Buffer.from(ed25519.sign(verdict.messageBytes, seed));
  } catch {
    return refused('sign_failed', { budget: 'consumed' });
  }

  // The artifact we hand back must verify under Node's OpenSSL ed25519 with
  // the key the grant pinned. A signature that fails this never leaves.
  let verified = false;
  try {
    verified = crypto.verify(null, verdict.messageBytes, publicKeyObject, signature);
  } catch {
    verified = false;
  }
  if (!verified) return refused('sign_verify_failed', { budget: 'consumed' });

  return {
    allowed: true,
    signature: signature.toString('base64'),
    messageSha256: verdict.messageSha256,
    messageBytes: verdict.messageBytes.length,
    pubkey,
    seq: approval.seq,
    windowMessages: approval.windowMessages,
    windowRemainingMessages: approval.windowRemainingMessages,
  };
}

module.exports = { signMessageApproved, messagePublicKey, MESSAGE_SEED_BYTES: SEED_BYTES };
