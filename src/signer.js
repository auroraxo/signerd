'use strict';

const crypto = require('node:crypto');
const bs58 = require('bs58');
const { VersionedTransaction } = require('@solana/web3.js');
const { gate } = require('./ledger');

const SIGNATURE_BYTES = 64;
// Versioned wire layout: compact-u16 signature count (1 byte for count === 1),
// then 64 signature bytes, then the message. Policy guarantees exactly one
// required signature, so the message starts at this offset.
const MESSAGE_OFFSET = 1 + SIGNATURE_BYTES;

function refused(reason, extra) {
  return extra === undefined
    ? { allowed: false, refused: reason }
    : { allowed: false, refused: reason, ...extra };
}

/**
 * Build the DER SPKI wrapper for a raw 32-byte Ed25519 public key so Node's
 * OpenSSL-backed verify() can check a signature produced by tweetnacl inside
 * web3.js. Two independent implementations must agree before a signature is
 * ever returned.
 */
function publicKeyObject(publicKeyBase58) {
  const raw = Buffer.from(bs58.decode(publicKeyBase58));
  if (raw.length !== 32) throw new Error('invalid_public_key');
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * Sign one already policy-verified transaction.
 *
 * Order is deliberate and fail-closed:
 *  1. key/grant mismatch is refused BEFORE any ledger write;
 *  2. gate() makes the spend/replay decision and fsyncs it BEFORE signing;
 *  3. signing, and only then independent verification, happen AFTER the
 *     budget is durably recorded.
 * If step 3 fails, budget has been burned without a signature leaving this
 * function. That is the conservative direction: spend is consumed, nothing
 * is signed. It can never sign twice for one approval.
 *
 * Byte-identity invariants checked before returning (a signature may only
 * ever replace the signature slot, never touch the approved message):
 *  - the returned wire has the same length as the approved wire;
 *  - bytes before and after the 64-byte signature slot are identical;
 *  - the message bytes re-serialize identically;
 *  - the signature verifies under Node's OpenSSL ed25519 implementation;
 *  - the returned wire is itself still policy-valid (evaluate() passes).
 */
function signApproved({ wire, grant, ledger, keypair, now = new Date() }) {
  if (!Buffer.isBuffer(wire) && !(wire instanceof Uint8Array)) return refused('invalid_wire');
  const grantSigner = grant && typeof grant === 'object'
    ? Object.getOwnPropertyDescriptor(grant, 'signer') : undefined;
  if (!grantSigner || !('value' in grantSigner) || typeof grantSigner.value !== 'string') {
    return refused('invalid_grant');
  }
  if (keypair === null || typeof keypair !== 'object' ||
      keypair.publicKey === undefined || keypair.secretKey === undefined) {
    return refused('signer_unavailable');
  }
  // Refuse before spending budget: a grant the daemon key cannot satisfy must
  // never reach the ledger.
  if (keypair.publicKey.toBase58() !== grantSigner.value) return refused('signer_key_mismatch');

  const verdict = gate(wire, grant, now, ledger);
  if (!verdict.allowed) return verdict;

  const input = Buffer.from(wire);
  let transaction;
  try {
    transaction = VersionedTransaction.deserialize(input);
    transaction.sign([keypair]);
  } catch {
    return refused('sign_failed', { budget: 'consumed' });
  }
  const signed = Buffer.from(transaction.serialize());

  if (signed.length !== input.length ||
      signed[0] !== input[0] ||
      !signed.subarray(0, MESSAGE_OFFSET - SIGNATURE_BYTES).equals(
        input.subarray(0, MESSAGE_OFFSET - SIGNATURE_BYTES)) ||
      !signed.subarray(MESSAGE_OFFSET).equals(input.subarray(MESSAGE_OFFSET))) {
    return refused('sign_verify_failed', { budget: 'consumed' });
  }

  let verified;
  try {
    const message = Buffer.from(transaction.message.serialize());
    const signature = Buffer.from(transaction.signatures[0]);
    if (signature.length !== SIGNATURE_BYTES || signature.every((b) => b === 0)) {
      return refused('sign_verify_failed', { budget: 'consumed' });
    }
    verified = crypto.verify(null, message, publicKeyObject(grantSigner.value), signature);
  } catch {
    verified = false;
  }
  if (!verified) return refused('sign_verify_failed', { budget: 'consumed' });

  // The artifact we hand back must itself pass the policy it was approved by.
  let recheck;
  try {
    const { evaluate } = require('./policy');
    recheck = evaluate(signed, grant, now);
  } catch {
    recheck = { allowed: false };
  }
  if (!recheck.allowed) return refused('sign_verify_failed', { budget: 'consumed' });

  return {
    allowed: true,
    signed: signed,
    signature: bs58.encode(Buffer.from(transaction.signatures[0])),
    amountLamports: verdict.amountLamports,
    feeLamports: verdict.feeLamports,
    totalLamports: verdict.totalLamports,
    wireSha256: verdict.wireSha256,
    seq: verdict.seq,
    windowSpentLamports: verdict.windowSpentLamports,
    windowRemainingLamports: verdict.windowRemainingLamports,
  };
}

module.exports = { signApproved, publicKeyObject, MESSAGE_OFFSET };
