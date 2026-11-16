'use strict';

// THE CLIENT VERIFIES WHAT THE DAEMON SENT BACK — before anything is
// delivered, before anything is written, before the exit code claims success.
//
// WHY THIS MODULE EXISTS (measured 2026-11-16, on the published v0.2.28
// tree, tools/measure-client-verification.js):
//
//   The daemon verifies its own output (src/signer.js) — but the CLIENT
//   believed the socket. `signerd sign` decoded `response.signed` and wrote
//   it to `--out` with exit 0, and `sign-message` wrote `{receipt, pubkey,
//   sig}` the same way. Three faces, each measured live against a server
//   that answers exactly what a lying daemon would answer:
//
//     F1 SUBSTITUTED MESSAGE — the server returned a signed wire whose
//        message bytes differ from the wire the operator asked to have
//        signed (last byte flipped, signature slot overwritten). The CLI
//        wrote it to `--out`, exit 0. `message equal: false`.
//     F2 GARBAGE SIGNATURE — same message, but the 64-byte signature slot
//        holds random bytes that verify under NOTHING. The CLI wrote it,
//        exit 0. `signature verifies under fee payer key: false`.
//     F3 NO SIGNATURE AT ALL — `{ok:true}` with no `signed` field. The CLI
//        wrote a 0-byte file, exit 0.
//
//   The message path had the same hole from the CLI's side: the openreceipts
//   consumer (receipt.py) verifies before it writes, but `signerd
//   sign-message` itself did not — it handed back `{receipt, pubkey, sig}`
//   that nothing had checked.
//
//   What makes F1/F2 checkable with NO key material is the shape of a Solana
//   transaction: the fee payer's PUBLIC key is inside the message the client
//   itself built. So the client can verify the signature with Node's OpenSSL
//   ed25519 against a key it already holds in plaintext, and byte-compare the
//   message region against the wire it sent. A lying daemon cannot pass
//   either check: it does not hold the key, and changing the message fails
//   the byte comparison.
//
// THE ORDER (deliberate, and the same conservative direction as the daemon):
// shape first (cheap, no crypto), then the byte identity, then the
// signature. Every failure is a refusal with a named code and a repair —
// never a silent drop, never an exception the CLI would turn into a bare
// errno.

const crypto = require('node:crypto');
const { VersionedTransaction } = require('@solana/web3.js');
const { publicKeyObject, MESSAGE_OFFSET } = require('./signer');
const { canonicalReceiptBytes, verifyEd25519 } = require('./receipt-identity');

function refused(code, message, fix, detail) {
  return detail === undefined
    ? { ok: false, code, message, fix }
    : { ok: false, code, message, fix, detail };
}

/**
 * Verify the signed wire the daemon returned against the wire the client
 * asked to have signed.
 *
 * Checks, in order:
 *   1. there IS a signature field;
 *   2. same length as the request (a signature may only replace the slot);
 *   3. byte 0 — the signature count — is unchanged;
 *   4. the MESSAGE REGION (bytes from the signature slot onward) is
 *      byte-identical to the requested wire's message region;
 *   5. the signature slot is not all zeros;
 *   6. the signed wire parses, and the signature verifies under the fee
 *      payer's own public key (accountKeys[0] of the message), over the
 *      message bytes, with Node's OpenSSL ed25519.
 *
 * Returns { ok: true, messageBytes, signature } or a refusal.
 */
function verifySignedWire({ wire, signed }) {
  if (!Buffer.isBuffer(wire) && !(wire instanceof Uint8Array)) {
    return refused('signed_wire_invalid', 'the requested wire is not bytes',
      '  fix: build the wire with buildTransferWire()/signerd build-tx before signing');
  }
  if (signed === undefined || signed === null) {
    return refused('signed_missing', 'the daemon answered ok:true but returned no signature',
      '  fix: the daemon at --socket did not produce an artifact; check it is the real signerd ' +
      '(only the daemon\'s owner may bind that path) and retry');
  }
  const out = Buffer.isBuffer(signed) ? signed : Buffer.from(signed);
  const request = Buffer.isBuffer(wire) ? wire : Buffer.from(wire);
  if (out.length !== request.length) {
    return refused('signed_length_mismatch',
      `the returned wire is ${out.length} bytes, the requested wire is ${request.length}`,
      '  fix: the daemon returned something other than this transaction; treat the socket as untrusted ' +
      'and verify the daemon you are talking to',
      { returnedBytes: out.length, requestedBytes: request.length });
  }
  if (out[0] !== request[0]) {
    return refused('signed_count_mismatch',
      `the returned wire declares ${out[0]} signature(s), the requested wire declares ${request[0]}`,
      '  fix: the daemon returned something other than this transaction; treat the socket as untrusted');
  }
  if (!out.subarray(MESSAGE_OFFSET).equals(request.subarray(MESSAGE_OFFSET))) {
    return refused('signed_message_mismatch',
      'the returned wire does not carry the message that was asked to be signed',
      '  fix: the daemon at --socket answered for a DIFFERENT transaction; verify the daemon ' +
      '(only the daemon\'s owner may bind that path) before trusting anything it returns');
  }
  const signature = out.subarray(1, MESSAGE_OFFSET);
  if (signature.every((b) => b === 0)) {
    return refused('signed_signature_empty', 'the returned signature slot is all zeros',
      '  fix: the daemon at --socket did not actually sign; verify it is the real signerd and retry');
  }
  let transaction;
  try {
    transaction = VersionedTransaction.deserialize(out);
  } catch {
    return refused('signed_unparseable', 'the returned wire cannot be parsed as a transaction',
      '  fix: the daemon at --socket returned corrupt bytes; treat the socket as untrusted');
  }
  let messageBytes;
  try {
    messageBytes = Buffer.from(transaction.message.serialize());
  } catch {
    return refused('signed_unparseable', 'the returned message cannot be serialized',
      '  fix: the daemon at --socket returned corrupt bytes; treat the socket as untrusted');
  }
  // The bytes actually signed are the message region of the wire itself:
  // for the one-signature legacy shape the client asks for, that is exactly
  // what web3.js serializes (measured: msg == wire.subarray(65)).
  const signedBytes = out.subarray(MESSAGE_OFFSET);
  let verified = false;
  try {
    const feePayer = transaction.message.accountKeys[0];
    verified = crypto.verify(null, signedBytes,
      publicKeyObject(feePayer.toBase58()), signature);
  } catch {
    verified = false;
  }
  if (!verified) {
    return refused('signed_signature_invalid',
      'the returned signature does not verify under the fee payer\'s public key',
      '  fix: the daemon at --socket returned a signature made by some other key or over other bytes; ' +
      'do not broadcast it — verify the daemon you are talking to');
  }
  return { ok: true, messageBytes: signedBytes.length, signature: signature.toString('base64') };
}

/**
 * Verify the receipt signature the daemon returned against the body the
 * client asked to have signed, under the public key the response carries.
 *
 * This is the message-path twin of verifySignedWire: the canonical bytes
 * are derived HERE, from the body the client itself sent, so a daemon that
 * signed something else cannot pass. The returned `pubkey` is NOT a trust
 * anchor (the daemon chose it) — pinning the key is the consumer's job, as
 * openreceipts' receipt.py does. What this catches is substitution of the
 * message and signatures that verify under nothing at all.
 */
function verifyMessageSignature({ body, response }) {
  if (response === null || typeof response !== 'object') {
    return refused('signed_missing', 'the daemon returned no answer',
      '  fix: the daemon at --socket did not answer; check it is running and owned by you');
  }
  if (typeof response.signature !== 'string' || typeof response.pubkey !== 'string') {
    return refused('signed_missing', 'the daemon answered ok:true but returned no signature',
      '  fix: the daemon at --socket did not produce an artifact; verify it is the real signerd');
  }
  const pubkey = Buffer.from(response.pubkey, 'base64');
  if (pubkey.length !== 32) {
    return refused('signed_pubkey_invalid', 'the returned public key is not 32 bytes',
      '  fix: the daemon at --socket returned a malformed key; treat the socket as untrusted');
  }
  let messageBytes;
  try {
    messageBytes = canonicalReceiptBytes(body);
  } catch {
    return refused('signed_body_invalid', 'the receipt body cannot be canonicalized',
      '  fix: the body must be a JSON object (see `signerd sign-message --body`)');
  }
  let signature;
  try {
    signature = Buffer.from(response.signature, 'base64');
  } catch {
    signature = Buffer.alloc(0);
  }
  if (signature.length !== 64) {
    return refused('signed_signature_invalid', 'the returned signature is not 64 bytes',
      '  fix: the daemon at --socket returned a malformed signature; treat the socket as untrusted');
  }
  if (typeof response.messageSha256 === 'string') {
    const digest = crypto.createHash('sha256').update(messageBytes).digest('hex');
    if (digest !== response.messageSha256) {
      return refused('signed_message_mismatch',
        'the daemon\'s message hash does not match the body that was asked to be signed',
        '  fix: the daemon at --socket answered for a DIFFERENT body; verify the daemon before trusting it',
        { expected: digest, returned: response.messageSha256 });
    }
  }
  if (!verifyEd25519(pubkey, messageBytes, signature)) {
    return refused('signed_signature_invalid',
      'the returned signature does not verify under the returned public key',
      '  fix: the daemon at --socket returned a signature over other bytes, or made by another key; ' +
      'do not write it — verify the daemon you are talking to');
  }
  return { ok: true, messageBytes: messageBytes.length, signature: response.signature, pubkey: response.pubkey };
}

module.exports = { verifySignedWire, verifyMessageSignature };
