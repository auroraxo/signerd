'use strict';

const { PublicKey, SystemProgram, Transaction } = require('@solana/web3.js');
const { request } = require('./daemon');

// A legacy Solana message carries exactly one signature slot, so the unsigned
// wire is: 1 byte signature count, 64 zero bytes of signature, then the
// message. The client fills the slot with zeros; only the daemon may fill it.
const SIGNATURE_SLOT_BYTES = 65;

/**
 * Build the UNSIGNED wire for a single legacy System transfer.
 *
 * This is the part that makes a client able to ask for a signature without
 * holding a key: a legacy transaction message needs the fee payer's PUBLIC
 * key and the instruction, never the secret. The signature slot is left as
 * zeros for the daemon to fill.
 *
 * The result is exactly the shape the daemon's policy accepts; a client that
 * builds anything else gets a structured refusal, not a signature.
 */
function buildTransferWire({ fromPubkey, toPubkey, lamports, blockhash }) {
  const from = typeof fromPubkey === 'string' ? new PublicKey(fromPubkey) : fromPubkey;
  const to = typeof toPubkey === 'string' ? new PublicKey(toPubkey) : toPubkey;
  if (!Number.isSafeInteger(lamports) || lamports < 0) throw new TypeError('lamports must be a non-negative integer');
  if (typeof blockhash !== 'string' || blockhash.length === 0) throw new TypeError('blockhash is required');
  const transaction = new Transaction();
  transaction.feePayer = from;
  transaction.recentBlockhash = blockhash;
  transaction.add(SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports }));
  // requireAllSignatures:false + verifySignatures:false makes web3.js emit the
  // zero signature slot instead of refusing to serialize an unsigned message.
  const wire = Buffer.from(transaction.serialize({ requireAllSignatures: false, verifySignatures: false }));
  if (wire.length < SIGNATURE_SLOT_BYTES + 1) throw new Error('wire_too_short');
  return wire;
}

/**
 * Ask the daemon to sign a wire.
 *
 * Returns the daemon's answer verbatim: either { ok: true, signed, ... } or
 * { ok: false, error, ... }. A refusal is data, not an exception — the caller
 * is expected to learn WHY it was refused instead of working around it.
 *
 * `dry: true` asks for the VERDICT without the signature: the daemon runs
 * the same policy and the same budget decision, returns { ok: true, dry: true,
 * allowed: true, ... } with no `signed` wire, and journals nothing (no
 * replay entry, no window spend). The same wire can then still be signed for
 * real.
 */
async function signViaDaemon({ socketPath, grant, wire, timeoutMs, dry }) {
  return request({ socketPath, grant, wire, timeoutMs, dry: dry === true ? true : undefined });
}

/**
 * Build an openreceipts/v1 receipt BODY for the message-grant envelope.
 *
 * The body is built from public values only (issuer name, type, subject,
 * claims, note, issued_at) - no key material is involved, and the daemon
 * signs the canonical bytes it derives from this object.
 *
 * issuedAt is OPTIONAL here on purpose: when absent the helper stamps the
 * current UTC time, matching receipt.py's own default (review #9, R9-2 —
 * before this, omitting issuedAt produced a body the daemon ALWAYS refuses
 * with 'envelope', because 84888d4 made issued_at a required field). An
 * explicit issuedAt (the daily runner's own stamp, a backdate, an offset
 * spelling) is used verbatim.
 */
function buildReceiptBody({ issuer, type, subject, claims = {}, note, issuedAt }) {
  if (typeof issuer !== 'string' || issuer.length === 0) throw new TypeError('issuer is required');
  if (typeof type !== 'string' || type.length === 0) throw new TypeError('type is required');
  if (typeof subject !== 'string' || subject.length === 0) throw new TypeError('subject is required');
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new TypeError('claims must be an object');
  }
  const body = {
    schema: 'openreceipts/v1',
    issuer,
    type,
    subject,
    issued_at: typeof issuedAt === 'string'
      ? issuedAt
      : new Date().toISOString().replace(/\.\d{3}Z$/, '+00:00'),
    claims: { ...claims },
  };
  if (typeof note === 'string') body.note = note;
  return body;
}

/**
 * Ask the daemon to sign a receipt body (the message-grant envelope).
 *
 * The body travels as a JSON TEXT; the daemon parses it and signs the
 * canonical bytes derived from the parsed value. A refusal is data, not an
 * exception.
 *
 * `dry: true` asks for the VERDICT without the signature (same contract as
 * signViaDaemon): nothing is signed and nothing is journaled.
 */
async function signMessageViaDaemon({ socketPath, grant, body, timeoutMs, dry }) {
  return request({ socketPath, grant, body: JSON.stringify(body), timeoutMs, dry: dry === true ? true : undefined });
}

module.exports = {
  buildTransferWire, signViaDaemon, SIGNATURE_SLOT_BYTES,
  buildReceiptBody, signMessageViaDaemon,
};
