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
 */
async function signViaDaemon({ socketPath, grant, wire, timeoutMs }) {
  return request({ socketPath, grant, wire, timeoutMs });
}

module.exports = { buildTransferWire, signViaDaemon, SIGNATURE_SLOT_BYTES };
