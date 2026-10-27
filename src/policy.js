'use strict';

const bs58 = require('bs58');
const { PublicKey, SystemProgram, VersionedTransaction } = require('@solana/web3.js');

const MAX_WIRE_BYTES = 1232;
const MAX_U64 = (1n << 64n) - 1n;

function refused(reason) {
  return { allowed: false, refused: reason };
}

function parseLamports(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const amount = BigInt(value);
  return amount <= MAX_U64 ? amount : null;
}

function parseKey(value) {
  try {
    const key = new PublicKey(value);
    if (key.toBase58() !== value) return null;
    return key;
  } catch {
    return null;
  }
}

/**
 * A deliberately tiny policy evaluation, NOT a signer or a secure daemon.
 * Only a single legacy SystemProgram.transfer with exactly three static keys
 * and one signer can pass. An allowed verdict authorizes nothing beyond this
 * one parsed message; it does not enforce replay, window limits or network fees.
 * Grant values are strings (never floating-point lamport numbers).
 */
function evaluate(raw, grant, now = new Date()) {
  if (!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) return refused('invalid_wire');
  const wire = Buffer.from(raw);
  if (!wire.length || wire.length > MAX_WIRE_BYTES) return refused('invalid_wire');
  const signer = parseKey(grant?.signer);
  const destination = parseKey(grant?.destination);
  const maximum = parseLamports(grant?.maxLamports);
  const expiry = typeof grant?.expiresAt === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(grant.expiresAt)
    ? Date.parse(grant.expiresAt) : NaN;
  if (!signer || !destination || maximum === null || !Number.isFinite(expiry)) return refused('invalid_grant');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) return refused('invalid_clock');
  if (now.getTime() >= expiry) return refused('expired');

  let transaction;
  try {
    transaction = VersionedTransaction.deserialize(wire);
    if (!Buffer.from(transaction.serialize()).equals(wire)) return refused('noncanonical_wire');
  } catch {
    return refused('invalid_wire');
  }
  // Refuse every v0 transaction, including one without lookups. ALT data is
  // not present in transaction bytes, so this refuses it before account access.
  if (transaction.version !== 'legacy') return refused('version_or_alt');
  const message = transaction.message;
  const keys = message.accountKeys;
  const h = message.header;
  if (h.numRequiredSignatures !== 1 || h.numReadonlySignedAccounts !== 0 ||
      h.numReadonlyUnsignedAccounts !== 1 || transaction.signatures.length !== 1 ||
      keys.length !== 3 || message.instructions.length !== 1) return refused('envelope');
  if (keys[0].equals(keys[1]) || keys[0].equals(keys[2]) || keys[1].equals(keys[2])) return refused('duplicate_key');
  if (!keys[0].equals(signer)) return refused('signer_or_fee_payer');
  if (!keys[1].equals(destination)) return refused('destination');
  if (!keys[2].equals(SystemProgram.programId)) return refused('program');
  const instruction = message.instructions[0];
  if (instruction.programIdIndex !== 2 || instruction.accounts.length !== 2 ||
      instruction.accounts[0] !== 0 || instruction.accounts[1] !== 1) return refused('instruction_accounts');
  // web3.js legacy Message decodes instruction data to base58 strings;
  // Buffer.from(string) would incorrectly inspect ASCII text, not wire bytes.
  let data;
  try { data = Buffer.from(bs58.decode(instruction.data)); } catch { return refused('instruction_data'); }
  if (data.length !== 12 || data.readUInt32LE(0) !== 2) return refused('instruction_data');
  const amount = data.readBigUInt64LE(4);
  if (amount > maximum) return refused('amount');
  return { allowed: true, amountLamports: amount.toString() };
}

module.exports = { evaluate };
