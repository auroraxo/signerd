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
 * Read a grant field from the object's OWN properties only, as a plain data
 * value. Inherited or accessor properties are refused: a polluted
 * Object.prototype must never be able to supply a grant field, and a getter
 * could return a different value on a second read (TOCTOU).
 */
function ownField(source, key) {
  if (source === null || typeof source !== 'object') return { ok: false };
  const descriptor = Object.getOwnPropertyDescriptor(source, key);
  if (!descriptor || !('value' in descriptor)) return { ok: false };
  return { ok: true, value: descriptor.value };
}

/**
 * Read the clock exactly once, and only from a real Date. A Date subclass can
 * override getTime() to lie about "now"; the caller must not be able to
 * resurrect an expired grant by passing a forged clock.
 */
function readClock(now) {
  if (!(now instanceof Date)) return NaN;
  if (Object.getPrototypeOf(now) !== Date.prototype) return NaN;
  const value = now.getTime();
  return Number.isFinite(value) ? value : NaN;
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
  const signerField = ownField(grant, 'signer');
  const destinationField = ownField(grant, 'destination');
  const maximumField = ownField(grant, 'maxLamports');
  const expiryField = ownField(grant, 'expiresAt');
  if (!signerField.ok || !destinationField.ok || !maximumField.ok || !expiryField.ok) {
    return refused('invalid_grant');
  }
  const signer = parseKey(signerField.value);
  const destination = parseKey(destinationField.value);
  const maximum = parseLamports(maximumField.value);
  const timestamp = typeof expiryField.value === 'string' &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(expiryField.value)
    ? expiryField.value : null;
  const expiry = timestamp === null ? NaN : Date.parse(timestamp);
  // Date.parse normalizes impossible calendar dates (e.g. February 30) instead
  // of rejecting them. A normalized expiry could silently extend a grant.
  const canonical = Number.isFinite(expiry) ? new Date(expiry).toISOString() : null;
  if (!signer || !destination || maximum === null || !Number.isFinite(expiry) ||
      canonical !== timestamp.replace(/(\.\d{1,3})?Z$/, (_, fraction) =>
        `${fraction ? (fraction + '000').slice(0, 4) : '.000'}Z`)) return refused('invalid_grant');
  const nowMs = readClock(now);
  if (!Number.isFinite(nowMs)) return refused('invalid_clock');
  if (nowMs >= expiry) return refused('expired');

  // Version-1 wire begins with the 0x81 prefix. Measured 2026-11-02 on two
  // independent samples of finalized mainnet blocks (4,465 transactions,
  // 100% JSON<->wire paired, tools/wire-prefix.mjs, output
  // research/first-byte-distribution-2026-11-02.json): byte 0 is 0x81 in
  // 2005/2005 v1 transactions, while legacy and v0 wire begins with the
  // compact-u16 signature count (0x01..0x05 in 2460/2460) - and inside this
  // 1232-byte cap at most 17 signatures fit, so that count can never reach
  // 0x80. Byte 0 >= 0x80 under the cap therefore cannot be legacy or v0: it
  // is versioned message wire or corrupt bytes, and both must refuse.
  //
  // Classified BEFORE any parsing on purpose: the pinned web3.js 1.98.4
  // cannot deserialize v1 wire at all and would return the generic
  // invalid_wire — the same reason a caller gets for three corrupt bytes —
  // while web3.js 3.1.1 parses it cleanly. The reason a caller sees must be a
  // property of the wire, not of whichever library is installed. The size
  // check above runs first, so an over-cap buffer is still invalid_wire.
  if (wire[0] >= 0x80) return refused('version_or_alt');

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

module.exports = { evaluate, ownField, readClock };
