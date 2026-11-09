'use strict';

// ONE source of truth for the VALUE SEMANTICS of a grant.
//
// WHY THIS MODULE EXISTS (measured 2026-11-08, on this tree):
//
//   The runtime judged grant values by their MEANING - a real 32-byte
//   canonical public key, a canonical RFC3339 instant, a cap inside u64, a
//   window inside the safe-integer range - while the CREATION path and the
//   LOADER judged them by their SHAPE: a base58 charset regex, a
//   calendar-SHAPE regex, digits-only regexes. Date.parse normalizes
//   impossible calendar dates instead of rejecting them, so
//   `grant-add --expires 2030-02-31T00:00:00Z` exited 0, wrote the file,
//   and every later request against that scope came back `invalid_grant`.
//   Measured with tools/measure-grant-value-contract.mjs: 16 of 30 cases
//   were written by the creation path and refused by the runtime
//   (research/grant-value-contract-2026-11-08.json, slot "before").
//
//   The rule was duplicated - and hand-kept - in five places
//   (src/policy.js, src/policy-message.js, src/ledger.js,
//   src/grantfile.js, src/grantadd.js). Five copies of one rule is what
//   let them drift; there is one copy now, and every site imports it.
//
// WHAT THESE FUNCTIONS ANSWER (all pure, all offline):
//   isCanonicalPublicKey(v)  a real 32-byte key in canonical base58
//   isCanonicalExpiry(v)     an instant that EXISTS and is canonical
//   isU64(v)                 a decimal integer in [0, 2^64-1]
//   isWindowMaxLamports(v)   a window cap the daemon can HONOUR: a decimal
//                             integer in [5000, 2^64-1] (the base fee every
//                             approval costs is the floor)
//   isWindowSeconds(v)       a positive safe integer (the ledger's clock)
//   isMessageCount(v)        a POSITIVE count in [1, MAX_SAFE_INTEGER]
//
// WHY THE EXPIRY RULE IS A ROUND TRIP (not a regex): a regex can describe
// the SHAPE of a timestamp, not whether the moment exists. "2030-02-31"
// has the shape of a date and is not one; Date.parse quietly moves it to
// March 2/3, which would silently EXTEND a grant past what the operator
// wrote. The round trip (parse, re-serialize, compare) is the only check
// that knows what was actually written - the same rule policy.js already
// used at request time, now shared.

const { PublicKey } = require('@solana/web3.js');

// The u64 ceiling the Solana runtime uses for lamport amounts.
const MAX_U64 = (1n << 64n) - 1n;
// The clock the ledger computes with: milliseconds since the epoch, so the
// window in seconds must stay a SAFE integer (Number.isSafeInteger) or the
// arithmetic silently loses precision.
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// The SHAPE of the expiry: RFC3339 with a 'Z' offset and at most
// millisecond precision. The shape is necessary but NOT sufficient - see
// isCanonicalExpiry.
const EXPIRES_SHAPE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;
// Digits only, no leading zeros (except "0" itself).
const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * A canonical base58 public key: it decodes to exactly 32 bytes AND
 * re-encodes to the very same string. The round trip is what rules out a
 * spelling that means something else than it looks like.
 */
function isCanonicalPublicKey(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    const key = new PublicKey(value);
    return key.toBase58() === value;
  } catch {
    return false;
  }
}

/**
 * An instant that EXISTS and is written canonically.
 *
 * Rejects what a shape regex would let through: "2030-02-31" (February has
 * 28 days in 2030), "2031-13-01" (there is no month 13), "2030-01-01T25:00:00Z"
 * (there is no hour 25), "2030-01-01T00:00:60Z" (a leap second has no place
 * in this grammar), "2030-02-29" (2030 is not a leap year). Accepts the
 * canonical forms: "…T00:00:00Z", "…T00:00:00.000Z", "…T00:00:00.5Z"
 * (the fraction is written short and means 500 ms) and a real leap day
 * ("2032-02-29T00:00:00Z").
 */
function isCanonicalExpiry(value) {
  if (typeof value !== 'string' || !EXPIRES_SHAPE.test(value)) return false;
  const expiry = Date.parse(value);
  if (!Number.isFinite(expiry)) return false;
  const canonical = new Date(expiry).toISOString();
  // The comparison spells the fraction the way toISOString() does: ".5" is
  // ".500", a missing fraction is ".000".
  const expected = value.replace(/(\.\d{1,3})?Z$/, (_, fraction) =>
    `${fraction ? (fraction + '000').slice(0, 4) : '.000'}Z`);
  return canonical === expected;
}

/** A decimal integer in [0, 2^64-1] - the range the lamport runtime uses. */
function isU64(value) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return false;
  return BigInt(value) <= MAX_U64;
}

/**
 * A window in seconds: a positive SAFE integer. Zero would set the window
 * cutoff to "now" and silently exclude every record at or before it (the
 * cap would never engage), and a value beyond MAX_SAFE_INTEGER loses
 * precision in the millisecond arithmetic the ledger does.
 */
function isWindowSeconds(value) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return false;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds > 0;
}

/**
 * The MINIMUM window lamport cap a grant can ever honour: the Solana
 * transaction base fee (5000 lamports). Every transfer through this
 * daemon is charged `amount + 5000` against its rolling window (ledger.js:
 * exactly one signature, no ComputeBudget instruction). A cap below 5000
 * can NEVER be satisfied: the cheapest possible real request (a transfer
 * of 0 lamports) costs 5000, so a cap in [0, 4999] makes every request
 * die with `window_cap`.
 *
 * What the grant file accepts must be what the daemon can honour
 * (measured 2026-11-09, research/grant-cap-domain-2026-11-09.json:
 * 4 contract violations on v0.2.12).
 */
const MIN_WINDOW_LAMPORTS = 5000n;

/** A window lamport cap: a decimal integer in [5000, 2^64-1]. */
function isWindowMaxLamports(value) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return false;
  try {
    const n = BigInt(value);
    return n >= MIN_WINDOW_LAMPORTS && n <= MAX_U64;
  } catch {
    return false;
  }
}

/**
 * A count of messages (the message window counts receipts, not lamports):
 * a POSITIVE safe integer in [1, MAX_SAFE_INTEGER]. A cap of 0 can never
 * be reached: the ledger checks `signed + 1 > window.max` BEFORE the first
 * signature, so 0 + 1 > 0 refuses the very first request with `window_cap`
 * (dead on arrival). The CLI's own repair text already calls this
 * "a positive whole number of messages".
 */
function isMessageCount(value) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return false;
  const count = Number(value);
  return Number.isSafeInteger(count) && count > 0 && count <= MAX_SAFE;
}

module.exports = {
  MAX_U64,
  MAX_SAFE,
  MIN_WINDOW_LAMPORTS,
  EXPIRES_SHAPE,
  DECIMAL,
  isCanonicalPublicKey,
  isCanonicalExpiry,
  isU64,
  isWindowMaxLamports,
  isWindowSeconds,
  isMessageCount,
};
