'use strict';

const crypto = require('node:crypto');
const { canonicalReceiptBytes } = require('./receipt-identity');
const { ownField, readClock } = require('./policy');

// The message-grant envelope: policy for signing a MESSAGE (an
// openreceipts/v1 receipt body) instead of a Solana transaction wire.
//
// Why this exists (measured 2026-10-30, tools/envelope-traffic.mjs): a v1
// SPL-Token envelope would have covered ~0.02% of sampled mainnet traffic on
// top of v0, while the one measured own key-load site (openreceipts) needs
// exactly this: an Ed25519 signature over canonical JSON receipt bytes. The
// envelope decision is a scope decision, not a safety claim; this module
// keeps the same refuse-by-default shape as src/policy.js.
//
// A message grant authorizes exactly one thing: "the key this daemon holds
// may sign an openreceipts/v1 receipt body for issuer <issuer>, type <type>,
// subject <subject>, whose canonical bytes are at most <maxBytes> long, at
// most <windowMaxMessages> times per <windowSeconds>, until <expiresAt>".
// Everything else in the body is either pinned by the grant (issuer, type,
// subject, the issuer's public key) or bounded (claims, note, issued_at).
//
// What it does NOT do: it does not check that the receipt is TRUE. A signed
// receipt says "the issuer said this", never "this happened". The grant
// bounds who may speak for the issuer and about what, not the truth.

const MESSAGE_SCHEMA = 'openreceipts/v1';

// A hard envelope bound independent of the grant: the daemon request frame
// is bounded and the receipt body travels inside it. 3072 canonical bytes
// leave room for framing, grant name and the request envelope.
const MAX_MESSAGE_BYTES = 3072;

// Same character class the grant file uses for names: the issuer of a
// receipt is an account/repo-style identifier, not free text.
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// Receipt subjects in the wild are repo paths ("auroraxo/signerd") or
// package names: printable ASCII, bounded.
const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;
const MAX_CLAIMS = 32;
const MAX_CLAIM_VALUE = 256;

// The exact body shape: an unknown top-level key is a schema violation, not
// an extension point (same rule as the grant file: a typo in a signed
// document must fail, not silently sign something else).
const BODY_KEYS = ['schema', 'issuer', 'type', 'subject', 'claims'];
// issued_at and note are openreceipts fields with no authorization meaning:
// they ride inside the signed bytes, but the grant does not speak about
// them. They are still BOUNDED (format/length), because the canonical bytes
// are.
const OPTIONAL_KEYS = ['note', 'issued_at'];

function refused(reason, extra) {
  return extra === undefined
    ? { allowed: false, refused: reason }
    : { allowed: false, refused: reason, ...extra };
}

// Read a field as a plain own data string, or fail.
function ownString(source, key) {
  const field = ownField(source, key);
  if (!field.ok || typeof field.value !== 'string') return null;
  return field.value;
}

// The expiry check follows policy.js semantics: a canonical RFC3339 UTC
// timestamp whose Date round trip reproduces it exactly, and a clock read
// exactly once from a genuine Date. Kept local so the message policy stays
// independently auditable.
function expiryMs(grant) {
  const value = ownString(grant, 'expiresAt');
  if (value === null || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value)) return NaN;
  const expiry = Date.parse(value);
  if (!Number.isFinite(expiry)) return NaN;
  const canonical = new Date(expiry).toISOString();
  const expected = value.replace(/(\.\d{1,3})?Z$/, (_, fraction) =>
    `${fraction ? (fraction + '000').slice(0, 4) : '.000'}Z`);
  return canonical === expected ? expiry : NaN;
}

// The grant's claim-key allowlist, if any: a comma-separated list of the
// claim keys the issuer is willing to have signed. An absent list means any
// key is allowed (documented limit: the grant then speaks about the receipt
// but not about its claims).
function allowedClaimKeys(grant) {
  const value = ownString(grant, 'claimKeys');
  if (value === null) return null;
  if (value === '') return [];
  const keys = value.split(',');
  for (const key of keys) if (!NAME.test(key)) return [];
  return keys;
}

/**
 * Evaluate a parsed receipt BODY against a message grant.
 *
 * `body` must be the result of JSON.parse on the client's body text; the
 * canonical bytes signed are derived HERE, deterministically, from the
 * parsed value — so two textual spellings of the same object are the same
 * message (and therefore one replay-set entry), while any change of value,
 * key set or key name is a different message.
 *
 * Returns { allowed: true, messageBytes, messageSha256 } or
 * { allowed: false, refused: reason }. It never throws on request data.
 */
function evaluateMessage(body, grant, now = new Date()) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return refused('invalid_body');
  }
  // The grant itself: kind, issuer and the pinned public key are read from
  // own properties only, so a polluted Object.prototype cannot supply them.
  const kind = ownString(grant, 'kind');
  const issuer = ownString(grant, 'issuer');
  const type = ownString(grant, 'type');
  const subject = ownString(grant, 'subject');
  const pubkey = ownString(grant, 'pubkey');
  const maxBytesField = ownField(grant, 'maxBytes');
  if (kind !== 'message' || issuer === null || !NAME.test(issuer) ||
      type === null || !NAME.test(type) || subject === null || !SUBJECT.test(subject) ||
      pubkey === null || !/^[A-Za-z0-9+/]{43}=$/.test(pubkey) ||
      !maxBytesField.ok || typeof maxBytesField.value !== 'string' ||
      !/^(0|[1-9][0-9]*)$/.test(maxBytesField.value)) {
    return refused('invalid_grant');
  }
  const grantMaxBytes = Number(maxBytesField.value);
  if (!Number.isSafeInteger(grantMaxBytes) || grantMaxBytes < 1 ||
      grantMaxBytes > MAX_MESSAGE_BYTES) {
    return refused('invalid_grant');
  }
  // Expiry, before any parsing work that could be mistaken for approval.
  const expiry = expiryMs(grant);
  const nowMs = readClock(now);
  if (!Number.isFinite(nowMs)) return refused('invalid_clock');
  if (!Number.isFinite(expiry)) return refused('invalid_grant');
  if (nowMs >= expiry) return refused('expired');

  // Exact key set: required keys present, nothing outside schema+optional.
  const keys = Object.getOwnPropertyNames(body);
  const allowed = new Set([...BODY_KEYS, ...OPTIONAL_KEYS]);
  for (const key of keys) if (!allowed.has(key)) return refused('envelope');
  for (const key of BODY_KEYS) {
    if (!Object.getOwnPropertyDescriptor(body, key)) return refused('envelope');
  }
  if (ownString(body, 'schema') !== MESSAGE_SCHEMA) return refused('invalid_schema');
  if (ownString(body, 'issuer') !== issuer) return refused('issuer');
  if (ownString(body, 'type') !== type) return refused('type');
  if (ownString(body, 'subject') !== subject) return refused('subject');

  // The canonical bytes are the message, and the SIZE CAP is checked before
  // any shape question about the parts: "does it even fit" precedes "is what
  // fits well-formed". Checking shape first would shadow the cap — a grant
  // capped below the shape bounds (e.g. maxBytes 700 vs a 256-char claim
  // limit) would report the part's refusal instead of the size refusal, and
  // an operator tuning maxBytes could never observe the cap engaging.
  // Both bounds apply: the grant's own cap and the envelope's hard cap (a
  // grant cannot widen the envelope).
  const messageBytes = canonicalReceiptBytes(body);
  const messageSha256 = crypto.createHash('sha256').update(messageBytes).digest('hex');
  if (messageBytes.length > Math.min(grantMaxBytes, MAX_MESSAGE_BYTES)) {
    return refused('message_too_large');
  }

  const claimsField = ownField(body, 'claims');
  if (!claimsField.ok || claimsField.value === null ||
      typeof claimsField.value !== 'object' || Array.isArray(claimsField.value)) {
    return refused('claims');
  }
  const claims = claimsField.value;
  const claimKeys = Object.getOwnPropertyNames(claims);
  if (claimKeys.length > MAX_CLAIMS) return refused('claims');
  const permitted = allowedClaimKeys(grant);
  for (const key of claimKeys) {
    if (!NAME.test(key)) return refused('claims');
    if (permitted !== null && !permitted.includes(key)) return refused('claims');
    const field = ownField(claims, key);
    if (!field.ok || typeof field.value !== 'string' || field.value.length > MAX_CLAIM_VALUE) {
      return refused('claims');
    }
  }
  if (Object.getOwnPropertyDescriptor(body, 'note')) {
    const note = ownString(body, 'note');
    if (note === null || note.length > 256) return refused('envelope');
  }
  if (Object.getOwnPropertyDescriptor(body, 'issued_at')) {
    const issuedAt = ownString(body, 'issued_at');
    if (issuedAt === null || issuedAt.length > 40 ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/.test(issuedAt)) {
      return refused('envelope');
    }
  }

  // The canonical bytes were derived above; the message identity is the same
  // bytes the grant was checked against.
  return { allowed: true, messageBytes, messageSha256 };
}

module.exports = {
  evaluateMessage, MAX_MESSAGE_BYTES, MESSAGE_SCHEMA,
};
