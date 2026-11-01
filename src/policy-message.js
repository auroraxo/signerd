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
const BODY_KEYS = ['schema', 'issuer', 'type', 'subject', 'claims', 'issued_at'];
// issued_at and note are openreceipts fields with no authorization meaning:
// they ride inside the signed bytes, but the grant does not speak about
// them. They are still BOUNDED (format/length), because the canonical bytes
// are.
//
// issued_at is REQUIRED (2026-11-01, review #7): openreceipts' own signer
// always sets it (receipt.py defaults it to now) and its primary verifier
// reads body['issued_at'] unconditionally, so a receipt without it makes the
// consumer CRASH (KeyError: 'issued_at') instead of failing politely. The
// daemon refuses such a body rather than minting an artifact the ecosystem
// cannot read.
//
// The value is checked STRICTLY, not by Date.parse: Date.parse normalizes
// impossible calendar dates ("2026-02-30" -> March 2) and accepts
// out-of-grammar offsets ("+99:99"), so a regex plus a real-calendar check
// is the only way to know what was actually signed. The grant expiry
// already refuses exactly this class (canonical round trip); the body field
// did not.
const OPTIONAL_KEYS = ['note'];

// How far a receipt may be dated into the future. The issuer key must not
// produce a statement that claims to come from the future: the artifact
// would be permanently undatable ("issued 2030-...") and no verifier could
// place it in time. 24h covers the real consumer's own stamping (the daily
// live runner dates its receipts at 21:00 UTC of the CURRENT day, which is
// up to ~21h ahead of an early-morning run) and nothing beyond it.
// The past is NOT bounded: backdating a receipt about a past event is
// legitimate, and the grant's own expiresAt already bounds when the
// SIGNING happens.
const MAX_FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;

// RFC3339 with the seconds field pinned to 00-59 (a leap second has no
// place in a signed artifact) and the offset inside the grammar's range.
const ISSUED_AT =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|([+-])(\d{2}):(\d{2}))$/;

function daysInMonth(year, month) {
  const lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return lengths[month - 1];
}

/**
 * The instant a well-formed issued_at denotes, or null when the spelling is
 * not a real timestamp.
 *
 * Deliberately NOT Date.parse: that normalizes Feb 30 into March 2 and
 * accepts offsets like "+99:99", so a receipt could be signed for a moment
 * that does not exist. Every component is range-checked, the day number is
 * checked against the real length of that month (leap years included), and
 * the instant is assembled explicitly from the parts.
 */
function issuedAtMs(value) {
  if (typeof value !== 'string') return null;
  const m = ISSUED_AT.exec(value);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  // Fractional seconds are REAL: JS Date resolves only to whole
  // milliseconds, so the pre-2026-11-01 code passed 0 here and silently
  // truncated .000001-.999999 to the second boundary. That loosened every
  // bound computed from the instant (the 24h future bound accepted up to
  // 999999 microseconds past it). The fraction is kept in fixed-point
  // microseconds and folded in at the end, exactly.
  const fraction = m[7] === undefined ? 0 : Number(m[7].padEnd(6, '0'));
  if (month < 1 || month > 12) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  let offsetMinutes = 0;
  // m[8] is the whole tail ("Z" or "±HH:MM"); only the ± form has sign
  // groups. Reading m[9..11] for "Z" yields Number(undefined) = NaN, which
  // would poison the instant below and — because NaN > x is always false —
  // SILENTLY DISABLE the future bound. Caught by test/review9-fraction
  // ("guard: the bound itself did not move" refused +1s post-fix).
  if (m[8] !== undefined && m[8] !== 'Z') {
    const offsetHours = Number(m[10]);
    const offsetMins = Number(m[11]);
    if (offsetHours > 23 || offsetMins > 59) return null;
    offsetMinutes = (m[9] === '-' ? -1 : 1) * (offsetHours * 60 + offsetMins);
  }
  if (!Number.isFinite(offsetMinutes)) return null;
  // setUTCFullYear instead of Date.UTC: Date.UTC maps the years 0-99 onto
  // 1900-1999, which would silently shift a timestamp by centuries.
  const when = new Date(0);
  when.setUTCFullYear(year, month - 1, day);
  when.setUTCHours(hour, minute, second, 0);
  const instant = when.getTime();
  if (!Number.isFinite(instant)) return null;
  // Fixed-point microseconds: (seconds * 1e6 + fraction) - offset*60e6, as
  // an integer — exact whenever the value fits Number.isSafeInteger
  // (roughly the years 1685-2254; every real receipt lives there). Outside
  // that range the microsecond value cannot be held exactly, so fall back
  // to the old whole-millisecond value: fractions are far below the float
  // resolution there and bounds keep their pre-2026-11-01 semantics
  // (review8's year-9999 probe stays refused, only via the future bound).
  const instantMicros = (instant - offsetMinutes * 60000) * 1000 + fraction;
  // Fail CLOSED: a non-finite assembled instant must be a refusal (null ->
  // 'envelope'), never a value that makes the future-bound comparison false.
  if (!Number.isFinite(instantMicros)) return null;
  if (!Number.isSafeInteger(instantMicros)) return instant - offsetMinutes * 60000;
  return instantMicros / 1000;
}

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

  // issued_at is required (review #7: the openreceipts verifier reads it
  // unconditionally) and must denote a real moment.
  const issuedAt = ownString(body, 'issued_at');
  if (issuedAt === null) return refused('envelope');
  const issuedAtInstant = issuedAtMs(issuedAt);
  if (issuedAtInstant === null) return refused('envelope');
  // The daemon must not sign a statement dated into the future (beyond the
  // tolerance): the artifact would claim a moment that has not happened.
  // The past is allowed - backdating is legitimate, and expiresAt already
  // bounds the signing itself.
  if (issuedAtInstant > nowMs + MAX_FUTURE_SKEW_MS) return refused('issued_at_in_future');

  // The canonical bytes were derived above; the message identity is the same
  // bytes the grant was checked against.
  return { allowed: true, messageBytes, messageSha256 };
}

module.exports = {
  evaluateMessage, MAX_MESSAGE_BYTES, MESSAGE_SCHEMA,
};
