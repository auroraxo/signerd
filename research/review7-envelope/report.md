# Review #7: the message-grant envelope (issued_at contract)

2026-11-01, producer pulse. Scope per card: `src/policy-message.js`,
`src/signer-message.js`, `src/receipt-identity.js`, and
`ledger.approveMessage/messageScopeKey/MESSAGE_DOMAIN` — the surface review #6
did NOT cover (it covered only the seal).

Baseline: suite **176/176** at 20140e9, no in-flight work (repo clean, claim
expired, previous run's Tag-2 commit 20140e9 == origin).

Method (falsification-first, repo convention): probes in this directory measure
both trees; regression tests in `test/review7-envelope.test.js` written first
and proven red against a scratch checkout of pre-fix 20140e9.

## Findings

### R7-1 (HIGH): a receipt body WITHOUT `issued_at` was signed; the primary
### consumer crashes on that artifact

- Pre-fix, policy probe: `evaluateMessage` **ALLOWED** (VIOLATION line).
- Pre-fix, live daemon: the socket signed it (`error=undefined` = `ok:true`,
  probe VIOLATION line).
- External judge, measured directly against openreceipts at
  702409a: `receipt.py verify` on a receipt without `issued_at` →
  **exit 1, `KeyError: 'issued_at'`** (it reads `body['issued_at']`
  unconditionally in the success print). `verify.mjs` → exit 0 but prints
  `issued undefined`.
- The envelope therefore minted artifacts its designated primary verifier
  cannot read — a user-zero integration defect, not a style opinion. The
  openreceipts CLI itself always sets `issued_at` (defaults to now), so the
  daemon refusing it breaks no real caller.
- Fix: `issued_at` moved into the required key set (BODY_KEYS); missing →
  `refused: envelope`.

### R7-2 (HIGH): `issued_at` was format-checked, not semantics-checked

Pre-fix, every one of these was **ALLOWED and signed** (policy probe VIOLATION):

| input | Date.parse behaviour | pre-fix |
|---|---|---|
| `2026-02-30T00:00:00+00:00` | normalizes to **Mar 2** | signed |
| `2026-11-01T00:00:00+99:99` | accepted by regex | signed |
| `2026-11-01T00:00:00+24:00` | accepted by regex | signed |
| `2026-01-01T25:00:00Z` | hour 25 via regex | signed |
| `2026-06-30T23:59:60Z` | leap second | signed |
| `2026-13-01...` / `2026-01-32...` | month/day ranges | signed |

The same class was already fixed for the GRANT expiry (`expiryMs` does a
canonical round trip precisely because "Date.parse normalizes impossible
calendar dates") — the body field lagged behind. The consumer cannot detect
it: `receipt.py verify` prints `issued 2026-02-30 ... OK` (measured).

Fix: `issuedAtMs()` — RFC3339 grammar regex + component range checks + real
calendar day (leap years included) + explicit instant assembly via
`setUTCFullYear` (the `Date.UTC(year,...)` 0-99 → 1900-1999 mapping would
shift early years by centuries). Failure → `refused: envelope`.

### R7-3 (MED): future-dated receipts were signed without bound

Pre-fix: `2030-01-01...` and `3000-01-01...` **ALLOWED** and signed
(probe VIOLATION). Fix: `refused: issued_at_in_future` beyond
`now + 24h`. The past is deliberately unbounded (backdating about a past
event is legitimate; `expiresAt` bounds when signing happens).

**The 24h tolerance is measured, not chosen.** The real daily consumer
(`research/consumer-live-2026-11-01/receipt.json`, signed 2026-10-31 23:40Z)
carries `issued_at: 2026-11-01T21:00:00+00:00` — **+21.4h future** by
construction (the runner stamps 21:00 UTC of DAY). Any bound below ~21.4h
breaks the running 30-day test. Guard probe pins exactly that shape: live
daemon signs it and OpenSSL verifies the signature.

## Ladder

- `test/review7-envelope.test.js` on pre-fix 20140e9 (scratch worktree):
  **5 red / 5 green** — the 5 red are R7-1/R7-2a/b/c/d; the 5 green are the
  false-positive guards (they must pass on both trees and they do).
- Same file on the fix tree: **10/10 green**.
- Full suite: **176/176 → 186/186**, zero failures, plus crash harness both
  modes (see workboard proof).
- Probes: policy 4 VIOLATION + 4 PASS (pre-fix) → 8 PASS (post-fix); live
  3 VIOLATION + 1 vacuous-interop (pre-fix) → 12 PASS (post-fix).

## Guards measured GREEN on both trees (what the review did NOT find broken)

- Canonicalization differential vs Python: **10/10 byte-identical** on
  control chars, quotes/backslash, `é`/emoji, astral, lone-surrogate escape,
  DEL, nbsp, `/`, U+2028 — the "daemon signs bytes Python verifies
  differently" class does not exist on reachable bodies (claim values are
  string-typed, keys ASCII-constrained, canonicalizer fully ASCII-escapes).
- `approvedMessage`/scope: message records are 4-part `msg\0...` in the live
  journal; tx approvals before a message approval did NOT consume the message
  window (1/5, not 4/5); message records did NOT consume the tx window
  (spent pinned to exactly 20400); same bytes in the other envelope are a
  separate identity (not a false replay); message replay refused by the
  ledger itself.
- Kind separation both directions, replay, window cap, size-cap-before-shape,
  expiry, claimKeys allowlist (broken allowlist = empty = refuse-all), own
  `__proto__` property refused WITHOUT throwing (the "never throws on request
  data" contract holds; deep nesting is bounded by the daemon's 4096-char
  body-text cap — measured at depth 1500/3000/4000: `message_too_large` /
  `request_invalid` / `request_invalid`, daemon alive after).
- Both openreceipts verifiers accept a post-fix signed artifact (python 0,
  node 0, pinned against the daemon key).

## Cost

`evaluateMessage` happy path, 20k iterations: **29.2µs pre-fix → 25.3µs
post-fix** (the new path replaces a regex+length branch with a tighter
parser; no regression — ≈0.08% of the 31.4ms live roundtrip p50).

## Limits (kept in the same report as the fix, per repo convention)

- No outside user, no audit, no real keys in the repo; seals are not
  signatures.
- `+15:00` stays accepted: RFC3339 grammar bounds offsets to 00-23, real
  world to ±14:00 — grammar-legal-but-unreal offsets are NOT refused
  (deliberate: spec conformance, not tz database).
- `issued_at` is still NOT pinned to the signing time: a consumer stamp up to
  24h future (the measured daily-runner contract) is accepted by design.
  Receipts remain "the issuer said this at T", never "this happened at T".
- `note` remains free text (≤256 chars) the grant does not speak about —
  documented envelope limit, unchanged.
- Two probe-harness bugs were found in MY OWN probes before reporting (pin
  checked against the wrong key → pin-mismatch by design; over-large
  window approval → correct `window_cap` math). Both were probe bugs, not
  product findings, and are fixed in this directory.

## Probe artifacts

- `probe-policy.js` — pure policy layer, prints PASS/VIOLATION per claim.
- `probe-live.js` — live daemon over the socket + ledger cross-budget +
  the real openreceipts verifiers on the signed artifact.
- `helper.js` — shared fixture (same shape as `test/message-e2e.test.js`).
