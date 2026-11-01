# Boundary probe: the 24h future bound and the daily runner's earliest clock

2026-11-01, parent pulse (main session), scratch worktree of 5770b59.
Probe: `probe.js` (drives `evaluateMessage` with an injected clock; no
daemon, no signature — the policy question only).

## Questions

R7/R8 measured +21.4h (accepted) and +43h (refused) but never the exact
edge of `MAX_FUTURE_SKEW_MS` (src/policy-message.js:275,
`issuedAtInstant > nowMs + SKEW`). Two open questions:

1. Is the bound inclusive at exactly +24h? (Decides the earliest clock
   time at which the daily consumer's next DAY artifact becomes
   runnable: the runner pins issued_at to DAY T21:00Z.)
2. Do fraction-bearing spellings behave at the edge?

## Measured answers (pre-fix tree 5770b59)

1. INCLUSIVE. Strict `>`: exactly `now+24h` is ALLOWED, the first
   refusal is strictly beyond it. Boundary set (12 rows in probe.js):
   target-24h exactly = ALLOWED; target-24h+1ms = refused
   issued_at_in_future; generic +24h (Z, +02:00 offset spelling, .000
   fraction) all ALLOWED; +24h+1ms refused; far future refused; past
   allowed.
   -> Day 4 (DAY=2026-11-02) becomes runnable at exactly
   2026-11-01T21:00:00Z (23:00 Berlin), one second earlier is refused.

2. DEFECT (became R9-1, fixed in d101512): `issuedAtMs()` dropped the
   fraction, so `.000001`-`.999999` spellings of instants up to one
   second past the bound were ALLOWED (999999 microseconds of slack).
   The bound's real edge was fuzzy at every second boundary.

## Ladder for the fix

- test/review9-fraction.test.js on pre-fix 5770b59: 2 red / 3 green
  (the reds: 1us and 999999us over the bound accepted, via Z and +00:00
  spellings; the greens: guards that must hold on both trees).
- After fix (d101512): 5/5. Full suite on the scratch tree: 191 tests,
  183 pass, 0 fail, 8 skipped (consumer-e2e needs the sibling
  openreceipts checkout; runs in the main checkout and CI).
- Full suite WITH the real consumer wired in
  (SIGNERD_OPENRECEIPTS=~/github_repos/openreceipts npm test): 191 tests,
  190 pass, 0 fail, 1 skipped — all 7 consumer-e2e tests run and pass on
  the fixed tree. CI on the pushed branch: run 41275203188, jobs
  test=success + consumer-e2e=success.
- Signed bytes UNCHANGED by the fix: receipt-identity.js is untouched and
  evaluateMessage still emits the fraction verbatim into the canonical
  bytes. Only the admission decision (the bound) changed.
- Why this is a real ecosystem fix, not just precision: Python's
  fromisoformat ACCEPTS and PRESERVES 6-digit fractions (measured), and
  receipt.py can emit an explicit --issued-at; Node verify.mjs parses
  fractions too (truncating to ms). So a fraction-bearing receipt is
  readable by the ecosystem while the daemon mis-measured its moment.
  Now the daemon agrees with the primary (Python) verifier.
- The fix's own first post-fix run was RED: the initial patch read
  offset groups for "Z" spellings, Number(undefined) = NaN poisoned the
  instant, and NaN > x is false — the future bound SILENTLY STOPPED
  refusing (+1s was accepted). Caught by the guard, fixed with an
  explicit NaN fail-closed path. Documented here because it is the
  strongest evidence in this repo so far that the red-first discipline
  pays for itself.

## What this does NOT cover

- Only the message envelope policy; the transaction-side policy (tx
  spend grants) is untouched and out of scope here.
- No daemon-level e2e of fraction spellings (policy-level only; the
  daemon path calls the same evaluateMessage).
- No independent review: this measurement and its fix are same-agent
  work (main session); the independent review runs separately on the
  envelope as a whole.
