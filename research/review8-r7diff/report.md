# Review #8 — adversarial review of the Review-#7 fix diff (84888d4)

Date: 2026-11-01 (producer pulse). Reviewer: same agent (adversarial, NOT
independent — the card's open limitation stands).

## Scope

Exactly the three changes 84888d4 shipped in `src/policy-message.js`:

1. `issued_at` made REQUIRED (`BODY_KEYS`), refusal reason `envelope`;
2. `issuedAtMs()`: strict RFC3339 grammar + component ranges + real calendar
   day + explicit assembly (`setUTCFullYear`, not `Date.parse`);
3. future bound: `issued_at_in_future` beyond now+24h (strict `>`).

Everything else (seal surface, ledger, socket, canonicalization) was reviewed
in #2–#7 and is out of scope here except where the new code touches it.

## Verdict

**The fix holds.** No new defect found in the diff. Two adjacent facts
measured and recorded (one consumer-side cosmetic, one pre-existing
amplification — neither introduced by 84888d4).

## Falsification ladder

Probes: `probe-policy.js` (16 checks, pure `evaluateMessage`),
`probe-live.js` (8 checks, live daemon over a real Unix socket, interop via
the REAL openreceipts verifiers pinned to the fixture key).

| tree | probe-policy | probe-live |
|---|---|---|
| pre-fix `20140e9` (scratch worktree) | 8 pass / **8 fail** | 5 pass / **3 fail** |
| post-fix `84888d4` | **16/16** | **8/8** |

Red on pre-fix: R8-1 (missing issued_at signed), R8-3 (prototype-inherited
issued_at satisfied the old optional path's absence), R8-4 (:60, +24:00,
+99:99, hour 24 signed), R8-5 (Feb 30 / Feb 29 non-leap / day 32 / Apr 31
signed), R8-9..R8-12 (no future bound existed at all). Green on both trees
(the false-positive guards): daily-runner spelling, consumer default
spelling, Z-form, note bounds, leap days on real leap years, fractional
seconds 1–6 digits, hostile-clock handling (`readClock` rejects Date
subclasses -> `invalid_clock`, so the bound is not bypassable via a forged
clock; the daemon passes its own `new Date()` at `src/daemon.js:247`).

Full suite at HEAD: **186/186** (baseline of 84888d4).

## Measured facts adjacent to the diff

**1. Reverse asymmetry (daemon accepts -> consumer can't parse): CLEAN.**
R7-1's bug was "signs what the consumer crashes on". The fixed grammar is a
strict superset of what Python 3.12 `datetime.fromisoformat` parses —
measured, all classes: fractional seconds (1–6 digits), offsets up to ±23:59,
negative offsets, Z-form, leap-day dates (2024-02-29, 2000-02-29). Both
consumers verified on live artifacts (`probe-live.js` L4/L5/L6): `receipt.py
verify` and `verify.mjs` accept every daemon-signed artifact (they never
re-parse the timestamp — they print `body['issued_at']` verbatim;
`feed.py:67` sorts it lexicographically).

**2. feed.py sorts by the raw string (cosmetic, consumer-side).**
`ok.sort(key=lambda e: e["receipt"].get("issued_at", ""), reverse=True)` —
semantically equal instants in different spellings sort by spelling, not by
instant (`"...T21:00:00Z"` > `"...T21:00:00+00:00"` lexicographically, and a
`-05:00` spelling of an earlier instant can sort above a later one). Not
gated by the daemon; recorded so nobody mistakes the feed order for a time
order.

**3. Replay amplification by spelling (PRE-EXISTING, measured on both
trees).** Replay identity is the canonical BYTES (`ledger.js:918`,
`MESSAGE_DOMAIN || bytes`). Five spellings of ONE instant
(`+00:00`, `Z`, `-05:00`, `.000+01:00`, `+01:00`) produce five distinct
bodies -> five signatures and five window slots (measured live, 5/5 signed;
byte-identical repeat refused `replay`; window cap still governs the total).
Pre-fix tree: 3/3 spellings signed identically. This is capacity
amplification within the grant's own window budget — NOT authorization
amplification (scope, issuer, subject and budget still bound every
signature). `receipt.py`'s help string `--issued-at ... (default: now);
replay identity` overstates what any consumer enforces: no openreceipts
component deduplicates by instant (measured). If instant-level dedup is ever
wanted, it is a deliberate semantic change (canonicalize issued_at), not a
bug fix.

## Own harness errors found during this review (honest log)

1. `helper.stop()` swallows the async `stop()` promise — the un-awaited
   restart left the journal lock (`ledger_locked: pid ...` instead of the
   expected `replay`). Fixed by awaiting `daemon.stop()` directly.
2. Probe ordering: the window-cap probe consumed the replay probe's scope
   slots, so the replay probe observed `window_cap` instead of `replay`.
   Fixed with per-scope grants (separate subject) and a cap-driving loop.
3. First restructure started a second fixture whose grants pinned another
   fixture's key -> `grant_key_mismatch` at daemon construction. Replaced by
   rewriting the grant file after start (grants reload on every request).

## Cost re-measured (independent of the commit message claim)

`evaluateMessage` on the fixed tree: **28.7 µs** valid-body path / 25.8 µs
refusal path (n=20000 each) vs 25.3 µs claimed in 84888d4 — same order,
machine-dependent.

## 30-day consumer test — Tag 3, plus a new measured interaction

- Tag 3 (`DAY=2026-11-01`) on the POST-fix tree: **all checks passed**
  (import, pinned-key equality, both verifiers, no client key file,
  window_cap, replay-after-restart, R6-1 empty-seal refusal). The runner's
  `+19h` future stamp (21:00Z at a ~02:00Z run) signs as designed.
- **New measured interaction:** pre-running tomorrow's tag
  (`DAY=2026-11-02`, stamp +43h) now refuses at the first sign with
  `issued_at_in_future` — the 24h bound binds the runner to its own day.
  This is the R7-3 tolerance doing exactly what it was measured for.
- The Tag-2 artifact in `research/consumer-live-2026-11-01/` was overwritten
  by the Tag-3 rerun (runner behavior: DAY-colliding overwrite). The pre-fix
  Tag-2 artifact remains in git history at 20140e9.

## Limits

Adversarial but NOT independent (same agent wrote the fix and the probes).
No external user, no audit, no real keys in the probe fixtures. The review
covers only the R7 fix diff's issued_at surface; the seal surface and the
envelope's other 20 review-#7 probes are unchanged by this review. Consumer
leniency measured against the installed Python 3.12.3 and the repo's
verify.mjs only.

## Next

The card's "independent review" step still requires a different agent or
person; this run does not satisfy it and does not claim to. Tag 4 of the
30-day test is the next routine step.
