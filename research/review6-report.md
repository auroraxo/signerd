# Review #6 — 2026-10-31 — the seal surface (grant seal + journal seal + passphrase paths)

Base: `feature/message-grant-envelope` @ 1655883 (the HEAD that carries the
message-grant envelope). Probes: `research/review6/p*.js`, each printing a
JSON verdict; they attack the tree from outside `src/`.

Scope note: the takeover of this review's probe set (9 probes + 2 regression
tests, written 15:10–16:02 local against the R5-2 tree `c1b1c09`) was an
interrupted run. This report is the completed measurement against `1655883`.

## Verdicts

| probe | surface | pre-fix (1655883) | post-fix |
|---|---|---|---|
| p1 | empty grant-seal passphrase | **FAIL-OPEN** — forged grant signed | REFUSED at start (`seal_passphrase_required`) |
| p2 | floor guard, journal absent | **FAIL-OPEN** — unsealed daemon starts fresh | `ledger_sealed` |
| p3 | downgrade end to end | **FAIL-OPEN** — same message signed twice | `ledger_sealed`, no second signature |
| p4 | `seal-journal` floor semantics | **FAIL-OPEN** — floor laundered; missing floor unrepairable | refused / repaired, both reported |
| p5 | grant canonicalization | held | held |
| p6 | passphrase file hygiene | **3 gaps** — symlink followed, no owner, no dir | all refused |
| p7 | journal chain + anchor matrix | held | held |
| p8 | prototype pollution | held | held |
| p9 | sealed reload + key cache | held | held |

## Defects fixed

R6-1 empty seal passphrase disabled sealed mode (src/daemon.js)
R6-2 missing-journal downgrade guard + double-sign (src/ledger.js)
R6-3 `seal-journal` laundered a forged history / could not repair a missing floor (src/journalseal-ops.js)
R6-4 passphrase path hygiene (bin/signerd.js)
R6-5 sealing a 0-record journal produced a lone newline -> `ledger_corrupt` (src/journalseal-ops.js)

## Falsification ladder

`test/review6-fixes.test.js` (9 tests) and the two takeover regression tests,
run against the pre-fix tree 1655883 and against the fixed tree:

| test file | pre-fix | post-fix |
|---|---|---|
| `research/review6/regression-empty-seal-passphrase.test.js` | 1 defect RED, 1 control GREEN | 2 GREEN |
| `research/review6/regression-floor-guard-journal-absent.test.js` | 1 defect RED, 2 controls GREEN | 3 GREEN |
| `test/review6-fixes.test.js` | 6 RED, 3 GREEN | 9 GREEN |

Full suite: 176/176 (162 before this review). Crash harness green in both
modes (`test:crash`, `test:crash:sealed`).

## Limits (named, not papered over)

- No outside user, no audit, no real keys in the repo.
- A seal floor deleted *together* with a truncation beforehand leaves no
  marker: undetectable, documented.
- The passphrase hygiene is a pre-read check; the residual race window is the
  same one every other path in this codebase has.
- A hardlink to a passphrase file is still accepted (it is a second name for
  a file whose contents the attacker already controls).
- `seal-journal` is still an operator tool: it seals whatever journal it is
  handed, so the operator must read what it prints.
