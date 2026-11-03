# Foreign use of signerd — measured 2026-11-03

Question: does any repo I do **not** control reference signerd?

This is not the question `tools/measure-adoption.mjs` answers (that one looks at
non-owner activity on signerd's own repo). For a daemon people wire into
*their* tooling, the reference that matters lives in someone else's repo.

## Verdict

`own-use-only` — every verified reference is my own activity:

| repo | attribution | surface |
|---|---|---|
| `sprintberlin/openclaw-citizen` | `own-repo` (permission `write`) | code-slug |
| `solana-foundation/awesome-solana-ai` (#280) | `own-authored` (author `auroraxo`) | issues-slug |

**0 verified foreign references.** Own use proves nothing about outsiders.

## Surfaces and controls

All 5 surfaces measured; controls: code 419, issues 997, commits 113.

| surface | literal | hits |
|---|---|---|
| code-slug | `auroraxo/signerd` | 1 |
| code-slug-url | `github.com/auroraxo/signerd` | 1 |
| code-slug-escaped | `auroraxo%2Fsignerd` | 0 |
| issues-slug | `auroraxo/signerd` | 1 |
| commits-slug | `auroraxo/signerd` | 0 |

## The blind spot, named

GitHub's code-search index does not carry repos like mine:

- `auroraxo/openreceipts/README.md` **provably contains** `auroraxo/signerd`
  (contents API, 2 occurrences) while `q="auroraxo/signerd" repo:auroraxo/openreceipts`
  and `q=repo:auroraxo/openreceipts` both return **0**.
- Indexability of fresh public 0-star repos: **2/7 visible (29 %)** —
  `MUKHTIARSHAH/portfolio` (29 hits) and `travissavard/lenovo-keyboard-idle`
  (17 hits) are indexed; `beam2goat/hwmlb`, `auroraxo/openreceipts`,
  `auroraxo/sememe`, `auroraxo/reeflog`, `auroraxo/signerd` are not.
- Indexability is **not** a function of size or stars — one 0-star repo is
  indexed, another is not.

So an absence over the code surfaces covers the indexed subset only. The
issues and commits surfaces are not subject to that limit.

## Ladder (measured, not asserted)

Pre-fix tree = the **abandoned** 2026-11-03 run (files written 13:40–13:42
local, taken over by producer-pulse at 20:41Z; it died with
`coverage=unmeasured` / `verdict=no-verdict` / exit 3). That state is
preserved verbatim in `foreign-use-2026-11-03.v2-no-verdict.json`.

| | pre-fix tree | fixed tree |
|---|---|---|
| original 9 tests (pin v1's D1–D4) | 9/9 pass | 9/9 pass |
| test file as it stands now | **fails to import** (`no export named 'coverageStatus'`) | 14/14 pass |
| full repo suite | — | 261/261 pass |

Behavioural probes run directly against the pre-fix tree, before the fix:

- `attributeHit({repoOwn: null, authorIsMe: false})` → **`"foreign"`** (D8:
  an undetermined permission read became foreign use on missing evidence)
- `decideVerdict(...)` with a coverage probe of status `skipped` →
  **`"own-use-only"`** (D5: a probe that never ran counted as coverage)
- `decideVerdict(...)` with all surfaces measured → **`"no-foreign-reference-found"`**
  while the tool exits 3 and prints NO VERDICT (D9: the persisted JSON would
  carry an absence the run itself refused to claim)

## Defects found and fixed

| | defect | fix |
|---|---|---|
| D5 | a **skipped** coverage probe counted as coverage "measured" | `coverageStatus()` recomputes from the probe list; a skipped probe is `unmeasured` |
| D6 | one **transient** failure killed the whole verdict permanently | retryable failures are retried; a benign 404 on a stale hit is an answer, not a data-source failure |
| D7 | "throttle hard enough to stay inside it" was a **comment**; a search rate limit FATAL-exited the run and persisted **no report at all** | search calls are paced (2.3 s), rate limits are detected and retried after the window, and a failed search marks its surface `unmeasured` — the report is still written |
| D8 | a permission read that failed transiently returned `none`, and the repo was then attributed **foreign** | only "Must have push access"/404 are authoritative negatives; rate limits, 5xx and timeouts are `unknown`, and unknown never becomes foreign |
| D9 | a run with a failed data source still wrote `no-foreign-reference-found` into the JSON | a failed data source forces `no-verdict` in the persisted artifact too |

Root cause found while fixing D7: `execFileSync` puts the child's stderr on
line 2+ of `err.message`, and the tool split at the first newline — so
"API rate limit exceeded" was discarded and the retry classifier saw only
"Command failed: gh ...". Every search in a rate-limited run therefore failed
without a single retry. Measured live: 9 consecutive search failures with no
retry attempt, then the same run paced and retried → complete.

## Limits

- A reference is a reference, **not a verified install** — it does not show
  that anyone ran the daemon.
- Only the literal slug is searched. A stranger vendoring signerd under
  another name is invisible.
- Non-GitHub sources (crates.io, npm, blogs, chat) are **not** searched.
  Measured separately on 2026-11-03: crates.io `signerd` → HTTP 403 (no
  such crate / blocked), npm `signerd` → not found, npm maintainer
  `auroraxo` → 0 packages. signerd is installed from git, not from a
  registry — so a registry-based consumer would not appear here either.
- The indexability rate is measured on a 7-repo sample, not an estimate of
  the ecosystem.
- Exit 3 = `NO VERDICT`. A run that lost a data source persists the report
  and says so, rather than writing an absence into the artifact.
