# 30-day consumer test — day 4 (DAY=2026-11-02)

Date: 2026-11-01 21:36–22:35Z (Berlin 23:36–00:35)
Runner: `research/consumer-live-daily/run.sh` with `DAY=2026-11-02`
Tree: signerd `main` 2e35ad6 (v0.1.0), openreceipts `main` 25c9106 (the fixed
verifiers), issuer key `~/.openreceipts/auroraxo.key` imported into a throwaway
keystore, pinned public key `openreceipts/keys/auroraxo.pub`.

## Result: 8/8 live checks green

| check | measured outcome |
|---|---|
| issuer key imports (PKCS8 -> seed -> raw64, OpenSSL cross-check) | pubkey matches the OpenSSL derivation; keystore key `EywbUFhywbf6sNG67AbSvKcVByWdNsYTrda4R4nu7sci` |
| site pubkey == repo-pinned key | `z74vce0VgGTpPP7Nu/G+O9IVDgcKg/lceC/2GAvwzi8=` |
| client signs through the daemon | `receipt.py sign --via-signerd` -> receipt signed, no key in the client |
| client key material | `OPENRECEIPTS_HOME` never created |
| both openreceipts verifiers accept the artifact | `python3 receipt.py verify` OK, `node verify.mjs` OK |
| overdrawn window | 4th sign refused `refused: window_cap`, no file written |
| replay after daemon restart | refused `refused: replay`, no file written |
| empty seal passphrase (R6-1) | daemon refuses to start `seal_passphrase_required`, no socket left behind |

Artifact: `research/consumer-live-2026-11-02/receipt.json` + `report.json`
(commit 15e98e7).

## Falsifying control: the day gate still binds

`DAY=2026-11-03` (+47h) was refused by the daemon with
`refused: issued_at_in_future` and wrote no artifact directory — the 24h
future bound measured on 1.11. still binds the runner to its day after the
v0 merge. The run exits 1 at step 4, before any artifact is written.

## Incidental defect found and fixed: the CI image migration broke main

Pushing the day-4 artifact turned main red — **not** because of the artifact
(a JSON file) but because the `ubuntu-latest` runner image migrated
`ubuntu-24.04` -> `ubuntu-26.04` between this morning's green run
(41285330425) and the new one (41353018658). The same tree passed before.

Root cause, measured rather than guessed:

1. The failing assertion (`daemon scan must cover all writable mappings`)
   named no mapping. The first fix was to make it name its holes
   (`test/user-zero.test.js`).
2. With that in place, CI reported the holes: four **writable** anonymous
   regions of the daemon failing with `EIO` (the read-only `[vvar]` /
   `[vvar_vclock]` EIOs were already excluded by `scanIsComplete`).
3. Chunked reads + a rescan on address-space change did not fix it: the
   EIOs persisted on every attempt, always at chunk offset 0.
4. Page-level isolation then read the mechanism out of
   `/proc/<pid>/pagemap`: the failing pages report `present=false,
   swapped=true`. Linux refuses to read swapped-out pages through
   `/proc/<pid>/mem` (EIO), and the ubuntu-26.04 runners swap them.

So the EIO is an environment property, not an instrument defect — and a
swapped page *can* hold the key, so absence must not be claimed over it.

Fix (merged to main, `0d6e28b`):

- `scripts/memscan.js` isolates a failed chunk page by page and asks pagemap
  what backs each failing page: proven backingless -> `regionsEmpty` (with
  the pagemap entry kept as auditable evidence); present, swapped, or unknown
  -> a hole. `swappedHoles()` / `unexplainedHoles()` split the two cases.
- `test/user-zero.test.js` requires **zero unexplained writable holes**; a
  swapped page is named as a diagnostic, and the absence claim is scoped to
  the resident pages on a swap-pressured runner. Zero hits over everything
  readable stays a hard assertion.
- Two real defects in the new scanner, both found by the new tests: a
  zero-length read made `Buffer.indexOf` return 0 (a bogus hit), and the
  returned scan reported the kept attempt instead of how many scans were made.

## Ladder (falsification, both sides)

| test | old tree 096cb1c (whole-mapping scanner) | this tree |
|---|---|---|
| a read failure is bounded to one chunk | red | green |
| a stale snapshot is rescanned | red | green |
| a read-only EIO is not a hole (false-positive guard) | green | green |
| the scanner finds a known pattern (positive control) | green | green |

Suite 210/210 locally (was 206), crash harnesses green in both modes,
CI green on ubuntu-26.04: 41357091481 (branch) and 41357207125 (main),
both jobs `test` + `consumer-e2e`.

## Limits of this evidence

- Still **User Zero**: the consumer is my own repo; no third party uses
  signerd, no audit.
- The client-side absence claim is proven for resident pages only on a
  swap-pressured runner; it is named, not assumed.
- The 30-day test still runs per pulse, not as its own unattended job.
- Day 4 is one day of a 30-day series; the series is not complete.
