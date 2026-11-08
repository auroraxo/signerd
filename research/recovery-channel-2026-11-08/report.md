# The recovery channel, measured (2026-11-08)

## The question

The README of the tree that shipped **v0.2.9** (commit `0059c7a`) says:

> On exit 3 the signed wire (or the signed receipt document) is **still on stdout**

and the exit table says:

> | 3 | **the signature was made, the file delivery failed** |

Exit 3 is the one exit code whose whole meaning is *"the artefact is here"*. It is
what an operator trusts after paying for a signature. So the question is not "does
the CLI print something" but:

> **When the CLI exits 3, is the paid-for artefact actually recoverable?**

## The measurement

Live daemon, real signing, the journal as the witness. The journal grows only when
the daemon really signs, so `journal 366 -> 732 bytes` is the proof that **the spend
happened**.

| case | stdout channel | `--out` | measured on v0.2.9 |
|---|---|---|---|
| A | regular file under `ulimit -f 0` (the ordinary `... > signed.json` capture) | regular file | **exit 3, stdout 0 bytes, stderr 0 bytes**, `--out` unchanged, journal grew, retry refused `{"error":"replay"}` |
| B | `/dev/full` (opens, every write fails `ENOSPC`) | regular file | **exit 3, stdout 0 bytes, stderr 0 bytes**, journal grew |
| C | healthy pipe | regular file | exit 3, stdout carries the complete response (the contract holds) |
| D | `/dev/null` (the write *succeeds*, the bytes are discarded) | regular file | **exit 3** while nothing retains a byte |
| E | regular file under `ulimit -f 1` (1024 bytes allowed) | regular file | **exit 3 with exactly 1024 bytes of truncated JSON** |

The journal holds only hashes — the signature itself is not recoverable from it. So
in cases A, B, D and E the operator had **paid and lost the artefact**, while the
exit code said it was on stdout.

## Why it happened (mechanism, measured — not assumed)

1. `process.exit()` does **not** flush a pending stdout write. The bytes are queued,
   the process is gone, nothing reached the kernel.
2. A failing write on a **file** is reported **asynchronously** (an `error` event on
   the stream). An immediate `process.exit()` runs first, so the error never
   surfaces either. The process reports success on a channel that refused every byte.
3. `fs.writeSync(1, buf)` returns how many bytes landed. Under `RLIMIT_FSIZE` it can
   write **part** of the payload and fail on the next call — measured: `ulimit -f 1`,
   a 1402-byte payload wrote **1024** bytes and then threw `EFBIG`. A partial write
   is a failed delivery; a truncated artefact is not an artefact.
4. `/dev/full` throws `ENOSPC`; a pipe whose reader is gone throws `EPIPE`; a
   momentarily full pipe throws `EAGAIN` (the one transient case).
5. A **zero-byte write is not a probe**: it succeeds on `/dev/full` and on a closed
   stdout. The probe that means something is the real payload.
6. `/dev/null` and `/dev/zero` **accept every write and keep nothing**. "No error" is
   therefore not proof of delivery — the channel must be asked whether it *retains*.
7. `writeSync(1, 8 MB)` to a pipe with no reader **hangs** (blocking write), so the
   `EAGAIN` path is bounded-retry only.

## Why it is a product defect, not a harness artifact

* stdout-is-a-file is the ordinary capture pattern (`signerd sign ... > signed.json`),
  in CI and on an operator's shell.
* The exit code's entire meaning is "the artefact is here". An exit code that can be
  produced while the artefact is gone is a lie in the one place the product promised
  truth.
* The journal proves the spend happened, so the operator cannot retry — exit 3 is the
  **last** place the truth could have been told.

## The fix

| file | what it does |
|---|---|
| `src/stdout.js` | `writeFdSync` / `writeStdoutSync` / `writeStderrSync`: a synchronous, **full-length-checked** write (a partial write is a failure; `EAGAIN` is retried bounded; nothing throws). `stdoutRetainsBytes()`: reads `/proc/self/fd/1` and reports whether the channel *keeps* what it is given. |
| `src/recovery.js` | the exit-code decision. Exit 3 only when the artefact was **verified** on a channel that **retains** it; otherwise exit **4** (`recovery_failed:` on stderr, with the errno and the repair). |
| `bin/signerd.js`, `examples/user-zero-client.js` | the `sign`, `sign-message` and client paths use the verified write and the new decision. |

Exit 4 is new, and deliberately: exit 1 says "no signature was made" (false here),
exit 2 says "usage error" (false here), and exit 3 says "the artefact is on stdout"
(false here). Exit 4 says exactly what happened: *signed, and unrecoverable*.

## The ladder (test-first)

`test/recovery-channel.test.js` — 8 cases. The red baseline was captured against the
**real pre-fix binaries** in a separate git worktree at `0059c7a`
(`git worktree add /tmp/signerd-prefix 0059c7a`), not against a simulation:

| case | what it pins | pre-fix | post-fix |
|---|---|---|---|
| R1 | CASE A: exit 3 only when the wire really reached stdout | **RED** | green |
| R2 | CASE B: a dead device channel is VERIFIED and named | **RED** | green |
| R3 | guard: a healthy pipe still gets the **complete** exit-3 response | green | green |
| R4 | CASE D: a channel that discards bytes is not a recovery channel | **RED** | green |
| R5 | CASE E: a **partial** write is not a delivered artefact | **RED** | green |
| G1 | guard: ordinary stdout-to-file capture still exits 0, `ok:true` | green | green |
| G2 | guard: the ordinary pipe path is unchanged | green | green |
| G3 | guard: the example client keeps its exit-code and stdout contract | green | green |

The captured run is in `red-baseline.txt` (4 red, 4 green) — measured, not asserted.

The four guards are green on **both** trees, so the fix cannot be "pass by changing the
healthy path".

## The mutation ladder (the falsification of the fix)

`tools/mutation-ladder-recovery-channel.sh` — 6 mutations, each caught, the tree
restored byte-identically:

| # | mutation | caught by |
|---|---|---|
| M1 | the verified write degrades to the async `process.stdout.write` of v0.2.9 | 3 cases red |
| M2 | the partial-write check dropped | R5 |
| M3 | the retention check dropped | R4 |
| M4 | the failure reported as exit 3 anyway | 3 cases red |
| M5 | the `recovery_failed` statement silenced | 2 cases red |
| M6 | the `sign-message` path left unverified | 1 case red |

## Limits (stated, not hidden)

* The check happens **at the moment of the write**, not before the sign. A channel
  that breaks between the verification and the reader is still outside the contract —
  that window is what the journal's hashes are for.
* When `/proc` is unavailable, retention is **assumed** (the write result then
  decides). The assumption is documented in `src/stdout.js`, not silent.
* `EAGAIN` is retried bounded (200 × 10 ms). A pipe that stays full for longer is
  reported as a failed delivery — deliberately, since a blocked write on a pipe with
  no reader **hangs** the process.
* The exit-4 path is new; a consumer that only knows 0/1/2/3 sees an unknown code.
  The stderr statement is the contract, and it is machine-greppable
  (`recovery_failed:`).
* The `--out` preflight remains a point-in-time check (TOCTOU) — that window is what
  exit 3 exists for, and it is unchanged.
