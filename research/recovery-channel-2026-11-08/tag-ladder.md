# The recovery ladder, run on the two PUBLISHED tags (2026-11-08)

The ladder `test/recovery-channel.test.js` was captured against a local
pre-fix worktree (`0059c7a`) on 2026-11-08, which is one host's copy of the
tree. To make the falsification independent of that worktree, the same test
file was run against **fresh clones of the published tags**, each with its own
`npm install`, from empty directories:

| published tag | command | result |
|---|---|---|
| `v0.2.9` (the tree that shipped the defect) | `git clone --depth 1 --branch v0.2.9 … && npm install && cp <file-from-v0.2.10> test/ && node --test test/recovery-channel.test.js` | **4 fail / 4 pass** — R1 (file stdout under `ulimit -f 0`), R2 (`/dev/full`), R4 (`/dev/null`), R5 (partial write under `ulimit -f 1`) all RED; R3 + G1 + G2 + G3 green |
| `v0.2.10` (the tag that carries the fix) | `git clone --depth 1 --branch v0.2.10 … && npm install && node --test test/recovery-channel.test.js` | **8 pass / 0 fail** |

(The `v0.2.9` clone does not contain the ladder — the file did not exist
before this fix — so it was copied in from the `v0.2.10` clone. The
*binaries under test* are the published `v0.2.9` tag's own.)

The ladder is not a simulation in either direction:

* every case starts a **real `Daemon`** (`src/daemon.js`) with a real keystore
  and grant file, and the CLI runs as a **subprocess** under `ulimit` / with a
  chosen stdout target;
* R1 and R2 assert the premise themselves: `journal bytes grew` — the daemon
  really signed, so the spend happened and the artefact is at stake. On
  `v0.2.9` that premise holds while the artefact is lost (exit 3 with 0 bytes
  on stdout); that is exactly what makes the four cases RED there;
* the four guards are green on **both** tags, so the fix cannot pass by
  changing the healthy path.

This file is the cross-tag record; `red-baseline.txt` keeps the original
pre-fix capture against the worktree, and `report.md` carries the mechanism
and the limits.
