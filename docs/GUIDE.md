# signerd guide

The full walkthrough: keystore, grants, sealed mode, signing, revocation. For the short version see the [README](../README.md).

## Shape

```bash
# one-time setup: an encrypted keystore and a grant file.
# The passphrase file is a SECRET: create it owner-only. On a default desktop
# umask (0002) a plain `printf ... > pass` lands at 0664 and is refused by
# design — a group-readable passphrase could be read by anyone on the machine.
# Keystore and state directories are created by signerd itself, owner-only.
umask 077
mkdir -p ~/.config/signerd            # 0700 via umask
printf 'your passphrase\n' > ~/.config/signerd/pass
chmod 600 ~/.config/signerd/pass
signerd keygen --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass

# Create the grant file the daemon expects (owner-only 0600; refuses to clobber).
# This is the step that makes the quickstart run verbatim without guessing the schema:
signerd grant-add --grants ~/.config/signerd/grants.json --name ops-24h \
            --keystore ~/.config/signerd/ops.key \
            --destination So11111111111111111111111111111111111111112 \
            --max-lamports 500000000 --window-max-lamports 500000000 \
            --window-seconds 3600 --expires 2030-01-01T00:00:00Z
# (--keystore makes the signer the keystore's public key - no paste step.
#  The daemon refuses grant_signer_mismatch, so this cannot drift.)
# A SECOND scope is a second grant in the SAME file, added with --append
# (one scope per grant; atomic write, the map stays loadable; the appended
# grant is live on the daemon's next request - the file is re-read per
# request). Without --append an existing file is refused. A SEALED file is
# rewritten only by the CLI, never by hand: `grant-add --append` re-seals the
# file as part of the act (it needs the seal passphrase, see below), and
# `grant-remove` does the same. Hand-editing a sealed file breaks its seal,
# and the daemon then refuses the file (grant_file_seal_mismatch).
signerd grant-add --grants ~/.config/signerd/grants.json --name ops-payroll --append \
            --keystore ~/.config/signerd/ops.key \
            --destination Vote111111111111111111111111111111111111111 \
            --max-lamports 1000000 --window-max-lamports 1000000 \
            --window-seconds 60 --expires 2030-01-01T00:00:00Z

# REVOKE a scope: remove the grant by name. Do NOT hand-edit the grant file —
# the loader judges the file first (directory, lease, owner, mode, schema,
# seal), the write is atomic (temp+rename), and the removal takes effect on
# the daemon's NEXT request (no restart, no signal). An unknown name changes
# nothing and the refusal lists the grants that are in the file.
signerd grant-remove --grants ~/.config/signerd/grants.json --name ops-payroll
# A SEALED file is re-sealed as part of the act (the old seal covered content
# that no longer exists); it needs the seal passphrase:
signerd grant-remove --grants ~/.config/signerd/grants.json --name ops-payroll \
            --seal-passphrase-file ~/.config/signerd/seal.pass
# Limits: removal is BY NAME (it removes the whole scope — it does not narrow
# a cap; edit the file for that), and a grant removed mid-request is judged by
# the loader read at the START of that request.

# OR adopt a key you already hold — the migration path. Reads a solana-keygen
# id.json, a base58 secret, or 64 raw bytes; encrypts it; leaves the source alone.
# Refuses an existing keystore (the keygen line above writes the SAME file):
# run EITHER keygen OR import for a first key.
signerd import --keystore ~/.config/signerd/ops.key --from ~/.config/solana/id.json \
             --passphrase-file ~/.config/signerd/pass
# To replace a keystore on purpose, add --overwrite (the old key is gone
# afterwards); a refused overwrite (invalid --from) leaves the file untouched.

signerd run --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass \
            --grants ~/.config/signerd/grants.json \
            --ledger ~/.local/share/signerd/journal.jsonl \
            --socket ~/.local/share/signerd/signerd.sock

# a client: no key material, only a grant name and the transaction bytes.
# build-tx reads only the keystore's PUBLIC key (no passphrase) and writes
# the unsigned file the next line reads. Its default blockhash is a random
# placeholder: perfect to exercise the daemon, it will NOT confirm on chain.
#
# FOR A REAL TRANSFER — a fresh blockhash, obtained by a step that actually
# runs (the package ships @solana/web3.js, so this works right after
# install; measured 2026-11-05: 1.98.4 returns the hash DIRECTLY, so it is
# r.blockhash, not r.value.blockhash as in web3.js 2.x docs):
BLOCKHASH=$(node -e "new (require('@solana/web3.js').Connection)('https://api.mainnet-beta.solana.com').getLatestBlockhash('finalized').then(r=>console.log(r.blockhash))")
signerd build-tx --keystore ~/.config/signerd/ops.key \
            --to So11111111111111111111111111111111111111112 \
            --lamports 42 --out tx.bin --blockhash "$BLOCKHASH"
signerd sign --socket ~/.local/share/signerd/signerd.sock --grant ops-24h --tx tx.bin

# optional (opt-in, fail-closed): seal the grant file and the journal against
# content written by anyone who could write them before the daemon looks. After
# this, the daemon refuses unsealed or altered files instead of trusting mode
# checks alone.
#
# ORDER MATTERS, and the order is the one the tools need:
#   1. seal the GRANT file (it exists already);
#   2. the JOURNAL is created by the daemon on its first append - the `sign`
#      line above is that append - so `seal-journal` comes AFTER it;
#   3. STOP the daemon (it holds the journal lock while it serves; a live
#      lock is refused with `ledger_locked: pid <n>` - that refusal is the
#      daemon's protection, not a bug), then run the two seal commands;
#   4. restart the daemon in sealed mode (the command below).
# The flags below are the tools' own: `seal-grants` reads
# --seal-passphrase-file, `seal-journal` reads --journal for the path.
signerd seal-grants --grants ~/.config/signerd/grants.json \
            --seal-passphrase-file ~/.config/signerd/seal.pass
signerd seal-journal --journal ~/.local/share/signerd/journal.jsonl \
            --journal-seal-passphrase-file ~/.config/signerd/seal.pass

# now restart the daemon in SEALED mode: the same command as above, plus the
# two seal passphrases. A sealed daemon refuses an unsealed, altered or
# shortened grant file or journal (grant_file_unsealed / grant_file_seal_mismatch
# / ledger_sealed / ledger_mac_short).
signerd run --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass \
            --grants ~/.config/signerd/grants.json \
            --ledger ~/.local/share/signerd/journal.jsonl \
            --socket ~/.local/share/signerd/signerd.sock \
            --grant-seal-passphrase-file ~/.config/signerd/seal.pass \
            --journal-seal-passphrase-file ~/.config/signerd/seal.pass
# A sealed grant file is rewritten only by the CLI: `grant-add --append` and
# `grant-remove` re-seal it as part of the act (they need
# --seal-passphrase-file). Hand-editing a sealed file breaks its seal and the
# daemon then refuses the file (grant_file_seal_mismatch).
# Note (measured, not asserted): the signing path itself never touches the
# network — that fetch runs in YOUR shell, and signerd stays offline. The
# signed wire is then valid to mainnet itself except for one thing this
# quickstart cannot give you: the fee payer must hold SOL. Measured with
# `node tools/measure-wire-validity.mjs` (simulation only, nothing
# submitted): an unfunded fee payer comes back AccountNotFound, a
# placeholder blockhash BlockhashNotFound, and a flipped signature byte
# SignatureFailure — the instrument's three controls (research/
# wire-validity-2026-11-05.json).
#
# Simulation is not acceptance: `node tools/measure-wire-submission.mjs`
# (2026-11-05) SUBMITS that signed wire — funded fee payer, fresh blockhash,
# product daemon signature — to a real Solana runtime on a LOCAL
# solana-test-validator (agave 4.3.2; mainnet never contacted; the
# instrument refuses any non-loopback endpoint with exit 3). Measured: the
# runtime ACCEPTS the wire, it lands confirmed with err=null, and the ledger
# delta is exactly -(42 + 5000 lamport fee) on the payer, +42 on the
# destination; the three controls are each REJECTED for their own class
# (placeholder -> blockhash, flipped signature -> signature, unfunded payer
# -> balance). Artifact research/wire-submission-2026-11-05.json. Limits,
# stated with the result: a local validator is the same runtime code, not
# the same chain — no mainnet state, fee market or congestion; mainnet
# acceptance was not measured because funding a mainnet fee payer moves
# real lamports.
```

```js
// The client API that exists today (measured 2026-11-05 against the
// installed package, research/install-path-v0.2.0-2026-11-05.json):
// signViaDaemon returns the daemon's answer verbatim — a refusal is data,
// not an exception.
const { buildTransferWire, signViaDaemon } = require('signerd/src/client.js');

const wire = buildTransferWire({
  fromPubkey,     // the fee payer's PUBLIC key — no secret crosses this line
  toPubkey,
  lamports: 42,
  blockhash,
});
const answer = await signViaDaemon({ socketPath, grant: 'ops-24h', wire });
if (answer.ok) {
  const signedWire = Buffer.from(answer.signed, 'base64');   // 215 bytes, seq 1
} else {
  console.log(answer.error);   // e.g. 'alt', 'version_or_alt', 'window_cap'
}
```

The earlier version of this section showed a `Signerd.connect(...)` / `signer.sign(...)` API. **That API does not exist** — the package exports `Daemon` and `request` from `signerd/src/daemon.js` and the four helpers above from `signerd/src/client.js`; there is no `Signerd` export anywhere in the tree (measured 2026-11-05: `require('signerd/src/daemon.js')` yields `['Daemon','request']`). A typed SDK is a plan, not a shipped surface, and the snippet above is the one that runs.

`examples/user-zero-client.js` is the same thing in executable form: it builds an unsigned
legacy transfer from a fee payer's **public** key, sends it, and writes back the signed wire.
It never opens a key file — see "User zero, measured" below.

**2026-11-07: an unwritable `--out` is refused before the daemon signs.**
Measured on the tree at `aebe5f9`: with `--out` aimed at a directory that did not exist,
`signerd sign --out …` made the daemon **sign first** — the journal grew 366 bytes, the budget
was charged, the replay identity was recorded — and only then crashed on `fs.writeFileSync`
with a bare `ENOENT:` and exit 1. The signature was thrown away, and retrying the identical
wire with a corrected `--out` was permanently refused `replay`: budget spent, nothing delivered,
and the operator's repair ("create the directory") could never take effect. `sign-message`
(303 journal bytes, receipt lost), the shipped `examples/user-zero-client.js` (uncaught ENOENT),
`build-tx` and `seal-grants` (bare errno, exit 1) had the same shape.

Every `--out` consumer now runs a preflight (`src/out-preflight.js`) **before** the socket is
touched: a missing/unwritable parent, an existing directory as target, or an unwritable target
file is refused with `out_parent_unwritable` / `out_is_directory` / `out_unwritable`, a `fix:`
line (e.g. `mkdir -p <parent>`) and exit 2 — journal untouched (0 bytes), no budget, no replay
entry, so the corrected retry signs for real. That retry is the falsification. Pinned by
`test/out-preflight.test.js` (9 cases: 7 red on the pre-fix tree, 2 guards) and
`tools/mutation-ladder-out-preflight.sh` (6 mutations, each caught, tree restored
byte-identically). Limits: preflight checks what the local filesystem answers at that moment
(a TOCTOU window remains — `writeFileSync` errors are still possible), and it does not create
the parent directory for you.

**2026-11-07: a delivery that fails *after* signing keeps the signature (exit 3).**
The preflight above closes the door on the failures it can see, but it cannot see every one:
the filesystem can change between the preflight and the write, the disk can fill, and the
output path can be a node the preflight did not classify. Measured on the tree at `aebe5f9`,
each of these destroyed a **paid-for** signature — the daemon had already signed, the journal
had grown, the budget was charged and the replay identity recorded, and then the write failed:

| `--out` target | old behaviour | consequence |
|---|---|---|
| dangling symlink | preflight said `ok:true`; `ENOENT` after signing | signature lost, retry refused `replay` |
| a FIFO | preflight said `ok:true`; the daemon's `open` blocked forever | daemon hung **after** signing |
| `ulimit -f 0` (`RLIMIT_FSIZE`) | `EFBIG` after signing | signature lost, retry refused `replay` |
| an existing 200-byte file | `O_TRUNC` truncated it to **0 bytes**, then the write failed | the operator's old file destroyed *and* no new one |
| an existing `0644` file | the write succeeded and the file stayed `0644` | the delivered signature stayed world-readable |

Two changes close that window.

**The preflight now judges the *resolved* target.** `src/out-preflight.js` follows the final
symlink chain (`lstat` at every hop, never `stat`, 32-hop limit) and refuses what the write
would actually open: a symlink loop (`out_symlink_loop`), and any non-regular node — directory,
FIFO, device, socket (`out_not_regular_file`). A symlink to a **valid** regular file is
accepted and written *through*; the link is not the defect.

**Delivery is atomic.** `writeOutAtomic()` writes a same-directory temporary file at mode
`0600`, `fsync`s it, and `rename`s it over the target. A failed write therefore never touches
the previous file, and a successful one lands `0600` regardless of the target's old mode.

**The exit code says what happened.** `bin/signerd.js`, `examples/user-zero-client.js`,
`src/buildtx.js` and `seal-grants` now distinguish four outcomes:

| exit | meaning |
|---|---|
| 0 | signed **and** delivered |
| 1 | the daemon or the policy refused (no signature was made) |
| 2 | a usage/preflight refusal (no signature was made) |
| 3 | **the signature was made, the file delivery failed — and the signed wire IS on stdout** |
| 4 | **the signature was made, and the artefact is UNRECOVERABLE** (neither `--out` nor stdout could carry it) |

On exit 3 the signed wire (or the signed receipt document) is **still on stdout**, and the
error is reported as `outError` in the JSON answer plus a `fix:` line on stderr. The
signature is no longer thrown away: an operator can salvage it with the repair the error
names, and the journal already records what was signed. Pinned by `test/out-delivery.test.js`
(13 cases: 10 red on the pre-fix tree, 3 guards) and `tools/mutation-ladder-out-delivery.sh`
(8 mutations, each caught, tree restored byte-identically). Limits: exit 3 still means the
`--out` file does **not** contain the signature — the artefact is on stdout; the preflight is
still a point-in-time check, so a TOCTOU window remains (that window is what exit 3 exists
for); and a symlink chain longer than 32 hops is refused rather than followed.

**2026-11-08: exit 3 is a promise the CLI now VERIFIES (the recovery channel is checked, not assumed).**

The exit-3 promise above is exactly the promise the product must not break: *the artefact
is on stdout*. Nothing used to check that. Measured on the tree that shipped v0.2.9, with a
live daemon that really signed (the journal grew `366 -> 732` bytes, so **the spend
happened**):

| stdout channel | old behaviour | consequence |
|---|---|---|
| a regular file under `ulimit -f 0` (the ordinary `... > signed.json` capture) | `process.stdout.write(...)` then immediate `process.exit(3)` | **exit 3, stdout 0 bytes, stderr 0 bytes** — the write never reached the kernel and the error event never surfaced |
| `/dev/full` (opens, every write fails `ENOSPC`) | same | same: exit 3 with nothing anywhere |
| `/dev/null` (the write *succeeds* and the bytes are discarded) | same | exit 3 while nothing retains a byte |

The exit code said "the artefact is here" in the one place the product promised truth.
Three changes close it:

**The response is written with a synchronous, length-checked write** (`src/stdout.js`).
`fs.writeSync(1, ...)` returns how many bytes landed; under `RLIMIT_FSIZE` it can write
*part* of the payload and fail on the next call, so the write is looped until the full
length is down or an error is recorded. A partial write is a **failed** delivery — a
truncated artefact is not an artefact. `EAGAIN` (a momentarily full pipe) is retried
bounded; a zero-length probe is never used, because it succeeds on `/dev/full` and proves
nothing.

**The channel must RETAIN the bytes** (`stdoutRetainsBytes()` reads
`/proc/self/fd/1`). `/dev/null` and `/dev/zero` accept every write and keep nothing, so
"no error" is not proof of delivery. When `/proc` is unavailable the write result decides,
and that assumption is documented rather than silent.

**An exit code may only claim what was verified** (`src/recovery.js`). Exit 3 now means
*the write landed in a channel that keeps it*; if it did not, the CLI exits **4**, prints
`recovery_failed:` on stderr with the errno and the repair, and says plainly that the
journal recorded the spend while the signature itself is gone. Exit 1 would be a lie in
the other direction (1 says "no signature was made"), which is why 4 exists.

Pinned by `test/recovery-channel.test.js` — 8 cases, 4 red on the pre-fix tree (CASE A a
file stdout under `ulimit -f 0`, CASE B `/dev/full`, CASE D `/dev/null`, CASE E a
**partial** write under `ulimit -f 1`) and 4 guards green on both trees (a healthy pipe
still gets the complete exit-3 response, ordinary capture still exits 0, the example
client keeps its contract), so the fix cannot be "pass by changing the healthy path".
The red baseline was captured against the **real pre-fix binaries** in a separate git
worktree at `0059c7a`, not against a simulation — it is committed at
`research/recovery-channel-2026-11-08/red-baseline.txt` (4 red, 4 green), with the
measurement and its limits in `research/recovery-channel-2026-11-08/report.md`.
`tools/mutation-ladder-recovery-channel.sh` breaks each property of the fix in a
plausible way (6 mutations: the async write of v0.2.9, the partial-write check, the
retention check, the exit-3 lie, the silenced statement, an unverified second command)
— each is caught, and the tree is restored byte-identically.

Limits: the check happens at
the moment of the write, not before the sign — a channel that breaks *between* the
verification and the reader is still outside the contract (that window is what the
journal's hashes are for); when `/proc` is unavailable, retention is assumed; and the
new exit code 4 is unknown to a consumer that only knows 0/1/2/3 (the greppable
`recovery_failed:` on stderr is the contract).

**2026-11-07: the example client obeys the daemon's flag surface, and `--dry` is real there.**
The client ships in the npm package, and until now it carried its own hand-rolled parser.
Measured against the real daemon, that parser dropped flags without a word: `--totally-unknown x`
exited 0 with a **real** signature and 366 journal bytes; `--lamports 22 --lamports 999`
exited 0 with a real signature **for 999** (last value wins, silently); `--out` with no value
exited 0 with a real signature (the flag read as absent); `--hold yes` exited 0; and `--dry`
exited 0 with a **real** signature — the reverse of what the flag means. A client that drops
flags signs what the operator did not ask for.

It now parses with the same rules as `bin/signerd`: a flag it does not take is refused
(`unknown_flag: --x`, with the repair), a flag given twice is refused (`duplicate_flag:`, naming
**both** values), a value flag with no value is refused (`missing_value:`), and a switch given
a value is refused (`flag_takes_no_value:`) — each before any wire is built or any socket is
touched, each with a `fix:` line and exit 2. `--dry` runs the same policy and budget decision
and answers `{"ok":true,"dry":true,...}`: no signature, no `--out`, no journal record, so the
identical request still signs for real afterwards — that is the falsification, pinned by
`test/user-zero-client-surface.test.js` (9 cases: 6 red on the pre-fix tree, 3 guards) and
`tools/mutation-ladder-client-surface.sh` (8 mutations, each caught, tree restored
byte-identically). Limits: this is argument hygiene in the example, not a sandbox — the value
of a flag is still judged by the daemon (cap, destination, policy), and the client holds no key
whether or not you pass `--dry`.

The planned core is a Rust daemon, a TypeScript SDK, and a built-in MCP server.

**Shipped 2026-11-06: `--dry` is real.** `signerd sign --dry` and `signerd sign-message --dry` (and a strict `dry: true` boolean on the wire frame) run the *same* scope path — the same policy evaluation, the same replay check, the same rolling-window and per-transaction budget decision — without producing a signature and without writing the journal: no record, no replay entry, no window spend, so the identical request can still be signed for real afterwards. Refusals are identical to the real path, so a dry `allowed: true` is a promise the real path keeps except when a concurrent request spends the same budget in between. Two deliberate limits: `dry` must be a boolean or the request fails closed with `request_invalid` (never degraded into a real signature), and a dry run writes nothing to `--out`. Pinned by `test/dry-run-surface.test.js` (7 cases) and `tools/mutation-ladder-dry.sh` (7 mutations, each one caught). **2026-11-06 (day 8 of the live test): the same contract now holds through the real consumer** — `test/dry-consumer-falsification.test.js` previews the identical `receipt.py` body with `--dry` and then signs it for real (4 tests, red on the pre-fix tree; 5 mutations caught); the live sequence runs in `research/consumer-live-2026-11-06/`.

### User zero, measured

The claim "the client holds no key" is an empirical statement about a running process, not
about source code, so `test/user-zero.test.js` measures it. The test migrates a plaintext
key file into a keystore, starts a daemon, runs the example client as a **separate process**
that then stays alive, and scans that process's whole address space (`/proc/<pid>/mem`) for
the 64-byte secret:

| process | copies of the secret key found |
|---|---|
| control: a client that does `Keypair.fromSecretKey` the old way | **1+** (positive control) |
| the daemon | **3** — this is where the key is supposed to be |
| `examples/user-zero-client.js`, which just got a signature | **0** |

The control is what makes the zero mean something: if the scanner could not find a key that
is demonstrably present, the subject's zero would be an artifact of the instrument. The test
also refuses to report absence unless every writable mapping was actually read — an unread
heap cannot be searched, and silence there is not evidence. The signature the client received
is verified independently under Node's OpenSSL ed25519 against the public key.


### What the v0 daemon does today

- **`src/keystore.js`** — encrypted keystore: scrypt (N=16384) + AES-256-GCM, file mode 0600. A keystore file with any group/other permission bit is refused even though decryption would succeed, as is a keystore **directory** that is group- or world-writable or not owned by the current user; a wrong passphrase and a tampered ciphertext are indistinguishable (`keystore_auth_failed`). `importKeystore` adopts an **existing** plaintext secret (the migration path): it accepts a solana-keygen JSON byte array, a base58 secret, or 64 raw bytes, refuses anything it cannot decode unambiguously, validates the key before writing anything, and never deletes or rewrites the source file.
- **`src/client.js`** — the client half: builds an unsigned legacy transfer from public values only and asks the daemon to sign. A refusal is returned as data, not thrown, so a caller learns *why* rather than working around it.
- **`src/grantfile.js`** — one strict grant file. Unknown fields are refused (a typo in a security file is a mistake, not an extra rule), grant names may not reach `Object.prototype`, and the loaded grants live on a null prototype. The file is **re-read on every request**, so a revocation takes effect on the next request instead of after a restart; its directory and ownership are checked on every read, a symlink at that path is refused, and a file another user can write is tightened (or refused if it cannot be).
- **`src/daemon.js`** — a Unix socket (mode 0600) speaking newline-framed JSON. A request carries a grant **name** and base64 wire bytes (or a JSON-text `body` for message grants); the response carries a signature or a machine-readable refusal. The socket is a capability: only the owner can talk to it, and only the instance that bound it may unlink it. Exactly one request is served per connection, and an extra frame is refused *before* it can be parsed or charged. The request frame is capped at **25600 transport bytes** — derived from the true worst case of the body contract (4096 chars × 6 bytes for control-char re-escapes, plus envelope) so every contract-admitting body always fits; a frame over the cap is refused **by name** (`request_too_large`, with the bound and the repair in the response), never destroyed in silence. The shipped client names a verdict-less connection close as `connection_closed` instead of blaming its own clock. The daemon holds an atomic single-writer lock on the journal for as long as it serves, and releases it only after the server is closed and its connections are drained.
- **`src/signer.js`** — the signing path. Order is deliberate: grant/key mismatch is refused *before* any ledger write, the ledger fsyncs *before* signing, and the returned bytes are checked to differ from the approved wire only inside the 64-byte signature slot and to verify under Node's OpenSSL ed25519 implementation. If signing or verification fails after approval, the budget is burned and **nothing** is signed — the conservative direction.

The v0 daemon still only speaks the narrow legacy System-transfer envelope of `src/policy.js`: one instruction, three accounts, one signer, no ALT, no CPI, no Token-2022, no authority change.

### Recent fixes and lessons

**2026-11-13: `seal-grants` judges with the product's own loader.**

`seal-grants` was the one write path to the grant file that did **not** run through the
product's loader (`src/grantfile.js`) — the judge `grant-add --append`, `grant-remove` and
the `sign-message --add-grant` bootstrap (fixed for the same class on 2026-11-11) all
consult. Measured live on the tree at `98bcfa0` (= published v0.2.20): a document with a
cap below the 5000-lamport base fee, a typo'd field (`maxLamport`), a reserved name
(`__proto__`) or a symlink at the grant path was sealed with `exit 0` and `{"ok":true}` —
making an unloadable document **authentic** while `status`, `grant-remove` and `run` refuse
the same file. The `__proto__` face also vanished from the printed summary (`grants:[]`),
so the "what was sealed" line the command exists to print was wrong on exactly the file an
operator most needed to see.

`seal-grants` now runs the file through `loadGrantFile` **before** computing a seal: a
symlink is refused by name (`grant_file_symlink`, with the repair `grant-add` names), and
everything the loader refuses — directory mode and ownership, the read lease, file owner
and mode, schema, unknown fields, reserved names, value semantics — is refused before a
byte is written, with the loader's own reason and repair line. The sealed payload is built
from the loader's validated grants. Guards: sealing a valid file, re-sealing an already
sealed file (the documented "edit by hand, then re-seal" repair) and `seal-grants --out`
to another path all still work.

Pinned by `test/seal-grants-judge.test.js` (7 cases: 4 red on the pre-fix tree, 3 guards
green on both), the two-tree measurement `tools/measure-seal-grants-judge.js` →
`research/seal-grants-judge-2026-11-13.json` (verdict `seal-grants-judge-holds`, prefix
shows all 4 faces, fixed tree refuses all 4, guards hold) with its pin
`test/seal-grants-judge-measurement.test.js` (P1–P6), and
`tools/mutation-ladder-seal-grants-judge.sh` (4/4 mutations caught, control green, tree
byte-identical). Limits: this closes the *seal* path only — `seal-grants` still trusts the
file content it is handed (sealing a forged file makes the forgery valid; it prints what
it sealed for that reason), and the loader judges the file at the instant of the read,
same TOCTOU window as every other path here.

