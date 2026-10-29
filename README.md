# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys. signerd signs only the subset of transactions it can fully verify offline; everything else gets a structured refusal — and that refusal is the feature.

**Status: v0 prototype (October 2026), NOT a signing service or security-reviewed wallet.** The scope was narrowed on 2026-10-26 after an adversarial review (see Safety boundary). On 2026-10-27 the first tested *legacy System-transfer-only* refusal checker and its atomic expenditure/replay ledger were added; on 2026-10-27/28 the local daemon (Unix socket, encrypted keystore, grant file) was added. **The daemon holds a real key and produces real signatures — it has passed two independent adversarial reviews (the daemon hardening diff on 2026-10-27, and the signing path on 2026-10-29), each with every finding fixed and regression-tested against the reviewed code, but no professional audit has happened and no real funds should use it yet.** The rest of the v1 envelope below remains a plan.

## The idea

Today every Solana process that signs a transaction loads the full keypair into its own memory: `Keypair.fromSecretKey`, `id.json`, or `SOLANA_PRIVATE_KEY`. Authorization is binary. A process either holds the master key or can do nothing.

signerd inverts that:

- The key lives once, in a local daemon, encrypted at rest and exposed only through a Unix socket.
- Processes hold scoped grants, not keys.
- The daemon checks a transaction against the grant **before** signing — and signs only what it can decide from the transaction bytes alone. Anything undecidable is refused with a machine-readable reason, never guessed.

The useful new capability is that an agent can be told, "you may send SOL and these tokens to these destinations, up to 0.5 SOL, for 24 hours," without receiving the key and without being watched. A prompt-injected agent hits a wall instead of a silent gap.

## Safety boundary (measured, not assumed)

An adversarial review on 2026-10-26 built and ran a counterexample probe (`@solana/web3.js`, zero network) against a naive bytes-only engine. Result: five attack classes bypass offline checking, and no parser can fix them — the required information is not in the bytes.

**Enforceable offline (proven by the probe's control case):** transactions with zero address-table lookups, restricted to programs that cannot invoke other programs, with amounts read from instruction data and per-window accounting held statefully by the daemon.

**Structurally refused in v1, because undecidable offline:**

1. Any transaction using address lookup tables — the resolved destination, program id, or account content is not in the bytes (Turnkey ships the same guard: deny `address_table_lookups.count > 0`).
2. Any program that can CPI (Whirlpool, Jupiter, …) — inner instructions are not part of the signed message.
3. Token-2022 — transfer fees, hooks, and permanent delegates depend on on-chain mint state.
4. Authority-changing instructions (`Delegate`, `Approve`, `SetAuthority`, `CloseAccount`, `Freeze`) — spend caps cannot express "no authority changes".

A later, explicitly labeled `--simulate` mode may add RPC-backed checking for the refused classes, the way kora does it today. That path is never claimed as offline.

## The v1 envelope (refuse by default)

- Allowed programs: System, Memo, ComputeBudget, plus top-level SPL **Token (not Token-2022)** `Transfer` / `TransferChecked` on allowlisted mints and destinations.
- Hard refusal of ALTs, arbitrary programs, Token-2022, and all authority instructions.
- Per-transaction and per-window caps, summed across transactions by the daemon.
- Structured refusals: `{refused: "alt", detail: …}`, so a caller can learn why instead of working around it.

## Shape

```bash
# one-time setup: an encrypted keystore and a grant file
signerd keygen --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass

# OR adopt a key you already hold — the migration path. Reads a solana-keygen
# id.json, a base58 secret, or 64 raw bytes; encrypts it; leaves the source alone.
signerd import --keystore ~/.config/signerd/ops.key --from ~/.config/solana/id.json \
             --passphrase-file ~/.config/signerd/pass

signerd run --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass \
            --grants ~/.config/signerd/grants.json \
            --ledger ~/.local/share/signerd/journal.jsonl \
            --socket ~/.local/share/signerd/signerd.sock

# a client: no key material, only a grant name and the transaction bytes
signerd sign --socket ~/.local/share/signerd/signerd.sock --grant ops-24h --tx tx.bin
```

```ts
const signer = await Signerd.connect({ grant: "ops-24h" });
const signature = await signer.sign(transaction);  // or: { refused: "alt" }
```

`examples/user-zero-client.js` is the same thing in executable form: it builds an unsigned
legacy transfer from a fee payer's **public** key, sends it, and writes back the signed wire.
It never opens a key file — see "User zero, measured" below.

The planned core is a Rust daemon, a TypeScript SDK, and a built-in MCP server. `--dry` runs the same scope path without producing a real signature.

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
- **`src/daemon.js`** — a Unix socket (mode 0600) speaking newline-framed JSON. A request carries a grant **name** and base64 wire bytes; the response carries a signature or a machine-readable refusal. The socket is a capability: only the owner can talk to it, and only the instance that bound it may unlink it. Exactly one request is served per connection, and an extra frame is refused *before* it can be parsed or charged. The daemon holds an atomic single-writer lock on the journal for as long as it serves, and releases it only after the server is closed and its connections are drained.
- **`src/signer.js`** — the signing path. Order is deliberate: grant/key mismatch is refused *before* any ledger write, the ledger fsyncs *before* signing, and the returned bytes are checked to differ from the approved wire only inside the 64-byte signature slot and to verify under Node's OpenSSL ed25519 implementation. If signing or verification fails after approval, the budget is burned and **nothing** is signed — the conservative direction.

The v0 daemon still only speaks the narrow legacy System-transfer envelope of `src/policy.js`: one instruction, three accounts, one signer, no ALT, no CPI, no Token-2022, no authority change.

## Free and paid

- Free, MIT: daemon, encrypted keystore, the full v1 envelope, local socket, CLI, SDKs, MCP server, and append-only local audit log. No usage limits and no telemetry.
- Paid later: managed high-availability operation, HSM or PKCS#11 backends, and organization controls such as SSO, approval workflows, and audit export. Signing itself is never sold per call.

## Landscape (honest)

- **kora** (Solana Foundation, MIT, 203★) — self-hostable signer server whose policy layer (allowlists, spend limits, Token-2022 rules) resolves everything via RPC and simulation. Proves the category; it is network-facing rather than a local socket, and its guarantees depend on the RPC.
- **solana-keychain** (Solana Foundation, MIT, 77★, audited) — an open signing framework that deliberately validates the signing hop, never what a transaction does.
- **Turnkey** (closed) — policy engine that documents the same ALT undecidability and ships a deny-ALT policy.
- **Steward** (EVM-focused, MIT, 98★) — states in its own README that local envelope modes expose plaintext key material at sign time.

Checked on 2026-10-24/26, re-measured on 2026-10-28 with `tools/key-load-sites.mjs` (output in `research/key-load-sites-2026-10-28.json`): the earlier "21 files across six of my own repositories" was wrong — it counted checkouts sitting in my working directory as if they were repositories I control. Of 85 key-load files across 51 local checkouts, 72 are in third-party clones with no write access, 4 in my fork of `orca-so/whirlpools`, and 9 in the two repos I author: 8 in signerd itself (keystore, signer, tests — this is where the key is supposed to be) and 1 in `openreceipts` (Ed25519 receipt signing, not a Solana transaction path). "Migrate my 21 key-load sites" was therefore never a real backlog.

**Envelope fit of that one remaining site, measured 2026-10-28/29** (`tools/envelope-fit.mjs`, output in `research/envelope-fit-openreceipts-2026-10-28.json`, offline proof in `test/envelope-fit.test.js` + `test/envelope-fit-tool.test.js`): the note had guessed "probably not, Ed25519 instead of Solana-Tx". The verdict holds, the reason does not — both are Ed25519. The PKCS8 seed in `~/.openreceipts/auroraxo.key` derives the same public key under both OpenSSL and web3.js, `signerd import` accepts that key after a mechanical PEM→raw conversion, and the **published identity is measured, not assumed**: the site-derived key equals the pinned issuer key (`openreceipts/keys/auroraxo.pub`, byte-for-byte) and verifies all 6 published receipts under their canonical `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` bytes — the JS canonicalizer in `src/receipt-identity.js` is hash-identical to Python's on all 6 receipts, and a receipt signed by a different key, a flipped byte, or a mismatched pinned key makes the tool report FAILED rather than pass (the harness asserts that refusal). What does not fit is the **message domain**: openreceipts signs canonical JSON receipts, the v0 envelope signs a legacy System transfer wire, so `policy.evaluate` refuses a receipt body (`invalid_wire`) and should. The refusal is not a tooling gap — importing the key without a message-grant envelope would move a key the daemon cannot use, so no migration is built. Unchanged: `sendaifun/solana-agent-kit` documents a raw private key as its setup path; a keyword scan of 1,123 live Solana-ecosystem repositories found no local scoped-signing daemon (a scan, not a semantic census); this remains a hypothesis with zero outside users.

## First executable increment (policy only, not a signer)

`src/policy.js` evaluates serialized transactions with `evaluate(wire, grant, now)` and returns `{ allowed: true, amountLamports: "…" }` or `{ allowed: false, refused: "…" }`. It deliberately permits **only one** legacy System Program transfer from the grant signer/fee payer to one fixed destination under a string-encoded lamport cap. The sole signer must be the source and fee payer; the only keys must be source, destination, and System Program. V0 is refused even without ALTs. Any extra instruction (including ComputeBudget/priority-price drain), SPL Token/Token-2022 instruction, authority change, CPI-capable program, invalid grant, expired grant, or noncanonical wire is refused. The tests generate disposable keys locally and cover both the one allowed case and the known attack classes.

`src/ledger.js` is the accounting layer that must sit between a positive verdict and any future signature. `gate(wire, grant, now, ledger)` refuses with `ledger_unavailable` when no ledger is attached, so a policy verdict alone never spends budget. The ledger keeps an append-only JSONL journal, fsyncs it **before** returning an approval, and charges each approval `amount + 5000` lamports (the envelope allows exactly one signature and no ComputeBudget instruction, so the base fee is fixed and no priority fee can be attached) against a rolling per-scope window:

- **Scope-keyed budget**: spend is counted per signer+destination pair, so two grants aimed at the same destination share one window cap instead of each getting a fresh one.
- **Replay**: one transaction **message** is approved at most once, ever, across restarts (SHA-256 of the message, persisted in the journal). The message — not the bytes the client sent — is the identity, because the 64-byte signature slot is client-controlled and is overwritten by the daemon: two wires that differ only there are one transaction, and the signed artifact the daemon returns carries that same message. The raw wire hash is recorded alongside it (`w` / `m` in journal format 2). A journal written before 2026-10-29 (format 1) carries only the wire hash, so it is **refused at load** (`ledger_legacy_format`) until migrated explicitly: `signerd migrate --ledger <file> --wires <dir>` (the original wires restore message identity for every record; a missing wire refuses and writes nothing) or `--discard-legacy` (keeps window spend, marks message identity unknown, and reports the accepted gap via `legacyState`). The original journal is kept as `<file>.pre-migrate.<random>.bak` (exclusive create, never overwritten); the migration holds the daemon's journal lock throughout.
- **Self-verifying**: every record carries a hash of its own fields chained to the previous record's hash, so the journal is a hash chain. An in-place edit — even a same-size one, e.g. `"a":"42"` → `"a":"12"` — breaks the chain and makes the load fail closed (`ledger_tampered`) instead of being silently trusted.
- **Fail closed**: an unreadable or corrupt journal makes the constructor throw; a torn final line (crash mid-append) is dropped and repaired, never parsed; an fsync failure during approval returns `ledger_write_failed` with nothing entering in-memory state; if the rollback of a failed append also fails, the ledger poisons itself and refuses every later approval (`ledger_inconsistent`); window refusals occur before any write.
- **Foreign-write detection**: before every append the ledger re-reads the file and compares both its length and its SHA-256 with the state it last wrote, so an outside writer is refused (`ledger_changed`) rather than merged into.
- **Journal hygiene**: the journal *is* the replay set and the window budget, so it is validated before a single record is read — it must be a regular file (not a symlink), owned by us (or root), and not group/other writable; its directory must not be group/other writable (a sticky directory is allowed) and must be ours. A readable-only journal is tightened to 0600 instead of bricking the daemon; a journal someone else could write is refused (`ledger_mode` / `ledger_owner` / `ledger_dir_mode`).
- **Clock safety**: a backwards clock cannot shrink recorded window spend.
- **No global side effects**: the library never mutates `process.umask`; the journal is created 0600 explicitly.

The atomicity claim is falsified, not asserted: `npm run test:crash` spawns a child that approves transfers in a loop, SIGKILLs it at pseudo-random points (25 rounds), and asserts that every approval the child *reported* is durable in the journal afterward — i.e. the journal is a superset of what any caller was told, and it still loads after a torn append.

### Independent adversarial probe (2026-10-27)

An independent worker ran 132 adversarial cases (raw message construction, data-field shifts, wire malleability, grant manipulation, re-serialization tampering, hidden instructions) against the implemented code. Findings and disposition:

- **Fixed — prototype-polluted grant fields**: a grant missing `expiresAt` / `windowMaxLamports` silently inherited the value from a polluted `Object.prototype`, changing the verdict. All grant fields are now read from **own properties only** (`ownField`), and accessors (getters) are refused so a TOCTOU getter cannot report the cap twice.
- **Fixed — hostile clock**: a `Date` subclass overriding `getTime()` could make an expired grant look current. The clock is now read once, and only from a genuine `Date` (`readClock`); subclasses are refused.
- **By design, not a defect**: amount `0` is allowed (it moves nothing, and the ledger still charges its 5000-lamport fee); operator-chosen grant values (`maxLamports = u64max`, far-future `expiresAt`) are honored as written; signature bytes are deliberately not verified — the policy attests to the *message*, and the future signing path decides what to sign; a flipped blockhash byte passes because the blockhash is not (and cannot be) validated offline — it merely fails on-chain.
- The probe worker timed out before writing its own report; the raw case log survived (`allowed`/`refusedCounts`/`errors` + per-case detail), and both defects above were independently reproduced and then regression-tested before being called fixed.

It does **not** parse transactions, hold keys, or sign. **One writer per journal file, enforced by an atomic lock**: the daemon claims `<journal>.lock` with a unique per-instance token via `open(O_EXCL)` + `link()`, so two daemons can never hold the same lock. A stale lock whose owner is provably dead is taken over by renaming it aside and proving the moved bytes are the ones that were judged dead; if they differ, the takeover backs off instead of stealing. The journal grows without bound (compaction is future work).

```bash
npm ci
npm test
```

**Not safe for real keys yet.** The policy prototype is unit-tested and the daemon is tested end-to-end over a real socket (86 tests: 9 policy, 20 ledger, 18 daemon, 8 signer, 7 grant file, 8 keystore, 8 review-#2 regressions, 5 envelope-fit, 2 user-zero). The daemon's signing path passed **two independent adversarial reviews** (2026-10-27 on the hardening diff, 2026-10-29 on the signing path), each with every finding fixed and regression-tested — but neither is a professional audit, so do not point it at a key with funds yet. It has no authentication beyond the socket's file mode, no key rotation, and the ledger does not bind transaction lifetime (blockhash freshness) — a stale blockhash simply fails on-chain.

### Adversarial review of the daemon (2026-10-27) — findings and fixes

An independent reviewer ran the suite (green) **plus 8 isolated probe scripts** in `/tmp` that the repo's own tests did not cover. The suite was green while five real defects existed, so each finding below now has a regression test that **fails against the reviewed code and passes against the fix** (verified by running the new tests against a copy of the pre-fix tree: 7 failures, all fixed afterwards).

- **Fixed — stale-lock takeover race (HIGH)**: the takeover was a classic TOCTOU (read lock → check pid → unlink → retry). Two daemons could both judge the dead owner and both acquire; the reviewer reproduced both daemons starting on one journal in 2/3 runs, signing **the same wire twice** (both reporting `seq 2`) and leaving a journal that could never load again (`ledger_corrupt`). The lock is now claimed atomically with a unique per-instance token (`open(O_EXCL)` + `link()`), and a stale lock is taken over by renaming it aside and byte-comparing the moved content with the content that was judged — if they differ, the takeover backs off. Verified: 5/5 race runs now yield exactly one winner (was: two).
- **Fixed — `stop()` released the lock before draining (HIGH)**: the lock was freed while the daemon was still serving in-flight requests, so a second daemon could start and the first could still sign. `stop()` now closes the server, drains open connections, unlinks the socket, and releases the journal lock **last**.
- **Fixed — orphan server after a post-`listen()` failure (HIGH)**: a `chmod` failure after `listen()` released the lock but left the server listening; `stop()` could not reach it. Startup now fails closed and closes the server.
- **Fixed — post-start server `error` (MEDIUM)**: the `error` handler was removed with the wrong function reference, so it stayed attached for the server's lifetime and released the lock while the daemon kept serving. It now triggers an orderly stop: stop serving first, release the lock last.
- **Fixed — invalid-UTF-8 tail destroyed a durable record (MEDIUM)**: the torn tail was measured *after* UTF-8 decoding, so one invalid byte became a 3-byte U+FFFD and the repair truncated **2 bytes into the last fsynced record**, silently dropping an approval. The tail is now located in raw bytes.
- **Fixed — same-size journal tamper accepted (LOW/MEDIUM)**: the foreign-write check compared only `statSync().size`, so an in-place same-length edit was accepted and then trusted on reload. The check now compares SHA-256, and the journal carries a per-record hash chain so a tampered file fails to load at all.
- **Fixed — keystore directory checks too weak (LOW/MEDIUM)**: only world-writable (`0o002`) directories were refused, so a group-writable (`0o770`) directory passed, and directory **ownership** was not checked at all. Both are now refused (`keystore_dir_mode`, `keystore_dir_owner`).
- **Fixed — library mutated global `process.umask` (LOW)**: the daemon constructor set `process.umask(0o077)` for the whole host process. The library no longer touches it; modes are set explicitly.
- **Coverage added**: stale-lock takeover, `stop()` ordering with a held connection, post-`listen()` failure, post-start `error`, UTF-8 tail, same-size tamper, group-writable/foreign-owned keystore directories, umask neutrality, and the poisoned-ledger rollback-failure path — all previously untested.

A caveat on the green suite: it was green *while* these defects existed, so "tests pass" was never the evidence that the guarantees held. The evidence is the probe scripts and the falsifying tests above.

### Adversarial review #2 of the signing path (2026-10-29) — findings and fixes

A second independent review targeted the whole signing path (`src/policy.js`, `src/ledger.js`, `src/signer.js`, `src/daemon.js`, `src/keystore.js`, `src/grantfile.js`) with the real daemon over a real socket, plus a socket-takeover exploit chain. It reported **6 findings, all reproduced** (R2-1 … R2-6), and every one has a regression test in `test/review2.test.js` that **fails against the reviewed tree (`90ac545`: 8/8 fail) and passes against the fix** — verified by running the file against an exported copy of the pre-fix code.

- **Fixed — R2-1 (MED): a failed `start()` or a never-started `stop()` unlinked a LIVE daemon's socket.** The cleanup unlinked `socketPath` unconditionally, so a second daemon that failed to start (or was stopped without ever starting) deleted the running daemon's socket file. Anyone who can bind that path then impersonates the signing daemon, and a client trusting the path accepts a forged approval. Ownership is now explicit: `socketOwned` is set only once *this* instance has bound the path, and only that instance removes it. A never-started `stop()` and a pre-`listen()` failure now leave the live socket untouched (verified: the rival's start fails with `socket_in_use`, the socket still exists, the original daemon still answers).
- **Fixed — R2-1b (MED, found while fixing R2-1): the socket's DIRECTORY was never checked.** Without that, a stranger who can write the directory can unlink the socket and bind their own server at the documented path — no daemon failure required. `start()` now refuses a group/other-writable (non-sticky) socket directory (`socket_dir_mode`) or one it does not own (`socket_dir_owner`), and creates a missing one as 0700 rather than inheriting the umask. A sticky directory like `/tmp` stays allowed, because only the file's own owner may unlink there.
- **Fixed — R2-2 (MED): the replay set was keyed on the client-controlled signature slot.** The 64-byte slot is overwritten by the daemon, so two wires differing only there are the same transaction — both were approved and both were signed, and the returned signed artifact was not in the replay set at all, so handing it back bought another approval. The replay identity is now the **message** (journal format 2 records both `w` = wire hash and `m` = message hash); the daemon reports `messageSha256` in its response so a client can check the returned artifact carries the message it asked for. **Limitation, documented rather than hidden:** a pre-upgrade journal (format 1) carries only wire hashes, so approvals recorded before 2026-10-29 keep wire-level protection only until they age out of the window.
- **Fixed — R2-3 (MED-HIGH): the journal had no owner/mode/directory validation, while the keystore already had all three.** The journal *is* the replay set and the window budget, so a foreign pre-created file, a group-writable journal, or a journal in a writable directory meant the spend record could be replaced or emptied. It is now validated before a single record is read (regular file, not a symlink, ours, not group/other writable; directory not writable-by-others or sticky, and ours). A readable-only journal we own is tightened to 0600 instead of bricking the daemon; anything a stranger could write is refused (`ledger_mode` / `ledger_owner` / `ledger_dir_mode` / `ledger_not_a_file`).
- **Fixed — R2-4 (LOW): the grant file was read once at startup, so revocation only took effect after a restart.** The file is now re-read on **every request**: a deleted grant stops working on the next request, a newly written grant works immediately, and an invalid grant file refuses every request instead of falling back to the grants cached at startup. Reloading on every request would have widened the attack surface, so the path is checked on each read too (directory mode/ownership, file ownership, no symlink, writable file tightened or refused).
- **Fixed — R2-5 (LOW): the framing buffer was never consumed, so the first request was re-handled on every later data event**, and a pipelined second request was silently dropped. One request is now served per connection; an extra frame is refused **before** `handle()` can parse, budget or sign it (pipelined frames get an explicit `one_request_per_connection` in the same write; late frames are dropped and the connection is reaped).
- **Fixed — R2-6 (LOW): `wire` accepted a JSON byte array.** `Buffer.from(array, 'base64')` ignores its encoding argument, so a byte array was converted and treated as a wire. The field must now be a non-empty **string** whose base64 round-trips to the same bytes — which also rejects base64url, whitespace and other junk Node's lenient decoder would otherwise swallow. A refused wire never touches the journal (asserted).

Re-verified against the fixed tree: the original probe scripts now report `socket_in_use` + socket still present (R2-1), `request_invalid` for a byte-array wire (R2-6), grant reload reflected on the next request (R2-4), same-message-prefills refused with `replay` and `ledgerRecords: 1` (R2-2), one response per frame with the second refused (R2-5), and `ledger_changed` for a journal swapped between construction and first append. The full suite (86 tests) and the crash harness (25 SIGKILL rounds, 118 reported approvals, all durable) are green.

### Adversarial review #3 (2026-10-29) — findings and fixes

Reviewed commit `2d0f1d9`; verdict VULNERABLE (1 HIGH, 1 MED, 1 LOW), all reproduced.

- **Fixed — R3-1 (HIGH): a group/other-writable grant file was chmod-"tightened" and then trusted.** chmod cannot undo a forged edit or revoke a write descriptor a stranger already holds, so the daemon signed attacker-chosen transfers. The grant file is now refused outright (`grant_file_mode`), like the journal.
- **Fixed — R3-2 (MED): the format 1 → 2 migration dropped message-level replay** (same message + different signature slot was re-approved and re-signed). Format-1 journals now fail closed; migration is explicit (see Replay above). Regression tests use genuine format-1 bytes in `test/fixtures/` (`test/journal-migration.test.js`).
- **Documented — R3-3 (LOW):** the hash chain is unkeyed SHA-256: it detects corruption and naive edits, **not** a rewrite by the journal's owner who recomputes hashes. Same-uid compromise is out of scope.

## Next qualification

1. A **third** independent adversarial review of the signing path after the review-#2 fixes land (`src/signer.js`, `src/daemon.js`, `src/keystore.js`, `src/grantfile.js`, `src/ledger.js`), before pointing it at a key with funds: two reviews have run (2026-10-27 hardening diff, 2026-10-29 signing path) and all 12 findings are fixed and regression-tested, but neither was a professional audit and the fixes themselves have not been independently reviewed.
2. Expand supported instructions only when the fee and authority effects can be bounded; refuse anything undecidable, rather than widening policy to pass tests.
3. Migrate own key-loading sites that fit the reviewed envelope as user zero; then run the 30-day restart/over-limit/refusal test. **The one remaining own site (`openreceipts`) was measured on 2026-10-28** — it does not fit the v0 message domain (canonical JSON receipts vs. legacy System transfer wires), though the key itself is adoptable after conversion. No own legacy site remains to migrate: user zero must now come from an envelope that can express the work (a message-grant for receipt signing, or v1 SPL-Token for real Solana transfers), or from an outside adopter. No outside users yet.
