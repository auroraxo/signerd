# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys. signerd signs only the subset of transactions it can fully verify offline; everything else gets a structured refusal — and that refusal is the feature.

**Status: v0 prototype (October 2026), NOT a signing service or security-reviewed wallet.** The scope was narrowed on 2026-10-26 after an adversarial review (see Safety boundary). On 2026-10-27 the first tested *legacy System-transfer-only* refusal checker and its atomic expenditure/replay ledger were added; on 2026-10-27/28 the local daemon (Unix socket, encrypted keystore, grant file) was added. **The daemon holds a real key and produces real signatures — it has passed one independent adversarial review of the hardening diff (2026-10-27, findings fixed and regression-tested), but the signing path as a whole is not security-reviewed, and no real funds should use it yet.** The rest of the v1 envelope below remains a plan.

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
- **`src/grantfile.js`** — one strict grant file. Unknown fields are refused (a typo in a security file is a mistake, not an extra rule), grant names may not reach `Object.prototype`, and the loaded grants live on a null prototype.
- **`src/daemon.js`** — a Unix socket (mode 0600) speaking newline-framed JSON. A request carries a grant **name** and base64 wire bytes; the response carries a signature or a machine-readable refusal. The socket is a capability: only the owner can talk to it. The daemon holds an atomic single-writer lock on the journal for as long as it serves, and releases it only after the server is closed and its connections are drained.
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

Checked on 2026-10-24/26: 21 files across six of my own repositories load key material into process memory; `sendaifun/solana-agent-kit` documents a raw private key as its setup path. A keyword scan of 1,123 live Solana-ecosystem repositories found no local scoped-signing daemon (a scan, not a semantic census). This remains a hypothesis with zero outside users.

## First executable increment (policy only, not a signer)

`src/policy.js` evaluates serialized transactions with `evaluate(wire, grant, now)` and returns `{ allowed: true, amountLamports: "…" }` or `{ allowed: false, refused: "…" }`. It deliberately permits **only one** legacy System Program transfer from the grant signer/fee payer to one fixed destination under a string-encoded lamport cap. The sole signer must be the source and fee payer; the only keys must be source, destination, and System Program. V0 is refused even without ALTs. Any extra instruction (including ComputeBudget/priority-price drain), SPL Token/Token-2022 instruction, authority change, CPI-capable program, invalid grant, expired grant, or noncanonical wire is refused. The tests generate disposable keys locally and cover both the one allowed case and the known attack classes.

`src/ledger.js` is the accounting layer that must sit between a positive verdict and any future signature. `gate(wire, grant, now, ledger)` refuses with `ledger_unavailable` when no ledger is attached, so a policy verdict alone never spends budget. The ledger keeps an append-only JSONL journal, fsyncs it **before** returning an approval, and charges each approval `amount + 5000` lamports (the envelope allows exactly one signature and no ComputeBudget instruction, so the base fee is fixed and no priority fee can be attached) against a rolling per-scope window:

- **Scope-keyed budget**: spend is counted per signer+destination pair, so two grants aimed at the same destination share one window cap instead of each getting a fresh one.
- **Replay**: identical wire bytes are approved at most once, ever, across restarts (SHA-256 set persisted in the journal).
- **Self-verifying**: every record carries a hash of its own fields chained to the previous record's hash, so the journal is a hash chain. An in-place edit — even a same-size one, e.g. `"a":"42"` → `"a":"12"` — breaks the chain and makes the load fail closed (`ledger_tampered`) instead of being silently trusted.
- **Fail closed**: an unreadable or corrupt journal makes the constructor throw; a torn final line (crash mid-append) is dropped and repaired, never parsed; an fsync failure during approval returns `ledger_write_failed` with nothing entering in-memory state; if the rollback of a failed append also fails, the ledger poisons itself and refuses every later approval (`ledger_inconsistent`); window refusals occur before any write.
- **Foreign-write detection**: before every append the ledger re-reads the file and compares both its length and its SHA-256 with the state it last wrote, so an outside writer is refused (`ledger_changed`) rather than merged into.
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

**Not safe for real keys yet.** The policy prototype is unit-tested and the daemon is tested end-to-end over a real socket (67 tests: 29 policy/ledger, 18 daemon, 8 signer, 7 grant file, 5 keystore). The daemon's signing path passed an **independent adversarial review on 2026-10-27** whose findings were all fixed and regression-tested — but that review was of one diff, not of the signing path as a whole, so do not point it at a key with funds yet. It has no authentication beyond the socket's file mode, no key rotation, and the ledger does not bind transaction lifetime (blockhash freshness) — a stale blockhash simply fails on-chain.

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

## Next qualification

1. A second independent adversarial review of the daemon's signing path (`src/signer.js`, `src/daemon.js`, `src/keystore.js`, `src/grantfile.js`) before pointing it at a key with funds. The policy/ledger path had one, and the daemon hardening diff had one on 2026-10-27 whose findings are now fixed — but the signing path as a whole has not been reviewed end to end.
2. Expand supported instructions only when the fee and authority effects can be bounded; refuse anything undecidable, rather than widening policy to pass tests.
3. Migrate own key-loading sites that fit the reviewed envelope as user zero; then run the 30-day restart/over-limit/refusal test. **Step one is unblocked** — `signerd import` now adopts an existing key, and the client-side half (no key in the client process) is built and measured above. What is still open is real migration: none of the measured key-load sites currently runs a plain legacy System transfer, so each one is either an envelope question or an adoption decision, not a tooling gap. No outside users yet.
