# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys. signerd signs only the subset of transactions it can fully verify offline; everything else gets a structured refusal — and that refusal is the feature.

**Status: v0 shipped to `main` (2026-11-01), NOT a signing service or security-reviewed wallet.** The scope was narrowed on 2026-10-26 after an adversarial review (see Safety boundary). On 2026-10-27 the first tested *legacy System-transfer-only* refusal checker and its atomic expenditure/replay ledger were added; on 2026-10-27/28 the local daemon (Unix socket, encrypted keystore, grant file) was added; on 2026-10-31 the **message-grant envelope** landed and on 2026-11-01 the whole qualification branch (envelope + reviews #6–#9 + the real openreceipts consumer) was **merged to main and tagged `v0.1.0`**. **The daemon holds a real key and produces real signatures — it has passed seven adversarial review rounds (daemon hardening 2026-10-27; signing path 2026-10-29, #2; migration/replay 2026-10-29, #3; open-handle 2026-10-30, #4; 18 external attack probes, #5; seal surface, #6; message envelope, #7 — the last plus #8/#9 re-verified on 2026-11-01, #9 for the first time by an independent reviewer), and every finding from all rounds is fixed and regression-tested against the reviewed code. No professional audit has happened, there are no outside users yet, and no real funds should use it yet.** The rest of the v1 envelope below remains a plan.

## Install (measured 2026-11-06)

No package is published to npm yet — the artifact is ready and the remaining gate is credentials (see Distribution and adoption below) — so the install path that exists today is the release tag:

```bash
npm install github:auroraxo/signerd#v0.2.11
```

**Prerequisites (measured 2026-11-07, fixed in this pin):** the daemon needs a C compiler (`cc`) once, to build its kernel lease helper from the shipped `tools/leasecheck.c` — `keygen` and `grant-add` work without it, `run` is the first step that needs it. On a machine with no compiler, the previous pin refused with `grant_file_lease_unavailable: grant_file_lease_unavailable: spawnSync cc ENOENT` — exit 1, the verdict printed twice, a Node-internal errno as the "detail", and no repair. This pin refuses by naming the repair instead, and a read-only install directory gets its own repair rather than a raw linker dump (measured live against the published `v0.2.7` tag installed in an empty directory, and against this pin: `research/lease-prereq-2026-11-07.json`; the contract is in `test/lease-prereq-surface.test.js`). Install a compiler, or point `CC` at one (`CC=/path/to/cc signerd run ...`); if the install directory is read-only, build the helper there by hand:

```bash
cc -O2 -o node_modules/signerd/tools/leasecheck node_modules/signerd/tools/leasecheck.c
```

**What this pin ships that `v0.2.10` does not** (each measured below, each defect immutable on the v0.2.10 tag): **the delivered signature is durable, not only atomic** — `--out` delivered as temp file + fsync + rename was *atomic* but the parent directory was never fsynced, so a crash could lose the rename and leave the previous artefact (or none) at `--out` while the CLI exited **0** ("signed **and** delivered"), the spend was already charged, and the retry was then refused `replay` — the honest exit 3/4 report never happened (measured with `strace` on the v0.2.10 tree: `fsync(temp)` then `rename`, no directory fsync; the fix adds `openat(dir, O_RDONLY)` + `fsync(dir)` after the rename; `test/out-dir-fsync.test.js` is 1 RED / 2 guards green on the published v0.2.10 tag and 3/3 on this pin, `research/recovery-channel-2026-11-08/tag-ladder.md` and the ladder in this section). Also still new in this pin: **exit 3 is verified, and exit 4 exists** — the exit code that promises "the signed wire is on stdout" now checks that the write actually landed, in full, on a channel that keeps the bytes; when it did not, the CLI exits **4** with `recovery_failed:` instead of claiming the artifact is there (measured with a live daemon that really signed: on v0.2.9 a file stdout under `ulimit -f 0` and `/dev/full` both ended exit 3 with 0 bytes anywhere, `/dev/null` ended exit 3 keeping nothing, and `ulimit -f 1` ended exit 3 with 1024 bytes of truncated JSON — paid for, unrecoverable, and reported as recoverable; `research/recovery-channel-2026-11-08/report.md`). Also still shipped by this pin: **grant creation enforces daemon value semantics** — `grant-add` and the loader reject values the daemon cannot honour (impossible calendar dates like Feb 31, non-canonical 32-byte public keys, u64 overflow, non-safe window seconds) with a machine-readable `grant_field_invalid` and a field-specific `fix:` line instead of writing a scope that is permanently dead at request time (measured with `tools/measure-grant-value-contract.mjs`: 16 of 30 candidate values were written and refused on v0.2.8; 0 on this pin; `research/grant-value-contract-2026-11-08.json`). Earlier pin gains (lease-helper prerequisite named, preflight out-checks, atomic delivery, wrongly-used flags refused, the shipped client obeying the flag surface, the sealed-mode block running verbatim, `--dry` real and falsified in the day-8 consumer run) are still shipped by this pin; the defects they close are immutable on the tags that carry them.

The pin is **not allowed to drift from the releases**: `test/pin-release-sync.test.js` fails the suite when the front page pins a tag older than the newest release (measured red on 2026-11-07: pin `v0.2.5` against release `v0.2.6` — two releases of fixes a stranger copying this page would not get), so moving the release and moving the pin are one act.

That path is **measured, not asserted**: `node tools/measure-install-path.mjs --ref v0.2.11` performs a real install from the tag into an empty directory and checks the installed manifest (version matches the tag, not publish-blocked) and the quickstart, writing `research/install-path-<tag>-<date>.json`. The superseded tag `v0.1.0` measured `defective:private-true+readme-no-quickstart` (it predates the stranger-install fixes below) — that artifact is kept as the falsification record.

**What the tag must ship (measured 2026-11-06, `test/installed-tag-journey.test.js`):** every command this README documents in a code block must be *dispatched by the pinned tag* and documented by the tag's own README — because the installed package ships the TAG's README, not this page's. v0.2.2 failed exactly this: it was cut before `grant-remove` existed, so a stranger who installed the pin and followed the revocation instruction hit an unknown command. The journey test reads the pin from this README, so moving the pin moves the measurement; a command documented here but absent from the tag turns the suite red before the next release, not after it.

**The revocation path, measured from the published tag** (`research/pinned-install-revocation-2026-11-06.json`): a fresh install of the published v0.2.3 tag in an empty directory — not the checkout — runs `keygen -> grant-add -> grant-add --append -> grant-remove -> run -> sign`, then revokes a scope *while the daemon runs* (no restart, no signal): the same daemon then refuses that grant with `grant_not_found`, and the surviving scope still signs. Unsigned transaction 215 bytes, signed wire 215 bytes (measured, not asserted).

**There is no Rust package and no cargo-based install path.** signerd is a Node package with no `Cargo.toml`; a listing elsewhere advertised an install-from-git cargo command, which fails with `could not find Cargo.toml` (measured 2026-11-05, `research/install-path-v0.1.0-2026-11-05.json`) and has been corrected.

The release contract itself is pinned by `test/release-contract.test.js`: the working manifest must be publishable, the latest release tag must carry a publishable manifest and the quickstart, and the version must agree with the tag — so a stale or broken release cannot ship silently again.

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

## What the traffic actually looks like (measured 2026-11-02)

**The earlier version of this section (measured 2026-10-30) claimed "4 in 1,000" — that number was wrong, in both directions, and the error was in the measuring tool.** The table below is the corrected measurement. It runs the *product's own* `policy.evaluate()` against real mainnet wire bytes — not a hand-written restatement of the policy — so it answers the question that matters: how much real traffic would the daemon actually be able to sign?

`tools/policy-traffic.mjs` fetches finalized mainnet blocks twice — once as JSON, once as base64 wire — pairs each transaction by signature bytes (100% pairing verified), and feeds the *wire bytes* into `src/policy.js` with the most permissive grant that transaction could plausibly carry (the actual signer, the actual destination, the actual amount). Output: `research/policy-traffic-2026-11-02.json` (+ `-rows.json`), 2,835 transactions across 6 finalized slots (464588085–464588090).

| Measure | Value |
|---|---|
| Transactions measured | 2,835 (100% JSON↔wire paired) |
| Shape candidates (1 signer, 3 keys, 1 System instruction) | 201 |
| **Approved by the product** | **192 — 95.5% of candidates, 6.8% of all traffic** |
| Refused among candidates | 9, all fail-closed: 7× `version_or_alt`, 2× `invalid_wire` (the 2 `invalid_wire` were v1 rows; since the classification fix below they are refused `version_or_alt` — replay derives from stored verdicts of that commit) |
| Traffic version mix | 1,257 v1 (44.3%), 710 v0, 868 legacy |

**The honest reading:** the current envelope covers roughly **7 in 100** transactions, not 4 in 1,000. The old 0.41% figure was an artifact of two defects in the classifier, both found and fixed by measurement (details below): a broken base58 decoder hid 11 of the 192 real approvals, and a version-blind classifier folded version-1 wire into the legacy buckets. After the fixes, the classifier and the product agree on **all 2,835 transactions** — 192 `v0_fit` exactly equals 192 product approvals, with zero disagreements on any transaction.

Two facts that matter more than the headline:

- **Version-1 transactions are 44% of current traffic** and the pinned `@solana/web3.js` 1.98.4 cannot deserialize v1 wire at all (measured: in one block, all 368 v1 transactions fail to deserialize; 459 v0/legacy succeed). The daemon refuses them **as `version_or_alt`** — fail-closed, but that is a ceiling on today's reach, not a rounding error. (Before 2026-11-02 they were refused as `invalid_wire`, the same reason a caller gets for three corrupt bytes; the named reason was recovered without touching the parser, see "Version-1 classification" below.)
- **The reach question was measured, not argued: upgrading `@solana/web3.js` does not widen reach on v1 wire.** `tools/v1-reach.mjs` (output `research/v1-reach-2026-11-02.json`, pinned in `test/v1-reach-tool.test.js`) feeds 14 signature-verified live v1 transactions into the product's own `evaluate()` under three libraries: 1.98.4 deserializes 0/14, 1.99.0 parses 14/14 but cannot re-serialize, 3.1.1 round-trips 14/14 — and all three produce the **same verdicts** (`version_or_alt` under the cap, `invalid_wire` over it, 0 approvals). The version rule, not the parser, decides reach, so the migration (66/186 tests fail under 3.1.1, a major-version API rewrite) buys zero approvals.
- **Shape fit is not the bottleneck; grant terms are.** Of 201 candidates, 192 are approved even under maximally permissive grants. The narrow envelope is *not* what limits this product's usefulness — the limit is where a scoped signature is actually needed.

The v1 SPL-Token envelope remains rejected as the main path: of the 2,835 transactions measured, real bare single-instruction SPL transfers are a handful, because token transfers are wrapped in DEX programs, compute-budget instructions, or address tables. The message-grant envelope (signing a receipt, an attestation, a quote — not a transaction shape) is where the evidence points, and it is the one measured own site (`openreceipts`).

### Three defects in the measuring tool, found and fixed by measurement

1. **The base58 decoder was wrong.** `decodeBase58` counted *trailing* `'1'` characters instead of *leading* ones and started from `bytes=[0]`, so any base58 string ending in `'1'` gained a spurious `0x00` prefix and true leading-zero payloads lost their zero byte. Real System-transfer payloads whose base58 ends in `'1'` (about 1 in 58) were mis-sized and pushed out of `v0_fit` into `legacy_other` — the share was **undercounted**. Measured: 11 of 192 product-approved transfers were hidden by exactly this defect. Fixed and now pinned against the `bs58` package as an oracle, including 200 random round-trips (`test/envelope-traffic-classifier.test.mjs`).
2. **The classifier was version-blind.** A version-1 message has no `message.version` and no `addressTableLookups`, so it passed the legacy check and was scored against the v0 envelope — v1 wire the daemon cannot even parse was counted as `v0_fit` (2 live cases), while the remaining v1 traffic folded silently into `legacy_other`, the bucket documented as "CPI, DEX, compute budget". Fixed: v1 is now detected from its json marker (`message.transactionConfig`, present on v1 and absent on legacy and v0, verified live) and gets its own named `v1` bucket.
3. **The versioned wire was scored as legacy.** The getBlock wrapper's `version` field was dropped when the `{transaction, meta}` wrapper was unwrapped, so version-0 transactions were scored `v0_fit` even though the product refuses all versioned wire as `version_or_alt`. Fixed: the wrapper's version is now carried onto the transaction, and version 0 is treated as versioned wire (`vtx`), never legacy.

Each fix has a control in `test/envelope-traffic-classifier.test.mjs` (5 tests: three defect controls, a 200-payload oracle round-trip, and a false-positive guard that keeps a genuine legacy transaction classified as `v0_fit`). All three defect controls are red on the pre-fix tree and green after.

Four further defects in the measuring tool were found and fixed earlier (2026-10-30), each of which had produced a clean-looking but false result: `--blocks=25` was sliced to `'=25'` → `NaN`, so the sampling loop never ran and the tool reported "0 transactions" as if it were a finding; `getBlock` with `maxSupportedTransactionVersion: 0` now fails for *every* slot because mainnet serves version 1; `getBlock` returns `{transaction, meta}` wrappers, so classifying them directly marked everything malformed; and the file carried a fabricated SPL Token program id (`TokenkegQdZ1…`) while the real one is `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` — which is why an early run reported 0 token matches while 731 real `Tokenkeg` instructions sat in six blocks. The classifier now self-checks against hand-built fixtures (`--selftest`, 9/9) before it reports a number, and refuses to report at all on a zero-transaction sample.

### Version-1 classification (measured and fixed 2026-11-02)

Version 1 is ~44% of live traffic, and the pinned `@solana/web3.js` 1.98.4 cannot
deserialize v1 wire. The daemon therefore refused v1 as `invalid_wire` — the
**same reason a caller gets for three corrupt bytes** — and the answer changed
with the installed library: under 3.1.1 the same wire was refused
`version_or_alt`. A caller could not tell "your message format is not
implemented" from "your payload is corrupt", and the reason depended on a
dependency version.

The fix is a measured classification rule, not a guess. `tools/wire-prefix.mjs`
fetched two independent samples of finalized mainnet blocks (4 blocks each,
**4,465 transactions total, 100% JSON↔wire paired**, output
`research/first-byte-distribution-2026-11-02.json`) and measured the wire
prefix against each transaction's own version label:

| Wire | Byte 0 | Sample 1 (3,147 tx) | Sample 2 (1,318 tx) |
|---|---|---|---|
| version 1 | `0x81` | 1,434 / 1,434 | 571 / 571 |
| legacy | signature count (`0x01`–`0x05`) | 617 / 617 | 294 / 294 |
| version 0 | signature count (`0x01`–`0x04`) | 1,096 / 1,096 | 453 / 453 |

Legacy and v0 wire begins with the compact-u16 signature count, and inside the
policy's 1232-byte cap at most **17** signatures fit — so that count can never
reach `0x80`. Byte 0 ≥ `0x80` under the cap therefore cannot be legacy or v0:
it is versioned message wire or corrupt bytes, and both must refuse.

So `src/policy.js` classifies versioned wire **before any parsing** and answers
`version_or_alt` for it. The verdict is now a property of the wire, not of the
installed library — all three probed libraries produce identical verdicts. The
size cap still outranks it (over-cap stays `invalid_wire`), and legacy
transfers, v0 transactions, three corrupt bytes and JSON bodies all behave
exactly as before.

Proof: `test/v1-wire-refusal.test.js` (7 tests — red on the pre-fix tree where
every under-cap v1 row answered `invalid_wire`, green after; the guard cases
are green on **both** trees) and `test/v1-reach-tool.test.js` (9 tests pinning the
measurement, including exit code 3 for an empty fixture, broken pairing and an
unusable candidate probe). The committed fixture
`test/fixtures/v1-wire-2026-11-02.json` holds 14 signature-verified live v1
rows, 3 of them shape-eligible — a v1 transaction whose own accounts would
satisfy the envelope, so the **only** reason it is refused is the version rule.

**What this does not do:** it does not make the daemon approve v1 wire. It
cannot and must not — the envelope is legacy-only by design. It makes the
refusal *legible*, which is the product's whole promise.

### The message-grant envelope (built and measured 2026-10-31)

The traffic measurement above points at a different job than "sign this
transaction": signing a **message** — a receipt, an attestation, a quote. That
envelope now exists, next to the transaction envelope, in the same daemon.

A message grant is a different schema, on purpose: it speaks about a receipt
domain, not about a money destination, so the field sets are disjoint and a
grant that mixes them is refused rather than sorted out at request time.

```json
{
  "kind": "message",
  "issuer": "auroraxo",
  "type": "release",
  "subject": "auroraxo/signerd",
  "pubkey": "<base64 Ed25519 public key the daemon must hold>",
  "maxBytes": "700",
  "expiresAt": "2026-11-01T00:00:00.000Z",
  "windowMaxMessages": "5",
  "windowSeconds": "3600",
  "claimKeys": "version,build"
}
```

The grant authorizes exactly one thing: *the key this daemon holds may sign an
`openreceipts/v1` receipt body for this issuer, this type and this subject,
whose canonical bytes are at most `maxBytes` long, at most
`windowMaxMessages` times per `windowSeconds`, until `expiresAt`.* Everything
else in the body is either pinned by the grant (issuer, type, subject, the
issuer's public key) or bounded (claims, note). `issued_at` is REQUIRED and
semantics-checked (review #7, 2026-11-01): the openreceipts verifier reads it
unconditionally, so a receipt without it would crash the primary consumer, and
an impossible timestamp (`2026-02-30`) must not normalize into a real one —
the daemon refuses both. A receipt dated further than 24h into the future is
refused (`issued_at_in_future`); the tolerance is measured against the daily
runner, which stamps `issued_at` at 21:00 UTC of DAY (up to ~21.4h ahead of an
early-morning run). The past is not bounded: backdating about a past event is
legitimate, and `expiresAt` bounds when the signing happens. `claimKeys` is
optional; when present it is the allowlist of claim keys that may be signed.

```bash
signerd sign-message --socket ~/.local/share/signerd/signerd.sock \
            --grant releases-24h --body receipt-body.json --out receipt.json
```

The artifact is an ordinary `openreceipts/v1` document — `{receipt, pubkey,
sig}` — so `python3 receipt.py verify receipt.json` and `node verify.mjs
receipt.json` accept it unchanged.

**The receipt-producing flow exists on both ends now** (2026-10-31):
`receipt.py sign --via-signerd <socket> --grant <name>` builds the body,
sends it to the daemon and — before writing any file — verifies the signature
it got back against its own body and against a locally pinned public key.
That client path needs **no key material at all**: no `OPENRECEIPTS_HOME` is
created, no `.key` file is read or written. Refusals from the daemon
(`window_cap`, `replay`, `type`, `subject`, …) exit non-zero and write
nothing. Checked end to end in `test/via-signerd-consumer.test.js` (7 tests:
empty client home, verify-before-write with a lying daemon, pinned-key
mismatch, restart + replay, overdraw, off-scope type/subject, unreachable
socket — all **red on the pre-client tree** and green after) and live against
the real issuer key (`research/consumer-live-2026-10-31/`: site key == pinned
key, both verifiers accept, overdraw and cross-restart replay refused, no
client key file ever created).

**Measured, not claimed** (`test/message-e2e.test.js`, live daemon, real
socket):

- a receipt signed by the daemon verifies under **both** openreceipts
  verifiers — the Python CLI and the zero-dependency Node verifier — against
  the pinned issuer key, with the canonical bytes produced by signerd's own
  canonicalizer;
- the daemon canonicalizes: a body whose *textual* key order differs from the
  canonical order yields the same signature target, and the signed bytes
  verify under OpenSSL ed25519 with the imported key;
- **the two envelopes cannot borrow each other**: a receipt on a transaction
  grant and a transaction wire on a message grant are both refused with
  `grant_kind_mismatch`, never signed;
- the window counts **messages**, not lamports (a receipt costs nothing on
  chain): at `windowMaxMessages: 2` the third distinct receipt is refused with
  `window_cap` and `windowRemainingMessages: 0`; the same receipt body again
  is refused with `replay` — one signature per distinct receipt, ever;
- expiry takes effect on the next request without a restart (the grant file
  is re-read per request);
- a grant that pins **another** public key poisons the whole file: the daemon
  refuses to start, and a running daemon refuses every request (including the
  healthy grant next to it) — fail-closed, not fail-open;
- cost: **p50 31.4 ms, p95 63.4 ms** per signed receipt (n=50, fsync-dominated;
  the transaction path's measured roundtrip was 31.0 ms).

**Falsification ladder**: all 15 new tests (11 policy + 4 e2e) are **red on
the pre-envelope tree** (`c1b1c09`): the policy module does not exist there,
and the daemon refuses to even load a grant file that carries a `kind` field
(`grant_unknown_field`). On the fix tree they are green. The transaction
path is untouched: the suite went from 140 to 155 with 0 failures, and both
crash-harness modes (sealed and unsealed) stay green.

**What this does not do**: it does not check that a receipt is *true*. A
signed receipt says "the issuer said this", never "this happened". The grant
bounds who may speak for the issuer and about what — not the truth. The
The message-grant envelope has had an adversarial review (review #7,
2026-11-01: the issued_at contract and the canonicalization/ledger-scope
surface — 2 HIGH + 1 MED found and fixed, all falsified against the pre-fix
tree, see below) and an **independent** one (review #9, 2026-11-01, isolated
reviewer: 2 more defects found and fixed — see Review #9 below); the
transaction path has had six rounds.

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

**Envelope fit of that one remaining site, measured 2026-10-28/29** (`tools/envelope-fit.mjs`, output in `research/envelope-fit-openreceipts-2026-10-28.json`, offline proof in `test/envelope-fit.test.js` + `test/envelope-fit-tool.test.js`): the note had guessed "probably not, Ed25519 instead of Solana-Tx". The verdict holds, the reason does not — both are Ed25519. The PKCS8 seed in `~/.openreceipts/auroraxo.key` derives the same public key under both OpenSSL and web3.js, `signerd import` accepts that key after a mechanical PEM→raw conversion, and the **published identity is measured, not assumed**: the site-derived key equals the pinned issuer key (`openreceipts/keys/auroraxo.pub`, byte-for-byte) and verifies all 6 published receipts under their canonical `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` bytes — the JS canonicalizer in `src/receipt-identity.js` is hash-identical to Python's on all 6 receipts, and a receipt signed by a different key, a flipped byte, or a mismatched pinned key makes the tool report FAILED rather than pass (the harness asserts that refusal). What does not fit is the **message domain**: openreceipts signs canonical JSON receipts, the v0 envelope signs a legacy System transfer wire, so `policy.evaluate` refuses a receipt body (`invalid_wire`) and should. The refusal is not a tooling gap — importing the key without a message-grant envelope would move a key the daemon cannot use, so no migration was built **until the message-grant envelope landed (2026-10-31, see "The message-grant envelope" above): the daemon now signs these bodies, and the refusal of the old envelope stays correct.** Unchanged: `sendaifun/solana-agent-kit` documents a raw private key as its setup path; a keyword scan of 1,123 live Solana-ecosystem repositories found no local scoped-signing daemon (a scan, not a semantic census); this remains a hypothesis with zero outside users.

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

**Not safe for real keys yet.** The policy prototype is unit-tested and the daemon is tested end-to-end over a real socket (140 tests: 9 policy, 20 ledger, 18 daemon, 8 signer, 7 grant file, 8 keystore, 8 review-#2 regressions, 5 envelope-fit, 2 user-zero, 6 R4-1 lease regressions incl. one live-daemon end-to-end, 9 R4-2 journal-lease regressions incl. one live-daemon end-to-end, 15 R5-2 journal-seal regressions, 4 sealed-journal end-to-end). The daemon's signing path passed **three independent adversarial reviews** (2026-10-27 on the hardening diff, 2026-10-29 on the signing path, 2026-10-30 on R4-1), each with every finding fixed and regression-tested — but neither is a professional audit, so do not point it at a key with funds yet. It has no authentication beyond the socket's file mode, no key rotation, and the ledger does not bind transaction lifetime (blockhash freshness) — a stale blockhash simply fails on-chain.

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
- **Documented — R3-3 (LOW):** the hash chain is unkeyed SHA-256: it detects corruption and naive edits, **not** a rewrite by a writer who recomputes hashes. Framed at the time as "same-uid compromise is out of scope"; review #5 showed the writer only needs write access *at some earlier moment*, not the same uid (R5-2 below) — so this is now a named open finding, not a scope note.

### Adversarial review #4 (2026-10-30) — R4-1: an open write handle survives `chmod`

**Finding (HIGH, reproduced).** R3-1 refuses a group/other-writable grant file, but `chmod` does not revoke a descriptor opened *before* the tightening. A process that opened the file while it was writable keeps writing through it afterwards, the mode still reads `0600`, and the daemon re-reads the file on **every** request — so forged grants reach the signer. Reproduced against `5c72342`: with a stranger holding the file open for writing, a live daemon signed the request (`test/r4-1-e2e.test.js`, pre-fix: fail).

**Fix — kernel-enforced read lease, not a `/proc` scan.** `tools/leasecheck.c` takes an `F_RDLCK` lease on the file it is about to read: the kernel grants it **only if nobody holds the file open for writing**, and it decides that for *every* uid. The bytes are read through the lease-holding fd, and the lease is re-checked afterwards (`F_GETLEASE`) so a writer that got in mid-read yields `lease=broken` and is refused instead of handed over.

An intermediate `/proc`-scan fix was built first and then **measured and rejected** — it could not see a foreign uid's descriptors at all (D2), and its cached verdict under `dev:ino:ctime:size` never changed when a file was *opened*, so a writer appearing after the first scan was invisible for the process's lifetime (D1). Cost was 7.8 ms per request (D3); the lease probe is ~5.8 ms including the helper process (the daemon already spends ~2 ms per request on the journal's `fsync`).

The lease type is the whole design and the first version got it wrong: `F_WRLCK` conflicts with *every* opener, so a single `cat grants.json` would have made the daemon refuse to sign. `F_RDLCK` conflicts only with writers — both are pinned by `test/r4-1.test.js` (`held open for READING is still accepted` passes on all three trees; it is the false-positive guard).

**Falsification ladder** (6 tests, run against copies of each tree):

| tree | pass | fail |
|---|---|---|
| `5c72342` pre-fix (no writer check) | 1 | 5 |
| `/proc`-scan intermediate | 2 | 4 |
| `F_SETLEASE` (shipped) | **6** | 0 |

**Limits, stated rather than hidden:** point-in-time — it proves the state *at read time*, not that the file was never written before the daemon started. **A finished past write is now measured, not assumed, to be caught: it is not (review #5, below).** Linux-only (`F_SETLEASE`): on a kernel without leases the helper exits 4 and the daemon **refuses** rather than reporting a pass it could not observe. The helper binary is not committed (built from `tools/leasecheck.c` by `npm run build`, wired as `pretest`) — a checked-in binary would be an opaque trust dependency. Verification: 98 tests green from a clean build, crash harness 25 rounds / 121 approvals all durable.

### R4-2 (2026-10-30) — the journal had the same open-handle hole

**Finding.** R4-1 closed the grant file; the **journal** still read itself with `fs.readFileSync`. A process that opened the journal for writing before a `chmod 0600` keeps writing through that descriptor, and the journal *is* the replay set and the spend budget: bytes believed at load (and at the append's unchanged-check) could differ from what a surviving descriptor writes a moment later. `assertJournalPath` only inspects the path, so nothing observed the open handle. Reproduced against `a806edd`: with a stranger holding the journal open, a live daemon **signed** the request.

**Fix.** The journal now goes through the same `readUnderLease` primitive as the grant file — at load (`#load`), at the append's unchanged-check (`#appendLine`), and in both reads of `migrateJournal` (the read, and the byte-compare before the `rename` that commits the migration). `readUnderLease(file, {prefix})` parameterizes only the error-code prefix, so every existing caller keeps byte-identical `grant_file_*` codes while the journal reports `ledger_held_writer`, `ledger_lease_unsupported`, `ledger_lease_denied`, `ledger_too_large`. ENOENT is carried in `err.detail`, so a missing journal is still the normal fresh start and a missing migration target is still `ledger_missing`. The daemon passes `ledger_held_writer` through `approve()` to the client verbatim instead of flattening it to `ledger_write_failed`.

**Falsification** — 9 tests in `test/r4-2.test.js` + `test/r4-2-e2e.test.js`, run against both trees:

| tree | pass | fail |
|---|---|---|
| `a806edd` pre-fix | 1 | 8 |
| journal `F_SETLEASE` (shipped) | **9** | 0 |

The single pre-fix pass is the false-positive guard (`held open for READING is still loaded and usable`) — it is what would make the daemon refuse whenever anybody inspected the journal.

**Cost, measured:** 17.5 ms per append vs 9.2 ms before (6.4 ms of that is the lease probe — one helper process per load/append, on top of the ~5.8 ms/req the grant-file lease already costs). This is the price of the guarantee, not an optimisation target yet; if it matters later the probe belongs at the trust points that already exist (`fsync` per approval), not in a cache.

**Limits:** same point-in-time limit as R4-1 — a descriptor opened *after* the probe but before our own append is caught by the next load/append, not this one. **The mode/owner/directory checks and the chain hash do *not* carry the rest: review #5 measured a stranger's finished truncate and a re-chained rewrite both loading clean (R5-2 below).** Linux-only, and the helper refuses (exit 4) rather than fakes a pass, exactly like R4-1. Verification: 107 tests green from a clean build, crash harness 25 rounds / 92 reported approvals all durable.

### Adversarial review #5 (2026-10-30) — 17 probes; 1 fixed, 2 findings open and named

18 probe scripts (`research/review5/p*.js`) attack the tree from outside `src/`, each printing a JSON verdict. Re-run after the fix below.

- **Fixed — R5-1 (HIGH, reproduced): a second start() could unlink a LIVE daemon's socket and take over the documented client path.** The stale-socket probe was one `connect()` collapsed into two verdicts ("connected" = alive, anything else = dead). A listening socket whose accept queue is saturated refuses *new* connects with `EAGAIN`, which the probe read as "dead": it unlinked the live socket, bound its own at that path, and every client trusting the path then talked to an impostor (reproduced: inode changed, old daemon alive, `research/review5/p4-socket-live-unlink.js` pre-fix).
  **Fix — three verdicts, and only one error proves death.** `src/socketprobe.js` returns `live` / `stale` / `unknown`: `stale` requires `ECONNREFUSED` (nobody is listening) or a non-socket file; `EAGAIN`, timeouts and everything else are `unknown` and **refuse** the start (`socket_in_use`) instead of unlinking. Regression tests in `test/socketprobe.test.js` pin all three verdicts, including a real saturated accept queue.
  Falsification: 112 tests green; `p4` and `p4b` re-run — second daemon now refused `socket_in_use`, socket inode unchanged.

- **FIXED — R5-2, grant half (2026-10-31, reproduced): a stranger's finished write to the grant file survives the mode checks.** Review #4's lease only proves state *at read time*. Measured (`p2-past-write-grant.js`): a grant file that was `0666` while a stranger wrote forged grants into it, then tightened to `0600`, passes every check the daemon makes (owner, mode, directory, lease) — and the daemon **signs the attacker's destination**. A writable `MAP_SHARED` mapping with no open fd (`p10`) writes through the same way after the mapping is dropped.
  **Fix — sealed grant files (opt-in, fail-closed).** `signerd seal-grants` adds an HMAC-SHA256 over the canonical document (keys sorted; formatting and key order are not payload), keyed by a scrypt-derived key from `--grant-seal-passphrase-file` (0600, same rule as the keystore passphrase). `signerd run --grant-seal-passphrase-file` then REFUSES an unsealed, altered or shape-broken document with `grant_file_unsealed` / `grant_file_seal_mismatch` / `grant_file_seal_invalid`, on start and on every per-request reload. The seal lives inside the file on purpose — a second seal file could be swapped wholesale by the same attacker. Re-sealing an honestly edited file (salt changes) costs one scrypt; every ordinary request pays one HMAC, measured at +0.38 ms per grant load (6.36 ms sealed vs 5.98 ms unsealed, 200 loads each) on top of the existing lease cost. Falsification: `test/r5-2-seal.test.js`, 9 tests — pre-fix tree 5 pass/4 fail (the four enforcement tests fail; the false-positive guard passes on both trees), post-fix 9/9; full suite 121/121. `verify-grants` checks a file without the journal; `seal-grants` prints exactly what it sealed, because sealing a forged file makes the forgery valid.
  **Fixed — journal half (2026-10-31, reproduced): sealed journal, per-record keyed chain MAC.** The same attack shapes hit the journal: a stranger's finished truncate (`p3`) let the daemon **re-sign a message it had already signed** (double-sign), a re-chained rewrite (`p15`) reset the budget, and a writable `MAP_SHARED` mapping (`p10`) forged history. The fix, opt-in and fail-closed like the grant half: journal format 4 appends an HMAC-SHA256 over each record, chained to the previous record's MAC (`x` field), keyed by scrypt from `--journal-seal-passphrase-file`; the floor (`seq`, MAC head) is anchored in `<journal>.anchor` at fsync time so a truncated or wholly fabricated journal cannot replay as a shorter honest one. `signerd run --journal-seal-passphrase-file` refuses an unsealed journal (`ledger_sealed`), a wrong passphrase or altered bytes (`ledger_mac_invalid`) and a shortened one (`ledger_mac_short`) at load; `seal-journal` seals an existing valid journal (refuses partially sealed or already sealed) and prints `records/seqFrom/seqTo/wireSha256/floor` — because sealing a forged journal makes the forgery valid. Records verified at load; every append re-keys the chain head, so the MAC is checked on the next load too. Measured cost: startup +87 ms (one scrypt), +2.6 ms per approval (17.55 → 20.18 ms over 50 approvals), on top of the existing fsync + lease cost. The anchor write is crash-safe by construction: a record is only trusted if it chains from the anchored floor, so a crash between append and anchor drops nothing that was ever acknowledged — the crash harness runs green in both modes (`test:crash`, `test:crash:sealed`). Falsification, both directions: `p3b`/`p15b`/`p10b` on the pre-fix tree — truncate ACCEPTED + re-signed the same message, re-chain ACCEPTED + reset the budget, same-length mmap rewrite ACCEPTED; on the fixed tree all three refuse (`ledger_mac_short` / `ledger_mac_invalid`). Regression: `test/r5-2-journal-seal.test.js` 15 tests, `test/r5-2-journal-e2e.test.js` 4 (live daemon, wrong/right passphrase, live CLI), full suite 140/140; crash harness green both modes.

- **Held (no finding):** lease refuses a foreign writer on grant file *and* journal (`p1`), survives a writable mmap while the mapping is alive (`p10` phase A, `p12`, `p13`), fails closed when the helper is missing/faked (`p8`: forged helper output cannot make an unreadable file pass — the real bytes are read through the helper's own fd), one request per connection (`p5`), message-level replay on both identities (`p6`), symlink/mode/format-1 refusals (`p7`), grant reload still live (`p14`), format-1 smuggling refused (`p17`), R2-1/R2-3 behaviour unchanged (`p11`). Cost (`p9`): lease probe p50 6.0 ms, full request round trip p50 31.0 ms.

### Adversarial review #6 (2026-10-31) — 9 probes on the seal surface; 5 defects found and fixed, 4 held

Probe scripts live in `research/review6/p*.js` and attack the tree from outside `src/`; each prints a JSON verdict. They were written against the R5-2 tree and continued to the HEAD that carries the message-grant envelope.

- **Fixed — R6-1 (HIGH): an empty seal passphrase file silently turned sealed mode OFF.** `bin/signerd.js` readPassphrase() turns an empty (or newline-only) file into `''`, and `src/daemon.js` decided the mode from `.length > 0` — so `signerd run --grant-seal-passphrase-file <empty file>` ran the daemon **unsealed** while the operator believed it was sealed, and a forged, unsealed grant document was signed for the attacker's destination (measured end to end: `p1` e2e, forged destination signed). The same empty passphrase was already a hard error in `status` (`seal_passphrase_required`) and on the journal side (`journal_seal_passphrase_required`): one flag, three behaviours. **Fix:** the daemon now refuses an explicitly requested but empty seal passphrase at construction (`seal_passphrase_required` / `journal_seal_passphrase_required`), identically on both halves. Falsification: `research/review6/regression-empty-seal-passphrase.test.js` is RED on the pre-fix tree (the forged grant is accepted) and green after; its control — the same forged document refused with a *real* passphrase (`grant_file_unsealed`) — is green on **both** trees.

- **Fixed — R6-2 (HIGH): deleting the journal file bypassed the no-passphrase downgrade guard, and the same message got signed twice.** The guard that refuses an unsealed daemon when a seal floor exists lived only on the success path of `Ledger#load()`, i.e. only when the journal file *exists*. A stranger with write access to the state directory could delete the journal, leave the floor claiming history, and the next unsealed restart started **fresh** with an empty replay set (measured: `p3` e2e, byte-identical signatures before and after the downgrade — a real double-sign). **Fix:** both guards now fire from the same ENOENT branch — the sealed daemon still says `ledger_mac_short`, the unsealed one now says `ledger_sealed`. Falsification: `research/review6/regression-floor-guard-journal-absent.test.js` is RED pre-fix (no throw at all) and green after; its two controls (sealed daemon refuses a deleted journal; unsealed daemon refuses an *empty* journal) are green on **both** trees.

- **Fixed — R6-3 (MED): `seal-journal` laundered a forged history.** The recovery tool rewrote the seal floor to whatever the journal it was handed said, without asking whether the floor *witnessed* that journal. Handed a forged journal beside the operator's genuine floor, it replaced the floor with one derived from the forgery and turned the daemon's `ledger_anchor_mismatch` refusal into an accepted history (measured: `p4` case5). It also could not repair the one state the daemon refuses to start in (`ledger_anchor_missing`): it printed `already_sealed` and left the brick in place. **Fix:** the tool now asks the same three questions the daemon asks — is the floor authentic under this passphrase, does its count fit the chain, and does its head at that count equal the journal's keyed head at that point (`checkFloorAgainstChain`). A floor that disagrees is a refusal (`ledger_anchor_mismatch` / `ledger_mac_short`), never replaced; the old floor is preserved next to the backup; a *missing* floor on a journal that verifies record-by-record is now created and reported (`floorRepaired: true`). Residual limit, named: a floor deleted *together* with a truncation beforehand leaves no marker to find — undetectable here, and documented rather than papered over.

- **Fixed — R6-4 (MED): the passphrase path had weaker hygiene than every other secret path.** `readPassphrase()` checked the file mode on a `statSync` and nothing else: no symlink refusal (a symlink there was followed), no owner check, no directory check — while the keystore, grant file, journal, anchor and socket directory all refuse those. **Fix:** the passphrase path now refuses a symlink (lstat, regular file only), a group/other-accessible file, a foreign-owned file, and a group/other-writable directory — the same rules the other paths use. Measured: `p6` Q1/Q3/Q5 before, refused after (Q5's hardlink arm remains accepted by design: a hardlink is a second name for a file whose contents the attacker already controls).

- **Fixed — R6-5 (LOW): sealing a 0-record journal produced a lone newline and was refused as `ledger_corrupt`.** The tool joined an empty record list to `'\n'`, which `parseJournal` rejects as corrupt — a clean, empty file (exactly what a fresh sealed journal is) was refused with a corruption code, identically on the pre-fix tree. **Fix:** a 0-record journal seals to a 0-byte sealed journal and loads.

- **Held (no finding):** the grant seal's canonicalization resists every forgery variant tried — key order, whitespace, unicode escapes, duplicate keys, number formats, extra top-level and extra in-grant fields (`p5`: no variant that loads authorizes more; the only collisions are number-vs-null in a field the loader ignores); no prototype pollution reaches the grant map, the request path or the policy fields (`p8`); every chain manipulation and anchor mutation is refused, only the documented full rollback is accepted (`p7`); the per-request sealed reload refuses every forged, altered, unreadable or revoked document and the seal-key cache never skips the MAC (`p9`). Measured cost of the seal path on the request line: 126 ms per request under salt churn (one scrypt per new salt), 12 requests measured.

### Adversarial review #7 (2026-11-01) — first review of the message-grant envelope itself: 2 HIGH + 1 MED found and fixed, the rest held

Probe scripts live in `research/review7-envelope/` and attack the surface review #6 skipped: `policy-message`, `signer-message`, `receipt-identity`, and `approveMessage`/`messageScopeKey`/`MESSAGE_DOMAIN`. Full report: `research/review7-envelope/report.md`.

- **Fixed — R7-1 (HIGH): a receipt body WITHOUT `issued_at` was signed, and the primary consumer crashes on that artifact.** `receipt.py verify` reads `body['issued_at']` unconditionally — measured exit 1, `KeyError: 'issued_at'` (the Node verifier prints `issued undefined`). The envelope minted receipts its designated verifier cannot read. Fix: `issued_at` is a required body key; missing → `refused: envelope`. The openreceipts CLI itself always sets the field, so no real caller breaks.
- **Fixed — R7-2 (HIGH): `issued_at` was format-checked, not semantics-checked.** Impossible calendar dates normalize through `Date.parse` (`2026-02-30` → March 2) and out-of-grammar offsets/seconds (`+99:99`, `+24:00`, hour 25, leap second `:60`) passed the old regex — all six classes were ALLOWED and signed (measured); the consumer cannot detect it (`receipt.py verify` prints `issued 2026-02-30 ... OK`). The grant expiry already refused exactly this class; the body field lagged. Fix: `issuedAtMs()` — grammar regex + component ranges + real-calendar day (leap years) + explicit assembly via `setUTCFullYear` (because `Date.UTC` maps years 0-99 onto 1900-1999). Refused → `envelope`.
- **Fixed — R7-3 (MED): future-dated receipts were signed without bound.** `2030-01-01` and `3000-01-01` were ALLOWED. Fix: `refused: issued_at_in_future` beyond `now + 24h`. The 24h tolerance is measured, not chosen: the daily runner stamps `issued_at` at 21:00 UTC of DAY, and the Tag-2 artifact was signed at 23:40 UTC with `issued_at` +21.4h in the future — any tighter bound breaks the running 30-day test. The past stays unbounded (backdating about a past event is legitimate; `expiresAt` bounds the signing itself).
- **Held (no finding):** the canonicalization differential does not exist on reachable bodies — 10/10 hostile strings (control chars, quotes, é/emoji, astral, lone-surrogate escape, DEL, nbsp, U+2028) are byte-identical to Python's `json.dumps` (claim values are string-typed, so number spellings never reach the bytes); the ledger's scope-disjointness claim holds under direct attack (message records are 4-part `msg\0...` in the live journal; tx approvals did not consume the message window — 1/5, not 4/5; message records did not consume the tx window — spent pinned at exactly 20400; same bytes in the other envelope are a separate identity, not a false replay); the "never throws on request data" contract holds, including an own `__proto__` property and deep nesting bounded by the daemon's 4096-char body cap (measured depths 1500/3000/4000: `message_too_large`/`request_invalid`/`request_invalid`, daemon alive after); both openreceipts verifiers accept the post-fix artifact.
- Falsification: `test/review7-envelope.test.js` — on the pre-fix tree 20140e9 (scratch checkout) **5 red / 5 green**, post-fix **10/10**; the 5 green are the false-positive guards and pass on both trees. Full suite 176 → 186, crash harness green in both modes. Cost of the extra checks: `evaluateMessage` 29.2 µs → 25.3 µs (20k iterations) — no regression. Limits, named: `+15:00` stays legal (RFC3339 grammar, not a tz database); `issued_at` is still not pinned to signing time within the 24h tolerance; `note` remains free text the grant does not speak about.

## Review #8 and Review #9 (2026-11-01) — the #7 fix held; the independent review found two more

Review #8 re-attacked the review-#7 fix diff itself (16 policy + 8 live
probes, `research/review8-r7diff/`): all three #7 findings stayed refused,
the false-positive guards stayed green on both trees, and the fixed future
bound is measured to be inclusive at exactly +24h with the first refusal at
+24h+1µs.

Review #9 was the **first review by an isolated reviewer context** that
committed its initial findings *before* reading any prior review report:
- **Fixed — R9-1 (MINOR): fractional seconds never reached the 24h future bound.** The grammar accepted `2026-11-03T21:00:00.999999Z` but the captured fraction was discarded, so a receipt up to 999 999 µs past the bound was still signed (measured on the pre-fix tree). Fix: the fraction is parsed exactly in fixed-point microseconds; the boundary probe and 5 guard tests ship as a second witness. Signed bytes are unchanged.
- **Fixed — R9-2 (LOW): the client helper `buildReceiptBody()` built an always-refused body when called without `issuedAt`** (regression from review #7's fix, since 84888d4). Fix: defaults to now, matching `receipt.py`.

Ladder: 7 red on the pre-fix tree (5770b59), 13 green, 15 new regression tests; full suite 206/206 with 0 skipped. Honest note: the reviewer is independent of reviews #5–#8 but the same model family — independent, not foreign.

## Stranger-install / quickstart defects (2026-11-02) — 4 found and fixed, the refusals held

The qualification suite has always run from a checkout (`npm ci`, pretest builds `tools/leasecheck`, the daemon is started from `../bin`). A stranger installing the package gets a different tree, so the first hour was measured end to end instead of assumed: `scripts/install-smoke.js` (`npm run test:install-smoke`) packs, installs into a fresh directory, then runs keygen -> grant -> daemon -> `sign-message` verified **outside** the product (Node OpenSSL ed25519 against the daemon keypair) and a refusal ladder where every step asserts a NEGATIVE first, so a green run cannot come from a skipped step. It runs in CI next to the suite.

Running the documented quickstart verbatim under this machine's default umask **0002** (the Ubuntu/Debian desktop default) found four defects — measured, not argued:

1. **The loop (worst): signerd created the state it then refused.** `keygen` made the keystore's parent directory with a bare `mkdirSync`, which inherits the umask -> 0775 -> the very next `run` refused that directory with `keystore_dir_mode: 775`. A stranger who did everything right hit a wall built by the tool itself. **Fix:** a directory the write path *creates* is made 0700 explicitly (mkdir mode + chmod, the same pattern the daemon's socket directory already used); a directory that already exists is the operator's and stays under the load-time rules — the review #6 contract (loader is the judge) is unchanged, now pinned by `test/quickstart-stranger.test.js`.
2. **The passphrase file (by design, but a dead end):** `printf > pass` yields 0664 under umask 0002, and `readPassphrase()` correctly refuses a group-readable passphrase — the refusal message only named the verdict, not the repair. **Fix:** the refusal stays fail-closed and now prints `fix: chmod 600 <path>` (and `chmod 700 <dir>` for the directory case). The rule itself is untouched: `test/quickstart-stranger.test.js` pins that a genuinely loose file is still refused (this is the one test GREEN on the pre-fix tree — the false-positive guard).
3. **The ledger directory: a raw errno where a setup step belonged.** The README points `--ledger` at `~/.local/share/signerd/...`, a directory nothing ever created -> `ledger_lock_failed: ENOENT` (also `seal-journal`/`migrate` would refuse at the lock). **Fix:** `start()` creates the ledger's parent directory 0700 with the same dir-mode/owner refusals when it pre-exists loose (`ledger_dir_mode` / `ledger_dir_owner`), mirroring the socket directory.
4. **The quickstart did not create its own inputs.** The README's Shape block now creates the passphrase file owner-only (umask 077 + chmod) and says why. Measured verbatim afterwards under umask 0002: keygen exit 0, keystore dir 0700, state dir 0700, daemon up, refusal ladder intact.

**Ladder:** `test/quickstart-stranger.test.js` (5 tests) is 4 RED / 1 GREEN on the pre-fix tree and 5/5 GREEN after; the pre-fix-GREEN one is the loose-passphrase refusal (the guard proving the fix did not weaken the rule). Full suite 212 -> **217/217**, crash harness green both modes, install-smoke 12/12 checks.

**Limits:** no signature bytes, grant semantics or ledger format changed; an operator who pre-created a loose state directory still gets the (now self-explaining) refusal rather than a silent chmod; the install-smoke covers Linux x64/npm only (no macOS/Windows run); still user zero — no outside user has installed it.

## Sealed-mode surface defects (2026-11-06) — the documented sealed block could not run

The sealed mode is opt-in, so almost nobody had walked it end to end, and the instruments that guard the quickstart missed it: `test/installed-tag-journey.test.js` checks that the pinned tag *dispatches* and *documents* each command **name** — never that the documented **flags** parse — and no test executed the seal block from the README. The defect cluster below was found by running the README's own seal block verbatim against a fresh setup, and each defect is pinned by `test/sealed-mode-surface.test.js` (7 tests: 4 enforcement RED on the pre-fix tree, 3 guards GREEN on both trees).

1. **The tools were documented with the daemon's flags.** The block said `seal-grants --grant-seal-passphrase-file` and `seal-journal --ledger`, but the tools read `--seal-passphrase-file` and `--journal` (`readPassphrase(args, 'seal-passphrase-file')`, `requireArg(args, 'journal')`). Both lines exited 2 with `missing --seal-passphrase-file` / `missing --journal` — a documented command that cannot execute, the same class as the cargo-install line fixed on 2026-11-02. **Fix:** the README now writes the tools' own flags.
2. **The block was in the wrong place.** It sat *before* `signerd run`, but the journal file is created by the daemon's **first append** — the `sign` line — so `seal-journal` on a fresh setup failed with `ledger_missing`, and while the daemon was still running it would also have hit `ledger_locked: pid <n>`. **Fix:** the block now sits after the client section and states its own order: seal the grant file, then (after the daemon has signed once, and after it is stopped) seal the journal, then restart in sealed mode. The closing `signerd run ...` shorthand — which is not an executable command — is now the full command with its flags, so the block can be run verbatim.
3. **A crashed daemon bricked the offline recovery tools.** `seal-journal` and `migrate` each carried their own minimal lock claim that refused **every** existing lock with `ledger_locked: stop the daemon first`, while the daemon itself took over a provably dead owner (`#acquireJournalLock`). A daemon killed with SIGKILL leaves `<journal>.lock` behind (nobody runs the release path), so the tools refused **forever** with a message telling the operator to stop a daemon that was not running — while `signerd run` on the same journal would have started. The tools were the only processes that could not proceed, and they are exactly the processes an operator reaches for after a crash. **Fix:** the daemon's lock logic moved into `src/journal-lock.js` and the offline tools now use the **same** implementation — one rule, so the two cannot drift apart again. A live owner still refuses everything (`ledger_locked: pid <n>`, guard G1); a provably dead owner is taken over with the same guarded rename-and-prove race window the daemon's review #1 test pins.
4. **The README told the operator to hand-edit a file the loader refuses to trust.** The old instruction said the sealed grant file was never rewritten at all and sent the operator to edit it by hand and re-seal afterwards — contradicting the CLI, which has re-sealed a sealed file on `grant-add --append --seal-passphrase-file` since commit `bf72775` (measured working 2026-11-06: append → `{"ok":true,…,"sealed":true}`, `verify-grants` ok). Hand-editing a sealed file breaks its seal, and the daemon then refuses the file (`grant_file_seal_mismatch`). **Fix:** the README now names the CLI's repair (`grant-add --append` / `grant-remove` re-seal as part of the act). The regression test scans the README for the old sentence, so this cannot come back unnoticed.

**Ladder:** `test/sealed-mode-surface.test.js` is **4 RED / 3 GREEN** on the pre-fix tree (`git stash` of the fix, test kept) and **7/7 GREEN** after; the 3 pre-fix greens are the false-positive guards (a live lock still refuses, a missing journal still refuses, a group-readable passphrase file is still refused) — a fix that refuses everything is not a fix. Full suite 391 -> **398/398**, crash harness green in both modes (25 SIGKILL rounds, sealed and unsealed), install-smoke 12/12.

**Instrument note (why the first version of the test measured nothing):** `process.kill(pid, 0)` reports an **unreaped zombie** as alive, and a synchronous `spawnSync('sleep')` poll loop blocks the very event loop that would reap it. A daemon killed as a backgrounded grandchild therefore looked alive forever, and the "dead owner" precondition of the takeover test could never hold. The test now spawns the daemon as a direct child and waits for the `exit` event asynchronously. The same trap would bite any later test that wants a provably dead lock owner.

**Limits:** the sealed mode itself is unchanged — same HMAC seal, same key derivation, same floor anchor, same refusals; only the lock's *ownership rule* is now shared, and a live lock still refuses exactly as before. No signature bytes, grant semantics or journal format changed. Still user zero — no outside user has installed it.

## Flag-surface defects (2026-11-06) — a security flag could be silently switched off

`bin/signerd.js` parsed `--flag value` into a map and then read only the flags the dispatch knew about. Everything else was dropped without a word. For a cosmetic flag that is invisible; for a security flag it is a **fail-open**, because the flags that turn sealed mode on are *optional* — `run` starts happily without them.

**Measured (2026-11-06, live, pre-fix), the same grant file both times** — a file that was sealed with `seal-grants` and then tampered with (cap raised to 999999999999, so the HMAC no longer verifies), started twice, differing only in one dash of one flag (each line below is the *flag given to `signerd run`* and the daemon's answer):

```
--grant-seal-passphrase-file <pass>   -> grant_file_seal_mismatch   (daemon REFUSES)
--grant-seal-passphrasefile  <pass>   -> {"ok":true,...}            (daemon STARTS)
```

One missing dash and the daemon started **unsealed** on a grant file whose seal no longer verifies — reporting `{"ok":true}` and giving no indication that sealed mode was off. Sealed mode exists to refuse exactly that file. Two more cases of the same class were measured: `--journal-seal-passphrasefile` behaves identically on the journal half, and `grant-add --seal-passphrase-file <file>` **without** `--append` accepted the flag and wrote an **unsealed** file (`seal` field absent, `{"ok":true}`) — the operator asked for a sealed file and got one the daemon in sealed mode would refuse, while the `--append` path already refused the same situation (`grant_file_unsealed`): one flag, two behaviours.

**Why nothing caught it:** every existing instrument checked *documented* lines against the CLI (`missing --<flag>` is visible; an ignored flag is not). A flag the README does not document, but that an operator can type — and that the CLI silently swallows — had no instrument at all.

**Fix (test-first).** `src/cli-flags.js` declares, per command, the flags that command's dispatch actually reads. `bin/signerd.js` refuses anything else **before** it reads, writes or starts anything:

```
unknown_flag: --grant-seal-passphrasefile
  fix: signerd run does not take --grant-seal-passphrasefile - did you mean --grant-seal-passphrase-file?
  fix: signerd run takes: --grants --grant-seal-passphrase-file --journal-seal-passphrase-file --keystore --ledger --passphrase-file --socket
```

The refusal names the flag, the repair (the closest flag the command does take, when there is one) and the full list; a positional argument after the command is refused the same way (`unknown_argument`), so nothing is dropped either. An **unknown command** still prints the usage banner — `tools/measure-documented-flags.mjs` reads that banner to classify one. `grant-add --seal-passphrase-file` without `--append` now refuses `grant_file_unsealed` and writes **nothing**, naming both repairs the CLI offers (create then `seal-grants`, or `--append`).

**Ladder (`test/flag-surface.test.js`, 10 tests):** **7 RED / 3 GREEN** on the pre-fix tree (the fix stashed, the test kept). The 7 RED are the defect tests — including the live one above, where a typo'd seal flag started a daemon on a tampered sealed file. The 3 GREEN are the false-positive guards: with the *correct* seal flag the tampered sealed file is still refused (`grant_file_seal_mismatch`), an unknown command still prints the usage banner, and the ordinary documented commands still run — a fix that refuses everything is not a fix. After: **10/10**.

**Instrument note.** The strict surface changed the CLI's *refusal shape*, and the documented-surface instrument had to learn it: `missing --<flag>` named the flag the CLI **wanted**, `unknown_flag: --<flag>` now names the flag the README **got wrong**. Same defect class — the documented line does not run — so `tools/measure-documented-flags.mjs` reports both as a flag defect (new kind `unknown-flag`), and the guard that pins the pre-fix seal block accepts either shape. Two of the review-#6 CLI tests also had to be corrected: they passed `--keystore`/`--passphrase-file` to `status`, which has never read either — flags the old CLI swallowed silently, so those tests were passing for a reason unrelated to what they assert. The instrument, not the test, was wrong; the hygiene assertions are unchanged and still pass.

**Limits:** argument hygiene, not a sandbox — a flag that *is* in the list can still be given a bad value (the value validators judge that), and the allowlist only holds as long as a dispatch's flag list is kept in sync with `src/cli-flags.js` (pinned per direction: F4 checks every flag the README documents is accepted; the per-command lists are the flags each dispatch reads). Still user zero — no outside user has installed it, and nothing here changes signature bytes, grant semantics, journal format or the seal itself.

## Flag-arity defects (2026-11-07) — a flag can be used wrongly and the difference is dropped

The 2026-11-06 fix above answers *"is this flag known?"*. It cannot answer *"is this flag used the way you typed it?"* — and the parser turned tokens into a **map**, so three shapes simply vanished, because a map holds one value per key:

**Measured (2026-11-07, live, pre-fix tree `6ff287d`) — four fail-opens, one class.**

| Command line typed | What signerd did | What it should have done |
|---|---|---|
| `run --grants narrow.json --grants wide.json` | last wins **silently** | refuse `duplicate_flag` |
| `grant-add … --max-lamports 1000 --max-lamports 999999999` | exit 0, file written with `maxLamports "999999999"` | refuse `duplicate_flag` |
| `keygen --keystore first.key --keystore second.key` | exit 0, `second.key` created, `first.key` never created | refuse `duplicate_flag` |
| `run … --grant-seal-passphrase-file` *(path forgotten)* | sealed mode reads as **absent** | refuse `missing_value` |

The first row is the sharpest, because it is a **scope** change, not a convenience. Measured live: `narrow.json` caps the grant at 1000 lamports and `wide.json` at 999999999. The daemon given `--grants narrow.json --grants wide.json` enforced **wide** and **signed 500005000 lamports** (`{"ok":true,…,"seq":1}`) for a transaction that `narrow.json` alone refuses with `amount` (`{"ok":false,"error":"amount"}`). The operator named `narrow.json` first, and nothing said the second `--grants` replaced it.

The fourth row is the 2026-11-06 failure **re-entering through arity instead of spelling**. `args["grant-seal-passphrase-file"]` becomes `true` when the path is missing, and the dispatch reads `typeof … === "string"` — so sealed mode reads as *not set*. Measured on the same tampered sealed grant file as above: the correct flag refuses `grant_file_seal_mismatch` (exit 1); the flag with no value let the daemon **start** and answer `{"ok":true}`. One forgotten path turned the sealed-mode guarantee off, exactly as one missing dash did.

Two more measured in the same class: `grant-add … --seal-passphrase-file` *(no value, no `--append`)* exited 0 and wrote a file with **no `seal` field** — while the same flag *with* a value refuses `grant_file_unsealed`: one flag, two behaviours. And `sign … --dry true` made `args.dry` the **string** `"true"`, so `args.dry === true` was false and the request went out as a **real sign**: exit 0, a real signature, 368 bytes appended to the journal, `--out` written (215 bytes). The bare `--dry` previewed and wrote nothing. The README promises a non-boolean dry is *"never degraded into a real signature"* — the CLI degraded it anyway, because it read arity as presence.

**Why nothing caught it:** every instrument in this repo compares a *documented* line against the CLI. A documented line cannot carry a duplicate flag twice without looking wrong on the page — so this class is invisible to the documented-surface, the installed-tag-journey and the release-surface alike. It needed an operator who types the same flag twice, which is exactly what a wrapper script or a copied command line does.

**Fix (test-first).** `src/cli-flags.js` gains `parseArgv()` (the tokens, plus the arity problems) and `arityProblems()` (the rule, per command); `bin/signerd.js` refuses on the first problem **before** it reads, writes or starts anything:

```
duplicate_flag: --grants
  fix: give --grants once   # it was given twice: "…/narrow.json" and "…/wide.json"
  fix: signerd run cannot know which one you meant, and silently taking the last one changes what is enforced
missing_value: --grant-seal-passphrase-file
  fix: give --grant-seal-passphrase-file its value   # a flag without a value reads as absent, and an absent security flag turns a guarantee off
flag_takes_no_value: --dry
  fix: give --dry alone   # it is a switch and takes no value, but it was given "true"
```

Each refusal names the flag, the repair, and — for a duplicate — **both values**, so the operator can see which file was meant twice. The switch set is declared per command (`--dry`, `--append`, `--overwrite`, `--add-grant`, `--discard-legacy`), because the same name can be a switch in one command and a value flag in another.

**Ladder (`test/flag-arity-surface.test.js`, 15 tests):** **11 RED / 4 GREEN** on the pre-fix tree `6ff287d` (the fix stashed, the test kept). The 11 RED are the defect tests — including the live daemon that signed 500005000 lamports, the tampered sealed file that started unsealed, and the `--dry true` that became a real signature. The 4 GREEN are the false-positive guards, and they are green **on both trees**: the bare `--dry` still previews and writes nothing (and the same body still signs for real afterwards), an unknown flag still answers `unknown_flag` with the did-you-mean suggestion, the ordinary documented commands still run, and an **absent** flag still answers the documented `missing --<flag>` — arity covers a flag that was *typed*, not one that was forgotten. After: **15/15**, full suite **450/450** (was 435).

**Mutation ladder (`tools/mutation-ladder-arity.sh`, 7 mutations):** each mutation breaks one property of the rule in a plausible way — duplicates parsed but never reported; a value flag with no value accepted; a switch given a value accepted; `--dry` no longer declared a switch; the refusal computed but never acted on; the duplicate refusal no longer naming both values; the switch set dropped so every flag reads as a value flag. **All 7 caught**, the tree restored byte-identically (sha256).

**Limits:** argument hygiene, not a sandbox — it says nothing about the *value* of a flag (a present-but-wrong value is judged by the value validators, as before), and it does not change signature bytes, grant semantics, journal format or the seal. The switch list is a second hand-maintained table next to `COMMAND_FLAGS`; a switch added to a dispatch without listing it there reads as a value flag. Still user zero — no outside user has installed it, and no real funds are involved.

## Grant value contract defects (2026-11-08) — a scope the operator wrote could never sign

The creation path (`signerd grant-add`) and the loader (`src/grantfile.js`) judged grant values by their **shape** — a base58 charset regex for keys, a calendar-shape regex for the expiry (`/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/`), digits-only regexes for the caps — while the daemon runtime (`src/policy.js`, `src/ledger.js`) judged them by their **meaning**: an actual 32-byte canonical public key (`new PublicKey(v).toBase58() === v`), a canonical RFC3339 round trip, a u64 in range (`[0, 2^64-1]`), a positive safe-integer window (`Number.isSafeInteger`).

`Date.parse` normalizes impossible calendar dates instead of rejecting them: `Date.parse("2030-02-31T00:00:00Z")` rolls forward to `2030-03-03T00:00:00.000Z`. So `grant-add --expires 2030-02-31T00:00:00Z` exited 0, wrote the grant file, and every later request against that scope was refused `invalid_grant` — a scope that looked configured and was permanently dead.

Measured with `tools/measure-grant-value-contract.mjs` (output `research/grant-value-contract-2026-11-08.json`): **16 of 30 candidate values** were accepted by the creation path and then refused by the daemon.

All five validation sites (`grantadd.js`, `grantfile.js`, `policy.js`, `policy-message.js`, `ledger.js`) now read **one shared source of truth** (`src/grantvalues.js`):
- `isCanonicalPublicKey(v)` — real 32-byte Ed25519 public key in canonical base58;
- `isCanonicalExpiry(v)` — real instant that exists in UTC (no Feb 31, no month 13, no hour 25, no leap seconds);
- `isU64(v)` — decimal integer in `[0, 2^64-1]`;
- `isWindowSeconds(v)` — positive safe integer (no zero, no precision loss);
- `isMessageCount(v)` — safe integer message count.

The refusal voice follows the house rule: the machine-readable code `grant_field_invalid` appears exactly once and names a field-specific `fix:` line.

**Ladder (`test/grant-value-contract.test.js`, 7 tests):** **4 RED / 3 GREEN** on the pre-fix tree (V1, V2, V5, V6 red; V3 oracle and V4 boundary guards green on both trees). After: **7/7**, full suite **502/502** (was 495).

**Mutation ladder (`tools/mutation-ladder-grant-values.sh`, 5 mutations):**
- M1: `grantadd` accepts calendar shape without canonical instant (Feb 31 bug) -> caught;
- M2: `grantadd` accepts base58 charset without 32-byte key -> caught;
- M3: `grantadd` accepts arbitrary digits for `maxLamports` -> caught;
- M4: `loader` accepts non-canonical expiry -> caught;
- M5: refusal drops the `fix:` line -> caught.
All 5 caught, tree restored byte-identically.

**Measurement artifact:** `research/grant-value-contract-2026-11-08.json` records 30 cases across both slots — before: 16 contract violations; after: 0.

## Delivery durability defects (2026-11-08) — the delivered signature could be lost by a crash

> **Fixed in this pin (`v0.2.11`).** The defect below was measured on the tree that shipped `v0.2.10`; the fix ships here. On the `v0.2.10` tag the ladder is 1 RED / 2 guards green; on this pin it is 3/3.

The `--out` delivery is atomic: a temp file in the same directory, `fsync`, then `rename` over the target. Atomic means a reader never sees a half-written artefact and a failed write never destroys the previous content. It does **not** mean the delivery is *durable* — and that word is the one the CLI's exit code promises.

Measured 2026-11-08 with `strace` on this tree (one delivery, `writeOutAtomic`):

```
openat(".../.signed.json.signerd-<pid>-<hex>.tmp", O_WRONLY|O_CREAT|O_EXCL) = 22
fsync(22)                                   = 0     <- the TEMP FILE
rename(".../.signed.json....tmp", ".../signed.json") = 0
```

One `fsync`, on the temp file, and then the rename. **The parent directory is never fsynced.**

A rename is a *directory* operation: until the directory entry itself is durable, a crash can lose it — the target reverts to its previous content, or the new name is not there at all. The temp file's own `fsync` made the **data** durable, not the **name**. So the sequence can end with the CLI having exited **0** ("signed **and** delivered"), the operator believing the paid-for signature is at `--out`, and the file on disk still holding the *previous* artefact — or nothing at all.

That is the same loss this repo has been closing for a week, one layer further out: the daemon signed, the budget was charged and the replay identity was recorded, so the retry is refused `replay`. The signature is gone, and the honest report (exit 3 / exit 4) never happens, because the CLI said everything was fine.

This is not a house-style nit. **Four sibling atomic-write sites in this very tree already fsync the parent directory after their rename** — `src/ledger.js:756`, `src/journalseal.js:237`, `src/journalseal-ops.js:297`, `src/migrate.js:145`. The `--out` delivery was the one that skipped it, and it is the one that carries a paid-for artefact.

**The fix:** after the rename, the delivery opens the parent directory read-only and fsyncs it, so the *name* of the delivered artefact is durable when the CLI returns. Best effort, like every other site: the artefact **is** on disk at that point, so a platform that cannot fsync a directory must not turn a successful delivery into a failure. The trace after the fix:

```
fsync(22) = 0                                  <- the temp file (the data)
rename(...) = 0
openat(".../the-output-dir", O_RDONLY) = 22    <- the DIRECTORY
fsync(22) = 0                                  <- the directory entry (the name)
```

**Ladder (`test/out-dir-fsync.test.js`, 3 tests):** **1 RED** on the pre-fix tree (D1/D2 — no directory fsync was seen at all), 2 guards green on both trees. After: **3/3**, full suite **513/513** (was 510). The ladder watches the real syscalls (`fs.fsyncSync` and `fs.renameSync` on the shared `node:fs` module) and records them in ORDER, because counting fsyncs cannot see a fsync that happens in the wrong place — see M2.

**Mutation ladder (`tools/mutation-ladder-out-dir-fsync.sh`, 5 mutations):**
- M1: the directory fsync removed -> caught;
- M2: the directory fsync moved BEFORE the rename (makes the OLD name durable, leaves the new entry exactly as exposed as if there had been no fsync) -> caught;
- M3: the temp file's own fsync dropped -> caught;
- M4: a failing directory fsync turned into a failed delivery -> caught (the artefact is on disk; refusing it would be a new lie);
- M5: the fsync done on the wrong directory -> caught.

All 5 caught, the control stayed green, and the tree was restored byte-identically.

**Limits, stated rather than hidden:** the directory fsync makes the name durable against a crash of *this machine*; it does not protect against a filesystem that lies about `fsync`, and it does not make the delivery atomic across a network filesystem (the temp file and the target share a directory, so the rename stays within one filesystem). A platform that refuses to fsync a directory gets the best-effort path and no guarantee — the same trade the four sibling sites make. The check is at the moment of the delivery, not before the sign.

## Socket-path domain defects (2026-11-09) — three defects in how signerd judged its socket

The socket path is a **capability**: whoever can bind it can impersonate the signing daemon. That is why the daemon validates the socket directory, its mode and its owner (`src/daemon.js`).

It also means the path itself has a domain — and the domain is the one the **kernel** enforces, not an arbitrary guess.

**Measured on this host (Linux, `struct sockaddr_un`):**

* `char sun_path[108]` (see `sys/un.h`). A real bind + connect round trip works at 108 bytes and fails with `EINVAL` at 109 (`tools/measure-socket-path-domain.js` proves this with live round trips at 107, 108 and 109 bytes).
* The kernel measures **bytes** of the string handed to `bind()`, not characters: 90 characters of mixed ASCII and two-byte UTF-8 (135 bytes total) fail with `EINVAL`, while 105 ASCII bytes work.

**Three defects measured on the published `v0.2.11` tag (`research/socket-path-domain-2026-11-09.json`):**

1. **The check measured characters against the wrong ceiling:** `path.resolve(socketPath).length > 100`.
   - A legitimate 105-byte path was **refused** (`socket_path_too_long`) although the kernel accepts it — a false refusal of a working setup.
   - A 90-character / 135-byte path **passed** the check and died later at `bind()` with a raw `EINVAL: listen EINVAL: invalid argument ...` — the daemon's own refusal surface was bypassed.
   - The check measured the *resolved* path while the kernel judges the string actually passed to `bind()` — two different strings.
2. **The refusal carried no detail:** `socket_path_too_long: ` — an empty string, no byte count, no limit, no repair line. The house voice (`test/grant-refusal-voice.test.js`) requires every refusal to name its code once, its value, and its repair.
3. **The client never preflighted the path:** `signerd sign --socket <121 bytes>` reached `net.connect` and printed `EINVAL: connect EINVAL <path> - Local (undefined:undefined)` — a raw errno, a mangled message, and the literal text `(undefined:undefined)`.

**Fix:** `src/socketpath.js` is the single source of truth for both sides.
- `checkSocketPath` judges the path in **bytes** against `SUN_PATH_MAX_BYTES = 108`.
- The daemon constructor refuses with code, byte count, limit and repair line before anything is locked or started.
- The client preflights the path before the round trip and refuses with the **same** code and repair line.

**Measurement (`research/socket-path-domain-2026-11-09.json`, pinned by `test/socket-path-measurement.test.js`):**

* Baseline (`git archive v0.2.11`, the published tag): 3 of 3 cases violated (empty-detail 121-byte refusal + raw errno in client; raw `EINVAL` on 90-char / 135-byte path; false refusal on 105-byte path).
* This tree: 3 of 3 cases conform, verdict **`fixed`**.
* Regression ladder: `test/socket-path-domain.test.js` (8 tests: S1–S4 red on `dc75e63`, G1–G3 guards green on both; 8/8 green here).
* Mutation ladder: `tools/mutation-ladder-socket-path.sh` — 7 mutations caught (character count, ceiling 200, ceiling 100, missing byte count, no client preflight, no daemon check, no client repair line), both controls green, tree restored byte-identically.
* Preflight cost: **225 ns per call** (measured over 200,000 calls).

**Limits, stated rather than hidden:** `sun_path` is 108 bytes on Linux, but BSD/macOS allocate 104 bytes in `sockaddr_un.sun_path`. On this Linux host the 108-byte limit is what the kernel enforces; running on macOS against a 106-byte path is caught by the kernel at bind time (untested live because no macOS host is reachable; the Darwin integrity checks are documented in the release notes). The check runs on the path as passed, which matches what `net.createServer().listen(path)` hands down to the C library.

## Next qualification

0. A **third** independent adversarial review of the signing path after the review-#2 fixes land (`src/signer.js`, `src/daemon.js`, `src/keystore.js`, `src/grantfile.js`, `src/ledger.js`), before pointing it at a key with funds: two reviews have run (2026-10-27 hardening diff, 2026-10-29 signing path) and all 12 findings are fixed and regression-tested, but neither was a professional audit and the fixes themselves have not been independently reviewed.
1. Expand supported instructions only when the fee and authority effects can be bounded; refuse anything undecidable, rather than widening policy to pass tests.
2. Migrate own key-loading sites that fit the reviewed envelope as user zero; then run the 30-day restart/over-limit/refusal test. **The one remaining own site (`openreceipts`) was measured on 2026-10-28** — it does not fit the v0 message domain (canonical JSON receipts vs. legacy System transfer wires), though the key itself is adoptable after conversion. No own legacy site remains to migrate: user zero must now come from an envelope that can express the work (a message-grant for receipt signing, or v1 SPL-Token for real Solana transfers), or from an outside adopter. No outside users yet. **2026-10-31: the message-grant envelope exists, a live daemon signs receipts that both openreceipts verifiers accept (`test/message-e2e.test.js`), and the receipt-producing flow is wired end to end: `receipt.py sign --via-signerd` runs the real client with zero key material (`test/via-signerd-consumer.test.js`, 7 tests; live run `research/consumer-live-2026-10-31/`).** What is still open: the 30-day test itself (started 2026-10-31 with restart + overdraw + replay checks, to be run daily) and the first outside user. **2026-11-01 (day 2): `research/consumer-live-daily/run.sh` — the daily runner, `DAY=YYYY-MM-DD ./research/consumer-live-daily/run.sh` writes `research/consumer-live-<DAY>/`. Day 2 additionally pins the R6-1 fix live: an empty seal passphrase file must refuse to start (`seal_passphrase_required`), which the pre-fix tree does not do — it started unsealed.** **2026-11-01 (day 3 + the review window): the independent review #9 landed and was merged (HEAD 0e99685), the daily runner was run green against the fixed openreceipts main (25c9106) after the H12d verifier/feed fixes, and the qualification branch was **merged to main and tagged `v0.1.0`** — v0 is shipped. **2026-11-04 (day 7): green at the earliest moment the day exists — the receipt is dated 21:00Z of DAY and the future bound admits it from 21:00Z on; the run at 21:38Z (`research/consumer-live-2026-11-05/`, 8/8 checks) proves the gate opens on time, and the DAY+1 control refused `issued_at_in_future` with no artifact. Days 4-6 live in their committed artifacts (`research/consumer-live-2026-11-0{2,3,4}/`).** **2026-11-06 (day 8): `--dry` falsified in the live consumer run (`research/consumer-live-2026-11-06/`, report + receipt).** Before the real client runs, the identical receipt body is previewed via `sign-message --dry`: it reports `allowed: true`, writes nothing to `--out`, appends 0 bytes to the journal, and the SAME body is signed for real immediately afterwards (`receipt.py sign --via-signerd`) — proving that the dry run burned neither the window budget nor the replay identity. A dry run that had leaked a replay record would refuse here with `replay`. Pinned by `test/dry-consumer-falsification.test.js` (4/4 tests: 2 rot on pre-fix `e121f0c`, green here) and `tools/mutation-ladder-dry-consumer.sh` (5/5 mutations caught).
3. **The SPL-Token option is now measured and rejected as the main path** (2026-10-30, `tools/envelope-traffic.mjs`): a v1 SPL-Token envelope would cover ~3 of 13,390 sampled mainnet transactions (0.02%), because real token transfers are wrapped in DEX programs, compute-budget instructions or address tables rather than being bare single-instruction transfers. The message-grant envelope (signing a receipt/attestation rather than a transaction shape) is the direction this evidence points at — it is the domain of the one measured own site. This is a scope decision, not a safety claim: no envelope has been reviewed for it yet.

## Distribution and adoption (measured, not asserted)

**First earned placement (2026-11-02):** [solana-foundation/awesome-solana-ai#280](https://github.com/solana-foundation/awesome-solana-ai/pull/280) adds signerd to the list's Developer Tools section (format per that list's CONTRIBUTING; the list merged 70 of 183 outsider PRs at submission time, so a merge is not assumed). Whether that channel delivers is a question with an answer, not a hope.

**Adoption is a verdict, not a sentence.** `node tools/measure-adoption.mjs` classifies external use from non-owner stars/forks/issues/PRs, non-GitHub referrers, and the live state of the placement PR. Baseline committed in `research/adoption-2026-11-02.json`: 0 non-owner stars, 0 forks, 0 external issues/PRs, 0 external referrers, 14-day views 3/3, 348 clones (our own CI checkouts, explicitly not an adoption signal) — verdict **`not-distributed-not-consumed`**. A merge will read as `distributed-not-yet-consumed`, never as adoption; only a non-owner star/fork/issue/PR can read as `user-one-evidence`. The probe exits 3 with `NO VERDICT` when a data source fails (control: a nonexistent repo), so partial evidence never becomes a claim (`test/measure-adoption.test.mjs`).

**Foreign use is a different question, and it is measured separately** (`node tools/measure-foreign-use.mjs`, report in `research/foreign-use-2026-11-03.json`). Adoption measures what happens on *this* repo's own page; the question that actually matters for a daemon people wire into *their* tooling is whether a repo I do not control references signerd. That probe sweeps five surfaces (the repo slug, the slug as a `github.com` URL, the URL-escaped slug in dependency strings, issues/PRs, and commit messages), and it answers in classes rather than sentences:

- every surface carries a **positive control** — a literal known to exist in an indexed repo. A surface whose control does not resolve is `unmeasured`, never "zero hits";
- every hit is **verified by reading the file**, not by trusting the search index;
- ownership is decided by the **collaborator-permission endpoint**, and a hit is attributed by its **author** — so my own placement in a foreign repo (awesome-solana-ai#280) is my distribution, not an outsider's consumption. An undetermined permission read is `unknown`, never `foreign`.

Measured 2026-11-03: 5/5 surfaces measured (controls 419 code / 997 issues / 113 commits), 2 candidate repos, **0 verified foreign references**, both verified references own → verdict **`own-use-only`** ("own use, which proves nothing about outsiders"). The report names its own blind spot: GitHub's code-search index does not carry repos like mine — `auroraxo/openreceipts/README.md` provably contains the slug while `q=repo:auroraxo/openreceipts` returns 0, and only 2 of 7 sampled fresh public 0-star repos are indexed (29%). So an absence over the code surfaces covers the indexed subset only; the issues and commits surfaces are not subject to that limit.

**Limits of this probe:** a reference is a reference, not a verified install — it does not show that anyone ran the daemon; it does not search non-GitHub sources (blog posts, Discord); the package registries are now covered by their own probe (below), but only for name and description; it is limited to the literal slug, so a stranger who vendors signerd under a different name is invisible; the indexability rate is measured on a 7-repo sample, not an estimate of the ecosystem. Exit 3 = `NO VERDICT`; a run that lost a data source persists the report and says so rather than writing an absence into the artifact (`test/measure-foreign-use.test.mjs`, 14 tests).

**The registries are a separate probe, because the old claim about them was wrong** (`node tools/measure-registry-presence.mjs`, report in `research/registry-presence-2026-11-03.json`). The limits section above used to read "crates.io/npm out of scope (measured: crates.io 403)". That 403 was reproduced live on 2026-11-04 and it is **not a property of the registry**: crates.io rejects requests without a `User-Agent` header — same endpoint, same minute, 403 without the header and 200 with it. A client defect had been recorded as a measured absence, which is the one failure this repo keeps naming as its most dangerous. The probe now sends a `User-Agent`, treats a UA-less 403 as a **client defect** (`unmeasured-client-defect`) rather than evidence, and keeps the reproduction in the artifact so the claim cannot come back unnoticed.

What it measures: exact-name lookups (`/crates/signerd`, `/signerd`) where **404 is an authoritative absence**, plus name/description sweeps on both registries, plus a positive control per registry (`serde`, `express`) — a registry whose control does not resolve is `unmeasured`, never "zero hits". Verdict `registry-absence` / `registry-presence` / `no-verdict` (exit 3).

Measured 2026-11-03: crates.io exact `signerd` **404**, npm exact `signerd` **404**, both searches measured, both controls resolved → verdict **`registry-absence`**. The one hit is recorded but explicitly **not** counted as foreign use: `@zanii/signerd` on npm is a **name collision** — same name, same concept ("keep the agent's private key out of the agent's process"), published 2026-10-19, seven days *before* this repo's first commit (2026-10-26), with no reference to `auroraxo/signerd`, no dependency on it and no repo link. That is independent prior art, not consumption of this project, and counting it would have been a false positive in the flattering direction. Only a hit that links to this project counts (`referenceClass=foreign-reference`); collisions and incidental mentions are recorded and excluded (`test/measure-registry-presence.test.mjs`, 13 tests).

**The collision is differentiated by measurement, not by adjective** (`node tools/measure-prior-art-delta.mjs`, report in `research/prior-art-delta-2026-11-03.json`). "Same name, different concept" was prose; this probe measures both **published** packages with the same instrument so it can say the opposite. Both premise sentences are found verbatim — the shared surface is real and quoted, not denied. The domain is not shared: applying the same 6-term list (`solana`, `blockhash`, `transaction`, `lamports`, `systemprogram`, `1232`) to their **implementation** files (`src/*.ts`) finds **0/6 terms, 0 occurrences**, while the same list over our `src/`+`bin/` finds **132 occurrences** (solana 11, transaction 51, lamports 56, blockhash 6, systemprogram 5, 1232 3). Their daemon is built around a remote ledger (a required `serverUrl`, 8 mentions, npm deps `@zanii/{core,kms,pq,sdk}`); our daemon has **0 network imports or fetch calls** in src/bin. Verdict **`prior-art-distinct-domain`**: the collision lives in the name and the premise sentence, not in the product's domain. The falsification path is built in — any published change that touches the domain terms flips the verdict to `prior-art-overlaps-domain`, and a blind scanner (0 own-domain matches) or an unmeasured prior-art surface is `no-verdict` (exit 3), never "distinct". Limits: lexical counting (prose mentioning Solana counts as touching; overlap means touching, not competing); their git history is unmeasured (npm metadata carries no repository field); published artifacts only, either side can change. The prior art is **alive** (269 downloads last week, latest version 0.2.0 published 2026-10-29, Apache-2.0) — measured to be taken seriously, not dismissed.(`test/measure-prior-art-delta.test.mjs`, 15 tests.)

**Publish readiness: the bare name is free, and the artifact works before anything is published** (`node tools/measure-publish-readiness.mjs`, report in `research/publish-readiness-2026-11-04.json`). The next decision on the table is whether to claim the bare name `signerd` on the registries where the collision could appear. Measured 2026-11-04: exact-name **404 (free)** on npm, crates.io **and PyPI** — PyPI was previously listed among the unmeasured surfaces and is now first-class, with the same positive controls (`express` / `serde` / `requests`, all 200) so a free reading only stands when the registry itself resolved. The verdict distinguishes three states so it can never flatter: `publish-name-free` (all 404), `publish-name-taken` (a 200 whose maintainers are *not* auroraxo — a collision, never "free"), `publish-name-ours` (a 200 we already hold, not reported as free), and `no-verdict` (exit 3) whenever any surface or control is unmeasured — the crates.io-403 lesson applied to a new question.

The artifact side is measured **before** any publish: `npm pack` produces `signerd-0.2.0.tgz`, and installing that tarball into a clean directory runs the full product path — `keygen` writes the keystore, `run` starts the daemon (socket 0600), a valid grant file loads, and `examples/user-zero-client.js` gets a **real signature back through the socket** (215 signed bytes, seq 1) holding only the public key. The signature verifies Ed25519-valid against the keystore's public key over the wire message, and a one-byte message tamper fails that same verification (negative control). The compiled helper `tools/leasecheck` is not in the tarball by design (a checked-in binary would be an opaque trust dependency): `src/lease.js` builds it at runtime from the shipped `tools/leasecheck.c` — verified in the installed copy (`cc -O2`, exit 0). Fail-closed behaviour survived the stranger's-copy test: running from a group-writable directory is refused with the actionable `chmod 700` fix, not silently accepted.

**What blocks publishing is credentials, not the artifact**: measured on this machine, `npm whoami` returns `ENEEDAUTH`, no `~/.npmrc` or project `.npmrc` exists, and the secret store is empty. This probe measures the *name*, never the ability to publish it. Availability is also a snapshot — nothing reserves a free name.

**Correction, 2026-11-04 (day 7 of the live test): that sentence was only half true.** The "private": true field that v0 shipped with made every real npm publish fail with EPRIVATE — and no dry-run can see it: `npm publish --dry-run` never calls `libnpmpublish.publish()`, warns about auth instead, and exits 0, so the readiness probe correctly reported a missing token and wrongly concluded nothing else was wrong. The refusal was found zero-network, on the real manifest and the real packed tarball: `publish()` throws EPRIVATE *before any registry access* (that is why the proof needs no credentials), a private:true control still throws EPRIVATE, and the same manifest without the field gets past the gate and fails with a different code. The field is removed (58ea9d4); `test/publish-gate.test.js` pins the invariant — RED on the shipped v0 manifest, GREEN after, and a hand mutation (private: true restored) flips it RED again. After the fix a real (non-dry-run) publish stops at ENEEDAUTH: credentials are now the only blocker. Full suite 303/303.

Ladder: `test/measure-publish-readiness.test.mjs` (11 tests) is **RED on the pre-instrument tree `a2b0804`** (the module does not exist — the instrument is the fix); three hand mutations each go red in the dangerous direction (a 200 classified as `free` → 9/11; partial coverage yielding a verdict → 10/11; our own maintainers misread as a collision → 10/11), restored byte-identical to 11/11. Full suite 302/302 (was 291).
