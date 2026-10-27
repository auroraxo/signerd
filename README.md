# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys. signerd signs only the subset of transactions it can fully verify offline; everything else gets a structured refusal — and that refusal is the feature.

**Status: early prototype (October 2026), NOT a signing service or security-reviewed wallet.** The scope was narrowed on 2026-10-26 after an adversarial review (see Safety boundary). On 2026-10-27 the first tested *legacy System-transfer-only* refusal checker and its atomic expenditure/replay ledger were added; the rest of the v1 envelope below remains a plan.

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
signerd init
signerd key add ops --from ~/.config/solana/id.json
signerd grant create ops --name ops-24h \
  --dest ./allowlist.txt --mints ./mints.txt --max-sol 0.5 --ttl 24h
```

```ts
const signer = await Signerd.connect({ grant: "ops-24h" });
const signature = await signer.sign(transaction);  // or: { refused: "alt" }
```

The planned core is a Rust daemon, a TypeScript SDK, and a built-in MCP server. `--dry` runs the same scope path without producing a real signature.

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
- **Fail closed**: an unreadable or corrupt journal makes the constructor throw; a torn final line (crash mid-append) is dropped and repaired, never parsed; an fsync failure during approval returns `ledger_write_failed` with nothing entering in-memory state; window refusals occur before any write.
- **Clock safety**: a backwards clock cannot shrink recorded window spend.

The atomicity claim is falsified, not asserted: `npm run test:crash` spawns a child that approves transfers in a loop, SIGKILLs it at pseudo-random points (25 rounds), and asserts that every approval the child *reported* is durable in the journal afterward — i.e. the journal is a superset of what any caller was told, and it still loads after a torn append.

### Independent adversarial probe (2026-10-27)

An independent worker ran 132 adversarial cases (raw message construction, data-field shifts, wire malleability, grant manipulation, re-serialization tampering, hidden instructions) against the implemented code. Findings and disposition:

- **Fixed — prototype-polluted grant fields**: a grant missing `expiresAt` / `windowMaxLamports` silently inherited the value from a polluted `Object.prototype`, changing the verdict. All grant fields are now read from **own properties only** (`ownField`), and accessors (getters) are refused so a TOCTOU getter cannot report the cap twice.
- **Fixed — hostile clock**: a `Date` subclass overriding `getTime()` could make an expired grant look current. The clock is now read once, and only from a genuine `Date` (`readClock`); subclasses are refused.
- **By design, not a defect**: amount `0` is allowed (it moves nothing, and the ledger still charges its 5000-lamport fee); operator-chosen grant values (`maxLamports = u64max`, far-future `expiresAt`) are honored as written; signature bytes are deliberately not verified — the policy attests to the *message*, and the future signing path decides what to sign; a flipped blockhash byte passes because the blockhash is not (and cannot be) validated offline — it merely fails on-chain.
- The probe worker timed out before writing its own report; the raw case log survived (`allowed`/`refusedCounts`/`errors` + per-case detail), and both defects above were independently reproduced and then regression-tested before being called fixed.

It does **not** parse transactions, hold keys, or sign. Single writer per journal file; no cross-process lock; journal grows without bound.

```bash
npm ci
npm test
```

**Not safe for real keys yet.** There is no daemon, keystore, socket authentication, or grant isolation. The prototype does **not** sign or submit transactions, and it has no independent adversarial review of the implemented code (the first review attempt of the policy prototype timed out; a second independent false-allow probe of `src/policy.js` was commissioned). Its per-transaction cap and the ledger's fee arithmetic do not replace on-chain simulation, and the ledger does not bind transaction lifetime (blockhash freshness) — a stale blockhash simply fails on-chain. Do not compose its `allowed` boolean with a real signer until these boundaries have been implemented and reviewed.

## Next qualification

1. Independent wire-format/adversarial review of both `src/policy.js` and `src/ledger.js` (the false-allow probe covers the policy; the ledger's journal/atomicity semantics still need review) before attaching a key or exposing a socket.
2. Expand supported instructions only when the fee and authority effects can be bounded; refuse anything undecidable, rather than widening policy to pass tests.
3. Migrate own key-loading sites that fit the reviewed envelope as user zero; then run the 30-day restart/over-limit/refusal test. No outside users yet.
