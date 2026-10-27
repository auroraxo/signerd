# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys. signerd signs only the subset of transactions it can fully verify offline; everything else gets a structured refusal — and that refusal is the feature.

**Status: early policy-only prototype (October 2026), NOT a signing service or security-reviewed wallet.** The scope was narrowed on 2026-10-26 after an adversarial review (see Safety boundary). On 2026-10-27 the first tested *legacy System-transfer-only* refusal checker was added; the rest of the v1 envelope below remains a plan.

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

```bash
npm ci
npm test
```

**Not safe for real keys yet.** There is no daemon, keystore, socket authentication, grant isolation, stateful spend/window accounting, replay protection, transaction lifetime check, independent parser/audit, or user-zero migration. The prototype does **not** sign or submit transactions. Its per-transaction cap does not bound repeat spending, and it does not bound base transaction fees. Do not compose its `allowed` boolean with a real signer until these boundaries have been implemented and reviewed.

## Next qualification

1. Independent wire-format/adversarial review and daemon-owned atomic replay/window accounting before attaching a key or exposing a socket.
2. Expand supported instructions only when the fee and authority effects can be bounded; refuse anything undecidable, rather than widening policy to pass tests.
3. Migrate own key-loading sites that fit the reviewed envelope as user zero; then run the 30-day restart/over-limit/refusal test. No outside users yet.
