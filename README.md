# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys. signerd signs only the subset of transactions it can fully verify offline; everything else gets a structured refusal — and that refusal is the feature.

**Status: RFC stage (October 2026). No implementation yet. The scope below was narrowed on 2026-10-26 after an adversarial review (see Safety boundary).**

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

## Next qualification

1. Prove the boundary in code: the four refusal classes are refused structurally, and the offline check holds on the no-ALT subset (negative controls first).
2. Migrate my own key-loading sites that fit the envelope to grants as user zero.
3. Run the 30-day refutation: zero remaining key loads in scope, forced daemon restarts, every over-limit or undecidable grant structurally refused.
