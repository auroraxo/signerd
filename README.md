# signerd

Scoped signing daemon for Solana: the ssh-agent pattern, applied to Solana keys.

**Status: RFC stage (October 2026). No implementation yet.**

## The idea

Today every Solana process that signs a transaction loads the full keypair into its own memory: `Keypair.fromSecretKey`, `id.json`, or `SOLANA_PRIVATE_KEY`. Authorization is binary. A process either holds the master key or can do nothing.

signerd inverts that:

- The key lives once, in a local daemon, encrypted at rest and exposed only through a Unix socket.
- Processes hold scoped grants, not keys: program allowlist, destination allowlist, per-transaction and per-window amount caps, TTL, and caller binding.
- The daemon parses the actual transaction bytes offline and checks them against the grant before signing. A violation returns a structured refusal, not a silent failure.

The useful new capability is that an agent can be told, "you may act through these three programs, up to 0.5 SOL, for 24 hours," without receiving the key and without being watched.

## Shape

```bash
signerd init
signerd key add ops --from ~/.config/solana/id.json
signerd grant create ops --name whirl-24h \
  --program whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc \
  --dest ./whirl-vaults.txt --max-sol 0.5 --ttl 24h
```

```ts
const signer = await Signerd.connect({ grant: "whirl-24h" });
const signature = await signer.sign(transaction);
```

The planned core is a Rust daemon, a TypeScript SDK, and a built-in MCP server. `--dry` runs the same scope path without producing a real signature.

## Free and paid

- Free, MIT: daemon, encrypted keystore, all scope types, local socket, CLI, SDKs, MCP server, and append-only local audit log. No usage limits and no telemetry.
- Paid later: managed high-availability operation, HSM or PKCS#11 backends, and organization controls such as SSO, approval workflows, and audit export. Signing itself is never sold per call.

## Evidence and limits

Checked on 2026-10-24: 21 files across six of my own repositories load key material into process memory. `sendaifun/solana-agent-kit` documents a raw private key as its setup path. Solana Foundation's `kora` is a centralized cloud paymaster, and the open EVM analogue Steward exposes plaintext key material in local mode. A census of 1,123 live Solana-ecosystem repositories found no local scoped signing daemon.

This is still a hypothesis. No outside user has asked for or used it, and the transaction parser is the security boundary: a parse error can grant more authority than intended.

## Next qualification

1. Prove the offline scope check against legacy and v0 transactions, including address lookup tables and Token-2022 transfers.
2. Migrate my own 21 key-loading sites to grants as user zero.
3. Run the 30-day refutation: zero remaining key loads, forced daemon restarts, and every over-limit grant structurally refused.
