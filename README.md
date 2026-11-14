# signerd

**Give your scripts permission to sign, not your private key.**

signerd is a small local signing daemon for Solana, modelled on `ssh-agent`.
Your key lives once, encrypted, inside the daemon. Bots and scripts get a
*grant* instead: "send up to 0.5 SOL to this address within 24 hours". The
daemon checks every request against that grant before it signs, and refuses
anything it cannot verify from the transaction bytes alone.

> **Status: early prototype (v0).** It has had adversarial review by its own
> author, but no independent security audit. Do not use it with funds you
> cannot afford to lose. It is a reviewed idea with a tested implementation,
> not a reviewed wallet.

## Why

Today most Solana scripts load the full keypair (`id.json`, an env var, a
secret in CI). Whatever runs next to that key can spend everything in it.
With signerd:

- the key is stored once, encrypted, behind a local Unix socket
- each process holds a scoped grant, never the secret
- a prompt-injected or buggy script can only do what its grant allows
- revoking a grant takes effect on the next request, without a restart

## Install

```bash
npm install signerd
```

That installs it into the current project. The examples below call `signerd`
directly, so either prefix them with `npx`, or install it globally:

```bash
npm install -g signerd
```

The same tree from a release tag:

```bash
npm install github:auroraxo/signerd#v0.2.23
```

You need Node.js and a C compiler (`cc`) once: the daemon builds a small
kernel-lease helper from the shipped `tools/leasecheck.c`. If it is missing,
signerd says so and names the repair.

```bash
cc -O2 -o node_modules/signerd/tools/leasecheck node_modules/signerd/tools/leasecheck.c
```

## Try it in five steps

```bash
# 1. an encrypted key and a passphrase file (owner-only on purpose)
umask 077
mkdir -p ~/.config/signerd
printf 'your passphrase\n' > ~/.config/signerd/pass
chmod 600 ~/.config/signerd/pass
signerd keygen --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass

# 2. a grant: what this scope may do
signerd grant-add --grants ~/.config/signerd/grants.json --name ops-24h \
            --keystore ~/.config/signerd/ops.key \
            --destination So11111111111111111111111111111111111111112 \
            --max-lamports 500000000 --window-max-lamports 500000000 \
            --window-seconds 3600 --expires 2030-01-01T00:00:00Z
# a second scope is a second grant in the same file, added with --append
signerd grant-add --grants ~/.config/signerd/grants.json --name ops-payroll --append \
            --keystore ~/.config/signerd/ops.key \
            --destination Vote111111111111111111111111111111111111111 \
            --max-lamports 1000000 --window-max-lamports 1000000 \
            --window-seconds 60 --expires 2030-01-01T00:00:00Z

# 3. start the daemon
signerd run --keystore ~/.config/signerd/ops.key --passphrase-file ~/.config/signerd/pass \
            --grants ~/.config/signerd/grants.json \
            --ledger ~/.local/share/signerd/journal.jsonl \
            --socket ~/.local/share/signerd/signerd.sock
```

Then clients ask the daemon to sign with `signerd sign` or
`signerd sign-message`, giving a grant name and the transaction bytes, never a
key. Add `--dry` to see the decision without signing or spending any budget.
To revoke a scope:

```bash
signerd grant-remove --grants ~/.config/signerd/grants.json --name ops-24h
```

For a transfer that could actually land, the blockhash has to be fresh. The
package ships `@solana/web3.js`, and current versions return the hash directly:

```bash
BLOCKHASH=$(node -e "new (require('@solana/web3.js').Connection)('https://api.mainnet-beta.solana.com').getLatestBlockhash('finalized').then(r=>console.log(r.blockhash))")
signerd build-tx --keystore ~/.config/signerd/ops.key \
            --to So11111111111111111111111111111111111111112 \
            --lamports 42 --out tx.bin --blockhash "$BLOCKHASH"
signerd sign --socket ~/.local/share/signerd/signerd.sock --grant ops-24h --tx tx.bin
```

The default blockhash is only a placeholder for exercising the daemon. It will
not confirm on chain, and the fee payer still needs SOL. signerd itself stays
offline: that fetch runs in your shell.

From Node, the client that ships today is `signViaDaemon`. A refusal comes back
as data, not an exception:

```js
const { buildTransferWire, signViaDaemon } = require('signerd/src/client.js');

const wire = buildTransferWire({
  fromPubkey,     // the fee payer's PUBLIC key — no secret crosses this line
  toPubkey,
  lamports: 42,
  blockhash,
});
const answer = await signViaDaemon({ socketPath, grant: 'ops-24h', wire });
if (answer.ok) {
  const signedWire = Buffer.from(answer.signed, 'base64');
} else {
  console.log(answer.error);   // e.g. 'alt', 'version_or_alt', 'window_cap'
}
```

Already have a key? `signerd import` encrypts an existing `id.json` and leaves
the original untouched. To replace a keystore on purpose, add `--overwrite`
(the old key is gone afterwards). The complete walkthrough, including signing
and the refusal ladder, is in
[docs/GUIDE.md](https://github.com/auroraxo/signerd/blob/main/docs/GUIDE.md).

### Sealed mode (optional)

```bash
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
```

A sealed grant file is rewritten only by the CLI: `grant-add --append` and
`grant-remove` re-seal it as part of the act (they need
`--seal-passphrase-file`). Hand-editing a sealed file breaks its seal and the
daemon then refuses the file (`grant_file_seal_mismatch`).

## What it will and will not sign

signerd signs only what it can fully decide offline, and refuses everything
else with a machine-readable reason (`{refused: "alt", ...}`).

| Signs (v1) | Refuses |
|---|---|
| System transfers, Memo, ComputeBudget | Address lookup tables |
| SPL Token `Transfer` / `TransferChecked` on allowlisted mints and destinations | Programs that can call other programs (Whirlpool, Jupiter, ...) |
| Within per-transaction and rolling-window caps | Token-2022, authority changes (`Approve`, `SetAuthority`, `CloseAccount`, ...) |

Measured on 2,835 finalized mainnet transactions, the current envelope covers
roughly 7 in 100 of them. That is a deliberate trade: it signs a narrow set
with certainty instead of a wide set with guesses.

## Good to know

- Everything is local: a Unix socket, an encrypted keystore (scrypt +
  AES-256-GCM), an append-only journal. No network service.
- Grant files are checked on load: owner, mode, schema, seal. A grant that could
  never sign (past expiry, cap below the base fee) is refused at creation.
- Refusals name the flag and the fix instead of failing silently.
- Exit codes are part of the contract, including "signed but could not deliver".

## Prior art

The npm name `@zanii/signerd` already exists, and it is a different product.
Measured with `node tools/measure-prior-art-delta.mjs` (report:
`research/prior-art-delta-2026-11-03.json`): the other package
matches **0/6 terms, 0 occurrences** of this project's signing-domain
vocabulary, while this package has **132 occurrences** of it. The other
package had 269 downloads last week. Verdict:
**`prior-art-distinct-domain`**. Sharing a name is not sharing a design.

## Learn more

- [docs/GUIDE.md](https://github.com/auroraxo/signerd/blob/main/docs/GUIDE.md): the full walkthrough
- [Engineering record](https://github.com/auroraxo/signerd/blob/main/docs/README-full-history-2026-11-13.md):
  reviews, measurements, defects found and fixed
- [research/](https://github.com/auroraxo/signerd/tree/main/research): raw measurement artifacts behind every number

Issues and questions are welcome.

## License

MIT, see [LICENSE](https://github.com/auroraxo/signerd/blob/main/LICENSE).
