'use strict';

// Building the UNSIGNED transaction file the documented quickstart's
// `signerd sign --tx tx.bin` step reads.
//
// WHY (measured 2026-11-05): the README Shape block ended with
// `signerd sign --socket ... --grant ops-24h --tx tx.bin`, and NO documented
// step ever created tx.bin — the stranger dead-ended on a bare
// `ENOENT: no such file or directory, open 'tx.bin'`. The old end-to-end
// test missed it because its harness wrote tx.bin itself, the same pattern
// that hid the grant-file dead end (see test/quickstart-grantfile.test.js).
//
// WHAT THIS DOES AND DOES NOT DO:
//   * It reads only the keystore's PUBLIC metadata field (readKeystorePublicKey
//     reads that one cleartext field; no passphrase, no secret, no key material).
//     The fee payer is therefore the PUBLIC key — the caller still holds no
//     secret. This is the same property examples/user-zero-client.js has.
//   * The default blockhash is a RANDOM PLACEHOLDER: it makes the documented
//     chain runnable end to end (the daemon checks the envelope, signs, and
//     the result verifies) but the transaction will NOT confirm on chain.
//     A real transfer needs a fresh getLatestBlockhash value, passed with
//     --blockhash. The command says so in its own output; it does not
//     pretend the placeholder is usable.
//   * Nothing is signed here. Signing stays in the daemon, behind the grant.
//
// The wire is built with the product's own client helper (buildTransferWire),
// so the documented quickstart and the shipped API produce the same bytes.

const { buildTransferWire } = require('./client');
const { readKeystorePublicKey } = require('./keystore');
const { Keypair } = require('@solana/web3.js');

class BuildTxError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BuildTxError';
    this.code = code;
  }
}

function requirePublicKeyString(value, flag) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new BuildTxError('missing_argument', `build-tx needs ${flag}`);
  }
  return value;
}

function parseLamports(raw) {
  const s = typeof raw === 'string' ? raw.trim() : raw;
  // Only a plain non-negative integer: 'forty-two', '1e3', '42.5', '-1' and
  // ' 42 ' are refused rather than silently coerced. The amount reaches a
  // value comparison in the daemon, so a sloppy parse here would be a
  // scope bug, not a convenience.
  if (typeof s !== 'string' || !/^\d+$/.test(s)) {
    throw new BuildTxError('invalid_lamports',
      `build-tx needs --lamports as a non-negative integer (got ${JSON.stringify(raw)})`);
  }
  const n = Number(s);
  if (!Number.isSafeInteger(n)) {
    throw new BuildTxError('invalid_lamports', 'build-tx: --lamports is out of the safe integer range');
  }
  return n;
}

/**
 * Build the unsigned wire for a transfer.
 *
 * fromPubkey: the fee payer's public key (string)
 * toPubkey:   destination public key (string)
 * lamports:   integer amount
 * blockhash:  base58-32 recent blockhash (string)
 */
function buildTransferWireBytes({ fromPubkey, toPubkey, lamports, blockhash }) {
  try {
    return buildTransferWire({ fromPubkey, toPubkey, lamports, blockhash });
  } catch (err) {
    throw new BuildTxError('wire_build_failed', `build-tx: ${err && err.message ? err.message : String(err)}`);
  }
}

/**
 * Create the transaction file for the documented `sign --tx` step.
 *
 * Returns { ok, out, bytes, from, to, lamports, blockhash, placeholder }.
 * Throws BuildTxError with a machine-readable code; the caller maps it to
 * the refusal message (repair named, like every other refusal).
 */
function buildTxFile({
  keystorePath,
  to,
  lamports,
  out,
  blockhash,
  fsModule,
}) {
  const fsx = fsModule || require('node:fs');

  requirePublicKeyString(keystorePath, '--keystore');
  const toPubkey = requirePublicKeyString(to, '--to');
  const amount = parseLamports(lamports);
  requirePublicKeyString(out, '--out');

  let fromPubkey;
  try {
    fromPubkey = readKeystorePublicKey({ file: keystorePath });
  } catch (err) {
    throw new BuildTxError('keystore_unreadable',
      `build-tx: cannot read the keystore's public key at ${keystorePath}: ${err && err.message ? err.message : String(err)}`);
  }

  const isPlaceholder = typeof blockhash !== 'string' || blockhash.length === 0;
  const bh = isPlaceholder ? Keypair.generate().publicKey.toBase58() : blockhash;

  const wire = buildTransferWireBytes({
    fromPubkey, toPubkey, lamports: amount, blockhash: bh,
  });

  // Atomic: a failed write must not leave a truncated or half-built wire at
  // `out`, and the result lands owner-only regardless of the mode the target
  // had before (writeFileSync's mode only applies on create).
  const delivery = require('./out-preflight').writeOutAtomic(out, wire);
  if (!delivery.ok) {
    const err = new BuildTxError(delivery.code, delivery.message);
    throw err;
  }

  return {
    ok: true,
    out,
    bytes: wire.length,
    from: fromPubkey,
    to: toPubkey,
    lamports: amount,
    blockhash: bh,
    placeholder: isPlaceholder,
  };
}

module.exports = {
  BuildTxError,
  buildTxFile,
  buildTransferWireBytes,
  parseLamports,
};
