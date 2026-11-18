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
const bs58 = require('bs58');

class BuildTxError extends Error {
  constructor(code, message, fix) {
    super(message);
    this.name = 'BuildTxError';
    this.code = code;
    // The repair travels WITH the refusal: the CLI prints it verbatim, so
    // no caller has to invent wording for a code it has never seen (the
    // same shape src/refusal-voice.js gives the daemon's verdicts).
    if (typeof fix === 'string' && fix.length > 0) this.fix = fix;
  }
}

function requirePublicKeyString(value, flag) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new BuildTxError('missing_argument', `build-tx needs ${flag}`);
  }
  return value;
}

/**
 * A base58 string that decodes to EXACTLY 32 bytes - the shape both
 * --to (an Ed25519 public key) and --blockhash (a 32-byte hash) must have.
 *
 * WHY (measured 2026-11-18, tools/measure-buildtx-input-voice.js, on the
 * PUBLISHED v0.2.36): with no local check, a value the operator mistyped
 * reached web3.js and came back as the LIBRARY's prose with a fix line
 * that echoed it:
 *
 *   --to not-a-key!        -> wire_build_failed: build-tx: Non-base58 character
 *                             fix: build-tx: Non-base58 character
 *   --to <31-byte key>     -> wire_build_failed: build-tx: Invalid public key input
 *   --blockhash nonsense!  -> wire_build_failed: build-tx: Non-base58 character
 *   --blockhash <31-byte>  -> wire_build_failed: build-tx: Blob.encode[recentBlockhash]
 *                             requires (length 32) Uint8Array as src
 *
 * Every face: the same code for two different flags, a third-party message,
 * and a `fix:` line that restates the error in the same words - no flag
 * named, nothing to do. The file-input half of this command already had
 * the named voice (keystore_unreadable, out-preflight); the VALUE half
 * spoke a foreign language. grant-add judges the same shape with the
 * same words (grant_field_invalid: "a base58 Ed25519 public key of
 * exactly 32 bytes"), so build-tx now refuses its own inputs the same way
 * BEFORE the wire builder runs: the flag is named, the shape is stated,
 * and nothing third-party reaches the operator.
 *
 * The DECODE itself is done with the project's own bs58 dependency - the
 * same package web3.js uses underneath - so the acceptance rule cannot
 * drift between this check and the wire builder.
 */
function requireBase58_32(value, flag) {
  requirePublicKeyString(value, flag);
  let raw;
  try {
    raw = bs58.decode(value);
  } catch {
    throw new BuildTxError('invalid_key_argument',
      `build-tx: ${flag} must be base58 (got a character base58 does not know)`,
      `pass ${flag} as a base58 value - ${flag} <pubkey-or-blockhash>   ` +
      '# base58 knows no 0, O, I or l; copy the value instead of retyping it');
  }
  if (raw.length !== 32) {
    throw new BuildTxError('invalid_key_argument',
      `build-tx: ${flag} must decode to exactly 32 bytes (got ${raw.length})`,
      `pass ${flag} as base58 of a 32-byte value - ${flag} <pubkey-or-blockhash>   ` +
      '# a truncated or padded value decodes, but is not one this product can build with');
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
    // This is now the RESIDUAL class: --to/--blockhash/--lamports were
    // already judged above, so a failure here means the wire builder itself
    // rejected a well-formed value (or an internal helper broke). It still
    // must not hand the operator the library's sentence as its own repair -
    // it gets the command that rebuilds the file.
    throw new BuildTxError('wire_build_failed',
      `build-tx: the wire could not be built: ${err && err.message ? err.message : String(err)}`,
      'rebuild the file from the values you know are right: ' +
      'signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>');
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
  // Judge the values BEFORE web3.js sees them: a mistyped --to or
  // --blockhash is refused by name with the flag named, not as
  // wire_build_failed with the library's prose (measured, see
  // requireBase58_32 above).
  const toPubkey = requireBase58_32(to, '--to');
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
  const bh = isPlaceholder ? Keypair.generate().publicKey.toBase58()
    : requireBase58_32(blockhash, '--blockhash');

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
