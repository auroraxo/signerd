#!/usr/bin/env node
'use strict';

/**
 * user-zero client: signs a SOL transfer WITHOUT holding a key.
 *
 * This is the shape signerd exists for. A process that needs to move SOL used
 * to do this:
 *
 *     const keypair = Keypair.fromSecretKey(new Uint8Array(JSON.parse(
 *         fs.readFileSync(keypairPath, 'utf8'))));
 *     tx.sign(keypair);                      // the secret is now in THIS process
 *
 * Here the client only ever holds the fee payer's PUBLIC key, the grant name
 * and the socket path. It builds the unsigned wire, hands it over the socket,
 * and gets back a signed transaction. The secret key is never read, never
 * parsed, and never enters this process.
 *
 * Usage:
 *   node examples/user-zero-client.js \
 *     --socket <sock> --grant <name> --from <pubkey> --to <pubkey> \
 *     --lamports 42 --blockhash <base58-32> --out <signed-file> [--hold]
 *
 * --hold keeps the process alive with the signed wire in memory until stdin
 * closes, so a parent can scan this process's memory. That is what turns
 * "the client holds no key" from a claim into a measurement.
 */

const fs = require('node:fs');
const { buildTransferWire, signViaDaemon } = require('../src/client');

const USAGE = `user-zero client — asks signerd to sign; never holds a key

  --socket <path>      signerd Unix socket (required)
  --grant <name>       grant name to sign under (required)
  --from <pubkey>      fee payer PUBLIC key (required)
  --to <pubkey>        destination (required)
  --lamports <n>       amount (required)
  --blockhash <b58>    recent blockhash, 32 bytes base58 (required)
  --out <file>         write the signed transaction bytes here (optional)
  --hold               wait for stdin EOF before exiting (memory scan)
`;

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) args[key] = true;
    else { args[key] = next; i += 1; }
  }
  return args;
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || value.length === 0) {
    process.stderr.write(`missing --${name}\n\n${USAGE}`);
    process.exit(2);
  }
  return value;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const socketPath = requireArg(args, 'socket');
  const grant = requireArg(args, 'grant');
  const from = requireArg(args, 'from');
  const to = requireArg(args, 'to');
  const blockhash = requireArg(args, 'blockhash');
  const lamports = Number(requireArg(args, 'lamports'));
  if (!Number.isSafeInteger(lamports) || lamports < 0) {
    process.stderr.write('--lamports must be a non-negative integer\n');
    process.exit(2);
  }

  // Only public values are read: the fee payer's public key, the destination,
  // the amount, the blockhash. There is no key file here to open.
  const wire = buildTransferWire({ fromPubkey: from, toPubkey: to, lamports, blockhash });
  const response = await signViaDaemon({ socketPath, grant, wire });

  if (!response.ok) {
    // A refusal is the normal answer outside the grant's scope. Report it and
    // leave nothing behind: no signature, no partial file.
    process.stdout.write(JSON.stringify({ ok: false, error: response.error, detail: response.detail || null }) + '\n');
    process.exit(1);
  }

  const signed = Buffer.from(response.signed, 'base64');
  if (typeof args.out === 'string') fs.writeFileSync(args.out, signed, { mode: 0o600 });

  process.stdout.write(JSON.stringify({
    ok: true,
    signature: response.signature,
    amountLamports: response.amountLamports,
    feeLamports: response.feeLamports,
    seq: response.seq,
    signedBytes: signed.length,
    out: typeof args.out === 'string' ? args.out : null,
  }) + '\n');

  if (args.hold === true) {
    process.stdout.write('READY_TO_SCAN\n');
    // Stay alive until the parent closes stdin, so a memory scan sees the
    // same process that just performed the signing.
    await new Promise((resolve) => {
      process.stdin.on('close', resolve);
      process.stdin.resume();
      setTimeout(resolve, 60_000);
    });
  }
}

main().catch((err) => {
  process.stderr.write(`${err.code || 'error'}: ${err.message}\n`);
  process.exit(1);
});
