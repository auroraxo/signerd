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
 *     --lamports 42 --blockhash <base58-32> --out <signed-file> [--hold] [--dry]
 *
 * --dry asks for the VERDICT without a signature: the daemon runs the same
 * policy and the same budget decision, signs nothing and journals nothing,
 * and the client writes no --out file. The identical request can then still
 * be signed for real - test/user-zero-client-surface.test.js falsifies that
 * (U6: an allowed dry run leaves the machine untouched).
 *
 * The flag surface is the daemon's, reused: unknown flags, a flag given
 * twice, a value flag with no value and a switch given a value are refused
 * BEFORE anything is requested. Measured 2026-11-07, before that, the client
 * dropped them: --dry was answered with a REAL signature.
 *
 * --hold keeps the process alive with the signed wire in memory until stdin
 * closes, so a parent can scan this process's memory. That is what turns
 * "the client holds no key" from a claim into a measurement.
 */

const fs = require('node:fs');
const { buildTransferWire, signViaDaemon } = require('../src/client');
const {
  parseTokens, arityProblemsFor, checkFlagsFor, closestFlag,
  CLIENT_FLAGS, CLIENT_SWITCH_FLAGS,
} = require('../src/cli-flags');

const USAGE = `user-zero client — asks signerd to sign; never holds a key

  --socket <path>      signerd Unix socket (required)
  --grant <name>       grant name to sign under (required)
  --from <pubkey>      fee payer PUBLIC key (required)
  --to <pubkey>        destination (required)
  --lamports <n>       amount (required)
  --blockhash <b58>    recent blockhash, 32 bytes base58 (required)
  --out <file>         write the signed transaction bytes here (optional)
  --dry                ask for the verdict only: no signature, no journal, no --out
  --hold               wait for stdin EOF before exiting (memory scan)
`;

/**
 * The refusal the flag surface produces, in the daemon CLI's shape: a
 * machine-readable reason, a `fix:` line naming the repair, exit 2. The
 * refusal happens BEFORE anything is requested - no wire is built, no
 * socket is touched.
 */
function refuse(problem) {
  if (problem.code === 'unknown_flag') {
    const suggestion = closestFlag(problem.flag, problem.supported);
    process.stderr.write(`unknown_flag: --${problem.flag}\n` +
      `  fix: the client does not take --${problem.flag}` +
      `${suggestion === null ? '' : ` - did you mean --${suggestion}?`}\n` +
      `  fix: the client takes: ${problem.supported.map((f) => `--${f}`).join(' ')}\n`);
    process.exit(2);
  }
  if (problem.code === 'unknown_argument') {
    process.stderr.write(`unknown_argument: ${problem.argument}\n` +
      `  fix: the client takes flags only, not positional arguments\n`);
    process.exit(2);
  }
  if (problem.code === 'duplicate_flag') {
    process.stderr.write(`duplicate_flag: --${problem.flag}\n` +
      `  fix: give --${problem.flag} once   # it was given twice: ` +
      `${JSON.stringify(problem.first)} and ${JSON.stringify(problem.second)}\n` +
      `  fix: the client cannot know which one you meant, and ` +
      `silently taking the last one changes what is signed\n`);
    process.exit(2);
  }
  if (problem.code === 'missing_value') {
    process.stderr.write(`missing_value: --${problem.flag}\n` +
      `  fix: give --${problem.flag} its value   # a flag without a value ` +
      `reads as absent, and an absent flag changes what is signed\n` +
      `  fix: see \`user-zero-client\` usage above\n`);
    process.exit(2);
  }
  if (problem.code === 'flag_takes_no_value') {
    process.stderr.write(`flag_takes_no_value: --${problem.flag}\n` +
      `  fix: give --${problem.flag} alone   # it is a switch and takes no ` +
      `value, but it was given ${JSON.stringify(problem.value)}\n` +
      `  fix: see \`user-zero-client\` usage above\n`);
    process.exit(2);
  }
  process.exit(2);
}

function parseArgs(argv) {
  // The same token walk and the same two rules as bin/signerd.js: the
  // surface (is this flag MINE?) and the arity (was it used the way you
  // typed it?). A map cannot express "given twice", "given without a value"
  // or "a switch given a value" - it can only hold one value per key, which
  // is exactly why those shapes used to vanish without a word here.
  const { args, raw } = parseTokens(argv);
  const surface = checkFlagsFor(CLIENT_FLAGS, args, args._);
  if (!surface.ok) refuse(surface);
  const problems = arityProblemsFor(CLIENT_FLAGS, CLIENT_SWITCH_FLAGS, raw);
  if (problems.length > 0) refuse(problems[0]);
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
  const response = await signViaDaemon({
    socketPath, grant, wire, dry: args.dry === true ? true : undefined,
  });

  if (response.ok && response.dry === true) {
    // A dry run answers with the VERDICT and writes nothing: no signature,
    // no --out file, no journal record, no window spend. Reporting it in
    // the same JSON shape keeps the output one-line parseable, and `dry:true`
    // makes it impossible to mistake a preview for a signature.
    process.stdout.write(JSON.stringify({
      ok: true, dry: true, allowed: true,
      amountLamports: response.amountLamports,
      feeLamports: response.feeLamports,
      wireSha256: response.wireSha256,
      windowRemainingLamports: response.windowRemainingLamports,
      out: null,
    }) + '\n');
    return;
  }

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
