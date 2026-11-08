#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { checkFlags, closestFlag, parseArgv } = require('../src/cli-flags');
const { checkOutWritable, outPreflightFix, writeOutAtomic, outWriteFix } = require('../src/out-preflight');
const { deliverRecovery, deliverResponse } = require('../src/recovery');
const { writeStderrSync } = require('../src/stdout');
// Strip the leading `${code}: ` from a `fail()` message so a refusal prints
// its code EXACTLY ONCE (measured doubled on 2026-11-07, see src/lease.js).
const { detailOf } = require('../src/lease');

/**
 * Refuse an unwritable --out BEFORE anything is read, requested or signed.
 *
 * Measured 2026-11-07 (pre-fix aebe5f9): `sign --out <missing-dir>/x.bin`
 * had the daemon SIGN first (journal written, budget charged, replay
 * identity recorded) and only then crash in fs.writeFileSync with a bare
 * ENOENT — the signature was thrown away, and every retry with a corrected
 * --out was refused `replay`. Same for sign-message, the example client,
 * build-tx and seal-grants. Refusing before the round trip keeps the spend
 * and the replay set untouched, so the operator's fix actually works.
 */
function requireWritableOut(outPath) {
  const check = checkOutWritable(outPath);
  if (check.ok) return;
  const fix = outPreflightFix(check);
  process.stderr.write(`${check.code}: ${check.message}\n${fix}\n`);
  process.exit(2);
}

const USAGE = `signerd — scoped signing daemon for Solana (early prototype)

Usage:
  signerd keygen --keystore <file>            create an encrypted keystore
  signerd grant-add --grants <file> --name <grant>
            (--signer <pubkey> | --keystore <file>) --destination <pubkey>
            --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>
            [--append] [--seal-passphrase-file <file>]
            create the grant file run expects (0600); refuses to clobber
            an existing or sealed file; --append adds the grant to an
            existing file instead (one scope per grant, map stays valid,
            atomic write; a SEALED file is never rewritten - re-seal after
            a hand edit); with --keystore the signer is read
            from the keystore's PUBLIC key (no passphrase needed)
  signerd grant-remove --grants <file> --name <grant> [--seal-passphrase-file <file>]
            remove ONE grant from an existing grant file (the revocation
            path): the loader judges the file first (directory, lease,
            owner, mode, schema, seal), the write is atomic (temp+rename),
            and the removal takes effect on the daemon's NEXT request — no
            restart, no signal. An unknown --name changes NOTHING and the
            refusal names the grants that are in the file. A SEALED file is
            re-sealed as part of the act and needs --seal-passphrase-file
  signerd build-tx --keystore <file> --to <pubkey> --lamports <u64> --out <file>
            [--blockhash <b58-32>]
            build the UNSIGNED transaction file the documented 'sign --tx'
            step reads. Uses only the keystore's PUBLIC key (no passphrase,
            no secret); the file is written 0600. Without --blockhash a
            random placeholder blockhash is used: fine to exercise the
            daemon, it will NOT confirm on chain — pass a fresh
            getLatestBlockhash value for a real transfer.
  signerd import --keystore <file> --from <secret-file> [--overwrite]
            encrypt an EXISTING plaintext key (id.json / base58 / raw 64 bytes);
            refuses an existing keystore unless --overwrite replaces it
            (the old key is gone afterwards)
  signerd run --keystore <file> --passphrase-file <file>
            --grants <file> --ledger <file> --socket <file>
            [--grant-seal-passphrase-file <file>]
            [--journal-seal-passphrase-file <file>]
  signerd sign --socket <file> --grant <name> --tx <wire-file> [--out <file>] [--dry]
  signerd sign-message --socket <file> --grant <name> --body <json-file> [--out <file>] [--dry]
            [--add-grant --keystore <file>]  create the message grant for <name>
            from the body (issuer/type/subject) pinning the PUBLIC key recorded
            in <keystore>, if the grant file lacks it, then sign; the grant
            file (--grants, default: next to the keystore) is created if missing
            ask the daemon to sign an openreceipts/v1 receipt BODY (the
            message-grant envelope): the daemon canonicalizes, checks the
            grant and writes {receipt..., pubkey, sig} with the DAEMON's key
  signerd status --grants <file> --ledger <file>
            [--grant-seal-passphrase-file <file>]
            [--journal-seal-passphrase-file <file>]
  signerd seal-grants --grants <file> --seal-passphrase-file <file> [--out <file>]
            add/replace the HMAC seal of a grant file (provenance, R5-2)
  signerd verify-grants --grants <file> --seal-passphrase-file <file>
            check a grant file's seal without touching the journal
  signerd seal-journal --journal <file> --journal-seal-passphrase-file <file>
            verify the journal's chain, then seal it (provenance, R5-2):
            every record gets a keyed chain MAC and a seal floor <journal>.anchor
            records how much history the daemon approved; refused while a
            daemon holds the journal lock; prints exactly what it sealed
  signerd migrate --ledger <file> (--wires <dir> | --discard-legacy)
            upgrade a format-1 journal; --wires restores message-level replay
            protection, --discard-legacy explicitly accepts losing it

Notes:
  --passphrase-file must be mode 0600 and is read once at startup.
  --grant-seal-passphrase-file turns on sealed-grant mode: the daemon then
  REFUSES a grant file whose HMAC seal does not verify (an unsealed or
  altered file cannot be used to have the daemon sign).
  --journal-seal-passphrase-file turns on sealed-journal mode the same way:
  without the key the daemon refuses a journal that was ever sealed, and a
  journal shorter than its seal floor (truncation) is refused with it.
  Every refusal is a machine-readable reason; nothing is signed outside the
  grant's scope. This is NOT a reviewed wallet or a production daemon.
`;

function parseArgs(argv) {
  // The ARITY rule (measured 2026-11-07) needs the TOKENS, not just the
  // map: a map cannot express "given twice", "given without a value" or
  // "a switch given a value" - it can only hold one value per key, which is
  // exactly why all three shapes used to vanish without a word.
  //
  // The problems are returned SEPARATELY, never as a key of `args`: the
  // flag surface iterates the keys of `args`, and a bookkeeping key would
  // be reported as an unknown flag. (First attempt did exactly that - G4
  // caught it: `unknown_flag: --_problems`.)
  return parseArgv(argv);
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || value.length === 0) {
    process.stderr.write(`missing --${name}\n${USAGE}`);
    process.exit(2);
  }
  return value;
}

// R6-6 (review #6, p6): the passphrase path had a mode check on statSync only
// - no symlink refusal (a symlink here was followed), no owner check, no
// directory check. Every other security-relevant path in this codebase
// (keystore, grant file, journal, anchor, socket dir) refuses symlinks and
// foreign/world-writable locations; the passphrase unlocks those very
// protections and deserves the same hygiene. Checks run BEFORE the read; a
// race after them is the same residual window every other path here has.
function readPassphrase(args, flag = 'passphrase-file') {
  if (typeof args[flag] !== 'string') {
    process.stderr.write(`missing --${flag}\n`);
    process.exit(2);
  }
  const file = requireArg(args, flag);
  const lstat = fs.lstatSync(file); // a symlink at this path is refused (ELOOP)
  if (!lstat.isFile()) {
    process.stderr.write(`${flag} must be a regular file\n`);
    process.exit(2);
  }
  const mode = lstat.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    // Name the repair, not just the verdict. The passphrase file is the one
    // secret an operator creates by hand (the README says: write it), and
    // under the common desktop umask 0002 `printf > pass` yields 0664 - so
    // this refusal was the first thing a stranger hit, with no way to guess
    // the fix. The rule stays fail-closed; the message now carries the
    // command that repairs it.
    process.stderr.write(
      `${flag} must not be group/other accessible (mode ${mode.toString(8)})\n` +
      `  fix: chmod 600 ${file}   # the passphrase file is a secret; keep it owner-only\n`);
    process.exit(2);
  }
  if (typeof process.getuid === 'function' &&
      lstat.uid !== process.getuid() && lstat.uid !== 0) {
    process.stderr.write(`${flag} must be owned by the operator (uid ${lstat.uid})\n`);
    process.exit(2);
  }
  const dirStat = fs.statSync(path.dirname(path.resolve(file)));
  const dirMode = dirStat.mode & 0o7777;
  if ((dirMode & 0o022) !== 0 && (dirMode & 0o1000) === 0) {
    process.stderr.write(
      `${flag} must not live in a group/other writable directory (mode ${dirMode.toString(8)})\n` +
      `  fix: chmod 700 ${path.dirname(path.resolve(file))}   # a stranger could replace the file there\n`);
    process.exit(2);
  }
  if (typeof process.getuid === 'function' &&
      dirStat.uid !== process.getuid() && dirStat.uid !== 0) {
    process.stderr.write(`${flag} directory must be owned by the operator (uid ${dirStat.uid})\n`);
    process.exit(2);
  }
  return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, '');
}

async function main() {
  const { args, problems } = parseArgs(process.argv.slice(2));
  const command = args._[0];

  // THE FLAG SURFACE (measured 2026-11-06): a flag the operator set used to
  // be dropped without a word. For `--grant-seal-passphrasefile` (typo: no
  // dash) the daemon then STARTED on a sealed-and-tampered grant file
  // (reporting {"ok":true}) where the correct flag refuses with
  // grant_file_seal_mismatch - one missing dash turned sealed mode off.
  // Refuse BEFORE anything is read, written or started. An unknown COMMAND
  // keeps the usage banner below (measure-documented-flags.mjs reads it).
  const verdict = checkFlags(command, args, args._);
  if (!verdict.ok) {
    if (verdict.code === 'unknown_flag') {
      const suggestion = closestFlag(verdict.flag, verdict.supported);
      process.stderr.write(`unknown_flag: --${verdict.flag}\n` +
        `  fix: signerd ${command} does not take --${verdict.flag}` +
        `${suggestion === null ? '' : ` - did you mean --${suggestion}?`}\n` +
        `  fix: signerd ${command} takes: ${verdict.supported.map((f) => `--${f}`).join(' ')}\n`);
      process.exit(2);
    }
    process.stderr.write(`unknown_argument: ${verdict.argument}\n` +
      `  fix: signerd ${command} takes flags, not positional arguments ` +
      `(it ignores nothing: check the flag name above its value)\n`);
    process.exit(2);
  }

  // THE FLAG ARITY SURFACE (measured 2026-11-07, live, pre-fix tree 6ff287d).
  // The flag surface above answers "is this flag KNOWN?". This answers "is
  // this flag USED the way you typed it?" - and the answer matters, because
  // the parser used to answer it by DROPPING what it could not express:
  //
  //   run --grants narrow.json --grants wide.json
  //     last wins silently. Measured: the daemon enforced wide.json and
  //     SIGNED 500005000 lamports that narrow.json (cap 1000) refuses with
  //     `amount`. The operator named narrow.json FIRST.
  //   run ... --grant-seal-passphrase-file      (path forgotten)
  //     `args[...] === true`, so sealed mode read as NOT SET. Measured on a
  //     sealed-and-tampered grant file: the correct flag refuses
  //     `grant_file_seal_mismatch`, the flag with no value let the daemon
  //     START and answer `{"ok":true}`.
  //   sign ... --dry true
  //     `args.dry` became the STRING "true", so the request went out as a
  //     REAL sign: exit 0, a real signature, 368 bytes appended to the
  //     journal, `--out` written.
  //
  // Refuse BEFORE anything is read, written or started, and name the
  // repair. The shape is the same as the flag surface above: a
  // machine-readable reason, a `fix:` line, exit 2.
  const arity = problems || [];
  if (arity.length > 0) {
    const p = arity[0];
    if (p.code === 'duplicate_flag') {
      process.stderr.write(`duplicate_flag: --${p.flag}\n` +
        `  fix: give --${p.flag} once   # it was given twice: ` +
        `${JSON.stringify(p.first)} and ${JSON.stringify(p.second)}\n` +
        `  fix: signerd ${command} cannot know which one you meant, and ` +
        `silently taking the last one changes what is enforced\n`);
      process.exit(2);
    }
    if (p.code === 'missing_value') {
      process.stderr.write(`missing_value: --${p.flag}\n` +
        `  fix: give --${p.flag} its value   # a flag without a value reads ` +
        `as absent, and an absent security flag turns a guarantee off\n` +
        `  fix: see \`signerd\` usage for the flags ${command} takes\n`);
      process.exit(2);
    }
    if (p.code === 'flag_takes_no_value') {
      process.stderr.write(`flag_takes_no_value: --${p.flag}\n` +
        `  fix: give --${p.flag} alone   # it is a switch and takes no value, ` +
        `but it was given ${JSON.stringify(p.value)}\n` +
        `  fix: see \`signerd\` usage for the flags ${command} takes\n`);
      process.exit(2);
    }
  }

  if (command === 'keygen') {
    const { createKeystore } = require('../src/keystore');
    const file = requireArg(args, 'keystore');
    const passphrase = readPassphrase(args);
    const out = createKeystore({ file, passphrase, overwrite: args.overwrite === true });
    process.stdout.write(JSON.stringify(out) + '\n');
    return;
  }

  if (command === 'import') {
    const { importKeystore } = require('../src/keystore');
    const file = requireArg(args, 'keystore');
    const from = requireArg(args, 'from');
    const passphrase = readPassphrase(args);
    try {
      const out = importKeystore({ file, passphrase, from, overwrite: args.overwrite === true });
      process.stdout.write(JSON.stringify(out) + '\n');
    } catch (err) {
      // Measured 2026-11-05 (the README block runs keygen and import into the
      // SAME --keystore path): the stranger's first contact with the migration
      // path was a self-referential verdict with no repair -
      // "keystore_exists: keystore_exists" - while the flag that actually
      // repairs it (--overwrite) was accepted by the CLI and documented
      // NOWHERE. Name the repair, same rule as the passphrase, grant-file and
      // tx-file refusals. The rule stays fail-closed: nothing is overwritten
      // without --overwrite, and a refused overwrite leaves the file intact
      // (validation-before-write, pinned in test/import-repair-surface.test.js).
      if (err && err.code === 'keystore_exists') {
        process.stderr.write(
          `keystore_exists: ${file} already holds a key\n` +
          `  fix: signerd import --keystore <other-file> --from ${from} ...   # adopt into a DIFFERENT keystore, or\n` +
          `  fix: add --overwrite   # replace ${file} with the imported key (the old key is gone)\n`);
        process.exit(1);
      }
      throw err;
    }
    return;
  }

  if (command === 'run') {
    const { Daemon } = require('../src/daemon');
    const sealPassphrase = typeof args['grant-seal-passphrase-file'] === 'string'
      ? readPassphrase(args, 'grant-seal-passphrase-file') : undefined;
    const journalSealPassphrase = typeof args['journal-seal-passphrase-file'] === 'string'
      ? readPassphrase(args, 'journal-seal-passphrase-file') : undefined;
    const daemon = new Daemon({
      socketPath: requireArg(args, 'socket'),
      keystorePath: requireArg(args, 'keystore'),
      passphrase: readPassphrase(args),
      grantFile: requireArg(args, 'grants'),
      ledgerFile: requireArg(args, 'ledger'),
      grantSealPassphrase: sealPassphrase,
      journalSealPassphrase,
    });
    await daemon.start();
    process.stdout.write(JSON.stringify({ ok: true, ...daemon.status() }) + '\n');
    const shutdown = async () => { await daemon.stop(); process.exit(0); };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  if (command === 'build-tx') {
    const { BuildTxError, buildTxFile } = require('../src/buildtx');
    try {
      // Preflight the destination before anything is read or built: a bare
      // ENOENT after a successful build tells the operator nothing they can
      // act on (P5).
      requireWritableOut(args.out);
      const built = buildTxFile({
        keystorePath: args.keystore,
        to: args.to,
        lamports: args.lamports,
        out: args.out,
        blockhash: typeof args.blockhash === 'string' ? args.blockhash : undefined,
      });
      process.stdout.write(JSON.stringify(built) + '\n');
      return;
    } catch (err) {
      if (err instanceof BuildTxError) {
        // Refusals name the repair (the passphrase/grant-file/tx-file rule).
        const fix = err.code === 'missing_argument'
          ? '  fix: see `signerd` usage — build-tx --keystore <file> --to <pubkey> --lamports <u64> --out <file>'
          : err.code === 'invalid_lamports'
            ? '  fix: pass a plain non-negative integer, e.g. --lamports 42'
            : err.code === 'keystore_unreadable'
              ? '  fix: point --keystore at a keystore created by `signerd keygen`'
              : `  fix: ${detailOf(err)}`;
        process.stderr.write(`${err.code}: ${detailOf(err)}\n${fix}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  if (command === 'sign') {
    const { request } = require('../src/daemon');
    const socketPath = requireArg(args, 'socket');
    const grant = requireArg(args, 'grant');
    const txPath = requireArg(args, 'tx');
    // Preflight BEFORE the round trip: a refusal here must leave the
    // journal, the budget and the replay set untouched (P1/P2).
    requireWritableOut(args.out);
    let wire;
    try {
      wire = fs.readFileSync(txPath);
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        // Measured 2026-11-05: the quickstart's `sign --tx tx.bin` step died
        // on a bare errno — tx.bin is never created by the documented steps.
        // Name the repair, same rule as the passphrase and grant-file refusals.
        process.stderr.write(
          `tx_missing: no transaction file at ${txPath}\n` +
          `  fix: signerd build-tx --keystore <file> --to <pubkey> ` +
          `--lamports <n> --out ${txPath}  (public key only, no passphrase)\n`);
        process.exit(2);
      }
      throw err;
    }
    const response = await request({ socketPath, grant, wire, dry: args.dry === true ? true : undefined });
    if (response.ok && !response.dry && typeof args.out === 'string') {
      // DELIVERY. The daemon has already signed: the budget is spent and the
      // replay identity is recorded. If the write fails now, the signature
      // must NOT die with it (measured live 2026-11-07: `ulimit -f 0` made
      // the write fail AFTER signing — exit 1, stdout empty, and the retry
      // permanently refused `replay`, so the operator paid for bytes they
      // could never get back).
      //
      // So: deliver atomically, and on failure exit 3 with the signed wire
      // ON STDOUT. Exit 3 means "the work happened, the file did not" — a
      // distinct state from a refusal (1) and from a usage error (2).
      const signed = Buffer.from(response.signed, 'base64');
      const delivery = writeOutAtomic(args.out, signed);
      if (!delivery.ok) {
        response.outError = {
          code: delivery.code,
          errno: delivery.errno,
          path: delivery.path,
          message: delivery.message,
        };
        // DELIVER THE RECOVERY, VERIFIED. Exit 3 promises "the artifact is
        // on stdout" — a promise only the checked write can keep
        // (src/recovery.js: measured 2026-11-08, the unchecked write made
        // exit 3 with 0 bytes on a file stdout under RLIMIT_FSIZE=0).
        const recovery = deliverRecovery({
          payload: JSON.stringify(response) + '\n',
          outPath: delivery.path,
          outError: delivery,
          subject: 'the signature',
          fixLine: outWriteFix(delivery),
        });
        writeStderrSync(recovery.stderr);
        process.exit(recovery.exitCode);
      }
      delete response.signed;
    }
    const answer = deliverResponse({
      payload: JSON.stringify(response) + '\n',
      // The artifact rides on stdout alone when there is no --out file to
      // carry it — but a --dry response has NO signature in it, so nothing
      // is lost there and the exit code must not claim otherwise.
      artifact: response.dry !== true && typeof args.out !== 'string',
      ok: response.ok === true,
      exitCode: response.ok ? 0 : 1,
    });
    if (answer.stderr) writeStderrSync(answer.stderr);
    process.exit(answer.exitCode);
  }

  if (command === 'grant-add') {
    const { writeGrantFile, buildTxGrant } = require('../src/grantadd');
    const { readKeystorePublicKey } = require('../src/keystore');
    const grants = requireArg(args, 'grants');
    const name = requireArg(args, 'name');
    // The signer is either stated explicitly or derived from the keystore's
    // PUBLIC key (cleartext metadata, no passphrase, no secret read). The
    // derivation is the quickstart path: the daemon refuses
    // grant_signer_mismatch, so deriving from the same keystore the daemon
    // runs makes the documented setup fail-proof without a paste step.
    if (typeof args.signer !== 'string' && typeof args.keystore !== 'string') {
      process.stderr.write(
        'grant-add needs --signer <pubkey> or --keystore <file> ' +
        '(the signer is read from the keystore\'s public key)\n');
      process.exit(2);
    }
    const signer = typeof args.signer === 'string'
      ? args.signer
      : readKeystorePublicKey({ file: requireArg(args, 'keystore') });
    // A seal passphrase that this path CANNOT honor must not be silently
    // dropped (measured 2026-11-06): without --append the file is created
    // fresh and UNSEALED, so `grant-add --seal-passphrase-file <file>` used
    // to report ok:true and write a file with no `seal` field at all - the
    // operator asked for a sealed file and got one the daemon in sealed mode
    // would refuse (grant_file_unsealed). The --append path already refuses
    // this same situation; one flag, one behaviour. Refuse, name the repair,
    // write nothing.
    if (typeof args['seal-passphrase-file'] === 'string' && args.append !== true) {
      process.stderr.write(
        `grant_file_unsealed: ${grants} carries no seal, but --seal-passphrase-file was given without --append\n` +
        `  fix: leave out --seal-passphrase-file   # create the file first, then seal it:\n` +
        `       signerd seal-grants --grants ${grants} --seal-passphrase-file ${args['seal-passphrase-file']}\n` +
        `  fix: add --append   # --append + --seal-passphrase-file extends AND re-seals an existing sealed file\n`);
      process.exit(1);
    }
    const grant = buildTxGrant({
      name,
      signer,
      destination: requireArg(args, 'destination'),
      maxLamports: requireArg(args, 'max-lamports'),
      windowMaxLamports: requireArg(args, 'window-max-lamports'),
      windowSeconds: requireArg(args, 'window-seconds'),
      expiresAt: requireArg(args, 'expires'),
    });
    // --append: add the grant to an EXISTING grant file instead of refusing
    // an existing file. Measured 2026-11-05 (live, the documented setup
    // order): a second `grant-add` against the first file died with the
    // self-referential verdict `grant_file_exists: <path>` - no repair
    // named, and NO way to create a second scope at all (the loader loads a
    // map of grants; the CLI could only create a one-grant file). The
    // repair this names must be one the CLI actually offers.
    if (args.append === true) {
      const { extendGrantFile } = require('../src/grantadd');
      try {
        const sealPassphrase = typeof args['seal-passphrase-file'] === 'string'
          ? readPassphrase(args, 'seal-passphrase-file') : undefined;
        const out = extendGrantFile({
          file: grants,
          name,
          grant,
          sealPassphrase,
        });
        process.stdout.write(JSON.stringify({ ok: true, ...out }) + '\n');
        return;
      } catch (err) {
        // Name the repair, not just the verdict (the passphrase/keystore/
        // import rule), and only repairs this CLI actually offers.
        if (err && err.code === 'grant_file_exists') {
          // TOCTOU: the file appeared between the lstat and the create.
          process.stderr.write(
            `grant_file_exists: ${grants} already exists\n` +
            `  fix: add --append   # add ${name} to the existing file (one scope per grant)\n` +
            `  fix: point --grants at another file   # a NEW file holds exactly this grant\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_exists') {
          process.stderr.write(
            `grant_exists: ${name} is already in ${grants}\n` +
            `  fix: choose another --name   # each grant is one scope; edit the file by hand to change one\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_file_sealed') {
          process.stderr.write(
            `grant_file_sealed: ${grants} carries an HMAC seal\n` +
            `  fix: edit the file by hand, then re-seal:\n` +
            `       signerd seal-grants --grants ${grants} --seal-passphrase-file <file>\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_file_unsealed') {
          process.stderr.write(
            `grant_file_unsealed: ${grants} carries no seal, but --seal-passphrase-file was given\n` +
            `  fix: leave out --seal-passphrase-file to append unsealed, or\n` +
            `  fix: signerd seal-grants --grants ${grants} --seal-passphrase-file <file>\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_file_symlink') {
          process.stderr.write(
            `grant_file_symlink: ${grants} is a symlink\n` +
            `  fix: point --grants at the real file, or remove the link   # a symlink is never followed here\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_file_mode') {
          process.stderr.write(
            `${err.code}: ${detailOf(err)}\n` +
            `  fix: chmod 600 ${grants}   # a grant file another user can write must not be extended\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_file_dir_mode') {
          process.stderr.write(
            `${err.code}: ${detailOf(err)}\n` +
            `  fix: chmod 700 ${path.dirname(path.resolve(grants))}   # a stranger could swap the file there\n`);
          process.exit(1);
        }
        if (err && err.code === 'grant_file_write_failed') {
          process.stderr.write(
            `${err.code}: ${err.detail || 'the atomic write failed'}\n` +
            `  fix: check the directory is writable and has space; the existing file is UNCHANGED\n`);
          process.exit(1);
        }
        throw err;
      }
    }
    try {
      const out = writeGrantFile({ file: grants, name, grant });
      process.stdout.write(JSON.stringify({ ok: true, ...out }) + '\n');
      return;
    } catch (err) {
      // THE MEASURED DEFECT (2026-11-05): the verdict `grant_file_exists:
      // <path>` named no repair. A second scope was impossible from the CLI:
      // the loader loads a MAP of grants, grant-add could only ever write a
      // one-grant file, and the README documents exactly one grant. The
      // repair is --append - a command this CLI actually offers.
      if (err && err.code === 'grant_file_exists') {
        process.stderr.write(
          `grant_file_exists: ${grants} already exists\n` +
          `  fix: add --append   # add ${name} to the existing file (one scope per grant)\n` +
          `  fix: point --grants at another file   # a NEW file holds exactly this grant\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_symlink') {
        process.stderr.write(
          `grant_file_symlink: ${grants} is a symlink\n` +
          `  fix: point --grants at the real file, or remove the link   # a symlink is never followed here\n`);
        process.exit(1);
      }
      // The create path refused with a bare errno (measured 2026-11-08:
      // `EACCES: permission denied, open '<path>'`) - no code, no repair.
      // The --append path already refused this code with a repair; the two
      // paths now refuse the same way.
      if (err && err.code === 'grant_file_write_failed') {
        process.stderr.write(
          `${err.code}: ${err.detail || 'the grant file could not be written'}\n` +
          `  fix: make the directory writable (chmod 700 $(dirname ${grants})) and retry\n` +
          `  fix: or point --grants at a file in a directory you own\n`);
        process.exit(1);
      }
      throw err;
    }
  }

  if (command === 'grant-remove') {
    const { removeGrantFromFile } = require('../src/grantadd');
    const grants = requireArg(args, 'grants');
    const name = requireArg(args, 'name');
    try {
      const sealPassphrase = typeof args['seal-passphrase-file'] === 'string'
        ? readPassphrase(args, 'seal-passphrase-file') : undefined;
      const out = removeGrantFromFile({ file: grants, name, sealPassphrase });
      process.stdout.write(JSON.stringify({ ok: true, ...out }) + '\n');
      return;
    } catch (err) {
      // Name the repair, not just the verdict (the same rule as
      // grant-add/passphrase/keystore/tx refusals).
      if (err && err.code === 'grant_not_found') {
        const listed = Array.isArray(err.grants) && err.grants.length > 0
          ? `in-file grants: ${err.grants.join(', ')}\n`
          : 'the file holds no grants\n';
        process.stderr.write(
          `grant_not_found: no grant named ${name} in ${grants}\n` +
          `  ${listed}` +
          `  fix: choose one of the in-file names with --name   # a removal removes the whole scope, by name\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_sealed') {
        process.stderr.write(
          `grant_file_sealed: ${grants} carries an HMAC seal\n` +
          `  fix: add --seal-passphrase-file <file>   # the removal re-seals the file for you\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_unsealed') {
        process.stderr.write(
          `grant_file_unsealed: ${grants} carries no seal, but --seal-passphrase-file was given\n` +
          `  fix: leave out --seal-passphrase-file to remove from an unsealed file, or\n` +
          `  fix: signerd seal-grants --grants ${grants} --seal-passphrase-file <file>\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_symlink') {
        process.stderr.write(
          `grant_file_symlink: ${grants} is a symlink\n` +
          `  fix: point --grants at the real file, or remove the link   # a symlink is never followed here\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_mode') {
        process.stderr.write(
          `${err.code}: ${detailOf(err)}\n` +
          `  fix: chmod 600 ${grants}   # a grant file another user can write must not be modified\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_dir_mode') {
        process.stderr.write(
          `${err.code}: ${detailOf(err)}\n` +
          `  fix: chmod 700 ${path.dirname(path.resolve(grants))}   # a stranger could swap the file there\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_unreadable') {
        process.stderr.write(
          `${err.code}: ${detailOf(err)}\n` +
          `  fix: nothing to remove — no grant file at ${grants}\n` +
          `  fix: signerd grant-add --grants ${grants} --name <grant> ...   # create one\n`);
        process.exit(1);
      }
      if (err && err.code === 'grant_file_write_failed') {
        process.stderr.write(
          `${err.code}: ${err.detail || 'the atomic write failed'}\n` +
          `  fix: check the directory is writable and has space; the existing file is UNCHANGED\n`);
        process.exit(1);
      }
      throw err;
    }
  }

  if (command === 'sign-message') {
    const { request } = require('../src/daemon');
    const socketPath = requireArg(args, 'socket');
    const grant = requireArg(args, 'grant');
    // Preflight BEFORE the socket round trip (P3): an unwritable --out must
    // not sign, journal, or charge rolling-window budget.
    requireWritableOut(args.out);
    const bodyText = fs.readFileSync(requireArg(args, 'body'), 'utf8');
    // Shape check BEFORE the round trip: the body must be a JSON object (a
    // bare number or string would only fail at the policy layer).
    try {
      const parsed = JSON.parse(bodyText);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        process.stderr.write('body_invalid: expected a JSON object\n');
        process.exit(2);
      }
    } catch {
      process.stderr.write('body_invalid: not JSON\n');
      process.exit(2);
    }
    // --add-grant: bootstrap the message grant this command needs, straight
    // from the body (issuer/type/subject) and the daemon key. Runs BEFORE the
    // socket round trip, so the documented message quickstart works without
    // knowing the grant schema. A grant that already exists under this name
    // is LEFT ALONE (the daemon judges it at request time); a sealed file is
    // never rewritten.
    if (args['add-grant'] === true) {
      const { readKeystorePublicKey } = require('../src/keystore');
      const { addGrantToFile, buildMessageGrant } = require('../src/grantadd');
      const bs58 = require('bs58');
      // The PUBLIC key is cleartext keystore metadata (the format's own
      // contract), so no passphrase is needed to bootstrap a grant that pins
      // it — and no secret is ever read here.
      const keystorePath = requireArg(args, 'keystore');
      const pubkeyB64 = Buffer.from(bs58.decode(readKeystorePublicKey({ file: keystorePath }))).toString('base64');
      const bodyObj = JSON.parse(bodyText);
      const claimKeys = bodyObj.claims !== null && typeof bodyObj.claims === 'object' &&
        !Array.isArray(bodyObj.claims) && Object.getOwnPropertyNames(bodyObj.claims).length > 0
        ? Object.getOwnPropertyNames(bodyObj.claims).sort().join(',')
        : undefined;
      const messageGrant = buildMessageGrant({
        name: grant,
        issuer: bodyObj.issuer,
        type: bodyObj.type,
        subject: bodyObj.subject,
        pubkey: pubkeyB64,
        // 700: the README's own example cap — a cap the operator can observe
        // engaging, not the envelope's hard ceiling; widen it in the file.
        maxBytes: '700',
        expiresAt: new Date(Date.now() + 24 * 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
        windowMaxMessages: '5',
        windowSeconds: '3600',
        claimKeys,
      });
      const grantsPath = typeof args.grants === 'string'
        ? args.grants
        : path.join(path.dirname(path.resolve(keystorePath)), 'grants.json');
      // Report on stderr: stdout stays a single-JSON response channel.
      // An EXISTING grant under this name is left alone (addGrantToFile
      // refuses to overwrite; a sealed file is refused, never rewritten).
      try {
        const added = addGrantToFile({ file: grantsPath, name: grant, grant: messageGrant });
        process.stderr.write(JSON.stringify({ ok: true, grantFile: added.file, grant: added.grant, bootstrapped: true }) + '\n');
      } catch (err) {
        if (err && err.code === 'grant_exists') {
          process.stderr.write(JSON.stringify({ ok: true, grantFile: grantsPath, grant, bootstrapped: false }) + '\n');
        } else {
          throw err;
        }
      }
    }
    const response = await request({ socketPath, grant, body: bodyText, dry: args.dry === true ? true : undefined });
    if (response.ok && !response.dry && typeof args.out === 'string') {
      // The receipt file, openreceipts-shaped: the body the daemon signed
      // (re-serialized with sorted keys, indent 2 - formatting is not
      // payload), plus pubkey and sig, exactly what `receipt.py verify` and
      // verify.mjs read.
      const bodyObj = JSON.parse(bodyText);
      const ordered = {};
      for (const key of Object.keys(bodyObj).sort()) ordered[key] = bodyObj[key];
      const doc = { receipt: ordered, pubkey: response.pubkey, sig: response.signature };
      // DELIVERY, same rule as `sign`: the receipt is already signed. If the
      // write fails, the receipt must survive on stdout (exit 3) instead of
      // dying with the budget that was already spent on it.
      const delivery = writeOutAtomic(args.out, Buffer.from(JSON.stringify(doc, null, 2) + '\n'));
      if (!delivery.ok) {
        response.receiptDoc = doc;
        response.outError = {
          code: delivery.code,
          errno: delivery.errno,
          path: delivery.path,
          message: delivery.message,
        };
        // Same verified recovery as `sign` (src/recovery.js): exit 3 only
        // when the receipt document is ACTUALLY on stdout.
        const recovery = deliverRecovery({
          payload: JSON.stringify(response) + '\n',
          outPath: delivery.path,
          outError: delivery,
          subject: 'the receipt',
          fixLine: outWriteFix(delivery),
        });
        writeStderrSync(recovery.stderr);
        process.exit(recovery.exitCode);
      }
    }
    const answer = deliverResponse({
      payload: JSON.stringify(response) + '\n',
      // No --out: the signature rides on stdout alone. A --dry response has
      // no signature, so it never counts as a lost artifact.
      artifact: response.dry !== true && typeof args.out !== 'string',
      ok: response.ok === true,
      exitCode: response.ok ? 0 : 1,
    });
    if (answer.stderr) writeStderrSync(answer.stderr);
    process.exit(answer.exitCode);
  }

  if (command === 'status') {
    const { loadGrantFile } = require('../src/grantfile');
    const { Ledger } = require('../src/ledger');
    const sealPassphrase = typeof args['grant-seal-passphrase-file'] === 'string'
      ? readPassphrase(args, 'grant-seal-passphrase-file') : undefined;
    const journalSealPassphrase = typeof args['journal-seal-passphrase-file'] === 'string'
      ? readPassphrase(args, 'journal-seal-passphrase-file') : undefined;
    const options = sealPassphrase === undefined ? {} : {
      sealKeyFor: require('../src/grantseal').makeSealKeyProvider(sealPassphrase),
    };
    const loaded = loadGrantFile(requireArg(args, 'grants'), options);
    const ledger = new Ledger({
      file: requireArg(args, 'ledger'),
      sealPassphrase: journalSealPassphrase,
    });
    process.stdout.write(JSON.stringify({
      ok: true, grants: loaded.names, ledger: ledger.snapshot(), legacyState: ledger.legacyState(),
      sealed: sealPassphrase !== undefined, journalSealed: journalSealPassphrase !== undefined,
    }) + '\n');
    return;
  }

  if (command === 'seal-journal') {
    const { sealExistingJournal } = require('../src/journalseal-ops');
    const result = sealExistingJournal({
      journalFile: requireArg(args, 'journal'),
      passphrase: readPassphrase(args, 'journal-seal-passphrase-file'),
    });
    process.stdout.write(JSON.stringify(result) + '\n');
    return;
  }

  if (command === 'seal-grants') {
    const { sealDocument } = require('../src/grantseal');
    const file = requireArg(args, 'grants');
    const passphrase = readPassphrase(args, 'seal-passphrase-file');
    const raw = fs.readFileSync(file, 'utf8');
    let doc;
    try {
      doc = JSON.parse(raw);
    } catch {
      process.stderr.write('grant_file_invalid: not JSON\n');
      process.exit(1);
    }
    if (doc === null || typeof doc !== 'object' || Array.isArray(doc) ||
        doc.version !== 1 || typeof doc.grants !== 'object' || doc.grants === null ||
        Array.isArray(doc.grants)) {
      process.stderr.write('grant_file_invalid: expected {version:1, grants:{...}}\n');
      process.exit(1);
    }
    const sealed = sealDocument(doc, passphrase);
    const out = typeof args.out === 'string' ? args.out : file;
    requireWritableOut(out);
    const delivery = writeOutAtomic(out, Buffer.from(JSON.stringify(sealed, null, 2) + '\n'));
    if (!delivery.ok) {
      process.stderr.write(`out_write_failed: cannot write sealed grants to ${out}: ${delivery.message}\n`);
      process.exit(1);
    }
    // The operator must see WHAT was sealed: sealing a forged file makes the
    // forgery valid, so the names and the caps are printed.
    const summary = Object.keys(sealed.grants).sort().map((name) => ({
      name,
      signer: sealed.grants[name].signer,
      destination: sealed.grants[name].destination,
      maxLamports: sealed.grants[name].maxLamports,
      expiresAt: sealed.grants[name].expiresAt,
    }));
    process.stdout.write(JSON.stringify({ ok: true, out, grants: summary }) + '\n');
    return;
  }

  if (command === 'verify-grants') {
    const { loadGrantFile } = require('../src/grantfile');
    const { makeSealKeyProvider } = require('../src/grantseal');
    const passphrase = readPassphrase(args, 'seal-passphrase-file');
    const loaded = loadGrantFile(requireArg(args, 'grants'), {
      sealKeyFor: makeSealKeyProvider(passphrase),
    });
    process.stdout.write(JSON.stringify({ ok: true, grants: loaded.names }) + '\n');
    return;
  }

  if (command === 'migrate') {
    const { migrateJournal } = require('../src/migrate');
    const result = migrateJournal({
      file: requireArg(args, 'ledger'),
      wiresDir: typeof args.wires === 'string' ? args.wires : null,
      discardLegacy: args['discard-legacy'] === true,
    });
    process.stdout.write(JSON.stringify({ ok: true, ...result }) + '\n');
    return;
  }

  process.stderr.write(USAGE);
  process.exit(2);
}

main().catch((err) => {
  // A grant VALUE the daemon cannot honour. The creation path and the
  // loader now judge values by the SAME rules (src/grantvalues.js), so a
  // refusal here means the grant would never sign - it must say what to
  // write instead, not just which field was wrong (house rule: every
  // refusal names a repair).
  if (err && err.code === 'grant_field_invalid') {
    const field = detailOf(err);
    // The detail names the FIELD; the repair says what that field must hold.
    // The rules are the ones the daemon applies (src/grantvalues.js).
    const FIX = {
      signer: 'a base58 Ed25519 public key of exactly 32 bytes (e.g. read it from the keystore: --keystore <file>)',
      destination: 'a base58 Ed25519 public key of exactly 32 bytes (the recipient wallet address)',
      expiresAt: 'a real UTC instant such as 2030-01-01T00:00:00Z - no Feb 31, no month 13, no offset',
      maxLamports: 'an integer at most 18446744073709551615 (the u64 cap)',
      windowMaxLamports: 'an integer at most 18446744073709551615 (the u64 window cap)',
      windowSeconds: 'a positive whole number of seconds (no fractions, no zero)',
      windowMaxMessages: 'a positive whole number of messages',
      maxBytes: 'an integer between 1 and 3072',
      // Details from validateGrant (the loader) arrive as `<name>.key` /
      // `<name>.format` / `<name>.windowSeconds`.
      key: 'a base58 Ed25519 public key of exactly 32 bytes (signer and destination)',
      format: 'a value the daemon can honour: real UTC instant, u64 caps, positive whole window seconds',
    };
    const fix = FIX[field] || FIX[String(field).split('.').pop()] || 'a value the daemon can honour (see the grant-add usage)';
    process.stderr.write(
      `${err.code}: ${field}\n` +
      `  fix: set the field to ${fix}\n`);
    process.exit(1);
  }
  // Name the repair, not just the verdict (same rule as the passphrase
  // refusal): the quickstart's `run` was the first contact with the product
  // for a stranger whose grant file did not exist yet — measured 2026-11-05
  // as a bare `grant_file_unreadable: ENOENT` with no way to guess the fix.
  if (err && err.code === 'grant_file_unreadable') {
    process.stderr.write(
      `${err.code}: ${detailOf(err)}\n` +
      `  fix: signerd grant-add --grants <file> --name <grant> --keystore <file> --destination <pubkey>\n` +
      `          --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>` +
      `   # create the grant file run expects\n`);
    process.exit(1);
  }
  // The lease helper is compiled from the shipped tools/leasecheck.c the
  // first time the daemon reads the grant file. On a machine without a C
  // compiler (measured 2026-11-07, published tag v0.2.7 in an empty dir:
  // keygen exit 0, grant-add exit 0, `run` -> "spawnSync cc ENOENT", exit 1)
  // the stranger was told a Node-internal API name and given no repair,
  // while every other refusal in this CLI names its fix. Both repairs this
  // can need: a compiler, or a writable install directory.
  if (err && typeof err.code === 'string' && err.code.endsWith('_lease_unavailable')) {
    const detail = detailOf(err);
    process.stderr.write(`${err.code}: ${detail}\n`);
    if (/was not found|is not executable|could not be started/.test(detail)) {
      process.stderr.write(
        `  fix: install a C compiler (cc), or point CC at one: CC=/path/to/cc signerd run ...` +
        `   # the lease helper is built from tools/leasecheck.c, so the daemon needs a compiler once\n`);
    } else if (/not writable/.test(detail)) {
      process.stderr.write(
        `  fix: make the install directory writable (or pre-build it there: cc -O2 -o tools/leasecheck tools/leasecheck.c)` +
        `   # the helper must be written next to its shipped source\n`);
    } else {
      process.stderr.write(
        `  fix: build the lease helper by hand: cc -O2 -o tools/leasecheck tools/leasecheck.c` +
        `   # then start the daemon again\n`);
    }
    process.exit(1);
  }
  process.stderr.write(`${err.code || 'error'}: ${detailOf(err)}\n`);
  process.exit(1);
});
