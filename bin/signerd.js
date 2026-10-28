#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const USAGE = `signerd — scoped signing daemon for Solana (early prototype)

Usage:
  signerd keygen --keystore <file>            create an encrypted keystore
  signerd import --keystore <file> --from <secret-file>
            encrypt an EXISTING plaintext key (id.json / base58 / raw 64 bytes)
  signerd run --keystore <file> --passphrase-file <file>
            --grants <file> --ledger <file> --socket <file>
  signerd sign --socket <file> --grant <name> --tx <wire-file> [--out <file>]
  signerd status --grants <file> --ledger <file>

Notes:
  --passphrase-file must be mode 0600 and is read once at startup.
  Every refusal is a machine-readable reason; nothing is signed outside the
  grant's scope. This is NOT a reviewed wallet or a production daemon.
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) args[key] = true;
      else { args[key] = next; i += 1; }
    } else args._.push(token);
  }
  return args;
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || value.length === 0) {
    process.stderr.write(`missing --${name}\n${USAGE}`);
    process.exit(2);
  }
  return value;
}

function readPassphrase(args) {
  if (typeof args['passphrase-file'] !== 'string') {
    process.stderr.write('missing --passphrase-file\n');
    process.exit(2);
  }
  const file = requireArg(args, 'passphrase-file');
  const mode = fs.statSync(file).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    process.stderr.write(`passphrase file must not be group/other accessible (mode ${mode.toString(8)})\n`);
    process.exit(2);
  }
  return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, '');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

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
    const out = importKeystore({ file, passphrase, from, overwrite: args.overwrite === true });
    process.stdout.write(JSON.stringify(out) + '\n');
    return;
  }

  if (command === 'run') {
    const { Daemon } = require('../src/daemon');
    const daemon = new Daemon({
      socketPath: requireArg(args, 'socket'),
      keystorePath: requireArg(args, 'keystore'),
      passphrase: readPassphrase(args),
      grantFile: requireArg(args, 'grants'),
      ledgerFile: requireArg(args, 'ledger'),
    });
    await daemon.start();
    process.stdout.write(JSON.stringify({ ok: true, ...daemon.status() }) + '\n');
    const shutdown = async () => { await daemon.stop(); process.exit(0); };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  if (command === 'sign') {
    const { request } = require('../src/daemon');
    const socketPath = requireArg(args, 'socket');
    const grant = requireArg(args, 'grant');
    const wire = fs.readFileSync(requireArg(args, 'tx'));
    const response = await request({ socketPath, grant, wire });
    if (response.ok && typeof args.out === 'string') {
      fs.writeFileSync(args.out, Buffer.from(response.signed, 'base64'), { mode: 0o600 });
      delete response.signed;
    }
    process.stdout.write(JSON.stringify(response) + '\n');
    process.exit(response.ok ? 0 : 1);
  }

  if (command === 'status') {
    const { loadGrantFile } = require('../src/grantfile');
    const { Ledger } = require('../src/ledger');
    const loaded = loadGrantFile(requireArg(args, 'grants'));
    const ledger = new Ledger({ file: requireArg(args, 'ledger') });
    process.stdout.write(JSON.stringify({
      ok: true, grants: loaded.names, ledger: ledger.snapshot(),
    }) + '\n');
    return;
  }

  process.stderr.write(USAGE);
  process.exit(2);
}

main().catch((err) => {
  process.stderr.write(`${err.code || 'error'}: ${err.message}\n`);
  process.exit(1);
});
