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
            [--grant-seal-passphrase-file <file>]
  signerd sign --socket <file> --grant <name> --tx <wire-file> [--out <file>]
  signerd status --grants <file> --ledger <file>
            [--grant-seal-passphrase-file <file>]
  signerd seal-grants --grants <file> --seal-passphrase-file <file> [--out <file>]
            add/replace the HMAC seal of a grant file (provenance, R5-2)
  signerd verify-grants --grants <file> --seal-passphrase-file <file>
            check a grant file's seal without touching the journal
  signerd migrate --ledger <file> (--wires <dir> | --discard-legacy)
            upgrade a format-1 journal; --wires restores message-level replay
            protection, --discard-legacy explicitly accepts losing it

Notes:
  --passphrase-file must be mode 0600 and is read once at startup.
  --grant-seal-passphrase-file turns on sealed-grant mode: the daemon then
  REFUSES a grant file whose HMAC seal does not verify (an unsealed or
  altered file cannot be used to have the daemon sign).
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

function readPassphrase(args, flag = 'passphrase-file') {
  if (typeof args[flag] !== 'string') {
    process.stderr.write(`missing --${flag}\n`);
    process.exit(2);
  }
  const file = requireArg(args, flag);
  const mode = fs.statSync(file).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    process.stderr.write(`${flag} must not be group/other accessible (mode ${mode.toString(8)})\n`);
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
    const sealPassphrase = typeof args['grant-seal-passphrase-file'] === 'string'
      ? readPassphrase(args, 'grant-seal-passphrase-file') : undefined;
    const daemon = new Daemon({
      socketPath: requireArg(args, 'socket'),
      keystorePath: requireArg(args, 'keystore'),
      passphrase: readPassphrase(args),
      grantFile: requireArg(args, 'grants'),
      ledgerFile: requireArg(args, 'ledger'),
      grantSealPassphrase: sealPassphrase,
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
    const sealPassphrase = typeof args['grant-seal-passphrase-file'] === 'string'
      ? readPassphrase(args, 'grant-seal-passphrase-file') : undefined;
    const options = sealPassphrase === undefined ? {} : {
      sealKeyFor: require('../src/grantseal').makeSealKeyProvider(sealPassphrase),
    };
    const loaded = loadGrantFile(requireArg(args, 'grants'), options);
    const ledger = new Ledger({ file: requireArg(args, 'ledger') });
    process.stdout.write(JSON.stringify({
      ok: true, grants: loaded.names, ledger: ledger.snapshot(), legacyState: ledger.legacyState(),
      sealed: sealPassphrase !== undefined,
    }) + '\n');
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
    fs.writeFileSync(out, JSON.stringify(sealed, null, 2) + '\n', { mode: 0o600 });
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
  process.stderr.write(`${err.code || 'error'}: ${err.message}\n`);
  process.exit(1);
});
