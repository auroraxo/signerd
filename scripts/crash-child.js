'use strict';

// Crash child: approves transfers until it is killed. Every approval that is
// REPORTED to stdout is also appended to a report file (fsync'd), so the parent
// can compare "what the caller believed" against "what the journal recorded".
//
// Usage: node scripts/crash-child.js <journal> <report> <maxIterations> [passphrase]
// With a passphrase the journal is SEALED (R5-2 journal half): every approval
// is anchored before the verdict is returned.

const fs = require('node:fs');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Ledger, gate } = require('../src/ledger');

const [journal, report, maxIterationsRaw, passphrase] = process.argv.slice(2);
const maxIterations = Number(maxIterationsRaw) || 10000;

const signer = Keypair.generate();
const recipient = Keypair.generate().publicKey;
const now = new Date('2026-10-27T10:00:00.000Z');
const grant = {
  signer: signer.publicKey.toBase58(),
  destination: recipient.toBase58(),
  maxLamports: '42',
  expiresAt: '2026-10-28T10:00:00Z',
  windowMaxLamports: '1000000000',
  windowSeconds: '86400',
};

const ledger = new Ledger({ file: journal, sealPassphrase: passphrase });
const reportFd = fs.openSync(report, 'a');

let iteration = 0;
for (;;) {
  iteration += 1;
  if (iteration > maxIterations) break;
  // A distinct wire each time (fresh blockhash) so the replay set is not the
  // thing under test here: the journal's crash behavior is.
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: recipient, lamports: 42 }));
  tx.sign(signer);
  const wire = tx.serialize();

  const verdict = gate(wire, grant, now, ledger);
  if (!verdict.allowed) {
    // Window exhausted or replay: report and stop, this is a test artifact.
    fs.writeSync(reportFd, JSON.stringify({ iteration, verdict }) + '\n');
    fs.fsyncSync(reportFd);
    break;
  }
  // The approval has been RETURNED to the caller. Record that fact durably.
  fs.writeSync(reportFd, JSON.stringify({ iteration, verdict }) + '\n');
  fs.fsyncSync(reportFd);
}
fs.closeSync(reportFd);
