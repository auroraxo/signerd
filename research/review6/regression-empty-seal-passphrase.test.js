'use strict';
// REGRESSION TEST (review #6, finding 1)
//
// Defect: `signerd run --grant-seal-passphrase-file <file>` with an EMPTY
// passphrase file (touch seal.pass / a newline-only file) silently turns
// sealed-grant mode OFF, because bin/signerd.js readPassphrase() returns ''
// and src/daemon.js decides the mode from `.length > 0`. The daemon then
// ACCEPTS an unsealed, forged grant document and signs the attacker's
// destination, while `signerd status` and the journal side both refuse the
// same empty passphrase with seal_passphrase_required /
// journal_seal_passphrase_required.
//
// Expected (fail-closed) behaviour: an explicitly requested but empty seal
// passphrase must REFUSE everywhere - the same way `status` already does.
//
// Against c1b1c09 this test FAILS (the daemon starts and the forged grant is
// accepted). It passes once the empty passphrase is refused at start.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { Keypair, SystemProgram, Transaction, VersionedTransaction } = require('@solana/web3.js');

const { Daemon, request } = require('../../src/daemon');
const { grantDoc, writeJson, makeWire, KSPASS } = require('./common');
const { createKeystore, loadKeystore } = require('../../src/keystore');

const FORGED = 'an unsealed forged document';

function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r6-reg1-'));
  fs.chmodSync(d, 0o700);
  return d;
}

test('empty grant-seal passphrase file must refuse, not silently disable sealed mode', async () => {
  const dir = tmpDir();
  let daemon = null;
  try {
    const keystore = path.join(dir, 'ops.key');
    createKeystore({ file: keystore, passphrase: KSPASS });
    const keypair = loadKeystore({ file: keystore, passphrase: KSPASS });
    const attacker = Keypair.generate().publicKey.toBase58();

    // The stranger's forged, UNSEALED grant: destination = attacker.
    const grantFile = path.join(dir, 'grants.json');
    writeJson(grantFile, grantDoc(keypair.publicKey.toBase58(), attacker,
      { maxLamports: '1000000000', windowMaxLamports: '1000000000' }), 0o600);

    const sealPassFile = path.join(dir, 'seal.pass');
    fs.writeFileSync(sealPassFile, ''); // the operator's empty file
    fs.chmodSync(sealPassFile, 0o600);
    const empty = fs.readFileSync(sealPassFile, 'utf8').replace(/\r?\n$/, '');

    // What bin/signerd.js hands the daemon for an empty passphrase file.
    assert.equal(empty, '', 'fixture: readPassphrase on an empty file yields ""');

    const socketPath = path.join(dir, 'r1.sock');
    const ledgerFile = path.join(dir, 'r1.jsonl');

    // 1) the daemon must REFUSE to start in sealed mode with an empty
    //    passphrase (today it starts in UNSEALED mode).
    //    The refusal may come from the constructor (synchronous) or from
    //    start(); both are explicit refusals.
    let refusal = null;
    try {
      daemon = new Daemon({
        socketPath, keystorePath: keystore, passphrase: KSPASS,
        grantFile, ledgerFile, grantSealPassphrase: empty,
      });
      await daemon.start();
    } catch (err) {
      refusal = err;
    }
    assert.ok(refusal !== null,
      'a daemon asked for sealed mode with an empty passphrase must refuse to start '
      + '(today it starts in UNSEALED mode and serves the forged grant)');
    assert.ok(
      ['seal_passphrase_required', 'grant_file_unsealed', 'grant_file_invalid'].includes(refusal.code),
      `refusal must be an explicit seal-related code, got: ${refusal.code || refusal.message}`,
    );

    // 2) belt and braces: even if construction were allowed, the forged
    //    document must never be served a signature.
    if (daemon && daemon.started) {
      const w = makeWire(keypair, attacker);
      const resp = await request({ socketPath, grant: 'ops', wire: w });
      assert.equal(resp.ok, false, `forged grant must not be signed, got ${JSON.stringify(resp)}`);
    }
  } finally {
    if (daemon) { try { await daemon.stop(); } catch { /* already stopped */ } }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('control: the same forged document IS refused when a real passphrase is given', async () => {
  const dir = tmpDir();
  try {
    const keystore = path.join(dir, 'ops.key');
    createKeystore({ file: keystore, passphrase: KSPASS });
    const keypair = loadKeystore({ file: keystore, passphrase: KSPASS });
    const attacker = Keypair.generate().publicKey.toBase58();
    const grantFile = path.join(dir, 'grants.json');
    writeJson(grantFile, grantDoc(keypair.publicKey.toBase58(), attacker), 0o600);

    let refusal = null;
    try {
      const d = new Daemon({
        socketPath: path.join(dir, 'r1c.sock'), keystorePath: keystore, passphrase: KSPASS,
        grantFile, ledgerFile: path.join(dir, 'r1c.jsonl'), grantSealPassphrase: FORGED_PASSPHRASE(),
      });
      await d.start();
      await d.stop();
    } catch (err) {
      refusal = err;
    }
    assert.ok(refusal !== null,
      'an unsealed document with a real passphrase must be refused');
    assert.equal(refusal.code, 'grant_file_unsealed',
      `expected grant_file_unsealed, got: ${refusal.code || refusal.message}`);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function FORGED_PASSPHRASE() { return 'the operator seal passphrase'; }
