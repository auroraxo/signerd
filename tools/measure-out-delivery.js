#!/usr/bin/env node
'use strict';
// LIVE MEASUREMENT (2026-11-07): the OUTPUT DELIVERY contract.
//
//   D1  a dangling-symlink --out is refused BEFORE the daemon signs
//       (journal 0 bytes, no budget, no replay entry) and exits 2.
//   D2  a FIFO --out is refused before the daemon signs — the daemon must
//       never be paid for a write that would block forever.
//   D3  a symlink to a VALID file is accepted and written THROUGH (the link
//       is not the defect), and the delivered bytes land 0600.
//   D4  a write failure AFTER the daemon signed exits 3 and the signed wire
//       is STILL ON STDOUT — the paid-for artifact is recoverable.
//   D5  a write failure AFTER the daemon signed does NOT destroy a
//       pre-existing --out file (atomic temp+rename, never O_TRUNC).
//   D6  a successful delivery lands 0600 even when the target was 0644.
//
// Nothing is written outside the temp dir this creates; the daemon runs on a
// local socket with its own keystore/grant/ledger, and no lamport moves.
//
// The D4 failure is provoked with RLIMIT_FSIZE=0 (ulimit -f 0): the path is
// writable by permission, so the preflight passes, and the write fails AFTER
// the daemon has signed. That is the exact residual the card names
// ("writeFileSync-Fehler moeglich") and the one no preflight can prevent.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

function sh(args, opts = {}) {
  return spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 60000, ...opts });
}
function base58(bytes) {
  return require('bs58').encode(bytes);
}
function journalBytes(ledger) {
  return fs.existsSync(ledger) ? fs.readFileSync(ledger).length : 0;
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-delivery-measure-'));
  const keystore = path.join(root, 'ops.key');
  const pass = path.join(root, 'pass');
  const grants = path.join(root, 'grants.json');
  const ledger = path.join(root, 'journal.jsonl');
  const socket = path.join(root, 's.sock');
  const tx = path.join(root, 'tx.bin');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });

  const out = {
    date: '2026-11-07',
    tree: process.argv[2] || 'main',
    contract: 'exit 0 delivered | 1 refusal | 2 usage/preflight refusal | 3 signed but not delivered',
  };

  let r = sh([CLI, 'keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (r.status !== 0) throw new Error(`keygen failed: ${r.stderr}`);
  r = sh([CLI, 'grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', base58(Buffer.alloc(32, 7)), '--max-lamports', '1000000',
    '--window-max-lamports', '2000000', '--window-seconds', '3600',
    '--expires', new Date(Date.now() + 86400_000).toISOString().replace(/\.\d{3}Z$/, 'Z')]);
  if (r.status !== 0) throw new Error(`grant-add failed: ${r.stderr}`);

  const { buildTransferWire } = require(path.join(ROOT, 'src', 'client.js'));
  const { loadKeystore } = require(path.join(ROOT, 'src', 'keystore.js'));
  const keypair = loadKeystore({ file: keystore, passphrase: 'pw' });
  const recipient = base58(Buffer.alloc(32, 7));
  const wire = buildTransferWire({
    fromPubkey: keypair.publicKey.toBase58(),
    toPubkey: recipient,
    lamports: 42,
    blockhash: base58(Buffer.alloc(32, 3)),
  });
  fs.writeFileSync(tx, wire, { mode: 0o600 });

  const daemon = spawn(process.execPath, [CLI, 'run', '--keystore', keystore,
    '--passphrase-file', pass, '--grants', grants, '--ledger', ledger, '--socket', socket],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let daemonErr = '';
  daemon.stderr.on('data', (d) => { daemonErr += d.toString(); });
  const deadline = Date.now() + 15000;
  while (!fs.existsSync(socket) && Date.now() < deadline) {
    await new Promise((res) => setTimeout(res, 100));
  }
  if (!fs.existsSync(socket)) throw new Error(`daemon did not start: ${daemonErr}`);

  const signArgs = (outPath) => [CLI, 'sign', '--socket', socket, '--grant', 'ops', '--tx', tx, '--out', outPath];

  // --- D1: dangling symlink ------------------------------------------------
  {
    const link = path.join(root, 'd1-link');
    fs.symlinkSync(path.join(root, 'missing-dir', 'x.bin'), link);
    const before = journalBytes(ledger);
    const res = sh(signArgs(link));
    let json = null;
    try { json = JSON.parse((res.stdout || '').trim()); } catch { /* not json */ }
    out.d1_dangling_symlink_refused_before_signing = {
      exit: res.status,
      stderrHead: (res.stderr || '').split('\n').slice(0, 2).join(' | '),
      journalBytesBefore: before,
      journalBytesAfter: journalBytes(ledger),
      journalUntouched: journalBytes(ledger) === before,
      stdoutEmpty: (res.stdout || '').trim() === '',
      signed: json ? typeof json.signed === 'string' : false,
    };
  }

  // --- D2: FIFO ------------------------------------------------------------
  {
    const fifo = path.join(root, 'd2-fifo');
    // mkfifo via node: there is no fs.mkfifo, so use the shell.
    spawnSync('mkfifo', [fifo]);
    const before = journalBytes(ledger);
    const res = sh(signArgs(fifo));
    let json = null;
    try { json = JSON.parse((res.stdout || '').trim()); } catch { /* not json */ }
    out.d2_fifo_refused_before_signing = {
      exit: res.status,
      stderrHead: (res.stderr || '').split('\n').slice(0, 2).join(' | '),
      journalBytesBefore: before,
      journalBytesAfter: journalBytes(ledger),
      journalUntouched: journalBytes(ledger) === before,
      stdoutEmpty: (res.stdout || '').trim() === '',
      signed: json ? typeof json.signed === 'string' : false,
    };
  }

  // --- D3: symlink to a VALID file ----------------------------------------
  {
    const real = path.join(root, 'd3-real.bin');
    const link = path.join(root, 'd3-link.bin');
    fs.writeFileSync(real, Buffer.alloc(0), { mode: 0o600 });
    fs.symlinkSync(real, link);
    const before = journalBytes(ledger);
    const res = sh(signArgs(link));
    let json = null;
    try { json = JSON.parse((res.stdout || '').trim()); } catch { /* not json */ }
    const stillLink = fs.existsSync(link) ? fs.lstatSync(link).isSymbolicLink() : false;
    const delivered = fs.existsSync(real) ? fs.readFileSync(real) : Buffer.alloc(0);
    out.d3_symlink_to_valid_file_written_through = {
      exit: res.status,
      linkStillALink: stillLink,
      bytesDelivered: delivered.length,
      deliveredMode: fs.existsSync(real) ? (fs.statSync(real).mode & 0o777).toString(8) : null,
      journalGrew: journalBytes(ledger) > before,
      signedOnStdout: json ? typeof json.signed === 'string' : false,
    };
  }

  // --- D4/D5: the write fails AFTER the daemon signed ----------------------
  {
    // A fresh wire each time: the daemon refuses a replayed wire, and the
    // measurement wants the write to fail, not the replay to be refused.
    const freshTx = path.join(root, 'tx-fresh.bin');
    const freshWire = buildTransferWire({
      fromPubkey: keypair.publicKey.toBase58(),
      toPubkey: recipient,
      lamports: 43,
      blockhash: base58(Buffer.alloc(32, 4)),
    });
    fs.writeFileSync(freshTx, freshWire, { mode: 0o600 });

    const target = path.join(root, 'd4-out.bin');
    const prior = Buffer.from('PRE-EXISTING CONTENT THAT MUST SURVIVE'.repeat(4));
    fs.writeFileSync(target, prior, { mode: 0o600 });

    const before = journalBytes(ledger);
    // ulimit -f 0 => RLIMIT_FSIZE 0 => the write fails with EFBIG. The path is
    // writable by permission, so the preflight passes and the failure lands
    // AFTER the daemon signed.
    const res = spawnSync('bash', ['-c',
      `ulimit -f 0; exec "${process.execPath}" "${CLI}" sign --socket "${socket}" --grant ops --tx "${freshTx}" --out "${target}"`],
      { encoding: 'utf8', timeout: 60000 });
    let json = null;
    try { json = JSON.parse((res.stdout || '').trim()); } catch { /* not json */ }
    const after = fs.existsSync(target) ? fs.readFileSync(target) : null;

    out.d4_write_failure_after_signing_keeps_the_signature = {
      exit: res.status,
      stderrHead: (res.stderr || '').split('\n').slice(0, 3).join(' | '),
      journalBytesBefore: before,
      journalBytesAfter: journalBytes(ledger),
      daemonDidSign: journalBytes(ledger) > before,
      stdoutHasSignedWire: json ? typeof json.signed === 'string' : false,
      signedBytesLength: json && typeof json.signed === 'string' ? Buffer.from(json.signed, 'base64').length : 0,
      outErrorCode: json && json.outError ? json.outError.code : null,
      outErrorErrno: json && json.outError ? json.outError.errno : null,
    };
    out.d5_failed_write_does_not_destroy_the_previous_file = {
      targetExists: fs.existsSync(target),
      previousBytesPreserved: after ? after.equals(prior) : false,
      previousBytesLength: after ? after.length : null,
      previousBytesLengthBefore: prior.length,
    };
  }

  // --- D6: mode lands 0600 even when the target was 0644 ------------------
  {
    const target = path.join(root, 'd6-out.bin');
    fs.writeFileSync(target, Buffer.alloc(0), { mode: 0o644 });
    fs.chmodSync(target, 0o644);
    const freshTx = path.join(root, 'tx-fresh2.bin');
    fs.writeFileSync(freshTx, buildTransferWire({
      fromPubkey: keypair.publicKey.toBase58(),
      toPubkey: recipient,
      lamports: 44,
      blockhash: base58(Buffer.alloc(32, 5)),
    }), { mode: 0o600 });
    const res = sh([CLI, 'sign', '--socket', socket, '--grant', 'ops', '--tx', freshTx, '--out', target]);
    out.d6_delivered_mode_is_0600 = {
      exit: res.status,
      modeBefore: '644',
      modeAfter: fs.existsSync(target) ? (fs.statSync(target).mode & 0o777).toString(8) : null,
      bytesDelivered: fs.existsSync(target) ? fs.statSync(target).size : 0,
    };
  }

  daemon.kill('SIGTERM');
  await new Promise((res) => { daemon.once('exit', res); setTimeout(res, 3000); });
  try { daemon.kill('SIGKILL'); } catch { /* already gone */ }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  process.exit(0);
}

main().catch((err) => { process.stderr.write(String(err && err.stack || err) + '\n'); process.exit(1); });
