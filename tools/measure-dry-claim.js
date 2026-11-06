#!/usr/bin/env node
'use strict';
// LIVE MEASUREMENT (2026-11-06): the README claims
//   "`--dry` runs the same scope path without producing a real signature."
// Measure what actually happens, on THIS tree (bin + src):
//   M1  the CLI's answer to `sign --dry ...`
//   M2  a raw socket frame that carries `dry: true` - does the daemon honor it?
//   M3  a raw frame that carries `dry: "true"` (the mistyped shape)
//   M4  a control frame with no dry field - the REAL signature, for comparison
// Nothing is written outside the temp dir this creates; the daemon runs on a
// local socket with its own keystore/grant/ledger, and no lamport moves.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync, spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

function sh(args) {
  return spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 60000 });
}

function base58(bytes) {
  return require('bs58').encode(bytes);
}

/** One raw request frame over the daemon socket; the daemon answers one line. */
function rawFrame(socketPath, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socketPath);
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('frame_timeout')); }, 10000);
    socket.on('connect', () => socket.write(JSON.stringify(payload) + '\n'));
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return;
      clearTimeout(timer);
      socket.end();
      try { resolve(JSON.parse(buffer.subarray(0, newline).toString('utf8'))); }
      catch (err) { reject(err); }
    });
    socket.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-dry-measure-'));
  const keystore = path.join(root, 'ops.key');
  const pass = path.join(root, 'pass');
  const grants = path.join(root, 'grants.json');
  const ledger = path.join(root, 'journal.jsonl');
  const socket = path.join(root, 's.sock');
  const tx = path.join(root, 'tx.bin');
  fs.writeFileSync(pass, 'pw\n', { mode: 0o600 });

  const out = { date: '2026-11-06', tree: process.argv[2] || 'main' };

  const journalBytes = () => (fs.existsSync(ledger) ? fs.readFileSync(ledger).length : 0);

  // The destination must be a REAL account, distinct from the signer and
  // from the System program (the policy refuses envelope/duplicate_key when
  // it is not) - the same shape test/daemon.test.js builds.
  const { Keypair } = require('@solana/web3.js');
  const recipient = Keypair.generate().publicKey.toBase58();

  let r = sh([CLI, 'keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (r.status !== 0) throw new Error(`keygen failed: ${r.stderr}`);
  r = sh([CLI, 'grant-add', '--grants', grants, '--name', 'ops', '--keystore', keystore,
    '--destination', recipient, '--max-lamports', '1000000',
    '--window-max-lamports', '2000000', '--window-seconds', '3600',
    '--expires', new Date(Date.now() + 86400_000).toISOString().replace(/\.\d{3}Z$/, 'Z')]);
  if (r.status !== 0) throw new Error(`grant-add failed: ${r.stderr}`);

  const { buildTransferWire } = require(path.join(ROOT, 'src', 'client.js'));
  const { loadKeystore } = require(path.join(ROOT, 'src', 'keystore.js'));
  const keypair = loadKeystore({ file: keystore, passphrase: 'pw' });
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i += 1) bytes[i] = (i * 7 + 1) % 256;
  const wire = buildTransferWire({
    fromPubkey: keypair.publicKey.toBase58(),
    toPubkey: recipient,
    lamports: 42,
    blockhash: base58(bytes),
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

  // M1: the CLI's answer to the documented-looking flag. It runs LAST of the
  // CLI checks because it needs the daemon AND a transaction file on disk.
  const outPath = path.join(root, 'signed.bin');
  const before1 = journalBytes();
  const m1 = sh([CLI, 'sign', '--socket', socket, '--grant', 'ops', '--tx', tx, '--dry', '--out', outPath]);
  let m1Json = null;
  try { m1Json = JSON.parse((m1.stdout || '').trim()); } catch { /* not json */ }
  out.m1_cli_dry = {
    status: m1.status,
    stderrHead: (m1.stderr || '').split('\n').slice(0, 4).join(' | '),
    stdoutHead: (m1.stdout || '').trim().slice(0, 200),
    ok: m1Json ? m1Json.ok === true : false,
    dryEcho: m1Json ? m1Json.dry === true : false,
    hasSignature: m1Json
      ? typeof m1Json.signed === 'string' || typeof m1Json.signature === 'string'
      : false,
    outFileWritten: fs.existsSync(outPath),
    journalGrew: journalBytes() > before1,
  };

  const wireB64 = wire.toString('base64');
  const frame = (extra) => rawFrame(socket, Object.assign({ grant: 'ops', wire: wireB64 }, extra));

  // M2: dry:true - does the daemon honor it?
  const before2 = journalBytes();
  const res2 = await frame({ dry: true });
  out.m2_frame_dry_true = {
    ok: res2.ok,
    error: res2.error || null,
    hasSignature: typeof res2.signed === 'string' || typeof res2.signature === 'string',
    dryEcho: res2.dry === true,
    responseKeys: Object.keys(res2).sort(),
    journalBytesBefore: before2,
    journalBytesAfter: journalBytes(),
    journalGrew: journalBytes() > before2,
  };

  // M3: dry:"true" - the mistyped shape.
  const before3 = journalBytes();
  const res3 = await frame({ dry: 'true' });
  out.m3_frame_dry_string = {
    ok: res3.ok,
    error: res3.error || null,
    hasSignature: typeof res3.signed === 'string' || typeof res3.signature === 'string',
    dryEcho: res3.dry === true,
    journalBytesBefore: before3,
    journalBytesAfter: journalBytes(),
    journalGrew: journalBytes() > before3,
  };

  // M4: control - the REAL sign of the same wire.
  const before4 = journalBytes();
  const res4 = await frame({});
  out.m4_control_real_sign = {
    ok: res4.ok,
    error: res4.error || null,
    hasSignature: typeof res4.signed === 'string',
    journalBytesBefore: before4,
    journalBytesAfter: journalBytes(),
    journalGrew: journalBytes() > before4,
  };

  daemon.kill('SIGTERM');
  await new Promise((res) => { daemon.once('exit', res); setTimeout(res, 3000); });
  try { daemon.kill('SIGKILL'); } catch { /* already gone */ }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  process.exit(0);
}

main().catch((err) => { process.stderr.write(String(err && err.stack || err) + '\n'); process.exit(1); });
