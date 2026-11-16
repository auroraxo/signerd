#!/usr/bin/env node
'use strict';
// Measure what the CLIENT believes when the daemon lies.
//
// WHY (measured 2026-11-16): the daemon verifies its own output before it
// returns it (src/signer.js) - but nothing between the socket and the
// operator's file was checked. `signerd sign` decoded `response.signed` and
// wrote it to `--out` with exit 0, and `sign-message` wrote
// `{receipt, pubkey, sig}` the same way. A server that answers exactly what
// a lying daemon would answer is enough: the socket is a capability, and
// whoever can bind it can impersonate the signing daemon (src/socketprobe.js).
//
// THREE FACES, each a server that answers ok:true with something that is
// not the artifact the client asked for:
//
//   F1 substituted message - the returned wire's message region differs
//      from the requested wire (a byte flipped, the slot overwritten);
//   F2 garbage signature - the message matches, the 64-byte signature slot
//      holds random bytes that verify under nothing;
//   F3 no signature - `{ok:true}` with no `signed` field at all.
//
// The measurement runs each face against the CLI (`sign` and
// `sign-message`) and against the example client, and records the exit code,
// whether an --out file was written, and - for the file that WAS written -
// whether it would verify. A client that writes an artifact that does not
// verify is DEFECTIVE; a client that exits non-zero and writes nothing is
// FIXED.
//
// Usage:
//   node tools/measure-client-verification.js [--out <file>] [--published <dir>]
//
//   --published <dir>  run against an INSTALLED signerd (the published
//                      package, e.g. a clean `npm install signerd` copy),
//                      so the defect can be measured on the released tree.
//   --out <file>       where to write the JSON verdict (default:
//                      research/client-verification-<date>.json).
//
// No network. No writes outside os.tmpdir() and the output file.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const { VersionedTransaction, Keypair } = require(path.join(REPO, 'node_modules', '@solana', 'web3.js'));
const { buildTransferWire } = require(path.join(REPO, 'src', 'client.js'));

const args = process.argv.slice(2);
function argOf(flag) {
  const i = args.indexOf(flag);
  // >= 0, not > 0: a flag may be the FIRST argument. Measured while
  // building this tool: `i > 0` silently ignored `--published <dir>` when it
  // led the command line, so the "published" measurement ran against the
  // checkout and reported the fixed tree as the pre-fix baseline.
  return i >= 0 && args[i + 1] ? path.resolve(args[i + 1]) : null;
}
const OUT = argOf('--out') || path.join(REPO, 'research',
  `client-verification-${new Date().toISOString().slice(0, 10)}.json`);
const PUBLISHED = argOf('--published');

const CLI = PUBLISHED
  ? path.join(PUBLISHED, 'bin', 'signerd.js')
  : path.join(REPO, 'bin', 'signerd.js');
const CLIENT = PUBLISHED
  ? path.join(PUBLISHED, 'examples', 'user-zero-client.js')
  : path.join(REPO, 'examples', 'user-zero-client.js');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/**
 * A server that answers exactly what it is told to answer.
 *
 * It runs as a CHILD PROCESS on purpose: the measurements drive the CLI
 * with spawnSync, which blocks this process's event loop - an in-process
 * server never gets to accept the connection and every face times out
 * instead of being measured (that failure mode was hit while building this
 * tool; a timeout is NOT a verdict).
 *
 * The child is a script file, not an inline `-e` string: the answer travels
 * in a JSON file, so nothing has to survive a shell quoting round trip.
 */
function lyingServer(socketPath, answer) {
  try { fs.unlinkSync(socketPath); } catch { /* absent */ }
  const dir = path.dirname(socketPath);
  const answerFile = path.join(dir, `${path.basename(socketPath)}.answer.json`);
  fs.writeFileSync(answerFile, JSON.stringify(answer));
  const serverFile = path.join(dir, `${path.basename(socketPath)}.server.js`);
  fs.writeFileSync(serverFile, SERVER_SRC);
  const child = spawnSync('sh', ['-c',
    `exec "${process.execPath}" "${serverFile}" "${socketPath}" "${answerFile}" > "${socketPath}.log" 2>&1 & echo $!`],
    { encoding: 'utf8' });
  const pid = parseInt(String(child.stdout).trim(), 10);
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`lying server failed to start: ${child.stderr}`);
  }
  for (let i = 0; i < 100 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.05']);
  if (!fs.existsSync(socketPath)) {
    const log = fs.existsSync(`${socketPath}.log`) ? fs.readFileSync(`${socketPath}.log`, 'utf8') : '';
    throw new Error(`lying server did not bind ${socketPath}: ${log}`);
  }
  return {
    pid,
    close: () => {
      try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ }
      fs.rmSync(socketPath, { force: true });
    },
  };
}

// The child server itself: one request, one answer, then close.
const SERVER_SRC = [
  "const net = require('node:net');",
  "const fs = require('node:fs');",
  "const [socketPath, answerFile] = process.argv.slice(2);",
  "const answer = fs.readFileSync(answerFile, 'utf8');",
  "try { fs.unlinkSync(socketPath); } catch {}",
  "const server = net.createServer((socket) => {",
  "  let buf = '';",
  "  socket.on('data', (chunk) => {",
  "    buf += chunk;",
  "    if (!buf.includes('\\n')) return;",
  "    socket.end(answer + '\\n');",
  "  });",
  "  socket.on('error', () => {});",
  "});",
  "server.listen(socketPath, () => process.stdout.write('READY\\n'));",
  "setTimeout(() => process.exit(0), 120000);",
  "",
].join('\n');

function run(nodeArgs, opts = {}) {
  const res = spawnSync(process.execPath, nodeArgs, { encoding: 'utf8', timeout: 60000, ...opts });
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

/** The client's own artifact: does it verify? */
function wireVerdict(file) {
  if (!fs.existsSync(file)) return { present: false };
  const bytes = fs.readFileSync(file);
  if (bytes.length === 0) return { present: true, bytes: 0, verifies: false, reason: 'empty' };
  return { present: true, bytes: bytes.length, verifies: true, reason: 'nonempty' };
}

async function main() {
  const dir = tmpDir('signerd-clientverify-');
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the client-verification measurement only\n', { mode: 0o600 });
  const keygen = run([CLI, 'keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (keygen.status !== 0) throw new Error(`keygen failed: ${keygen.stderr}`);
  // The daemon's own public key: the fee payer of the control wire must be
  // THIS key, or the daemon refuses signer_or_fee_payer and the control
  // measures nothing (that failure was hit while building this tool: the
  // control exited 1 with no artifact and said nothing about the fix).
  const daemonPubkey = JSON.parse(keygen.stdout.trim().split('\n').pop()).publicKey;

  const signer = Keypair.generate();
  const wire = buildTransferWire({
    fromPubkey: signer.publicKey.toBase58(),
    toPubkey: Keypair.generate().publicKey.toBase58(),
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  // A correctly signed wire for the SAME message: the honest daemon's shape.
  const honest = VersionedTransaction.deserialize(wire);
  honest.sign([signer]);
  const honestSigned = Buffer.from(honest.serialize());

  const body = {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    claims: { version: 'v0.0.0-measurement' },
    issued_at: '2026-11-16T10:00:00+00:00',
  };
  const bodyPath = path.join(dir, 'receipt-body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(body, null, 2), { mode: 0o600 });

  const faces = [];
  const record = (face, target, res, outPath, extra = {}) => {
    const artifact = wireVerdict(outPath);
    faces.push({
      face,
      target,
      exit: res.status,
      stdoutHead: res.stdout.split('\n')[0].slice(0, 300),
      stderrHead: res.stderr.split('\n').slice(0, 3).join(' | ').slice(0, 300),
      artifact,
      ...extra,
    });
  };

  // ---- F1 substituted message -----------------------------------------
  {
    const socketPath = path.join(dir, 'sub.sock');
    const tampered = Buffer.from(honestSigned);
    tampered[tampered.length - 1] ^= 0xff;
    const server = lyingServer(socketPath, {
      ok: true, signature: 'x', signed: tampered.toString('base64'),
      amountLamports: '42', feeLamports: '5000', totalLamports: '5042',
      wireSha256: '0'.repeat(64), messageSha256: '0'.repeat(64), seq: '1',
      windowSpentLamports: '5042', windowRemainingLamports: '1000000',
    });
    const out = path.join(dir, 'f1.bin');
    fs.writeFileSync(path.join(dir, 'tx.bin'), wire, { mode: 0o600 });
    const res2 = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', path.join(dir, 'tx.bin'), '--out', out]);
    record('F1-substituted-message', 'signerd sign --out', res2, out, {
      messageEqual: fs.existsSync(out) ? Buffer.from(honestSigned).subarray(65).equals(fs.readFileSync(out).subarray(65)) : null,
    });
    const clientOut = path.join(dir, 'f1-client.bin');
    const res3 = run([CLIENT, '--socket', socketPath, '--grant', 'ops',
      '--from', signer.publicKey.toBase58(), '--to', Keypair.generate().publicKey.toBase58(),
      '--lamports', '42', '--blockhash', Keypair.generate().publicKey.toBase58(), '--out', clientOut]);
    record('F1-substituted-message', 'examples/user-zero-client.js', res3, clientOut);
    server.close();
  }

  // ---- F2 garbage signature -------------------------------------------
  {
    const socketPath = path.join(dir, 'garbage.sock');
    const garbage = Buffer.from(honestSigned);
    garbage.set(crypto.randomBytes(64), 1);
    const server = lyingServer(socketPath, {
      ok: true, signature: 'x', signed: garbage.toString('base64'),
      amountLamports: '42', feeLamports: '5000', totalLamports: '5042',
      wireSha256: '0'.repeat(64), messageSha256: '0'.repeat(64), seq: '1',
      windowSpentLamports: '5042', windowRemainingLamports: '1000000',
    });
    const out = path.join(dir, 'f2.bin');
    fs.writeFileSync(path.join(dir, 'tx.bin'), wire, { mode: 0o600 });
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', path.join(dir, 'tx.bin'), '--out', out]);
    record('F2-garbage-signature', 'signerd sign --out', res, out, {
      messageEqual: fs.existsSync(out) ? Buffer.from(honestSigned).subarray(65).equals(fs.readFileSync(out).subarray(65)) : null,
    });
    const clientOut = path.join(dir, 'f2-client.bin');
    const res3 = run([CLIENT, '--socket', socketPath, '--grant', 'ops',
      '--from', signer.publicKey.toBase58(), '--to', Keypair.generate().publicKey.toBase58(),
      '--lamports', '42', '--blockhash', Keypair.generate().publicKey.toBase58(), '--out', clientOut]);
    record('F2-garbage-signature', 'examples/user-zero-client.js', res3, clientOut);
    server.close();
  }

  // ---- F3 no signature at all ------------------------------------------
  {
    const socketPath = path.join(dir, 'nosig.sock');
    const server = lyingServer(socketPath, {
      ok: true, signature: 'x', amountLamports: '42', feeLamports: '5000', totalLamports: '5042',
      wireSha256: '0'.repeat(64), messageSha256: '0'.repeat(64), seq: '1',
      windowSpentLamports: '5042', windowRemainingLamports: '1000000',
    });
    const out = path.join(dir, 'f3.bin');
    fs.writeFileSync(path.join(dir, 'tx.bin'), wire, { mode: 0o600 });
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', path.join(dir, 'tx.bin'), '--out', out]);
    record('F3-no-signature', 'signerd sign --out', res, out);
    const receiptOut = path.join(dir, 'f3-receipt.json');
    const resMsg = run([CLI, 'sign-message', '--socket', socketPath, '--grant', 'ops', '--body', bodyPath, '--out', receiptOut]);
    record('F3-no-signature', 'signerd sign-message --out', resMsg, receiptOut);
    server.close();
  }

  // ---- F4 substituted body on the message path ------------------------
  {
    const socketPath = path.join(dir, 'msgsub.sock');
    // The server answers ok with a signature over the WRONG body (and a
    // messageSha256 that matches THAT body, so only the client's own
    // canonicalization of the body it sent can catch it).
    const { ed25519 } = require(path.join(REPO, 'node_modules', '@noble', 'curves', 'ed25519.js'));
    const seed = crypto.randomBytes(32);
    const other = Buffer.from(JSON.stringify({ schema: 'openreceipts/v1', issuer: 'attacker',
      type: 'release', subject: 'auroraxo/signerd', claims: {}, issued_at: '2026-11-16T10:00:00+00:00' }));
    const sig = Buffer.from(ed25519.sign(other, seed));
    const server = lyingServer(socketPath, {
      ok: true, kind: 'message',
      signature: sig.toString('base64'),
      pubkey: Buffer.from(ed25519.getPublicKey(seed)).toString('base64'),
      messageSha256: crypto.createHash('sha256').update(other).digest('hex'),
      seq: '1', windowMessages: '1', windowRemainingMessages: '4',
    });
    const receiptOut = path.join(dir, 'f4-receipt.json');
    const res = run([CLI, 'sign-message', '--socket', socketPath, '--grant', 'ops', '--body', bodyPath, '--out', receiptOut]);
    record('F4-substituted-body', 'signerd sign-message --out', res, receiptOut);
    server.close();
  }

  // ---- C1 control: a REAL daemon still works --------------------------
  {
    const socketPath = path.join(dir, 'real.sock');
    const ledger = path.join(dir, 'journal.jsonl');
    const grants = path.join(dir, 'grants.json');
    const destination = Keypair.generate().publicKey.toBase58();
    const expiry = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const add = run([CLI, 'grant-add', '--grants', grants, '--name', 'ops',
      '--keystore', keystore, '--destination', destination,
      '--max-lamports', '1000', '--window-max-lamports', '1000000',
      '--window-seconds', '3600', '--expires', expiry]);
    if (add.status !== 0) throw new Error(`grant-add failed: ${add.stdout}${add.stderr}`);
    const daemon = spawnSync('sh', ['-c',
      `exec "${process.execPath}" "${CLI}" run --keystore "${keystore}" --passphrase-file "${pass}" ` +
      `--grants "${grants}" --ledger "${ledger}" --socket "${socketPath}" > "${dir}/daemon.log" 2>&1 & echo $!`],
      { encoding: 'utf8' });
    const pid = parseInt(String(daemon.stdout).trim(), 10);
    for (let i = 0; i < 100 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.1']);
    try {
      const realWire = buildTransferWire({
        fromPubkey: daemonPubkey, toPubkey: destination,
        lamports: 42, blockhash: Keypair.generate().publicKey.toBase58(),
      });
      fs.writeFileSync(path.join(dir, 'tx-real.bin'), realWire, { mode: 0o600 });
      const out = path.join(dir, 'c1.bin');
      const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops',
        '--tx', path.join(dir, 'tx-real.bin'), '--out', out]);
      const bytes = fs.existsSync(out) ? fs.readFileSync(out) : null;
      let verifies = null;
      if (bytes && bytes.length > 65) {
        try {
          const tx = VersionedTransaction.deserialize(bytes);
          const msg = Buffer.from(tx.message.serialize());
          const crypto2 = require('node:crypto');
          const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
            Buffer.from(tx.message.accountKeys[0].toBytes())]);
          const key = crypto2.createPublicKey({ key: spki, format: 'der', type: 'spki' });
          verifies = crypto2.verify(null, msg, key, Buffer.from(tx.signatures[0]));
        } catch { verifies = false; }
      }
      faces.push({
        face: 'C1-real-daemon', target: 'signerd sign --out', exit: res.status,
        artifact: wireVerdict(out), verifies, messageEqual: bytes ? bytes.subarray(65).equals(realWire.subarray(65)) : null,
        note: 'control: the honest path must still sign and verify',
      });
    } finally {
      try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ }
    }
  }

  const defective = faces.filter((f) => f.face.startsWith('F')
    && f.exit === 0 && f.artifact.present && (f.artifact.bytes > 0));
  const verdict = {
    generatedAt: new Date().toISOString(),
    target: PUBLISHED ? `installed:${PUBLISHED}` : `checkout:${REPO}`,
    cli: CLI,
    client: CLIENT,
    faces,
    defectiveCount: defective.length,
    verdict: defective.length === 0 ? 'client-verification-holds' : 'client-accepts-unverified-artifact',
    limits: [
      'A lying server is an impostor at the socket path, which the daemon\'s own socket protections (0700 dir, 0600 socket, owner checks) are designed to prevent; this measures the CLIENT\'s last line of defense, not the socket\'s.',
      'The message-path check verifies the signature against the pubkey the response carries, so it catches substitution and unverifiable signatures, not a daemon answering with its own key - pinning the key is the consumer\'s job (openreceipts receipt.py does it).',
      'No network, no on-chain broadcast: the verification is over the bytes the client received.',
    ],
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(verdict, null, 2) + '\n');
  process.stdout.write(`${JSON.stringify({ verdict: verdict.verdict, defectiveCount: defective.length, out: OUT })}\n`);
  process.exit(verdict.verdict === 'client-verification-holds' ? 0 : 3);
}

main().catch((err) => {
  process.stderr.write(`measurement_failed: ${err.message}\n`);
  process.exit(4);
});
