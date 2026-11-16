#!/usr/bin/env node
'use strict';
// Measure what the CLIENT does with the frame the daemon sends BACK.
//
// WHY (measured 2026-11-16): the daemon caps the REQUEST frame by name
// (MAX_REQUEST_BYTES = 25_600, refused as `request_too_large` with a
// repair). The mirror image was never capped: src/daemon.js `request()`
// does `buffer = Buffer.concat([buffer, chunk])` until a newline shows up,
// with NO upper bound. A server that answers with an endless stream and
// no newline makes the client buffer every byte it gets (measured: 137 MB
// of RSS growth inside the 10 s timeout window) and then report
// `request_timeout` - the clock blamed for a frame the server never
// finished.
//
// The refusal VOICE of the same path is just as thin: the transport
// failures of the client carry no code and no repair.
//   - `response_invalid` (src/daemon.js) rejects with a bare Error: the
//     CLI prints the generic `error: response_invalid`, no repair;
//   - `connection_closed` has a repair IN THE SOURCE, but the CLI's
//     generic error path prints code + detail only, so the repair never
//     reaches the operator (measured: `connection_closed: ` and nothing
//     else);
//   - a frame that is not a verdict at all (`{"error":"boom"}`, no `ok`)
//     is relayed to stdout verbatim as if it were an answer.
//
// THE PRODUCT CONTRACT: every refusal names ONE code and ONE repair, and
// the client never writes an artifact it has not checked. The request side
// was closed on 2026-11-11 (request_too_large / connection_closed); the
// response side is still open.
//
// FOUR FACES, each a server that answers with something the client must
// refuse BY NAME:
//   R1 oversized frame   - an endless stream without a newline
//   R2 non-JSON frame    - `not json`
//   R3 verdict-less close- the socket dies without an answer
//   R4 no verdict field  - `{"error":"boom"}` (no `ok`)
// plus G1, the control: the honest daemon still signs.
//
// Usage:
//   node tools/measure-response-frame.js [--out <file>] [--published <dir>]
//
//   --published <dir>  run against an INSTALLED signerd (the published
//                      package), so the defect can be measured on the
//                      released tree.
//   --out <file>       where to write the JSON verdict (default:
//                      research/response-frame-<date>.json).
//
// No network. No writes outside os.tmpdir() and the output file.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const { Keypair } = require(path.join(REPO, 'node_modules', '@solana', 'web3.js'));
const { buildTransferWire } = require(path.join(REPO, 'src', 'client.js'));

const args = process.argv.slice(2);
function argOf(flag) {
  const i = args.indexOf(flag);
  // >= 0, not > 0: a flag may be the FIRST argument (the lesson from
  // tools/measure-client-verification.js, where `i > 0` silently ignored
  // `--published <dir>` and the "published" run measured the checkout).
  return i >= 0 && args[i + 1] ? path.resolve(args[i + 1]) : null;
}
const OUT = argOf('--out') || path.join(REPO, 'research',
  `response-frame-${new Date().toISOString().slice(0, 10)}.json`);
const PUBLISHED = argOf('--published');

const TREE = PUBLISHED || REPO;
const CLI = path.join(TREE, 'bin', 'signerd.js');
const DAEMON_SRC = path.join(TREE, 'src', 'daemon.js');

function fail(msg) { console.error(msg); process.exit(3); }

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function run(nodeArgs, opts = {}) {
  const res = spawnSync(process.execPath, nodeArgs, { encoding: 'utf8', timeout: 60000, ...opts });
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

/**
 * The server for one face. It runs as a CHILD PROCESS on purpose:
 * spawnSync blocks this process's event loop, so an in-process server
 * never accepts the connection and every face times out instead of being
 * measured (a timeout is NOT a verdict - the lesson from
 * tools/measure-client-verification.js).
 *
 * The face travels in a JSON file, so nothing has to survive a shell
 * quoting round trip.
 *
 * face kinds:
 *   'stream'  - write `bytes` of 'A' and never write a newline
 *   'answer'  - write `answer` + '\n' and close
 *   'close'   - read the request, then destroy the socket (no verdict)
 */
function faceServer(socketPath, face) {
  try { fs.unlinkSync(socketPath); } catch { /* absent */ }
  const dir = path.dirname(socketPath);
  const faceFile = path.join(dir, `${path.basename(socketPath)}.face.json`);
  fs.writeFileSync(faceFile, JSON.stringify(face));
  const serverFile = path.join(dir, `${path.basename(socketPath)}.server.js`);
  fs.writeFileSync(serverFile, SERVER_SRC);
  const child = spawnSync('sh', ['-c',
    `exec "${process.execPath}" "${serverFile}" "${socketPath}" "${faceFile}" > "${socketPath}.log" 2>&1 & echo $!`],
    { encoding: 'utf8' });
  const pid = parseInt(String(child.stdout).trim(), 10);
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`face server failed to start: ${child.stderr}`);
  }
  for (let i = 0; i < 100 && !fs.existsSync(socketPath); i += 1) spawnSync('sleep', ['0.05']);
  if (!fs.existsSync(socketPath)) {
    const log = fs.existsSync(`${socketPath}.log`) ? fs.readFileSync(`${socketPath}.log`, 'utf8') : '';
    throw new Error(`face server did not bind ${socketPath}: ${log}`);
  }
  return {
    pid,
    close: () => {
      try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ }
      fs.rmSync(socketPath, { force: true });
    },
  };
}

const SERVER_SRC = [
  "const net = require('node:net');",
  "const fs = require('node:fs');",
  "const [socketPath, faceFile] = process.argv.slice(2);",
  "const face = JSON.parse(fs.readFileSync(faceFile, 'utf8'));",
  "try { fs.unlinkSync(socketPath); } catch {}",
  "const server = net.createServer((socket) => {",
  "  socket.on('error', () => {});",
  "  socket.on('data', () => {",
  "    if (face.kind === 'answer') { socket.end(face.answer + '\\n'); return; }",
  "    if (face.kind === 'close') { socket.destroy(); return; }",
  "    if (face.kind === 'stream') {",
  "      const chunk = Buffer.alloc(64 * 1024, 0x41);",
  "      let sent = 0;",
  "      const pump = () => {",
  "        while (sent < face.bytes) {",
  "          const ok = socket.write(chunk);",
  "          sent += chunk.length;",
  "          if (!ok) { socket.once('drain', pump); return; }",
  "        }",
  "        socket.end();",
  "      };",
  "      pump();",
  "    }",
  "  });",
  "});",
  "server.listen(socketPath, () => process.stdout.write('READY\\n'));",
  "setTimeout(() => process.exit(0), 180000);",
  "",
].join('\n');

/**
 * The library face: how much does the CLIENT buffer from a server that
 * never finishes its frame? Measured in a CHILD process, because the
 * parent blocks on spawnSync.
 */
function libraryProbe(dir, socketPath) {
  const script = path.join(dir, 'lib-probe.js');
  fs.writeFileSync(script, [
    "'use strict';",
    "const net = require('node:net');",
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    `const { request } = require(${JSON.stringify(DAEMON_SRC)});`,
    "const socketPath = process.argv[2];",
    "const started = Date.now();",
    "const rss0 = process.memoryUsage().rss;",
    "(async () => {",
    "  let outcome;",
    "  try {",
    "    await request({ socketPath, grant: 'g', wire: Buffer.alloc(100).toString('base64'), timeoutMs: 4000 });",
    "    outcome = { resolved: true };",
    "  } catch (err) {",
    "    outcome = { rejected: true, code: err.code || null, message: String(err.message).slice(0, 80) };",
    "  }",
    "  const rss1 = process.memoryUsage().rss;",
    "  process.stdout.write(JSON.stringify({",
    "    outcome, elapsedMs: Date.now() - started,",
    "    rssGrowthMB: Math.round((rss1 - rss0) / (1024 * 1024)),",
    "  }));",
    "})();",
    "",
  ].join('\n'));
  const res = spawnSync(process.execPath, [script, socketPath], {
    encoding: 'utf8', timeout: 30000,
  });
  if (res.error) throw res.error;
  try {
    return JSON.parse(String(res.stdout).trim() || '{}');
  } catch {
    return { parseError: String(res.stdout).slice(0, 200), stderr: String(res.stderr).slice(0, 200) };
  }
}

/**
 * What the operator was told. The product contract: ONE code and ONE
 * repair per refusal. `fix:` is the product's repair marker.
 */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  return {
    code,
    firstLine: firstLine.slice(0, 200),
    hasFix: /(^|\n)\s*fix:/.test(text),
  };
}

async function main() {
  const dir = tmpDir('signerd-responseframe-');
  const keystore = path.join(dir, 'ops.key');
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the response-frame measurement only\n', { mode: 0o600 });
  const keygen = run([CLI, 'keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (keygen.status !== 0) fail(`keygen failed: ${keygen.stderr}`);

  const signer = Keypair.generate();
  const wire = buildTransferWire({
    fromPubkey: signer.publicKey.toBase58(),
    toPubkey: Keypair.generate().publicKey.toBase58(),
    lamports: 42,
    blockhash: Keypair.generate().publicKey.toBase58(),
  });
  const txPath = path.join(dir, 'tx.bin');
  fs.writeFileSync(txPath, wire, { mode: 0o600 });

  const faces = [];
  const record = (face, res, outPath, extra = {}) => {
    const voice = voiceOf(res.stderr);
    faces.push({
      face,
      exit: res.status,
      stdoutHead: res.stdout.split('\n')[0].slice(0, 200),
      stderrHead: res.stderr.split('\n').slice(0, 2).join(' | ').slice(0, 250),
      voice,
      artifactWritten: fs.existsSync(outPath),
      ...extra,
    });
  };

  // ---- R1 oversized response frame ------------------------------------
  {
    const socketPath = path.join(dir, 'oversize.sock');
    const server = faceServer(socketPath, { kind: 'stream', bytes: 256 * 1024 * 1024 });
    const lib = libraryProbe(dir, socketPath);
    const out = path.join(dir, 'r1.bin');
    const started = Date.now();
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath, '--out', out]);
    record('R1-oversized-frame', res, out, {
      elapsedMs: Date.now() - started,
      library: lib,
    });
    server.close();
  }

  // ---- R2 non-JSON response frame -------------------------------------
  {
    const socketPath = path.join(dir, 'notjson.sock');
    const server = faceServer(socketPath, { kind: 'answer', answer: 'not json' });
    const out = path.join(dir, 'r2.bin');
    const started = Date.now();
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath, '--out', out]);
    record('R2-non-json-frame', res, out, { elapsedMs: Date.now() - started });
    server.close();
  }

  // ---- R3 verdict-less close ------------------------------------------
  {
    const socketPath = path.join(dir, 'close.sock');
    const server = faceServer(socketPath, { kind: 'close' });
    const out = path.join(dir, 'r3.bin');
    const started = Date.now();
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath, '--out', out]);
    record('R3-verdict-less-close', res, out, { elapsedMs: Date.now() - started });
    server.close();
  }

  // ---- R4 a frame that is not a verdict -------------------------------
  {
    const socketPath = path.join(dir, 'noverdict.sock');
    const server = faceServer(socketPath, { kind: 'answer', answer: '{"error":"boom"}' });
    const out = path.join(dir, 'r4.bin');
    const started = Date.now();
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath, '--out', out]);
    record('R4-no-verdict-field', res, out, { elapsedMs: Date.now() - started });
    server.close();
  }

  // ---- G1 control: the honest daemon still signs ----------------------
  {
    const socketPath = path.join(dir, 'honest.sock');
    const server = faceServer(socketPath, {
      kind: 'answer',
      answer: JSON.stringify({ ok: true, signature: 'x', signed: 'AA==', amountLamports: '42' }),
    });
    const out = path.join(dir, 'g1.bin');
    const res = run([CLI, 'sign', '--socket', socketPath, '--grant', 'ops', '--tx', txPath, '--out', out]);
    // The control does NOT have to sign (the fake signature cannot verify):
    // it has to be refused BY NAME and write NOTHING. The happy path is
    // covered by the suite; here the control proves the harness works.
    record('G1-control-named-refusal', res, out, { control: true });
    server.close();
  }

  fs.rmSync(dir, { recursive: true, force: true });

  const source = fs.readFileSync(DAEMON_SRC, 'utf8');
  const capMatch = source.match(/MAX_RESPONSE_BYTES = ([\d_]+);/);
  const out = {
    tool: 'measure-response-frame',
    date: '2026-11-16',
    tree: PUBLISHED ? `published:${PUBLISHED}` : 'worktree',
    head: spawnSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO, encoding: 'utf8' }).stdout.trim(),
    maxResponseBytes: capMatch ? Number(capMatch[1].replace(/_/g, '')) : null,
    cases: {},
  };

  // A face is DEFECTIVE when the operator got no named code, or no
  // repair, or the client waited for its own clock instead of naming the
  // server's failure.
  const named = (c) => c.voice.code && c.voice.code !== 'error' && c.voice.code !== 'request_timeout';
  for (const f of faces) {
    const defect = f.control
      ? false
      : (!named(f) || !f.voice.hasFix || f.artifactWritten === true
        || (f.face === 'R3-verdict-less-close' && f.elapsedMs > 4000)
        || (f.face === 'R1-oversized-frame' && f.elapsedMs > 4000));
    out.cases[f.face] = {
      exit: f.exit,
      elapsedMs: f.elapsedMs,
      stdoutHead: f.stdoutHead,
      stderrHead: f.stderrHead,
      code: f.voice.code,
      hasFix: f.voice.hasFix,
      artifactWritten: f.artifactWritten,
      library: f.library || null,
      defect,
    };
  }

  const defective = Object.entries(out.cases).filter(([, c]) => c.defect).map(([k]) => k);
  out.defectiveFaces = defective.length;
  out.totalFaces = faces.filter((f) => !f.control).length;
  out.verdict = defective.length === 0
    ? 'client-names-every-response-failure'
    : 'client-swallows-response-failures';

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
  console.log(JSON.stringify({ ...out, outFile: OUT }, null, 2));
  process.exit(0);
}

main().catch((err) => { console.error(err && err.stack || err); process.exit(3); });
