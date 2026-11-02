#!/usr/bin/env node
// install-smoke — what a STRANGER gets after `npm install github:auroraxo/signerd#<tag>`.
//
// WHY THIS EXISTS (measured 2026-11-02): the qualification suite (212 tests)
// runs from a CHECKOUT: `npm ci`, `pretest` builds tools/leasecheck, the
// daemon is started from ../bin. A stranger installing the published package
// gets a different tree — no `npm test`, no pretest build, a PATH-resolved
// `signerd` bin, and a README whose quickstart starts with
// `signerd keygen --keystore ~/.config/signerd/ops.key` while the default
// umask (0002) makes ~/.config/signerd a 0775 directory, which
// readPassphrase() refuses ("must not live in a group/other writable
// directory", mode 775 — measured on this machine, exit 2, no keystore).
//
// This script performs the stranger's first hour END TO END against an
// installed package (never against the checkout):
//   1. npm pack + install the tarball into a fresh directory (what npm does
//      for a git/tag install, without network flakiness of git installs),
//   2. `signerd keygen` in a 0700 sandbox, capture the printed public key,
//   3. a message grant pinned to that key, `signerd run`, wait for the socket,
//   4. `signerd sign-message` over a receipt body, verifying the returned
//      artifact with Node OpenSSL ed25519 against the KEYPAIR — the product's
//      own signature path, checked outside the product's verify helpers,
//   5. refusals a stranger must see, not guess: window_cap writes no file,
//      replay after daemon restart is refused, an unreachable socket exits
//      non-zero, an EMPTY seal passphrase refuses to start, and a group-writable
//      passphrase directory is refused (the umask trap above, now a PINNED
//      behavior instead of a surprise),
//   6. license + README present in the installed tree (npm pack file gate).
//
// Falsification built in: every step asserts a NEGATIVE first (the wrong
// verification must fail; the refused run must write nothing), so a green run
// cannot come from a silently skipped step. Exits non-zero on any deviation.
//
// Usage:  node scripts/install-smoke.js [--dir <install-dir>]
//   Default dir: mkdtemp under os.tmpdir(). Everything secret is throwaway.
'use strict';

process.umask(0o077);

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const root = (() => {
  const i = process.argv.indexOf('--dir');
  return i > 0 && process.argv[i + 1]
    ? path.resolve(process.argv[i + 1])
    : fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-install-smoke-'));
})();
fs.mkdirSync(root, { mode: 0o700, recursive: true });

const notes = [];
function step(msg) { notes.push(msg); process.stdout.write(`== ${msg}\n`); }
function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: 'utf8', timeout: 120000, ...opts });
  if (res.error) throw new Error(`${cmd} ${args.join(' ')}: ${res.error.message}`);
  return res;
}
function must(cond, msg, detail) {
  if (!cond) { if (detail) process.stderr.write(String(detail).slice(0, 4000) + '\n'); throw new Error(`FAILED: ${msg}`); }
}
const isAscii = (s) => !/[^\x00-\x7f]/.test(s);

// ---- 1. pack + install (the stranger's tree) --------------------------------
step(`pack + install into ${root}`);
const pack = run('npm', ['pack', '--pack-destination', root], { cwd: REPO });
must(pack.status === 0, 'npm pack', pack.stderr);
const tarball = path.join(root, fs.readdirSync(root).find((f) => f.endsWith('.tgz')));
must(fs.existsSync(tarball), 'pack produced a tarball');
const consumer = path.join(root, 'consumer');
fs.mkdirSync(consumer, { mode: 0o700 });
const install = run('npm', ['install', '--no-audit', '--no-fund', tarball], { cwd: consumer });
must(install.status === 0, 'npm install of the packed tarball', install.stderr);
const pkgRoot = path.join(consumer, 'node_modules', 'signerd');
must(fs.existsSync(path.join(pkgRoot, 'package.json')), 'installed package root exists');

// gate: the installed tree must carry the license and the README, and must
// NOT carry CI configuration (what npm ships is what npm keeps).
for (const f of ['LICENSE', 'README.md', 'package.json', 'bin/signerd.js', 'src/daemon.js', 'tools/leasecheck.c']) {
  must(fs.existsSync(path.join(pkgRoot, f)), `installed tree contains ${f}`);
}
must(!fs.existsSync(path.join(pkgRoot, '.github')), 'no CI config in the installed tree');

const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
must(pkgJson.name === 'signerd', 'package name');
must(pkgJson.bin && pkgJson.bin.signerd, 'bin.signerd declared');
const bin = path.join(consumer, 'node_modules', '.bin', 'signerd');
must(fs.existsSync(bin), 'npm linked the signerd bin');

// gate: the version a stranger sees must match package.json (the reeflog
// v0.1.0 lesson: tree and release disagreeing is a release defect).
const version = pkgJson.version;
must(/^\d+\.\d+\.\d+/.test(version), `semver version in package.json (got ${version})`);

// ---- 2. keygen --------------------------------------------------------------
step('keygen in a 0700 sandbox');
const sandbox = path.join(root, 'sandbox');
fs.mkdirSync(sandbox, { mode: 0o700 });
const passFile = path.join(sandbox, 'pass');
fs.writeFileSync(passFile, 'install-smoke passphrase\n', { mode: 0o600 });
const keystore = path.join(sandbox, 'ops.key');
const keygen = run(bin, ['keygen', '--keystore', keystore, '--passphrase-file', passFile]);
must(keygen.status === 0, 'keygen exit 0', keygen.stderr);
const keygenOut = JSON.parse(keygen.stdout.trim().split('\n').pop());
must(typeof keygenOut.publicKey === 'string' && keygenOut.publicKey.length > 40, 'keygen printed a public key');
const publicKeyB64 = Buffer.from(crypto.createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(bs58Decode(keygenOut.publicKey))]),
  format: 'der', type: 'spki',
}).export({ format: 'jwk' }).x, 'base64url').toString('base64'); // standard base64, 44 chars with '=' pad — the grant schema refuses base64url

// negative first: the passphrase-directory trap must be REFUSED, not silently
// accepted. This is the measured umask-0002 quickstart failure; pinning it
// here means the surprise is documented by behavior, not prose.
const looseDir = path.join(root, 'loose');
fs.mkdirSync(looseDir, { mode: 0o775 });
fs.chmodSync(looseDir, 0o775);
const loosePass = path.join(looseDir, 'pass');
fs.writeFileSync(loosePass, 'x\n', { mode: 0o664 });
const trap = run(bin, ['keygen', '--keystore', path.join(looseDir, 'k.key'), '--passphrase-file', loosePass]);
must(trap.status !== 0, 'group-writable passphrase dir must be refused');
must(/group\/other writable directory/.test(trap.stderr), 'trap message names the directory mode', trap.stderr);
must(!fs.existsSync(path.join(looseDir, 'k.key')), 'refused keygen wrote no keystore');

// ---- 3. grants + daemon -----------------------------------------------------
step('message grant + daemon');
const expires = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const grants = path.join(sandbox, 'grants.json');
fs.writeFileSync(grants, JSON.stringify({ version: 1, grants: { releases: {
  kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
  pubkey: publicKeyB64, maxBytes: '700', expiresAt: expires,
  windowMaxMessages: '3', windowSeconds: '3600',
} } }, null, 2), { mode: 0o600 });

const ledger = path.join(sandbox, 'journal.jsonl');
const socket = path.join(sandbox, 'signerd.sock');
const daemonOut = path.join(sandbox, 'daemon.out');
function startDaemon() {
  const out = fs.openSync(daemonOut, 'a');
  const child = spawn(bin, ['run', '--keystore', keystore, '--passphrase-file', passFile,
    '--grants', grants, '--ledger', ledger, '--socket', socket],
  { stdio: ['ignore', out, out], detached: false });
  for (let i = 0; i < 100 && !fs.existsSync(socket); i++) spawnSync('sleep', ['0.1']);
  must(fs.existsSync(socket), 'daemon bound its socket', fs.readFileSync(daemonOut, 'utf8'));
  return child;
}
function stopDaemon(child) {
  child.kill('SIGTERM');
  for (let i = 0; i < 100 && fs.existsSync(socket); i++) spawnSync('sleep', ['0.1']);
}
let daemon = startDaemon();

// empty seal passphrase: the daemon must refuse to START (R6-1), measured from
// the installed package too — sealed mode is opt-in fail-closed, never silent.
const emptySeal = path.join(sandbox, 'seal.empty');
fs.writeFileSync(emptySeal, '', { mode: 0o600 });
const emptySock = path.join(sandbox, 'empty.sock');
const refused = run(bin, ['run', '--keystore', keystore, '--passphrase-file', passFile,
  '--grants', grants, '--ledger', path.join(sandbox, 'j2.jsonl'), '--socket', emptySock,
  '--grant-seal-passphrase-file', emptySeal]);
must(refused.status !== 0, 'empty seal passphrase refuses startup');
must(/seal_passphrase_required/.test(refused.stderr + refused.stdout), 'refusal names seal_passphrase_required', refused.stderr);
must(!fs.existsSync(emptySock), 'refused daemon left no socket');

// ---- 4. sign + independent verification ------------------------------------
step('sign-message + verification outside the product');
const body = {
  schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
  subject: 'auroraxo/signerd', issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  claims: { version, channel: 'smoke' },
  note: 'signed through an installed signerd package, no key material in this client',
};
const bodyFile = path.join(sandbox, 'body.json');
const receiptFile = path.join(sandbox, 'receipt.json');
fs.writeFileSync(bodyFile, JSON.stringify(body, null, 2));
const sign = run(bin, ['sign-message', '--socket', socket, '--grant', 'releases',
  '--body', bodyFile, '--out', receiptFile]);
must(sign.status === 0, 'sign-message exit 0', sign.stderr);
must(fs.existsSync(receiptFile), 'receipt file written');
const doc = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));
must(doc.receipt && doc.pubkey && doc.sig, 'artifact has receipt, pubkey, sig');
must(Buffer.from(doc.pubkey, 'base64').length === 32, 'artifact pubkey is 32 raw bytes');

// canonical bytes, re-derived HERE (sorted keys, ASCII — Python's
// json.dumps(sort_keys=True, separators=(",",":"))), not imported from the
// product: if the product canonicalized differently, this verify fails.
const canonical = JSON.stringify(sortDeep(doc.receipt)).replace(/[^\x00-\x7f]/g,
  (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
const keyObj = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: doc.pubkey }, format: 'jwk' });
const sig = Buffer.from(doc.sig, 'base64');
const good = crypto.verify(null, Buffer.from(canonical, 'utf8'), keyObj, sig);
must(good, 'signature verifies under Node OpenSSL ed25519 against the daemon key');
must(doc.pubkey === publicKeyB64, 'artifact key equals the keygen public key');

// negative controls: the verifier must FAIL on a wrong body and a wrong key —
// otherwise the positive result above means nothing.
const tampered = Buffer.from(canonical, 'utf8'); tampered[tampered.length - 1] ^= 1;
must(!crypto.verify(null, tampered, keyObj, sig), 'tampered canonical bytes must NOT verify');
const other = crypto.generateKeyPairSync('ed25519');
must(!crypto.verify(null, Buffer.from(canonical, 'utf8'), other.publicKey, sig), 'foreign key must NOT verify');

// ---- 5. refusal ladder a stranger must see ---------------------------------
step('refusal ladder');
// 5a. window_cap: windowMaxMessages=3 -> 1 signed above + 2 more + 4th refused, no file.
for (let i = 0; i < 2; i++) {
  const b = { ...body, claims: { version, seq: String(i) }, issued_at: new Date(Date.now() + (i + 1) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') };
  fs.writeFileSync(bodyFile, JSON.stringify(b));
  const r = run(bin, ['sign-message', '--socket', socket, '--grant', 'releases', '--body', bodyFile, '--out', path.join(sandbox, `w${i}.json`)]); // eslint-disable-line
  must(r.status === 0, `sign ${i + 1} accepted`, `stdout=${r.stdout}\nstderr=${r.stderr}\ndaemon.out=${fs.readFileSync(daemonOut, 'utf8')}`);
}
const overOut = path.join(sandbox, 'over.json');
fs.writeFileSync(bodyFile, JSON.stringify({ ...body, claims: { version, seq: 'over' }, issued_at: new Date(Date.now() + 3000).toISOString().replace(/\.\d{3}Z$/, 'Z') }));
const over = run(bin, ['sign-message', '--socket', socket, '--grant', 'releases', '--body', bodyFile, '--out', overOut]);
must(over.status !== 0, 'fourth message in a 3-window is refused');
must(/window_cap/.test(over.stdout + over.stderr), 'overdraw names window_cap', `stdout=${over.stdout}\nstderr=${over.stderr}`);
must(!fs.existsSync(overOut), 'refused overdraw wrote no file');

// 5b. replay after restart: byte-identical body refused across a restart.
stopDaemon(daemon);
fs.writeFileSync(bodyFile, JSON.stringify({ ...body })); // the ORIGINAL body again
daemon = startDaemon();
const replayOut = path.join(sandbox, 'replay.json');
const replay = run(bin, ['sign-message', '--socket', socket, '--grant', 'releases', '--body', bodyFile, '--out', replayOut]);
must(replay.status !== 0, 'identical body refused after daemon restart');
must(/replay/.test(replay.stdout + replay.stderr), 'restart refusal names replay', `stdout=${replay.stdout}\nstderr=${replay.stderr}`);
must(!fs.existsSync(replayOut), 'refused replay wrote no file');

// 5c. unreachable socket: exit != 0, no file.
const awaySock = path.join(sandbox, 'nope.sock');
const awayOut = path.join(sandbox, 'away.json');
fs.writeFileSync(bodyFile, JSON.stringify(body));
const away = run(bin, ['sign-message', '--socket', awaySock, '--grant', 'releases', '--body', bodyFile, '--out', awayOut]);
must(away.status !== 0, 'unreachable socket exits non-zero');
must(!fs.existsSync(awayOut), 'unreachable socket wrote no file');

stopDaemon(daemon);

// ---- report -----------------------------------------------------------------
const report = {
  generatedAt: new Date().toISOString(),
  what: 'stranger-install smoke: npm-pack install -> keygen -> grant -> daemon -> sign-message -> verification + refusal ladder, all against the INSTALLED package',
  packageVersion: version,
  installRoot: root.replace(os.tmpdir(), '$TMPDIR'),
  checks: {
    installedTreeHasLicenseReadmeBin: true,
    ciConfigAbsentFromInstall: true,
    keygenOk: true,
    passphraseDirTrapRefused: true,
    emptySealPassphraseRefused: true,
    signOk: true,
    independentVerify: good,
    tamperedBytesRejected: true,
    foreignKeyRejected: true,
    windowCapNoFile: true,
    replayAfterRestartNoFile: true,
    unreachableSocketNoFile: true,
  },
  notes,
};
fs.writeFileSync(path.join(root, 'report.json'), JSON.stringify(report, null, 2) + '\n');
process.stdout.write('INSTALL SMOKE PASSED (' + version + ')\n');
process.stdout.write(JSON.stringify(report.checks) + '\n');

function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}
function bs58Decode(s) {
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const c of s) { const i = ALPH.indexOf(c); if (i < 0) throw new Error('bad base58'); n = n * 58n + BigInt(i); }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of s) { if (c !== '1') break; bytes.unshift(0); }
  return Buffer.from(bytes);
}
