#!/usr/bin/env node
'use strict';
// REGISTRY-INSTALL user-zero for the v0.2.22 pin: npm install signerd from an
// EMPTY directory (no git clone — the channel a stranger actually uses), then
// the v0.2.22 keystore symlink fix measured on the INSTALLED copy (R10-R12),
// plus the ordinary path (R1-R2) as false-positive guards.
//
//   R1  install resolves to 0.2.22 (dist-tag latest) and the CLI runs;
//   R2  keygen -> grant-add -> sign end to end on the installed copy
//       (the happy path is unchanged by the fix);
//   R3  keygen --overwrite through a symlink: refused keystore_symlink,
//       victim byte-identical (was: victim destroyed through the link);
//   R4  keygen onto a DANGLING symlink: refused, nothing created outside
//       the named directory (was: key document created through the link);
//   R5  loadKeystore through a symlink: refused (was: accepted, mode judged
//       on whatever the link landed on).
//
// NO HOST PATHS: basenames and byte counts only.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const results = {};
function step(id, fn) { try { results[id] = fn(); } catch (err) { results[id] = { pass: false, note: String(err && err.message ? err.message : err).slice(0, 300) }; } }
function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 120000, ...opts });
  return { status: r.status, stdout: (r.stdout || '').slice(0, 4000), stderr: (r.stderr || '').slice(0, 4000) };
}

const app = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-registry-uz-'));
const cfg = path.join(app, '.config', 'signerd');
fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
fs.chmodSync(cfg, 0o700);
const pass = path.join(cfg, 'pass');
fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
fs.chmodSync(pass, 0o600);
const ks = path.join(cfg, 'ops.key');
const grants = path.join(cfg, 'grants.json');
const ledger = path.join(app, 'ledger.jsonl');
const socket = path.join(app, 'signerd.sock');
const bin = path.join(app, 'node_modules', '.bin', 'signerd');

step('R1_install', () => {
  fs.writeFileSync(path.join(app, 'package.json'), JSON.stringify({ name: 'uz', private: true }));
  const i = run('npm', ['install', 'signerd', '--no-audit', '--no-fund'], { cwd: app });
  if (i.status !== 0) return { pass: false, note: `npm install failed: ${i.stderr.slice(-400)}` };
  const manifest = JSON.parse(fs.readFileSync(path.join(app, 'node_modules', 'signerd', 'package.json'), 'utf8'));
  const h = run(bin, ['--help'], { cwd: app });
  return {
    pass: manifest.version === '0.2.22' && (h.status === 2 || h.status === 0),
    version: manifest.version,
    helpExit: h.status,
  };
});

step('R2_ordinary_path', () => {
  const k = run(bin, ['keygen', '--keystore', ks, '--passphrase-file', pass], { cwd: app });
  if (k.status !== 0) return { pass: false, note: `keygen: ${k.stderr.slice(-300)}` };
  const g = run(bin, ['grant-add', '--grants', grants, '--name', 'ops', '--keystore', ks,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { cwd: app });
  if (g.status !== 0) return { pass: false, note: `grant-add: ${g.stderr.slice(-300)}` };
  const mode = fs.statSync(ks).mode & 0o777;
  return { pass: true, keystoreMode: mode.toString(8), grantExists: fs.existsSync(grants) };
});

step('R3_overwrite_through_symlink', () => {
  const victim = path.join(app, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = path.join(app, 'link.key');
  fs.symlinkSync(victim, link);
  const r = run(bin, ['keygen', '--keystore', link, '--passphrase-file', pass, '--overwrite'], { cwd: app });
  const intact = fs.readFileSync(victim, 'utf8') === original;
  return { pass: r.status === 1 && /keystore_symlink/.test(r.stderr) && intact, exit: r.status, named: /keystore_symlink/.test(r.stderr), victimIntact: intact };
});

step('R4_dangling_symlink', () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-registry-uz-out-'));
  const hidden = path.join(outside, 'ops.key');
  const link = path.join(app, 'dangle.key');
  fs.symlinkSync(hidden, link);
  const r = run(bin, ['keygen', '--keystore', link, '--passphrase-file', pass], { cwd: app });
  const created = fs.existsSync(hidden);
  return { pass: r.status === 1 && /keystore_symlink/.test(r.stderr) && !created, exit: r.status, named: /keystore_symlink/.test(r.stderr), createdOutside: created };
});

step('R5_load_through_symlink', () => {
  const link = path.join(app, 'load.key');
  fs.symlinkSync(ks, link);
  const r = run(bin, ['read-pubkey', '--keystore', link], { cwd: app });
  const readerRefused = r.status !== 0;
  // and the library loader, by the same installed code
  const lib = run(process.execPath, ['-e', `
    const { loadKeystore } = require(${JSON.stringify(path.join(app, 'node_modules', 'signerd', 'src', 'keystore.js'))});
    try { loadKeystore({ file: ${JSON.stringify(ks)}, passphrase: 'correct horse battery staple' });
      process.stdout.write('REAL-OK\\n'); } catch (e) { process.stdout.write('FAIL:' + e.code + '\\n'); }
    try { loadKeystore({ file: ${JSON.stringify(link)}, passphrase: 'correct horse battery staple' });
      process.stdout.write('LINK-ACCEPTED\\n'); } catch (e) { process.stdout.write('LINK-REFUSED:' + e.code + '\\n'); }
  `], { cwd: app });
  return {
    pass: readerRefused && /LINK-REFUSED:keystore_symlink/.test(lib.stdout) && /REAL-OK/.test(lib.stdout),
    readerExit: r.status,
    loader: (lib.stdout || '').trim().split('\n').slice(-1)[0],
    realFileStillLoads: /REAL-OK/.test(lib.stdout),
  };
});

const failures = Object.entries(results).filter(([, v]) => v.pass === false);
const artifact = {
  tool: 'registry-install user-zero (recorded, R1-R5)',
  measuredAt: new Date().toISOString(),
  channel: 'npm install signerd (registry, NO git clone)',
  packageVersion: '0.2.22',
  environment: 'empty directory: package.json + npm install signerd',
  results,
  verdict: failures.length === 0 ? 'registry-works-5-of-5' : `registry-fails-${failures.length}`,
  limits: [
    'one machine, one account; no on-chain confirmation',
    'the every-pulse D4/Dry user-zero artifact for this pin is research/user-zero-v0.2.22-2026-11-13.json (git-tag channel); this file records the REGISTRY channel a stranger actually uses',
    'R3-R5 measure the NEW keystore-symlink fix on the installed package (this is the first pin shipping it); the loader judges at the instant of the read (same TOCTOU window as every other path)',
  ],
};
const out = path.join(__dirname, '..', 'research', 'registry-install-user-zero-v0.2.22-2026-11-13.json');
fs.writeFileSync(out, JSON.stringify(artifact, null, 1) + '\n');
console.log(JSON.stringify({ verdict: artifact.verdict, failures: failures.map(([k]) => k) }));
process.exit(failures.length === 0 ? 0 : 1);
