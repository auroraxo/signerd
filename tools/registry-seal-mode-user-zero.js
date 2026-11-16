#!/usr/bin/env node
'use strict';
// The seal-mode fix on the CHANNEL A STRANGER USES: npm install signerd,
// then a sealed grant file must not be readable without its passphrase.
//
// WHY (measured 2026-11-16, this repo): the v0.2.27 tree refused a keyless
// read of a SEALED grant file only in the WORKTREE. The published tarball is
// what a stranger installs, and the fix lives in src/grantfile.js - a file
// the npm package ships. Measuring the fix on the tree proves the code
// changed; measuring it on the INSTALLED package proves the stranger got
// the change.
//
// WHAT IT MEASURES on `npm install signerd` (no clone):
//   S1 the installed CLI's loader refuses a sealed grant file read without
//      a passphrase (grant_file_sealed) and never hands back the tampered
//      destination;
//   S2 the installed `status` on a sealed file without a passphrase exits
//      non-zero (no {"ok":true,"sealed":false});
//   S3 the installed daemon refuses to START on a sealed grant file without
//      the grant passphrase;
//   S4 the installed `seal-grants` still re-seals after a hand edit (the
//      documented repair - the one path that may judge a sealed payload);
//   S5 the installed `verify-grants` still refuses a tampered file WITH the
//      passphrase (the keyed read is unchanged);
//   G1 GUARD: an UNSEALED grant file still loads without a passphrase.
//
// NO HOST PATHS: basenames and reason codes only.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const OUT = process.argv[2] ||
  path.join(REPO, 'research', `seal-mode-registry-${pinnedVersion()}-${new Date().toISOString().slice(0, 10)}.json`);

function pinnedVersion() {
  const readme = fs.readFileSync(path.join(REPO, 'README.md'), 'utf8');
  const tags = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((t) => t.split('#')[1]))];
  if (tags.length !== 1) {
    console.error(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: 'README pin is not exactly one tag' }));
    process.exit(3);
  }
  return tags[0].replace(/^v/, '');
}

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 180000, ...opts });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function jsonLine(text) {
  const line = String(text).split('\n').filter((l) => l.trim().startsWith('{')).pop();
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
}

const DESTINATION = 'So11111111111111111111111111111111111111112';
const TAMPERED = '11111111111111111111111111111111';

function caseDir(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-regsealmode-${tag}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return { root, cfg, sealPass, grants: path.join(cfg, 'grants.json'), ledger: path.join(root, 'journal.jsonl') };
}

function writeDoc(file, doc) {
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function txDoc(signer) {
  return {
    version: 1,
    grants: {
      ops: {
        signer,
        destination: DESTINATION,
        maxLamports: '1000',
        expiresAt: '2030-01-01T00:00:00Z',
        windowMaxLamports: '1000000',
        windowSeconds: '3600',
      },
    },
  };
}

function tamper(file) {
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  doc.grants.ops.destination = TAMPERED;
  writeDoc(file, doc);
}

function main() {
  const version = pinnedVersion();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-regsealmode-app-'));
  const install = sh('npm', ['install', 'signerd', '--silent'], { cwd: dir });
  const manifestPath = path.join(dir, 'node_modules', 'signerd', 'package.json');
  let installed = null;
  try { installed = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).version; } catch { installed = null; }
  const CLI = path.join(dir, 'node_modules', 'signerd', 'bin', 'signerd.js');
  const run = (args, opts = {}) => sh(process.execPath, [CLI, ...args], { cwd: dir, ...opts });

  const results = {};
  const steps = {
    // S1: the installed loader refuses a keyless read of a sealed file.
    S1_keyless_read_refused() {
      const c = caseDir('s1');
      writeDoc(c.grants, txDoc('11111111111111111111111111111111'));
      const sealed = run(['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      tamper(c.grants);
      const script = `
        const { loadGrantFile } = require(${JSON.stringify(path.join(dir, 'node_modules', 'signerd', 'src', 'grantfile.js'))});
        try {
          const l = loadGrantFile(process.argv[1]);
          process.stdout.write(JSON.stringify({ loaded: true, destination: l.grants.ops ? l.grants.ops.destination : null }));
        } catch (err) { process.stdout.write(JSON.stringify({ loaded: false, code: err.code || 'error' })); }
      `;
      const probe = sh(process.execPath, ['-e', script, c.grants]);
      const v = jsonLine(probe.stdout) || { loaded: false, code: 'no_verdict' };
      return {
        sealedExit: sealed.status,
        loaded: v.loaded === true,
        code: v.code || null,
        readTampered: v.loaded === true && v.destination === TAMPERED,
        pass: sealed.status === 0 && v.loaded === false && v.code === 'grant_file_sealed',
      };
    },
    // S2: `status` refuses instead of answering {"ok":true,"sealed":false}.
    S2_status_refused() {
      const c = caseDir('s2');
      writeDoc(c.grants, txDoc('11111111111111111111111111111111'));
      run(['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      const r = run(['status', '--grants', c.grants, '--ledger', c.ledger]);
      return {
        exit: r.status,
        named: /grant_file_sealed/.test(r.stderr),
        reportedOk: /"ok":true/.test(r.stdout),
        reportedUnsealed: /"sealed":false/.test(r.stdout),
        pass: r.status !== 0 && /grant_file_sealed/.test(r.stderr) && !/"ok":true/.test(r.stdout),
      };
    },
    // S3: the daemon refuses to start without the grant passphrase.
    S3_daemon_refused() {
      const c = caseDir('s3');
      const keystore = path.join(c.cfg, 'ops.key');
      const pass = path.join(c.cfg, 'pass');
      fs.writeFileSync(pass, 'keystore phrase\n', { mode: 0o600 });
      const keygen = run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
      const pub = keygen.status === 0 ? (jsonLine(keygen.stdout) || {}).publicKey : null;
      if (!pub) return { pass: false, note: 'keygen failed on the installed copy' };
      writeDoc(c.grants, txDoc(pub));
      run(['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      tamper(c.grants);
      const r = run(['run', '--keystore', keystore, '--passphrase-file', pass, '--grants', c.grants,
        '--ledger', c.ledger, '--socket', path.join(c.root, 'signerd.sock')]);
      return {
        exit: r.status,
        named: /grant_file_sealed/.test(r.stderr),
        reportedServing: /"ok":true/.test(r.stdout),
        pass: r.status !== 0 && /grant_file_sealed/.test(r.stderr),
      };
    },
    // S4: the documented repair (re-seal after a hand edit) still works.
    S4_reseal_still_works() {
      const c = caseDir('s4');
      writeDoc(c.grants, txDoc('11111111111111111111111111111111'));
      run(['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      const doc = JSON.parse(fs.readFileSync(c.grants, 'utf8'));
      doc.grants.ops.destination = DESTINATION;
      writeDoc(c.grants, doc);
      const reseal = run(['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      const verify = run(['verify-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      return {
        resealExit: reseal.status,
        verifyExit: verify.status,
        pass: reseal.status === 0 && verify.status === 0,
      };
    },
    // S5: the keyed read still refuses a tampered file.
    S5_keyed_read_still_refuses() {
      const c = caseDir('s5');
      writeDoc(c.grants, txDoc('11111111111111111111111111111111'));
      run(['seal-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      tamper(c.grants);
      const r = run(['verify-grants', '--grants', c.grants, '--seal-passphrase-file', c.sealPass]);
      return {
        exit: r.status,
        named: /grant_file_seal_mismatch/.test(r.stderr),
        pass: r.status !== 0 && /grant_file_seal_mismatch/.test(r.stderr),
      };
    },
    // G1 (guard): an UNSEALED file still loads without a passphrase.
    G1_unsealed_still_loads() {
      const c = caseDir('g1');
      writeDoc(c.grants, txDoc('11111111111111111111111111111111'));
      const script = `
        const { loadGrantFile } = require(${JSON.stringify(path.join(dir, 'node_modules', 'signerd', 'src', 'grantfile.js'))});
        try { const l = loadGrantFile(process.argv[1]); process.stdout.write(JSON.stringify({ loaded: true, destination: l.grants.ops.destination })); }
        catch (err) { process.stdout.write(JSON.stringify({ loaded: false, code: err.code || 'error' })); }
      `;
      const probe = sh(process.execPath, ['-e', script, c.grants]);
      const v = jsonLine(probe.stdout) || { loaded: false };
      const status = run(['status', '--grants', c.grants, '--ledger', c.ledger]);
      return {
        loaded: v.loaded === true,
        destination: v.destination || null,
        statusExit: status.status,
        pass: v.loaded === true && v.destination === DESTINATION && status.status === 0,
      };
    },
  };

  for (const [id, fn] of Object.entries(steps)) {
    try { results[id] = fn(); } catch (err) {
      results[id] = { pass: false, note: String(err && err.message ? err.message : err).slice(0, 300) };
    }
  }

  const failures = Object.entries(results).filter(([, r]) => r.pass !== true).map(([k]) => k);
  const artifact = {
    tool: 'seal-mode on the registry channel (npm install signerd)',
    measuredAt: new Date().toISOString(),
    channel: 'npm install signerd (registry, NO git clone)',
    packageVersion: installed,
    expectedVersion: version,
    installExit: install.status,
    results,
    failures,
    verdict: install.status === 0 && installed === version && failures.length === 0
      ? 'registry-seal-mode-holds' : 'registry-seal-mode-defect-present',
  };
  fs.writeFileSync(OUT, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(JSON.stringify({ verdict: artifact.verdict, failures }, null, 2));
  process.exit(artifact.verdict === 'registry-seal-mode-holds' ? 0 : 1);
}

main();
