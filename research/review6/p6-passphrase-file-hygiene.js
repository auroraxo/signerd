'use strict';
// p6: PASSPHRASE FILE HYGIENE for the two NEW seal passphrases
// (--grant-seal-passphrase-file, --journal-seal-passphrase-file).
//
// Every other security-relevant path in this codebase gets owner + directory
// + (usually) lstat checks:
//   keystore   -> file mode, DIRECTORY mode+owner
//   grant file -> file mode (writable refused), DIRECTORY mode+owner, O_NOFOLLOW
//   journal    -> file mode+owner, DIRECTORY mode+owner, lstat
//   anchor     -> lstat (no symlink), owner, NO group/other access at all
//   socket dir -> mode+owner
// but the PASSPHRASE files go through bin/signerd.js readPassphrase():
//
//     const mode = fs.statSync(file).mode & 0o777;
//     if ((mode & 0o077) !== 0) refuse;
//     return fs.readFileSync(file, 'utf8')...
//
// METHOD: the grant file is sealed with the CORRECT passphrase, so the CLI
// SUCCEEDS only if the passphrase path was accepted AND read correctly. Any
// refusal therefore isolates the passphrase path, not the grant file.
//
//   Q1 SYMLINK at the passphrase path (stat follows; no lstat / O_NOFOLLOW)
//   Q2 FOREIGN-OWNED 0600 file (no owner check) - measured as ROOT
//   Q3 passphrase file inside a WORLD-WRITABLE directory (no dir check)
//   Q4 TOCTOU: stat-then-read is two path walks
//   Q5 HARDLINK at the passphrase path
//
// For contrast, the same shapes are measured at the GRANT path, which the
// codebase protects with O_NOFOLLOW + a directory check.

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { tmpdir, verdict } = require('./common');
const { sealDocument } = require('../../src/grantseal');

const BIN = path.join(__dirname, '..', '..', 'bin', 'signerd.js');
const PASS = 'the real seal passphrase';

function runCli(args, opts = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', timeout: 30000, ...opts });
  return {
    status: r.status,
    stdout: (r.stdout || '').trim().slice(0, 300),
    stderr: (r.stderr || '').trim().slice(0, 300),
    accepted: r.status === 0,
  };
}

async function main() {
  const out = { probe: 'p6-passphrase-file-hygiene', results: {}, findings: [] };
  const dir = tmpdir('r6p6-');
  try {
    // A SEALED grant file whose seal verifies with PASS.
    const grantFile = path.join(dir, 'grants.json');
    const sealed = sealDocument({ version: 1, grants: {} }, PASS);
    fs.writeFileSync(grantFile, JSON.stringify(sealed, null, 2) + '\n');
    fs.chmodSync(grantFile, 0o600);
    const ledger = path.join(dir, 'j.jsonl');
    fs.writeFileSync(ledger, ''); fs.chmodSync(ledger, 0o600);

    const status = (passFile, extra = []) => runCli([
      'status', '--grants', grantFile, '--ledger', ledger,
      '--grant-seal-passphrase-file', passFile, ...extra,
    ]);

    // ---- baseline ----
    const good = path.join(dir, 'seal.pass');
    fs.writeFileSync(good, PASS + '\n'); fs.chmodSync(good, 0o600);
    out.results.baseline_good = status(good);
    if (!out.results.baseline_good.accepted) {
      throw new Error('baseline must succeed: ' + JSON.stringify(out.results.baseline_good));
    }

    // ---- Q1: SYMLINK ----
    const target = path.join(dir, 'elsewhere.pass');
    fs.writeFileSync(target, PASS + '\n'); fs.chmodSync(target, 0o600);
    const link = path.join(dir, 'seal.link');
    fs.symlinkSync(target, link);
    out.results.Q1_symlink = status(link);
    out.results.Q1_verdict = out.results.Q1_symlink.accepted
      ? 'SYMLINK ACCEPTED: the passphrase path is followed (stat, not lstat)'
      : 'symlink refused';

    // ---- Q5: HARDLINK ----
    const hard = path.join(dir, 'seal.hard');
    fs.linkSync(good, hard);
    out.results.Q5_hardlink = status(hard);
    out.results.Q5_verdict = out.results.Q5_hardlink.accepted
      ? 'HARDLINK ACCEPTED (a second name for a known-content file)'
      : 'hardlink refused';

    // ---- Q3: passphrase in a WORLD-WRITABLE directory ----
    const open = path.join(dir, 'opendir');
    fs.mkdirSync(open, { recursive: true });
    fs.chmodSync(open, 0o777);
    const openPass = path.join(open, 'seal.pass');
    fs.writeFileSync(openPass, PASS + '\n'); fs.chmodSync(openPass, 0o600);
    out.results.Q3_world_writable_dir = status(openPass);
    out.results.Q3_verdict = out.results.Q3_world_writable_dir.accepted
      ? 'ACCEPTED: no directory check on the passphrase path'
      : 'refused';

    // ---- Q2: FOREIGN-OWNED 0600 file, read as ROOT ----
    // The whole run happens in a ROOT-owned tree, because the grant-file
    // directory check (dir owned by us or root) would otherwise refuse first
    // and mask the passphrase behaviour.
    const rootDir = path.join(dir, 'roottree');
    fs.mkdirSync(rootDir, { recursive: true });
    fs.chmodSync(rootDir, 0o755);
    const rootGrant = path.join(rootDir, 'grants.json');
    const rootSealed = sealDocument({ version: 1, grants: {} }, PASS);
    fs.writeFileSync(rootGrant, JSON.stringify(rootSealed, null, 2) + '\n');
    fs.chmodSync(rootGrant, 0o600);
    const rootLedger = path.join(rootDir, 'j.jsonl');
    fs.writeFileSync(rootLedger, ''); fs.chmodSync(rootLedger, 0o600);
    const foreignDir = path.join(rootDir, 'foreign');
    fs.mkdirSync(foreignDir, { recursive: true });
    fs.chmodSync(foreignDir, 0o755);
    const foreignPass = path.join(foreignDir, 'seal.pass');
    fs.writeFileSync(foreignPass, PASS + '\n'); fs.chmodSync(foreignPass, 0o600);
    execFileSync('sudo', ['-n', 'chown', '-R', 'root:root', rootDir]);
    execFileSync('sudo', ['-n', 'chown', '-R', 'nobody:nogroup', foreignDir]);
    const foreignStat = fs.statSync(foreignPass);
    out.results.Q2_foreign_stat = {
      uid: foreignStat.uid, mode: (foreignStat.mode & 0o777).toString(8),
      current_uid: process.getuid(),
    };
    const asRoot = spawnSync('sudo', ['-n', '-u', 'root', process.execPath, BIN, 'status',
      '--grants', rootGrant, '--ledger', rootLedger, '--grant-seal-passphrase-file', foreignPass],
      { encoding: 'utf8', timeout: 30000 });
    const asRoot2 = {
      status: asRoot.status,
      stdout: (asRoot.stdout || '').trim().slice(0, 300),
      stderr: (asRoot.stderr || '').trim().slice(0, 300),
      accepted: asRoot.status === 0,
    };
    out.results.Q2_foreign_owned_as_root = asRoot2;
    // CONTROL: the same root run with a ROOT-owned passphrase file.
    const rootPass = path.join(rootDir, 'seal.pass');
    execFileSync('sudo', ['-n', 'tee', rootPass], { input: PASS + '\n', encoding: 'utf8' });
    execFileSync('sudo', ['-n', 'chmod', '0600', rootPass]);
    execFileSync('sudo', ['-n', 'chown', 'root:root', rootPass]);
    const asRootControl = spawnSync('sudo', ['-n', '-u', 'root', process.execPath, BIN, 'status',
      '--grants', rootGrant, '--ledger', rootLedger, '--grant-seal-passphrase-file', rootPass],
      { encoding: 'utf8', timeout: 30000 });
    out.results.Q2_control_root_owned_passphrase = {
      status: asRootControl.status,
      stderr: (asRootControl.stderr || '').trim().slice(0, 300),
      accepted: asRootControl.status === 0,
    };
    out.results.Q2_verdict = asRoot2.accepted
      ? 'ACCEPTED as root: no OWNER check on the passphrase file (root reads attacker-planted 0600 file)'
      : `refused as root: ${asRoot2.stderr}`;

    // ---- CONTRAST: the same shapes at the GRANT path ----
    const glink = path.join(dir, 'grants.link');
    fs.symlinkSync(grantFile, glink);
    out.results.contrast_symlink_at_grant_path = runCli([
      'status', '--grants', glink, '--ledger', ledger, '--grant-seal-passphrase-file', good]);
    const gopen = path.join(dir, 'gopen');
    fs.mkdirSync(gopen, { recursive: true }); fs.chmodSync(gopen, 0o777);
    fs.copyFileSync(grantFile, path.join(gopen, 'grants.json'));
    fs.chmodSync(path.join(gopen, 'grants.json'), 0o600);
    out.results.contrast_grant_in_world_writable_dir = runCli([
      'status', '--grants', path.join(gopen, 'grants.json'), '--ledger', ledger,
      '--grant-seal-passphrase-file', good]);

    // ---- Q4: stat-then-read is two path walks ----
    out.results.Q4_structural = 'readPassphrase(): fs.statSync(file) [mode check] then fs.readFileSync(file) [read] - no O_NOFOLLOW, no fd-based check';

    if (out.results.Q1_verdict.startsWith('SYMLINK')) out.findings.push('NEW FINDING: passphrase path follows a symlink (no lstat/O_NOFOLLOW), unlike the grant/journal/anchor paths');
    if (out.results.Q2_verdict.startsWith('ACCEPTED')) out.findings.push('NEW FINDING: no owner check on the passphrase file (a root-run daemon accepts a foreign 0600 file)');
    if (out.results.Q3_verdict.startsWith('ACCEPTED')) out.findings.push('NEW FINDING: no directory check on the passphrase file (world-writable directory accepted)');
  } catch (err) {
    out.threw = String(err && err.stack || err);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p6-passphrase-file-hygiene', fatal: String(err && err.stack || err) }));
