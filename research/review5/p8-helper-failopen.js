'use strict';
// P8: fail-OPEN / fail-CLOSED behaviour of the lease helper (R4-1/R4-2's
// enforcement point), tested in a SCRATCH copy of src+tools so nothing in the
// repo is modified:
//   A  helper missing + no compiler        -> must REFUSE (not pass)
//   B  helper exits 4 (leases unsupported) -> must REFUSE (never fake a pass)
//   C  helper exits 3 (writer held)        -> must REFUSE
//   D  helper that never takes a lease but prints LC1 lease=held + forged
//      bytes                              -> observed: ACCEPTED. This shows the
//      helper's output is fully trusted: whoever can write tools/leasecheck
//      defeats R4-1, R4-2, R3-1 and the journal owner/mode checks at once.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..', '..');
const SCRATCH = path.join(__dirname, 'scratch-helper');
const out = {};

fs.rmSync(SCRATCH, { recursive: true, force: true });
fs.mkdirSync(path.join(SCRATCH, 'src'), { recursive: true });
fs.mkdirSync(path.join(SCRATCH, 'tools'), { recursive: true });
fs.chmodSync(SCRATCH, 0o700);
fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(SCRATCH, 'node_modules'));
for (const f of fs.readdirSync(path.join(REPO, 'src'))) {
  fs.copyFileSync(path.join(REPO, 'src', f), path.join(SCRATCH, 'src', f));
}
fs.copyFileSync(path.join(REPO, 'tools', 'leasecheck.c'), path.join(SCRATCH, 'tools', 'leasecheck.c'));

const grantsFile = path.join(SCRATCH, 'grants.json');
fs.writeFileSync(grantsFile, JSON.stringify({
  version: 1,
  grants: {
    ops: {
      signer: '11111111111111111111111111111111',
      destination: '11111111111111111111111111111112',
      maxLamports: '1000',
      expiresAt: '2099-01-01T00:00:00Z',
      windowMaxLamports: '1000',
      windowSeconds: '60',
    },
  },
}));
fs.chmodSync(grantsFile, 0o600);

function load(cc) {
  const script = `
    const { loadGrantFile } = require(${JSON.stringify(path.join(SCRATCH, 'src', 'grantfile.js'))});
    try {
      const l = loadGrantFile(${JSON.stringify(grantsFile)});
      process.stdout.write(JSON.stringify({ ok: true, names: l.names }));
    } catch (err) {
      process.stdout.write(JSON.stringify({ ok: false, code: err.code, msg: String(err.message).slice(0, 160) }));
    }
  `;
  const res = spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    env: { ...process.env, CC: cc },
    timeout: 30000,
  });
  let parsed;
  try { parsed = JSON.parse(res.stdout); } catch { parsed = { raw: res.stdout, err: res.stderr }; }
  return parsed;
}

const helperPath = path.join(SCRATCH, 'tools', 'leasecheck');
const srcPath = `${helperPath}.c`;

// A: no helper binary, no working compiler
fs.rmSync(helperPath, { force: true });
out.A_missing_helper_cc_false = load('/bin/false');

// A2: no helper, compiler exists -> builds and passes (sanity: normal path works)
out.A2_missing_helper_cc_cc = load('cc');

// B: helper exits 4
fs.writeFileSync(helperPath, '#!/bin/sh\nexit 4\n');
fs.chmodSync(helperPath, 0o755);
out.B_helper_exit4_lease_unsupported = load('cc');

// C: helper exits 3
fs.writeFileSync(helperPath, '#!/bin/sh\nexit 3\n');
fs.chmodSync(helperPath, 0o755);
out.C_helper_exit3_held_writer = load('cc');

// D: helper that takes NO lease and just fabricates metadata + forged bytes
const forged = {
  version: 1,
  grants: {
    ops: {
      // valid schema, DIFFERENT destination than what is on disk ('...1112')
      signer: '11111111111111111111111111111111',
      destination: 'So11111111111111111111111111111111111111112',
      maxLamports: '999999',
      expiresAt: '2099-01-01T00:00:00Z',
      windowMaxLamports: '999999',
      windowSeconds: '60',
    },
  },
};
fs.writeFileSync(helperPath, [
  '#!/bin/sh',
  // no fcntl, no lease, no O_NOFOLLOW: invent the metadata line and emit bytes
  `echo 'LC1 dev=1 ino=1 uid=${process.getuid()} mode=0600 size=1 lease=held'`,
  `printf '%s' ${JSON.stringify(JSON.stringify(forged))}`,
  'exit 0',
].join('\n'));
fs.chmodSync(helperPath, 0o755);
out.D_helper_forges_lease_and_bytes = load('cc');

// restore a real helper for the scratch tree, then verify the real one passes
fs.rmSync(helperPath, { force: true });
out.E_real_helper_after_restore = load('cc');

// F: helper path is a directory (planted) -> must refuse, not pass
fs.rmSync(helperPath, { force: true });
fs.mkdirSync(helperPath);
out.F_helper_is_directory = load('cc');
fs.rmdirSync(helperPath);

console.log(JSON.stringify(out, null, 2));
fs.rmSync(SCRATCH, { recursive: true, force: true });
