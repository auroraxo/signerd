#!/usr/bin/env node
'use strict';
// Two-tree lost-update measurement for the grant-file write paths (CLI-level).
// Faces:
//   A1 ok-vs-disk mismatch: writers reported ok but the file disagrees
//   A2 missing writes: fewer grants on disk than writers+create reported
//   A3 lock file left behind (a leaked lock bricks later writes)
const { spawnSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const argv = process.argv.slice(2);
const outIdx = argv.indexOf('--out');
const OUT = outIdx === -1 ? null : argv[outIdx + 1];
const TREE = argv.filter((a, i) => i !== outIdx && i !== outIdx + 1).pop();
const CLI = path.join(TREE, 'bin', 'signerd.js');
const SIGNER = '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi';
const DEST = '8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR';
const N = 8;
const ROUNDS = Number(process.env.ROUNDS || 3);

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-lockmeasure-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}
function cli(args, cwd) {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', timeout: 30000 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}
const addA = (g, n) => ['grant-add', '--grants', g, '--name', n, '--signer', SIGNER,
  '--destination', DEST, '--max-lamports', '100000', '--window-max-lamports', '1000000',
  '--window-seconds', '60', '--expires', '2099-01-01T00:00:00Z'];

function round() {
  const dir = sandbox();
  const create = cli(addA('grants.json', 'good'), dir);
  const createOk = create.status === 0 && /"ok":true/.test(create.stdout);
  const kids = [];
  for (let i = 1; i <= N; i += 1) {
    kids.push(new Promise((resolve) => {
      const c = spawn(process.execPath, [CLI, ...addA('grants.json', `g${i}`), '--append'],
        { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
      let so = ''; let se = '';
      c.stdout.on('data', (d) => { so += d; });
      c.stderr.on('data', (d) => { se += d; });
      c.on('close', (code) => resolve({ code, stdout: so, stderr: se }));
    }));
  }
  return Promise.all(kids).then((rs) => {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, 'grants.json'), 'utf8'));
    const names = Object.keys(doc.grants).sort();
    const appendOk = rs.filter((r) => r.code === 0 && /"ok":true/.test(r.stdout)).length;
    const refused = rs.filter((r) => r.code !== 0).length;
    const expectedOk = (createOk ? 1 : 0) + appendOk;
    return {
      createOk,
      appendOkReports: appendOk,
      refusedWriters: refused,
      grantsOnDisk: names.length,
      expected: N + 1,
      a1_mismatch: expectedOk !== names.length,
      a2_missing: names.length !== N + 1,
      a3_lockLeft: fs.existsSync(path.join(dir, 'grants.json.lock')),
      names,
      stderrSamples: rs.filter((r) => r.code !== 0).slice(0, 2).map((r) => r.stderr.split('\n')[0]),
    };
  });
}

(async () => {
  const runs = [];
  for (let i = 0; i < ROUNDS; i += 1) runs.push(await round());
  const defectFaces = {
    A1_ok_vs_disk_mismatch: runs.filter((r) => r.a1_mismatch).length,
    A2_grants_missing: runs.filter((r) => r.a2_missing).length,
    A3_lock_left_behind: runs.filter((r) => r.a3_lockLeft).length,
  };
  const clean = Object.values(defectFaces).every((v) => v === 0);
  const result = {
    tool: 'tools/measure-grant-file-lock.js',
    tree: path.resolve(TREE),
    generatedAt: '2026-11-17',
    rounds: ROUNDS,
    writersPerRound: N,
    runs,
    defectFaces,
    verdict: clean ? 'grant-file-writes-serialize' : 'lost-updates-present',
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (OUT) fs.writeFileSync(OUT, JSON.stringify(result, null, 2) + '\n');
  process.exit(clean ? 0 : 1);
})();
