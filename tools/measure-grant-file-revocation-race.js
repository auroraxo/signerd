#!/usr/bin/env node
'use strict';
// Two-tree lost-update measurement for the REVOCATION face of the grant-file
// write paths (CLI-level): 6 concurrent `grant-add --append` against 2
// concurrent `grant-remove` on ONE grant file that starts with
// {doomed1, doomed2, good}.
//
// WHY THIS IS NOT THE APPEND-ONLY PROBE (tools/measure-grant-file-lock.js):
// that tool measured append||append only, while src/grant-file-lock.js names
// the revocation case as THE security face - the loader re-reads the file on
// every request, so a lost update that resurrects a removed grant is a silent
// revocation undo. This probe runs remove against append, the interleaving
// where a judge-then-rename overwrites the other writer's result in BOTH
// directions.
//
// Faces:
//   R1 a removed grant is BACK on disk at the end (revocation undone)
//   R2 an append reported {"ok":true} but its grant is missing (lost append)
//   R3 a remove reported {"ok":true} but its target is still present
//      (ok reported for a revocation that did not happen)
//   R4 the lock file is left behind (a leaked lock bricks later writes)
//
// Usage: node tools/measure-grant-file-revocation-race.js [--out <file>] <tree>
//   ROUNDS / APPENDERS env: rounds (default 5), concurrent appends (default 6).
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const argv = process.argv.slice(2);
const outIdx = argv.indexOf('--out');
const OUT = outIdx === -1 ? null : argv[outIdx + 1];
const TREE = argv.filter((a, i) => i !== outIdx && i !== outIdx + 1).pop();
if (!TREE) {
  console.error('usage: measure-grant-file-revocation-race.js [--out <file>] <tree>');
  process.exit(2);
}
const CLI = path.join(path.resolve(TREE), 'bin', 'signerd.js');
const SIGNER = '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi';
const DEST = '8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR';
const ROUNDS = Number(process.env.ROUNDS || 5);
const APPENDERS = Number(process.env.APPENDERS || 6);
const REMOVERS = 2;
const START = ['doomed1', 'doomed2', 'good'];

const add = (g, n, ...extra) => ['grant-add', '--grants', g, '--name', n, '--signer', SIGNER,
  '--destination', DEST, '--max-lamports', '100000', '--window-max-lamports', '1000000',
  '--window-seconds', '60', '--expires', '2099-01-01T00:00:00Z', ...extra];
const rm = (g, n) => ['grant-remove', '--grants', g, '--name', n];

function run(args, cwd) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let so = ''; let se = '';
    c.stdout.on('data', (d) => { so += d; });
    c.stderr.on('data', (d) => { se += d; });
    c.on('close', (code) => resolve({ code, stdout: so, stderr: se }));
  });
}

(async () => {
  const runs = [];
  for (let r = 0; r < ROUNDS; r += 1) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-revrace-'));
    fs.chmodSync(dir, 0o700);
    let s = await run(add('grants.json', 'doomed1'), dir);
    if (s.code !== 0) { console.error('setup doomed1 failed: ' + s.stderr); process.exit(2); }
    for (const n of ['doomed2', 'good']) {
      s = await run(add('grants.json', n, '--append'), dir);
      if (s.code !== 0) { console.error(`setup ${n} failed: ` + s.stderr); process.exit(2); }
    }
    const jobs = [];
    for (let i = 1; i <= APPENDERS; i += 1) jobs.push(run(add('grants.json', `new${i}`, '--append'), dir));
    for (let i = 1; i <= REMOVERS; i += 1) jobs.push(run(rm('grants.json', `doomed${i}`), dir));
    const rs = await Promise.all(jobs);
    const appendRes = rs.slice(0, APPENDERS);
    const removeRes = rs.slice(APPENDERS);
    const names = Object.keys(JSON.parse(fs.readFileSync(path.join(dir, 'grants.json'), 'utf8')).grants).sort();
    const r2 = appendRes.map((a, i) => ({ i: i + 1, ok: a.code === 0 && /"ok":true/.test(a.stdout) }))
      .filter((x) => x.ok && !names.includes(`new${x.i}`)).length;
    const r3 = removeRes.map((d, i) => ({ i: i + 1, ok: d.code === 0 && /"ok":true/.test(d.stdout) }))
      .filter((x) => x.ok && names.includes(`doomed${x.i}`)).length;
    runs.push({
      expected: `good + new1..new${APPENDERS} = ${APPENDERS + 1}`,
      count: names.length,
      names,
      appendOk: appendRes.filter((a) => a.code === 0).length,
      removeOk: removeRes.filter((d) => d.code === 0).length,
      r1_revoked_back: START.filter((n) => n !== 'good').filter((n) => names.includes(n)),
      r2_added_missing_after_ok: r2,
      r3_removed_present_after_ok: r3,
      r4_lock_left: fs.existsSync(path.join(dir, 'grants.json.lock')),
      stderrSamples: rs.filter((x) => x.code !== 0).slice(0, 3).map((x) => x.stderr.split('\n')[0]),
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const defectFaces = {
    R1_revoked_grant_back: runs.filter((r) => r.r1_revoked_back.length > 0).length,
    R2_added_missing_after_ok: runs.reduce((n, r) => n + r.r2_added_missing_after_ok, 0),
    R3_removed_present_after_ok: runs.reduce((n, r) => n + r.r3_removed_present_after_ok, 0),
    R4_lock_left_behind: runs.filter((r) => r.r4_lock_left).length,
  };
  const clean = Object.values(defectFaces).every((v) => v === 0);
  const result = {
    tool: 'tools/measure-grant-file-revocation-race.js',
    tree: path.resolve(TREE),
    generatedAt: new Date().toISOString().slice(0, 10),
    rounds: ROUNDS,
    appendersPerRound: APPENDERS,
    removersPerRound: REMOVERS,
    runs,
    defectFaces,
    verdict: clean ? 'revocation-and-append-serialize' : 'revocation-race-lost-update',
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (OUT) fs.writeFileSync(OUT, JSON.stringify(result, null, 2) + '\n');
  process.exit(clean ? 0 : 1);
})();
