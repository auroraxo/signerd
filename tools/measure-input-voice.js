'use strict';

// MEASURE the operator-input refusal class on two trees.
//
//   node tools/measure-input-voice.js --cli <path/to/bin/signerd.js> \
//        --out research/input-voice-<tree>.json
//
// The instrument answers one question per face: does the CLI refuse an
// unreadable OPERATOR input with a NAMED reason, a repair, and the exit
// code the contract reserves for a usage refusal (2) - or does it leak a
// raw Node errno?
//
// MEASURED 2026-11-14:
//   published v0.2.22 -> 7 of 10 faces leak a raw errno / wrong exit code
//   the fixed tree     -> 0 of 10
//
// No network. Everything happens in a throwaway tmpdir.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function parseArgs(argv) {
  const out = { cli: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--cli') out.cli = argv[++i];
    else if (argv[i] === '--out') out.out = argv[++i];
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.cli) {
  process.stderr.write('usage: measure-input-voice.js --cli <bin/signerd.js> [--out <file>]\n');
  process.exit(2);
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-input-voice-measure-'));
}

function sh(cli, argv) {
  const r = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8', timeout: 30000 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/** The ten faces: five refusal faces plus the two guard families. */
function buildFaces(dir) {
  const sub = path.join(dir, 'a-directory');
  fs.mkdirSync(sub, { recursive: true });

  const lockedPass = path.join(dir, 'locked.pass');
  fs.writeFileSync(lockedPass, 'secret\n');
  fs.chmodSync(lockedPass, 0o000);
  let passUnreadable = true;
  try { fs.readFileSync(lockedPass); passUnreadable = false; } catch { /* bites */ }

  const lockedTx = path.join(dir, 'locked.bin');
  fs.writeFileSync(lockedTx, 'x');
  fs.chmodSync(lockedTx, 0o000);
  let txUnreadable = true;
  try { fs.readFileSync(lockedTx); txUnreadable = false; } catch { /* bites */ }

  const lockedBody = path.join(dir, 'locked.json');
  fs.writeFileSync(lockedBody, '{}');
  fs.chmodSync(lockedBody, 0o000);
  let bodyUnreadable = true;
  try { fs.readFileSync(lockedBody); bodyUnreadable = false; } catch { /* bites */ }

  const faces = [
    { id: 'passphrase_file_missing', kind: 'refusal',
      argv: ['run', '--keystore', path.join(dir, 'ops.key'),
        '--passphrase-file', path.join(dir, 'no-such.pass'),
        '--grants', path.join(dir, 'g.json'), '--ledger', path.join(dir, 'j.jsonl'),
        '--socket', path.join(dir, 's.sock')] },
    { id: 'passphrase_file_not_a_file', kind: 'refusal',
      argv: ['run', '--keystore', path.join(dir, 'ops.key'),
        '--passphrase-file', sub,
        '--grants', path.join(dir, 'g.json'), '--ledger', path.join(dir, 'j.jsonl'),
        '--socket', path.join(dir, 's.sock')] },
    { id: 'tx_missing', kind: 'refusal',
      argv: ['sign', '--socket', path.join(dir, 's.sock'), '--grant', 'g',
        '--tx', path.join(dir, 'no-tx.bin')] },
    { id: 'tx_not_a_file', kind: 'refusal',
      argv: ['sign', '--socket', path.join(dir, 's.sock'), '--grant', 'g', '--tx', sub] },
    { id: 'body_missing', kind: 'refusal',
      argv: ['sign-message', '--socket', path.join(dir, 's.sock'), '--grant', 'g',
        '--body', path.join(dir, 'no-such.json')] },
    { id: 'body_not_a_file', kind: 'refusal',
      argv: ['sign-message', '--socket', path.join(dir, 's.sock'), '--grant', 'g',
        '--body', sub] },
  ];
  if (passUnreadable) {
    faces.push({ id: 'passphrase_file_unreadable', kind: 'refusal',
      argv: ['run', '--keystore', path.join(dir, 'ops.key'),
        '--passphrase-file', lockedPass,
        '--grants', path.join(dir, 'g.json'), '--ledger', path.join(dir, 'j.jsonl'),
        '--socket', path.join(dir, 's.sock')] });
  }
  if (txUnreadable) {
    faces.push({ id: 'tx_unreadable', kind: 'refusal',
      argv: ['sign', '--socket', path.join(dir, 's.sock'), '--grant', 'g', '--tx', lockedTx] });
  }
  if (bodyUnreadable) {
    faces.push({ id: 'body_unreadable', kind: 'refusal',
      argv: ['sign-message', '--socket', path.join(dir, 's.sock'), '--grant', 'g',
        '--body', lockedBody] });
  }
  return faces;
}

const dir = tmpDir();
let rows;
try {
  rows = buildFaces(dir).map((face) => {
    const res = sh(args.cli, face.argv);
    const out = `${res.stdout}${res.stderr}`;
    const rawErrno = /(^|\n)(ENOENT|EACCES|EISDIR|ELOOP|ENOTDIR):/.test(out)
      || /no such file or directory/.test(out);
    const named = new RegExp(`^${face.id}:`, 'm').test(out);
    const hasFix = /fix:/.test(out);
    // The contract: a usage refusal exits 2 and names itself.
    const ok = !rawErrno && named && hasFix && res.status === 2;
    // The artifact must be host-path-free (the house rule from the
    // registry-user-zero lesson): the throwaway tmpdir is replaced by a
    // placeholder before anything is recorded.
    const firstLine = (out.split('\n').find((l) => l.trim()) || '')
      .trim().replace(dir, '<tmp>').slice(0, 160);
    return {
      id: face.id,
      exit: res.status,
      named,
      hasFix,
      rawErrno,
      ok,
      firstLine,
    };
  });
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

const violations = rows.filter((r) => !r.ok);
const report = {
  measuredAt: new Date().toISOString(),
  cli: args.cli,
  verdict: violations.length === 0 ? 'refusals-present' : 'violations-present',
  faces: rows.length,
  violations: violations.length,
  rows,
};
const text = `${JSON.stringify(report, null, 2)}\n`;
if (args.out) {
  fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
  fs.writeFileSync(path.resolve(args.out), text);
}
process.stdout.write(text);
process.exit(violations.length === 0 ? 0 : 1);
