'use strict';

// MEASURE the `signerd import --from` SOURCE-PATH voice.
//
//   node tools/measure-import-source-voice.js --cli <path/to/bin/signerd.js> \
//        --out research/import-source-voice-<tree>.json
//
// WHY THIS CLASS AND NOT THE ONE MEASURED 2026-11-14: the earlier sweep
// (tools/measure-input-voice.js) covered --passphrase-file, --tx and --body.
// The migration path's own source file - the plaintext key a developer
// ALREADY holds and hands to `import --from` - was never swept. Measured
// 2026-11-14 on the published v0.2.23 tree:
//
//   import --from <missing>   -> "import_source_unreadable: ENOENT",  exit 1
//   import --from <directory> -> "import_source_unreadable: EISDIR",  exit 1
//   import --from <mode 000>  -> "import_source_unreadable: EACCES",  exit 1
//
// The code line is a bare errno: the reason names nothing the operator can
// act on (was the file missing, a directory, or forbidden?), there is no
// repair, and exit 1 is reserved for "the daemon or the policy refused" -
// a typo in a path is a USAGE refusal (exit 2). Same contract as the three
// swept families:
//
//   - the first line names the face itself;
//   - a `fix:` line tells the operator what to change;
//   - exit 2;
//   - no raw Node errno in the message.
//
// NO NETWORK. Everything happens in a throwaway tmpdir; the artifact
// records basenames and byte counts only (never a host path).

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
  process.stderr.write('usage: measure-import-source-voice.js --cli <bin/signerd.js> [--out <file>]\n');
  process.exit(2);
}

const ERRNO = /\b(ENOENT|EACCES|EISDIR|ENOTDIR|ELOOP|EPERM|EAGAIN)\b/;

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-import-voice-measure-'));
}

function sh(cli, argv) {
  const r = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8', timeout: 30000 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/** Drop the measuring machine's paths from a captured line. */
function scrub(text) {
  return String(text || '')
    .replace(/\/home\/[^\s"']+/g, '<home>')
    .replace(/\/tmp\/[^\s"']+/g, '<tmp>')
    .replace(/[A-Za-z]:\\[^\s"']+/g, '<win>');
}

/**
 * Three faces of ONE class: the source file the operator hands to
 * `import --from`. Setup that the product itself refuses (a locked
 * passphrase file) must not become a face - the harness sets 0600 itself.
 */
function buildFaces(dir) {
  const cfg = path.join(dir, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);
  const keystore = path.join(cfg, 'ops.key');

  const directory = path.join(dir, 'a-directory');
  fs.mkdirSync(directory, { recursive: true });

  const locked = path.join(dir, 'locked.json');
  fs.writeFileSync(locked, '[]\n', { mode: 0o600 });
  fs.chmodSync(locked, 0o000);
  let lockedBites = true;
  try { fs.readFileSync(locked); lockedBites = false; } catch { /* bites as intended */ }

  const missing = path.join(dir, 'missing.json');

  const faces = [
    { id: 'import_source_missing', from: missing },
    { id: 'import_source_not_a_file', from: directory },
  ];
  // A mode-000 file is only a face on a host where that actually refuses
  // the read (root reads anything) - otherwise the case is NOT measured,
  // never counted as a pass.
  if (lockedBites) faces.push({ id: 'import_source_unreadable', from: locked });

  return { faces, keystore, pass, cfg };
}

const dir = tmpDir();
const { faces, keystore, pass } = buildFaces(dir);

const rows = faces.map((face) => {
  const r = sh(args.cli, [
    'import', '--keystore', keystore, '--passphrase-file', pass, '--from', face.from,
  ]);
  const firstLine = scrub((r.stderr || '').split('\n').find((l) => l.trim()) || '');
  const named = firstLine.startsWith(`${face.id}:`);
  const hasFix = /^\s+fix: /m.test(r.stderr);
  const rawErrno = ERRNO.test(scrub(r.stderr));
  const exit = r.status;
  return {
    id: face.id,
    firstLine,
    named,
    hasFix,
    exit,
    rawErrno,
    ok: named && hasFix && exit === 2 && !rawErrno,
    // The refusal must NOT have created or touched the target keystore:
    // a usage refusal is pre-flight, nothing may be written.
    targetCreated: fs.existsSync(keystore),
  };
});

const violations = rows.filter((r) => !r.ok).length;
const report = {
  measuredAt: new Date().toISOString(),
  cli: path.basename(args.cli),
  faces: rows.length,
  verdict: violations === 0 ? 'refusals-present' : 'violations-present',
  violations,
  rows,
};

// A refusal must leave no trace behind: the keystore is created only by a
// face that is NOT part of this class (there is none) - assert it, so a
// future face that writes while refusing fails here too.
for (const row of rows) {
  if (row.targetCreated) {
    report.verdict = 'violations-present';
    report.violations += 1;
    row.ok = false;
    row.wroteTarget = true;
  }
  delete row.targetCreated;
}

const json = JSON.stringify(report, null, 2) + '\n';
if (args.out) {
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, json);
}
process.stdout.write(json);
process.exit(report.violations === 0 ? 0 : 1);
