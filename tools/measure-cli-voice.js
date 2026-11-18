'use strict';

// MEASURE the voice of the refusals bin/signerd.js prints ITSELF.
//
//   node tools/measure-cli-voice.js --cli <path/to/bin/signerd.js> \
//        --out research/cli-voice-<state>-<date>.json
//
// WHY THIS CLASS: the refusal voice was closed class by class - the
// daemon's verdicts (v0.2.34), the journal-integrity family (v0.2.36), the
// build-tx value inputs (v0.2.37), the import source file (v0.2.24 sweep).
// What remained were the refusals this CLI mints at its OWN ad-hoc sites,
// each written by hand: the two keystore faces keygen raises, the
// secret-key format refusal import raises, the --body shape check,
// grant-add's signer requirement, and the passphrase-file ownership rule.
// Measured 2026-11-18 on the pre-fix tree (4a2ae5f):
//
//   keygen onto an existing keystore   -> `keystore_exists: `  (empty
//      detail, NO repair - while the sibling import path named --overwrite)
//   keygen --overwrite onto a DIRECTORY -> `keystore_write_failed: <path>:
//      EISDIR`  (a bare errno as the reason)
//   import --from <not a key>          -> `secret_key_invalid: `  (no repair,
//      the three accepted source formats named nowhere)
//   sign-message --body <not JSON>     -> `body_invalid: not JSON` (no
//      repair, although the map already carried one for this exact code)
//   grant-add without --signer/--keystore -> prose with NO code and NO fix
//   keygen --passphrase-file <foreign uid> -> prose with NO code and NO fix
//
// THE CONTRACT (the same four rules as the swept families):
//   - the first line names the face itself: `<code>: <detail>`;
//   - a `fix:` line tells the operator what to change - and it names a
//     real flag or command for the face (--overwrite, id.json, --body,
//     --keystore, chown) where a face-specific token is given;
//   - exit 2 (usage/preflight refused; exit 1 is the daemon's/policy's);
//   - no raw Node errno anywhere in the refusal.
//
// NO NETWORK. Everything happens in a throwaway tmpdir; every path in the
// artifact is scrubbed to <tmp> (never a host path, house rule 3).

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
  process.stderr.write('usage: measure-cli-voice.js --cli <bin/signerd.js> [--out <file>]\n');
  process.exit(2);
}

const ERRNO = /\b(ENOENT|EACCES|EISDIR|ENOTDIR|ELOOP|EPERM|EAGAIN|ENOSPC)\b/;

function sh(cli, argv) {
  const r = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8', timeout: 60000 });
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
 * The seven faces. Each: id, the code the face must wear, the invocation
 * (a function of the sandbox), and the token its repair must name.
 * `foreign` (the ownership face) is only a face where chown to another uid
 * is actually possible - otherwise it is NOT measured, never counted pass.
 */
function buildFaces(dir) {
  const cfg = path.join(dir, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(pass, 0o600);

  const faces = [];

  // F1 keygen onto an existing keystore: repair must name --overwrite.
  {
    const ks = path.join(cfg, 'f1.key');
    const first = sh(args.cli, ['keygen', '--keystore', ks, '--passphrase-file', pass]);
    if (first.status === 0) {
      faces.push({
        id: 'keystore_exists', code: 'keystore_exists', token: '--overwrite',
        argv: ['keygen', '--keystore', ks, '--passphrase-file', pass],
        // The refused run must leave the keystore byte-identical.
        guard: () => fs.existsSync(ks),
      });
    }
  }

  // F2 keygen --overwrite onto a DIRECTORY: reason must not be a bare errno.
  {
    const target = path.join(cfg, 'f2-is-a-directory');
    fs.mkdirSync(target, { recursive: true, mode: 0o700 });
    faces.push({
      id: 'keystore_write_failed', code: 'keystore_write_failed', token: null,
      argv: ['keygen', '--keystore', target, '--passphrase-file', pass, '--overwrite'],
      guard: () => fs.statSync(target).isDirectory(),
    });
  }

  // F3 import of a readable file that is no key: repair must name id.json.
  {
    const ks = path.join(cfg, 'f3.key');
    const bad = path.join(cfg, 'not-a-key.txt');
    fs.writeFileSync(bad, 'this is not a key\n', { mode: 0o600 });
    faces.push({
      id: 'secret_key_invalid', code: 'secret_key_invalid', token: 'id.json',
      argv: ['import', '--keystore', ks, '--from', bad, '--passphrase-file', pass],
      guard: () => !fs.existsSync(ks),
    });
  }

  // F4/F5 the --body shape check, two shapes: repair must name --body.
  for (const [suffix, text] of [['not-json', 'not json at all\n'], ['not-object', '[1,2]\n']]) {
    const body = path.join(cfg, `f4-${suffix}.json`);
    fs.writeFileSync(body, text, { mode: 0o600 });
    faces.push({
      id: `body_invalid_${suffix}`, code: 'body_invalid', token: '--body',
      argv: ['sign-message', '--socket', path.join(dir, 'never.sock'),
        '--grant', 'g', '--body', body],
    });
  }

  // F6 grant-add with neither signer source: repair must name --keystore.
  {
    const grants = path.join(cfg, 'f6-grants.json');
    faces.push({
      id: 'grant_add_signer_required', code: 'grant_add_signer_required', token: '--keystore',
      argv: ['grant-add', '--grants', grants, '--name', 'n',
        '--destination', 'So11111111111111111111111111111111111111112',
        '--max-lamports', '1000', '--window-max-lamports', '5000',
        '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z'],
      guard: () => !fs.existsSync(grants),
    });
  }

  // F7 a passphrase file owned by ANOTHER uid: repair must name chown.
  // Measured only where such ownership can actually be arranged.
  {
    const foreign = path.join(cfg, 'foreign.pass');
    fs.writeFileSync(foreign, 'someone else wrote this\n', { mode: 0o600 });
    let arranged = true;
    try { fs.chownSync(foreign, 65534, 65534); } catch {
      const r = spawnSync('sudo', ['-n', 'chown', '65534:65534', foreign],
        { encoding: 'utf8', timeout: 15000 });
      arranged = r.status === 0;
    }
    if (arranged) {
      const ks = path.join(cfg, 'f7.key');
      faces.push({
        id: 'passphrase_file_owner', code: 'passphrase_file_owner', token: 'chown',
        argv: ['keygen', '--keystore', ks, '--passphrase-file', foreign],
        guard: () => !fs.existsSync(ks),
      });
    }
  }

  return { faces, pass };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-cli-voice-measure-'));
const { faces } = buildFaces(dir);

const rows = faces.map((face) => {
  const r = sh(args.cli, face.argv);
  const stderr = scrub(r.stderr);
  const firstLine = (stderr.split('\n').find((l) => l.trim()) || '').trim();
  const named = firstLine.startsWith(`${face.code}:`);
  const hasFix = /^\s+fix: /m.test(stderr);
  const rawErrno = ERRNO.test(stderr);
  const tokenOk = face.token === null || stderr.includes(face.token);
  const exit = r.status;
  const guardOk = face.guard === undefined || face.guard() === true;
  return {
    id: face.id,
    code: face.code,
    firstLine,
    named,
    hasFix,
    token: face.token,
    tokenOk,
    exit,
    rawErrno,
    guardOk,
    ok: named && hasFix && tokenOk && exit === 2 && !rawErrno && guardOk,
  };
});

// Cleanup: restore foreign ownership so the sandbox can be removed.
try {
  const foreign = path.join(dir, 'cfg', 'foreign.pass');
  if (fs.existsSync(foreign)) {
    try { fs.chownSync(foreign, process.getuid(), process.getgid()); } catch {
      spawnSync('sudo', ['-n', 'chown', `${process.getuid()}:${process.getgid()}`, foreign],
        { timeout: 15000 });
  }
  }
} catch { /* best effort */ }

const violations = rows.filter((r) => !r.ok).length;
const head = spawnSync('git', ['rev-parse', '--short', 'HEAD'],
  { encoding: 'utf8', cwd: path.dirname(path.resolve(args.cli)) });
const report = {
  measuredAt: new Date().toISOString(),
  cli: path.basename(args.cli),
  head: (head.stdout || '').trim() || null,
  faces: rows.length,
  verdict: violations === 0 ? 'refusals-present' : 'violations-present',
  violations,
  rules: ['code-colon-first-line', 'fix-line', 'face-token-in-fix', 'exit-2', 'no-raw-errno', 'condition-held'],
  rows,
};

const json = JSON.stringify(report, null, 2) + '\n';
if (args.out) {
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, json);
}
process.stdout.write(json);
process.exit(report.violations === 0 ? 0 : 1);
