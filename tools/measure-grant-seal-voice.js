'use strict';

// MEASURE the voice of the GRANT-SEAL refusals.
//
//   node tools/measure-grant-seal-voice.js --cli <path/to/bin/signerd.js> \
//        [--out research/grant-seal-voice-<state>-<date>.json]
//
// WHY THIS CLASS: the refusal voice was closed class by class - the
// daemon's verdicts (v0.2.34), the journal-integrity family (v0.2.36),
// the build-tx value inputs (v0.2.37), the CLI's own ad-hoc sites
// (v0.2.38). What was left is the GRANT SEAL family - the refusals an
// operator meets when the file that carries their grants cannot be
// authenticated.
//
// The seal is the PROVENANCE half of this product: it is what makes a
// grant document's bytes trustworthy after a stranger once had write
// access. The refusal family that protects it is the one class where the
// operator is already in trouble, and it is the one class that still ships
// MUTE. Measured 2026-11-18 on the tree v0.2.38 (2f280b6), this tool's
// own first run:
//
//   verify-grants (tampered payload, right passphrase)
//     grant_file_seal_mismatch:            <- code, NO reason, NO repair
//   verify-grants (wrong passphrase)
//     grant_file_seal_mismatch:            <- same
//   verify-grants (shape-broken seal block)
//     grant_file_seal_invalid:             <- same
//   verify-grants (empty passphrase file)
//     seal_passphrase_required:            <- same
//
// The JOURNAL half of the same idea (ledger_mac_invalid, ledger_mac_short,
// ledger_sealed) has carried a repair since v0.2.36; the GRANT half has
// carried none since the seal shipped (v0.1.0 / R5-2, 2026-10-31). The
// asymmetry is the defect: the same operator, the same moment, two
// different levels of being told what to do.
//
// THE CONTRACT (the same rules as every other swept family):
//   - the first line names the face itself: `<code>: <detail>`;
//   - a `fix:` line tells the operator what to change;
//   - the repair names a real flag or command for the face;
//   - no raw Node errno and no host path in the refusal;
//   - the exit code is unchanged (a refusal stays a refusal).
//
// NO NETWORK. Everything happens in a throwaway tmpdir; every path in the
// artifact is scrubbed to <tmp> (house rule 3: never a host path).

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
  process.stderr.write('usage: measure-grant-seal-voice.js --cli <bin/signerd.js> [--out <file>]\n');
  process.exit(2);
}

const ERRNO = /\b(ENOENT|EACCES|EISDIR|ENOTDIR|ELOOP|EPERM|EAGAIN|ENOSPC)\b/;

/** The commands this CLI actually offers (src/cli-flags.js rule F3). */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

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
 * The operator's view of a refusal: the NAME, and whether a repair was
 * named.
 *
 * `code` is the first colon-separated token of the first non-empty stderr
 * line - the token a caller reads. `occurrences` counts how often the code
 * appears as a LINE-LEADING token (a word count would count `--destination`
 * and prose occurrences too).
 */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  const escaped = code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const occurrences = code
    ? (text.match(new RegExp(`(?:^|\\n)${escaped}(?::|\\s|$)`, 'g')) || []).length
    : 0;
  return {
    code,
    occurrences,
    hasFix: /(^|\n)\s*fix:/.test(text),
    detail: firstLine.slice(code.length).replace(/^:\s*/, '').trim(),
  };
}

/** A repair that names a command this CLI does not offer cannot be run. */
function unknownCommandsIn(text) {
  const found = [];
  const re = /signerd\s+([a-z][a-z-]*)/g;
  let m;
  while ((m = re.exec(String(text || ''))) !== null) {
    if (!KNOWN_COMMANDS.includes(m[1])) found.push(m[1]);
  }
  return [...new Set(found)];
}

/** The flags this CLI actually offers (src/cli-flags.js). */
const KNOWN_FLAGS = new Set([
  '--grants', '--ledger', '--socket', '--keystore', '--passphrase-file',
  '--seal-passphrase-file', '--grant-seal-passphrase-file',
  '--journal-seal-passphrase-file', '--name', '--destination', '--max-lamports',
  '--window-max-lamports', '--window-seconds', '--expires', '--out', '--append',
  '--grant', '--tx', '--body', '--dry', '--overwrite', '--from', '--signer',
  '--only', '--wires', '--discard-legacy', '--on', '--to', '--lamports',
  '--blockhash', '--key',
]);

/** A repair that names a flag this CLI does not offer cannot be run. */
function unknownFlagsIn(text) {
  const found = [];
  const re = /(--[a-z][a-z-]*)/g;
  let m;
  while ((m = re.exec(String(text || ''))) !== null) {
    if (!KNOWN_FLAGS.has(m[1])) found.push(m[1]);
  }
  return [...new Set(found)];
}

/**
 * The faces. Each: id, the code the face must wear, the invocation, and
 * the token its repair must name (the face-specific thing the operator
 * has to change).
 *
 * Every face is produced by a REAL file state, not by a mock: the grant
 * file is sealed with the product's own sealDocument(), then broken in one
 * specific way.
 */
function buildFaces(dir, cli) {
  const cfg = path.join(dir, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);

  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);

  const wrongPass = path.join(cfg, 'wrong.pass');
  fs.writeFileSync(wrongPass, 'a different passphrase entirely\n', { mode: 0o600 });
  fs.chmodSync(wrongPass, 0o600);

  const emptyPass = path.join(cfg, 'empty.pass');
  fs.writeFileSync(emptyPass, '\n', { mode: 0o600 });
  fs.chmodSync(emptyPass, 0o600);

  // A grant document with two REAL keys - one is the signer, one the
  // destination - so the loader's own value rules accept it.
  // The fixture builders come from THIS repo's own seal code and pinned
  // web3.js - the seal format is byte-identical between tree and package
  // (published packages ship src/grantseal.js unchanged), while the CLI
  // under test is the one --cli points at (repo tree OR an installed
  // npm package whose deps are hoisted to the parent node_modules).
  const REPO = path.resolve(__dirname, '..');
  const { Keypair } = require(require.resolve('@solana/web3.js', { paths: [REPO] }));
  const signer = Keypair.generate().publicKey.toBase58();
  const destination = Keypair.generate().publicKey.toBase58();
  const base = () => ({
    version: 1,
    grants: {
      ops: {
        signer,
        destination,
        maxLamports: '1000000',
        windowMaxLamports: '5000000',
        windowSeconds: '3600',
        expiresAt: '2030-01-01T00:00:00Z',
      },
    },
  });

  // The seal comes from the product's OWN sealing code, so the fixture is
  // a file this daemon really produced.
  const { sealDocument } = require(path.join(REPO, 'src', 'grantseal.js'));
  const passphrase = fs.readFileSync(sealPass, 'utf8').replace(/\r?\n$/, '');
  const writeDoc = (name, doc) => {
    const p = path.join(cfg, name);
    fs.writeFileSync(p, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(p, 0o600);
    return p;
  };

  const sealed = writeDoc('sealed.json', sealDocument(base(), passphrase));
  const tamperedDoc = base();
  tamperedDoc.grants.ops.destination = Keypair.generate().publicKey.toBase58();
  const tampered = writeDoc('tampered.json', { ...sealDocument(base(), passphrase), grants: tamperedDoc.grants });
  const brokenSealDoc = sealDocument(base(), passphrase);
  brokenSealDoc.seal.alg = 'not-hmac-sha256';
  const brokenSeal = writeDoc('broken-seal.json', brokenSealDoc);
  const unsealed = writeDoc('unsealed.json', base());

  const ledger = path.join(cfg, 'journal.jsonl');
  const socket = path.join(cfg, 'daemon.sock');

  const faces = [
    {
      id: 'seal_mismatch_tampered', code: 'grant_file_seal_mismatch', token: 'seal',
      argv: ['verify-grants', '--grants', tampered, '--seal-passphrase-file', sealPass],
      detail: true,
    },
    {
      id: 'seal_mismatch_wrong_passphrase', code: 'grant_file_seal_mismatch', token: 'seal',
      argv: ['verify-grants', '--grants', sealed, '--seal-passphrase-file', wrongPass],
      detail: true,
    },
    {
      id: 'seal_invalid_broken_block', code: 'grant_file_seal_invalid', token: 'seal',
      argv: ['verify-grants', '--grants', brokenSeal, '--seal-passphrase-file', sealPass],
      detail: true,
    },
    {
      id: 'seal_passphrase_required', code: 'seal_passphrase_required', token: 'passphrase',
      argv: ['verify-grants', '--grants', sealed, '--seal-passphrase-file', emptyPass],
      detail: true,
    },
    {
      // The keyless read of a sealed file: the refusal the seal exists
      // for. It HAS a repair (v0.2.33) - but its DETAIL embeds the
      // resolved absolute path of the operator's file, which is the
      // house-rule-3 leak the other faces do not have.
      id: 'grant_file_sealed_keyless', code: 'grant_file_sealed', token: 'seal',
      argv: ['status', '--grants', sealed, '--ledger', ledger],
      pathInDetail: sealed,
    },
    {
      // A passphrase for a file that carries no seal: also a control.
      id: 'grant_file_unsealed', code: 'grant_file_unsealed', token: 'seal',
      argv: ['verify-grants', '--grants', unsealed, '--seal-passphrase-file', sealPass],
      control: true,
    },
  ];

  return { faces, sealed, unsealed, sealPass, cfg, ledger, socket };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-grant-seal-voice-'));
const { faces } = buildFaces(dir, args.cli);

const rows = faces.map((face) => {
  const r = sh(args.cli, face.argv);
  const rawStderr = String(r.stderr || '');
  const stderr = scrub(rawStderr);
  const v = voiceOf(stderr);
  const named = v.code === face.code;
  const tokenOk = face.token === null || stderr.includes(face.token);
  const unknownCommands = unknownCommandsIn(stderr);
  const unknownFlags = unknownFlagsIn(stderr);
  // The host-path rule is checked on the RAW stderr, never on the scrubbed
  // text: scrubbing first would make the rule unfalsifiable (the measuring
  // instrument's own first version did that and the rule could never fail).
  const hostPath = /\/home\/|\/Users\/|\/root\//.test(rawStderr);
  // A face whose DETAIL must not name the file's resolved path. The fix
  // lines carry <grants> placeholders; the prose around them must not
  // smuggle the operator's own path back in.
  const detailLeaksPath = face.pathInDetail !== undefined &&
    rawStderr.includes(face.pathInDetail);
  const rawErrno = ERRNO.test(stderr);
  // The reason must not be EMPTY: "grant_file_seal_mismatch: " tells the
  // operator nothing beyond the code.
  const detailOk = face.detail !== true || v.detail.length > 0;
  const refused = r.status !== 0;
  const ok = named && v.occurrences === 1 && v.hasFix && tokenOk &&
    unknownCommands.length === 0 && unknownFlags.length === 0 &&
    !hostPath && !detailLeaksPath && !rawErrno && detailOk && refused;
  return {
    id: face.id,
    code: face.code,
    control: face.control === true,
    firstLine: (stderr.split('\n').find((l) => l.trim()) || '').trim().slice(0, 200),
    named,
    occurrences: v.occurrences,
    hasFix: v.hasFix,
    detail: v.detail,
    detailOk,
    token: face.token,
    tokenOk,
    unknownCommands,
    unknownFlags,
    hostPath,
    detailLeaksPath,
    rawErrno,
    exit: r.status,
    refused,
    ok,
  };
});

const violations = rows.filter((r) => !r.ok && !r.control).length;
const controlsBroken = rows.filter((r) => !r.ok && r.control).length;
const head = spawnSync('git', ['rev-parse', '--short', 'HEAD'],
  { encoding: 'utf8', cwd: path.resolve(args.cli, '..', '..') });
const report = {
  measuredAt: new Date().toISOString(),
  cli: path.basename(args.cli),
  head: (head.stdout || '').trim() || null,
  faces: rows.length,
  defectFaces: rows.filter((r) => !r.control).length,
  controlFaces: rows.filter((r) => r.control).length,
  violations,
  controlsBroken,
  verdict: violations === 0 ? 'grant-seal-voice-closed' : 'grant-seal-voice-mute',
  rules: [
    'code-on-first-line', 'code-exactly-once', 'fix-line', 'face-token-in-fix',
    'no-unknown-command', 'no-unknown-flag', 'no-host-path',
    'no-path-in-detail', 'no-raw-errno',
    'non-empty-reason', 'still-refuses',
  ],
  rows,
};

const json = JSON.stringify(report, null, 2) + '\n';
if (args.out) {
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, json);
}
process.stdout.write(json);
process.exit(report.violations === 0 && report.controlsBroken === 0 ? 0 : 1);
