#!/usr/bin/env node
'use strict';
// MEASURE THE MISSING-FLAG VOICE on a given CLI.
//
// WHY (measured 2026-11-19, tree 16ba572): the LAST hand-written refusal
// class that stayed mute. The flag ARITY refusals (duplicate_flag,
// missing_value, flag_takes_no_value) print `<code>: ...` + fix + exit 2;
// build-tx answers `missing_argument: build-tx needs --keystore` + fix.
// But an ABSENT required flag answered bare prose:
//
//     $ signerd sign
//     missing --socket
//     <77-line usage banner>
//     exit 2
//
// No `code:` first line, no `fix:` line, the flag named only inside prose.
// The house rule (test/grant-refusal-voice.test.js, README: "Refusals name
// the flag and the fix instead of failing silently") says otherwise.
// The face escaped every existing gate because it has NO code token to
// scrape: test/refusal-voice-coverage.test.js compares codes against the
// REPAIRS map, and this refusal never carried one.
//
// Verdict per face: the refusal must carry
//   V1 a `missing_flag: --<name>` FIRST line (code: colon form, code once);
//   V2 a `fix:` line that names the flag itself (--<name>);
//   V3 a `fix:` line naming the flags the command takes (real surface);
//   V4 exit 2 (nothing ran);
//   V5 stdout stays empty (a usage question is not a verdict frame);
//   V6 no host path in any fix line (rule 3 of the refusal voice).
//
// Guards (must hold on BOTH trees): the happy path still works; the
// unknown_flag voice is unchanged; an unknown command still answers the
// USAGE banner; build-tx still answers missing_argument + fix.

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function parseArgs(argv) {
  const out = { cli: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--cli') out.cli = argv[++i];
    else if (argv[i] === '--out') out.out = argv[++i];
  }
  return out;
}

function sh(cli, argv) {
  const r = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8', timeout: 60000 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function scrub(text) {
  return String(text || '')
    .replace(/\/home\/[^\s"']+/g, '<home>')
    .replace(/\/tmp\/[^\s"']+/g, '<tmp>')
    .replace(/[A-Za-z]:\\[^\s"']+/g, '<win>');
}

// The COMMAND_FLAGS surface, read from the source under test — never a
// hand-written list (the rule of test/refusal-voice-coverage.test.js).
// Works on BOTH trees: the require line may or may not already destructure
// COMMAND_FLAGS (main does since 2026-11-19, the pre-fix bin did not); the
// table itself lives in src/cli-flags.js either way.
function commandFlagsOf(cli) {
  const src = fs.readFileSync(cli, 'utf8');
  if (!/require\('\.\.\/src\/cli-flags'\)/.test(src)) {
    throw new Error('bin does not load cli-flags the expected way');
  }
  const flagsSrc = fs.readFileSync(path.join(path.dirname(cli), '..', 'src', 'cli-flags.js'), 'utf8');
  const tableMatch = flagsSrc.match(/const COMMAND_FLAGS = \{([\s\S]*?)\n\};/);
  if (!tableMatch) throw new Error('COMMAND_FLAGS not found in src/cli-flags.js');
  const table = {};
  // Whole-table parse, NOT line-by-line: several entries span lines
  // (`run: [ ... ]`, `grant-add: [ ... ]`, `status: [ ... ]`), and a
  // line-split silently dropped exactly those commands — the post-fix run
  // flagged 4 faces whose takes-list looked wrong when the SUPPORTED side
  // parsed as []. Caught by the instrument measuring itself.
  const entryRe = /'?([a-z-]+)'?:\s*\[([^\]]*)\]/g;
  let entry;
  while ((entry = entryRe.exec(tableMatch[1])) !== null) {
    table[entry[1]] = entry[2].split(',').map((s) => s.trim().replace(/['"]/g, '')).filter(Boolean);
  }
  return table;
}

function buildFaces(dir) {
  const cfg = path.join(dir, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  const faces = [];

  // One face per command: the invocation leaves EXACTLY ONE required flag
  // absent, so the verdict is unambiguous.
  faces.push({ id: 'keygen_needs_passphrase', command: 'keygen', flag: 'passphrase-file',
    argv: ['keygen', '--keystore', path.join(cfg, 'f.key')] });
  faces.push({ id: 'import_needs_from', command: 'import', flag: 'from',
    argv: ['import', '--keystore', path.join(cfg, 'f2.key')] });
  faces.push({ id: 'run_needs_socket', command: 'run', flag: 'socket',
    argv: ['run', '--keystore', path.join(cfg, 'f3.key'), '--passphrase-file', pass,
      '--grants', path.join(cfg, 'g.json'), '--ledger', path.join(cfg, 'l.json')] });
  faces.push({ id: 'sign_needs_grant', command: 'sign', flag: 'grant',
    argv: ['sign', '--socket', path.join(cfg, 's.sock'), '--tx', path.join(cfg, 'tx.bin')] });
  faces.push({ id: 'sign_needs_tx', command: 'sign', flag: 'tx',
    argv: ['sign', '--socket', path.join(cfg, 's.sock'), '--grant', 'g'] });
  faces.push({ id: 'sign_message_needs_body', command: 'sign-message', flag: 'body',
    argv: ['sign-message', '--socket', path.join(cfg, 's.sock'), '--grant', 'g'] });
  faces.push({ id: 'grant_add_needs_destination', command: 'grant-add', flag: 'destination',
    argv: ['grant-add', '--grants', path.join(cfg, 'g.json'), '--name', 'n',
      '--signer', '11111111111111111111111111111111'] });
  faces.push({ id: 'grant_add_needs_expires', command: 'grant-add', flag: 'expires',
    argv: ['grant-add', '--grants', path.join(cfg, 'g.json'), '--name', 'n',
      '--signer', '11111111111111111111111111111111',
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '1000', '--window-max-lamports', '5000', '--window-seconds', '60'] });
  faces.push({ id: 'grant_remove_needs_name', command: 'grant-remove', flag: 'name',
    argv: ['grant-remove', '--grants', path.join(cfg, 'g.json')] });
  faces.push({ id: 'status_needs_grants', command: 'status', flag: 'grants',
    argv: ['status'] });
  faces.push({ id: 'seal_grants_needs_passphrase', command: 'seal-grants', flag: 'seal-passphrase-file',
    argv: ['seal-grants', '--grants', path.join(cfg, 'g.json')] });
  faces.push({ id: 'verify_grants_needs_passphrase', command: 'verify-grants', flag: 'seal-passphrase-file',
    argv: ['verify-grants', '--grants', path.join(cfg, 'g.json')] });
  faces.push({ id: 'seal_journal_needs_journal', command: 'seal-journal', flag: 'journal',
    argv: ['seal-journal'] });
  faces.push({ id: 'migrate_needs_ledger', command: 'migrate', flag: 'ledger',
    argv: ['migrate'] });
  return faces;
}

function judgeFace(face, r, supported) {
  const stderr = r.stderr;
  const lines = stderr.split('\n');
  const first = lines[0] || '';
  const codeMatch = first.match(/^missing_flag: --([a-z-]+)$/);
  const named = codeMatch ? codeMatch[1] : null;
  const fixLines = stderr.split('\n').filter((l) => /^\s*fix:/.test(l));
  const fixText = fixLines.join('\n');
  const codeCount = named ? (stderr.match(/\bmissing_flag\b/g) || []).length : 0;
  const takesList = fixLines.find((l) => l.includes(`signerd ${face.command} takes:`)) || '';
  const takes = takesList.match(/takes: (.*)$/);
  const takesFlags = takes ? takes[1].trim().split(/\s+/).map((f) => f.replace(/^--/, '')) : [];
  return {
    id: face.id, code: 'missing_flag',
    argv: face.argv.map((a) => scrub(a)),
    exit: r.status,
    named: named === face.flag ? face.flag : named,
    expectedFlag: face.flag,
    firstLine: scrub(first),
    fixes: fixLines.length,
    fixNamesFlag: fixText.includes(`--${face.flag}`),
    takesListReal: takesFlags.length > 0 &&
      supported.every((f) => takesFlags.includes(f)) &&
      takesFlags.every((f) => supported.includes(f)),
    codeOnce: codeCount === 1,
    stdoutEmpty: r.stdout.trim() === '',
    exit2: r.status === 2,
    noHostPath: !/[\\/]home[\\/]|[\\/]tmp[\\/]/.test(fixText),
  };
}

const args = parseArgs(process.argv.slice(2));
if (!args.cli) {
  process.stderr.write('usage: measure-missing-flag-voice.js --cli <bin/signerd.js> [--out <file>]\n');
  process.exit(2);
}
const cli = path.resolve(args.cli);
const COMMAND_FLAGS = commandFlagsOf(cli);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mf-voice-'));
const faces = buildFaces(dir);

const guards = [];
{
  // G1 the happy path still works end to end (keygen + import source rules
  // need a real key; keygen alone is the cheapest exit-0 path).
  const ks = path.join(dir, 'happy.key');
  const g1 = sh(cli, ['keygen', '--keystore', ks, '--passphrase-file', path.join(dir, 'cfg', 'pass')]);
  guards.push({ id: 'happy_keygen', pass: g1.status === 0 && fs.existsSync(ks) });
  // G2 the unknown_flag voice is unchanged.
  const g2 = sh(cli, ['keygen', '--definitely-not-a-flag']);
  guards.push({ id: 'unknown_flag_unchanged', pass:
    /^unknown_flag: --definitely-not-a-flag$/m.test(g2.stderr) &&
    /^\s*fix:/m.test(g2.stderr) && g2.status === 2 });
  // G3 an unknown command still answers the USAGE banner (the
  // documented-flags instrument classifies commands by that banner).
  const g3 = sh(cli, ['definitely-not-a-command']);
  const banner = (g3.stderr.split('\n')[0] || '').trim();
  guards.push({ id: 'unknown_command_banner', pass:
    banner === 'signerd — scoped signing daemon for Solana (early prototype)' && g3.status === 2 });
  // G4 build-tx keeps its own missing_argument voice (the sibling parity
  // this defect was measured against).
  const g4 = sh(cli, ['build-tx']);
  guards.push({ id: 'buildtx_missing_argument', pass:
    /^missing_argument: build-tx needs --keystore$/m.test(g4.stderr) &&
    /^\s*fix:/m.test(g4.stderr) && g4.status === 2 });
}

const rows = faces.map((face) => {
  const r = sh(cli, face.argv);
  const v = judgeFace(face, r, COMMAND_FLAGS[face.command] || []);
  v.holds = Boolean(v.exit2 && v.stdoutEmpty && v.codeOnce && v.named === v.expectedFlag &&
    v.fixNamesFlag && v.takesListReal && v.noHostPath);
  return v;
});

const defects = rows.filter((r) => !r.holds);
const verdict = defects.length === 0
  ? 'missing-flag-voice-closed'
  : 'missing-flag-voice-mute';
const result = {
  generatedAt: new Date().toISOString(),
  cli: scrub(cli),
  verdict,
  faces: rows.length,
  faceDefects: defects.length,
  guards: guards.map((g) => ({ id: g.id, pass: g.pass })),
  guardBroken: guards.filter((g) => !g.pass).map((g) => g.id),
  rows,
  rules: ['missing_flag-first-line', 'fix-names-flag', 'takes-list-real-surface', 'exit-2', 'stdout-empty', 'code-once', 'no-host-path'],
};
const out = JSON.stringify(result, null, 1);
if (args.out) {
  fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
  fs.writeFileSync(args.out, out + '\n');
}
process.stdout.write(out + '\n');
process.stderr.write(`\nVERDICT ${verdict}: ${defects.length}/${rows.length} defect faces, ` +
  `guards ${guards.filter((g) => g.pass).length}/${guards.length}\n`);
fs.rmSync(dir, { recursive: true, force: true });
process.exit(defects.length === 0 && guards.every((g) => g.pass) ? 0 : 1);
