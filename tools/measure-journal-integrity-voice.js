#!/usr/bin/env node
'use strict';

// Measure what the OPERATOR is told when the JOURNAL refuses them.
//
// WHY (measured 2026-11-18, on the published v0.2.35 npm package, this
// tool's own first run):
//
//   $ signerd migrate --ledger journal.jsonl
//   legacy_wire_required: 2 legacy record(s); pass --wires <dir> or explicitly --discard-legacy
//   $ signerd migrate --ledger tampered.jsonl --discard-legacy
//   error: ledger_tampered
//   $ signerd migrate --ledger journal.jsonl --wires ./absent
//   wires_dir_unreadable: ENOENT
//
// The journal is the REPLAY SET and the WINDOW BUDGET. When it refuses, the
// operator is one line away from spending money they did not intend to, and
// the README promises exactly what this class does not deliver:
//
//   "Refusals name the flag and the fix instead of failing silently."
//
// The v0.2.34 fix gave the DAEMON's policy verdicts a repair (the class the
// product exists for). The JOURNAL-INTEGRITY class stayed mute: it is the
// class an operator meets when something is already wrong with their
// history - the one moment where a repair is worth the most.
//
// WHAT IS AND IS NOT DEFECTIVE HERE:
//
//   A face is DEFECTIVE when EITHER of these holds:
//
//     (A) NO REPAIR. The operator gets the refusal's NAME and nothing else.
//         A code names a condition; it does not tell anybody what to DO.
//         For `legacy_wire_required` the operator cannot learn that the
//         repair is `--wires <dir>` or `--discard-legacy` - the two choices
//         the product offers - without reading the source.
//
//     (B) THE CODE IS NOT A CODE. The stderr line starts with `error: `
//         instead of the refusal's own name, so the name is BURIED in the
//         detail text. `error: ledger_tampered` is not a machine-readable
//         refusal: a caller that reads the first `:`-separated token gets
//         the literal word "error", and every refusal looks the same. This
//         happens where the loader raises a bare `new Error('...')` instead
//         of an error that CARRIES its code.
//
//   The exit code is UNCHANGED by the fix (1 for a refusal, 2 for a usage
//   error) - this is about what the operator is TOLD, not about the channel.
//
//   The machine channel is UNCHANGED too: the JSON a caller parses is not
//   touched by this class, which never printed JSON in the first place.
//
// FACES (each one is a journal-integrity refusal the operator can actually
// meet; each is produced by a real file state, not by a mock):
//
//   J1  legacy_wire_required      migrate, a legacy journal, no choice made
//   J2  wires_dir_unreadable      migrate --wires <a directory that is not there>
//   J3  legacy_wire_missing       migrate --wires <an empty directory>
//   J4  ledger_torn_tail          migrate on a journal with a torn last line
//   J5  ledger_tampered           migrate on a journal whose chain was edited
//   J6  ledger_corrupt            migrate on a structurally broken journal
//   J7  ledger_dir_mode           migrate on a journal in a group-writable dir
//   J8  ledger_not_a_file         migrate on a journal path that is a directory
//   J9  ledger_missing            migrate on a journal that does not exist
//   J10 ledger_mode              migrate on a group-writable journal file
//   J11 ledger_torn_tail (sealed) seal-journal on a journal with a torn tail
//   J12 ledger_sealed             seal-journal without the journal seal key
//   J13 ledger_legacy_format      the daemon loading a legacy journal
//   J14 ledger_locked             migrate while a daemon holds the lock
//   J15 journal_seal_chain_invalid  seal-journal on a journal whose chain was edited
//
//   G1  control-migration-works   a legal migrate still succeeds, exit 0
//   G2  control-code-is-the-code  every refusal's first token IS its code
//   G3  control-no-host-path      no repair carries a host path
//   G4  control-known-command     every repair names a command this CLI offers
//
// Usage:
//   node tools/measure-journal-integrity-voice.js [--out <file>] [--published <dir>]
//
//   --published <dir>  run against an INSTALLED signerd (the published
//                      package), so the defect can be measured on the
//                      released tree.
//   --out <file>       where to write the JSON verdict (default:
//                      research/journal-integrity-voice-<date>.json).
//
// No network. Writes only inside os.tmpdir() and the output file.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
function argOf(flag) {
  const i = args.indexOf(flag);
  // >= 0, not > 0: a flag may be the FIRST argument (the lesson from
  // tools/measure-client-verification.js).
  return i >= 0 && args[i + 1] ? path.resolve(args[i + 1]) : null;
}
const OUT = argOf('--out') || path.join(REPO, 'research',
  `journal-integrity-voice-${new Date().toISOString().slice(0, 10)}.json`);
const PUBLISHED = argOf('--published');

const TREE = PUBLISHED || REPO;
const CLI = path.join(TREE, 'bin', 'signerd.js');

function fail(msg) { console.error(msg); process.exit(3); }
if (!fs.existsSync(CLI)) fail(`no CLI at ${CLI}`);

/** The commands this CLI actually offers (src/cli-flags.js rule F3). */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

/**
 * The operator's view of a refusal: is the NAME there, and is a repair
 * named?
 *
 * `code` is the FIRST colon-separated token of the first non-empty stderr
 * line. That is the token a caller reads. If it is the literal word
 * `error`, the refusal did not name itself - face (B).
 */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  return {
    code,
    firstLine: firstLine.slice(0, 200),
    hasFix: /(^|\n)\s*fix:/.test(text),
    stderrBytes: Buffer.byteLength(text),
  };
}

/** A repair that names a command this CLI does not offer cannot be run. */
function repairNamesUnknownCommand(stderr) {
  const text = String(stderr || '');
  const found = [];
  const re = /signerd\s+([a-z][a-z-]*)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (!KNOWN_COMMANDS.includes(m[1])) found.push(m[1]);
  }
  return [...new Set(found)];
}

/** A host path must never appear in a refusal (the house rule). */
function hostPathsIn(text) {
  return /\/home\/|\/Users\/|\/root\//.test(String(text || ''));
}

/** The refusal named itself: the first token is not the literal "error". */
function codeNamesItself(stderr, expected) {
  const v = voiceOf(stderr);
  if (expected && v.code !== expected) return false;
  return v.code !== '' && v.code !== 'error';
}

function run(argv, opts = {}) {
  const res = spawnSync(process.execPath, [CLI, ...argv], {
    encoding: 'utf8', timeout: 60000, ...opts,
  });
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

/**
 * Build a format-1 journal (no message identity) with a VALID chain, so the
 * journal reaches the face under test instead of failing on the chain first.
 *
 * The chain hash is computed by the PRODUCT's own chainHash(), so the
 * fixture is exactly what the product accepts - a hand-rolled hash would
 * trip `ledger_tampered` instead of the face under test.
 */
function buildLegacyJournal(dir, name, records = 2) {
  const { chainHash, GENESIS_HASH } = require(path.join(REPO, 'src', 'ledger.js'));
  let prev = GENESIS_HASH;
  const lines = [];
  for (let i = 1; i <= records; i += 1) {
    const w = crypto.createHash('sha256').update(`wire-${name}-${i}`).digest('hex');
    const body = { s: i, t: 1700000000000 + i, w, a: String(1000 * i), f: '5000', k: 'signer\0dest' };
    const rec = { ...body, h: chainHash(prev, body) };
    prev = rec.h;
    lines.push(JSON.stringify(rec));
  }
  const file = path.join(dir, name);
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  return { file, lines };
}

/**
 * Build a CURRENT (format-3) journal with a valid chain, so seal-journal
 * reaches the face under test. seal-journal refuses a format-1 journal
 * first (ledger_legacy_format), which would mask the sealed faces.
 */
function buildCurrentJournal(dir, name, records = 2) {
  const { chainHash, GENESIS_HASH } = require(path.join(REPO, 'src', 'ledger.js'));
  let prev = GENESIS_HASH;
  const lines = [];
  for (let i = 1; i <= records; i += 1) {
    const w = crypto.createHash('sha256').update(`wire-${name}-${i}`).digest('hex');
    const m = crypto.createHash('sha256').update(`message-${name}-${i}`).digest('hex');
    const body = { v: 3, s: i, t: 1700000000000 + i, w, m, a: String(1000 * i), f: '5000', k: 'signer\0dest' };
    const rec = { ...body, h: chainHash(prev, body) };
    prev = rec.h;
    lines.push(JSON.stringify(rec));
  }
  const file = path.join(dir, name);
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  return { file, lines };
}

function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-journalvoice-'));
  // The directory itself must be owner-only: the passphrase-file check
  // refuses a group-writable directory, which would mask the face under
  // test with a different refusal.
  fs.chmodSync(dir, 0o700);

  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for the journal-voice measurement only\n', { mode: 0o600 });

  const legacy = buildLegacyJournal(dir, 'legacy.jsonl');
  const tampered = path.join(dir, 'tampered.jsonl');
  {
    const lines = legacy.lines.map((l) => JSON.parse(l));
    lines[1].a = '999999';
    fs.writeFileSync(tampered, lines.map((r) => JSON.stringify(r)).join('\n') + '\n', { mode: 0o600 });
  }
  const corrupt = path.join(dir, 'corrupt.jsonl');
  fs.writeFileSync(corrupt, '{"s":1,"t":1700000000001,"w":"not-a-hash"}\n', { mode: 0o600 });
  const torn = path.join(dir, 'torn.jsonl');
  fs.writeFileSync(torn, legacy.lines.join('\n') + '\n{"s":3,"t":1700002', { mode: 0o600 });

  // A journal in a group-writable DIRECTORY (the directory rule, not the
  // file rule).
  const looseDir = path.join(dir, 'loose');
  fs.mkdirSync(looseDir, { mode: 0o777 });
  fs.chmodSync(looseDir, 0o777);
  const looseJournal = path.join(looseDir, 'journal.jsonl');
  fs.copyFileSync(legacy.file, looseJournal);
  fs.chmodSync(looseJournal, 0o600);

  // A group-writable journal FILE (the file rule).
  const looseFile = path.join(dir, 'loosefile.jsonl');
  fs.copyFileSync(legacy.file, looseFile);
  fs.chmodSync(looseFile, 0o666);

  // A wires directory that exists but holds no wire for the records.
  const emptyWires = path.join(dir, 'wires-empty');
  fs.mkdirSync(emptyWires, { mode: 0o700 });

  // A journal path that is a DIRECTORY.
  const dirJournal = path.join(dir, 'journal-is-a-dir');
  fs.mkdirSync(dirJournal, { mode: 0o700 });

  const faces = [];
  const scrub = (text) => String(text || '').split(dir).join('<tmp>');
  const record = (face, res, expect, note) => {
    const v = voiceOf(res.stderr);
    const unknownCommands = repairNamesUnknownCommand(res.stderr);
    const leak = hostPathsIn(res.stderr);
    const namesItself = codeNamesItself(res.stderr, expect);
    const defective = !v.hasFix || !namesItself;
    faces.push({
      face,
      expect,
      note,
      exit: res.status,
      stderrHead: scrub(v.firstLine),
      stderrBytes: v.stderrBytes,
      hasCode: v.code !== '',
      codeIsTheCode: namesItself,
      hasFix: v.hasFix,
      unknownCommandsInRepair: unknownCommands,
      hostPathInRepair: leak,
      defective,
    });
  };

  // ---- J1 legacy_wire_required -----------------------------------------
  record('J1-legacy-wire-required',
    run(['migrate', '--ledger', legacy.file]),
    'legacy_wire_required',
    'a legacy journal, and the operator has not chosen how to resolve it');

  // ---- J2 wires_dir_unreadable -----------------------------------------
  record('J2-wires-dir-unreadable',
    run(['migrate', '--ledger', legacy.file, '--wires', path.join(dir, 'no-such-dir')]),
    'wires_dir_unreadable',
    'the operator named a wires directory that is not there');

  // ---- J3 legacy_wire_missing ------------------------------------------
  record('J3-legacy-wire-missing',
    run(['migrate', '--ledger', legacy.file, '--wires', emptyWires]),
    'legacy_wire_missing',
    'the wires directory exists but holds no wire for the records');

  // ---- J4 ledger_torn_tail ---------------------------------------------
  record('J4-ledger-torn-tail',
    run(['migrate', '--ledger', torn, '--discard-legacy']),
    'ledger_torn_tail',
    'the last journal line was cut off by a crash');

  // ---- J5 ledger_tampered ----------------------------------------------
  record('J5-ledger-tampered',
    run(['migrate', '--ledger', tampered, '--discard-legacy']),
    'ledger_tampered',
    'a record was edited, so the chain no longer verifies');

  // ---- J6 ledger_corrupt -----------------------------------------------
  record('J6-ledger-corrupt',
    run(['migrate', '--ledger', corrupt, '--discard-legacy']),
    'ledger_corrupt',
    'the journal is structurally broken');

  // ---- J7 ledger_dir_mode ----------------------------------------------
  record('J7-ledger-dir-mode',
    run(['migrate', '--ledger', looseJournal, '--discard-legacy']),
    'ledger_dir_mode',
    'the journal sits in a group-writable directory');

  // ---- J8 ledger_not_a_file --------------------------------------------
  record('J8-ledger-not-a-file',
    run(['migrate', '--ledger', dirJournal, '--discard-legacy']),
    'ledger_not_a_file',
    'the journal path is a directory');

  // ---- J9 ledger_missing -----------------------------------------------
  record('J9-ledger-missing',
    run(['migrate', '--ledger', path.join(dir, 'no-such-journal.jsonl'), '--discard-legacy']),
    'ledger_missing',
    'the journal does not exist');

  // ---- J10 ledger_mode -------------------------------------------------
  record('J10-ledger-mode',
    run(['migrate', '--ledger', looseFile, '--discard-legacy']),
    'ledger_mode',
    'the journal file itself is group-writable');

  // ---- J11 ledger_sealed ------------------------------------------------
  // A journal that WAS sealed, read without the key: the loader must refuse
  // rather than degrade to an unsealed read.
  {
    const sealedDir = path.join(dir, 'sealed');
    fs.mkdirSync(sealedDir, { mode: 0o700 });
    const sealed = buildCurrentJournal(sealedDir, 'sealed.jsonl');
    const seal = run(['seal-journal', '--journal', sealed.file,
      '--journal-seal-passphrase-file', pass]);
    if (seal.status !== 0) fail(`the control seal failed: ${seal.stderr}`);
    record('J11-ledger-sealed',
      run(['migrate', '--ledger', sealed.file, '--discard-legacy']),
      'ledger_sealed',
      'a sealed journal, read without the seal key');
  }

  // ---- J12 ledger_mac_invalid -----------------------------------------
  // A forgery an attacker can actually make: the record body is edited AND
  // the unkeyed chain is RE-CHAINED to match - so the unkeyed chain holds
  // and only the KEYED chain (the seal) can see the edit. That is the
  // attack the seal exists for, and it is the face the seal must name.
  {
    const sealedDir = path.join(dir, 'sealed2');
    fs.mkdirSync(sealedDir, { mode: 0o700 });
    const sealed = buildCurrentJournal(sealedDir, 'sealed2.jsonl');
    const seal = run(['seal-journal', '--journal', sealed.file,
      '--journal-seal-passphrase-file', pass]);
    if (seal.status !== 0) fail(`the control seal failed: ${seal.stderr}`);
    // Re-chain the edited journal so the UNKEYED chain verifies.
    const { chainHash, GENESIS_HASH } = require(path.join(REPO, 'src', 'ledger.js'));
    const raw = fs.readFileSync(sealed.file, 'utf8');
    const lines = raw.trim().split('\n').map((l) => JSON.parse(l));
    const edited = { ...lines[1], a: '4242' };
    delete edited.h;
    let prev = GENESIS_HASH;
    const rebuilt = [];
    for (const rec of lines) {
      const body = rec === lines[1] ? edited : rec;
      const bodyFields = { ...body };
      delete bodyFields.h;
      const h = chainHash(prev, bodyFields);
      prev = h;
      rebuilt.push(JSON.stringify({ ...bodyFields, h }));
    }
    const editedFile = path.join(sealedDir, 'rechained.jsonl');
    fs.writeFileSync(editedFile, rebuilt.join('\n') + '\n', { mode: 0o600 });
    record('J12-ledger-mac-invalid',
      run(['seal-journal', '--journal', editedFile, '--journal-seal-passphrase-file', pass]),
      'ledger_mac_invalid',
      'a sealed record was edited and the unkeyed chain re-chained: only the keyed chain can see it');
  }

  // ---- J13 ledger_legacy_format ---------------------------------------
  // The DAEMON's own refusal for a legacy journal - the same class, on the
  // surface the daemon owns. It needs a REAL grant file, or the grant
  // loader refuses first and the face under test is masked.
  {
    const daemonDir = path.join(dir, 'daemon');
    fs.mkdirSync(daemonDir, { mode: 0o700 });
    const j = buildLegacyJournal(daemonDir, 'legacy-daemon.jsonl');
    const keyFile = path.join(daemonDir, 'ops.key');
    const keygen = run(['keygen', '--keystore', keyFile, '--passphrase-file', pass]);
    if (keygen.status !== 0) fail(`the control keygen failed: ${keygen.stderr}`);
    const grantsFile = path.join(daemonDir, 'grants.json');
    const add = run(['grant-add', '--grants', grantsFile, '--name', 'ops', '--keystore', keyFile,
      '--destination', 'So11111111111111111111111111111111111111112',
      '--max-lamports', '500000000', '--window-max-lamports', '500000000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
    if (add.status !== 0) fail(`the control grant-add failed: ${add.stderr}`);
    record('J13-ledger-legacy-format',
      run(['status', '--grants', grantsFile, '--ledger', j.file]),
      'ledger_legacy_format',
      'the daemon refuses a legacy journal instead of loading it');
  }

  // ---- J14 ledger_locked -----------------------------------------------
  // A daemon holding the journal lock: the migration must be refused. The
  // lock owner must be ALIVE (a dead owner is taken over by design), so the
  // lock file names this very process.
  {
    const lockDir = path.join(dir, 'locked');
    fs.mkdirSync(lockDir, { mode: 0o700 });
    const j = buildLegacyJournal(lockDir, 'locked.jsonl');
    // The lock file the journal lock claims (src/journal-lock.js): pid,
    // token, startedAt. A live pid -> refused, never taken over.
    const lockFile = path.join(lockDir, 'locked.jsonl.lock');
    fs.writeFileSync(lockFile, JSON.stringify({
      pid: process.pid, token: 'measurement-owner', startedAt: Date.now(),
    }) + '\n', { mode: 0o600 });
    const migrated = run(['migrate', '--ledger', j.file, '--discard-legacy']);
    record('J14-ledger-locked', migrated, 'ledger_locked',
      'a live daemon holds the journal lock');
  }

  // ---- G1 control: a legal migrate still works ------------------------
  {
    const goodDir = path.join(dir, 'good');
    fs.mkdirSync(goodDir, { mode: 0o700 });
    const j = buildLegacyJournal(goodDir, 'good.jsonl');
    const res = run(['migrate', '--ledger', j.file, '--discard-legacy']);
    faces.push({
      face: 'G1-control-migration-works',
      expect: 'ok',
      note: 'a legal migration still succeeds and prints its own report',
      exit: res.status,
      stdoutHead: scrub((res.stdout.split('\n')[0] || '').slice(0, 200)),
      stderrHead: scrub(voiceOf(res.stderr).firstLine),
      stderrBytes: voiceOf(res.stderr).stderrBytes,
      passed: res.status === 0 && /"ok":true/.test(res.stdout),
      defective: !(res.status === 0 && /"ok":true/.test(res.stdout)),
    });
  }

  // ---- G2/G3/G4 guards over every face ---------------------------------
  // These must be GREEN on BOTH trees: they keep the instrument honest, so
  // the pre-fix and post-fix verdicts are comparable.
  const defectFaces = faces.filter((f) => f.face.startsWith('J'));
  const controls = {
    G1: null, // placeholder, filled above
    G2: {
      name: 'control-exit-code-unchanged',
      note: 'every refusal still exits 1 - the fix changes what is SAID, never the channel',
      passed: defectFaces.every((f) => f.exit === 1),
    },
    G3: {
      name: 'control-no-host-path',
      note: 'no refusal carries a host path (the operator\'s own fixture paths are scrubbed)',
      passed: faces.every((f) => f.hostPathInRepair !== true),
    },
    G4: {
      name: 'control-known-command',
      note: 'every repair names a command this CLI actually offers',
      passed: faces.every((f) => (f.unknownCommandsInRepair || []).length === 0),
    },
  };
  for (const key of Object.keys(controls)) {
    if (controls[key] === null) continue;
    const c = controls[key];
    c.face = key;
    c.expect = 'guard';
    c.exit = 1;
    c.stderrHead = '';
    c.stderrBytes = 0;
    c.hasCode = true;
    c.codeIsTheCode = true;
    c.hasFix = true;
    c.hostPathInRepair = false;
    c.unknownCommandsInRepair = [];
    c.defective = !c.passed;
    faces.push(c);
  }

  const defectCount = faces.filter((f) => f.defective).length;
  const judgement = defectCount === 0
    ? 'journal-integrity-refusals-name-their-repair'
    : 'journal-integrity-refusals-ship-mute';

  const result = {
    tool: 'measure-journal-integrity-voice',
    measuredAt: new Date().toISOString(),
    tree: PUBLISHED ? 'published' : 'working-tree',
    version: require(path.join(TREE, 'package.json')).version,
    judgement,
    defectCount,
    faceCount: faces.length,
    faces,
  };

  fs.writeFileSync(OUT, JSON.stringify(result, null, 2) + '\n');
  console.log(`${judgement}: ${defectCount} defective face(s) of ${faces.length}`);
  for (const f of faces) {
    if (f.defective) {
      console.log(`  DEFECT ${f.face} exit=${f.exit} code=${f.codeIsTheCode ? 'ok' : 'BURIED'} fix=${f.hasFix ? 'ok' : 'NONE'}`);
      console.log(`         ${f.stderrHead}`);
    }
  }
  console.log(`artifact: ${OUT}`);
  // Exit 0 when the measurement RAN (the verdict is in the artifact, not in
  // the exit code): the tool must be usable on both the defective and the
  // fixed tree.
  process.exit(0);
}

main();
