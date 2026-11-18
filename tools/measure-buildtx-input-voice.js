#!/usr/bin/env node
'use strict';

// Measure what the OPERATOR is told when build-tx REFUSES a VALUE they typed.
//
// WHY (measured 2026-11-18, on the published v0.2.36 npm package, this
// tool's own first run):
//
//   $ signerd build-tx --keystore ks.json --to notavalidpubkey ...
//   wire_build_failed: build-tx: Non-base58 character
//     fix: build-tx: Non-base58 character
//   $ signerd build-tx ... --blockhash 'abc'
//   wire_build_failed: build-tx: Blob.encode[recentBlockhash] requires
//     (length 32) Uint8Array as src
//     fix: build-tx: build-tx: Blob.encode[recentBlockhash] requires ...
//
// Two defects in one refusal. First, the `fix:` line ECHOES the error: a
// repair that restates the failure in the same words is not a repair - the
// operator is told what broke twice and what to DO never. Second, the flag
// is never named: `--to` and `--blockhash` both fail as the same code
// (`wire_build_failed`) with third-party prose (bs58's "Non-base58
// character", web3.js/buffer's "Blob.encode[recentBlockhash] requires ..."),
// so the operator cannot tell WHICH of the two values they got wrong, and
// the first `:`-separated token a caller reads is `wire_build_failed` for
// every cause.
//
// This is the VALUE-input half of the class already closed for FILES
// (tools/measure-input-voice.js, v0.2.22: a mistyped --tx/--body path
// leaked a raw errno) and for GRANT FIELDS (grant_field_invalid names the
// field and what it must hold). build-tx was never swept: it validates
// --lamports itself (invalid_lamports, named + repaired) and lets web3.js
// speak for the two keys.
//
// WHAT IS AND IS NOT DEFECTIVE HERE:
//
//   A face is DEFECTIVE when EITHER of these holds:
//
//     (A) NO ACTIONABLE REPAIR. Missing `fix:` line, OR the fix line only
//         restates the error detail, OR it names neither a flag (`--x`) nor
//         a command this CLI offers. "fix: build-tx: Non-base58 character"
//         fails all three readings: it is the error again, in the same
//         words, naming nothing the operator can change.
//
//     (B) THE FLAG IS NOT NAMED. The refusal (code + message + fix) never
//         mentions the flag the operator actually passed, so a caller who
//         passed a bad `--to` and a bad `--blockhash` in two different runs
//         gets the identical code and the identical words. The value input
//         is refused in a library's vocabulary, not the product's.
//
//   Exit codes are UNCHANGED by the fix: a bad value is a USAGE refusal
//   and stays exit 2 (the channel is not what this measures - except that
//   the instrument pins it so the fix cannot silently move it).
//
//   A wrong-LAWFUL blockhash (well-formed 32 bytes, stale or fabricated) is
//   deliberately NOT a face: it cannot be judged offline, and the README
//   already says the placeholder will not confirm on chain.
//
// FACES (each is produced by a real value, not by a mock):
//
//   B1  --to is not base58 at all              (`not-a-key!`)
//   B2  --to is base58 but not 32 bytes        (31-byte key)
//   B3  --blockhash is not base58              (`nonsense!!!`)
//   B4  --blockhash is base58 but not 32 bytes (31-byte value)
//   B5  --to is base58 32 bytes BUT the keystore does not exist -
//       control for the neighbouring face (keystore_unreadable already
//       names itself and its repair; it must stay green)
//
//   G1  control-build-works        a legal build-tx still exits 0
//   G2  control-lamports-voice     --lamports garbage keeps
//                                  invalid_lamports + its own fix
//   G3  control-exit-code          every refusal face still exits 2
//   G4  control-no-host-path       no refusal carries a host path
//   G5  control-known-command      every repair that names a command names
//                                  one this CLI offers
//
// Usage:
//   node tools/measure-buildtx-input-voice.js [--out <file>] [--published <dir>]
//
//   --published <dir>  run against an INSTALLED signerd (the published
//                      package), so the defect can be measured on the
//                      released tree.
//   --out <file>       where to write the JSON verdict (default:
//                      research/buildtx-input-voice-<date>.json).
//
// No network. Writes only inside os.tmpdir() and the output file.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
function argOf(flag) {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? path.resolve(args[i + 1]) : null;
}
const OUT = argOf('--out') || path.join(REPO, 'research',
  `buildtx-input-voice-${new Date().toISOString().slice(0, 10)}.json`);
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

/** 31 raw bytes in base58: decodes fine, is NOT a 32-byte key. */
const B58_31 = (() => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  // A 31-byte string in base58 is 42-43 chars; pick a fixed valid one by
  // encoding 31 bytes of 0x01 via a tiny local encoder (no deps, no net).
  const bytes = Buffer.alloc(31, 1);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = '';
  while (n > 0n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  return out;
})();

/**
 * The operator's view of a refusal.
 *
 * `fixLine` is the text AFTER the `fix: ` marker - comparing that to the
 * error detail is what detects the echo defect.
 */
function voiceOf(stderr) {
  const text = String(stderr || '');
  const lines = text.split('\n');
  const firstLine = lines.find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  // `code: detail` on the first line; detail starts after the first colon.
  const detail = firstLine.includes(':')
    ? firstLine.slice(firstLine.indexOf(':') + 1).trim() : '';
  const fixRaw = (text.match(/(^|\n)\s*fix:\s*(.*)/) || [])[2] || null;
  return {
    code,
    firstLine: firstLine.slice(0, 200),
    detail,
    hasFix: fixRaw !== null,
    fixText: fixRaw === null ? null : fixRaw.trim(),
    stderrBytes: Buffer.byteLength(text),
    text,
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

function run(argv) {
  const res = spawnSync(process.execPath, [CLI, ...argv], {
    encoding: 'utf8', timeout: 60000,
  });
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

/**
 * Defect (A): no actionable repair. Missing, an echo of the error detail,
 * or a line that names neither a flag nor a command.
 */
function fixIsActionable(v) {
  if (!v.hasFix || v.fixText === null || v.fixText.length === 0) return false;
  const fix = v.fixText;
  // The echo: the repair IS the error detail again (with or without the
  // `build-tx: ` prefix the message carries), in the same words.
  const stripped = fix.replace(/^build-tx:\s*/, '');
  if (v.detail && (stripped === v.detail || fix === v.detail)) return false;
  if (v.detail && stripped === v.detail.replace(/^build-tx:\s*/, '')) return false;
  // Still just the error repeated: fix and message differ only by the flag
  // word `build-tx:` which appears in BOTH by construction.
  const namesFlag = /--[a-z-]+/.test(fix);
  const namesCommand = /signerd\s+[a-z]/.test(fix);
  return namesFlag || namesCommand;
}

/** Defect (B): the flag the operator passed is never named by the refusal.
 *
 *  The FIRST line is what an operator (and a caller reading the first
 *  `:`-separated token) sees - the flag has to be named THERE, not only in
 *  some later line of prose. */
function flagNamed(stderr, flag) {
  const text = String(stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  return firstLine.includes(flag);
}

function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-buildtxvoice-'));
  fs.chmodSync(dir, 0o700);
  const scrub = (text) => String(text || '').split(dir).join('<tmp>');

  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'buildtx-input-voice measurement passphrase\n', { mode: 0o600 });
  const keystore = path.join(dir, 'ops.key');
  const keygen = run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  if (keygen.status !== 0) fail(`control keygen failed: ${keygen.stderr}`);
  const pubkey = JSON.parse(keygen.stdout).publicKey;
  if (typeof pubkey !== 'string' || pubkey.length < 40) fail('keygen printed no publicKey');

  const faces = [];

  const record = (face, res, flag, note) => {
    const v = voiceOf(res.stderr);
    const unknownCommands = repairNamesUnknownCommand(res.stderr);
    const leak = hostPathsIn(res.stderr);
    const actionable = fixIsActionable(v);
    const named = flagNamed(res.stderr, flag);
    const defective = !actionable || !named;
    faces.push({
      face,
      flag,
      note,
      exit: res.status,
      code: v.code,
      stderrHead: scrub(v.firstLine),
      fixHead: scrub((v.fixText || '').slice(0, 200)),
      stderrBytes: v.stderrBytes,
      hasCode: v.code !== '',
      fixActionable: actionable,
      flagNamed: named,
      unknownCommandsInRepair: unknownCommands,
      hostPathInRepair: leak,
      defective,
    });
  };

  const base = (extra) => ['build-tx', '--keystore', keystore, '--to', pubkey,
    '--lamports', '42', '--out', path.join(dir, 'tx.bin'), ...extra];

  // ---- B1 --to is not base58 at all ------------------------------------
  // `--to` given twice would be a duplicate_flag refusal, so the --to faces
  // swap the value IN PLACE (the flag-arity rule keeps this honest).
  const baseTo = (value) => ['build-tx', '--keystore', keystore, '--to', value,
    '--lamports', '42', '--out', path.join(dir, 'tx.bin')];
  record('B1-to-not-base58', run(baseTo('not-a-key!')), '--to',
    'the destination value is not base58 - bs58 speaks');

  // ---- B2 --to is base58 but 31 bytes ----------------------------------
  record('B2-to-wrong-length', run(baseTo(B58_31)), '--to',
    'the destination decodes, but to 31 bytes - web3.js speaks');

  // ---- B3 --blockhash is not base58 ------------------------------------
  record('B3-blockhash-not-base58', run(base(['--blockhash', 'nonsense!!!'])),
    '--blockhash', 'the blockhash value is not base58');

  // ---- B4 --blockhash is base58 but not 32 bytes -----------------------
  record('B4-blockhash-wrong-length', run(base(['--blockhash', B58_31])),
    '--blockhash', 'the blockhash decodes, but not to 32 bytes - buffer speaks');

  // ---- B5 control: the neighbouring keystore face stays named ----------
  {
    const res = run(['build-tx', '--keystore', path.join(dir, 'no-such.key'),
      '--to', pubkey, '--lamports', '42', '--out', path.join(dir, 'tx.bin')]);
    const v = voiceOf(res.stderr);
    faces.push({
      face: 'B5-keystore-face-stays-named',
      flag: '--keystore',
      note: 'the file-input half of build-tx already names itself and its repair',
      exit: res.status,
      code: v.code,
      stderrHead: scrub(v.firstLine),
      fixHead: scrub((v.fixText || '').slice(0, 200)),
      stderrBytes: v.stderrBytes,
      hasCode: v.code !== '',
      fixActionable: fixIsActionable(v),
      flagNamed: flagNamed(res.stderr, '--keystore'),
      unknownCommandsInRepair: repairNamesUnknownCommand(res.stderr),
      hostPathInRepair: hostPathsIn(res.stderr),
      defective: !(v.code === 'keystore_unreadable' && fixIsActionable(v)),
    });
  }

  // ---- G1 control: a legal build still works ---------------------------
  {
    const out = path.join(dir, 'good.bin');
    const res = run(['build-tx', '--keystore', keystore, '--to', pubkey,
      '--lamports', '42', '--out', out]);
    faces.push({
      face: 'G1-control-build-works',
      expect: 'guard',
      note: 'a legal build-tx still exits 0 and writes the wire',
      exit: res.status,
      code: 'ok',
      stderrHead: scrub((res.stderr.split('\n')[0] || '').slice(0, 120)),
      stderrBytes: Buffer.byteLength(res.stderr),
      fixActionable: true,
      flagNamed: true,
      unknownCommandsInRepair: [],
      hostPathInRepair: hostPathsIn(res.stderr),
      defective: !(res.status === 0 && fs.existsSync(out) && fs.statSync(out).size > 0),
    });
  }

  // ---- G2 control: the --lamports voice is untouched -------------------
  {
    const res = run(base([]).map((a) => (a === '42' ? 'fortytwo' : a)));
    const v = voiceOf(res.stderr);
    faces.push({
      face: 'G2-control-lamports-voice',
      expect: 'guard',
      note: 'invalid_lamports keeps its named repair - the fix must not regress it',
      exit: res.status,
      code: v.code,
      stderrHead: scrub(v.firstLine),
      fixHead: scrub((v.fixText || '').slice(0, 200)),
      stderrBytes: v.stderrBytes,
      fixActionable: fixIsActionable(v),
      flagNamed: flagNamed(res.stderr, '--lamports'),
      unknownCommandsInRepair: repairNamesUnknownCommand(res.stderr),
      hostPathInRepair: hostPathsIn(res.stderr),
      defective: !(v.code === 'invalid_lamports' && fixIsActionable(v) &&
        flagNamed(res.stderr, '--lamports')),
    });
  }

  // ---- G3/G4/G5 guards over every face ---------------------------------
  const defectFaces = faces.filter((f) => /^[B]\d/.test(f.face));
  const guards = [
    {
      face: 'G3-control-exit-code',
      note: 'every value refusal still exits 2 - the fix changes what is SAID, never the channel',
      passed: defectFaces.every((f) => f.exit === 2),
    },
    {
      face: 'G4-control-no-host-path',
      note: 'no refusal carries a host path (the operator\'s own fixture paths are scrubbed)',
      passed: faces.every((f) => f.hostPathInRepair !== true),
    },
    {
      face: 'G5-control-known-command',
      note: 'every repair that names a command names one this CLI offers',
      passed: faces.every((f) => (f.unknownCommandsInRepair || []).length === 0),
    },
  ];
  for (const g of guards) {
    faces.push({
      ...g, expect: 'guard', exit: 2, code: 'guard',
      stderrHead: '', stderrBytes: 0,
      fixActionable: true, flagNamed: true,
      unknownCommandsInRepair: [], hostPathInRepair: false,
      defective: !g.passed,
    });
  }

  const defectCount = faces.filter((f) => f.defective).length;
  const judgement = defectCount === 0
    ? 'buildtx-value-inputs-name-their-flag-and-repair'
    : 'buildtx-value-inputs-ship-foreign-prose';

  const result = {
    tool: 'measure-buildtx-input-voice',
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
      console.log(`  DEFECT ${f.face} exit=${f.exit} code=${f.code} ` +
        `fix=${f.fixActionable ? 'ok' : 'ECHO/EMPTY'} flag=${f.flagNamed ? 'named' : 'UNNAMED'}`);
      console.log(`         ${scrub(f.stderrHead)}`);
      if (f.fixHead) console.log(`         fix: ${scrub(f.fixHead)}`);
    }
  }
  console.log(`artifact: ${OUT}`);
  // Exit 0 when the measurement RAN (the verdict is in the artifact, not in
  // the exit code): the tool must be usable on both the defective and the
  // fixed tree.
  process.exit(0);
}

main();
