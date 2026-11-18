'use strict';

// THE MISSING-FLAG VOICE: an absent required flag refuses like every other
// refusal this CLI prints (2026-11-19).
//
// WHY (measured 2026-11-19, tree 16ba572, tools/measure-missing-flag-voice.js
// on research/missing-flag-voice-prefix-2026-11-19.json, verdict
// missing-flag-voice-mute 14/14): the flag ARITY refusals print
// `<code>: ...` + `fix:` + exit 2 (duplicate_flag, missing_value,
// flag_takes_no_value), build-tx answers `missing_argument: build-tx needs
// --keystore` + fix, the daemon answers every verdict with code + fix.
// The ABSENT flag did not:
//
//     $ signerd sign
//     missing --socket
//     <77-line banner>          <- no `code:` line, no `fix:` line, exit 2
//
//     $ signerd keygen --keystore k
//     missing --passphrase-file <- nothing at all beyond prose
//
// The face escaped every existing gate because it carries NO code token:
// test/refusal-voice-coverage.test.js compares scraped CODES against the
// REPAIRS map, and this refusal never had a code to scrape. The README
// promise ("Refusals name the flag and the fix instead of failing
// silently") therefore had a silent hole — the usage-voice class.
//
// THE CONTRACT (D = defect face, RED on the pre-fix tree; G = guard, green
// on BOTH trees):
//   D1 an absent required flag answers `missing_flag: --<flag>` as its
//      FIRST line (code named exactly once), never bare prose;
//   D2 the refusal carries a `fix:` line that names the absent flag;
//   D3 the fix also names the flags the command actually takes, read from
//      src/cli-flags.js COMMAND_FLAGS — the same surface the unknown_flag
//      voice names (no hand-written copy);
//   D4 exit stays 2 (a usage question ran nothing);
//   D5 stdout stays empty (a usage question is not a verdict frame);
//   D6 no host path in any fix line (rule 3 of src/refusal-voice.js);
//   D7 both call sites speak it: requireArg (keygen) AND readPassphrase
//      (the seal/passphrase family, which printed not even a banner);
//   G1 guard: the happy path still works (keygen exit 0, file created);
//   G2 guard: the unknown_flag voice is unchanged (its own shape);
//   G3 guard: an unknown command still answers the USAGE banner first
//      (tools/measure-documented-flags.mjs classifies commands by it);
//   G4 guard: build-tx keeps missing_argument + fix (the parity anchor);
//   G5 guard: the arity refusals keep their shapes (duplicate_flag,
//      missing_value) — this fix must not reclassify TYPED problems.
//
// HOW: the checkout's own CLI in a temp sandbox. No network, no daemon.
// LADDER: D1-D7 RED pre-fix, G1-G5 GREEN on both; see
// tools/mutation-ladder-missing-flag-voice.sh for the mutation ladder.
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const { COMMAND_FLAGS } = require(path.join(ROOT, 'src', 'cli-flags.js'));

function sh(argv) {
  const r = spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', timeout: 60000 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mf-gate-'));
test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });
const cfg = path.join(dir, 'cfg');
fs.mkdirSync(cfg, { mode: 0o700 });
const pass = path.join(cfg, 'pass');
fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });

/** One absent-flag face: the run must refuse in the voice, naming `flag`. */
function assertVoice(res, command, flag, label) {
  const first = res.stderr.split('\n')[0] || '';
  assert.strictEqual(first, `missing_flag: --${flag}`,
    `${label}: first line must be the code, got ${JSON.stringify(first)}`);
  const codes = res.stderr.match(/\bmissing_flag\b/g) || [];
  assert.strictEqual(codes.length, 1, `${label}: the code appears exactly once, got ${codes.length}`);
  const fixes = res.stderr.split('\n').filter((l) => /^\s*fix:/.test(l));
  assert.ok(fixes.length >= 1, `${label}: a fix line is required, stderr=${JSON.stringify(res.stderr)}`);
  // D2: the flag must be named by a DIRECT fix line — not just incidentally
  // by the takes list, which also contains every supported flag.
  const directFixes = fixes.filter((l) => !l.includes('takes:'));
  assert.ok(directFixes.length >= 1,
    `${label}: a fix beyond the takes list is required, got ${JSON.stringify(fixes)}`);
  assert.ok(directFixes.join('\n').includes(`--${flag}`),
    `${label}: the fix must name the absent flag --${flag}, got ${JSON.stringify(directFixes)}`);
  const takes = fixes.find((l) => l.includes(`signerd ${command} takes:`));
  assert.ok(takes, `${label}: the fix must name the surface of \`signerd ${command}\``);
  const listed = takes.replace(/^.*takes:/, '').trim().split(/\s+/).map((f) => f.replace(/^--/, ''));
  const supported = COMMAND_FLAGS[command];
  assert.ok(supported && supported.length > 0, `${label}: COMMAND_FLAGS must know ${command}`);
  assert.deepStrictEqual([...listed].sort(), [...supported].sort(),
    `${label}: the takes list must be exactly the real surface`);
  assert.ok(!/[\\/]home[\\/]|[\\/]tmp[\\/]/.test(fixes.join('\n')),
    `${label}: a fix line must not carry a host path`);
  assert.strictEqual(res.status, 2, `${label}: exit 2, got ${res.status}`);
  assert.strictEqual(res.stdout.trim(), '', `${label}: stdout stays empty, got ${JSON.stringify(res.stdout)}`);
}

test('D1/D2/D3/D4/D5/D6: requireArg faces speak the voice (keygen, sign, status, migrate)', () => {
  assertVoice(sh(['keygen', '--keystore', path.join(cfg, 'f.key')]),
    'keygen', 'passphrase-file', 'keygen missing passphrase-file');
  assertVoice(sh(['sign']), 'sign', 'socket', 'sign missing socket');
  assertVoice(sh(['sign', '--socket', path.join(cfg, 's.sock'), '--grant', 'g']),
    'sign', 'tx', 'sign missing tx');
  assertVoice(sh(['status']), 'status', 'grants', 'status missing grants');
  assertVoice(sh(['migrate']), 'migrate', 'ledger', 'migrate missing ledger');
});

test('D7: readPassphrase faces speak the same voice (seal family printed prose only)', () => {
  assertVoice(sh(['verify-grants', '--grants', path.join(cfg, 'g.json')]),
    'verify-grants', 'seal-passphrase-file', 'verify-grants missing seal pass');
  assertVoice(sh(['seal-grants', '--grants', path.join(cfg, 'g.json')]),
    'seal-grants', 'seal-passphrase-file', 'seal-grants missing seal pass');
  assertVoice(sh(['seal-journal']), 'seal-journal', 'journal', 'seal-journal missing journal');
});

test('D3 edge: the takes list comes from COMMAND_FLAGS, not a copy (grant-add full surface)', () => {
  const res = sh(['grant-add', '--grants', path.join(cfg, 'g.json'), '--name', 'n',
    '--signer', '11111111111111111111111111111111']);
  assertVoice(res, 'grant-add', 'destination', 'grant-add missing destination');
});

test('G1 guard: the happy path still works (green on both)', () => {
  const ks = path.join(dir, 'happy.key');
  const res = sh(['keygen', '--keystore', ks, '--passphrase-file', pass]);
  assert.strictEqual(res.status, 0, `keygen must succeed: ${res.stderr}`);
  assert.ok(fs.existsSync(ks), 'the keystore must exist');
});

test('G2 guard: the unknown_flag voice is unchanged (green on both)', () => {
  const res = sh(['keygen', '--definitely-not-a-flag']);
  assert.strictEqual(res.status, 2, `exit 2: ${res.stderr}`);
  assert.match(res.stderr, /^unknown_flag: --definitely-not-a-flag$/m,
    `unknown_flag keeps its shape: ${res.stderr}`);
  assert.match(res.stderr, /^\s*fix:/m, `unknown_flag keeps its fix: ${res.stderr}`);
  assert.ok(!/^missing_flag:/m.test(res.stderr),
    `unknown_flag must not be reclassified as a missing flag: ${res.stderr}`);
});

test('G3 guard: an unknown command still answers the USAGE banner first (green on both)', () => {
  const res = sh(['definitely-not-a-command']);
  assert.strictEqual(res.status, 2, `exit 2: ${res.stderr}`);
  assert.strictEqual((res.stderr.split('\n')[0] || '').trim(),
    'signerd — scoped signing daemon for Solana (early prototype)',
    `the banner stays first — measure-documented-flags classifies by it: ${res.stderr.split('\n')[0]}`);
  assert.ok(!/^missing_flag:/m.test(res.stderr), 'an unknown command is not a missing flag');
});

test('G4 guard: build-tx keeps missing_argument + fix (parity anchor, green on both)', () => {
  const res = sh(['build-tx']);
  assert.strictEqual(res.status, 2, `exit 2: ${res.stderr}`);
  assert.match(res.stderr, /^missing_argument: build-tx needs --keystore$/m,
    `build-tx keeps its own voice: ${res.stderr}`);
  assert.match(res.stderr, /^\s*fix:/m, `build-tx keeps its fix: ${res.stderr}`);
});

test('G5 guard: arity refusals keep their shapes (typed, not forgotten — green on both)', () => {
  const dup = sh(['keygen', '--keystore', path.join(cfg, 'a.key'),
    '--keystore', path.join(cfg, 'b.key')]);
  assert.match(dup.stderr, /^duplicate_flag: --keystore$/m,
    `duplicate_flag keeps its shape: ${dup.stderr}`);
  const miss = sh(['keygen', '--keystore', path.join(cfg, 'c.key'), '--passphrase-file']);
  assert.match(miss.stderr, /^missing_value: --passphrase-file$/m,
    `missing_value keeps its shape: ${miss.stderr}`);
  assert.match(miss.stderr, /^\s*fix:/m, `missing_value keeps its fix: ${miss.stderr}`);
});
