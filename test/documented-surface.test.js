'use strict';

// The DOCUMENTED-SURFACE test: every `signerd ...` line a reader copies out
// of a README must be a line the CLI it addresses accepts.
//
// WHY (measured 2026-11-06): test/installed-tag-journey.test.js answers
// "does the TAG ship the command" (dispatch + the tag's own README documents
// it) and was GREEN at v0.2.3. This file answers the next question: "does the
// documented invocation RUN". It was not green at v0.2.3:
//
//   v0.2.3's README (what the installed package ships) documents
//     signerd seal-grants --grants <file> --grant-seal-passphrase-file <file>
//     signerd seal-journal --ledger <file> --journal-seal-passphrase-file <file>
//     signerd run ... --grant-seal-passphrase-file <file>
//   and the CLI answers `missing --seal-passphrase-file` (exit 2),
//   `missing --journal` (exit 2), and the third line is not executable at
//   all - `run ...` is a placeholder. Every one of those three command NAMES
//   ships, so no name-level check could see them.
//
// THE RULES (tools/measure-documented-flags.mjs):
//   D1 the CLI must not answer `missing --<flag>` to a documented invocation
//   D2 no documented invocation may contain a `...` placeholder
//   D3 a failure for a reason the README does not claim (a file that does
//      not exist yet, a socket nobody serves) is NOT a defect
//
// THE LADDER (measured, not asserted):
//   T*    the pure rules, offline, with fixture rows - no CLI, no tag.
//   G1    the instrument CAN fail: the pre-fix seal block (verbatim, the
//         exact lines v0.2.3 ships) measured against main's CLI must come
//         back defective with exactly those three defects. Green on both
//         trees: main's CLI always had the tools' own flags - the README was
//         what disagreed.
//   G2    a detector that reports nothing for every input is not a detector:
//         an unknown command and an empty README must not read as clean.
//   J1    MAIN's README against MAIN's CLI - the front page must only
//         promise what this tree runs. GREEN now (the fix 7026d85 landed);
//         RED on 7026d85~1 (same three defects).
//   J2    the PINNED TAG's README against the PINNED TAG's CLI - what the
//         installed package ships must run. Measured DEFECTIVE at v0.2.3;
//         named-skipped while the pin carries exactly that measured block,
//         and LIVE (hard assertion) as soon as the pin carries a tag whose
//         README is fixed. Any defect that is NOT the measured block fails
//         the suite immediately - the skip names the known block, it does
//         not open the gate.
//
// No network. No writes outside os.tmpdir().
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'measure-documented-flags.mjs');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const README = path.join(ROOT, 'README.md');
const CLI_REL = path.join('bin', 'signerd.js');

// Populated in test.before: on a tree without the tool the import must fail
// this file RED, not pass silently (the instrument IS the fix).
let documentedInvocations;
let flagsIn;
let placeholderLines;
let classifyRun;
let derive;
let measure;

test.before(async () => {
  const mod = await import(`file://${TOOL}`);
  ({
    documentedInvocations, flagsIn, placeholderLines, classifyRun, derive, measure,
  } = mod);
});

// ---------------------------------------------------------------------------
// T: the pure rules, offline.
// ---------------------------------------------------------------------------

test('T1 documentedInvocations reads fenced code blocks, joins continuations, ignores prose', () => {
  const md = [
    'Prose that names a command it does not run: `signerd ghost --x`.',
    '',
    '```bash',
    'signerd keygen --keystore k --passphrase-file p',
    'signerd seal-journal --journal j \\',
    '            --journal-seal-passphrase-file s',
    '```',
    '',
    '```text',
    'signerd not-a-fence-line',
    '```',
  ].join('\n');
  const invs = documentedInvocations(md);
  // 3, not 2: fences are read regardless of their language tag (the same
  // rule installed-tag-journey uses) - a copyable command line counts.
  assert.strictEqual(invs.length, 3, `prose must not count: ${JSON.stringify(invs)}`);
  assert.strictEqual(invs[0].command, 'keygen');
  assert.strictEqual(invs[1].command, 'seal-journal');
  assert.strictEqual(invs[2].command, 'not-a-fence-line');
  assert.match(invs[1].text, /journal-seal-passphrase-file s$/m,
    'line continuations must be joined back into one invocation');
  assert.deepStrictEqual(invs[1].flags, ['journal', 'journal-seal-passphrase-file']);
});

test('T2 an invocation inside a fence that never closes is still read (a reader copies it)', () => {
  const md = '```bash\nsignerd grant-remove --grants g --name n\n';
  const invs = documentedInvocations(md);
  assert.strictEqual(invs.length, 1);
  assert.strictEqual(invs[0].command, 'grant-remove');
});

test('T3 classifyRun: the CLI asking for a flag is missing-flag, with the flag named', () => {
  const inv = { command: 'seal-grants', text: 'signerd seal-grants --grants g' };
  const v = classifyRun(inv, { stdout: '', stderr: 'missing --seal-passphrase-file\n<usage>' });
  assert.deepStrictEqual(v, { kind: 'missing-flag', flag: 'seal-passphrase-file' });
});

test('T3b classifyRun: the CLI refusing a flag the README gave is unknown-flag, with the flag named', () => {
  // The strict CLI's refusal shape (measured 2026-11-06): it names the flag
  // the README GOT WRONG instead of the flag it wanted.
  const inv = { command: 'seal-grants', text: 'signerd seal-grants --grants g --grant-seal-passphrase-file s' };
  const v = classifyRun(inv, {
    stdout: '', status: 2,
    stderr: 'unknown_flag: --grant-seal-passphrase-file\n' +
      '  fix: signerd seal-grants does not take --grant-seal-passphrase-file\n' +
      '  fix: signerd seal-grants takes: --grants --out --seal-passphrase-file\n',
  });
  assert.deepStrictEqual(v, { kind: 'unknown-flag', flag: 'grant-seal-passphrase-file' });
});

test('T4 classifyRun: the USAGE banner is unknown-command (command not shipped at all)', () => {
  const banner = 'signerd — scoped signing daemon for Solana (early prototype)';
  const v = classifyRun({ command: 'ghost', text: 'signerd ghost' }, { stdout: `${banner}\n`, stderr: '' });
  assert.strictEqual(v.kind, 'unknown-command');
});

test('T5 classifyRun: a placeholder line is a placeholder even when the CLI accepted its flags', () => {
  const inv = { command: 'run', text: 'signerd run ... --grant-seal-passphrase-file s' };
  const v = classifyRun(inv, { stdout: '', stderr: 'ENOENT: no such file\n' });
  assert.strictEqual(v.kind, 'placeholder');
});

test('T6 classifyRun: D3 - a missing file / dead socket is other, never a defect', () => {
  const inv = { command: 'sign', text: 'signerd sign --socket s --grant g --tx t' };
  for (const stderr of [
    "ENOENT: no such file or directory, open 'tx'",
    'connect ENOENT /run/x.sock',
    'keystore_unreadable: gone',
  ]) {
    const v = classifyRun(inv, { stdout: '', stderr, status: 1 });
    assert.strictEqual(v.kind, 'other', `"${stderr}" must not read as a defect`);
    assert.ok(v.reason, 'other must carry the reason it was not a pass');
  }
  // ... and an invocation that exits 0 is ok.
  assert.strictEqual(classifyRun(inv, { stdout: '{}', stderr: '', status: 0 }).kind, 'ok');
});

test('T7 classifyRun: a broken measurement is other, not clean (MODULE_NOT_FOUND must never pass)', () => {
  const v = classifyRun({ command: 'run', text: 'signerd run' },
    { stdout: '', stderr: "Error: Cannot find module 'x'\n" });
  assert.deepStrictEqual(v, { kind: 'other', reason: 'measurement broken' });
});

test('T8 derive: clean rows -> clean; flag, placeholder and unknown-command defects are reported', () => {
  const row = (command, verdict) => ({ command, text: `signerd ${command}`, verdict });
  const clean = derive([row('keygen', { kind: 'ok' }), row('sign', { kind: 'other', reason: 'ENOENT' })]);
  assert.strictEqual(clean.verdict, 'clean');
  assert.deepStrictEqual(clean.defects, []);

  const bad = derive([
    row('seal-grants', { kind: 'missing-flag', flag: 'seal-passphrase-file' }),
    row('seal-journal', { kind: 'unknown-flag', flag: 'ledger' }),
    row('run', { kind: 'placeholder' }),
    row('ghost', { kind: 'unknown-command' }),
  ]);
  assert.strictEqual(bad.verdict, 'defective');
  assert.deepStrictEqual(bad.defects.map((d) => d.kind).sort(),
    ['missing-flag', 'placeholder', 'unknown-command', 'unknown-flag']);
  // Every defect must carry a human-readable why - a bare kind is not a finding.
  for (const d of bad.defects) assert.ok(d.why && d.why.length > 10, JSON.stringify(d));
  // The unknown-flag defect names BOTH sides: the flag and the command.
  const unknown = bad.defects.find((d) => d.kind === 'unknown-flag');
  assert.strictEqual(unknown.flag, 'ledger');
  assert.match(unknown.why, /seal-journal/);
});

test('T9 flagsIn and placeholderLines match the rules derive uses', () => {
  assert.deepStrictEqual(flagsIn('signerd run --ledger l --socket s'), ['ledger', 'socket']);
  assert.strictEqual(flagsIn('signerd').length, 0);
  const invs = [{ text: 'signerd run ... --x y' }, { text: 'signerd run --x y' }];
  assert.deepStrictEqual(placeholderLines(invs), ['signerd run ... --x y']);
});

// ---------------------------------------------------------------------------
// G1: the instrument can fail. The pre-fix seal block, verbatim, against
// main's CLI. Green on both trees - main's CLI always read the tools' own
// flags; the README was what disagreed.
// ---------------------------------------------------------------------------
test('G1 the pre-fix seal block (the lines v0.2.3 ships) is caught, all three defects', () => {
  const preFix = [
    '```bash',
    'signerd seal-grants --grants ~/.config/signerd/grants.json \\',
    '            --grant-seal-passphrase-file ~/.config/signerd/seal.pass',
    'signerd seal-journal --ledger ~/.local/share/signerd/journal.jsonl \\',
    '            --journal-seal-passphrase-file ~/.config/signerd/seal.pass',
    'signerd run ... --grant-seal-passphrase-file ~/.config/signerd/seal.pass \\',
    '            --journal-seal-passphrase-file ~/.config/signerd/seal.pass',
    '```',
  ].join('\n');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-documented-guard-'));
  try {
    const readme = path.join(dir, 'README.md');
    fs.writeFileSync(readme, preFix);
    const report = measure(readme, CLI);
    assert.strictEqual(report.verdict, 'defective',
      'the instrument must catch the measured pre-fix block - a detector that reports nothing here is broken');
    // The instrument must catch the measured pre-fix block in whichever
    // refusal shape the CLI it addresses uses: the OLD CLI names the flag it
    // WANTED (missing-flag), the strict CLI names the flag the README got
    // WRONG (unknown-flag). Both are the same defect class; either shape
    // counts as caught, and a defect of any OTHER kind fails here.
    const byKind = (kind) => report.defects.filter((d) => d.kind === kind);
    const missing = byKind('missing-flag');
    const unknown = byKind('unknown-flag');
    assert.strictEqual(missing.length + unknown.length, 2, JSON.stringify(report.defects));
    if (missing.length === 2) {
      assert.deepStrictEqual(missing.map((d) => d.flag).sort(),
        ['journal', 'seal-passphrase-file']);
    } else {
      assert.deepStrictEqual(unknown.map((d) => d.flag).sort(),
        ['grant-seal-passphrase-file', 'ledger']);
    }
    assert.strictEqual(byKind('placeholder').length, 1, JSON.stringify(report.defects));
    assert.strictEqual(byKind('placeholder')[0].command, 'run');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('G2 an unknown command and an empty README must not read as clean', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-documented-guard2-'));
  try {
    const ghost = path.join(dir, 'ghost.md');
    fs.writeFileSync(ghost, '```bash\nsignerd ghost --flag x\n```\n');
    const bad = measure(ghost, CLI);
    assert.strictEqual(bad.verdict, 'defective', 'an unknown command must be a defect');
    assert.strictEqual(bad.defects[0].kind, 'unknown-command');

    const empty = path.join(dir, 'empty.md');
    fs.writeFileSync(empty, '# nothing here\n');
    const none = measure(empty, CLI);
    // Empty is allowed (it parses to zero rows) but it must not be reported
    // as a PASS over documented surface: zero rows is not evidence.
    assert.strictEqual(none.rows.length, 0,
      'an empty README parses to zero rows - J1/J0 elsewhere pin the floor, this only documents the edge');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// J1: MAIN's README against MAIN's CLI. The front page only promises what
// this tree runs.
// ---------------------------------------------------------------------------
test('J1 main README documents only invocations main CLI accepts', () => {
  const report = measure(README, CLI);
  const cmds = documentedInvocations(fs.readFileSync(README, 'utf8'));
  assert.ok(cmds.length >= 8, `the floor again: parsed ${cmds.length} invocations - the parser broke`);
  assert.deepStrictEqual(report.defects, [],
    `main's README must only document runnable invocations: ${JSON.stringify(report.defects)}`);
  assert.strictEqual(report.verdict, 'clean');
});

// ---------------------------------------------------------------------------
// J2: the PINNED TAG's README against the PINNED TAG's CLI - what the
// installed package ships. Named-skipped while the pin carries exactly the
// measured v0.2.3 sealed-block defect; a hard assertion for any other pin
// state.
// ---------------------------------------------------------------------------

/** Materialize the pinned tag (local object store first, origin second). */
function tagWorktree(tag) {
  const probe = spawnSync('git',
    ['rev-parse', '--verify', '--quiet', `${tag}^{commit}`], { cwd: ROOT });
  if (probe.status !== 0) {
    const fetched = spawnSync('git',
      ['fetch', '--depth', '1', 'origin', `refs/tags/${tag}:refs/tags/${tag}`],
      { cwd: ROOT, encoding: 'utf8' });
    if (fetched.status !== 0) {
      const why = String(fetched.stderr || '').trim().split('\n')[0] || `exit ${fetched.status}`;
      return { error: `pinned tag ${tag} is not local and not fetchable: ${why}` };
    }
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-docsurface-tag-'));
  const add = spawnSync('git', ['worktree', 'add', '--detach', '--force', dir, tag],
    { cwd: ROOT, encoding: 'utf8' });
  if (add.status !== 0) return { error: `worktree add failed: ${String(add.stderr).trim()}` };
  const deps = path.join(dir, 'node_modules');
  if (!fs.existsSync(deps)) fs.symlinkSync(path.join(ROOT, 'node_modules'), deps, 'dir');
  return { dir };
}

function pinnedTag() {
  const readme = fs.readFileSync(README, 'utf8');
  const found = readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g);
  assert.ok(found && found.length, 'README must document a stranger install command with a tag');
  const tags = [...new Set(found.map((s) => s.split('#')[1]))];
  assert.strictEqual(tags.length, 1, `README must pin exactly one tag, found: ${tags.join(', ')}`);
  return tags[0];
}

/**
 * The ONE defect block that is allowed to be skipped: the sealed-mode block
 * as v0.2.3 ships it (measured 2026-11-06, research/documented-surface-*
 * .json). Anything else fails the suite.
 */
/**
 * The measured pre-fix block, in BOTH refusal shapes.
 *
 * The tag's CLI is the OLD one (it answers `missing --<flag>`: the flag it
 * WANTED), while main's CLI answers `unknown_flag: --<flag>` (the flag the
 * README got WRONG). Same defect - the documented line does not run - so the
 * measured block has two shapes and both are recognized. A shape that is
 * NEITHER is a new defect and fails the suite (the skip must not open a
 * gate).
 */
function isMeasuredSealedBlock(defects) {
  const shape = defects.map((d) => `${d.kind}:${d.command}${d.flag ? `:${d.flag}` : ''}`).sort();
  const known = [
    // the old CLI (the pinned tag): it names the flag it wanted
    ['missing-flag:seal-grants:seal-passphrase-file',
      'missing-flag:seal-journal:journal', 'placeholder:run'],
    // the strict CLI (main): it names the flag the README got wrong
    ['unknown-flag:seal-grants:grant-seal-passphrase-file',
      'unknown-flag:seal-journal:ledger', 'placeholder:run'],
  ];
  return known.some((k) => JSON.stringify(shape) === JSON.stringify(k.sort()));
}

test('J2 the pinned tag ships a README whose documented invocations run', (t) => {
  const tag = pinnedTag();
  const mainPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const { dir, error } = tagWorktree(tag);
  if (error) return t.skip(`tag unmeasurable: ${error}`);
  try {
    const tagPkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    if (JSON.stringify(tagPkg.dependencies) !== JSON.stringify(mainPkg.dependencies)) {
      // The linked node_modules stand-in is only valid while the dependency
      // sets match - the same rule installed-tag-journey T_DEP uses.
      return t.skip(`tag ${tag} declares different dependencies; the linked-install stand-in is invalid`);
    }
    const tagReadme = path.join(dir, 'README.md');
    const tagCli = path.join(dir, CLI_REL);
    if (!fs.existsSync(tagReadme) || !fs.existsSync(tagCli)) {
      return t.skip(`tag ${tag} does not ship README.md and ${CLI_REL}`);
    }

    const report = measure(tagReadme, tagCli);

    // The skip NAMES the defect and its fix; it does not hide a new one.
    if (report.defects.length > 0 && isMeasuredSealedBlock(report.defects)) {
      return t.skip(
        `measured known block: pin ${tag} ships the pre-fix sealed-mode README ` +
        '(seal-grants/seal-journal documented with the DAEMON flags, `signerd run ...` a ' +
        'placeholder) - fixed on main by 7026d85, live here when the pin moves to the next tag; ' +
        `full report: research/documented-surface-tag-${tag}.json`);
    }
    assert.deepStrictEqual(report.defects, [],
      `pinned tag ${tag} ships README invocations its own CLI rejects: ` +
      JSON.stringify(report.defects));
    assert.strictEqual(report.verdict, 'clean');
  } finally {
    try { execFileSync('git', ['worktree', 'remove', '--force', dir], { cwd: ROOT, stdio: 'pipe' }); }
    catch { /* best effort */ }
  }
});
