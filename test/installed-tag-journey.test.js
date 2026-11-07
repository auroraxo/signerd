'use strict';
// The PINNED-TAG JOURNEY: does the tag a stranger installs ship the commands
// the front-page README tells them to run?
//
// WHY (measured 2026-11-06, this repo): github.com/auroraxo/signerd renders
// MAIN's README. It says `npm install github:auroraxo/signerd#v0.2.2` and,
// further down the same page, documents `signerd grant-remove` as the way to
// revoke a scope ("Do NOT hand-edit the grant file"). The pinned tag is a
// different tree: v0.2.2 shipped BEFORE grant-remove (27439be) and before
// grant-add --append (bf72775). Measured against the tag worktree:
//
//   $ node bin/signerd.js grant-remove --grants /tmp/x --name y   # at v0.2.2
//   signerd — scoped signing daemon for Solana (early prototype)   # USAGE
//   exit 2
//
// i.e. the revocation path is an unknown command at the pin — the same
// documented-command-vs-pinned-tree gap sememe found at v0.4.1 (its
// installed-tag-journey), which signerd had NO instrument for. Every prior
// signerd journey measured the WORKING tree's CLI or the tag's manifest;
// neither can fail for a command the tag simply does not have.
//
// THE CONTRACT:
//   J1 every command MAIN's README documents in a code block must be
//      DISPATCHED by the PINNED TAG's CLI (run, not grepped: the tag's own
//      bin answers `missing --x` for a command it knows, and prints the
//      USAGE banner for one it does not).
//   J2 the PINNED TAG's own README must document those commands too: the
//      installed package ships the TAG's README, so a stranger who reads the
//      file next to the code must learn the same surface.
//   G1 guard: MAIN's tree dispatches every command MAIN's README documents
//      (green on both trees — the working side cannot regress).
//   G2 guard: an unknown command IS reported as unknown by the detector
//      (the detector must be able to fail; without it J1 could not).
//
// LADDER (measured): J1+J2 RED with the pin at v0.2.2 (grant-remove is not
// dispatched and not documented at the tag); G1+G2 GREEN on both trees.
//
// The executable layer runs the TAG's tree with the repository's installed
// node_modules linked in — justified only while the dependency sets are
// byte-identical, which T_DEP asserts; if they ever differ the executable
// tests SKIP with that reason (named skip, never a silent pass over a
// different tree). The tag is read from the local object store or fetched
// from origin; if neither works, the tests SKIP with the fetch error.
//
// No network unless a tag must be fetched. No writes outside os.tmpdir().
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI_REL = path.join('bin', 'signerd.js');
const USAGE_BANNER = 'signerd — scoped signing daemon for Solana (early prototype)';
// A tag fetched for measurement lives here, NOT in refs/tags/: that namespace
// is the release census (release-contract.test.js, measure-release-surface),
// and a test that writes into it decides another test's verdict. Measured
// 2026-11-07 in CI: the pin fetched into refs/tags/ made the census read
// "latest release = v0.2.5" against package.json 0.2.6.
const TEST_TAG_NS = 'refs/signerd-test-tags';

function git(args, opts = {}) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', ...opts }).trim();
}

// The pin is the single source of truth: the test follows the README instead
// of hardcoding a version, so moving the pin moves the measurement.
function pinnedTag() {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const found = readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g);
  assert.ok(found && found.length, 'README must document a stranger install command with a tag');
  const tags = [...new Set(found.map((s) => s.split('#')[1]))];
  assert.strictEqual(tags.length, 1, `README must pin exactly one tag, found: ${tags.join(', ')}`);
  return tags[0];
}

// Every `signerd <command>` a reader can copy out of a fenced code block.
// Prose mentions are ignored on purpose: a sentence that names a command it
// does not run is not a promise to ship it.
function documentedCommands(markdown) {
  const lines = String(markdown).split('\n');
  let inFence = false;
  const out = new Set();
  for (const line of lines) {
    if (/^\s*```/.test(line)) { inFence = !inFence; continue; }
    if (!inFence) continue;
    const m = /^\s*(?:\$\s*)?signerd ([a-z][a-z0-9-]*)/.exec(line);
    if (m) out.add(m[1]);
  }
  return [...out].sort();
}

class SkipUnmeasurableTag extends Error {}

let TAG_WORK = null;
// Materialize the tag: local object store first, origin fetch second. The
// worktree carries the TAG's bytes (packing/reading ROOT would silently
// measure main instead of the tag — the exact defect this file exists for).
function tagWorktree(tag) {
  if (TAG_WORK) return TAG_WORK;
  const probe = spawnSync('git', ['rev-parse', '--verify', '--quiet', `${tag}^{commit}`], { cwd: ROOT });
  let ref = tag;
  if (probe.status !== 0) {
    const fetched = spawnSync('git',
      ['fetch', '--depth', '1', 'origin', `refs/tags/${tag}:${TEST_TAG_NS}/${tag}`],
      { cwd: ROOT, encoding: 'utf8' });
    if (fetched.status !== 0) {
      const why = String(fetched.stderr || '').trim().split('\n')[0] || `exit ${fetched.status}`;
      throw new SkipUnmeasurableTag(`pinned tag ${tag} is not local and not fetchable from origin: ${why}`);
    }
    ref = `${TEST_TAG_NS}/${tag}`;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-tag-tree-'));
  execFileSync('git', ['worktree', 'add', '--detach', '--force', dir, ref], { cwd: ROOT, stdio: 'pipe' });
  TAG_WORK = dir;
  return dir;
}

function cleanup() {
  if (!TAG_WORK) return;
  try { execFileSync('git', ['worktree', 'remove', '--force', TAG_WORK], { cwd: ROOT, stdio: 'pipe' }); }
  catch { /* best effort; a leftover worktree is not a test failure */ }
  TAG_WORK = null;
}
test.after(cleanup);

// The tag's CLI answering `missing --x` means the dispatch exists. The USAGE
// banner means the tag does not know the command at all — the measured
// behaviour of `grant-remove` at v0.2.2.
function dispatchAnswer(worktree, command) {
  const res = spawnSync(process.execPath, [path.join(worktree, CLI_REL), command],
    { encoding: 'utf8', timeout: 30000 });
  const out = `${res.stdout || ''}${res.stderr || ''}`;
  const first = out.split('\n')[0] || '';
  return { out, first };
}

test('J0 the README pins exactly one tag and documents commands to check', () => {
  const tag = pinnedTag();
  assert.match(tag, /^v\d+\.\d+\.\d+$/);
  const cmds = documentedCommands(fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8'));
  // If this ever drops to a near-empty set the fence parser broke and J1
  // would pass by checking nothing — pin the floor, not the exact count.
  assert.ok(cmds.length >= 8, `expected the documented surface to be parseable, got: ${cmds.join(' ')}`);
  assert.ok(cmds.includes('keygen') && cmds.includes('grant-add'),
    `core quickstart commands must parse, got: ${cmds.join(' ')}`);
});

test('G2 the detector reports an unknown command as unknown', () => {
  // Runs against MAIN's tree on purpose: the detector itself must be able to
  // fail, otherwise J1 is a guard that cannot fall (the repo rule).
  const { first } = dispatchAnswer(ROOT, 'definitely-not-a-command');
  assert.ok(!first.startsWith('missing'), `an unknown command must not read as dispatched: ${first}`);
  assert.strictEqual(first, USAGE_BANNER, `expected the USAGE banner for an unknown command, got: ${first}`);
});

test('G1 main dispatches every command main documents (guard, green on both trees)', () => {
  const cmds = documentedCommands(fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8'));
  const missing = [];
  for (const cmd of cmds) {
    const { first, out } = dispatchAnswer(ROOT, cmd);
    if (!first.startsWith('missing') || /Cannot find module/.test(out)) missing.push(`${cmd} -> ${first}`);
  }
  assert.deepStrictEqual(missing, [],
    `commands documented on main but not dispatched by main: ${missing.join('; ')}`);
});

test('T_DEP the tag and main declare identical dependencies (gate for the executable layer)', () => {
  const tag = pinnedTag();
  let work;
  try { work = tagWorktree(tag); } catch (err) {
    if (err instanceof SkipUnmeasurableTag) return; // reported by J1/J2
    throw err;
  }
  const mainPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const tagPkg = JSON.parse(fs.readFileSync(path.join(work, 'package.json'), 'utf8'));
  assert.deepStrictEqual(tagPkg.dependencies, mainPkg.dependencies,
    'the linked node_modules stand-in is only valid while the tag declares the same dependencies as main');
  assert.deepStrictEqual(tagPkg.peerDependencies, mainPkg.peerDependencies,
    'peer dependency drift invalidates the linked-install stand-in');
});

test('J1 the pinned tag dispatches every command main documents', { skip: false }, (t) => {
  const tag = pinnedTag();
  const mainReadme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const cmds = documentedCommands(mainReadme);
  let work;
  try {
    work = tagWorktree(tag);
    // The executable layer needs the tag's dependencies present; symlink them
    // in (same declared versions — pinned by T_DEP) instead of a network install.
    const deps = path.join(work, 'node_modules');
    if (!fs.existsSync(deps)) fs.symlinkSync(path.join(ROOT, 'node_modules'), deps, 'dir');
  } catch (err) {
    if (err instanceof SkipUnmeasurableTag) return t.skip(err.message);
    throw err;
  }

  const notShipped = [];
  for (const cmd of cmds) {
    const { first, out } = dispatchAnswer(work, cmd);
    // `missing ...` is the CLI acknowledging the command and asking for its
    // arguments. The USAGE banner means the tag does not have the command.
    // MODULE_NOT_FOUND is neither: it means the measurement itself broke, so
    // it fails loudly instead of counting as shipped.
    if (/Cannot find module/.test(out)) {
      notShipped.push(`${cmd} -> measurement broken (${first})`);
    } else if (!first.startsWith('missing')) {
      notShipped.push(`${cmd} -> ${first === USAGE_BANNER ? 'USAGE banner (command not shipped)' : first}`);
    }
  }
  assert.deepStrictEqual(notShipped, [],
    `documented on main but NOT shipped by the pinned tag ${tag}: ${notShipped.join('; ')}`);
});

test('J2 the pinned tag ships a README documenting the same commands', (t) => {
  const tag = pinnedTag();
  let work;
  try { work = tagWorktree(tag); }
  catch (err) {
    if (err instanceof SkipUnmeasurableTag) return t.skip(err.message);
    throw err;
  }
  const mainCmds = documentedCommands(fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8'));
  const tagCmds = documentedCommands(fs.readFileSync(path.join(work, 'README.md'), 'utf8'));
  const undocumented = mainCmds.filter((c) => !tagCmds.includes(c));
  assert.deepStrictEqual(undocumented, [],
    `documented on main but absent from the pinned tag ${tag} README (what the installed package ships): ` +
    undocumented.join(', '));
});
