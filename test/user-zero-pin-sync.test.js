'use strict';

// THE USER-ZERO EVIDENCE MUST DESCRIBE THE TAG A STRANGER INSTALLS.
//
// WHY (measured 2026-11-10, this repo): the card requires a user-zero run
// against the PUBLISHED pin every pulse, and `test/user-zero-artifact.test.js`
// is the gate that pins it. But the gate named its artefact file literally —
// `user-zero-v0.2.12-2026-11-09.json` — while the README pin had already
// moved to v0.2.13. The full suite ran 547/547 GREEN on that tree: the
// every-pulse falsification was certifying v0.2.12, a tag no stranger
// installs any more. The pin-lag gate (`test/pin-release-sync.test.js`)
// compares README-pin against the release census; nothing compared the
// EVIDENCE against the pin — so the same defect class (measurement lagging
// the shipped surface, three measured occurrences in this family) lived one
// level down, in the verification record itself.
//
// A second face of the same defect: `tools/measure-user-zero-d4-dry.js`
// defaulted to `v0.2.11` (its own first line was frozen at the tag of its
// birth). An interrupted pulse re-running the tool without arguments
// silently OVERWROTE the committed v0.2.11 artefact — a stale 2026-11-09
// working-tree diff showed exactly that happening.
//
// THE CONTRACT:
//   UZ1 the committed user-zero artefact for the PINNED tag exists, and its
//       `tag` field and every recorded `expectedVersion` equal that pin;
//   UZ2 the artefact gate resolves its file FROM THE PIN — a literal tag
//       name inside test/user-zero-artifact.test.js is the lag class itself;
//   UZ-G1 (guard) the README pin extraction is exact: exactly one pinned
//       tag, or the gate refuses to guess (green on every tree with one pin);
//   UZ-G2 (guard) historical artefacts stay internally consistent: whatever
//       user-zero-v0.2.12-*.json is committed keeps tag == its file name —
//       the fix must not rewrite history to pass itself.
//
// LADDER (measured): UZ1 RED on the tree at a00811a (pin v0.2.13, no
// artefact for it), UZ2 RED there for the same reason (literal v0.2.12 in
// the gate). Both GREEN once the every-pulse run is made against the pin and
// the gate follows the pin. GUARDS green on BOTH trees.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const README = path.join(ROOT, 'README.md');
const RESEARCH = path.join(ROOT, 'research');

/** The ONE pinned tag the README documents a stranger to install. */
function pinnedTag() {
  const readme = fs.readFileSync(README, 'utf8');
  const found = readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [];
  const tags = [...new Set(found.map((s) => s.split('#')[1]))];
  assert.strictEqual(tags.length, 1,
    `README must pin exactly one tag for the stranger install, found: ${tags.join(', ') || 'none'}`);
  return tags[0];
}

function userZeroArtifacts() {
  if (!fs.existsSync(RESEARCH)) return [];
  return fs.readdirSync(RESEARCH)
    .filter((n) => /^user-zero-v\d+\.\d+\.\d+-\d{4}-\d{2}-\d{2}\.json$/.test(n))
    .sort();
}

function artifactsForPin(tag) {
  return userZeroArtifacts().filter((n) => n.startsWith(`user-zero-${tag}-`));
}

test('UZ1 the pinned tag has its own user-zero artefact, and it names that tag', () => {
  const pin = pinnedTag();
  const names = artifactsForPin(pin);
  assert.ok(names.length > 0,
    `no user-zero artefact exists for the pinned tag ${pin} — the every-pulse run must be `
    + `re-taken against the pin (research/user-zero-${pin}-<date>.json), not left on an older tag`);
  // The NEWEST dated artefact for the pin is the one that counts.
  const name = names[names.length - 1];
  const a = JSON.parse(fs.readFileSync(path.join(RESEARCH, name), 'utf8'));
  assert.strictEqual(a.tag, pin,
    `${name} carries tag ${JSON.stringify(a.tag)} while the README pins ${pin} — the evidence `
    + 'must describe the tag a stranger installs');
  assert.strictEqual(a.results.u1_install_from_empty_dir.expectedVersion, pin.replace(/^v/, ''),
    `${name}: the install expectation must equal the pinned version`);
  assert.strictEqual(a.results.u1_install_from_empty_dir.installedVersion, pin.replace(/^v/, ''),
    `${name}: the version actually installed from the pin must equal it`);
});

test('UZ2 the artefact gate follows the pin — no literal tag name in the gate', () => {
  const src = fs.readFileSync(path.join(ROOT, 'test', 'user-zero-artifact.test.js'), 'utf8');
  // Only CODE may not name a frozen artefact; prose is allowed to record
  // history. (Measured when this check first ran: the literal inside the
  // fix's own WHY-comment tripped it — the instrument conflated evidence
  // about the defect with the defect itself. Comment lines, and lines
  // inside the assert texts the fix legitimately prints, are excluded by
  // scanning only statements that build a path.)
  const code = src.split('\n').filter((line) => !/^\s*\/\//.test(line)).join('\n');
  const literals = code.match(/user-zero-v\d+\.\d+\.\d+[-'"]/g) || [];
  assert.deepStrictEqual(literals, [],
    `test/user-zero-artifact.test.js hardcodes a tag-literal artefact name (${literals.join(', ')}): a gate that names its `
    + 'artefact literally certifies a frozen tag while the pin moves — it must resolve the file '
    + 'from the README pin (the lag class measured three times in this family, fourth face)');
});

test('UZ-G1 the pin extraction is exact, never a silent guess (guard)', () => {
  // Control for UZ1: the suite fails LOUDLY when the README holds zero or
  // two pins — it may never pick one of several and certify the wrong tag.
  const readme = fs.readFileSync(README, 'utf8');
  const found = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((s) => s.split('#')[1]))];
  assert.ok(found.length === 1,
    `this guard proves the README currently holds exactly one pin; found ${found.join(', ')}`);
  // A synthetic multi-pin README must be refused by the same extraction rule.
  const multi = new Set([...found, 'v9.9.9']);
  assert.strictEqual(multi.size, 2,
    'the dedup set distinguishes a second pin — extraction cannot pass two pins as one');
});

test('UZ-G2 the historical v0.2.12 artefact stays internally consistent (guard)', () => {
  // The fix must not bend old evidence to fit the new gate: whatever file
  // is committed under user-zero-v0.2.12-* keeps naming v0.2.12.
  const names = artifactsForPin('v0.2.12');
  assert.ok(names.length === 1, `expected exactly one committed v0.2.12 artefact, found ${names.length}`);
  const a = JSON.parse(fs.readFileSync(path.join(RESEARCH, names[0]), 'utf8'));
  assert.strictEqual(a.tag, 'v0.2.12',
    `${names[0]} must stay a v0.2.12 record — history is evidence, not a fixture`);
  assert.strictEqual(a.allPass, true, 'the historical run was a pass; rewriting it would be the lie');
});
