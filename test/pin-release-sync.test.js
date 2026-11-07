'use strict';

// THE PIN MUST NOT LAG THE RELEASES.
//
// WHY (measured 2026-11-07, this repo): the front-page README is the install
// path a stranger copies — `npm install github:auroraxo/signerd#v0.2.5` —
// while the release census already said v0.2.6. Two releases of headroom
// were spent that way: the v0.2.5 pin shipped WITHOUT the unwritable-`--out`
// preflight (b58d378, released as v0.2.6) and without the exit-3 delivery
// contract (f3d259d, on main only at the time of this measurement). Nothing
// in the suite could fail for it: `release-contract` ties the NEWEST TAG to
// package.json, `installed-tag-journey` measures whatever the pin says —
// and no test ever compared the two. The pin was free to drift, and did:
// v0.2.4 pin while v0.2.5 was out, then v0.2.5 pin while v0.2.6 was out.
//
// THE CONTRACT:
//   P1 the README pin must not name a tag OLDER than the newest release
//      tag in the census. A lagging pin is exactly the state where a
//      stranger installs a tree the front page already describes as fixed.
//   T1-T4 controls: the verdict is a PURE function of (pin, tags), so the
//      lag rule is pinned OFFLINE and in every direction — equal = synced,
//      pin ahead = release in progress (the moment THIS release passes
//      through), pin behind = the measured defect, no tags = unmeasurable,
//      never a verdict (the crates.io-403 rule: a missing census is not a
//      clean one).
//
// LADDER (measured): P1 RED on the tree at 069edfc — pin v0.2.5 against
// release v0.2.6, the defect this file exists for. GREEN once the pin moves
// with the release it belongs to.
//
// A tagless clone (fetch-depth 1, fetch-tags false) has no census: the test
// is then a NAMED skip, not a silent pass — `release-contract` still owns
// the tag/package.json agreement in that checkout.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const README = path.join(ROOT, 'README.md');

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
}

function semverOf(tag) {
  const m = /^v(\d+)\.(\d+)\.(\d+)$/.exec(tag);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function newestReleaseTag(tags) {
  let best = null;
  let bestKey = null;
  for (const t of tags) {
    const k = semverOf(t);
    if (!k) continue;
    if (!bestKey || k[0] > bestKey[0]
      || (k[0] === bestKey[0] && (k[1] > bestKey[1] || (k[1] === bestKey[1] && k[2] > bestKey[2])))) {
      best = t; bestKey = k;
    }
  }
  return best;
}

/**
 * The ONE rule, pure: does the pin lag the releases?
 *   'lagging'    the pin names an OLDER tag than the newest release
 *                -> the measured defect, must fail
 *   'synced'     pin == newest release
 *   'ahead'      pin names a tag that does not exist in the census yet
 *                (release in progress: commit cut, tag not yet pushed)
 *   'no-tags'    no semver release tag to judge against -> NO VERDICT
 */
function pinSyncVerdict(pin, tags) {
  const pinKey = semverOf(pin);
  if (!pinKey) return 'no-verdict-bad-pin';
  const newest = newestReleaseTag(tags);
  if (!newest) return 'no-tags';
  const newKey = semverOf(newest);
  const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  const d = cmp(pinKey, newKey);
  if (d < 0) return 'lagging';
  if (d === 0) return 'synced';
  return 'ahead';
}

/** The single install pin the front page tells a stranger to copy. */
function readmePin() {
  const readme = fs.readFileSync(README, 'utf8');
  const found = readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g);
  assert.ok(found && found.length, 'README must document a stranger install command with a tag');
  const tags = [...new Set(found.map((s) => s.split('#')[1]))];
  assert.strictEqual(tags.length, 1, `README must pin exactly one tag, found: ${tags.join(', ')}`);
  return tags[0];
}

test('P1 the README pin does not lag the newest release tag', (t) => {
  const pin = readmePin();
  const tags = git(['tag', '-l']).split('\n').filter(Boolean);
  const verdict = pinSyncVerdict(pin, tags);
  if (verdict === 'no-tags') {
    return t.skip('no release tag in this checkout (tagless clone) - unmeasurable here, not a pass');
  }
  assert.notStrictEqual(verdict, 'lagging',
    `README pins ${pin} but the newest release tag is ${newestReleaseTag(tags)} - a stranger ` +
    'installing the front page gets a tree older than the Releases page (measured ' +
    '2026-11-07: pin v0.2.5 against release v0.2.6, shipped without the --out preflight); ' +
    'move the pin in the release commit so install path and release census name the same tree');
  assert.ok(['synced', 'ahead'].includes(verdict), `unknown verdict: ${verdict}`);
});

// --- offline controls: the rule itself, all four directions ---------------

test('T1 control: pin equal to the newest release is synced', () => {
  assert.strictEqual(pinSyncVerdict('v0.2.7', ['v0.2.4', 'v0.2.5', 'v0.2.6', 'v0.2.7']), 'synced');
});

test('T2 control: a pin ahead of the census is a release in progress, not a lag', () => {
  // The state this release passes through: the bump commit pins the tag
  // that the same push is about to create. Failing it would fail every
  // release at the only moment the pin is being kept honest.
  assert.strictEqual(pinSyncVerdict('v0.2.7', ['v0.2.5', 'v0.2.6']), 'ahead');
});

test('T3 control: a pin behind the newest release is the measured defect', () => {
  assert.strictEqual(pinSyncVerdict('v0.2.5', ['v0.2.5', 'v0.2.6']), 'lagging');
});

test('T4 control: no release tag means NO VERDICT, never a clean one', () => {
  assert.strictEqual(pinSyncVerdict('v0.2.7', []), 'no-tags');
  assert.strictEqual(pinSyncVerdict('v0.2.7', ['not-a-semver-tag']), 'no-tags');
  assert.strictEqual(pinSyncVerdict('nonsense', ['v0.2.7']), 'no-verdict-bad-pin');
});

test('T5 control: non-release refs never count as releases', () => {
  assert.strictEqual(pinSyncVerdict('v0.2.6', ['v0.2.6', 'nightly', 'v0.3.0-rc.1']), 'synced');
});
