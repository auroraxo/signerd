'use strict';

// The release contract: what the RELEASED artifacts must satisfy, not what
// main satisfies.
//
// WHY (measured 2026-11-05, research/install-path-v0.1.0-2026-11-05.json):
// the tag a stranger installs from (v0.1.0) predated the stranger-install
// fixes: its manifest still carried "private": true (unpublishable, and
// invisible to every dry-run — test/publish-gate.test.js) and its README
// had no quickstart at all. Meanwhile the awesome-solana-ai PR #280 body
// advertised `cargo install --git ...` — a path that never existed (no
// Cargo.toml at the tag; `cargo install` fails with "could not find
// Cargo.toml"). Nothing failed anywhere: main was green, the PR was open,
// the tag was shipped — and every claim was false at the surface a
// stranger actually touches.
//
// THE CONTRACT (the reeflog lesson, generalized: tree and release may not
// disagree):
//   G1 the working manifest is publishable: no "private": true.
//   G2 the latest release tag v* is not stale-by-content: its manifest
//      must be publishable and its README must carry the quickstart
//      contract ("umask 077") that main pins. A tag is a claim about a
//      tree; this asserts the claim stays true.
//   G3 the README must DOCUMENT a stranger install command, and must not
//      advertise a cargo install: this repo is a Node package and has no
//      Cargo.toml, so "cargo install --git ..." fails with "could not find
//      Cargo.toml" — the exact command the awesome-solana-ai PR #280 body
//      told strangers to copy (measured 2026-11-05).
//
// No network. The tag's tree is read from the local git object store
// (`git show <tag>:file`), so the test runs offline and in CI.
//
// Ladder: T1 is RED on the pre-fix tree (it names the measured defects);
// T2-T4 are the offline controls that prove the checks can fail in the
// dangerous direction and pass on a clean pair, so T1 cannot pass vacuously.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const ANCHOR = 'umask 077';

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
}
function semverOf(tag) {
  const m = /^v(\d+)\.(\d+)\.(\d+)$/.exec(tag);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
function latestReleaseTag(tags) {
  let best = null;
  let bestKey = null;
  for (const t of tags) {
    const k = semverOf(t);
    if (!k) continue;
    if (!bestKey || k[0] > bestKey[0] || (k[0] === bestKey[0] && (k[1] > bestKey[1] || (k[1] === bestKey[1] && k[2] > bestKey[2])))) {
      best = t; bestKey = k;
    }
  }
  return best;
}
function manifestGates(manifest, readme) {
  const gates = [];
  if (manifest.private === true) gates.push('private-true');
  if (typeof readme !== 'string' || !readme.includes(ANCHOR)) gates.push('readme-no-quickstart');
  if (typeof readme === 'string' && readme.includes('cargo install')) gates.push('readme-advertises-cargo-install');
  if (typeof readme !== 'string' || !readme.includes('npm install github:auroraxo/signerd#')) gates.push('readme-no-install-command');
  return gates;
}
function showTag(tag, file) {
  try {
    return git(['show', `${tag}:${file}`]);
  } catch (err) {
    if (String(err).includes('does not exist') || String(err).includes('Pathspec')) return null;
    throw err;
  }
}

const tags = git(['tag', '-l']).split('\n').filter(Boolean);
const latest = latestReleaseTag(tags);

test('T1 the released artifacts satisfy the contract (RED while the tag is stale)', { skip: !latest && 'no release tag exists in this checkout' }, () => {
  const repoManifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const repoGates = manifestGates(repoManifest, fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8'));
  assert.deepStrictEqual(repoGates, [], `the working tree must satisfy G1: ${repoGates.join(', ')}`);

  // G3: package.json version and the release tag must name the same thing,
  // so "install the tag" and "this is the version" cannot drift apart.
  assert.strictEqual(latest, `v${repoManifest.version}`,
    `release tag ${latest} disagrees with package.json version ${repoManifest.version}`);

  const tagManifest = JSON.parse(showTag(latest, 'package.json'));
  const tagReadme = showTag(latest, 'README.md');
  const g2 = manifestGates(tagManifest, tagReadme);
  assert.deepStrictEqual(g2, [], `release tag ${latest} is stale-by-content: ${g2.join(', ')}`);
});

test('T2 control: a clean manifest + quickstart README passes on every tree', () => {
  const readme = `# x\n\`\`\`bash\n${ANCHOR}\n\`\`\`\n\n\`\`\`bash\nnpm install github:auroraxo/signerd#v9.9.9\n\`\`\``;
  assert.deepStrictEqual(manifestGates({ version: '9.9.9' }, readme), []);
});

test('T3 control: the dangerous direction is caught (private manifest)', () => {
  const readme = `x ${ANCHOR} x npm install github:auroraxo/signerd#v9.9.9`;
  assert.deepStrictEqual(manifestGates({ version: '9.9.9', private: true }, readme), ['private-true']);
});

test('T4 control: the dangerous direction is caught (README without quickstart)', () => {
  const readme = 'a README with no quickstart block npm install github:auroraxo/signerd#v9.9.9';
  assert.deepStrictEqual(manifestGates({ version: '9.9.9' }, readme), ['readme-no-quickstart']);
});

test('T5 control: a cargo install claim is caught (the PR #280 defect)', () => {
  const readme = `x ${ANCHOR} x npm install github:auroraxo/signerd#v9.9.9 cargo install --git https://github.com/auroraxo/signerd`;
  assert.deepStrictEqual(manifestGates({ version: '9.9.9' }, readme), ['readme-advertises-cargo-install']);
});

test('T6 control: a README without an install command is caught', () => {
  const readme = `x ${ANCHOR} x`;
  assert.deepStrictEqual(manifestGates({ version: '9.9.9' }, readme), ['readme-no-install-command']);
});
