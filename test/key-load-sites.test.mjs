// Regression test for tools/key-load-sites.mjs.
//
// The census exists to keep one sentence in the README honest:
//
//   "21 files across six of my own repositories load key material into
//    process memory"
//
// That sentence drove the user-zero migration plan, so the tool that checks it
// needs its own test: the classification (own / own-fork / third-party) is the
// part that can silently go wrong, because "my working directory" is not
// "my repositories".
//
// The test builds throwaway git checkouts with controlled remotes and asserts
// that the census classifies them the way the README claim depends on.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

// The tool path can be pointed at a mutated copy, so the suite can be used as
// a mutation check: if a broken classifier still passes, the test is worthless.
const TOOL = process.env.SIGNERD_CENSUS_TOOL
  ? path.resolve(process.env.SIGNERD_CENSUS_TOOL)
  : path.join(import.meta.dirname, '..', 'tools', 'key-load-sites.mjs');

async function makeRepo(root, name, { origin, upstream = null, files }) {
  const dir = path.join(root, name);
  await mkdir(dir, { recursive: true });
  await run('git', ['-C', dir, 'init', '--quiet']);
  await run('git', ['-C', dir, 'remote', 'add', 'origin', origin]);
  if (upstream) await run('git', ['-C', dir, 'remote', 'add', 'upstream', upstream]);
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, body, 'utf8');
  }
  return dir;
}

async function census(root) {
  const out = path.join(root, 'census.json');
  await run(process.execPath, [TOOL, '--repos', root, '--out', out]);
  return JSON.parse(await (await import('node:fs/promises')).readFile(out, 'utf8'));
}

test('census separates own repos, own forks and third-party checkouts', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'signerd-census-'));
  try {
    await makeRepo(root, 'own-repo', {
      origin: 'https://github.com/auroraxo/own-repo.git',
      files: { 'app.js': 'const k = Keypair.fromSecretKey(secret);\n' },
    });
    await makeRepo(root, 'own-fork', {
      origin: 'https://github.com/auroraxo/whirlpools.git',
      upstream: 'https://github.com/orca-so/whirlpools.git',
      files: { 'cli.js': 'const k = Keypair.fromSecretKey(secret);\n' },
    });
    await makeRepo(root, 'vendor-checkout', {
      origin: 'https://github.com/orca-so/xorca.git',
      files: { 'ts-scripts/stake.ts': 'const k = Keypair.fromSecretKey(secret);\n' },
    });
    await makeRepo(root, 'clean-repo', {
      origin: 'https://github.com/auroraxo/clean-repo.git',
      files: { 'index.js': 'export const answer = 42;\n' },
    });

    const { summary, sites } = await census(root);

    assert.equal(summary.reposScanned, 4, 'all four checkouts are scanned');
    assert.equal(summary.keyLoadFiles, 3, 'only the three key-loading files count');
    assert.deepEqual(summary.keyLoadFilesByRepoClass, {
      own: 1,
      'own-fork': 1,
      'third-party': 1,
    });

    // The distinction that breaks the README claim: a file sitting in my
    // working directory is not automatically a file in my repository.
    const byRepo = Object.fromEntries(sites.map((site) => [site.repo, site.repoClass]));
    assert.equal(byRepo['own-repo'], 'own');
    assert.equal(byRepo['own-fork'], 'own-fork');
    assert.equal(byRepo['vendor-checkout'], 'third-party');
    assert.equal(byRepo['clean-repo'], undefined);

    assert.deepEqual(
      summary.ownAuthoredReposWithSites.map((entry) => entry.repo),
      ['own-repo'],
    );
    assert.deepEqual(
      summary.ownForkReposWithSites.map((entry) => entry.repo),
      ['own-fork'],
    );
    assert.deepEqual(
      summary.thirdPartyReposWithSites.map((entry) => entry.repo),
      ['vendor-checkout'],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('census reports upstream for own forks and ignores unusable remotes', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'signerd-census-'));
  try {
    await makeRepo(root, 'own-fork', {
      origin: 'https://github.com/auroraxo/whirlpools.git',
      upstream: 'https://github.com/orca-so/whirlpools.git',
      files: { 'a.js': 'Keypair.fromSeed(secret);\n' },
    });
    // An origin that names no GitHub owner cannot be shown to be mine.
    await makeRepo(root, 'no-remote', {
      origin: 'not-a-github-url',
      files: { 'b.js': 'Keypair.fromSeed(secret);\n' },
    });
    // A git checkout with no remotes at all is not "a repository of mine".
    const anonymous = path.join(root, 'anonymous');
    await mkdir(anonymous, { recursive: true });
    await run('git', ['-C', anonymous, 'init', '--quiet']);
    await writeFile(path.join(anonymous, 'c.js'), 'Keypair.fromSeed(secret);\n', 'utf8');

    const { summary, sites } = await census(root);

    assert.equal(summary.reposScanned, 2, 'a repo without remotes is not scanned as owned');
    assert.equal(
      sites.some((site) => site.repo === 'anonymous'),
      false,
      'no remote means no ownership claim',
    );

    const fork = sites.find((site) => site.repo === 'own-fork');
    assert.equal(fork.repoClass, 'own-fork');
    assert.equal(fork.upstream, 'https://github.com/orca-so/whirlpools.git');

    const unknown = sites.find((site) => site.repo === 'no-remote');
    assert.equal(unknown.repoClass, 'third-party', 'an unrecognised origin is not "own"');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
