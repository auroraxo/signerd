#!/usr/bin/env node
// Reproducible census behind the README claim "21 files across six of my own
// repositories load key material into process memory".
//
// The claim drives the user-zero migration plan, so it must be computable and
// it must distinguish what the sentence quietly conflates:
//   - repos I own outright (origin owner == auroraxo, no upstream),
//   - my forks of other people's repos (origin auroraxo + upstream remote),
//   - third-party checkouts that live in my working directory.
//
// A file counts as a key-load site when a source pattern shows key material
// being turned into a usable key inside the process (Keypair construction from
// a secret, env/file key loading, PEM/private-key parsing).
//
//   node tools/key-load-sites.mjs [--repos <dir>] [--out <file.json>]
//
// Exit code is always 0: this is a measurement, not a gate.

import { readFile, readdir, stat, writeFile, mkdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';

const run = promisify(execFile);

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  const value = args[index + 1];
  if (value === undefined) throw Error(`missing value for ${name}`);
  args.splice(index, 2);
  return value;
};
const reposDir = option('--repos', path.join(os.homedir(), 'github_repos'));
const outFile = option('--out', null);

const OWN_OWNER = 'auroraxo';

// Only patterns that mean "raw key material becomes a live key here".
// bs58.decode alone is deliberately NOT enough (it decodes anything).
const KEY_PATTERNS = [
  /Keypair\.fromSecretKey\s*\(/,
  /Keypair\.fromSeed\s*\(/,
  /Keypair\.from_bytes\s*\(/,
  /new\s+Keypair\s*\(/,
  /keypairFromSecretKey\s*\(/,
  /loadKeypairFromFile\s*\(/,
  /keypairFromFile\s*\(/,
  /readKeyPair\s*\(/,
  /SOLANA_PRIVATE_KEY/,
  /\.secretKey\b/,
  /load_pem_private_key\s*\(/,
  /SigningKey\s*\(/,
  /from_secret_key\s*\(/,
  /private[_]?key\s*=/,
];

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'target', 'dist', 'build', '.next', 'coverage',
  'vendor', '.venv', '__pycache__', '.yarn', '.cache', 'out',
]);
const SKIP_FILES = /(package-lock\.json|yarn\.lock|\.min\.(js|mjs|cjs)|pnpm-lock\.yaml)$/;
const CODE_EXT = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx', '.py', '.rs', '.go']);
const MAX_BYTES = 1_500_000;

async function git(dir, ...argv) {
  try {
    const { stdout } = await run('git', ['-C', dir, ...argv]);
    return stdout.trim();
  } catch {
    return '';
  }
}

async function classify(dir) {
  const origin = await git(dir, 'remote', 'get-url', 'origin');
  const upstream = await git(dir, 'remote', 'get-url', 'upstream');
  if (!origin) return { origin: null, upstream: null, class: 'not-a-git-checkout' };
  const owner = origin.match(/github\.com[/:]([^/]+)\//)?.[1] ?? null;
  if (owner !== OWN_OWNER) return { origin, upstream: upstream || null, class: 'third-party' };
  if (upstream) return { origin, upstream, class: 'own-fork' };
  return { origin, upstream: null, class: 'own' };
}

async function walk(dir, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.github') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await walk(full, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (!CODE_EXT.has(ext)) continue;
      if (SKIP_FILES.test(entry.name)) continue;
      out.push(full);
    }
  }
  return out;
}

const sites = [];
const repos = [];
let filesScanned = 0;

const entries = await readdir(reposDir, { withFileTypes: true });
for (const entry of entries) {
  if (!entry.isDirectory()) continue;
  const dir = path.join(reposDir, entry.name);
  const meta = await classify(dir);
  if (meta.class === 'not-a-git-checkout') continue;
  const files = await walk(dir);
  filesScanned += files.length;
  let hits = 0;
  for (const file of files) {
    let body;
    try {
      const info = await stat(file);
      if (info.size > MAX_BYTES) continue;
      body = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    const matched = KEY_PATTERNS.filter((pattern) => pattern.test(body));
    if (matched.length > 0) {
      hits += 1;
      sites.push({
        repo: entry.name,
        repoClass: meta.class,
        origin: meta.origin,
        upstream: meta.upstream,
        file: path.relative(dir, file),
        patterns: matched.map((pattern) => pattern.source),
      });
    }
  }
  repos.push({
    repo: entry.name,
    repoClass: meta.class,
    origin: meta.origin,
    upstream: meta.upstream,
    files: files.length,
    keyLoadFiles: hits,
  });
}

const byClass = {};
for (const site of sites) byClass[site.repoClass] = (byClass[site.repoClass] ?? 0) + 1;
const reposWithSitesByClass = {};
for (const site of sites) {
  const key = site.repoClass;
  reposWithSitesByClass[key] ??= new Set();
  reposWithSitesByClass[key].add(site.repo);
}
const summary = {
  generatedAt: new Date().toISOString(),
  reposDir,
  reposScanned: repos.length,
  filesScanned,
  keyLoadFiles: sites.length,
  keyLoadFilesByRepoClass: byClass,
  reposWithSitesByRepoClass: Object.fromEntries(
    Object.entries(reposWithSitesByClass).map(([key, set]) => [key, [...set].sort()]),
  ),
  ownAuthoredReposWithSites: repos
    .filter((repo) => repo.repoClass === 'own' && repo.keyLoadFiles > 0)
    .map((repo) => ({ repo: repo.repo, keyLoadFiles: repo.keyLoadFiles })),
  thirdPartyReposWithSites: repos
    .filter((repo) => repo.repoClass === 'third-party' && repo.keyLoadFiles > 0)
    .map((repo) => ({ repo: repo.repo, keyLoadFiles: repo.keyLoadFiles }))
    .sort((a, b) => b.keyLoadFiles - a.keyLoadFiles),
  ownForkReposWithSites: repos
    .filter((repo) => repo.repoClass === 'own-fork' && repo.keyLoadFiles > 0)
    .map((repo) => ({ repo: repo.repo, upstream: repo.upstream, keyLoadFiles: repo.keyLoadFiles })),
};

process.stdout.write(JSON.stringify({ summary, sites }, null, 2) + '\n');
if (outFile) {
  await mkdir(path.dirname(outFile), { recursive: true });
  await writeFile(outFile, JSON.stringify({ summary, sites }, null, 2) + '\n');
}
