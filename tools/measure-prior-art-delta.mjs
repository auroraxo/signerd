#!/usr/bin/env node
// Measure the DIFFERENTIATION between auroraxo/signerd and the same-named
// prior art @zanii/signerd - the card step "Abgrenzung gegen die gleichnamige
// Prior Art messen" instead of treating the collision as competition panic.
//
// WHY THIS EXISTS (measured, not argued)
// The registry-presence probe recorded @zanii/signerd as independent prior art
// (published 2026-10-19, seven days before this repo's first commit). That run
// only compared NAME and DESCRIPTION. The differentiation claim - "same
// surface word, different concept" - was prose. Prose is falsifiable only if
// an instrument can say the opposite, so this probe measures BOTH published
// sides with the SAME term list.
//
// WHAT IS MEASURED (both sides, identical instrument)
//   P1 timeline: prior-art first publish (npm metadata) vs our first commit (git).
//   P2 domain:   6 Solana/transaction terms over their PUBLISHED src+README vs
//                our src+bin. Same list, case-insensitive, non-overlapping.
//   P3 network:  their required `serverUrl` (daemon is built around a remote
//                ledger) vs our network imports/fetch calls in src+bin.
//   P4 premise:  both packages claim the same premise sentence (their README
//                literal vs our README literal) - the shared surface is real
//                and quoted, not denied.
//   P5 registry: exact-name `signerd` on npm (404 = authoritative absence,
//                already measured 2026-11-03) - the bare name is unoccupied;
//                the collision lives in search/repo-name space only.
//   P6 activity: their last-week/last-month downloads - the prior art is alive,
//                which is why it gets measured rather than dismissed.
//
// CONTROLS (each can void the verdict -> exit 3, never a flattering default)
//   C1 own-domain scanner: our own repo must match >0 of the same 6 terms.
//      A blind scanner would report "distinct" for ANY package, so blindness
//      is no-verdict, not distinct.
//   C2 prior-art presence: metadata resolves, tarball downloads, sha256
//      recorded, >=1 source file scanned.
//   C3 detection fixture (tests): synthetic text containing every term must
//      be counted; receipt-style prose (their shape) must count 0.
//
// VERDICTS
//   prior-art-distinct-domain   name+premise collide, domain does not
//                               (their domainTotal == 0, ours > 0, both measured)
//   prior-art-overlaps-domain   their published source touches our domain ->
//                               the differentiation claim is FALSIFIED; report it
//   no-verdict (exit 3)         any surface or control unmeasured
//
// LIMITS (same report, not a footnote)
//   - term counting is lexical: vendored/minified code renaming every term
//     escapes it; both sides are scanned as published, not as built
//   - network coupling is measured structurally (required option + import
//     terms), not by running their daemon
//   - a substring term can be satisfied by prose mentioning Solana without
//     implementing it - an overlap verdict means "touching", not "competing"
//   - downloads are npm's number (bots included), not distinct users
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const UA = 'signerd-research/0.1 (github.com/auroraxo/signerd)';
const PRIOR_ART = '@zanii/signerd';

// Same list for BOTH sides - using different lists per side would be the
// defect class this instrument exists to avoid.
export const DOMAIN_TERMS = ['solana', 'blockhash', 'transaction', 'lamports', 'systemprogram', '1232'];

export const NETWORK_IMPORT_TERMS = [
  "require('http')", "require('https')", 'require("http")', 'require("https")',
  "require('node:http')", "require('node:https')", 'from \'node:http\'', 'from \'node:https\'',
  'node:http', 'node:https', 'fetch(', 'http.request(', 'https.request(',
];

export const PREMISE = {
  priorArt: "keep the agent's private key out of the agent's process",
  own: 'the ssh-agent pattern, applied to solana keys',
};

// --- pure, exported for tests -------------------------------------------

// Case-insensitive, non-overlapping occurrence counts per term.
export function scanTerms(text, terms) {
  const lower = String(text).toLowerCase();
  const counts = {};
  for (const term of terms) {
    let n = 0;
    let i = lower.indexOf(term);
    while (i !== -1) {
      n += 1;
      i = lower.indexOf(term, i + term.length);
    }
    counts[term] = n;
  }
  return counts;
}

export function totalCounts(counts) {
  return Object.values(counts).reduce((a, b) => a + b, 0);
}

// Their daemon is built around a remote ledger: SignerdOptions declares
// `serverUrl: string` (required). `serverUrl?:` alone would be optional.
export function classifyServerCoupling(text) {
  const t = String(text);
  return {
    required: /serverUrl\s*:/.test(t),
    optionalOnly: /serverUrl\?:/.test(t) && !/serverUrl\s*:/.test(t),
    mentions: (t.match(/serverUrl/g) || []).length,
  };
}

export function premiseEvidence(text, needle) {
  return { needle, found: String(text).toLowerCase().includes(String(needle).toLowerCase()) };
}

// The verdict is a pure function of measured inputs. C1/C2 are voiding
// controls: blindness or an unmeasured prior-art surface yields no-verdict,
// NEVER "distinct".
export function decideVerdict({ priorArtMeasured, priorArtFilesScanned, priorArtDomainTotal, ownDomainTotal }) {
  if (!priorArtMeasured) return 'no-verdict';
  if (!Number.isFinite(priorArtFilesScanned) || priorArtFilesScanned < 1) return 'no-verdict';
  if (!Number.isFinite(ownDomainTotal) || ownDomainTotal === 0) return 'no-verdict';
  if (priorArtDomainTotal > 0) return 'prior-art-overlaps-domain';
  return 'prior-art-distinct-domain';
}

export function exitCodeFor(verdict) {
  return verdict === 'no-verdict' ? 3 : 0;
}

// Summary fields are re-derived from the rows, never copied: hand-editing a
// row count must surface in the summary (mutation-tested).
export function deriveSummary(priorArt, own) {
  return {
    priorArtDomainTotal: totalCounts(priorArt.domainCounts),
    ownDomainTotal: totalCounts(own.domainCounts),
    ownNetworkImportTotal: totalCounts(own.networkImportCounts),
    priorArtNetworkImportTotal: totalCounts(priorArt.networkImportCounts),
  };
}

// --- scanning ------------------------------------------------------------

function walk(dir, exts) {
  const out = [];
  if (!statSync(dir, { throwIfNoEntry: false })?.isDirectory()) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p, exts));
    else if (exts.some((e) => entry.name.endsWith(e)) && !entry.name.endsWith('.map')) out.push(p);
  }
  return out;
}

function scanFiles(files) {
  const domain = {};
  const network = {};
  for (const term of DOMAIN_TERMS) domain[term] = 0;
  for (const term of NETWORK_IMPORT_TERMS) network[term] = 0;
  let text = '';
  for (const f of files) {
    const t = readFileSync(f, 'utf8');
    text += `\n${t}`;
    const d = scanTerms(t, DOMAIN_TERMS);
    const n = scanTerms(t, NETWORK_IMPORT_TERMS);
    for (const term of DOMAIN_TERMS) domain[term] += d[term];
    for (const term of NETWORK_IMPORT_TERMS) network[term] += n[term];
  }
  return { domainCounts: domain, networkImportCounts: network, text };
}

function fetch(url, { binary = false } = {}) {
  const args = ['-sS', '-w', '\n%{http_code}', '-A', UA, url];
  try {
    const out = execFileSync('curl', args, { encoding: binary ? 'buffer' : 'utf8', timeout: 60000, maxBuffer: 64 * 1024 * 1024 });
    const marker = Buffer.from('\n');
    const nl = out.lastIndexOf(marker);
    const status = Number(Buffer.from(out.slice(nl + 1)).toString().trim());
    const body = out.slice(0, nl);
    return { status, body };
  } catch (err) {
    return { status: 0, body: binary ? Buffer.alloc(0) : '', transportError: String(err.message).slice(0, 200) };
  }
}

// Prior-art side: npm metadata -> latest tarball -> extract -> scan published
// src (fallback dist) + README. Nothing is executed; only files are read.
function measurePriorArt({ metaPath, packageDir } = {}) {
  let meta = null;
  if (metaPath) {
    meta = JSON.parse(readFileSync(metaPath, 'utf8'));
  } else {
    const r = fetch(`https://registry.npmjs.org/${encodeURIComponent(PRIOR_ART).replace('%40', '%40')}`);
    if (r.status !== 200) return { measured: false, reason: `npm metadata status ${r.status}` };
    meta = JSON.parse(r.body);
  }
  const versions = Object.keys(meta.versions ?? {});
  const latest = versions[versions.length - 1];
  if (!latest) return { measured: false, reason: 'no versions in metadata' };

  let dir = packageDir;
  let tarballSha256 = null;
  let tmp = null;
  try {
    if (!dir) {
      const tarballUrl = meta.versions[latest].dist?.tarball;
      if (!tarballUrl) return { measured: false, reason: 'no tarball URL' };
      const dl = fetch(tarballUrl, { binary: true });
      if (dl.status !== 200) return { measured: false, reason: `tarball status ${dl.status}` };
      tarballSha256 = createHash('sha256').update(dl.body).digest('hex');
      tmp = mkdtempSync(join(tmpdir(), 'signerd-prior-art-'));
      const tgz = join(tmp, 'p.tgz');
      writeFileSync(tgz, dl.body);
      execFileSync('tar', ['-xzf', tgz, '-C', tmp]);
      dir = join(tmp, 'package');
    }
    // Published surface: src/ if present (their repo ships it), else dist/.
    // DOMAIN is measured over IMPLEMENTATION files only on BOTH sides (a
    // README that merely says "Solana" is prose, not an implementation).
    // PREMISE is measured over implementation + README on BOTH sides (a
    // premise is a claim, and claims live in the README).
    let srcFiles = walk(join(dir, 'src'), ['.ts', '.js']);
    if (srcFiles.length === 0) srcFiles = walk(join(dir, 'dist'), ['.js']);
    const readme = walk(dir, ['.md']).filter((f) => /README/i.test(f));
    const implementation = scanFiles(srcFiles);
    const withReadme = scanFiles([...srcFiles, ...readme]);
    if (srcFiles.length === 0) return { measured: false, reason: 'no source files in package' };
    const serverCoupling = classifyServerCoupling(withReadme.text);
    return {
      measured: true,
      name: meta.name,
      created: meta.time?.created ?? null,
      latest,
      versionCount: versions.length,
      license: meta.versions[latest].license ?? null,
      repositoryField: meta.versions[latest].repository?.url ?? null,
      description: String(meta.versions[latest].description ?? '').slice(0, 300),
      tarballSha256,
      filesScanned: [...srcFiles, ...readme].map((f) => f.replace(`${tmp ?? dir}/`, '')),
      implementationFilesScanned: srcFiles.length,
      domainCounts: implementation.domainCounts,
      networkImportCounts: implementation.networkImportCounts,
      serverUrl: serverCoupling,
      premise: premiseEvidence(withReadme.text, PREMISE.priorArt),
    };
  } catch (err) {
    return { measured: false, reason: `extraction/scan failed: ${String(err.message).slice(0, 200)}` };
  } finally {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  }
}

function measureDownloads() {
  const r = fetch(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(PRIOR_ART)}`);
  const m = fetch(`https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(PRIOR_ART)}`);
  const parse = (x) => (x.status === 200 ? JSON.parse(x.body) : null);
  const w = parse(r);
  const mm = parse(m);
  if (!w || !mm) return null;
  return { lastWeek: w.downloads, lastMonth: mm.downloads, windowWeek: [w.start, w.end], windowMonth: [mm.start, mm.end] };
}

function measureOwn() {
  const implementation = [...walk('src', ['.js']), ...walk('bin', ['.js'])];
  if (implementation.length === 0) return { measured: false, reason: 'own src/bin not found (wrong cwd?)' };
  const readme = walk('.', ['.md']).filter((f) => /README/i.test(f) && !f.includes('/node_modules/'));
  const implScan = scanFiles(implementation);
  const withReadme = scanFiles([...implementation, ...readme]);
  let firstCommit = null;
  try {
    firstCommit = execFileSync('git', ['log', '--reverse', '--format=%cI', 'HEAD'], { encoding: 'utf8' }).split('\n')[0] || null;
  } catch { /* git unavailable: timeline becomes unmeasured below */ }
  return {
    measured: true,
    filesScanned: implementation.length,
    implementationFilesScanned: implementation.length,
    firstCommit,
    domainCounts: implScan.domainCounts,
    networkImportCounts: implScan.networkImportCounts,
    premise: premiseEvidence(withReadme.text, PREMISE.own),
  };
}

function daysBetween(a, b) {
  if (!a || !b) return null;
  return Math.floor((Date.parse(b) - Date.parse(a)) / 86400000);
}

// --- main ----------------------------------------------------------------

export function main(argv = process.argv.slice(2)) {
  const flag = (name) => {
    const i = argv.indexOf(name);
    return i === -1 ? undefined : argv[i + 1];
  };
  const priorArt = measurePriorArt({ metaPath: flag('--meta'), packageDir: flag('--package-dir') });
  const own = measureOwn();
  const downloads = priorArt.measured ? measureDownloads() : null;

  const priorArtMeasured = Boolean(priorArt.measured);
  const priorArtFilesScanned = priorArtMeasured ? priorArt.filesScanned.length : 0;
  const summary = deriveSummary(
    priorArtMeasured ? priorArt : { domainCounts: {}, networkImportCounts: {} },
    own.measured ? own : { domainCounts: {}, networkImportCounts: {} },
  );
  const verdict = decideVerdict({
    priorArtMeasured,
    priorArtFilesScanned,
    priorArtDomainTotal: summary.priorArtDomainTotal,
    ownDomainTotal: own.measured ? summary.ownDomainTotal : 0,
  });

  const report = {
    generatedAt: new Date().toISOString(),
    what: 'does the same-named prior art @zanii/signerd occupy this product\'s domain (Solana transaction signing), or only its name and premise?',
    instrument: 'tools/measure-prior-art-delta.mjs',
    priorArt: { ...priorArt, downloads },
    own: own.measured ? own : { measured: false, reason: own.reason },
    timeline: {
      priorArtFirstPublish: priorArtMeasured ? priorArt.created : null,
      ownFirstCommit: own.measured ? own.firstCommit : null,
      priorArtDaysAhead: daysBetween(priorArtMeasured ? priorArt.created : null, own.measured ? own.firstCommit : null),
    },
    summary,
    controls: {
      priorArtMeasured,
      priorArtFilesScanned,
      ownScannerBlind: !(own.measured && summary.ownDomainTotal > 0),
      verdictVoiding: ['prior-art surface unmeasured', 'no prior-art files scanned', 'own domain scan empty (blind scanner)'],
    },
    verdict,
    verdictBasis: 'same 6-term list on both published surfaces; prior-art-domainTotal>0 falsifies distinct; blindness is no-verdict, never distinct',
    coverage: {
      measured: ['npm metadata + tarball (sha256)', 'their published src/README', 'our src+bin', 'git first commit', 'npm downloads'],
      notMeasured: ['their git history (no repository field in npm metadata)', 'blog/docs outside the package', 'minified/renamed code', 'runtime behaviour of their daemon', 'pyPI/crates presence (separate probe)'],
    },
    limits: [
      'lexical term counting: prose mentioning Solana counts as touching (overlap means touching, not competing)',
      'network coupling measured structurally (required option + import terms), not by running their code',
      'downloads include automated installs; not distinct human users',
      'a verdict compares PUBLISHED artifacts at one point in time; both sides can change',
    ],
  };
  mkdirSync('research', { recursive: true });
  const day = new Date().toISOString().slice(0, 10);
  const outFile = `research/prior-art-delta-${day}.json`;
  writeFileSync(outFile, JSON.stringify(report, null, 2) + '\n');
  console.log(`report: ${outFile}`);
  console.log(`verdict: ${verdict}`);
  console.log(`domain terms: prior-art ${summary.priorArtDomainTotal} vs own ${summary.ownDomainTotal}`);
  console.log(`timeline: prior art ${report.timeline.priorArtFirstPublish} vs first commit ${report.timeline.ownFirstCommit} (${report.timeline.priorArtDaysAhead}d ahead)`);
  return exitCodeFor(verdict);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main());
}
