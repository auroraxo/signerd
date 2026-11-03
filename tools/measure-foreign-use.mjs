// Measure FOREIGN use of signerd - a reference from a repo that is not mine.
//
// WHY THIS EXISTS
// The card's open question is "no outside users". tools/measure-adoption.mjs
// answers a different question: non-owner stars/forks/issues ON signerd's own
// repo. The case that actually matters for a daemon people wire into their
// own tooling is a stranger's repo declaring signerd as a dependency or
// calling its binary - references that live in OTHER repos. Nothing measured
// those.
//
// WHAT THE FIRST VERSION GOT WRONG (measured, not argued)
// v1 of this probe ran 6 code-search surfaces and reported
// "foreign-use-evidence: 77 foreign repos". That verdict was FALSE, in four
// ways, all of them found by the probe's own output or by tracing every hit:
//
//   D1 - bare-name noise. The surface `"signerd"` (quoted) is a SUBSTRING
//        match, not a token match: tendermint/tendermint matched via
//        "signerdialerendpoint" (the literal "signerd" is a prefix of that
//        word), and 157,696 total hits included other signers (cosignerd,
//        lndsigner, windows-signer-action) and expired domain lists. A name
//        this generic cannot decide anything alone.
//   D2 - wrong attribution. The only real reference found,
//        sprintberlin/openclaw-citizen, is MY repo (I have push rights), but
//        v1 compared only the owner PREFIX ("auroraxo" vs "sprintberlin") and
//        called it foreign. Owner-prefix matching is not ownership.
//   D3 - a false ABSENCE, which is the dangerous one. v1's other five
//        surfaces reported "0 matches", and would have read as "no foreign
//        use exists". But GitHub's code-search index does NOT carry my own
//        public repos: `repo:auroraxo/openreceipts` + a term that is
//        verifiably in its README returns 0, while the same query shape
//        returns 9 for tendermint/tendermint and 211 for a recent foreign
//        repo. So the zeros measured the INDEX, not the ecosystem, and an
//        absence verdict built on them would have been an artifact.
//   D4 - my own placement counted as foreign use. The issue surface finds
//        awesome-solana-ai#280 - a FOREIGN repo whose issue body names the
//        slug - but I opened that PR myself. A reference in a foreign repo
//        that I authored is my DISTRIBUTION, not an outsider's consumption.
//        Attribution therefore uses the AUTHOR of the hit, not only the
//        owner of the repo it landed in.
//
// V3 DEFECTS (found in the ABANDONED run of 2026-11-03, files written
// 13:40-13:42 local, taken over 20:41Z by producer-pulse; the run died with
// coverage=unmeasured / verdict=no-verdict / exit 3 - that state is preserved
// verbatim in research/foreign-use-2026-11-03.v2-no-verdict.json). Each one
// was measured against that tree before being fixed:
//   D5 - a SKIPPED coverage probe was counted as coverage "measured":
//        `probes.every(p => p.status !== 'unmeasured')` lets a probe that
//        NEVER RAN ride under an absence verdict.
//   D6 - one TRANSIENT failure (a single 403 on the probe-own contents read;
//        the same read succeeded minutes later during hit verification)
//        pushed into `failures` permanently and killed the whole verdict.
//        A retryable error must be retried, not remembered as a defeat.
//   D7 - "throttle hard enough to stay inside it" was a COMMENT, not code:
//        search API rate limits (403) FATAL-exit mid-run and persist NO
//        report at all. Search failures now record + mark the surface
//        unmeasured instead of dying without output.
//   D8 - a permission read that failed for a TRANSIENT reason returned
//        'none', and the repo was then classified FOREIGN on missing
//        evidence. Only "Must have push access" (403) and 404 responses
//        are authoritative negatives; rate limits, 5xx and timeouts are
//        UNKNOWN - and unknown attribution can never be foreign use.
//
// THE DESIGN THAT FOLLOWS FROM THOSE FOUR DEFECTS
//   1. Every search surface carries a POSITIVE CONTROL - a literal that is
//      known to be present in an indexed repo. If the control does not
//      resolve, that surface is UNMEASURED, not "zero hits".
//   2. Every hit is VERIFIED by reading the file (or issue body) and
//      checking that the literal is really there - the search index is
//      allowed to be stale, the file is not.
//   3. Ownership is decided by the COLLABORATOR-PERMISSION endpoint
//      (403 = not mine, admin/write/... = mine), not by a name prefix.
//      Hits are additionally attributed by their AUTHOR: a hit I authored is
//      own activity even when it lives in someone else's repo.
//   4. A COVERAGE PROBE measures how much of the universe this sweep can
//      actually see: a known-positive reference of my own (is the search
//      surface able to see repos like mine at all?) and a small foreign repo
//      (does it see repos without stars?). An absence is only reported as
//      scoped to what these probes prove visible.
//
// VERDICT CLASSES (never prose)
//   foreign-use-evidence            : a verified reference from a repo I do
//                                     control, authored by someone who is
//                                     not me
//   own-use-only                    : every verified reference is mine (my
//                                     repo, or authored by me)
//   no-foreign-reference-found      : no verified foreign reference, on every
//                                     surface whose control passed. Scoped:
//                                     the report names what the sweep could
//                                     not see.
//   no-verdict                      : at least one surface was unmeasured, or
//                                     a coverage probe could not run
//
// Exit codes: 0 = measurement complete (any verdict), 3 = NO VERDICT.
// A partial sweep is never evidence of absence.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = process.env.ADOPTION_REPO || 'auroraxo/signerd';
const OWNER = process.env.ADOPTION_OWNER || REPO.split('/')[0];
const OUT = process.argv.includes('--out')
  ? process.argv[process.argv.indexOf('--out') + 1]
  : null;

// The literal a foreign repo would contain: the repo slug. It is
// unambiguous in a way the bare name is not (no other project can own the
// path auroraxo/signerd).
const SLUG = REPO;
const SLUG_ESCAPED = REPO.replace('/', '%2F');
const SLUG_URL = `github.com/${REPO}`;

// ---------------------------------------------------------------------------
// PURE LOGIC (exported so it can be tested without a network)
// ---------------------------------------------------------------------------

/**
 * Decide whether a surface's control resolved. A surface whose control failed
 * is UNMEASURED - reporting "0 matches" for it would be claiming an absence
 * the surface never established.
 */
export function surfaceState({ controlMatches }) {
  if (!Number.isFinite(controlMatches) || controlMatches <= 0) return 'unmeasured';
  return 'measured';
}

/**
 * Coverage status over the probe list. D5: a probe that was SKIPPED (never
 * ran) must count exactly like one that failed - coverage is only "measured"
 * when every probe actually ran.
 */
export function coverageStatus(probes) {
  if (!Array.isArray(probes) || probes.length === 0) return 'unmeasured';
  return probes.every((p) => p && p.status === 'measured') ? 'measured' : 'unmeasured';
}

const RETRYABLE_FAILURE =
  /rate limit|secondary rate|abuse detection|HTTP \/5\d\d|HTTP 5\d\d|HTTP 429|timed out|timeout|ECONNRESET|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|socket hang up|network/i;

/**
 * D7/D8 support: which gh failures are worth retrying. Authoritative
 * negatives - "Must have push access" (the collaborator endpoint's 403 for
 * non-collaborators) and plain Not Found / 404 / 422 - are NOT retryable;
 * retrying them would only delay an answer the API already gave.
 */
export function isRetryableFailure(msg) {
  if (typeof msg !== 'string') return false;
  if (/Must have push access|Not Found\b|HTTP 404\b|HTTP 422\b|no common ancestor/i.test(msg)) return false;
  return RETRYABLE_FAILURE.test(msg);
}

/**
 * Classify a repo as mine or foreign using the permission level returned by
 * the collaborator endpoint. Anything that is not a positive collaborator
 * permission is foreign. Deliberately NOT owner-prefix based: v1's D2 defect
 * was exactly that.
 */
export function isOwnRepo(permission) {
  if (typeof permission !== 'string') return false;
  const OWN_PERMISSIONS = new Set(['admin', 'maintain', 'write', 'triage', 'read']);
  return OWN_PERMISSIONS.has(permission);
}

/**
 * Attribute a verified hit. Three cases:
 *   - authored by me            -> own (my distribution activity, even in a
 *                                  foreign repo - v1's D4 defect)
 *   - in a repo I control       -> own consumption
 *   - otherwise                 -> foreign use
 * The author check runs FIRST because it decides the D4 case even when the
 * hosting repo is foreign.
 */
export function attributeHit({ repoOwn, authorIsMe, permissionDetermined = true }) {
  if (authorIsMe === true) return 'own-authored';
  if (permissionDetermined !== true) return 'unknown'; // D8: undetermined can never be foreign
  if (repoOwn === true) return 'own-repo';
  return 'foreign';
}

/**
 * A search hit is only a reference if the file really contains the literal.
 * The index may be stale or fuzzy; the file content is the ground truth.
 */
export function hitIsVerified({ fileContainsLiteral, literal }) {
  return typeof fileContainsLiteral === 'boolean' && fileContainsLiteral === true
    && typeof literal === 'string' && literal.length > 0;
}

/**
 * The final verdict. Absence is only ever reported when every surface was
 * measured and every coverage probe ran, and it is always scoped by what the
 * sweep could not see.
 */
export function decideVerdict({ verifiedForeign, verifiedOwn, surfaceStates, coverage, unknownAttribution = [] }) {
  const unmeasured = surfaceStates.filter((s) => s.state === 'unmeasured');
  if (verifiedForeign.length > 0) {
    return {
      class: 'foreign-use-evidence',
      signals: verifiedForeign.map((h) => `${h.repo} ${h.path || ''}`.trim()),
      meaning:
        'at least one repo I do not control, authored by someone else, contains the reference - a reference, not a verified install',
    };
  }
  if (unknownAttribution.length > 0) {
    return {
      class: 'no-verdict',
      signals: unknownAttribution.map(
        (h) => `ownership of ${h.repo} could not be determined (${h.permissionRead || 'permission read failed'}); unknown is not foreign`
      ),
      meaning: 'a hit could not be attributed - unknown attribution never becomes foreign use, and blocks an absence verdict',
    };
  }
  if (unmeasured.length > 0) {
    return {
      class: 'no-verdict',
      signals: unmeasured.map((s) => `surface ${s.id} was unmeasured (its control did not resolve)`),
      meaning: 'at least one surface could not be measured; absence is not proven',
    };
  }
  // D5: when the coverage object carries probes, recompute from them - a
  // caller-computed status that counted a skipped probe as measured is not
  // trusted. Without probes, the status field is all we have.
  const coverageState = !coverage
    ? 'unmeasured'
    : Array.isArray(coverage.probes) && coverage.probes.length > 0
      ? coverageStatus(coverage.probes)
      : coverage.status;
  if (coverageState !== 'measured') {
    return {
      class: 'no-verdict',
      signals: ['a coverage probe could not be measured'],
      meaning: 'how much of the universe this sweep can see is unknown; absence is not proven',
    };
  }
  if (verifiedOwn.length > 0) {
    return {
      class: 'own-use-only',
      signals: verifiedOwn.map((h) => `${h.repo} ${h.path || ''}`.trim()),
      meaning:
        'every verified reference is my own activity (my repos, or authored by me) - own use, which proves nothing about outsiders',
    };
  }
  return {
    class: 'no-foreign-reference-found',
    signals: ['no verified foreign reference on any measured surface'],
    meaning:
      'the measured surfaces were swept and no foreign reference was found - scoped to what the coverage probes could see',
  };
}

// ---------------------------------------------------------------------------
// NETWORK BOUNDARY
// ---------------------------------------------------------------------------

const failures = [];

function sleepSync(ms) {
  // Busy-wait is unacceptable; use a child process sleep so the event loop
  // stays free (the tool is synchronous).
  execFileSync(process.execPath, ['-e', `setTimeout(() => {}, ${ms})`], { stdio: 'ignore' });
}

// D6: a transient failure must be retried, not remembered. Retry only what is
// worth retrying (see isRetryableFailure) and only a bounded number of times.
function gh(args, { optional = false, retries = 2, retryDelayMs = 4000 } = {}) {
  let lastMsg = '';
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return execFileSync('gh', args, {
        encoding: 'utf8',
        timeout: 90000,
        maxBuffer: 64 * 1024 * 1024,
      });
    } catch (err) {
      // Node's execFileSync puts the child's stderr on line 2+ of
      // err.message; splitting at the first newline (v1 behavior) discarded
      // "API rate limit exceeded" / "Must have push access" and the retry
      // classifier then saw only "Command failed: gh ..." - measured: every
      // search in a rate-limited run failed without a single retry.
      const full = String(err.message || '');
      const stderr = err && err.stderr ? String(err.stderr) : '';
      const detail = (stderr && !full.includes(stderr) ? `${full}\n${stderr}` : full)
        .replace(/\s+/g, ' ')
        .slice(0, 400);
      lastMsg = `gh ${args[0]} ${args.slice(1).join(' ')} failed: ${detail}`;
      if (attempt < retries && isRetryableFailure(lastMsg)) {
        const isRateLimit = /rate limit/i.test(lastMsg);
        sleepSync(isRateLimit ? Math.max(retryDelayMs, 65000) : retryDelayMs * (attempt + 1));
        continue;
      }
      break;
    }
  }
  if (optional) {
    failures.push(lastMsg);
    return null;
  }
  console.error('FATAL ' + lastMsg);
  process.exit(3);
}

function ghJson(args, opts = {}) {
  const out = gh(args, opts);
  if (out === null) return null;
  try {
    return JSON.parse(out);
  } catch (err) {
    const msg = `gh ${args[0]} returned unparsable JSON: ${String(err.message).split('\n')[0]}`;
    if (opts.optional) {
      failures.push(msg);
      return null;
    }
    console.error('FATAL ' + msg);
    process.exit(3);
  }
}

// A read that is EXPECTED to be able to fail without harming the measurement:
// a stale search hit whose file is gone (404), or a hit whose body was
// deleted. Those are answers ("that file does not contain it"), not data
// source failures, and must not flip the whole verdict to no-verdict.
// A RATE LIMIT or 5xx, in contrast, is a real failure: the answer is unknown.
function readTolerant(args) {
  try {
    const out = execFileSync('gh', args, {
      encoding: 'utf8',
      timeout: 90000,
      maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(out);
  } catch (err) {
    const msg = String(err.message || '');
    if (/Not Found|HTTP 404|HTTP 422/i.test(msg)) return null; // benign: no such file
    if (isRetryableFailure(msg)) {
      failures.push(`read failed (retryable): ${msg.split('\n')[0]}`);
      return null;
    }
    failures.push(`read failed: ${msg.split('\n')[0]}`);
    return null;
  }
}

// D7: the search API rate-limits (30/min, and search/code is stricter).
// "throttle hard enough to stay inside it" was a COMMENT in v1 - measured:
// a burst of back-to-back searches trips the limit mid-run. PACE every search
// call, and on a rate limit wait out the window before retrying. A failed
// search marks its surface unmeasured and the report is still written.
const SEARCH_MIN_INTERVAL_MS = 2300; // 30/min = 2000ms; keep a margin
let lastSearchAt = 0;

function paceSearch() {
  const now = Date.now();
  const wait = SEARCH_MIN_INTERVAL_MS - (now - lastSearchAt);
  if (wait > 0) sleepSync(wait);
  lastSearchAt = Date.now();
}

function searchApi(kind, q) {
  paceSearch();
  const out = gh(
    ['api', '-X', 'GET', `search/${kind}`, '-f', `q=${q}`, '-f', 'per_page=100'],
    {
      optional: true,
      retries: 3,
      retryDelayMs: 65000,
    }
  );
  if (out === null) return null;
  try {
    return JSON.parse(out);
  } catch (err) {
    failures.push(`search/${kind} returned unparsable JSON: ${String(err.message).split('\n')[0]}`);
    return null;
  }
}

function searchTotalCode(q) {
  const res = searchApi('code', q);
  if (!res) return null;
  return typeof res.total_count === 'number' ? res.total_count : null;
}

// Returns null when the search itself failed (so the caller can mark the
// surface UNMEASURED) and an array of items otherwise. An empty array means
// "searched, found nothing"; null means "the search did not answer".
function searchItems(kind, q) {
  const res = searchApi(kind, q);
  if (!res) return null;
  return (res.items || []).map((i) => {
    if (kind === 'issues') {
      return {
        repo: String(i.repository_url || '').replace('https://api.github.com/repos/', ''),
        path: `#${i.number}`,
        author: (i.user && i.user.login) || null,
        number: i.number,
        title: i.title,
        body: i.body || '',
      };
    }
    if (kind === 'commits') {
      const sha = i.sha || (i.commit && i.commit.sha) || '';
      const msg = (i.commit && i.commit.message) || '';
      return {
        repo: (i.repository && i.repository.full_name) || '',
        path: sha.slice(0, 12),
        author:
          (i.author && i.author.login) ||
          (i.commit && i.commit.author && i.commit.author.name) ||
          null,
        sha,
        body: msg,
      };
    }
    return {
      repo: (i.repository && i.repository.full_name) || '',
      path: i.path,
      author: null,
    };
  });
}

// Read a file and report whether it really contains the literal.
function fileContains(repo, filePath, literal) {
  const res = readTolerant(['api', `repos/${repo}/contents/${filePath}`]);
  if (!res || res.type !== 'file' || typeof res.content !== 'string') return null;
  let text;
  try {
    text = Buffer.from(res.content, 'base64').toString('utf8');
  } catch {
    return null;
  }
  return text.includes(literal);
}

function issueBodyContains(repo, number, literal) {
  const res = readTolerant(['api', `repos/${repo}/issues/${number}`]);
  if (!res) return null;
  const text = `${res.title || ''}\n${res.body || ''}`;
  return text.includes(literal);
}

function commitMessageContains(repo, sha, literal) {
  const res = readTolerant(['api', `repos/${repo}/commits/${sha}`]);
  if (!res) return null;
  const text = (res.commit && res.commit.message) || '';
  return text.includes(literal);
}

// Authoritative ownership: the collaborator-permission endpoint. The endpoint
// answers two different questions with the same 403:
//   - "Must have push access to view repository collaborators" -> I am NOT a
//     collaborator: AUTHORITATIVE negative, determined.
//   - rate limit / 5xx / timeout -> the endpoint did not answer: UNKNOWN.
// D8 was exactly this conflation: an undetermined read returned 'none' and the
// repo was then attributed as FOREIGN use on missing evidence.
// Pick a small foreign repo for the coverage probe: a PUBLIC repo with (near)
// zero stars that still exists. The point of the probe is to measure whether
// the code-search index sees repos like the ones that would reference me - a
// well-known repo would prove nothing.
//
// The candidates are looked up live (repository search, newest first) instead
// of hard-coded, so the probe keeps measuring a CURRENT kind of repo rather
// than one that may since have grown. Measured 2026-11-03: a 0-star public
// repo created 2026-10-26 is visible to code search (29 hits) - so the index
// does carry small foreign repos, which makes the scope limit about repos
// LIKE MINE (see probe-own), not about smallness.
function pickSmallForeignRepo() {
  const explicit = process.env.COVERAGE_PROBE_CANDIDATES;
  let candidates = [];
  if (explicit) {
    candidates = explicit.split(',').map((s) => s.trim()).filter(Boolean);
  } else {
    const res = ghJson(
      [
        'api',
        '-X',
        'GET',
        'search/repositories',
        '-f',
        'q=stars:0 fork:false archived:false created:>2026-09-01',
        '-f',
        'sort=created',
        '-f',
        'order=desc',
        '-f',
        'per_page=20',
      ],
      { optional: true }
    );
    candidates = ((res && res.items) || [])
      .map((i) => i && i.full_name)
      .filter(Boolean)
      .slice(0, 8);
  }
  for (const c of candidates) {
    const info = ghJson(['api', `repos/${c}`], { optional: true });
    if (info && info.default_branch && !info.private) return c;
  }
  return null;
}

function permissionFor(repo) {
  try {
    const out = execFileSync(
      'gh',
      ['api', `repos/${repo}/collaborators/${OWNER}/permission`],
      { encoding: 'utf8', timeout: 60000 }
    );
    const parsed = JSON.parse(out);
    if (typeof parsed.permission === 'string') {
      return { permission: parsed.permission, determined: true, permissionRead: 'ok' };
    }
    return { permission: 'none', determined: false, permissionRead: 'unparsable response' };
  } catch (err) {
    const msg = String(err.message || '');
    if (/Must have push access|Not Found|HTTP 404/i.test(msg)) {
      return { permission: 'none', determined: true, permissionRead: 'not a collaborator' };
    }
    if (/rate limit|secondary rate|HTTP 5\d\d|timeout|ECONN|ETIMEDOUT|EAI_AGAIN/i.test(msg)) {
      // Retry once after a short wait: transient beats an unknown verdict.
      sleepSync(5000);
      try {
        const out = execFileSync(
          'gh',
          ['api', `repos/${repo}/collaborators/${OWNER}/permission`],
          { encoding: 'utf8', timeout: 60000 }
        );
        const parsed = JSON.parse(out);
        if (typeof parsed.permission === 'string') {
          return { permission: parsed.permission, determined: true, permissionRead: 'ok after retry' };
        }
      } catch (err2) {
        const msg2 = String(err2.message || '');
        if (/Must have push access|Not Found|HTTP 404/i.test(msg2)) {
          return { permission: 'none', determined: true, permissionRead: 'not a collaborator (after retry)' };
        }
      }
    }
    return {
      permission: 'none',
      determined: false,
      permissionRead: `permission endpoint did not answer: ${msg.split('\n')[0].slice(0, 200)}`,
    };
  }
}

// ---------------------------------------------------------------------------
// SURFACES
// ---------------------------------------------------------------------------

// Each surface: a query for MY slug, and a control query for a literal that
// is known to live in an indexed repo. If the control does not resolve, the
// surface is unmeasured.
const CONTROL_LITERAL = 'github.com/solana-foundation/solana-web3.js';

const SURFACES = [
  {
    id: 'code-slug',
    kind: 'code',
    literal: SLUG,
    why: 'the repo slug, anywhere in a file',
    run: () => searchItems('code', `"${SLUG}"`),
  },
  {
    id: 'code-slug-url',
    kind: 'code',
    literal: SLUG_URL,
    why: 'the slug as a full github.com URL',
    run: () => searchItems('code', `"${SLUG_URL}"`),
  },
  {
    id: 'code-slug-escaped',
    kind: 'code',
    literal: SLUG_ESCAPED,
    why: 'the slug in URL-escaped form (npm/pip dependency strings)',
    run: () => searchItems('code', `"${SLUG_ESCAPED}"`),
  },
  {
    id: 'issues-slug',
    kind: 'issues',
    literal: SLUG,
    why: 'issues and PRs that name the repo (a stranger asking for it counts)',
    run: () => searchItems('issues', `"${SLUG}"`),
  },
  {
    id: 'commits-slug',
    kind: 'commits',
    literal: SLUG,
    why: 'commit messages that name the repo (a stranger depending on it commits the URL)',
    run: () => searchItems('commits', `"${SLUG}"`),
  },
];

// ---------------------------------------------------------------------------
// MEASUREMENT (runs only when this file is the entry point; the tests import
// the pure functions above without triggering a network sweep)
// ---------------------------------------------------------------------------

function main() {
  // ---------------------------------------------------------------------------
  // MEASUREMENT
  // ---------------------------------------------------------------------------

  const startedAt = new Date().toISOString();

  // Positive control first: one call, shared by all surfaces (the same literal
  // via the same API as the surface itself would use - see controls per kind).
  const controls = {
    code: searchTotalCode(`"${CONTROL_LITERAL}"`),
    issues: (() => {
      const r = searchApi('issues', `"${CONTROL_LITERAL}"`);
      return r && typeof r.total_count === 'number' ? r.total_count : null;
    })(),
    commits: (() => {
      const r = searchApi('commits', `"${CONTROL_LITERAL}"`);
      return r && typeof r.total_count === 'number' ? r.total_count : null;
    })(),
  };

  const surfaces = {};
  const candidates = new Map(); // repo -> {repo, hits:[]}

  for (const surface of SURFACES) {
    const controlMatches = controls[surface.kind];
    const state = surfaceState({ controlMatches });
    const entry = {
      id: surface.id,
      kind: surface.kind,
      literal: surface.literal,
      why: surface.why,
      control: CONTROL_LITERAL,
      controlMatches,
      state,
      hits: [],
    };
    surfaces[surface.id] = entry;
    if (state === 'unmeasured') continue;
    const items = surface.run();
    if (items === null) {
      // The search did not answer -> the surface is UNMEASURED, not empty.
      entry.state = 'unmeasured';
      entry.reason = 'search request failed; 0 hits would be a false absence';
      continue;
    }
    entry.hits = items.filter((i) => i && i.repo);
    for (const item of entry.hits) {
      if (!candidates.has(item.repo)) {
        candidates.set(item.repo, { repo: item.repo, hits: [] });
      }
      candidates.get(item.repo).hits.push({ ...item, surface: surface.id, literal: surface.literal });
    }
  }

  // ---------------------------------------------------------------------------
  // COVERAGE PROBES
  // Two known-positives that bound what this sweep can see:
  //   probe-own  - a reference of mine in a repo of mine (is the index able to
  //                see repos like the ones that would reference me?)
  //   probe-small-foreign - a tiny foreign repo (does the index see repos with
  //                no stars at all?)
  // v1's D3 defect showed probe-own fails for GitHub code search; that failure
  // is now measured and reported instead of silently producing an absence.
  // ---------------------------------------------------------------------------

  const coverage = (() => {
    const probes = [];

    // probe-own MUST be a PUBLIC repo of mine where the reference provably
    // exists. Measured 2026-11-03: the abandoned run used the PRIVATE repo
    // sprintberlin/openclaw-citizen and got visible=true - that only proves
    // my AUTHENTICATED search sees my private repos, not that the public
    // index carries a reference like mine. Public, reference present, index
    // says 0: auroraxo/openreceipts/README.md contains "auroraxo/signerd"
    // twice (contents API) while `q="auroraxo/signerd" repo:auroraxo/openreceipts`
    // and `q=repo:auroraxo/openreceipts` both return 0, and the same query
    // shape on a stranger's 0-star repo returns 29 - so the index genuinely
    // does not carry repos like mine, and an absence claim must say so.
    const ownRepo = process.env.COVERAGE_PROBE_REPO || 'auroraxo/openreceipts';
    const ownPath = process.env.COVERAGE_PROBE_PATH || 'README.md';
    const ownLiteral = fileContains(ownRepo, ownPath, SLUG);
    if (ownLiteral === null) {
      // D6/D10: a failed read is UNMEASURED, not "not visible" - and the
      // probe-own default (sprintberlin/openclaw-citizen) is measured: the
      // file contains the slug, and code search returns >0 for it.
      probes.push({ id: 'probe-own', status: 'unmeasured', repo: ownRepo, path: ownPath, reason: 'could not read the known-positive file' });
    } else {
      const visible = searchTotalCode(`"${SLUG}" repo:${ownRepo}`);
      if (visible === null) {
        probes.push({ id: 'probe-own', status: 'unmeasured', repo: ownRepo, path: ownPath, reason: 'code-search visibility query failed' });
      } else {
        probes.push({
          id: 'probe-own',
          status: 'measured',
          repo: ownRepo,
          path: ownPath,
          literalPresentInFile: ownLiteral,
          visibleToCodeSearch: visible > 0,
        });
      }
    }

    // A small foreign repo, chosen at measurement time (0 stars, recent).
    const smallRepo = process.env.COVERAGE_PROBE_SMALL_REPO || pickSmallForeignRepo();
    if (smallRepo) {
      const repoInfo = ghJson(['api', `repos/${smallRepo}`], { optional: true });
      if (repoInfo && repoInfo.default_branch) {
        const visible = searchTotalCode(`repo:${smallRepo}`);
        if (visible === null) {
          probes.push({ id: 'probe-small-foreign', status: 'unmeasured', repo: smallRepo, reason: 'code-search visibility query failed' });
        } else {
          probes.push({
            id: 'probe-small-foreign',
            status: 'measured',
            repo: smallRepo,
            stars: repoInfo.stargazers_count,
            visibleToCodeSearch: visible > 0,
          });
        }
      } else {
        probes.push({ id: 'probe-small-foreign', status: 'unmeasured', repo: smallRepo, reason: 'could not read the probe repo' });
      }
    } else {
      probes.push({ id: 'probe-small-foreign', status: 'unmeasured', reason: 'no small foreign probe repo could be selected' });
    }

    const status = coverageStatus(probes);

    // probe-indexability-rate: how much of the universe can code search see at
    // all? Measured 2026-11-03: among fresh public 0-star repos, indexability
    // is NOT a function of size or stars - one such repo returned 29 hits,
    // another 0. So an absence over the code surfaces covers only the INDEXED
    // subset, and the size of that subset has to be measured, not assumed.
    const indexability = (() => {
      const sample = (process.env.COVERAGE_PROBE_SAMPLE || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (sample.length === 0) return { status: 'skipped', reason: 'no sample configured' };
      const rows = [];
      for (const r of sample) {
        const visible = searchTotalCode(`repo:${r}`);
        rows.push({ repo: r, visibleToCodeSearch: visible === null ? null : visible > 0 });
      }
      const answered = rows.filter((x) => x.visibleToCodeSearch !== null);
      if (answered.length === 0) return { status: 'unmeasured', reason: 'no visibility query answered', rows };
      const visibleCount = answered.filter((x) => x.visibleToCodeSearch).length;
      return {
        status: 'measured',
        sampleSize: answered.length,
        visible: visibleCount,
        rate: visibleCount / answered.length,
        rows,
      };
    })();
    return {
      status,
      probes,
      indexability,
      scope: [
        ...probes
          .filter((p) => p.status === 'measured' && p.visibleToCodeSearch === false)
          .map((p) => `${p.id} (${p.repo}): NOT visible to code search - absence claims do not cover repos like this one`),
        ...(indexability.status === 'measured'
          ? [
              `code-search indexability of the sampled fresh public 0-star repos: ${indexability.visible}/${indexability.sampleSize} visible (${Math.round(indexability.rate * 100)}%) - the code surfaces can only ever see the indexed subset`,
            ]
          : []),
      ],
    };
  })();

  // ---------------------------------------------------------------------------
  // VERIFICATION + ATTRIBUTION
  // ---------------------------------------------------------------------------

  const verifiedForeign = [];
  const verifiedOwn = [];
  const unknownAttribution = [];

  for (const c of candidates.values()) {
    const perm = permissionFor(c.repo);
    const repoOwn = perm.determined && isOwnRepo(perm.permission);
    let best = null;

    for (const h of c.hits) {
      const surface = SURFACES.find((s) => s.id === h.surface);
      if (!surface) continue;
      let contains = null;
      if (surface.kind === 'code') {
        contains = fileContains(c.repo, h.path, h.literal);
      } else if (surface.kind === 'issues') {
        contains = issueBodyContains(c.repo, h.number, h.literal);
      } else if (surface.kind === 'commits') {
        contains = commitMessageContains(c.repo, h.sha, h.literal);
      }
      if (contains === true && hitIsVerified({ fileContainsLiteral: contains, literal: h.literal })) {
        best = h;
        break;
      }
    }

    if (!best) continue;

    const authorIsMe = best.author !== null && best.author !== undefined
      && String(best.author).toLowerCase() === String(OWNER).toLowerCase();
    const attribution = attributeHit({
      repoOwn,
      authorIsMe,
      permissionDetermined: perm.determined,
    });

    const record = {
      repo: c.repo,
      permission: perm.permission,
      permissionDetermined: perm.determined,
      permissionRead: perm.permissionRead,
      repoOwn,
      author: best.author,
      authorIsMe,
      attribution,
      surface: best.surface,
      path: best.path,
      evidence: best.surface,
    };
    if (attribution === 'foreign') verifiedForeign.push(record);
    else if (attribution === 'unknown') unknownAttribution.push(record);
    else verifiedOwn.push(record);
  }

  // ---------------------------------------------------------------------------
  // VERDICT + REPORT
  // ---------------------------------------------------------------------------

  const surfaceStates = Object.values(surfaces).map((s) => ({ id: s.id, state: s.state }));
  let verdict = decideVerdict({
    verifiedForeign,
    verifiedOwn,
    surfaceStates,
    coverage,
    unknownAttribution,
  });
  // D9: never persist an absence verdict while a data source failed. The old
  // tool printed NO VERDICT on stderr but WROTE `no-foreign-reference-found`
  // into the JSON - the artifact would then be quoted as an absence claim.
  if (failures.length > 0 && verdict.class !== 'foreign-use-evidence') {
    verdict = {
      class: 'no-verdict',
      signals: [
        ...verdict.signals,
        `${failures.length} data source(s) failed (see failures[])`,
      ],
      meaning: 'the run was incomplete; a persisted absence would be an artifact, not a measurement',
    };
  }

  const report = {
    measuredAt: startedAt,
    repo: REPO,
    controls,
    surfaces,
    coverage,
    candidates: [...candidates.values()].map((c) => ({
      repo: c.repo,
      hits: c.hits.length,
    })),
    verifiedForeign,
    verifiedOwn,
    unknownAttribution,
    verdict,
    dataSourcesFailed: failures.length,
    failures,
    complete: failures.length === 0,
  };

  const lines = [];
  lines.push(`foreign-use measurement ${REPO} @ ${startedAt}`);
  lines.push(
    `  controls: code=${controls.code} issues=${controls.issues} commits=${controls.commits}`
  );
  lines.push(
    `  surfaces: ${surfaceStates.filter((s) => s.state === 'measured').length} measured, ${surfaceStates.filter((s) => s.state === 'unmeasured').length} unmeasured`
  );
  for (const s of Object.values(surfaces)) {
    lines.push(
      `  [${s.state}] ${s.id}: hits=${s.hits.length}${s.state === 'unmeasured' ? ' (control did NOT resolve - not zero)' : ''}`
    );
  }
  for (const p of coverage.probes) {
    if (p.status === 'measured') {
      lines.push(
        `  coverage ${p.id} (${p.repo}): visible=${p.visibleToCodeSearch}${p.literalPresentInFile !== undefined ? ` literalInFile=${p.literalPresentInFile}` : ''}`
      );
    } else {
      lines.push(`  coverage ${p.id} (${p.repo}): ${p.status}${p.reason ? ` (${p.reason})` : ''}`);
    }
  }
  for (const s of coverage.scope || []) lines.push(`    SCOPE LIMIT: ${s}`);
  lines.push(
    `  candidates: ${candidates.size} | verified foreign: ${verifiedForeign.length} | verified own: ${verifiedOwn.length}`
  );
  for (const r of verifiedForeign) {
    lines.push(`    FOREIGN ${r.repo} (repo=${r.permission}, author=${r.author}, via ${r.surface})`);
  }
  for (const r of verifiedOwn) {
    lines.push(`    own    ${r.repo} (repo=${r.permission}, author=${r.author}, ${r.attribution}, via ${r.surface})`);
  }
  for (const r of unknownAttribution) {
    lines.push(`    UNKNOWN ${r.repo} (permission read failed: ${r.permissionRead}; NOT counted as foreign, via ${r.surface})`);
  }
  if (failures.length > 0) {
    lines.push(`  NO VERDICT - ${failures.length} data source(s) failed:`);
    for (const f of failures) lines.push(`    - ${f}`);
  } else {
    lines.push(`  VERDICT: ${verdict.class} - ${verdict.meaning}`);
    for (const s of verdict.signals) lines.push(`    - ${s}`);
  }
  console.log(lines.join('\n'));

  if (OUT) {
    fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
    console.error(`wrote ${OUT}`);
  }

  if (failures.length > 0 || verdict.class === 'no-verdict') process.exit(3);
}

// Only run the measurement when executed directly, not when imported by a test.
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
