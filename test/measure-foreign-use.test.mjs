// Controls for tools/measure-foreign-use.mjs - the instrument that asks
// whether a REPO I DO NOT CONTROL references signerd.
//
// These tests pin the four defects of v1, each one measured before it was
// written:
//   D1 bare-name substring noise   -> surfaceState must never let an
//                                     uncontrolled surface report "0 = none"
//   D2 owner-prefix attribution    -> isOwnRepo must accept the sprintberlin
//                                     repo I have push rights on
//   D3 false absence via blind
//      index                        -> decideVerdict must withhold an absence
//                                     verdict when a surface or a coverage
//                                     probe is unmeasured
//   D4 my own placement counted
//      as foreign use              -> attributeHit must call a hit I authored
//                                     own, even inside a foreign repo
//
// The pure functions are exported for exactly this reason: v1 had no
// separable logic, so its defects could only be caught by reading its live
// output.
//
// THE LADDER, MEASURED (not asserted):
//   pre-fix tree  = the ABANDONED v3 run of 2026-11-03 (files written
//   13:40-13:42 local, taken over by producer-pulse at 20:41Z; it died with
//   coverage=unmeasured / verdict=no-verdict / exit 3, preserved verbatim in
//   research/foreign-use-2026-11-03.v2-no-verdict.json).
//   - the ORIGINAL 9 tests pass on that tree (they pin v1's D1-D4);
//   - the file as it stands NOW fails on that tree (the module exports no
//     coverageStatus/isRetryableFailure, and the pre-fix decideVerdict
//     answered 'foreign' for an undetermined permission read and 'own-use-only'
//     for a coverage probe that never ran - both measured directly against
//     that tree before the fix);
//   - on the fixed tree: 14/14 pass.
//
// v1's own false-verdict report is NOT committed: the v1 code never existed in
// this repo's history, so there is nothing to point at - the defects above
// were measured on live output instead.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  surfaceState,
  coverageStatus,
  isRetryableFailure,
  isOwnRepo,
  attributeHit,
  hitIsVerified,
  decideVerdict,
} from '../tools/measure-foreign-use.mjs';

// ---- D1: an uncontrolled surface is UNMEASURED, never "zero" ---------------
test('D1: a surface whose control did not resolve is unmeasured, not zero', () => {
  assert.equal(surfaceState({ controlMatches: 0 }), 'unmeasured');
  assert.equal(surfaceState({ controlMatches: null }), 'unmeasured');
  assert.equal(surfaceState({ controlMatches: undefined }), 'unmeasured');
  assert.equal(surfaceState({ controlMatches: NaN }), 'unmeasured');
  assert.equal(surfaceState({ controlMatches: 419 }), 'measured');
});

// ---- D2: ownership by permission, not by owner prefix ----------------------
test('D2: a repo I have push rights on is mine even under another owner', () => {
  // measured: gh api repos/sprintberlin/openclaw-citizen/collaborators/auroraxo/permission -> write
  assert.equal(isOwnRepo('write'), true);
  assert.equal(isOwnRepo('admin'), true);
  assert.equal(isOwnRepo('maintain'), true);
  // measured: same call on tendermint/tendermint -> 403, on foreign repos -> no access
  assert.equal(isOwnRepo('none'), false);
  assert.equal(isOwnRepo(null), false);
  assert.equal(isOwnRepo(undefined), false);
  assert.equal(isOwnRepo(403), false);
});

// ---- D4: authorship beats hosting repo ------------------------------------
test('D4: a hit I authored is own activity even in a foreign repo', () => {
  // measured: awesome-solana-ai#280 is a foreign repo, author=auroraxo,
  // body contains the slug - my own placement, not foreign consumption
  assert.equal(attributeHit({ repoOwn: false, authorIsMe: true }), 'own-authored');
  assert.equal(attributeHit({ repoOwn: true, authorIsMe: true }), 'own-authored');
  assert.equal(attributeHit({ repoOwn: true, authorIsMe: false }), 'own-repo');
  // the only case that may ever be called foreign use:
  assert.equal(attributeHit({ repoOwn: false, authorIsMe: false }), 'foreign');
  assert.equal(attributeHit({ repoOwn: false, authorIsMe: undefined }), 'foreign');
});

// ---- verification: the file, not the index, decides ------------------------
test('a hit counts only when the file literally contains the reference', () => {
  assert.equal(
    hitIsVerified({ fileContainsLiteral: true, literal: 'auroraxo/signerd' }),
    true
  );
  // stale index entry / substring rumor / unreadable file -> not verified
  assert.equal(
    hitIsVerified({ fileContainsLiteral: false, literal: 'auroraxo/signerd' }),
    false
  );
  assert.equal(hitIsVerified({ fileContainsLiteral: null, literal: 'x' }), false);
  assert.equal(hitIsVerified({ fileContainsLiteral: true, literal: '' }), false);
});

// ---- D3 + verdict ladder ----------------------------------------------------
test('D3: a foreign hit wins even if other surfaces were unmeasured', () => {
  const v = decideVerdict({
    verifiedForeign: [{ repo: 'stranger/tool', path: 'a.md' }],
    verifiedOwn: [],
    surfaceStates: [
      { id: 'code-slug', state: 'measured' },
      { id: 'issues-slug', state: 'unmeasured' },
    ],
    coverage: { status: 'unmeasured' },
  });
  assert.equal(v.class, 'foreign-use-evidence');
});

test('D3: no absence verdict while any surface is unmeasured', () => {
  const v = decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [],
    surfaceStates: [
      { id: 'code-slug', state: 'measured' },
      { id: 'commits-slug', state: 'unmeasured' },
    ],
    coverage: { status: 'measured' },
  });
  assert.equal(v.class, 'no-verdict');
});

test('D3: no absence verdict while the coverage probe is unmeasured', () => {
  const v = decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [],
    surfaceStates: [{ id: 'code-slug', state: 'measured' }],
    coverage: { status: 'unmeasured' },
  });
  assert.equal(v.class, 'no-verdict');
  assert.equal(decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [],
    surfaceStates: [{ id: 'code-slug', state: 'measured' }],
    coverage: null,
  }).class, 'no-verdict');
});

test('own-only references report own-use-only, never absence', () => {
  const v = decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [{ repo: 'sprintberlin/openclaw-citizen', path: 'visionaer/ideen.md' }],
    surfaceStates: [{ id: 'code-slug', state: 'measured' }],
    coverage: { status: 'measured' },
  });
  assert.equal(v.class, 'own-use-only');
  assert.match(v.meaning, /proves nothing about outsiders/);
});

test('all surfaces measured, coverage measured, nothing found -> scoped absence', () => {
  const v = decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [],
    surfaceStates: [
      { id: 'code-slug', state: 'measured' },
      { id: 'issues-slug', state: 'measured' },
      { id: 'commits-slug', state: 'measured' },
    ],
    coverage: { status: 'measured' },
  });
  assert.equal(v.class, 'no-foreign-reference-found');
  assert.match(v.meaning, /scoped/);
});

// ---------------------------------------------------------------------------
// V3 DEFECTS - each measured against the abandoned 2026-11-03 tree BEFORE the
// fix (the tree that produced coverage=unmeasured / verdict=no-verdict /
// exit 3 and is preserved in research/foreign-use-2026-11-03.v2-no-verdict.json)
// ---------------------------------------------------------------------------

// ---- D5: a SKIPPED probe is not coverage ---------------------------------
test('D5: a skipped coverage probe does not count as measured coverage', () => {
  assert.equal(
    coverageStatus([
      { id: 'probe-own', status: 'measured' },
      { id: 'probe-small-foreign', status: 'skipped' },
    ]),
    'unmeasured'
  );
  assert.equal(
    coverageStatus([
      { id: 'probe-own', status: 'measured' },
      { id: 'probe-small-foreign', status: 'measured' },
    ]),
    'measured'
  );
  assert.equal(coverageStatus([]), 'unmeasured');
  assert.equal(coverageStatus(null), 'unmeasured');
});

test('D5: a caller-computed coverage status that counted a skipped probe is not trusted', () => {
  // The pre-fix code computed `probes.every(p => p.status !== 'unmeasured')`
  // and handed THAT to the verdict. A skipped probe therefore rode under an
  // absence verdict. The verdict must recompute from the probe list.
  const v = decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [],
    surfaceStates: [{ id: 'code-slug', state: 'measured' }],
    coverage: {
      status: 'measured', // the pre-fix (wrong) status
      probes: [
        { id: 'probe-own', status: 'measured' },
        { id: 'probe-small-foreign', status: 'skipped' },
      ],
    },
  });
  assert.equal(v.class, 'no-verdict');
});

// ---- D8: an undetermined permission read can never be foreign -------------
test('D8: an undetermined permission read is unknown, never foreign use', () => {
  // measured pre-fix: permissionFor() returned 'none' on ANY error, and
  // attributeHit() turned that into 'foreign' - foreign use claimed on
  // missing evidence.
  assert.equal(
    attributeHit({ repoOwn: false, authorIsMe: false, permissionDetermined: false }),
    'unknown'
  );
  assert.equal(
    attributeHit({ repoOwn: null, authorIsMe: false, permissionDetermined: false }),
    'unknown'
  );
  // a determined read still decides
  assert.equal(
    attributeHit({ repoOwn: false, authorIsMe: false, permissionDetermined: true }),
    'foreign'
  );
  assert.equal(
    attributeHit({ repoOwn: true, authorIsMe: true, permissionDetermined: false }),
    'own-authored'
  );
});

test('D8: unknown attribution blocks an absence verdict', () => {
  const v = decideVerdict({
    verifiedForeign: [],
    verifiedOwn: [],
    unknownAttribution: [
      { repo: 'stranger/tool', permissionRead: 'rate limit' },
    ],
    surfaceStates: [{ id: 'code-slug', state: 'measured' }],
    coverage: { status: 'measured', probes: [{ id: 'p', status: 'measured' }] },
  });
  assert.equal(v.class, 'no-verdict');
  assert.match(v.meaning, /never becomes foreign use/);
});

// ---- D7: retryable vs authoritative failures ------------------------------
test('D7: rate limits and 5xx are retryable, authoritative negatives are not', () => {
  assert.equal(isRetryableFailure('gh api failed: HTTP 403: rate limit exceeded'), true);
  assert.equal(isRetryableFailure('gh api failed: HTTP 502: bad gateway'), true);
  assert.equal(isRetryableFailure('gh api failed: timed out'), true);
  assert.equal(isRetryableFailure('gh api failed: socket hang up'), true);
  // authoritative: the endpoint already answered
  assert.equal(
    isRetryableFailure('gh api failed: HTTP 403: Must have push access to view repository collaborators'),
    false
  );
  assert.equal(isRetryableFailure('gh api failed: HTTP 404: Not Found'), false);
  assert.equal(isRetryableFailure('gh api failed: HTTP 422: Validation Failed'), false);
  assert.equal(isRetryableFailure(undefined), false);
});
