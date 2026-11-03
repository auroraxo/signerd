// Tests for tools/measure-prior-art-delta.mjs - the instrument that measures
// the differentiation from the same-named prior art @zanii/signerd.
//
// Ladder (measured, not asserted):
//   pre-fix tree 757951c: the file does not exist -> ERR_MODULE_NOT_FOUND,
//                     0/1 (the instrument IS the fix)
//   this tree:             all green
// G5 (the false-positive guard): the PREMISE test that finds their sentence
// in their own text is the case that must keep working - it passes on any
// tree, it is the guard that the domain test cannot pass by accident.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DOMAIN_TERMS,
  NETWORK_IMPORT_TERMS,
  PREMISE,
  scanTerms,
  totalCounts,
  classifyServerCoupling,
  premiseEvidence,
  decideVerdict,
  exitCodeFor,
  deriveSummary,
} from '../tools/measure-prior-art-delta.mjs';

test('scanTerms counts every occurrence, case-insensitively', () => {
  const counts = scanTerms('Solana and solana and SOLANA lamports', DOMAIN_TERMS);
  assert.equal(counts.solana, 3);
  assert.equal(counts.lamports, 1);
  assert.equal(counts.transaction, 0);
});

test('scanTerms counts non-overlapping occurrences only', () => {
  // 'transaction' appears inside 'transactions' - one occurrence, not two.
  assert.equal(scanTerms('transactions', DOMAIN_TERMS).transaction, 1);
  assert.equal(scanTerms('transactiontransaction', DOMAIN_TERMS).transaction, 2);
});

test('totalCounts sums the per-term counts', () => {
  assert.equal(totalCounts({ a: 1, b: 2, c: 0 }), 3);
});

test('classifyServerCoupling distinguishes required from optional serverUrl', () => {
  const required = classifyServerCoupling('export interface O { serverUrl: string; }');
  assert.equal(required.required, true);
  assert.equal(required.optionalOnly, false);

  const optional = classifyServerCoupling('export interface O { serverUrl?: string; }');
  assert.equal(optional.required, false);
  assert.equal(optional.optionalOnly, true);

  const none = classifyServerCoupling('export interface O { }');
  assert.equal(none.required, false);
  assert.equal(none.optionalOnly, false);
});

test('G5 guard: the prior-art premise sentence is found in their published text', () => {
  // This is the FALSE-POSITIVE GUARD: it must pass on any tree. It proves the
  // premise scan is not broken, so a 'distinct domain' verdict cannot come
  // from a scanner that finds nothing at all.
  const theirText = "**Keep the agent's private key out of the agent's process.** `zanii-signerd` unseals the key once, holds it in its own process";
  const found = premiseEvidence(theirText, PREMISE.priorArt);
  assert.equal(found.found, true);

  const other = premiseEvidence('something else entirely', PREMISE.priorArt);
  assert.equal(other.found, false);
});

test('decideVerdict: distinct only when prior art is measured and touches nothing', () => {
  assert.equal(
    decideVerdict({ priorArtMeasured: true, priorArtFilesScanned: 3, priorArtDomainTotal: 0, ownDomainTotal: 111 }),
    'prior-art-distinct-domain',
  );
});

test('decideVerdict: a prior art that touches the domain falsifies distinct', () => {
  assert.equal(
    decideVerdict({ priorArtMeasured: true, priorArtFilesScanned: 3, priorArtDomainTotal: 2, ownDomainTotal: 111 }),
    'prior-art-overlaps-domain',
  );
});

test('decideVerdict: an unmeasured prior art is NO VERDICT, never distinct', () => {
  assert.equal(
    decideVerdict({ priorArtMeasured: false, priorArtFilesScanned: 0, priorArtDomainTotal: 0, ownDomainTotal: 111 }),
    'no-verdict',
  );
});

test('decideVerdict: a blind own-side scanner is NO VERDICT, never distinct', () => {
  // The failure mode this guards: a scanner that matches nothing on EITHER
  // side would report "distinct" for any package at all.
  assert.equal(
    decideVerdict({ priorArtMeasured: true, priorArtFilesScanned: 3, priorArtDomainTotal: 0, ownDomainTotal: 0 }),
    'no-verdict',
  );
});

test('decideVerdict: prior art with zero scanned files is NO VERDICT', () => {
  assert.equal(
    decideVerdict({ priorArtMeasured: true, priorArtFilesScanned: 0, priorArtDomainTotal: 0, ownDomainTotal: 111 }),
    'no-verdict',
  );
});

test('exitCodeFor: no-verdict exits 3, every other verdict exits 0', () => {
  assert.equal(exitCodeFor('no-verdict'), 3);
  assert.equal(exitCodeFor('prior-art-distinct-domain'), 0);
  assert.equal(exitCodeFor('prior-art-overlaps-domain'), 0);
});

test('deriveSummary re-derives totals from the rows (hand-edited rows surface)', () => {
  const priorArt = { domainCounts: { solana: 0, transaction: 0 }, networkImportCounts: { 'node:https': 2 } };
  const own = { domainCounts: { solana: 10, transaction: 20 }, networkImportCounts: { 'node:https': 0 } };
  const summary = deriveSummary(priorArt, own);
  assert.equal(summary.priorArtDomainTotal, 0);
  assert.equal(summary.ownDomainTotal, 30);
  assert.equal(summary.priorArtNetworkImportTotal, 2);
  assert.equal(summary.ownNetworkImportTotal, 0);

  // mutate a row -> the derived summary must move with it
  priorArt.domainCounts.solana = 4;
  assert.equal(deriveSummary(priorArt, own).priorArtDomainTotal, 4);
});

test('the committed prior-art report is a real measurement, not a template', () => {
  const dir = new URL('../research/', import.meta.url);
  const files = readdirSync(dir).filter((f) => /^prior-art-delta-.*\.json$/.test(f));
  if (files.length === 0) return; // report not generated yet: nothing to assert
  const report = JSON.parse(readFileSync(join(dir.pathname, files[0]), 'utf8'));
  assert.ok(report.priorArt.measured, 'the prior art surface must be measured');
  assert.ok(report.priorArt.filesScanned.length >= 1);
  assert.ok(report.summary.ownDomainTotal > 0, 'the own side must not be empty');
  assert.ok(report.controls.ownScannerBlind === false, 'the own-side scanner must not be blind');
  assert.equal(report.verdict, 'prior-art-distinct-domain');
  assert.equal(report.priorArt.domainCounts.solana, 0);
  assert.ok(report.timeline.priorArtDaysAhead > 0, 'the prior art must be measured as earlier');
});

test('the tool file itself exists and exports a main', async () => {
  const mod = await import('../tools/measure-prior-art-delta.mjs');
  assert.equal(typeof mod.main, 'function');
});

test('the README quotes the report, not the other way around', () => {
  const dir = new URL('../research/', import.meta.url);
  const files = readdirSync(dir).filter((f) => /^prior-art-delta-.*\.json$/.test(f));
  if (files.length === 0) return; // report not generated yet: nothing to pin
  const report = JSON.parse(readFileSync(join(dir.pathname, files[0]), 'utf8'));
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  // Every number the README states for this measurement must be DERIVED from
  // the artifact - no hardcoded fallback here, or the pin would not pin.
  assert.ok(readme.includes('research/prior-art-delta-'), 'README must cite the report file');
  assert.ok(
    readme.includes(`**${report.summary.priorArtDomainTotal}/6 terms, ${report.summary.priorArtDomainTotal} occurrences**`),
    `prior-art domain total must be quoted as ${report.summary.priorArtDomainTotal}`,
  );
  assert.ok(
    readme.includes(`**${report.summary.ownDomainTotal} occurrences**`),
    `own domain total must be quoted as ${report.summary.ownDomainTotal}`,
  );
  assert.ok(
    readme.includes(`${report.priorArt.downloads.lastWeek} downloads last week`),
    `downloads must be quoted as ${report.priorArt.downloads.lastWeek}`,
  );
  assert.ok(
    readme.includes(`**\`${report.verdict}\`**`),
    `verdict must be quoted as ${report.verdict}`,
  );
});

test('the committed summary is re-derivable from its own rows', () => {
  const dir = new URL('../research/', import.meta.url);
  const files = readdirSync(dir).filter((f) => /^prior-art-delta-.*\.json$/.test(f));
  if (files.length === 0) return;
  const report = JSON.parse(readFileSync(join(dir.pathname, files[0]), 'utf8'));
  // Hand-editing a row must move the summary: the summary is derived, never
  // hand-typed. This is the mutation that a summary-shaped field could hide.
  const derived = deriveSummary(report.priorArt, report.own);
  assert.equal(derived.priorArtDomainTotal, report.summary.priorArtDomainTotal);
  assert.equal(derived.ownDomainTotal, report.summary.ownDomainTotal);
  assert.equal(derived.ownNetworkImportTotal, report.summary.ownNetworkImportTotal);

  // mutate a row -> the derived summary must move with it
  const mutated = { ...report.priorArt, domainCounts: { ...report.priorArt.domainCounts, solana: 7 } };
  assert.notEqual(deriveSummary(mutated, report.own).priorArtDomainTotal, report.summary.priorArtDomainTotal);
});

test('the prior-art term list is the SAME list used on both sides', () => {
  // A per-side list would be the defect class this instrument exists to avoid.
  assert.ok(DOMAIN_TERMS.length >= 4);
  assert.ok(DOMAIN_TERMS.includes('solana'));
  assert.ok(NETWORK_IMPORT_TERMS.includes('node:https'));
});
