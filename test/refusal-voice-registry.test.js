'use strict';

// PIN: the refusal voice reached the channel a stranger uses.
//
// WHY: research/refusal-voice-registry-v*-*.json claims that a daemon policy
// refusal on the PUBLISHED npm package reaches stderr with a code and a
// repair, that the machine channel is unchanged, and that the legal path
// stays silent. Without this gate the artifact is a stored claim — the
// registry-contradiction class this repo keeps finding is exactly a claim
// that no longer describes the channel.
//
// THE CONTRACT (P1-P4) plus a FALSIFICATION face:
//   P1 the newest artefact for the pin parses, names the schema, the
//      channel and the pin version;
//   P2 the numbers hold: both refusals exit 1 with the code once on stderr
//      and a fix line; the machine channel stayed ok:false + error; the
//      legal sign exits 0 with ZERO stderr bytes and wrote its artifact;
//   P3 FALSIFICATION: an artefact edited so that a failing case still
//      claims to pass is caught by a DERIVED verdict, not the stored one;
//   P4 GUARD: no host path anywhere in the committed artefact (green on
//      every tree).

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const RESEARCH = path.join(ROOT, 'research');

function pin() {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const tags = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((s) => s.split('#')[1]))];
  assert.strictEqual(tags.length, 1, `README pin is not exactly one tag: ${tags.join(', ')}`);
  return tags[0].replace(/^v/, '');
}

function newestArtefact() {
  const names = fs.existsSync(RESEARCH) ? fs.readdirSync(RESEARCH)
    .filter((n) => /^refusal-voice-registry-v\d+\.\d+\.\d+-\d{4}-\d{2}-\d{2}\.json$/.test(n))
    .sort() : [];
  return names.length > 0 ? names[names.length - 1] : null;
}

function load() {
  const name = newestArtefact();
  assert.ok(name, 'no refusal-voice registry artefact — run tools/measure-refusal-voice-registry.js against the pin');
  return { name, data: JSON.parse(fs.readFileSync(path.join(RESEARCH, name), 'utf8')) };
}

/** The artefact passes only if the NUMBERS say so, never the stored label. */
function derivedVerdict(data) {
  const fails = [];
  if (data.verdict !== 'refusal-voice-reaches-the-published-channel') fails.push('stored verdict is not the channel verdict');
  if (!Array.isArray(data.failures) || data.failures.length !== 0) fails.push('failures list is not empty');
  const cases = new Map((data.cases || []).map((c) => [c.case, c]));
  const dest = cases.get('destination');
  const ghost = cases.get('grant_not_found');
  const legal = cases.get('legal_sign_stays_silent');
  if (!dest) fails.push('no destination case');
  else {
    if (dest.exit !== 1) fails.push('destination did not exit 1');
    if (dest.fixPresent !== true) fails.push('destination stderr has no fix line');
    if (dest.stderrCodeLine !== 'destination') fails.push('the code is not the first stderr line');
    if (dest.machineUnchanged !== true) fails.push('the machine channel changed shape');
    if (dest.repairNamesRealCommand !== true) fails.push('the repair names no real command');
    if (dest.repairCarriesGrantName !== true) fails.push('the repair carries no grant name');
    if (dest.stderrHasHostPath || dest.stdoutHasHostPath) fails.push('a host path reached a channel');
  }
  if (!ghost) fails.push('no grant_not_found case');
  else {
    if (ghost.exit !== 1) fails.push('grant_not_found did not exit 1');
    if (ghost.fixPresent !== true) fails.push('grant_not_found stderr has no fix line');
    if (ghost.stderrCodeLine !== 'grant_not_found') fails.push('the code is not the first stderr line');
    if (ghost.machineUnchanged !== true) fails.push('the machine channel changed shape');
    if (ghost.repairCarriesGrantName !== true) fails.push('the repair carries no grant name');
  }
  if (!legal) fails.push('no legal-sign guard case');
  else {
    if (legal.exit !== 0) fails.push('a legal sign did not exit 0');
    if (legal.stderrBytes !== 0) fails.push('a legal sign wrote to stderr');
    if (legal.wroteOutput !== true) fails.push('the legal sign wrote no artifact');
  }
  if (data.hostPathFree !== true) fails.push('the artefact is not host-path free');
  return fails;
}

test('P1 the newest artefact parses, names the schema, channel and pin', () => {
  const { name, data } = load();
  assert.strictEqual(data.schema, 'signerd-refusal-voice-registry/1', `${name}: wrong schema`);
  assert.match(data.channel, /registry/, `${name}: the artefact must name the registry channel`);
  assert.strictEqual(data.version, pin(), `${name}: the artefact version must equal the README pin`);
  assert.ok(data.measuredAt, `${name}: no measuredAt`);
});

test('P2 the NUMBERS hold — derived, never from the stored verdict', () => {
  const { data } = load();
  assert.deepStrictEqual(derivedVerdict(data), []);
});

test('P3 FALSIFICATION: a passing claim over a failing case is caught', () => {
  const { data } = load();
  // The dangerous direction: everything silently okay EXCEPT the legal path
  // started chattering on stderr (the M7 mutation), with the stored label
  // still claiming success.
  const forged = JSON.parse(JSON.stringify(data));
  forged.failures = [];
  const legal = forged.cases.find((c) => c.case === 'legal_sign_stays_silent');
  legal.stderrBytes = 215;
  legal.exit = 1;
  assert.ok(derivedVerdict(forged).length > 0,
    'an artefact claiming success over a failing legal path must be caught');

  // And the reverse: a real refusal whose repair disappeared.
  const stripped = JSON.parse(JSON.stringify(data));
  stripped.failures = [];
  const dest = stripped.cases.find((c) => c.case === 'destination');
  dest.fixPresent = false;
  dest.repairCarriesGrantName = false;
  assert.ok(derivedVerdict(stripped).length > 0,
    'an artefact claiming a repair that is not there must be caught');
});

test('P4 GUARD: no host path anywhere in the committed artefact (green on every tree)', () => {
  const { name, data } = load();
  const raw = JSON.stringify(data);
  assert.ok(!/\/home\/|\/Users\/|\/root\//.test(raw), `${name}: a host path is recorded in the artefact`);
});
