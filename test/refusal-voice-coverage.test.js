'use strict';

// EVERY REFUSAL CODE THE SOURCE CAN EMIT HAS A REPAIR (2026-11-17).
//
// WHY (measured 2026-11-17, tools/measure-daemon-refusal-voice.js): a
// daemon refusal reached the operator as a code on stdout and NOTHING on
// stderr. The fix attaches a repair to every verdict. This gate is what
// keeps the NEXT refusal class from shipping mute: a code that appears in
// the source and has no repair is a defect waiting to happen.
//
// The contract:
//   C1 every code the source can emit has a repair;
//   C2 no code appears twice in the map (a duplicate key silently keeps the
//      LAST one - that is how a transaction refusal ended up pointing at
//      receipt fields; see src/refusal-voice.js);
//   C3 every repair names a command this CLI ACTUALLY OFFERS
//      (src/cli-flags.js rule F3);
//   C4 every repair carries no host path;
//   C5 a repair is never empty.
//
// HOW THE CODES ARE COLLECTED: from the SOURCE, not from a hand-written
// list - a list would rot the moment a code was added. Every
// `refused('...')`, `error: '...'` and `fail('...')` in src/ is scraped, and
// the union is compared against the map.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const { refusalFix, REPAIRS, KIND_SCOPED } = require(path.join(ROOT, 'src', 'refusal-voice.js'));

/** Every command this CLI offers - a repair may only name one of these. */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

/**
 * The codes that can reach a VERDICT FRAME - the codes the refusal voice
 * has to speak for.
 *
 * Scraped from the source, not from a hand-written list: a list would rot
 * the moment a code was added, and a code the map does not know is a
 * refusal that ships mute.
 *
 * The scrape is SCOPED to the modules that produce a verdict:
 *   - src/policy.js, src/policy-message.js, src/signer.js,
 *     src/signer-message.js, src/ledger.js: the policy/ledger verdicts
 *     (`refused('<code>')`);
 *   - src/daemon.js: the daemon's own literals (`error: '<code>'`);
 *   - src/keystore.js: the keystore family's `fail('<code>')` (added
 *     2026-11-18 with the cli-voice sweep: the keystore codes now travel
 *     through the SAME map at the CLI's generic tail, so a missing repair
 *     there is the same mute-refusal defect this gate exists to catch);
 *   - src/grantseal.js: the grant-SEAL family (added 2026-11-18 with the
 *     grant-seal-voice sweep: the seal reasons reached the operator as a
 *     bare name with no repair - `grant_file_seal_mismatch: ` - while the
 *     journal half of the same idea had repairs; the seal codes now
 *     travel through the SAME map, so a missing repair there is the same
 *     mute-refusal defect this gate exists to catch).
 *
 * Codes from the OTHER modules are deliberately OUT of scope: a
 * `grant_file_*` or `ledger_sealed` error is raised by a CLI command that
 * prints it with its OWN wording and its own repair (the grant-file and
 * journal refusal classes, which already had a voice before this fix). A
 * daemon verdict frame is a different surface, and only THAT surface is
 * what this gate covers.
 *
 * The scrape is generous within that scope: a code that is scraped but not
 * reachable still gets a repair, which is the safe direction - a repair
 * for an unreachable code is harmless, a missing repair is not.
 */
const VERDICT_MODULES = [
  'policy.js', 'policy-message.js', 'signer.js', 'signer-message.js',
  'ledger.js', 'daemon.js', 'keystore.js', 'grantseal.js',
];

function scrapeSourceCodes() {
  const dir = path.join(ROOT, 'src');
  const codes = new Set();
  const patterns = [
    /refused\('([a-z_]+)'/g,
    /error:\s*'([a-z_]+)'/g,
  ];
  // src/keystore.js raises its codes with `fail('<code>')` instead of the
  // `refused('...')` / `error: '...'` forms above - one extra pattern for
  // that file, still scraped from the source, never a hand-written list.
  // src/keystore.js and src/grantseal.js raise their codes with
  // `fail('<code>')` / `reason: '<code>'` instead of the `refused('...')` /
  // `error: '...'` forms above - extra patterns for those two files, still
  // scraped from the source, never a hand-written list.
  const multiPatternFiles = {
    'keystore.js': /fail\('([a-z_]+)'/g,
    'grantseal.js': /(?:fail|new Error|reason:)\s*\(?\s*'([a-z_]+)'/g,
  };
  let f;
  for (const [name, pattern] of Object.entries(multiPatternFiles)) {
    const text = fs.readFileSync(path.join(dir, name), 'utf8');
    pattern.lastIndex = 0;
    while ((f = pattern.exec(text)) !== null) codes.add(f[1]);
  }
  for (const name of VERDICT_MODULES) {
    const text = fs.readFileSync(path.join(dir, name), 'utf8');
    for (const re of patterns) {
      let m;
      re.lastIndex = 0;
      while ((m = re.exec(text)) !== null) codes.add(m[1]);
    }
  }
  return [...codes].sort();
}

test('C1: every refusal code the source can emit has a repair', () => {
  const codes = scrapeSourceCodes();
  assert.ok(codes.length > 20, `the scrape must find the codes, found ${codes.length}`);
  const missing = [];
  for (const code of codes) {
    // A code the map does not know, but which the CLI prints with its own
    // wording (the ones handled before the generic tail in bin/signerd.js).
    const known = Object.prototype.hasOwnProperty.call(REPAIRS, code) ||
      Object.prototype.hasOwnProperty.call(KIND_SCOPED, code);
    if (!known) missing.push(code);
  }
  assert.deepStrictEqual(missing, [],
    `these refusal codes have no repair: ${missing.join(', ')}`);
});

test('C1b: refusalFix answers for every known code, with a non-empty repair', () => {
  for (const code of Object.keys(REPAIRS)) {
    const fix = refusalFix(code);
    assert.ok(typeof fix === 'string' && fix.trim().length > 0,
      `the repair for ${code} must not be empty`);
  }
  for (const code of Object.keys(KIND_SCOPED)) {
    for (const kind of Object.keys(KIND_SCOPED[code])) {
      const fix = refusalFix(code, { kind });
      assert.ok(typeof fix === 'string' && fix.trim().length > 0,
        `the ${kind} repair for ${code} must not be empty`);
    }
  }
});

test('C2: no code appears twice in the map', () => {
  // A duplicate key in an object literal is not an error in JS - the LAST
  // one wins, silently. The map is written as source text here so the
  // duplicate is DETECTED instead of silently resolved.
  const source = fs.readFileSync(path.join(ROOT, 'src', 'refusal-voice.js'), 'utf8');
  const body = source.slice(source.indexOf('const REPAIRS = {'), source.indexOf('};', source.indexOf('const REPAIRS = {')));
  const keys = [...body.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]);
  const seen = new Set();
  const dupes = [];
  for (const key of keys) {
    if (seen.has(key)) dupes.push(key);
    seen.add(key);
  }
  assert.deepStrictEqual(dupes, [], `duplicate keys in the repair map: ${dupes.join(', ')}`);
});

test('C3: every repair names only commands this CLI offers', () => {
  const all = [...Object.values(REPAIRS)];
  for (const scoped of Object.values(KIND_SCOPED)) all.push(...Object.values(scoped));
  for (const text of all) {
    const re = /signerd\s+([a-z][a-z-]*)/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      assert.ok(KNOWN_COMMANDS.includes(m[1]),
        `the repair names a command this CLI does not offer: signerd ${m[1]}`);
    }
  }
});

test('C4/C5: no repair carries a host path, and none is empty', () => {
  const all = [...Object.values(REPAIRS)];
  for (const scoped of Object.values(KIND_SCOPED)) all.push(...Object.values(scoped));
  for (const text of all) {
    assert.ok(!/\/home\/|\/Users\/|\/root\//.test(text),
      `a repair must not carry a host path: ${text}`);
    assert.ok(text.trim().length > 0, 'a repair must not be empty');
  }
});
