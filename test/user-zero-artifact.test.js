'use strict';

// THE USER-ZERO ARTIFACT IS THE EVIDENCE — AND IT MUST BE RE-DERIVABLE.
//
// WHY (2026-11-08, this repo): tools/measure-user-zero-d4-dry.js was written
// to run the card's required every-pulse falsifications against the PUBLISHED
// tag installed into an empty directory. Its first three runs failed for
// HARNESS reasons, not product reasons:
//   * the passphrase file was written 0664 -> the tool correctly refused it
//     and the daemon never started (a correct refusal read as a product fail);
//   * the daemon was SIGKILLed between cases -> the grant LEASE stayed held
//     and the next daemon refused to start;
//   * two sign calls omitted cwd -> "tx_missing" for a file that had just
//     been built successfully.
// Each surfaced as a red product case. The fix is a HARNESS gate (exit 3,
// verdict HARNESS-FAIL) that must not be confusable with a measured defect.
//
// THE CONTRACT:
//   U1 the committed artefact is `allPass` and every named case passes;
//   U2 the D4 verdicts are the ones the exit contract demands: a
//      failing --out with a retaining stdout is exit 3 WITH bytes on stdout;
//      two losing channels is exit 4 with none. Neither may be 0;
//   U3 the dry-run falsification is REAL: no signature, the journal does
//      not move for `--dry`, and the control real sign DOES move it — an
//      instrument that only checked "the CLI said ok" would pass a --dry
//      that actually signs;
//   U4 the artefact carries NO host path;
//   U5 FALSIFICATION: an artefact edited so that `allPass` claims true over
//      a failing case is caught by a DERIVED verdict, not the stored one;
//   U6 false-positive guard: the HARNESS-FAIL exit code (3) must not be
//      confused with a measured exit 3 (the D4 success verdict).

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

// THE GATE FOLLOWS THE PIN, NOT A FROZEN FILE NAME (measured 2026-11-10).
// The literal `user-zero-v0.2.12-2026-11-09.json` this line carried made
// the suite certify v0.2.12 while the README pin had moved to v0.2.13 —
// the pin-lag class, fourth face: the VERIFICATION RECORD lagging the
// shipped surface. `test/user-zero-pin-sync.test.js` (UZ2) forbids a
// literal tag name here; the artefact is resolved from the README's pin.
function pinnedTag() {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const tags = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((s) => s.split('#')[1]))];
  assert.strictEqual(tags.length, 1,
    `README must pin exactly one tag; found: ${tags.join(', ') || 'none'}`);
  return tags[0];
}

function resolveArtifact() {
  const pin = pinnedTag();
  const dir = path.join(ROOT, 'research');
  const names = fs.readdirSync(dir)
    .filter((n) => n.startsWith(`user-zero-${pin}-`) && /\.json$/.test(n))
    .sort();
  assert.ok(names.length > 0,
    `no user-zero artefact for the pinned tag ${pin} — run tools/measure-user-zero-d4-dry.js `+
    `against the pin before expecting this gate to pass`);
  const name = names[names.length - 1];
  const a = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
  assert.strictEqual(a.tag, pin, `${name} names ${a.tag} while the pin is ${pin}`);
  return { name, doc: a };
}

function load() {
  return resolveArtifact().doc;
}

/**
 * The verdict is DERIVED from the EVIDENCE, never read from the stored
 * `pass` field: a forged artefact can leave `pass: true` while its own
 * numbers say otherwise. Where a case carries its evidence, that evidence
 * decides; where it does not (the setup gates), the stored field is all
 * there is, and U6 pins those separately.
 */
function derivePass(name, v) {
  if (name === 'u3_d4_out_fails_stdout_retains') {
    return v.exit === 3 && v.stdoutBytes > 0 && v.journalGrew === true && v.outFileAbsent === true;
  }
  if (name === 'u4_d4_both_channels_lost') {
    return v.exit === 4 && v.stdoutBytes === 0 && v.journalGrew === true;
  }
  if (name === 'u5_dry_is_real') {
    return v.dryExit === 0 && v.dryHadSignature === false
      && v.journalAfterDry === v.journalBefore
      && v.journalAfterReal > v.journalBefore;
  }
  if (name === 'u1_install_from_empty_dir') {
    return v.installStatus === 0 && v.installedVersion === v.expectedVersion;
  }
  if (name === 'u2_delivery_fsycs_parent_dir') {
    return Array.isArray(v.events)
      && JSON.stringify(v.events) === JSON.stringify(['fsync(file)', 'rename', 'fsync(dir)']);
  }
  if (name === 'u0_setup') return v.keygenExit === 0 && v.grantExit === 0;
  if (name === 'u0b_daemon') return v.started === true;
  return v.pass === true;
}

function deriveAllPass(artifact) {
  return Object.entries(artifact.results).every(([name, v]) => derivePass(name, v) === true);
}

test('U1 the committed artefact passes every case, and its headline agrees with them', () => {
  const a = load();
  assert.strictEqual(a.allPass, true, 'the committed verdict is allPass');
  assert.strictEqual(a.allPass, deriveAllPass(a),
    'HEADLINE/EVIDENCE CONTRADICTION: allPass does not follow from the cases');
  const failing = Object.entries(a.results)
    .filter(([name, v]) => derivePass(name, v) !== true)
    .map(([n]) => n);
  assert.deepStrictEqual(failing, [], `every case must pass: ${failing.join(', ')}`);
});

test('U2 the D4 verdicts are the exit-contract ones (3 with bytes, 4 with none, never 0)', () => {
  const a = load();
  const u3 = a.results.u3_d4_out_fails_stdout_retains;
  assert.strictEqual(u3.exit, 3, '--out fails, stdout retains -> exit 3');
  assert.ok(u3.stdoutBytes > 0, 'exit 3 promises the artifact IS on stdout');
  assert.strictEqual(u3.journalGrew, true, 'the spend happened, so the journal must grow');
  assert.strictEqual(u3.outFileAbsent, true, 'the failed --out file must not exist');

  const u4 = a.results.u4_d4_both_channels_lost;
  assert.strictEqual(u4.exit, 4, 'both channels lose it -> exit 4, never 0 and never 3');
  assert.strictEqual(u4.stdoutBytes, 0, 'nothing was retained');
  assert.strictEqual(u4.journalGrew, true, 'the spend happened anyway');
  assert.notStrictEqual(u4.exit, 0, 'exit 0 would claim the artifact is delivered');

  // The two verdicts are opposite, so one gate cannot pass both by accident.
  assert.notStrictEqual(u3.exit, u4.exit, 'the two channel states must differ');
});

test('U3 the dry-run falsification is real: no signature, journal frozen, control grows it', () => {
  const a = load();
  const u5 = a.results.u5_dry_is_real;
  assert.strictEqual(u5.dryExit, 0, 'the dry run succeeds');
  assert.strictEqual(u5.dryHadSignature, false, '--dry must not produce a signature');
  assert.strictEqual(u5.journalAfterDry, u5.journalBefore,
    '--dry must not grow the journal (an allowed dry run leaves the machine untouched)');
  assert.ok(u5.journalAfterReal > u5.journalBefore,
    'the CONTROL real sign must grow the journal — otherwise the freeze proves nothing');
});

test('U4 the committed artefact carries no host path', () => {
  const text = fs.readFileSync(path.join(ROOT, 'research', resolveArtifact().name), 'utf8');
  assert.ok(!/\/home\//.test(text), 'no /home/ path');
  assert.ok(!/\/tmp\//.test(text), 'no /tmp/ path');
  assert.ok(!/\/Users\//.test(text), 'no /Users/ path');
  assert.ok(!/[A-Za-z]:\\\\/.test(text), 'no Windows path');
});

test('U5 FALSIFICATION: an artefact that claims allPass over a failing case is caught', () => {
  const a = load();

  // Forge the EVIDENCE while the stored headline and stored pass stay green.
  const forged = JSON.parse(JSON.stringify(a));
  forged.results.u3_d4_out_fails_stdout_retains.exit = 0; // the dangerous lie
  forged.allPass = true;
  forged.results.u3_d4_out_fails_stdout_retains.pass = true;

  assert.strictEqual(forged.allPass, true, 'the stored headline still claims success (that is the point)');
  assert.strictEqual(derivePass('u3_d4_out_fails_stdout_retains', forged.results.u3_d4_out_fails_stdout_retains), false,
    'the DERIVED verdict must reject exit 0 as a D4 success');
  assert.strictEqual(deriveAllPass(forged), false,
    'allPass must be rejected when a D4 case is exit 0');

  // ...and the same derivation accepts the real artefact.
  assert.strictEqual(deriveAllPass(a), true, 'the real artefact is consistent');
});

test('U6 false-positive guard: HARNESS-FAIL (exit 3) is not a measured exit 3', () => {
  // The instrument exits 3 for a broken harness and 1 for a measured defect.
  // A D4 measurement reports 3 as SUCCESS. They must stay distinguishable:
  // the artefact's own D4 case carries the number, the harness gate does not
  // exist in a committed artefact at all.
  const a = load();
  assert.strictEqual(a.verdict, undefined,
    'a committed artefact carries no HARNESS-FAIL verdict — that path exits before writing');
  assert.strictEqual(a.results.u0_setup.pass, true, 'setup gate passed');
  assert.strictEqual(a.results.u0b_daemon.pass, true, 'daemon gate passed');
  assert.strictEqual(a.results.u3_d4_out_fails_stdout_retains.exit, 3,
    '3 here is the measured success verdict, not the harness gate');
});
