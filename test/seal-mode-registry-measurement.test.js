'use strict';
// PIN: the FIX reached the channel a stranger uses.
//
// The seal-mode fix lives in src/grantfile.js. Measuring it on this tree
// proves the CODE changed; measuring it on `npm install signerd` proves the
// stranger got the change (a release whose tarball lags its tree is the
// registry-contradiction class this repo keeps finding).
//
//   P1 the registry artifact parses and names its schema/channel;
//   P2 verdict registry-seal-mode-holds, no failure, versions agree with
//      the README pin;
//   P3 the four refusals hold on the INSTALLED copy: the keyless read is
//      refused by name (and never hands back the tampered destination),
//      `status` exits non-zero without an ok:true, the daemon refuses to
//      start;
//   P4 the guards hold on the INSTALLED copy: the documented re-seal
//      repair still works, the keyed read still refuses a tampered file,
//      an unsealed file still loads;
//   P5 the git-tag user-zero artifact for this pin exists, is allPass, and
//      carries no host path.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const RESEARCH = path.join(ROOT, 'research');
const REGISTRY = path.join(RESEARCH, 'seal-mode-registry-0.2.28-2026-11-16.json');
const USER_ZERO = path.join(RESEARCH, 'user-zero-v0.2.28-2026-11-16.json');

function registry() {
  return JSON.parse(fs.readFileSync(REGISTRY, 'utf8'));
}

function pin() {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const tags = [...new Set((readme.match(/github:auroraxo\/signerd#(v\d+\.\d+\.\d+)/g) || [])
    .map((t) => t.split('#')[1]))];
  assert.strictEqual(tags.length, 1, `README pin is not exactly one tag: ${tags.join(', ')}`);
  return tags[0].replace(/^v/, '');
}

test('P1 the registry artifact parses and names its channel', () => {
  const r = registry();
  assert.strictEqual(r.tool, 'seal-mode on the registry channel (npm install signerd)');
  assert.match(r.channel, /npm install signerd/);
  assert.strictEqual(r.installExit, 0);
});

test('P2 the verdict holds with no failure and the versions agree with the pin', () => {
  const r = registry();
  assert.strictEqual(r.verdict, 'registry-seal-mode-holds');
  assert.deepStrictEqual(r.failures, []);
  assert.strictEqual(r.expectedVersion, pin());
  assert.strictEqual(r.packageVersion, pin(),
    'the registry must have served the version the README pins');
});

test('P3 the four refusals hold on the INSTALLED copy', () => {
  const r = registry().results;
  const s1 = r.S1_keyless_read_refused;
  assert.strictEqual(s1.sealedExit, 0, 'the fixture must seal (test premise)');
  assert.strictEqual(s1.loaded, false, 'the installed loader must refuse a sealed file');
  assert.strictEqual(s1.code, 'grant_file_sealed');
  assert.strictEqual(s1.readTampered, false,
    'the tampered destination must never reach a keyless caller');

  const s2 = r.S2_status_refused;
  assert.notStrictEqual(s2.exit, 0, 'status must refuse');
  assert.strictEqual(s2.named, true, 'the refusal must carry the reason');
  assert.strictEqual(s2.reportedOk, false, 'never {"ok":true,...} for an unverified file');
  assert.strictEqual(s2.reportedUnsealed, false);

  const s3 = r.S3_daemon_refused;
  assert.notStrictEqual(s3.exit, 0, 'the daemon must refuse to start');
  assert.strictEqual(s3.named, true);
  assert.strictEqual(s3.reportedServing, false);
});

test('P4 the guards hold on the INSTALLED copy', () => {
  const r = registry().results;
  const s4 = r.S4_reseal_still_works;
  assert.strictEqual(s4.resealExit, 0, 'the documented re-seal repair must keep working');
  assert.strictEqual(s4.verifyExit, 0, 'the new seal must verify');

  const s5 = r.S5_keyed_read_still_refuses;
  assert.notStrictEqual(s5.exit, 0, 'the keyed read must still refuse tampered content');
  assert.strictEqual(s5.named, true);

  const g1 = r.G1_unsealed_still_loads;
  assert.strictEqual(g1.loaded, true, 'an unsealed file must still load keylessly');
  assert.ok(g1.destination && g1.destination.startsWith('So11'),
    'the unsealed grant must still come back');
  assert.strictEqual(g1.statusExit, 0);
});

test('P5 the git-tag user-zero artifact for this pin is allPass and host-path free', () => {
  assert.ok(fs.existsSync(USER_ZERO),
    `no user-zero artefact for the pinned tag ${pin()} - run tools/measure-user-zero-d4-dry.js`);
  const raw = fs.readFileSync(USER_ZERO, 'utf8');
  const uz = JSON.parse(raw);
  assert.strictEqual(uz.tag, `v${pin()}`);
  assert.strictEqual(uz.allPass, true, JSON.stringify(uz.results, null, 1).slice(0, 800));
  assert.ok(!/\/home\/[a-z0-9_-]+/.test(raw), 'no host user path in the artefact');
  assert.ok(!/\/tmp\/signerd-uz-/.test(raw), 'no scratch directory in the artefact');
});
