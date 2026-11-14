'use strict';

// PIN: the one-flag grant bootstrap must not write a scope that refuses the
// very body it was bootstrapped from.
//
// WHY (measured 2026-11-14, tools/measure-bootstrap-cap-lag.js, artifact
// research/bootstrap-cap-lag-2026-11-14.json): `sign-message --add-grant`
// reads issuer/type/subject/claimKeys out of the --body file and then
// hardcodes `maxBytes: '700'` - the README example's cap. The envelope's own
// hard cap is 3072 canonical bytes (src/policy-message.js
// MAX_MESSAGE_BYTES) and the policy's per-claim ceiling is 256 characters,
// so a body that is perfectly well-formed and far inside the envelope can
// still be LARGER than 700 canonical bytes.
//
// Measured: a body with two claims at the 256-char ceiling plus a 256-char
// note is 937 canonical bytes. The bootstrap wrote maxBytes 700 and the
// first sign of that body was refused `message_too_large`. The scope was
// created FOR that body and cannot sign it.
//
// The class is the same one the repo has closed twice before: a creation
// path that writes a value the product's own judge then refuses (the
// expired-expiry class of 2026-11-11, the uncanonical-pubkey class of
// 2026-11-11). Here the product's own creator is the one that cannot use
// its own file.
//
// WHAT THIS TEST CHECKS (no npm tarball needed - it drives the real CLI):
//   D1 the bootstrap writes a cap that COVERS the body it bootstraps from
//      (this is RED on the pre-fix tree);
//   G1 the cap never exceeds the envelope's hard ceiling (3072) - the
//      bootstrap may not widen the envelope;
//   G2 a small body keeps the documented 700 cap - the everyday default
//      does not silently widen;
//   G3 a body beyond the envelope's ceiling still gets a 3072 cap, and the
//      envelope itself refuses it (the ceiling is not moved by the fix);
//   G4 the bootstrap still pins issuer/type/subject/claimKeys from the body;
//   P1 the measurement artifact records the defect face.
//
// LADDER: D1 is RED on the pre-fix tree, GREEN after the fix; the guards are
// green on both trees.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const ARTIFACT = path.join(ROOT, 'research', 'bootstrap-cap-lag-v0.2.24-2026-11-14.json');
const FIXED = path.join(ROOT, 'research', 'bootstrap-cap-lag-fixed-2026-11-14.json');

const { canonicalReceiptBytes } = require(path.join(ROOT, 'src', 'receipt-identity'));
const { MAX_MESSAGE_BYTES } = require(path.join(ROOT, 'src', 'policy-message'));

function bootstrap(body) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-caplag-test-'));
  const keystore = path.join(work, 'ops.key');
  const pass = path.join(work, 'pass');
  const grants = path.join(work, 'grants.json');
  const socket = path.join(work, 's.sock');
  const bodyPath = path.join(work, 'body.json');
  fs.writeFileSync(pass, 'cap lag test\n', { mode: 0o600 });
  fs.writeFileSync(bodyPath, JSON.stringify(body, null, 2) + '\n');
  execFileSync(process.execPath, [CLI, 'keygen', '--keystore', keystore, '--passphrase-file', pass]);
  // The bootstrap writes the grant BEFORE the socket round trip, so the
  // connect failure afterwards is the harness's shape, not the measurement.
  try {
    execFileSync(process.execPath, [
      CLI, 'sign-message', '--socket', socket, '--grant', 'releases',
      '--body', bodyPath, '--add-grant', '--keystore', keystore, '--grants', grants,
      '--dry',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch { /* the socket does not exist yet; the grant file is already written */ }
  const grant = JSON.parse(fs.readFileSync(grants, 'utf8')).grants.releases;
  return { grant, work };
}

function bigBody() {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-15T21:00:00+00:00',
    claims: { a: 'x'.repeat(256), b: 'y'.repeat(256) },
    note: 'n'.repeat(256),
  };
}

function smallBody() {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-15T21:00:00+00:00',
    claims: { 'message-grant': 'live' },
  };
}

test('D1 the bootstrap writes a cap that covers the body it bootstraps from', () => {
  const body = bigBody();
  const canonical = canonicalReceiptBytes(body).length;
  assert.ok(canonical > 700, `the face needs a body above the old cap (${canonical})`);
  const { grant } = bootstrap(body);
  assert.ok(
    Number(grant.maxBytes) >= canonical,
    `maxBytes ${grant.maxBytes} must cover the body's ${canonical} canonical bytes`,
  );
});

test('G1 the bootstrap never writes a cap above the envelope ceiling', () => {
  const { grant } = bootstrap(bigBody());
  assert.ok(
    Number(grant.maxBytes) <= MAX_MESSAGE_BYTES,
    `maxBytes ${grant.maxBytes} must not exceed the envelope ceiling ${MAX_MESSAGE_BYTES}`,
  );
});

test('G2 a small body keeps the documented 700 cap', () => {
  const { grant } = bootstrap(smallBody());
  assert.strictEqual(grant.maxBytes, '700');
});

test('G3 a body beyond the envelope ceiling is capped at the ceiling, not beyond it', () => {
  const body = smallBody();
  body.note = 'n'.repeat(4000);
  const { grant } = bootstrap(body);
  assert.strictEqual(grant.maxBytes, String(MAX_MESSAGE_BYTES));
});

test('G4 the bootstrap still pins the body-derived fields', () => {
  const body = bigBody();
  const { grant } = bootstrap(body);
  assert.strictEqual(grant.issuer, body.issuer);
  assert.strictEqual(grant.type, body.type);
  assert.strictEqual(grant.subject, body.subject);
  assert.strictEqual(grant.claimKeys, 'a,b');
});

test('P1 the measurement artifacts record the defect face on the published tree and the fix on this one', () => {
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
  assert.strictEqual(artifact.verdict, 'grant-cap-lag');
  assert.strictEqual(artifact.face.firstSignError, 'message_too_large');
  assert.ok(artifact.face.bodyCanonicalBytes > Number(artifact.face.writtenMaxBytes));
  assert.strictEqual(artifact.face.writtenMaxBytes, '700');
  assert.strictEqual(artifact.face.withinEnvelopeCap, true);

  const fixed = JSON.parse(fs.readFileSync(FIXED, 'utf8'));
  assert.strictEqual(fixed.verdict, 'grant-cap-ok');
  assert.strictEqual(fixed.face.firstSignError, null);
  assert.strictEqual(fixed.firstSign.ok, true);
  assert.ok(Number(fixed.face.writtenMaxBytes) >= fixed.face.bodyCanonicalBytes);
});

test('P2 neither artifact leaks a host path', () => {
  for (const p of [ARTIFACT, FIXED]) {
    const text = fs.readFileSync(p, 'utf8');
    assert.ok(!text.includes('/home/'), `${p}: host path`);
    assert.ok(!text.includes('/tmp/signerd-caplag-'), `${p}: temp path`);
  }
});
