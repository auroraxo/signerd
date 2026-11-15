'use strict';

// PIN: the one-flag message bootstrap must not write a scope for a body the
// product's own envelope judge refuses.
//
// WHY (measured 2026-11-15, tools/measure-bootstrap-body-judge.js, artifact
// research/bootstrap-body-judge-v0.2.25-2026-11-15.json): `sign-message
// --add-grant` reads issuer/type/subject/claimKeys out of the --body file
// and writes a scope from them, but it never asks the ENVELOPE whether that
// body would be signed at all. The cap-lag fix (16bea8e, 2026-11-14) made
// maxBytes cover the body; the SHAPE of the body was still unjudged.
//
// Measured on the published v0.2.25 tree (6ab3718): of ten body faces, the
// bootstrap reported {"ok":true,...,"bootstrapped":true} and wrote a grant
// for seven of them - and the FIRST sign of the very same body was refused:
//   missing issued_at                        -> envelope
//   a claim value of 257 characters          -> claims
//   33 claims (the ceiling is 32)            -> claims
//   an unknown top-level key                 -> envelope
//   claims that are not an object            -> claims
//   issued_at more than 24h in the future    -> issued_at_in_future
//   a schema other than openreceipts/v1      -> invalid_schema
// The scope was created FOR that body and could not sign it - the same class
// as the expired-expiry (2026-11-11), the uncanonical-pubkey (2026-11-11)
// and the cap-lag (2026-11-14) defects: a creation path writes a value the
// product's own judge then refuses.
//
// WHAT THIS TEST CHECKS (no npm tarball needed - it drives the real CLI):
//   D1-D6 the bootstrap REFUSES each of those bodies, names the envelope's
//        own reason, and writes NO grant file;
//   G1 a well-formed body still bootstraps (the documented quickstart);
//   G2 a body over the envelope's CEILING still gets a 3072 cap - the size
//        cap is the bootstrap's own value, the envelope's ceiling is not
//        moved, and the scope stays usable for a smaller body;
//   G3 a refusal leaves an EXISTING grant file byte-identical;
//   P1 the measurement artifact records the defect face on the published
//        tree and the refusal on the fixed one.
//
// LADDER: D1-D6 are RED on the pre-fix tree, GREEN after the fix; the guards
// are green on BOTH trees.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const ARTIFACT = path.join(ROOT, 'research', 'bootstrap-body-judge-v0.2.25-2026-11-15.json');
const FIXED = path.join(ROOT, 'research', 'bootstrap-body-judge-fixed-2026-11-15.json');

const { MAX_MESSAGE_BYTES } = require(path.join(ROOT, 'src', 'policy-message'));

function run(args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    return {
      status: err.status === undefined ? null : err.status,
      stdout: String(err.stdout || ''),
      stderr: String(err.stderr || ''),
    };
  }
}

function keygen(work) {
  const keystore = path.join(work, 'ops.key');
  const pass = path.join(work, 'pass');
  fs.writeFileSync(pass, 'body judge ladder\n', { mode: 0o600 });
  const r = run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);
  assert.strictEqual(r.status, 0, `keygen failed: ${r.stderr}`);
  return { keystore, pass };
}

/** Write a body file and run the one-flag bootstrap against it. */
function bootstrap(work, body, { grant = 'releases' } = {}) {
  const bodyPath = path.join(work, 'body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(body, null, 2) + '\n');
  const grants = path.join(work, 'grants.json');
  const { keystore } = keygen(work);
  const r = run([
    'sign-message', '--socket', path.join(work, 'none.sock'), '--grant', grant,
    '--body', bodyPath, '--add-grant', '--keystore', keystore, '--grants', grants,
    '--dry',
  ]);
  const written = fs.existsSync(grants)
    ? (JSON.parse(fs.readFileSync(grants, 'utf8')).grants || {})[grant]
    : undefined;
  return { r, grants, bodyPath, written, log: `${r.stdout}\n${r.stderr}` };
}

function goodBody() {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-15T21:00:00+00:00',
    claims: { 'message-grant': 'live' },
  };
}

// The six body faces the ENVELOPE refuses for good reasons. Each one is a
// body that can never be signed - not by this scope, not by any scope.
const FACES = [
  ['D1', 'missing issued_at', (b) => { delete b.issued_at; }, 'envelope'],
  ['D2', 'a claim value of 257 characters', (b) => { b.claims.big = 'x'.repeat(257); }, 'claims'],
  ['D3', '33 claims (the ceiling is 32)', (b) => {
    b.claims = {};
    for (let i = 0; i < 33; i += 1) b.claims[`c${i}`] = 'v';
  }, 'claims'],
  ['D4', 'an unknown top-level key', (b) => { b.extra = 'nope'; }, 'envelope'],
  ['D5', 'claims that are not an object', (b) => { b.claims = 'not-a-map'; }, 'claims'],
  ['D6', 'a schema other than openreceipts/v1', (b) => { b.schema = 'openreceipts/v2'; }, 'invalid_schema'],
];

for (const [id, what, mutate, reason] of FACES) {
  test(`${id} the bootstrap refuses a body with ${what} and writes no grant`, () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-bodyjudge-'));
    const body = goodBody();
    mutate(body);
    const { r, grants, written, log } = bootstrap(work, body);
    assert.notStrictEqual(r.status, 0,
      `the bootstrap must refuse a body the envelope refuses: ${log}`);
    assert.match(r.stderr, new RegExp(reason),
      `the refusal must carry the envelope's own reason (${reason}): ${log}`);
    assert.doesNotMatch(log, /"bootstrapped":true/,
      'no success verdict for a body the product refuses');
    assert.strictEqual(written, undefined, 'no grant may be written for a refused body');
    assert.strictEqual(fs.existsSync(grants), false,
      'the grant file must not exist after a refused bootstrap');
  });
}

test('G1 GUARD: a well-formed body still bootstraps (the documented quickstart)', () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-bodyjudge-ok-'));
  const { r, written, log } = bootstrap(work, goodBody());
  assert.match(log, /"bootstrapped":true/, `the quickstart must still work: ${log}`);
  assert.ok(written, 'the grant must be written');
  assert.strictEqual(written.kind, 'message');
  assert.strictEqual(written.issuer, 'auroraxo');
  assert.strictEqual(written.subject, 'auroraxo/signerd');
  assert.strictEqual(written.claimKeys, 'message-grant');
  assert.strictEqual(written.maxBytes, '700');
});

test('G2 GUARD: a body over the envelope CEILING still gets a 3072 cap', () => {
  // The size cap is the bootstrap's OWN value (maxBytes covers the body and
  // is clamped to the envelope's ceiling). A body beyond the ceiling keeps
  // the documented behaviour: the scope is written, capped at the ceiling,
  // and the ENVELOPE refuses the body at sign time. The ceiling is not
  // moved by the fix.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-bodyjudge-big-'));
  const body = goodBody();
  body.note = 'n'.repeat(4000);
  const { r, written, log } = bootstrap(work, body);
  assert.match(log, /"bootstrapped":true/, `the size cap stays the bootstrap's own: ${log}`);
  assert.ok(written, 'the scope is still written');
  assert.strictEqual(written.maxBytes, String(MAX_MESSAGE_BYTES));
  assert.strictEqual(r.status === 0 || r.status === 1, true);
});

test('G3 GUARD: a refused bootstrap leaves an EXISTING grant file byte-identical', () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-bodyjudge-keep-'));
  const { keystore } = keygen(work);
  const grants = path.join(work, 'grants.json');
  const add = run([
    'grant-add', '--grants', grants, '--name', 'ops-24h', '--keystore', keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z',
  ]);
  assert.strictEqual(add.status, 0, `grant-add setup failed: ${add.stderr}`);
  const before = fs.readFileSync(grants, 'utf8');

  const body = goodBody();
  delete body.issued_at;
  const bodyPath = path.join(work, 'body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(body, null, 2) + '\n');
  const r = run([
    'sign-message', '--socket', path.join(work, 'none.sock'), '--grant', 'releases',
    '--body', bodyPath, '--add-grant', '--keystore', keystore, '--grants', grants, '--dry',
  ]);
  assert.notStrictEqual(r.status, 0, 'the bootstrap must refuse');
  assert.strictEqual(fs.readFileSync(grants, 'utf8'), before,
    'the refused bootstrap must not have changed the file');
});

test('P1 the measurement artifacts record the defect face on the published tree and the refusal on the fixed one', () => {
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
  assert.strictEqual(artifact.verdict, 'bootstrap-body-not-judged');
  assert.ok(artifact.defectCount >= 6,
    `the published tree must show at least six defect faces (got ${artifact.defectCount})`);
  const published = artifact.cases.filter((c) => c.defect);
  for (const c of published) {
    assert.strictEqual(c.bootstrap.bootstrapped, true,
      `${c.case}: the published tree must report a success verdict`);
    assert.strictEqual(c.grantWritten, true,
      `${c.case}: the published tree must write the scope`);
    assert.strictEqual(c.firstSign.ok, false,
      `${c.case}: the first sign of that body must be refused`);
    assert.ok(c.firstSign.error, `${c.case}: the refusal must name a reason`);
  }

  const fixed = JSON.parse(fs.readFileSync(FIXED, 'utf8'));
  assert.strictEqual(fixed.verdict, 'bootstrap-body-judged');
  assert.strictEqual(fixed.defectCount, 0, 'the fixed tree must show no defect face');
  for (const c of fixed.cases) {
    if (!c.defectFace) continue;
    assert.strictEqual(c.bootstrap.ok, false,
      `${c.case}: the fixed tree must refuse the body`);
    assert.strictEqual(c.grantWritten, false,
      `${c.case}: the fixed tree must write no scope`);
  }
});

test('P2 neither artifact leaks a host path', () => {
  for (const p of [ARTIFACT, FIXED]) {
    const text = fs.readFileSync(p, 'utf8');
    assert.ok(!text.includes('/home/'), `${p}: host path`);
    assert.ok(!text.includes('/tmp/signerd-'), `${p}: temp path`);
  }
});
