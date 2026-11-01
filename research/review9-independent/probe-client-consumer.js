'use strict';

// Review #9 (independent), probe file 4: the CLIENT helper contract and the
// CONSUMER verifier asymmetry.
//
// Run: node research/review9-independent/probe-client-consumer.js

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { verdict } = require('./helper');
const { buildReceiptBody } = require('../../src/client');
const { evaluateMessage } = require('../../src/policy-message');
const { canonicalReceiptBytes } = require('../../src/receipt-identity');

const OPENRECEIPTS = path.resolve(__dirname, '..', '..', '..', 'openreceipts');
const PUBKEY = Buffer.alloc(32, 9).toString('base64');

function grant(overrides = {}) {
  return {
    kind: 'message', issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd',
    pubkey: PUBKEY, maxBytes: '700', expiresAt: '2030-01-01T00:00:00.000Z',
    windowMaxMessages: '5', windowSeconds: '3600', ...overrides,
  };
}

// H11: does buildReceiptBody produce a body the daemon accepts, WITHOUT an
// explicit issuedAt?
// EXPECTED (H11, pre-fix state as measured on 5770b59): refused='envelope'
// — the helper treated issued_at as opt-in while 84888d4 made it required;
// that was finding R9-2.
// EXPECTED (H11, after the R9-2 fix on this branch): the helper's own
// default output is now ACCEPTED (it stamps now, like receipt.py). The
// assertion below is the POST-fix invariant; the pre-fix measurement
// (refused='envelope') is kept in the R9-2 section of report.md.
{
  const b = buildReceiptBody({ issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', claims: { version: 'v1' } });
  const v = evaluateMessage(b, grant());
  verdict('H11: buildReceiptBody WITHOUT issuedAt builds an ACCEPTED body (R9-2 fixed)',
    v.allowed === true, `outcome=${v.allowed ? 'ALLOW' : 'refused=' + v.refused}`);

  // The pre-fix defect, still reproducible on 5770b59: a body WITHOUT an
  // issued_at key (what the old helper emitted) is refused. This half must
  // stay green on every tree — it pins the daemon side of R9-2.
  const noKey = { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', claims: { version: 'v1' } };
  const vNo = evaluateMessage(noKey, grant());
  verdict('H11b-strict: a body with NO issued_at key at all is refused (daemon side unchanged)',
    vNo.refused === 'envelope', `refused=${vNo.refused}`);

  const b2 = buildReceiptBody({ issuer: 'auroraxo', type: 'release',
    subject: 'auroraxo/signerd', claims: { version: 'v1' },
    issuedAt: '2026-11-01T00:00:00+00:00' });
  const v2 = evaluateMessage(b2, grant());
  verdict('H11b: buildReceiptBody WITH issuedAt is accepted',
    v2.allowed === true, `outcome=${v2.allowed ? 'ALLOW' : v2.refused}`);
}

// ---- the consumer asymmetry (H12): what do the verifiers accept that the
// daemon refuses, and what do they do with artifacts the daemon can no
// longer mint? ----

function writeReceipt(dir, name, bodyObj, pubB64, sigB64) {
  const ordered = {};
  for (const key of Object.keys(bodyObj).sort()) ordered[key] = bodyObj[key];
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify({
    schema: 'openreceipts/v1', receipt: ordered, pubkey: pubB64, sig: sigB64,
  }, null, 2));
  return file;
}

/** Sign arbitrary bytes with a THROWAWAY local key (no repo key, no daemon). */
function localSigner() {
  const { generateKeyPairSync, sign: edSign } = require('node:crypto');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const pubB64 = Buffer.from(jwk.x, 'base64url').toString('base64');
  return {
    pubB64,
    sign: (bytes) => edSign(null, bytes, privateKey),
  };
}

function runVerifiers(file, pinnedFile) {
  const out = {};
  const py = spawnSync('python3', [path.join(OPENRECEIPTS, 'receipt.py'), 'verify', file,
    ...(pinnedFile ? ['--key', pinnedFile] : [])], { encoding: 'utf8' });
  out.pyExit = py.status;
  out.pyOut = (py.stdout || '').trim().split('\n')[0] || '';
  out.pyErr = (py.stderr || '').trim().split('\n').slice(-1)[0] || '';
  const js = spawnSync('node', [path.join(OPENRECEIPTS, 'verify.mjs'), file,
    ...(pinnedFile ? ['--key', pinnedFile] : [])], { encoding: 'utf8' });
  out.jsExit = js.status;
  out.jsOut = (js.stdout || '').trim().split('\n')[0] || '';
  out.jsErr = (js.stderr || '').trim().split('\n').slice(-1)[0] || '';
  return out;
}

// The daemon's OWN body builders for these attack bodies (policy verdicts).
function daemonVerdict(b) {
  const v = evaluateMessage(b, grant());
  return v.allowed ? 'ALLOW' : `refuse:${v.refused}`;
}

{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review9-consumer-'));
  try {
    const { pubB64, sign } = localSigner();
    const pinned = path.join(dir, 'pinned.pub');
    fs.writeFileSync(pinned, pubB64 + '\n', { mode: 0o600 });

    // The classes the daemon refuses (or refused before 84888d4); the
    // question is what the verifiers do with the same artifacts.
    const attacks = [
      ['no_issued_at', { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', claims: { version: 'v1' } }],
      ['feb30', { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', issued_at: '2026-02-30T00:00:00+00:00',
        claims: { version: 'v1' } }],
      ['offset99', { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', issued_at: '2026-11-01T00:00:00+99:99',
        claims: { version: 'v1' } }],
      ['year3000', { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', issued_at: '3000-01-01T00:00:00+00:00',
        claims: { version: 'v1' } }],
      ['garbage_issued_at', { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', issued_at: 'not-a-date',
        claims: { version: 'v1' } }],
      ['far_past', { schema: 'openreceipts/v1', issuer: 'auroraxo', type: 'release',
        subject: 'auroraxo/signerd', issued_at: '1900-01-01T00:00:00+00:00',
        claims: { version: 'v1' } }],
    ];
    console.log('body'.padEnd(20), 'daemon verdict'.padEnd(24), 'receipt.py', 'verify.mjs');
    for (const [name, b] of attacks) {
      const file = writeReceipt(dir, `${name}.json`, b, pubB64, sign(canonicalReceiptBytes(b)).toString('base64'));
      const r = runVerifiers(file, pinned);
      console.log(name.padEnd(20), daemonVerdict(b).padEnd(24),
        `${r.pyExit}`.padEnd(10), `${r.jsExit}`);
      if (name === 'no_issued_at') {
        verdict('H12: receipt.py CRASHES on a no-issued_at artifact (KeyError), verify.mjs exits 0 printing "issued undefined"',
          r.pyExit === 1 && r.jsExit === 0, `py: ${r.pyErr || r.pyOut} | js: ${r.jsOut}`);
      }
      if (name === 'feb30') {
        verdict('H12b: receipt.py prints OK on the impossible calendar date (cannot detect the class the daemon now refuses)',
          r.pyExit === 0 && /OK/.test(r.pyOut), `${r.pyOut}`);
      }
      if (name === 'year3000') {
        verdict('H12c: verifiers accept a 3000-dated receipt the daemon refuses (verifier places no bound; asymmetry by design)',
          r.pyExit === 0 && r.jsExit === 0, `py=${r.pyExit} js=${r.jsExit}`);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// H12d: the feed ordering class (feed.py sorts by the issued_at STRING).
// The claim under test: a LEXICOGRAPHIC sort of RFC3339 strings with
// differing offsets does NOT yield chronological order, so two receipts can
// be ordered the wrong way round in the feed.
// EXPECTED: the defect EXISTS for a pair where the offset flips the order —
// A = '2027-01-01T00:30:00+05:30' (= 2026-12-31T19:00Z, string-wise LATER)
// B = '2026-12-31T23:00:00+00:00' (= 2026-12-31T23:00Z, actually LATER):
// feed.py's descending string sort puts A first although B is newer.
// NOTE (probe bug, found and fixed): the first pair (+05:30 with only a
// 30-minute nominal difference) made BOTH orders coincide, so the probe
// reported VIOLATION for a pair that does not demonstrate the defect. The
// pair below is chosen so the two orders necessarily differ.
{
  const A = '2027-01-01T00:30:00+05:30'; // 2026-12-31T19:00:00Z
  const B = '2026-12-31T23:00:00+00:00'; // 2026-12-31T23:00:00Z (4h LATER)
  const stringDesc = A > B ? [A, B] : [B, A]; // feed.py: reverse lexicographic
  const chronoDesc = Date.parse(A) > Date.parse(B) ? [A, B] : [B, A];
  const wrong = stringDesc.join('|') !== chronoDesc.join('|');
  verdict('H12d: feed-style string sort mis-orders two receipts whose offsets differ (consumer-side ordering defect)',
    wrong,
    `string-desc: ${stringDesc[0]} first | chrono-desc: ${chronoDesc[0]} first (B is 4h later)`);
}

console.log('probe-client-consumer done.');
