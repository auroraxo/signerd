// Falsification harness for tools/envelope-fit.mjs itself: the measurement
// tool must be able to say NO.
//
// Runs the real tool as a subprocess against generated fixtures (never the
// operator's key) and asserts:
//   - a receipts dir where every receipt is signed by the site key reports
//     "all published receipts verify under the site-derived key";
//   - adding ONE receipt signed by a different key flips the status to
//     FAILED and names the offending file (a tool that always passes is
//     worthless);
//   - a pinned key that is not the site key reports siteMatchesPinned=false;
//   - the verdict stays fitsV0Envelope=false in both runs (the message-domain
//     conclusion must not depend on the identity outcome).

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { canonicalReceiptBytes } = require('../src/receipt-identity.js');

const tool = path.join(__dirname, '..', 'tools', 'envelope-fit.mjs');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-envelope-tool-'));
}

function receiptFor(privateKey, body) {
  const sig = crypto.sign(null, canonicalReceiptBytes(body), privateKey);
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return {
    receipt: body,
    pubkey: spki.subarray(spki.length - 32).toString('base64'),
    sig: sig.toString('base64'),
  };
}

function baseBody(subject) {
  return {
    claims: { tool: 'envelope-fit', version: 'v1' },
    issued_at: '2026-10-29T00:00:00+00:00',
    issuer: 'auroraxo',
    schema: 'openreceipts/v1',
    subject,
    type: 'release',
  };
}

function runTool(dir, outName) {
  const out = path.join(dir, outName);
  execFileSync(process.execPath, [
    tool,
    '--site', path.join(dir, 'site.pem'),
    '--pinned', path.join(dir, 'auroraxo.pub'),
    '--receipts', path.join(dir, 'receipts'),
    '--out', out,
  ], { stdio: ['ignore', 'pipe', 'inherit'] });
  return JSON.parse(fs.readFileSync(out, 'utf8'));
}

test('envelope-fit tool reports identity pass for own receipts and FAILED for a foreign one', () => {
  const dir = tmpDir();
  try {
    // Site key as openreceipts stores it: PKCS8 PEM, mode 600.
    const site = crypto.generateKeyPairSync('ed25519');
    const pem = site.privateKey.export({ type: 'pkcs8', format: 'pem' });
    fs.writeFileSync(path.join(dir, 'site.pem'), pem, { mode: 0o600 });
    const raw = crypto.createPublicKey(site.privateKey)
      .export({ type: 'spki', format: 'der' })
      .subarray(-32);
    fs.writeFileSync(path.join(dir, 'auroraxo.pub'), raw.toString('base64') + '\n');

    const receipts = path.join(dir, 'receipts');
    fs.mkdirSync(receipts);
    fs.writeFileSync(
      path.join(receipts, 'docrot-check-v1.json'),
      JSON.stringify(receiptFor(site.privateKey, baseBody('auroraxo/docrot-check')), null, 2) + '\n',
    );

    // Run 1: every receipt signed by the site key -> identity passes.
    const pass = runTool(dir, 'out-pass.json');
    assert.equal(pass.questions.publishedIdentity.siteMatchesPinned, true);
    assert.equal(pass.questions.publishedIdentity.receiptsTotal, 1);
    assert.equal(pass.questions.publishedIdentity.receiptsVerifiedWithSiteKey, 1);
    assert.equal(
      pass.questions.publishedIdentity.status,
      'all published receipts verify under the site-derived key',
    );
    assert.equal(pass.questions.fileFormat.verdict, 'refused: secret_key_invalid');
    assert.equal(pass.questions.operation.controlTransfer, 'allowed (instrument works)');
    assert.equal(pass.questions.operation.receiptBody, 'refused: invalid_wire');
    assert.equal(pass.verdict.fitsV0Envelope, false);
    assert.equal(pass.tmpCleaned, true);

    // Run 2: one receipt signed by a stranger -> the tool must say FAILED.
    const stranger = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(
      path.join(receipts, 'z-stranger.json'),
      JSON.stringify(receiptFor(stranger.privateKey, baseBody('auroraxo/stranger')), null, 2) + '\n',
    );
    const fail = runTool(dir, 'out-fail.json');
    assert.equal(fail.questions.publishedIdentity.status, 'FAILED — see failures');
    assert.equal(fail.questions.publishedIdentity.receiptsVerifiedWithSiteKey, 1);
    assert.ok(
      fail.questions.publishedIdentity.failures.some((f) => f.startsWith('z-stranger.json:')),
      'the offending receipt must be named',
    );
    // The message-domain conclusion must not change with the identity outcome.
    assert.equal(fail.verdict.fitsV0Envelope, false);

    // Run 3: pinned key not the site key -> siteMatchesPinned must be false.
    fs.unlinkSync(path.join(receipts, 'z-stranger.json'));
    const strangerRaw = crypto.createPublicKey(stranger.privateKey)
      .export({ type: 'spki', format: 'der' })
      .subarray(-32);
    fs.writeFileSync(path.join(dir, 'auroraxo.pub'), strangerRaw.toString('base64') + '\n');
    const wrongPin = runTool(dir, 'out-wrong-pin.json');
    assert.equal(wrongPin.questions.publishedIdentity.siteMatchesPinned, false);
    // Receipts still verify (they are signed by the site key); only the pin is wrong.
    assert.equal(wrongPin.questions.publishedIdentity.receiptsVerifiedWithSiteKey, 1);
    assert.ok(
      wrongPin.questions.publishedIdentity.failures.some((f) => f.includes('embedded pubkey != pinned key')),
      'a receipt whose embedded key differs from the pinned key must be named',
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
