'use strict';

// The message-grant envelope (2026-10-31): policy for signing an
// openreceipts/v1 receipt BODY instead of a Solana transaction wire.
//
// Regression tests written against the pre-envelope tree, where
// src/policy-message.js does not exist: every test in the first section
// FAILS on the pre-fix tree (require throws) and must pass on the fix. The
// false-positive guards at the bottom pin the transaction path's refusal of
// receipt bytes and pass on BOTH trees.

process.umask(0o077);

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const test = require('node:test');
const { Keypair } = require('@solana/web3.js');

const { evaluateMessage, MAX_MESSAGE_BYTES } = require('../src/policy-message');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-message-policy-'));
}

function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function pastIso(hours = 1) {
  return new Date(Math.floor(Date.now() / 1000 - hours * 3600) * 1000).toISOString();
}

const PUBKEY = Buffer.alloc(32, 9).toString('base64'); // 44 chars, '='-padded

function grant(overrides = {}) {
  return {
    kind: 'message',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    pubkey: PUBKEY,
    maxBytes: '700',
    expiresAt: futureIso(),
    windowMaxMessages: '5',
    windowSeconds: '60',
    ...overrides,
  };
}

function body(overrides = {}, drop = []) {
  const b = {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    claims: { version: 'v0.1.0' },
    issued_at: '2026-10-31T12:00:00+00:00',
    ...overrides,
  };
  for (const key of drop) delete b[key];
  return b;
}

test('message grant: the happy path canonicalizes and hashes deterministically', () => {
  const a = evaluateMessage(body(), grant());
  const b = evaluateMessage(body(), grant());
  assert.equal(a.allowed, true);
  assert.equal(b.allowed, true);
  assert.ok(Buffer.isBuffer(a.messageBytes));
  // Key order in the textual spelling must not change the canonical bytes.
  const reordered = JSON.parse('{"claims":{"version":"v0.1.0"},"issuer":"auroraxo","schema":"openreceipts/v1","subject":"auroraxo/signerd","type":"release","issued_at":"2026-10-31T12:00:00+00:00"}');
  const c = evaluateMessage(reordered, grant());
  assert.equal(c.allowed, true);
  assert.equal(a.messageSha256, c.messageSha256);
  // The canonical bytes match the openreceipts reference canonicalization:
  // sort_keys + separators + ensure_ascii.
  assert.equal(
    a.messageBytes.toString('utf8'),
    '{"claims":{"version":"v0.1.0"},"issued_at":"2026-10-31T12:00:00+00:00","issuer":"auroraxo","schema":"openreceipts/v1","subject":"auroraxo/signerd","type":"release"}',
  );
});

test('message grant: any value change is a different message', () => {
  const a = evaluateMessage(body(), grant()).messageSha256;
  const b = evaluateMessage(body({ claims: { version: 'v0.2.0' } }), grant()).messageSha256;
  assert.notEqual(a, b);
});

test('message grant: issuer, type and subject are pinned by the grant', () => {
  assert.equal(evaluateMessage(body({ issuer: 'someoneelse' }), grant()).refused, 'issuer');
  assert.equal(evaluateMessage(body({ type: 'scan' }), grant()).refused, 'type');
  assert.equal(evaluateMessage(body({ subject: 'auroraxo/other' }), grant()).refused, 'subject');
  // A missing pinned field is an envelope refusal, not a crash.
  assert.equal(evaluateMessage(body({}, ['issuer']), grant()).refused, 'envelope');
});

test('message grant: wrong schema and unknown top-level keys are refused', () => {
  assert.equal(evaluateMessage(body({ schema: 'openreceipts/v2' }), grant()).refused, 'invalid_schema');
  assert.equal(
    evaluateMessage(body({ extra: 'x' }), grant()).refused,
    'envelope',
    'an unknown top-level key must be refused, not signed',
  );
});

test('message grant: claims are bounded and optional claim keys are enforced', () => {
  const many = {};
  for (let i = 0; i < 33; i += 1) many[`k${i}`] = 'v';
  assert.equal(evaluateMessage(body({ claims: many }), grant()).refused, 'claims');
  assert.equal(evaluateMessage(body({ claims: { 'bad key': 'v' } }), grant()).refused, 'claims');
  assert.equal(evaluateMessage(body({ claims: { k: 42 } }), grant()).refused, 'claims');
  // The allowlist: claimKeys pins exactly which claim keys may be signed.
  const pinned = grant({ claimKeys: 'version,build' });
  assert.equal(evaluateMessage(body(), pinned).allowed, true);
  assert.equal(evaluateMessage(body({ claims: { other: 'v' } }), pinned).refused, 'claims');
  assert.equal(evaluateMessage(
    body({ claims: { version: 'v1', build: '42' } }), pinned,
  ).allowed, true);
  // An invalid claimKeys value in the grant cannot widen anything: the key
  // regex rejects it, making the allowlist EMPTY (refuse everything).
  const broken = grant({ claimKeys: 'version,has space' });
  assert.equal(evaluateMessage(body(), broken).refused, 'claims');
});

test('message grant: note and issued_at are bounded', () => {
  assert.equal(evaluateMessage(body({ note: 'x'.repeat(257) }), grant()).refused, 'envelope');
  assert.equal(evaluateMessage(body({ note: 'ok' }), grant()).allowed, true);
  assert.equal(
    evaluateMessage(body({ issued_at: 'not-a-date' }), grant()).refused,
    'envelope',
  );
  // openreceipts' real format (+00:00 offset) and Z both pass.
  assert.equal(evaluateMessage(body({ issued_at: '2026-10-31T12:00:00Z' }), grant()).allowed, true);
});

test('message grant: size cap and expiry are enforced with hardened reads', () => {
  const big = body({ claims: { pad: 'x'.repeat(800) } });
  const verdict = evaluateMessage(big, grant());
  assert.equal(verdict.refused, 'message_too_large');
  assert.equal(evaluateMessage(body(), grant({ expiresAt: pastIso() })).refused, 'expired');
  // A non-canonical expiry (February 30 normalizes) must be an invalid grant.
  assert.equal(evaluateMessage(body(), grant({ expiresAt: '2026-02-30T12:00:00Z' })).refused, 'invalid_grant');
  // A hostile clock (Date subclass) is refused, never believed. The clock is
  // the THIRD argument — passing it as a grant override (the first draft's
  // bug) spreads a Date into {} and silently tests nothing.
  class Liar extends Date { getTime() { return 0; } }
  assert.equal(evaluateMessage(body(), grant(), new Liar()).refused, 'invalid_clock');
  // A grant can never widen the envelope's hard cap.
  const greedy = grant({ maxBytes: String(MAX_MESSAGE_BYTES + 1) });
  assert.equal(evaluateMessage(body(), greedy).refused, 'invalid_grant');
});

test('message grant: malformed bodies never throw', () => {
  assert.equal(evaluateMessage(null, grant()).refused, 'invalid_body');
  assert.equal(evaluateMessage('text', grant()).refused, 'invalid_body');
  assert.equal(evaluateMessage([1, 2], grant()).refused, 'invalid_body');
  assert.equal(evaluateMessage(body(), null).refused, 'invalid_grant');
  assert.equal(evaluateMessage(body(), { kind: 'message' }).refused, 'invalid_grant');
  // Prototype pollution: no inherited field can supply issuer or claims.
  const polluted = Object.create({ issuer: 'auroraxo', type: 'release', subject: 'auroraxo/signerd', claims: {}, schema: 'openreceipts/v1' });
  polluted.schema = 'openreceipts/v1';
  assert.equal(evaluateMessage(polluted, grant()).refused, 'envelope');
});

test('message grant: the pubkey binding lives in the grant, as base64', () => {
  // A grant whose pubkey is not the 32-byte base64 shape is an invalid grant.
  assert.equal(evaluateMessage(body(), grant({ pubkey: 'not-base64' })).refused, 'invalid_grant');
  assert.equal(evaluateMessage(body(), grant({ pubkey: Buffer.alloc(31, 1).toString('base64') })).refused, 'invalid_grant');
});

// ---- false-positive guards: these pass on BOTH trees ----

test('GUARD: the transaction policy still refuses receipt canonical bytes', () => {
  const { evaluate } = require('../src/policy');
  const canonical = evaluateMessage(body(), grant()).messageBytes;
  const verdict = evaluate(canonical, grant(), new Date());
  assert.equal(verdict.allowed, false);
  // The old envelope refuses with its own reason; the new one never widens it.
  assert.equal(typeof verdict.refused, 'string');
});

test('GUARD: existing exports are untouched', () => {
  const policy = require('../src/policy');
  assert.equal(typeof policy.evaluate, 'function');
  const ledger = require('../src/ledger');
  assert.equal(typeof ledger.gate, 'function');
  assert.equal(ledger.MESSAGE_DOMAIN.length, 19);
});
