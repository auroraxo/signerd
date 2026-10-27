'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadGrantFile, validateGrant } = require('../src/grantfile');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-grants-'));
}
function writeGrantFile(dir, doc) {
  const file = path.join(dir, 'grants.json');
  fs.writeFileSync(file, typeof doc === 'string' ? doc : JSON.stringify(doc, null, 2));
  return file;
}
const good = {
  signer: '11111111111111111111111111111111',
  destination: 'So11111111111111111111111111111111111111112',
  maxLamports: '42',
  expiresAt: '2026-10-28T10:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

test('a well formed grant file loads and reports sorted grant names', () => {
  const dir = tmpDir();
  const file = writeGrantFile(dir, { version: 1, grants: { beta: good, alpha: good } });
  const loaded = loadGrantFile(file);
  assert.deepEqual(loaded.names, ['alpha', 'beta']);
  assert.equal(loaded.grants.alpha.maxLamports, '42');
});

test('unknown fields are refused: a typo in a security file is a mistake, not an extra rule', () => {
  const dir = tmpDir();
  const file = writeGrantFile(dir, {
    version: 1,
    grants: { ops: { ...good, maxLamport: '42' } },
  });
  assert.throws(() => loadGrantFile(file), /grant_unknown_field/);
});

test('wrong types, missing fields and bad formats are refused at load time', () => {
  const dir = tmpDir();
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { ops: { ...good, maxLamports: 42 } } })),
    /grant_field_invalid/);
  const missing = { ...good };
  delete missing.windowSeconds;
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { ops: missing } })),
    /grant_field_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { ops: { ...good, expiresAt: '2026-10-28 10:00' } } })),
    /grant_field_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { ops: { ...good, windowSeconds: '1.5' } } })),
    /grant_field_invalid/);
});

test('grant names that could reach Object.prototype are refused', () => {
  const dir = tmpDir();
  // Built as raw JSON: an object literal's `__proto__:` key would set the
  // prototype instead of creating an own property.
  assert.throws(() => loadGrantFile(writeGrantFile(dir, `{"version":1,"grants":{"__proto__":${JSON.stringify(good)}}}`)),
    /grant_name_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { constructor: good } })),
    /grant_name_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { 'has space': good } })),
    /grant_name_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: { '': good } })),
    /grant_name_invalid/);
});

test('a malformed or wrong-version grant file fails closed', () => {
  const dir = tmpDir();
  assert.throws(() => loadGrantFile(writeGrantFile(dir, 'not json')), /grant_file_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 2, grants: {} })), /grant_file_invalid/);
  assert.throws(() => loadGrantFile(writeGrantFile(dir, { version: 1, grants: [] })), /grant_file_invalid/);
  assert.throws(() => loadGrantFile(path.join(dir, 'missing.json')), /grant_file_unreadable/);
});

test('loaded grants live on a null prototype, so inherited names never resolve', () => {
  const dir = tmpDir();
  const file = writeGrantFile(dir, { version: 1, grants: { ops: good } });
  const loaded = loadGrantFile(file);
  assert.equal(Object.getPrototypeOf(loaded.grants), null);
  assert.equal(Object.prototype.hasOwnProperty.call(loaded.grants, 'toString'), false);
  assert.equal(loaded.grants.toString, undefined);
});

test('validateGrant rejects a grant whose value types are wrong', () => {
  assert.throws(() => validateGrant('ops', null), /grant_invalid/);
  assert.throws(() => validateGrant('ops', []), /grant_invalid/);
  assert.throws(() => validateGrant('ops', { ...good, maxLamports: '-1' }), /grant_field_invalid/);
});
