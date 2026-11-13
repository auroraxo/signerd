'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createKeystore, loadKeystore, writeKeystore, importKeystore, readKeystorePublicKey } = require('../src/keystore');
const { Keypair } = require('@solana/web3.js');

// The keystore holds the encrypted secret the daemon signs with, behind the
// same mode/owner/directory rules the grant file has. The grant side refuses
// a symlink at its path by NAME (grant_file_symlink, pinned since v0.2.20);
// these tests pin the same rule for the keystore side, measured against the
// published v0.2.21 tree (tools/measure-keystore-symlink.js):
// every write followed the link, the loader and the public-key reader
// accepted one, and an interrupted write could truncate the secret document
// in place.

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-kssym-')); }
function codeOf(fn) {
  try { fn(); return null; } catch (err) { return err && err.code ? String(err.code) : String(err && err.message); }
}
function linkTo(dir, target) {
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(target, link);
  return link;
}

// D1: keygen onto a symlink to an EXISTING file must refuse by name and
// leave the victim byte-identical. On v0.2.21 the verdict was keystore_exists
// (describing the victim, not the path) — or, with --overwrite, the victim was
// destroyed through the link.
test('D1 keygen through a symlink is refused as keystore_symlink; the victim stands', () => {
  const dir = tmp();
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = linkTo(dir, victim);
  const code = codeOf(() => createKeystore({ file: link, passphrase: 'p' }));
  assert.equal(code, 'keystore_symlink');
  assert.equal(fs.readFileSync(victim, 'utf8'), original, 'the link target must not be touched');
  assert.ok(fs.lstatSync(link).isSymbolicLink(), 'the link itself must stand untouched');
});

// D2: a DANGLING symlink: existsSync(follow) saw nothing on v0.2.21 and the
// write CREATED the target outside the directory the operator named.
test('D2 keygen onto a dangling symlink is refused; nothing is created outside the named path', () => {
  const dir = tmp();
  const outside = tmp();
  const hidden = path.join(outside, 'ops.key');
  const link = linkTo(dir, hidden);
  const code = codeOf(() => createKeystore({ file: link, passphrase: 'p' }));
  assert.equal(code, 'keystore_symlink');
  assert.equal(fs.existsSync(hidden), false, 'no file may appear at the link target');
  assert.equal(fs.readdirSync(dir).length, 1, 'the named directory gains nothing');
});

// D3: --overwrite is the documented repair for REPLACING A KEYSTORE, not an
// arbitrary-file-overwrite primitive through a link.
test('D3 --overwrite through a symlink is refused too (not an arbitrary-overwrite primitive)', () => {
  const dir = tmp();
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = linkTo(dir, victim);
  const code = codeOf(() => createKeystore({ file: link, passphrase: 'p', overwrite: true }));
  assert.equal(code, 'keystore_symlink');
  assert.equal(fs.readFileSync(victim, 'utf8'), original);
});

// D4: the migration path (import) uses the same writer and carries the rule.
test('D4 import through a symlink is refused; the victim and the source stand', () => {
  const dir = tmp();
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = linkTo(dir, victim);
  const src = path.join(dir, 'id.json');
  const kp = Keypair.generate();
  fs.writeFileSync(src, JSON.stringify(Array.from(kp.secretKey)));
  const code = codeOf(() => importKeystore({ file: link, passphrase: 'p', from: src, overwrite: true }));
  assert.equal(code, 'keystore_symlink');
  assert.equal(fs.readFileSync(victim, 'utf8'), original);
});

// D5: the loader is the judge of the state. A keystore reached through a
// symlink is refused by name — the mode check on v0.2.21 described the file
// the link LANDED on, never the path the daemon was pointed at.
test('D5 loadKeystore through a symlink is refused as keystore_symlink', () => {
  const dir = tmp();
  const real = path.join(dir, 'real.key');
  createKeystore({ file: real, passphrase: 'p' });
  const link = linkTo(dir, real);
  const code = codeOf(() => loadKeystore({ file: link, passphrase: 'p' }));
  assert.equal(code, 'keystore_symlink');
});

// D6: the public-key reader is the same surface: build-tx and grant pinning
// learn the identity of a key through it.
test('D6 readKeystorePublicKey through a symlink is refused as keystore_symlink', () => {
  const dir = tmp();
  const real = path.join(dir, 'real.key');
  createKeystore({ file: real, passphrase: 'p' });
  const link = linkTo(dir, real);
  const code = codeOf(() => readKeystorePublicKey({ file: link }));
  assert.equal(code, 'keystore_symlink');
});

// D7: the write is atomic (same-directory temp, O_EXCL, fsync, rename): an
// interrupted replacement leaves the OLD COMPLETE document, never a truncated
// secret file. Method: fail the rename (no bytes ever reached the target);
// the published file must still equal the old bytes.
test('D7 an interrupted replacement leaves the old complete keystore, not a truncated one', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'p' });
  const oldBytes = fs.readFileSync(file);
  const realRename = fs.renameSync;
  const realWrite = fs.writeFileSync;
  let directToTarget = 0;
  let renamedIntoPlace = false;
  fs.writeFileSync = function (fdOrPath, ...rest) {
    if (fdOrPath === file) directToTarget += 1;
    return realWrite.call(fs, fdOrPath, ...rest);
  };
  fs.renameSync = function (from, to) {
    if (to === file) {
      renamedIntoPlace = true;
      fs.renameSync = realRename; fs.writeFileSync = realWrite;
      const e = new Error('measured: injected rename failure');
      e.code = 'EIO';
      throw e;
    }
    return realRename.apply(fs, arguments);
  };
  const kp = Keypair.generate();
  assert.throws(() => writeKeystore({ file, passphrase: 'p2', secretKey: kp.secretKey, overwrite: true }));
  fs.renameSync = realRename; fs.writeFileSync = realWrite;
  assert.equal(renamedIntoPlace, true, 'the writer must deliver by rename, not in place');
  assert.equal(directToTarget, 0, 'no bytes may be written straight to the target');
  assert.ok(fs.readFileSync(file).equals(oldBytes), 'the published keystore keeps its OLD COMPLETE bytes');
  // the temp is cleaned up: only the keystore stands in the directory
  assert.deepEqual(fs.readdirSync(dir), ['ops.key']);
  // and the old passphrase still loads — the document was never touched
  assert.ok(loadKeystore({ file, passphrase: 'p' }));
});

// Guards (must hold before AND after the fix): the ordinary paths are
// unchanged.
test('G1 keygen -> load round trip on a real file: mode 0600, no leftovers', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  const created = createKeystore({ file, passphrase: 'right' });
  const loaded = loadKeystore({ file, passphrase: 'right' });
  assert.equal(loaded.publicKey.toBase58(), created.publicKey);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(dir), ['ops.key']);
});

test('G2 keygen onto a real existing file stays keystore_exists', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'p' });
  assert.equal(codeOf(() => createKeystore({ file, passphrase: 'p' })), 'keystore_exists');
});

test('G3 the loader still refuses loose modes (the rule is not weakened)', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'p' });
  fs.chmodSync(file, 0o644);
  assert.equal(codeOf(() => loadKeystore({ file, passphrase: 'p' })), 'keystore_mode');
});

test('G4 import of a real id.json still works end to end', () => {
  const dir = tmp();
  const src = path.join(dir, 'id.json');
  const kp = Keypair.generate();
  fs.writeFileSync(src, JSON.stringify(Array.from(kp.secretKey)));
  const file = path.join(dir, 'ops.key');
  const out = importKeystore({ file, passphrase: 'p', from: src });
  assert.equal(out.publicKey, kp.publicKey.toBase58());
  assert.equal(loadKeystore({ file, passphrase: 'p' }).publicKey.toBase58(), kp.publicKey.toBase58());
  assert.ok(fs.existsSync(src), 'the source file is never deleted');
});
