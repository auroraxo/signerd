'use strict';
// P7: R2-3 (journal path checks), R3-1 (writable grant file refused),
// R3-2 (format-1 journal refused at load; explicit `signerd migrate`).
// Every case here is a FALSIFICATION ATTEMPT: expected outcome stated inline.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { loadGrantFile } = require('../../src/grantfile');
const { Ledger, assertJournalPath } = require('../../src/ledger');
const { migrateJournal } = require('../../src/migrate');
const { tmpdir, grantDoc, writeGrants, Keypair } = require('./common');

const REPO = path.join(__dirname, '..', '..');
const signer = Keypair.generate();
const dest = Keypair.generate().publicKey;
const out = {};
const expect = (name, want, fn) => {
  try {
    const v = fn();
    out[name] = { observed: `ACCEPTED ${JSON.stringify(v)}`, want };
  } catch (err) {
    out[name] = { observed: `REFUSED ${err.code || err.message}`, want };
  }
};

const dir = tmpdir('signerd-r5-p7-');

// --- journal symlink: expect ledger_not_a_file (refused) ---
const target = path.join(dir, 'real-journal.jsonl');
fs.writeFileSync(target, '');
fs.chmodSync(target, 0o600);
const link = path.join(dir, 'link-journal.jsonl');
fs.symlinkSync(target, link);
expect('journal_symlink', 'REFUSED (ledger_not_a_file)', () => new Ledger({ file: link }).snapshot());

// --- journal group/other writable: expect ledger_mode (refused, not repaired) ---
const wj = path.join(dir, 'writable-journal.jsonl');
fs.writeFileSync(wj, '');
fs.chmodSync(wj, 0o666);
expect('journal_mode_0666', 'REFUSED (ledger_mode)', () => new Ledger({ file: wj }).snapshot());

// --- journal group-readable: expect ACCEPTED and tightened to 0600 ---
const rj = path.join(dir, 'readable-journal.jsonl');
fs.writeFileSync(rj, '');
fs.chmodSync(rj, 0o644);
expect('journal_mode_0644', 'ACCEPTED + chmod 0600', () => new Ledger({ file: rj }).snapshot());
out.journal_mode_0644.after_mode = (fs.statSync(rj).mode & 0o777).toString(8);

// --- journal in a group/other-writable NON-sticky dir: expect ledger_dir_mode ---
const badDir = path.join(dir, 'baddir');
fs.mkdirSync(badDir);
fs.chmodSync(badDir, 0o777);
const bdJournal = path.join(badDir, 'j.jsonl');
expect('journal_dir_0777_nonsticky', 'REFUSED (ledger_dir_mode)',
  () => assertJournalPath(bdJournal));
// same dir + sticky bit: expect ACCEPTED (documented allowance)
fs.chmodSync(badDir, 0o1777);
expect('journal_dir_1777_sticky', 'ACCEPTED', () => assertJournalPath(bdJournal));
fs.chmodSync(badDir, 0o755);

// --- grant file group/other writable: expect grant_file_mode (refused) ---
const wg = path.join(dir, 'grants-writable.json');
writeGrants(wg, grantDoc(signer.publicKey.toBase58(), dest.toBase58()), 0o666);
expect('grant_file_0666', 'REFUSED (grant_file_mode)', () => loadGrantFile(wg).names);
// grant file group-readable only: expect ACCEPTED (readable is harmless)
const rg = path.join(dir, 'grants-readable.json');
writeGrants(rg, grantDoc(signer.publicKey.toBase58(), dest.toBase58()), 0o644);
expect('grant_file_0644', 'ACCEPTED', () => loadGrantFile(rg).names);
// grant file as symlink: expect REFUSED (O_NOFOLLOW -> grant_file_invalid)
const gl = path.join(dir, 'grants-link.json');
fs.symlinkSync(rg, gl);
expect('grant_file_symlink', 'REFUSED (grant_file_invalid)', () => loadGrantFile(gl).names);

// --- R3-2: format-1 fixture refused at load ---
const f1 = path.join(dir, 'format1.jsonl');
fs.copyFileSync(path.join(REPO, 'test', 'fixtures', 'format1-ledger.jsonl'), f1);
fs.chmodSync(f1, 0o600);
expect('format1_journal_load', 'REFUSED (ledger_legacy_format)',
  () => new Ledger({ file: f1 }).snapshot());
// CLI status must fail closed too
const cli = spawnSync(process.execPath, [
  path.join(REPO, 'bin', 'signerd.js'), 'status',
  '--grants', rg, '--ledger', f1,
], { encoding: 'utf8', cwd: REPO });
out.format1_cli_status = { status: cli.status, stderr: (cli.stderr || '').trim().split('\n')[0] };

// --- format-1 record with an explicit v: expect REFUSED (no skip via v:1) ---
const forgedV = path.join(dir, 'forged-v1.jsonl');
fs.writeFileSync(forgedV, fs.readFileSync(f1, 'utf8').split('\n')[0] + '\n');
expect('format1_claimed_v1', 'REFUSED (ledger_corrupt — cannot skip the legacy check)',
  () => new Ledger({ file: forgedV }).snapshot());

// --- migrate --discard-legacy: expect migrate ok, then load ok ---
const mDiscard = path.join(dir, 'migrate-discard.jsonl');
fs.copyFileSync(f1, mDiscard);
fs.chmodSync(mDiscard, 0o600);
try {
  const res = migrateJournal({ file: mDiscard, discardLegacy: true });
  out.migrate_discard = { migrated: res.migrated, legacyRecords: res.legacyRecords };
  const led = new Ledger({ file: mDiscard });
  out.migrate_discard.after_load = led.snapshot();
  out.migrate_discard.legacyState = led.legacyState();
} catch (err) {
  out.migrate_discard = { error: err.code || err.message };
}

// --- migrate --wires: expect message identities restored ---
const mWires = path.join(dir, 'migrate-wires.jsonl');
fs.copyFileSync(f1, mWires);
fs.chmodSync(mWires, 0o600);
try {
  const res = migrateJournal({ file: mWires, wiresDir: path.join(REPO, 'test', 'fixtures') });
  out.migrate_wires = { migrated: res.migrated, resolved: res.resolved, unknown: res.unknownMessageRecords };
  out.migrate_wires.legacyState = new Ledger({ file: mWires }).legacyState();
} catch (err) {
  out.migrate_wires = { error: err.code || err.message, detail: err.message };
}

// --- migrate refuses without --wires/--discard-legacy (fail closed) ---
const mNone = path.join(dir, 'migrate-none.jsonl');
fs.copyFileSync(f1, mNone);
fs.chmodSync(mNone, 0o600);
try {
  out.migrate_without_flags = migrateJournal({ file: mNone });
} catch (err) {
  out.migrate_without_flags = `REFUSED ${err.code || err.message}`;
}

console.log(JSON.stringify(out, null, 2));
fs.rmSync(dir, { recursive: true, force: true });
