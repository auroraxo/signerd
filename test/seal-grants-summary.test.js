'use strict';

// THE SEAL SUMMARY MUST SHOW THE SCOPE THE OPERATOR JUST CERTIFIED.
//
// WHY (measured 2026-11-15, this repo): `seal-grants` is the command that
// makes a grant file AUTHENTIC — sealing a forged file makes the forgery
// valid, which is exactly why it prints what it sealed. It printed a
// HAND-PICKED SUBSET of the fields it had just sealed:
//
//     { name, signer, destination, maxLamports, expiresAt }
//
// Two faces of the same defect, both live on the published v0.2.26 tree:
//
//   S1  tx grant — the ROLLING WINDOW BUDGET was invisible. The window
//       (`windowMaxLamports`) is the cap that actually bounds the spend of
//       the window; `windowSeconds` is its width. A grant sealed with
//       `windowMaxLamports: 18446744073709551615` (the u64 maximum, i.e.
//       "no budget at all") printed a summary in which no budget appears
//       anywhere: the operator cannot see what they just made valid.
//   S2  message grant — the WHOLE SCOPE was invisible. A message grant has
//       a disjoint schema (kind/issuer/type/subject/pubkey/maxBytes/
//       windowMaxMessages/windowSeconds); the summary printed
//       `{name, expiresAt}` for it — the issuer, the type, the subject, the
//       pinned pubkey, the byte ceiling and the message count were all
//       absent. The command's own reason for existing ("it prints what it
//       sealed") did not hold for a whole class of grants.
//
// THE CONTRACT:
//   S1 a tx grant's summary carries the rolling window budget;
//   S2 a message grant's summary carries its whole scope;
//   S3 the summary is a FUNCTION of the sealed document: every field it
//       prints equals the field in the file that was written — the summary
//       may not drift from the artefact;
//   G1 guards (must hold on BOTH trees): sealing a valid file still works
//       and still names what it sealed; re-sealing an already sealed file
//       still works; the summary of a grant that has no window fields keeps
//       the fields it always had (name, signer, destination, maxLamports,
//       expiresAt) — the fix adds, it does not remove.
//
// LADDER: S1 and S2 are RED on the pre-fix tree (measured live against the
// published v0.2.26 tree, 812135f), GREEN here. G1 is green on BOTH trees.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'signerd.js');

const DESTINATION = 'So11111111111111111111111111111111111111112';
// ONE key, two spellings (base58 for the tx grant, base64 for the message
// grant) — the fixture must be a file a daemon could actually run: a doc
// whose tx grant and message grant pin DIFFERENT keys is refused by
// seal-grants (grant_file_key_mismatch), which is exactly the defect class
// measured 2026-11-17 (tools/measure-grant-key-verdict.js).
const KEY_BYTES = Buffer.alloc(32); // 32 zero bytes: base58 '11111111111111111111111111111111'
const SIGNER = '11111111111111111111111111111111';
const PUBKEY_B64 = KEY_BYTES.toString('base64');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120000 });
}

function secretDir(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  fs.writeFileSync(sealPass, 'a separate seal phrase\n', { mode: 0o600 });
  fs.chmodSync(sealPass, 0o600);
  return { root, cfg, sealPass };
}

function writeDoc(grantsPath, doc) {
  fs.writeFileSync(grantsPath, JSON.stringify(doc, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(grantsPath, 0o600);
}

function seal(s, grantsPath) {
  return run(['seal-grants', '--grants', grantsPath, '--seal-passphrase-file', s.sealPass]);
}

function summaryOf(result) {
  const line = String(result.stdout).split('\n').filter((l) => l.trim().startsWith('{')).pop();
  assert.ok(line, `seal-grants must print one JSON line: ${result.stdout}${result.stderr}`);
  return JSON.parse(line);
}

function txGrant(overrides = {}) {
  return Object.assign({
    signer: SIGNER,
    destination: DESTINATION,
    maxLamports: '1000',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxLamports: '500000000',
    windowSeconds: '3600',
  }, overrides);
}

function messageGrant(overrides = {}) {
  return Object.assign({
    kind: 'message',
    issuer: 'acme',
    type: 'release',
    subject: 'acme/app',
    pubkey: PUBKEY_B64,
    maxBytes: '700',
    expiresAt: '2030-01-01T00:00:00Z',
    windowMaxMessages: '5',
    windowSeconds: '3600',
  }, overrides);
}

// ---------------------------------------------------------------------------
// S1: the rolling window budget of a tx grant must be visible.
// ---------------------------------------------------------------------------

test('S1 a sealed tx grant reports its rolling window budget', () => {
  const s = secretDir('signerd-seal-summary-s1-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, {
    version: 1,
    grants: { ops: txGrant({ windowMaxLamports: '18446744073709551615', windowSeconds: '1' }) },
  });

  const r = seal(s, grants);
  assert.strictEqual(r.status, 0, `seal-grants must seal a valid file: ${r.stderr}`);
  const out = summaryOf(r);
  const ops = out.grants.find((g) => g.name === 'ops');
  assert.ok(ops, `the summary must name the grant: ${r.stdout}`);
  assert.strictEqual(ops.windowMaxLamports, '18446744073709551615',
    `the window budget the operator just sealed must be in the summary: ${r.stdout}`);
  assert.strictEqual(ops.windowSeconds, '1',
    `the window width must be in the summary: ${r.stdout}`);
});

// ---------------------------------------------------------------------------
// S2: the whole scope of a message grant must be visible.
// ---------------------------------------------------------------------------

test('S2 a sealed message grant reports its whole scope', () => {
  const s = secretDir('signerd-seal-summary-s2-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, {
    version: 1,
    grants: { releases: messageGrant() },
  });

  const r = seal(s, grants);
  assert.strictEqual(r.status, 0, `seal-grants must seal a valid file: ${r.stderr}`);
  const out = summaryOf(r);
  const rel = out.grants.find((g) => g.name === 'releases');
  assert.ok(rel, `the summary must name the grant: ${r.stdout}`);
  for (const field of ['kind', 'issuer', 'type', 'subject', 'pubkey', 'maxBytes',
    'windowMaxMessages', 'windowSeconds', 'expiresAt']) {
    assert.strictEqual(rel[field], messageGrant()[field],
      `the message scope field ${field} must be in the summary: ${r.stdout}`);
  }
});

// ---------------------------------------------------------------------------
// S3: the summary may not drift from the artefact that was written.
// ---------------------------------------------------------------------------

test('S3 the summary equals the sealed document field by field', () => {
  const s = secretDir('signerd-seal-summary-s3-');
  const grants = path.join(s.cfg, 'grants.json');
  const doc = {
    version: 1,
    grants: {
      ops: txGrant(),
      releases: messageGrant({ claimKeys: 'build,sha' }),
    },
  };
  writeDoc(grants, doc);

  const r = seal(s, grants);
  assert.strictEqual(r.status, 0, `seal-grants must seal a valid file: ${r.stderr}`);
  const sealed = JSON.parse(fs.readFileSync(grants, 'utf8'));
  const out = summaryOf(r);
  assert.strictEqual(out.grants.length, 2,
    `every sealed grant must appear in the summary: ${r.stdout}`);
  for (const entry of out.grants) {
    const written = sealed.grants[entry.name];
    assert.ok(written, `the summary names a grant that was not sealed: ${entry.name}`);
    for (const [field, value] of Object.entries(entry)) {
      if (field === 'name') continue;
      assert.strictEqual(written[field], value,
        `the summary must not contradict the sealed file (${entry.name}.${field}): ` +
        `${r.stdout}`);
    }
    // AND the other way round: a field the loader accepted but the summary
    // dropped would be a silent blind spot again.
    for (const field of Object.keys(written)) {
      assert.ok(Object.prototype.hasOwnProperty.call(entry, field),
        `the summary must carry every sealed field (${entry.name}.${field}): ${r.stdout}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Guards: the documented repair paths must still work, and the fix must ADD
// fields, never remove them.
// ---------------------------------------------------------------------------

test('G1 sealing a valid file still works and keeps the fields it always had', () => {
  const s = secretDir('signerd-seal-summary-g1-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, { version: 1, grants: { ops: txGrant() } });

  const r = seal(s, grants);
  assert.strictEqual(r.status, 0, `seal-grants must still work: ${r.stderr}`);
  assert.match(r.stdout, /"ok":true/, `the verdict must be ok:true: ${r.stdout}`);
  const out = summaryOf(r);
  const ops = out.grants.find((g) => g.name === 'ops');
  assert.ok(ops, `the summary must name what was sealed: ${r.stdout}`);
  assert.strictEqual(ops.signer, SIGNER);
  assert.strictEqual(ops.destination, DESTINATION);
  assert.strictEqual(ops.maxLamports, '1000');
  assert.strictEqual(ops.expiresAt, '2030-01-01T00:00:00Z');
});

test('G2 re-sealing an already sealed file still works', () => {
  const s = secretDir('signerd-seal-summary-g2-');
  const grants = path.join(s.cfg, 'grants.json');
  writeDoc(grants, { version: 1, grants: { releases: messageGrant() } });

  const first = seal(s, grants);
  assert.strictEqual(first.status, 0, `the first seal must work: ${first.stderr}`);
  const second = seal(s, grants);
  assert.strictEqual(second.status, 0, `the re-seal must work: ${second.stderr}`);
  const out = summaryOf(second);
  assert.strictEqual(out.grants.length, 1, `the re-seal must report the grant: ${second.stdout}`);
  assert.strictEqual(out.grants[0].issuer, 'acme',
    `the re-seal must report the scope too: ${second.stdout}`);
});
