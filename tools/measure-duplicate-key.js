#!/usr/bin/env node
'use strict';
// THE DUPLICATE-KEY INSTRUMENT: what does the product do when the grant
// document names the same key twice? (2026-11-19)
//
// WHY (measured first on tree 260384b = pre-fix v0.2.41): JSON.parse keeps
// the LAST spelling of a duplicated key and says nothing, so a hand edit
// that leaves one block behind can make the file display one scope and run
// another. The instrument measures EVERY reader on one fixture:
//
//   - the loader (the daemon's per-request judge, via status --grants);
//   - grant-add --append (the writer that could rewrite the file);
//   - the daemon's STARTUP (D10 - the security face);
//   - verify-grants (with a passphrase, the operator's own check).
//
// THE FIXTURE IS BUILT FROM THE PRODUCT'S OWN grant-add: a real file, then
// a second spelling of the same grant spliced in as the LAST block, with
// the HIDDEN cap (500000000) on the last spelling and the VISIBLE cap
// (5000) on the first. A JSON writer cannot emit a duplicate, which is
// exactly why the defect was invisible to the writer's own tests.
//
// VERDICTS:
//   duplicate-key-read-last-wins  any reader answered ok / rewrote / started
//   duplicate-key-refused         every reader refused with the code
//
// Usage:
//   node tools/measure-duplicate-key.js [--cli <path/to/bin/signerd.js>]
//        [--out <file>]
//   Exit 0 = refused everywhere, 1 = at least one reader went last-wins,
//   2 = bad usage / harness failure.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  args[process.argv[i]] = process.argv[i + 1];
}
const cli = args['--cli'] ? path.resolve(args['--cli']) : path.join(REPO, 'bin', 'signerd.js');
if (!fs.existsSync(cli)) {
  console.error(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: 'no CLI at ' + cli }));
  process.exit(2);
}

// NO HOST PATHS in the artifact: report basenames and byte counts only.
function scrub(p) { return path.basename(p); }
function sh(argv) {
  const r = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8' });
  return { status: r.status, signal: r.signal, stdout: r.stdout || '', stderr: r.stderr || '' };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-dupkey-'));
fs.chmodSync(dir, 0o700);
const pass = path.join(dir, 'pass');
const keystore = path.join(dir, 'k.key');
const grants = path.join(dir, 'g.json');
const ledger = path.join(dir, 'l.jsonl');
fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });

const exit2 = (why) => {
  console.error(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: why }));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(2);
};

if (sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]).status !== 0) {
  exit2('keygen failed');
}
const add = sh(['grant-add', '--grants', grants, '--name', 'ops',
  '--keystore', keystore,
  '--destination', 'So11111111111111111111111111111111111111112',
  '--max-lamports', '5000', '--window-max-lamports', '5000',
  '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
if (add.status !== 0) exit2('grant-add failed: ' + add.stderr);

// THE FIXTURE: splice a second spelling as the LAST block (hidden cap wins).
const doc = JSON.parse(fs.readFileSync(grants, 'utf8'));
const grant = doc.grants.ops;
const low = { ...grant, maxLamports: '5000', windowMaxLamports: '5000' };
const high = { ...grant, maxLamports: '500000000', windowMaxLamports: '500000000' };
const ind = (o) => JSON.stringify(o, null, 4).replace(/\n/g, '\n    ');
const dup = `{\n  "version": 1,\n  "grants": {\n    "ops": ${ind(low)},\n    "ops": ${ind(high)}\n  }\n}\n`;
const reparse = JSON.parse(dup);
if (reparse.grants.ops.maxLamports !== '500000000') {
  exit2('fixture must demonstrate last-wins (the hidden cap is what a reader enforces)');
}
const writeDup = () => fs.writeFileSync(grants, dup, { mode: 0o600 });

const faces = [];
const push = (id, hold, observed) => faces.push({ id, hold, observed });

// R1 the loader surface: status --grants on the duplicate file.
writeDup();
let r = sh(['status', '--grants', grants, '--ledger', ledger]);
push('status_refuses_duplicate',
  r.status === 1 && /grant_duplicate_key/.test(r.stderr) && !/"ok":true/.test(r.stdout),
  { status: r.status, names: /grant_duplicate_key/.test(r.stderr), stdoutOk: /"ok":true/.test(r.stdout) });

// R2 the writer: grant-add --append must refuse, and the file must be
//    byte-identical afterwards (pre-fix it accepted the file and REWROTE
//    it without the duplicate - the repair erased the operator's edit).
writeDup();
const before = fs.readFileSync(grants, 'utf8');
r = sh(['grant-add', '--grants', grants, '--name', 'second', '--append',
  '--keystore', keystore,
  '--destination', 'So11111111111111111111111111111111111111112',
  '--max-lamports', '7000', '--window-max-lamports', '7000',
  '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z']);
const after = fs.readFileSync(grants, 'utf8');
push('append_refuses_and_preserves_file',
  r.status !== 0 && /grant_duplicate_key/.test(r.stderr) && after === before,
  { status: r.status, names: /grant_duplicate_key/.test(r.stderr), bytesChanged: after !== before });

// R3 the daemon's STARTUP: must refuse to start, not serve the hidden cap.
writeDup();
r = spawnSync(process.execPath, [cli, 'run',
  '--keystore', keystore, '--passphrase-file', pass,
  '--grants', grants, '--ledger', ledger, '--socket', path.join(dir, 's.sock')],
{ encoding: 'utf8', timeout: 4000 });
push('daemon_refuses_to_start',
  r.status === 1 && /grant_duplicate_key/.test(r.stderr || ''),
  { status: r.status, signal: r.signal, names: /grant_duplicate_key/.test(r.stderr || '') });

// R4 the operator's own check, with the passphrase they would use.
writeDup();
r = sh(['verify-grants', '--grants', grants, '--seal-passphrase-file', pass]);
push('verify_names_the_duplicate',
  r.status === 1 && /grant_duplicate_key/.test(r.stderr),
  { status: r.status, names: /grant_duplicate_key/.test(r.stderr) });

// R5 the other writer: grant-remove must refuse too - a rewrite through
//    the last-wins parse would launder the ambiguity (keeping the hidden
//    spelling) exactly like append. The operator's repair is the hand-edit
//    the fix line names.
writeDup();
const beforeRm = fs.readFileSync(grants, 'utf8');
r = sh(['grant-remove', '--grants', grants, '--name', 'ops']);
const afterRm = fs.readFileSync(grants, 'utf8');
push('grant_remove_refuses_and_preserves_file',
  r.status !== 0 && /grant_duplicate_key/.test(r.stderr) && afterRm === beforeRm,
  { status: r.status, names: /grant_duplicate_key/.test(r.stderr), bytesChanged: afterRm !== beforeRm });

// G-A guard: a legal file is still served (status ok:true). This is the
// false-positive side of R1: the scanner must not brick the happy path.
// The file is recreated from scratch (the previous face left the dup
// document in place, and every reader now refuses it - by design).
fs.rmSync(grants, { force: true });
sh(['grant-add', '--grants', grants, '--name', 'ops',
  '--keystore', keystore,
  '--destination', 'So11111111111111111111111111111111111111112',
  '--max-lamports', '5000', '--window-max-lamports', '5000',
  '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
r = sh(['status', '--grants', grants, '--ledger', ledger]);
push('guard_legal_file_still_served',
  r.status === 0 && /"ok":true/.test(r.stdout),
  { status: r.status, stdoutOk: /"ok":true/.test(r.stdout) });

const defects = faces.filter((f) => !f.hold);
const guardIds = faces.filter((f) => f.id.startsWith('guard_')).map((f) => f.id);
const guardBroken = faces.filter((f) => f.id.startsWith('guard_') && !f.hold).map((f) => f.id);
const verdict = defects.length === 0
  ? 'duplicate-key-refused'
  : 'duplicate-key-read-last-wins';

const result = {
  generatedAt: new Date().toISOString(),
  cli: scrub(cli),
  verdict,
  faces: faces.length,
  faceDefects: defects.length,
  guardBroken,
  rows: faces,
  rules: ['duplicate-key-refused-by-name', 'file-byte-identical', 'daemon-start-refused', 'no-host-path', 'legal-file-served'],
};
const out = JSON.stringify(result, null, 1);
if (args['--out']) {
  fs.mkdirSync(path.dirname(path.resolve(args['--out'])), { recursive: true });
  fs.writeFileSync(path.resolve(args['--out']), out + '\n');
}
process.stdout.write(out + '\n');
process.stderr.write(`\nVERDICT ${verdict}: ${defects.length}/${faces.length} defect faces, ` +
  `guards broken: ${guardBroken.length}\n`);
fs.rmSync(dir, { recursive: true, force: true });
process.exit(defects.length === 0 ? 0 : 1);
