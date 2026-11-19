#!/usr/bin/env node
'use strict';
// THE WINDOW-FRAME INSTRUMENT: what does the grant's rolling window admit,
// and what does the operator see when the answer is "nothing"? (2026-11-19)
//
// WHY (measured on main ab21fcf AND on the published npm signerd@0.2.42,
// both defect): the ledger charges `amount + 5000` (the fixed base fee)
// against windowMaxLamports (src/ledger.js #decideSpend), while maxLamports
// is judged alone by src/policy.js (`amount <= maximum`). The fee arithmetic
// lives in exactly ONE of the two halves, so the value domain the creation
// path accepts (isWindowMaxLamports: [5000, 2^64-1]) does not agree with the
// domain the runtime can honour:
//
//   D1  A transfer AT the grant's own maxLamports is refused window_cap on
//       an EMPTY window (spent=0): cost = max + fee > window whenever
//       max > window - 5000. The README pairs max==window in BOTH example
//       grants (README.md:68/74, docs/GUIDE.md:24/39), so the documented
//       0.5 SOL and 1M lamport transfers can never sign, and the front-page
//       claim "Signs ... within per-transaction (maxLamports) and
//       rolling-window caps" reads the opposite way.
//   D2  The refusal REPORT is false for the empty window: it says "the
//       grant's rolling window is spent" while the same frame carries
//       windowSpentLamports:"0" and windowRemainingLamports:<the FULL cap>.
//       Spent = 0 and spent = full are opposite facts wearing one word.
//   D3  The NAMED repair is not runnable for the reported state: it says
//       "widen it" and names `grant-add --append --name <grant>`, but that
//       command refuses grant_exists for a grant that is still in the file.
//       (A NEW name would not help either: the fresh scope starts at the
//       same 0 spend, so the same transfer is refused again.)
//   D4  The reachable ceiling is undocumented and off by the fee: the
//       largest amount any window ever admits is windowMaxLamports - 5000
//       (measured: 995000 signs, 995001 refuses on a 1,000,000 window).
//       A grant advertising max = window - 1 (0.999999 SOL of a 1 SOL
//       window) still refuses every transfer.
//   D5  Creation accepts a grant that is dead for ANY positive transfer:
//       maxLamports=500000000 with windowMaxLamports=5000 (the minimum
//       isWindowMaxLamports accepts) is written ok:true; the first 1-lamport
//       transfer is refused window_cap with spent=0 and NOTHING is journaled.
//       That is the exact "dead on arrival" class grant-cap-domain killed
//       for the amount side in v0.2.12 — the same defect one step over.
//
// THE FIXTURE IS BUILT FROM THE PRODUCT'S OWN grant-add and build-tx (no
// hand-written JSON), and every face runs against ONE live daemon pair per
// tree, exactly the way an operator would drive it.
//
// VERDICTS:
//   window-frame-fee-blind     any D1-D5 face holds (this tree, pre-fix)
//   window-frame-honest        every face holds on neither tree (post-fix)
//
// Guards (must hold on BOTH trees, or the instrument itself is broken):
//   g1  a transfer at window - fee SIGNS (the fee arithmetic is understood;
//       the defect is the undocumented ceiling, not a broken window);
//   g2  a transfer well inside the ceiling SIGNS;
//   g3  after the g2 spend, a window_cap refusal reports the TRUE spend
//       (spent > 0, remaining < cap) - the report only lies on the empty
//       window, and the instrument must say so;
//   g4  a replay is refused replay after a signed transfer.
//
// Usage:
//   node tools/measure-window-frame.js [--cli <path/to/bin/signerd.js>]
//        [--out <file>]
//   Exit 0 = honest everywhere, 1 = at least one defect face holds,
//   2 = harness failure.
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

// NO HOST PATHS in the artifact: basenames and byte counts only.
function scrub(p) { return path.basename(p); }

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-winframe-'));
fs.chmodSync(dir, 0o700);
const exit2 = (why) => {
  console.error(JSON.stringify({ verdict: 'HARNESS-FAIL', reason: why }));
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  process.exit(2);
};

const pass = path.join(dir, 'pass');
const keystore = path.join(dir, 'k.key');
const ledger = path.join(dir, 'l.jsonl');
const socket = path.join(dir, 'd.sock');
const runDir = path.join(dir, 'run');
fs.mkdirSync(runDir, { mode: 0o700 });
fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });

function sh(argv) {
  const r = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}
function jsonOut(r) {
  try { return JSON.parse(r.stdout.trim().split('\n').pop()); } catch { return null; }
}
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

if (sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]).status !== 0) {
  exit2('keygen failed');
}

const DEST = 'So11111111111111111111111111111111111111112';
const VOTE = 'Vote111111111111111111111111111111111111111';
const BLOCKHASH = '4wUkybwB9QMxybEMnEivvKRcnVUnJcncyA2kbLsrqtzB';
const WINDOW = '1000000'; // the README quickstart's second pairing scale

// Each scenario gets its own grant file and daemon, exactly like an operator.
let daemonSeq = 0;
const children = [];
function startDaemon(grantsFile) {
  daemonSeq += 1;
  const sock = path.join(dir, `d${daemonSeq}.sock`);
  const led = path.join(dir, `l${daemonSeq}.jsonl`);
  const child = spawnSync; // (documenting the import) real spawn below
  const proc = require('node:child_process').spawn(
    process.execPath, [cli, 'run', '--keystore', keystore, '--passphrase-file', pass,
      '--grants', grantsFile, '--ledger', led, '--socket', sock],
    { stdio: 'ignore', detached: true },
  );
  children.push(proc);
  // Wait until status --socket answers live (bounded).
  for (let i = 0; i < 50; i += 1) {
    const probe = sh(['status', '--socket', sock]);
    if (probe.status === 0 && probe.stdout.includes('"state":"live"')) return { sock, led };
    sleep(100);
  }
  exit2(`daemon for ${scrub(grantsFile)} did not come up`);
  return null;
}
process.on('exit', () => { for (const p of children) { try { p.kill(); } catch { /* gone */ } } });

function addGrant(file, name, dest, max, window) {
  const r = sh(['grant-add', '--grants', file, '--name', name,
    '--keystore', keystore, '--destination', dest,
    '--max-lamports', max, '--window-max-lamports', window,
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
  return { status: r.status, ok: /"ok":true/.test(r.stdout) };
}
function buildTx(to, lamports, out) {
  const r = sh(['build-tx', '--keystore', keystore, '--to', to,
    '--lamports', lamports, '--out', out, '--blockhash', BLOCKHASH]);
  return r.status === 0;
}
function sign(sock, grant, txFile) {
  const r = sh(['sign', '--socket', sock, '--grant', grant, '--tx', txFile]);
  const body = jsonOut(r);
  return { status: r.status, body, stderr: r.stderr };
}

const faces = [];
const push = (id, hold, observed) => faces.push({ id, hold, observed });

// ---- D1: BOTH README quickstart pairings, transfer AT maxLamports --------
const readmePairings = [
  { name: 'ops-24h', dest: DEST, max: '500000000', window: '500000000',
    where: 'README.md:68 / docs/GUIDE.md:24' },
  { name: 'ops-payroll', dest: VOTE, max: '1000000', window: '1000000',
    where: 'README.md:74 / docs/GUIDE.md:39' },
];
for (const pairing of readmePairings) {
  const grants = path.join(dir, `g-${pairing.name}.json`);
  const made = addGrant(grants, pairing.name, pairing.dest, pairing.max, pairing.window);
  if (!made.ok) exit2(`grant-add refused the README pairing ${pairing.max}/${pairing.window}`);
  const daemon = startDaemon(grants);
  const tx = path.join(dir, `tx-${pairing.name}.bin`);
  if (!buildTx(pairing.dest, pairing.max, tx)) exit2('build-tx failed');
  const attempt = sign(daemon.sock, pairing.name, tx);
  // Defect face: empty-window refusal at the grant's own cap, with the
  // self-contradicting report (D1 + D2 in one face per pairing).
  const isCap = attempt.body !== null && attempt.body.error === 'window_cap';
  const detail = isCap && attempt.body.detail ? attempt.body.detail : {};
  push(`d1_d2_readme_pairing_${pairing.name}_max${pairing.max}`,
    isCap && detail.windowSpentLamports === '0' &&
      detail.windowRemainingLamports === pairing.max,
    { where: pairing.where, exitCode: attempt.status,
      error: attempt.body === null ? null : attempt.body.error,
      windowSpentLamports: detail.windowSpentLamports ?? null,
      windowRemainingLamports: detail.windowRemainingLamports ?? null,
      fixNamesAppend: typeof attempt.body?.fix === 'string' &&
        attempt.body.fix.includes('grant-add') && attempt.body.fix.includes('--append'),
      journalRecords: fs.existsSync(daemon.led) ? fs.readFileSync(daemon.led, 'utf8').split('\n').filter(Boolean).length : 0 });
}

// The named repair of the last face, run as documented (D3): grant-add
// --append --name <the grant the refusal names> against the same file.
// grant-add answers failures on STDERR as `<code>: <detail>` (exit 1), so
// the code is read from there, not from a JSON body.
const g1 = path.join(dir, 'g-ops-24h.json');
const repair = sh(['grant-add', '--grants', g1, '--name', 'ops-24h', '--append',
  '--keystore', keystore, '--destination', DEST,
  '--max-lamports', '500000000', '--window-max-lamports', '500000000',
  '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z']);
const repairFirstLine = repair.stderr.split('\n')[0] || '';
const repairCode = repairFirstLine.split(':')[0].trim();
push('d3_named_repair_not_runnable',
  repair.status !== 0 && repairCode === 'grant_exists',
  { exitCode: repair.status, stderrCode: repairCode,
    stderrFirstLine: repairFirstLine.slice(0, 120) });

// ---- D4: the reachable ceiling is window - fee ---------------------------
{
  const grants = path.join(dir, 'g-ceiling.json');
  const made = addGrant(grants, 'ceil', VOTE, WINDOW, WINDOW);
  if (!made.ok) exit2('grant-add refused the ceiling pairing');
  const daemon = startDaemon(grants);
  const at = path.join(dir, 'tx-at.bin');
  const over = path.join(dir, 'tx-over.bin');
  if (!buildTx(VOTE, String(Number(WINDOW) - 5000), at)) exit2('build-tx failed');
  if (!buildTx(VOTE, String(Number(WINDOW) - 4999), over)) exit2('build-tx failed');
  const signsAt = sign(daemon.sock, 'ceil', at);
  const refusesOver = sign(daemon.sock, 'ceil', over);
  push('d4_ceiling_is_window_minus_fee',
    signsAt.status === 0 && refusesOver.body !== null && refusesOver.body.error === 'window_cap',
    { signsAt: signsAt.status === 0, atLamports: Number(WINDOW) - 5000,
      refusesOver: refusesOver.body !== null && refusesOver.body.error === 'window_cap',
      overLamports: Number(WINDOW) - 4999 });
}

// ---- D5: creation accepts a grant dead for ANY positive transfer ---------
{
  const grants = path.join(dir, 'g-dead.json');
  const made = addGrant(grants, 'dead-top', DEST, '500000000', '5000');
  const daemon = startDaemon(grants);
  const tx = path.join(dir, 'tx-dead.bin');
  if (!buildTx(DEST, '1', tx)) exit2('build-tx failed');
  const attempt = sign(daemon.sock, 'dead-top', tx);
  const isCap = attempt.body !== null && attempt.body.error === 'window_cap';
  const detail = isCap && attempt.body.detail ? attempt.body.detail : {};
  const ledLines = fs.existsSync(daemon.led)
    ? fs.readFileSync(daemon.led, 'utf8').split('\n').filter(Boolean).length : 0;
  push('d5_creation_accepts_dead_grant',
    made.ok && isCap && detail.windowSpentLamports === '0' && ledLines === 0,
    { creationOk: made.ok, error: attempt.body === null ? null : attempt.body.error,
      windowSpentLamports: detail.windowSpentLamports ?? null,
      journalRecordsAfter: ledLines });
}

// ---- Guards ---------------------------------------------------------------
{
  const grants = path.join(dir, 'g-guard.json');
  const made = addGrant(grants, 'guard', VOTE, WINDOW, WINDOW);
  if (!made.ok) exit2('grant-add refused the guard pairing');
  const daemon = startDaemon(grants);
  const inTx = path.join(dir, 'tx-in.bin');
  const againTx = path.join(dir, 'tx-again.bin');
  if (!buildTx(VOTE, '1000', inTx)) exit2('build-tx failed');
  if (!buildTx(VOTE, '1000', againTx)) exit2('build-tx failed');
  const first = sign(daemon.sock, 'guard', inTx);          // g2: small spend signs
  // g3: after the small spend, a capped refusal reports the TRUE spend.
  // The small transfer cost 1000 + 5000 fee = 6000 charged.
  const bigTx = path.join(dir, 'tx-big.bin');
  if (!buildTx(VOTE, WINDOW, bigTx)) exit2('build-tx failed');
  const capped = sign(daemon.sock, 'guard', bigTx);
  const capDetail = capped.body && capped.body.detail ? capped.body.detail : {};
  // g4: replay of the signed transfer.
  const replay = sign(daemon.sock, 'guard', inTx);
  // g1: a transfer at window - fee still signs on the FRESH scope.
  const grants2 = path.join(dir, 'g-guard2.json');
  addGrant(grants2, 'guard2', VOTE, WINDOW, WINDOW);
  const daemon2 = startDaemon(grants2);
  const atTx = path.join(dir, 'tx-at2.bin');
  if (!buildTx(VOTE, String(Number(WINDOW) - 5000), atTx)) exit2('build-tx failed');
  const atCeiling = sign(daemon2.sock, 'guard2', atTx);
  push('g1_transfer_at_window_minus_fee_signs',
    atCeiling.status === 0 && atCeiling.body !== null && atCeiling.body.ok === true,
    { signed: atCeiling.status === 0, lamports: Number(WINDOW) - 5000 });
  push('g2_small_transfer_signs',
    first.status === 0 && first.body !== null && first.body.ok === true,
    { signed: first.status === 0 });
  push('g3_post_spend_window_report_true',
    capped.body !== null && capped.body.error === 'window_cap' &&
      capDetail.windowSpentLamports === '6000' &&
      capDetail.windowRemainingLamports === String(Number(WINDOW) - 6000),
    { windowSpentLamports: capDetail.windowSpentLamports ?? null,
      windowRemainingLamports: capDetail.windowRemainingLamports ?? null });
  push('g4_replay_refused',
    replay.body !== null && replay.body.error === 'replay',
    { error: replay.body === null ? null : replay.body.error });
}

const guards = faces.filter((f) => f.id.startsWith('g'));
const defects = faces.filter((f) => !f.id.startsWith('g') && f.hold);
const guardBroken = guards.filter((f) => !f.hold).map((f) => f.id);
const verdict = defects.length === 0 ? 'window-frame-honest' : 'window-frame-fee-blind';

const result = {
  generatedAt: new Date().toISOString(),
  cli: scrub(cli),
  verdict,
  faces: faces.length,
  faceDefects: defects.length,
  defectIds: defects.map((f) => f.id),
  guardBroken,
  rows: faces,
  rules: ['cost-is-amount-plus-5000-base-fee', 'policy-judges-maxLamports-alone',
    'empty-window-refusal-reports-spent-0', 'named-repair-runs-elsewhere',
    'no-host-path'],
};
const out = JSON.stringify(result, null, 1);
if (args['--out']) {
  fs.mkdirSync(path.dirname(path.resolve(args['--out'])), { recursive: true });
  fs.writeFileSync(path.resolve(args['--out']), out + '\n');
}
process.stdout.write(out + '\n');
process.stderr.write(`\nVERDICT ${verdict}: ${defects.length} defect faces, ` +
  `guards broken: ${guardBroken.length}\n`);
try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
process.exit(defects.length === 0 ? 0 : 1);
