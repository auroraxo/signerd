#!/usr/bin/env node
'use strict';

/**
 * MEASURE THE EXPIRY DOMAIN AT CREATION (2026-11-11).
 *
 * WHAT must hold: a grant the creation path WRITES must be one the daemon
 * can honour at least once. The window caps got this rule on 2026-11-09
 * (research/grant-cap-domain-2026-11-09.json); `expiresAt` is the same
 * existence claim on the time axis.
 *
 * WHY (measured on the published v0.2.17 tag, not this working tree):
 * the runtime rule is `nowMs >= expiry -> refused('expired')` (src/policy.js,
 * src/ledger.js), while the creation path judged `expiresAt` by its SHAPE
 * only. Faces:
 *   F1 `grant-add --expires 2020-01-01T00:00:00Z` -> exit 0, {"ok":true},
 *      file written; the FIRST request comes back {"ok":false,"error":
 *      "expired"}. The ok:true is the lie: a mistyped year manufactures a
 *      scope that can never sign.
 *   F2 `grant-add --append --expires <past>` -> exit 0, ok:true, the dead
 *      scope is appended into an EXISTING live grant file.
 *   F3 library faces (validateTxGrantArgs / validateMessageGrantArgs,
 *      the ones sign-message --add-grant builds through) accept it too.
 *
 * FOR EACH CASE, on BOTH trees:
 *   createOk   did the CLI creation path accept it (exit 0)?
 *   writeOk    was a file written?
 *   loadOk     does the product's loader accept the file?
 *   runtimeRefused  what does the product's own decision say for the
 *                   cheapest real request (policy + ledger, amount 0)
 *   contractHolds    createOk === false when runtime would be dead, i.e.
 *                    nothing dead-on-arrival is writable
 *
 * The runtime probe is the EXISTENCE claim: the loader may accept only
 * what the daemon CAN honour. A past expiry can never be honoured — not
 * "this request refuses" but "every request, forever".
 *
 * The baseline runs against `git archive v0.2.17` — the code a stranger
 * installs — never against this working tree. Exit 1 when the contract
 * does NOT hold on the FIXED tree, so the tool can gate a release.
 *
 * Output: research/expiry-at-creation-2026-11-11.json
 * Pinned by: test/expiry-at-creation-measurement.test.js
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'research', 'expiry-at-creation-2026-11-11.json');
const BASELINE_TAG = 'v0.2.17';
// The probe clock: every runtime verdict is taken AT this instant, so the
// artifact is reproducible and the "past/future" split does not drift with
// the wall clock of whoever runs the tool.
const NOW = new Date('2026-11-11T12:00:00.000Z');

const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const PAYER = Keypair.generate();
const RECIPIENT = Keypair.generate();

const TX_GOOD = {
  signer: PAYER.publicKey.toBase58(),
  destination: RECIPIENT.publicKey.toBase58(),
  maxLamports: '42',
  expiresAt: '2030-01-01T00:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

/**
 * The cases: one substitution into an otherwise good grant.
 *
 * 'defect' cases are instants the runtime can never honour; 'guard' cases
 * must keep being writable (an operator writes them on purpose).
 */
const CASES = [
  { field: 'expiresAt', value: '2020-01-01T00:00:00Z', label: 'expiry six years past', expect: 'defect' },
  { field: 'expiresAt', value: '2021-06-30T23:59:59Z', label: 'expiry far past (append face)', expect: 'defect' },
  { field: 'expiresAt', value: '2026-11-11T11:59:59Z', label: 'expiry one second before the probe clock', expect: 'defect' },
  { field: 'expiresAt', value: '2030-01-01T00:00:00Z', label: 'future expiry (the documented example)', expect: 'guard' },
  { field: 'expiresAt', value: '2099-01-01T00:00:00Z', label: 'far-future expiry', expect: 'guard' },
  // The SHAPE rule keeps its own reason: a non-existent instant must not be
  // re-labelled a liveness refusal (the 2026-11-08 value contract).
  { field: 'expiresAt', value: '2030-02-31T00:00:00Z', label: 'impossible day (shape, not liveness)', expect: 'guard' },
];

/** Extract a tagged tree into a scratch dir (the published baseline). */
function extractTag(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `expdom-${tag}-`));
  const res = spawnSync('sh', ['-c', `git archive ${tag} | tar -x -C "${dir}"`],
    { cwd: ROOT, encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`git archive ${tag} failed: ${res.stderr}`);
  fs.cpSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'), { recursive: true });
  return dir;
}

/**
 * The CLI creation face: the exact command an operator walks.
 * Returns { exit, wrote, firstLine, code } — no host paths in the result.
 */
function createViaCli(tree, grant, opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'expdom-create-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  const args = [path.join(tree, 'bin', 'signerd.js'), 'grant-add',
    '--grants', file, '--name', 'ops',
    '--signer', grant.signer, '--destination', grant.destination,
    '--max-lamports', grant.maxLamports,
    '--window-max-lamports', grant.windowMaxLamports,
    '--window-seconds', grant.windowSeconds,
    '--expires', grant.expiresAt];
  if (opts.append) {
    // Seed a LIVE grant first so --append has an existing file to extend.
    const seed = spawnSync(process.execPath, [path.join(tree, 'bin', 'signerd.js'), 'grant-add',
      '--grants', file, '--name', 'live',
      '--signer', grant.signer, '--destination', grant.destination,
      '--max-lamports', grant.maxLamports,
      '--window-max-lamports', grant.windowMaxLamports,
      '--window-seconds', grant.windowSeconds,
      '--expires', TX_GOOD.expiresAt],
    { encoding: 'utf8', timeout: 60000 });
    if (seed.status !== 0) return { exit: 'harness', wrote: false, changedBytes: false, firstLine: 'seed failed', code: 'harness' };
    const before = fs.readFileSync(file, 'utf8');
    args.push('--append');
    const res = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 60000 });
    const stderr = (res.stderr || '').trim();
    const firstLine = stderr.split('\n')[0] || '';
    const code = firstLine.split(':')[0].trim();
    // Honest face: did the REFUSED append still CHANGE the live file?
    const changedBytes = fs.readFileSync(file, 'utf8') !== before;
    return { exit: res.status, wrote: true, changedBytes, firstLine, code };
  }
  const res = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 60000 });
  const stderr = (res.stderr || '').trim();
  const firstLine = stderr.split('\n')[0] || '';
  const code = firstLine.split(':')[0].trim();
  return { exit: res.status, wrote: fs.existsSync(file), changedBytes: fs.existsSync(file), firstLine, code };
}

/** The loader's verdict for a grant, in a given tree (the product's reader). */
function loadVerdict(tree, grant) {
  const grantfile = require(path.join(tree, 'src', 'grantfile.js'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'expdom-load-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants: { ops: grant } }, null, 2) + '\n',
    { mode: 0o600 });
  try {
    grantfile.loadGrantFile(file);
    return { accepted: true, code: null };
  } catch (err) {
    return { accepted: false, code: err && err.code ? err.code : 'unknown' };
  }
}

/**
 * The daemon's own verdict for a grant, in a given tree: the policy layer
 * first, then the ledger. The probe is the CHEAPEST real request (amount 0,
 * the same existence probe as research/grant-cap-domain-2026-11-09.json).
 */
function runtimeVerdict(tree, grant) {
  const policy = require(path.join(tree, 'src', 'policy.js'));
  const ledgerMod = require(path.join(tree, 'src', 'ledger.js'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'expdom-led-'));
  fs.chmodSync(dir, 0o700);
  const ledger = new ledgerMod.Ledger({ file: path.join(dir, 'journal.jsonl') });
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT.publicKey, lamports: 0,
  }));
  tx.sign(PAYER);
  const wire = tx.serialize();
  const verdict = ledgerMod.gate(wire, grant, NOW, ledger);
  const pol = policy.evaluate(wire, grant, NOW);
  return {
    allowed: verdict.allowed === true,
    refused: verdict.refused || null,
    policyRefused: pol.refused || null,
  };
}

/** The library faces sign-message --add-grant builds through. */
function libraryFaces(tree, grant) {
  const grantadd = require(path.join(tree, 'src', 'grantadd.js'));
  const out = {};
  try {
    grantadd.validateTxGrantArgs({ name: 'ops', ...grant });
    out.txArgsAccepted = true;
    out.txArgsCode = null;
  } catch (err) {
    out.txArgsAccepted = false;
    out.txArgsCode = err.code || 'unknown';
  }
  try {
    grantadd.validateMessageGrantArgs({
      name: 'releases', issuer: 'acme', type: 'release', subject: 'acme/app',
      pubkey: require('node:crypto').randomBytes(32).toString('base64'),
      maxBytes: '700', windowMaxMessages: '5', windowSeconds: '3600',
      expiresAt: grant.expiresAt,
    });
    out.msgArgsAccepted = true;
    out.msgArgsCode = null;
  } catch (err) {
    out.msgArgsAccepted = false;
    out.msgArgsCode = err.code || 'unknown';
  }
  return out;
}

function measure(tree, tag) {
  const cases = [];
  for (const spec of CASES) {
    const grant = { ...TX_GOOD, [spec.field]: spec.value };
    const create = createViaCli(tree, grant);
    const append = spec.expect === 'defect' ? createViaCli(tree, grant, { append: true }) : null;
    const load = loadVerdict(tree, grant);
    const runtime = runtimeVerdict(tree, grant);
    const libs = libraryFaces(tree, grant);
    // The contract: nothing the runtime can NEVER honour may be writable.
    // For a 'defect' case the runtime must refuse AND creation must refuse;
    // for a 'guard' case creation must accept (no over-tightening).
    const contractHolds = spec.expect === 'defect'
      ? (create.exit !== 0 && !create.wrote && create.changedBytes === false
         && runtime.allowed === false && libs.txArgsAccepted === false
         && (append === null || (append.exit !== 0 && append.changedBytes === false)))
      : (spec.value === '2030-02-31T00:00:00Z'
        // The shape rule keeps its own reason (2026-11-08 contract): an
        // impossible date is refused as grant_field_invalid, NOT re-labelled
        // as the new liveness code, on BOTH trees.
        ? (create.exit !== 0 && create.code === 'grant_field_invalid')
        : (create.exit === 0 && create.wrote));
    cases.push({
      label: spec.label,
      value: spec.value,
      expect: spec.expect,
      createExit: create.exit,
      createWrote: create.wrote,
      createCode: create.code,
      appendExit: append ? append.exit : null,
      appendWrote: append ? append.wrote : null,
      appendChangedBytes: append ? append.changedBytes : null,
      appendCode: append ? append.code : null,
      loadAccepted: load.accepted,
      loadCode: load.code,
      runtimeAllowed: runtime.allowed,
      runtimeRefused: runtime.refused,
      library: libs,
      contractHolds,
    });
  }
  return { tag, cases };
}

// ---------------------------------------------------------------------------
const baselineDir = extractTag(BASELINE_TAG);
const baseline = measure(baselineDir, BASELINE_TAG);
const fixed = measure(ROOT, 'working-tree');

const defectCases = fixed.cases.filter((c) => c.expect === 'defect');
const contractOk = fixed.cases.every((c) => c.contractHolds);
// The baseline must SHOW the defect (create exit 0 + file written while the
// runtime refuses forever), otherwise the measurement proves nothing.
const baselineShowsDefect = defectCases.some((c) => {
  const b = baseline.cases.find((x) => x.value === c.value);
  return b && b.createExit === 0 && b.createWrote === true && b.runtimeAllowed === false;
});

const artifact = {
  measuredAt: new Date().toISOString(),
  tool: 'measure-expiry-at-creation',
  now: NOW.toISOString(),
  baseline: { tag: BASELINE_TAG, tree: `git archive ${BASELINE_TAG}` },
  fixed: { tree: 'working tree' },
  verdict: !baselineShowsDefect
    ? 'HARNESS-FAIL (baseline shows no defect — the measurement proves nothing)'
    : (contractOk ? 'contract-holds' : 'contract-violated'),
  defectFacesBaseline: defectCases.map((c) => {
    const b = baseline.cases.find((x) => x.value === c.value);
    return {
      value: c.value,
      baselineCreateExit: b.createExit,
      baselineCreateWrote: b.createWrote,
      baselineAppendExit: b.appendExit,
      baselineRuntimeRefused: b.runtimeRefused,
    };
  }),
  cases: fixed.cases.map((c, i) => ({
    label: c.label,
    value: c.value,
    expect: c.expect,
    contractHolds: c.contractHolds,
    baseline: {
      createExit: baseline.cases[i].createExit, createWrote: baseline.cases[i].createWrote,
      createCode: baseline.cases[i].createCode,
      appendExit: baseline.cases[i].appendExit, appendWrote: baseline.cases[i].appendWrote,
      appendChangedBytes: baseline.cases[i].appendChangedBytes,
      appendCode: baseline.cases[i].appendCode,
      loadAccepted: baseline.cases[i].loadAccepted, loadCode: baseline.cases[i].loadCode,
      runtimeAllowed: baseline.cases[i].runtimeAllowed,
      runtimeRefused: baseline.cases[i].runtimeRefused,
      library: baseline.cases[i].library,
    },
    fixed: {
      createExit: c.createExit, createWrote: c.createWrote, createCode: c.createCode,
      appendExit: c.appendExit, appendWrote: c.appendWrote, appendChangedBytes: c.appendChangedBytes,
      appendCode: c.appendCode,
      loadAccepted: c.loadAccepted, loadCode: c.loadCode,
      runtimeAllowed: c.runtimeAllowed, runtimeRefused: c.runtimeRefused,
      library: c.library,
    },
  })),
};

// Scrub host paths before writing (the house rule: no host paths in artifacts).
const json = JSON.stringify(artifact, null, 2)
  .replace(new RegExp(os.tmpdir().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '/tmp')
  .replace(/"([^"]*\/(?:expdom|expdom-create|expdom-load|expdom-led)-[^"]*)"/g, '"<scratch>"');
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${json}\n`);

console.log(JSON.stringify({
  verdict: artifact.verdict,
  baselineTag: BASELINE_TAG,
  defectFaces: artifact.defectFacesBaseline,
  contractOk,
}, null, 2));
process.exit(artifact.verdict === 'contract-holds' ? 0 : 1);
