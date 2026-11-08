#!/usr/bin/env node
// Measure the two candidate answers to one question: does upgrading the pinned
// @solana/web3.js widen signerd's reach on REAL version-1 wire?
//
// WHY THIS TOOL EXISTS (measured 2026-11-02):
// README documented v1 as a ceiling: "the pinned @solana/web3.js 1.98.4 cannot
// deserialize v1 wire ... the daemon refuses them as invalid_wire". The open
// card decision was: upgrade the pin, or document v1 as an upper bound? Both
// branches were probed instead of argued:
//
//   * 1.99.0 (last 1.x) DESERIALIZES v1 but CANNOT SERIALIZE it, so the
//     policy's canonical round-trip check throws -> verdict stays
//     invalid_wire. Zero behavioural gain.
//   * 3.1.1 DESERIALIZES and ROUND-TRIPS v1 byte-exactly, so the policy
//     reaches its version rule and refuses version_or_alt - a named reason,
//     but still a refusal. The policy allows `version === 'legacy'` only, so
//     no parser can produce one additional approval without a separate,
//     unreviewed envelope scope change. Measured on the trial copy:
//     66 of 186 tests fail under 3.1.1 (major-version API migration).
//
// So this tool measures reach, not parseability: the product's OWN
// src/policy.js evaluate() is fed REAL v1 wire from a committed fixture, with
// a grant built from each transaction's own accounts, under whichever
// web3.js the running process resolves.
//
// Inputs: a committed fixture (test/fixtures/v1-wire-*.json), never a live
// RPC, so CI re-derives every published number.
//
// Candidate probes: --web3=<dir> (repeatable, label=dir) resolves
// @solana/web3.js from that directory and measures it too. Candidate sections
// are NOT re-derivable in CI (the packages are not installed there) and are
// marked reRunnable:false; the pinned section always is re-derivable.
//
// Exit codes: 0 = measurement complete; 3 = no verdict (empty fixture, rows
// whose pairing was not verified, or a product verdict that threw instead of
// answering).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));

function argValue(flag) {
  const eq = process.argv.find(a => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const i = process.argv.indexOf(flag);
  if (i > 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) {
    return process.argv[i + 1];
  }
  return null;
}

const FIXTURE = argValue('--fixture') || 'test/fixtures/v1-wire-2026-11-02.json';
const OUT = argValue('--out');
// Repeatable: --web3=<dir> or --web3=<label>=<dir>
const candidateDirs = [];
for (const arg of process.argv) {
  if (!arg.startsWith('--web3=')) continue;
  const value = arg.slice('--web3='.length);
  const eq = value.indexOf('=');
  candidateDirs.push(eq > 0
    ? { label: value.slice(0, eq), dir: value.slice(eq + 1) }
    : { label: `web3@${value}`, dir: value });
}

function resolveWeb3(fromDir) {
  const entry = require.resolve('@solana/web3.js', { paths: [fromDir] });
  let dir = path.dirname(entry);
  let version = 'unknown';
  for (;;) {
    const pj = path.join(dir, 'package.json');
    if (fs.existsSync(pj)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pj, 'utf8'));
        if (pkg.name === '@solana/web3.js') { version = pkg.version; break; }
      } catch { /* keep walking */ }
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return { web3: require(entry), entry, version };
}

// A well-formed, maximally permissive grant for the row under test. For
// shape-eligible rows the keys come from the transaction's own json view
// (the same best-case construction as tools/policy-traffic.mjs); for the
// remaining rows only the wire is measured, so constant valid keys are used
// and the verdict can only be about parsing and the version rule.
const CONST_SIGNER = '11111111111111111111111111111112';
const CONST_DEST = '11111111111111111111111111111113';
const GRANT_EXPIRES = '2099-01-01T00:00:00Z';
const NOW = new Date('2026-11-02T12:00:00.000Z');

function grantFor(row) {
  if (row.json && Array.isArray(row.json.accountKeys) && row.json.accountKeys.length >= 2) {
    return { signer: row.json.accountKeys[0], destination: row.json.accountKeys[1] };
  }
  return { signer: CONST_SIGNER, destination: CONST_DEST };
}

// The product's policy source, loaded with a BOUND @solana/web3.js.
//
// Why not just require('../src/policy.js')? Because that module closes over the
// web3.js that resolves from the repo's own node_modules - the PINNED one. A
// candidate probe would then measure the candidate's PARSER while the product
// still decided with the old library, which is not the question. The first
// draft of this tool did exactly that and reported "invalid_wire" for the
// 3.1.1 candidate; loading the SAME source against the candidate library
// reports the real "version_or_alt". The source under test is byte-identical
// either way; only the library binding differs.
//
// LOCAL MODULES (2026-11-08): src/policy.js now pulls its grant value rules
// from src/grantvalues.js (one copy shared with the loader and the creation
// path). A bare `require('./grantvalues')` would resolve against tools/ and
// die with MODULE_NOT_FOUND, so local ids are resolved against src/ and
// loaded recursively - WITH THE SAME CANDIDATE BINDING. grantvalues.js
// parses the public keys, so measuring it against the pinned library while
// policy.js ran on the candidate would be exactly the split this tool exists
// to avoid.
const srcCache = new Map();
function loadSrc(id, web3mod, seen) {
  if (id === '@solana/web3.js') return web3mod;
  const resolved = id.startsWith('.')
    ? path.resolve(path.join(HERE, '..', 'src'), id.endsWith('.js') ? id : `${id}.js`)
    : null;
  if (resolved === null) return require(id);
  if (seen.has(resolved)) return seen.get(resolved).exports;
  const module_ = { exports: {} };
  seen.set(resolved, module_);
  srcCache.set(`${resolved}|${web3mod === undefined ? 'pinned' : 'candidate'}`, module_);
  const src = fs.readFileSync(resolved, 'utf8');
  const boundRequire = (nextId) => loadSrc(nextId, web3mod, seen);
  // eslint-disable-next-line no-new-func
  new Function('require', 'module', 'exports', src)(boundRequire, module_, module_.exports);
  return module_.exports;
}

function loadPolicy(web3mod) {
  return loadSrc('./policy.js', web3mod, new Map()).evaluate;
}

function measure(label, web3mod, version, rows, reRunnable) {
  const evaluate = loadPolicy(web3mod);
  const probe = {
    label,
    pkgVersion: version,
    reRunnable,
    deserializes: 0,
    roundTripsByteExact: 0,
    productVerdicts: {},
    productApprovals: 0,
    // Verdicts split by the policy's own size cap. A row above 1232 bytes is
    // refused on SIZE before any parsing happens, so counting it together with
    // parse failures would let a size refusal masquerade as a parser result.
    productVerdictsUnderCap: {},
    productVerdictsOverCap: {},
    errors: {},
  };
  for (const row of rows) {
    const wire = Buffer.from(row.wireBase64, 'base64');
    // The product's own verdict - this is the number that is reach.
    const grant = { ...grantFor(row), maxLamports: '18446744073709551615', expiresAt: GRANT_EXPIRES };
    const verdict = evaluate(wire, grant, NOW);
    if (verdict === undefined || verdict === null || typeof verdict.allowed !== 'boolean') {
      const err = 'evaluate returned no verdict';
      probe.errors[err] = (probe.errors[err] || 0) + 1;
      continue;
    }
    const key = verdict.allowed ? 'allowed' : String(verdict.refused);
    probe.productVerdicts[key] = (probe.productVerdicts[key] || 0) + 1;
    const bucket = row.overPolicyCap ? probe.productVerdictsOverCap : probe.productVerdictsUnderCap;
    bucket[key] = (bucket[key] || 0) + 1;
    if (verdict.allowed) probe.productApprovals++;

    // Parseability of the library, for the reach explanation.
    try {
      const tx = web3mod.VersionedTransaction.deserialize(wire);
      probe.deserializes++;
      try {
        if (Buffer.from(tx.serialize()).equals(wire)) probe.roundTripsByteExact++;
      } catch (e) {
        const msg = `serialize: ${String(e && e.message || e).slice(0, 80)}`;
        probe.errors[msg] = (probe.errors[msg] || 0) + 1;
      }
    } catch (e) {
      const msg = `deserialize: ${String(e && e.message || e).slice(0, 80)}`;
      probe.errors[msg] = (probe.errors[msg] || 0) + 1;
    }
  }
  return probe;
}

const fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
const rows = fixture.rows || [];
if (!Array.isArray(rows) || rows.length === 0) {
  console.error(`v1-reach: fixture ${FIXTURE} holds no rows - NO VERDICT`);
  process.exit(3);
}

// Pairing verification: the json signature must physically occur in the wire.
// An unverified row would measure a different transaction than it describes.
const bs58 = require('bs58');
let unverified = 0;
for (const row of rows) {
  let sigBytes = null;
  try { sigBytes = Buffer.from(bs58.decode(row.signature)); } catch { sigBytes = null; }
  const wire = Buffer.from(row.wireBase64, 'base64');
  if (!sigBytes || !wire.includes(sigBytes)) unverified++;
  if (String(row.version) !== '1') unverified++; // this fixture is about v1
}
if (unverified > 0) {
  console.error(`v1-reach: ${unverified} rows failed pairing/version verification - NO VERDICT`);
  process.exit(3);
}

const pinned = resolveWeb3(process.cwd());

const report = {
  generatedAt: new Date().toISOString(),
  source: 'fixture',
  fixture: FIXTURE,
  question: 'does an @solana/web3.js upgrade widen signerd reach on version-1 wire?',
  totals: {
    rows: rows.length,
    shapeEligible: rows.filter(r => r.shape).length,
    underCap: rows.filter(r => !r.overPolicyCap).length,
    overCap: rows.filter(r => r.overPolicyCap).length,
    unverified,
  },
  probes: [
    measure('pinned', pinned.web3, pinned.version, rows, true),
  ],
  limits: [
    'One committed fixture of signature-verified version-1 wire; a sample, not the ecosystem.',
    'The grant is built from the transaction under test (best case): it asks whether the daemon would sign if allowed, never whether a grant would be issued.',
    'Reach is decided by the policy version rule (legacy only), not by the parser: a parser that reads v1 still refuses it.',
    'Candidate probes need the named package installed locally and are marked reRunnable:false.',
  ],
};

for (const c of candidateDirs) {
  try {
    const { web3, version } = resolveWeb3(c.dir);
    const probe = measure(c.label, web3, version, rows, false);
    probe.dir = c.dir;
    report.probes.push(probe);
  } catch (e) {
    console.error(`v1-reach: candidate ${c.label} at ${c.dir} unusable: ${String(e && e.message || e)}`);
    process.exit(3);
  }
}

const pinnedProbe = report.probes[0];
const json = JSON.stringify(report, null, 2) + '\n';
if (OUT) {
  fs.writeFileSync(OUT, json);
  console.error(`wrote ${OUT}`);
} else {
  process.stdout.write(json);
}

// A short human summary on stderr so a live run is readable.
const summary = report.probes
  .map(p => `${p.label}@${p.pkgVersion}: deserialize ${p.deserializes}/${report.totals.rows}, roundtrip ${p.roundTripsByteExact}/${report.totals.rows}, under-cap verdicts ${JSON.stringify(p.productVerdictsUnderCap)}, over-cap verdicts ${JSON.stringify(p.productVerdictsOverCap)}, approvals ${p.productApprovals}`)
  .join('\n  ');
console.error(`rows ${report.totals.rows} (shape-eligible ${report.totals.shapeEligible})\n  ${summary}`);
if (pinnedProbe.productVerdicts.threw || pinnedProbe.errors.evaluate) process.exit(3);
