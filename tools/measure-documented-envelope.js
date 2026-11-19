#!/usr/bin/env node
'use strict';
// MEASURE THE DOCUMENTED ENVELOPE: the front page's sign/refuse table must
// describe the policy the shipped tree actually runs.
//
// WHY (measured 2026-11-19, tree a9e2207): the README's "What it will and
// will not sign" table promised the DESIGNED v1 envelope —
// "System transfers, Memo, ComputeBudget" and "SPL Token Transfer /
// TransferChecked on allowlisted mints and destinations" under "Signs (v1)" —
// while the shipped `src/policy.js` signs EXACTLY ONE legacy System transfer
// and refuses everything else. Measured live on this tree's own policy:
//
//   system transfer                -> allowed             (the one admitted shape)
//   memo only                      -> refused "envelope"  (promised: signs)
//   compute-budget only            -> refused "envelope"  (promised: signs)
//   spl token transfer             -> refused "envelope"  (promised: signs)
//   transfer over the grant cap    -> refused "amount"    (the cap claim holds)
//   version-1 / ALT wire           -> refused "version_or_alt"
//
// A script scoping its grant by the front page gets the OPPOSITE of what it
// read: capabilities the page says are signed are refused, and the same
// table ships in the npm tarball a stranger installs (measured 2026-11-19:
// `npm pack signerd@0.2.40` -> package/README.md carries the identical
// lines), so the front page is the most-read surface this defect sits on.
//
// The claim family sits OUTSIDE every existing README gate, because those
// gates check DIFFERENT contracts:
//   - test/documented-surface.test.js: every documented INVOCATION runs
//     (flags/commands), not what the product DECIDES;
//   - test/release-contract.test.js: install pin, no cargo install,
//     quickstart anchor — not the envelope claim;
//   - test/installed-tag-journey.test.js: command dispatch, not policy.
//
// HOW IT JUDGES (one rule, both directions):
//   every Sign cell of the table is paired with a probe that builds the
//   shape that cell names, and the cell holds only if the PRODUCT's own
//   `evaluate()` returns exactly what the cell claims (`expect`).
//   - a cell naming a shape the policy refuses is an OVER-CLAIM (defect);
//   - a Sign cell matching no probe is UNREADABLE (defect — fail closed,
//     an unmeasurable claim must never read as clean);
//   - a `{refused: "..."}` example the source never mints is a claim about
//     a verdict the product cannot produce (the README quotes `alt`;
//     158 codes are minted in src/ and `alt` is not one of them).
//
// Guards (V3/V4): the REFUSES column's shapes must still refuse — the README
// fix may not widen the product to make the page true — and the controls
// keep passing on both trees.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function parseArgs(argv) {
  const out = { root: null, readme: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--root') out.root = argv[++i];
    else if (argv[i] === '--readme') out.readme = argv[++i];
    else if (argv[i] === '--out') out.out = argv[++i];
  }
  return out;
}

function scrub(text) {
  return String(text || '')
    .replace(/\/home\/[^\s"']+/g, '<home>')
    .replace(/\/tmp\/[^\s"']+/g, '<tmp>')
    .replace(/[A-Za-z]:\\[^\s"']+/g, '<win>');
}

// Probe via a CHILD process: the parent must not keep a second web3.js heap,
// and a policy throw must read as `unmeasured`, never as a clean verdict.
function probe(root, probeId, script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'docenv-probe-'));
  const file = path.join(dir, `${probeId}.js`);
  fs.writeFileSync(file, script);
  const r = spawnSync(process.execPath, [file], {
    encoding: 'utf8',
    timeout: 60000,
    cwd: root,
  });
  fs.rmSync(dir, { recursive: true, force: true });
  try { return JSON.parse(r.stdout || ''); } catch { return null; }
}

function policyProbeScript(root, buildFn, grantFn) {
  return `
const { createRequire } = require('module');
// Resolve dependencies FROM the tree under test: in a repo checkout that is
// root/node_modules, in an npm install it is hoisted to an ancestor
// node_modules — same rule the package's own code follows, so the probe
// measures the tree it was pointed at, never this process's dependencies.
const req = createRequire(${JSON.stringify(path.join(root, 'package.json'))});
const { Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction,
  ComputeBudgetProgram, VersionedTransaction, TransactionMessage } =
  req('@solana/web3.js');
const { evaluate } = require(${JSON.stringify(path.join(root, 'src', 'policy.js'))});
const signer = Keypair.generate();
const to = Keypair.generate().publicKey;
const other = Keypair.generate().publicKey;
const bh = Keypair.generate().publicKey.toBase58();
const now = new Date('2026-11-19T06:00:00Z');
const grant = (${grantFn})(signer, to);
function legacy(...ix) {
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = bh;
  for (const i of ix) tx.add(i);
  tx.sign(signer);
  return tx.serialize();
}
const wire = (${buildFn})({ signer, to, other, bh, legacy,
  TransactionInstruction, ComputeBudgetProgram, SystemProgram,
  VersionedTransaction, TransactionMessage, PublicKey });
process.stdout.write(JSON.stringify(evaluate(wire, grant, now)));
`;
}

// The grant a claim face is judged under: the maximally permissive grant for
// that shape (a claim that only holds under a narrower scope than the shape
// itself needs would still be an over-claim).
const maxGrant = (signer, to) => ({
  signer: signer.publicKey.toBase58(),
  destination: to.toBase58(),
  maxLamports: '1000000000',
  expiresAt: '2027-01-01T00:00:00Z',
});

// A cap-grant with a low ceiling: the "Within per-transaction and
// rolling-window caps" cell is held by an OVER-cap transfer refusing.
const capGrant = (signer, to) => ({
  signer: signer.publicKey.toBase58(),
  destination: to.toBase58(),
  maxLamports: '41',
  expiresAt: '2027-01-01T00:00:00Z',
});

// Every Sign cell of the README table, read from the README itself — never
// from a hand-kept copy: a new cell is a new claim face.
function readTable(readmeText) {
  const section = readmeText.split('## What it will and will not sign')[1];
  if (!section) throw new Error('README has no envelope-claim section');
  const table = section.split(/\n## /)[0];
  const rows = table.split('\n').filter((l) => /^\|/.test(l) && !/^\|\s*-/.test(l));
  const signCells = [];
  const refuseCells = [];
  // Row 0 is the header (Signs | Refuses); sign = field 1, refuse = field 2.
  for (const row of rows.slice(1)) {
    const cells = row.split('|').map((c) => c.trim());
    if (cells[1]) signCells.push(cells[1]);
    if (cells[2]) refuseCells.push(cells[2]);
  }
  if (signCells.length === 0) throw new Error('README envelope table has no Sign cells');
  return { signCells, refuseCells, table };
}

const args = parseArgs(process.argv.slice(2));
if (!args.root || !args.readme) {
  process.stderr.write('usage: measure-documented-envelope.js --root <repo> --readme <README.md> [--out <file>]\n');
  process.exit(2);
}
const root = path.resolve(args.root);
const readmeText = fs.readFileSync(args.readme, 'utf8');
const { signCells, refuseCells } = readTable(readmeText);

const messageProbeScript = (root, buildFn, grantFn) => `
const { evaluateMessage } = require(${JSON.stringify(path.join(root, 'src', 'policy-message.js'))});
const now = new Date('2026-11-19T06:00:00Z');
const grant = (${grantFn})();
const body = (${buildFn})();
const v = evaluateMessage(body, grant, now);
process.stdout.write(JSON.stringify(v.allowed === true
  ? { allowed: true, amountLamports: String(v.messageBytes.length) }
  : { allowed: false, refused: v.refused }));
`;

// The message-grant scope a receipt claim is judged under: the product's own
// shape for a message grant (kind/issuer/type/subject/pubkey/maxBytes/window/
// expiry), pinned to a fixed key — public data only, no secrets involved.
const messageGrant = () => ({
  kind: 'message',
  issuer: 'auroraxo',
  type: 'build-attestation',
  subject: 'auroraxo/signerd',
  // 32 zero bytes, canonical base64 — a CLAIM shape, not a signing key: this
  // face asks whether the envelope ADMITS the body, not whether a signature
  // verifies (that is test/message-e2e.test.js's job).
  pubkey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  maxBytes: '700',
  windowMaxMessages: '100',
  windowSeconds: '3600',
  expiresAt: '2027-01-01T00:00:00Z',
});

// ONE face per claim: `re` matches the Sign cell that makes the claim,
// `script` builds the shape, `expect` is what the product must say for the
// claim to hold (`allowed` | `refused:<code>`).
const signFaces = [
  { id: 'system_transfer', re: /System transfers?/i,
    expect: 'allowed',
    script: policyProbeScript(root,
      ({ legacy, SystemProgram, signer, to }) =>
        legacy(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: to, lamports: 42 })),
      maxGrant) },
  { id: 'memo', re: /\bMemo\b/i,
    expect: 'allowed',
    script: policyProbeScript(root,
      ({ legacy, PublicKey, TransactionInstruction }) =>
        legacy(new TransactionInstruction({
          programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
          keys: [], data: Buffer.from('hi') })),
      maxGrant) },
  { id: 'compute_budget', re: /ComputeBudget/i,
    expect: 'allowed',
    script: policyProbeScript(root,
      ({ legacy, ComputeBudgetProgram }) =>
        legacy(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 })),
      maxGrant) },
  { id: 'spl_token_transfer', re: /SPL Token/i,
    expect: 'allowed',
    script: policyProbeScript(root,
      ({ legacy, PublicKey, TransactionInstruction, signer, to, other }) => {
        const token = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
        // classic SPL Token Transfer (tag 3) over the README's own claim:
        // source, destination, authority.
        const data = Buffer.concat([Buffer.from([3]), Buffer.from([42, 0, 0, 0, 0, 0, 0, 0])]);
        return legacy(new TransactionInstruction({ programId: token, keys: [
          { pubkey: signer.publicKey, isSigner: true, isWritable: true },
          { pubkey: to, isSigner: false, isWritable: true },
          { pubkey: other, isSigner: false, isWritable: false },
        ], data }));
      },
      maxGrant) },
  { id: 'spend_cap', re: /(per-transaction and rolling-window caps|window)/i,
    expect: 'refused:amount',
    script: policyProbeScript(root,
      ({ legacy, SystemProgram, signer, to }) =>
        legacy(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: to, lamports: 42 })),
      capGrant) },
  { id: 'message_receipt', re: /(receipt body|message grant|openreceipts)/i,
    expect: 'allowed',
    script: messageProbeScript(root,
      () => ({
        schema: 'openreceipts/v1',
        issuer: 'auroraxo',
        type: 'build-attestation',
        subject: 'auroraxo/signerd',
        claims: { commit: 'a9e2207', suite: '869' },
        issued_at: '2026-11-19T06:00:00+00:00',
      }),
      messageGrant) },
];

// REFUSES-column guards: these shapes must still refuse on both trees — a
// README fix that widens the product instead of telling the truth must not
// pass this instrument.
const refuseGuards = [
  { id: 'alt_lookup_wire', re: /Address lookup tables/i, expect: 'refused:version_or_alt',
    script: policyProbeScript(root,
      ({ TransactionMessage, VersionedTransaction, SystemProgram, signer, to, bh }) => {
        const msg = new TransactionMessage({
          payerKey: signer.publicKey, recentBlockhash: bh,
          instructions: [SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: to, lamports: 42 })],
        });
        return new VersionedTransaction(msg.compileToV0Message()).serialize();
      },
      maxGrant) },
  { id: 'cpi_capable_program', re: /call other programs/i, expect: 'refused:program',
    script: policyProbeScript(root,
      ({ legacy, PublicKey, TransactionInstruction, signer, to }) => {
        const whirlpool = new PublicKey('whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc');
        return legacy(new TransactionInstruction({ programId: whirlpool, keys: [
          { pubkey: signer.publicKey, isSigner: true, isWritable: true },
          { pubkey: to, isSigner: false, isWritable: true },
        ], data: Buffer.from([1, 2, 3]) }));
      },
      maxGrant) },
  { id: 'token_2022', re: /Token-2022/i, expect: 'refused:program',
    script: policyProbeScript(root,
      ({ legacy, PublicKey, TransactionInstruction, signer, to }) => {
        const token2022 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
        return legacy(new TransactionInstruction({ programId: token2022, keys: [
          { pubkey: signer.publicKey, isSigner: true, isWritable: true },
          { pubkey: to, isSigner: false, isWritable: true },
        ], data: Buffer.from([3, 42, 0, 0, 0, 0, 0, 0, 0]) }));
      },
      maxGrant) },
];

function verdictLabel(v) {
  if (v === null || v === undefined) return 'unmeasured';
  if (v.allowed === true) return `allowed${v.amountLamports ? `:${v.amountLamports}` : ''}`;
  return `refused:${v.refused}`;
}

const results = [];

for (const face of signFaces) {
  const matchedCells = signCells.filter((c) => face.re.test(c));
  if (matchedCells.length === 0) continue; // not claimed on this README
  const measured = probe(root, face.id, face.script);
  const label = verdictLabel(measured);
  // `allowed` carries the approved amount (`allowed:42`); the claim holds
  // when the shape is ADMITTED, not when it spends the same lamports.
  const holds = face.expect === 'allowed'
    ? /^allowed/.test(label)
    : label === face.expect;
  const defect = !holds;
  results.push({
    id: face.id, kind: 'sign-claim', claimedCells: matchedCells,
    expected: face.expect, measured: label, defect,
    why: holds
      ? `claimed and the product admits the shape (${label})`
      : `claimed as "${matchedCells.join(' / ')}" but the product says ${label} (expected ${face.expect})`,
  });
}

for (const guard of refuseGuards) {
  const matchedCells = refuseCells.filter((c) => guard.re.test(c));
  const measured = probe(root, guard.id, guard.script);
  const label = verdictLabel(measured);
  const defect = label !== guard.expect;
  results.push({
    id: guard.id, kind: 'refuse-guard', claimedCells: matchedCells,
    expected: guard.expect, measured: label, defect,
    why: !defect
      ? `still refuses ${label.replace('refused:', '')} (guard holds)`
      : `the REFUSES column says ${guard.expect} but the product says ${label} — the fix must not widen the product`,
  });
}

// Fail closed: a Sign cell with no probe behind it is an unmeasurable claim.
const uncoveredCells = signCells.filter((c) => !signFaces.some((f) => f.re.test(c)));
results.push({
  id: 'claims_readable', kind: 'coverage', claimedCells: uncoveredCells,
  expected: 'every Sign cell has a probe', measured: uncoveredCells.length === 0 ? 'covered' : 'uncovered',
  defect: uncoveredCells.length > 0,
  why: uncoveredCells.length === 0
    ? `all ${signCells.length} Sign cells match a measured probe`
    : `Sign cell matches no probe: ${uncoveredCells.join(' | ')}`,
});

// A `{refused: "..."}` example the source never mints is a claim about a
// verdict the product cannot produce.
const srcAll = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.js$/.test(e.name)) srcAll.push(fs.readFileSync(p, 'utf8'));
  }
})(path.join(root, 'src'));
const minted = new Set();
for (const s of srcAll) {
  for (const m of s.matchAll(/(?:refused|fail|ledgerError|ledgerRefusal|operatorFileRefusal|passphraseReadRefusal|missingFlagRefusal)\(\s*'([a-z_0-9]+)'/g)) minted.add(m[1]);
  for (const m of s.matchAll(/error:\s*'([a-z_0-9]+)'/g)) minted.add(m[1]);
  for (const m of s.matchAll(/code:\s*'([a-z_0-9]+)'/g)) minted.add(m[1]);
}
const quotedRefusals = [...readmeText.matchAll(/\{refused: "([a-z_0-9]+)"/g)].map((m) => m[1]);
const unmintedExamples = quotedRefusals.filter((c) => !minted.has(c));
results.push({
  id: 'refusal_example_minted', kind: 'example-code',
  claimedCells: quotedRefusals.map((c) => `{refused: "${c}"}`),
  expected: 'every quoted code exists in src/', measured: unmintedExamples.length ? `unminted:${unmintedExamples.join(',')}` : 'all-minted',
  defect: unmintedExamples.length > 0,
  why: unmintedExamples.length
    ? `the README quotes {refused: "${unmintedExamples.join('", "')}" } and src/ mints no such code (${minted.size} minted)`
    : `every quoted refusal code exists in src/ (${minted.size} minted)`,
});

const defects = results.filter((r) => r.defect);
const verdict = defects.length === 0 ? 'documented-envelope-truthful' : 'documented-envelope-overclaim';
const result = {
  generatedAt: new Date().toISOString(),
  root: scrub(root),
  readme: scrub(args.readme),
  verdict,
  faces: results.length,
  faceDefects: defects.length,
  results,
  quotedRefusalExamples: quotedRefusals,
  mintedCodeCount: minted.size,
};
if (args.out) fs.writeFileSync(args.out, `${JSON.stringify(result, null, 1)}\n`);
process.stdout.write(`${JSON.stringify(result, null, 1)}\n`);
process.exit(defects.length === 0 ? 0 : 1);
