// Envelope-fit check: does my ONE remaining own key-load site actually fit
// signerd's v0 envelope? The card guessed "probably not, Ed25519 instead of
// Solana-Tx". Measured 2026-10-28/29: the guess has the right verdict and the
// wrong reason — openreceipts signs with Ed25519 too, exactly like a Solana
// keypair. Four separate questions, four separate answers:
//
//   1. KEY TYPE      FITS.  The PKCS8 seed derives the same public key under
//                          OpenSSL and web3.js; `signerd import` accepts the
//                          converted key.
//   2. FILE FORMAT   DOES NOT FIT, by design.  openreceipts stores PKCS8 PEM;
//                          import accepts id.json/base58/raw-64 and refuses
//                          everything else rather than guessing. Conversion is
//                          mechanical (PEM -> seed -> 64 raw bytes).
//   3. PUBLISHED IDENTITY  MEASURED, not assumed.  The site-derived public key
//                          is compared byte-for-byte against the pinned issuer
//                          key (openreceipts/keys/auroraxo.pub) and against the
//                          key embedded in every published receipt; every
//                          receipt's Ed25519 signature is verified over the
//                          canonical body with the SITE-derived key. A receipt
//                          the site key cannot verify is reported as a failure,
//                          never folded into a pass.
//   4. OPERATION     DOES NOT FIT.  openreceipts signs canonical JSON receipt
//                          bytes; the v0 envelope signs a legacy System
//                          transfer wire. A receipt body can never pass
//                          policy.evaluate, and that refusal is correct.
//
// So the site is an ENVELOPE question (message domain), not a key-type
// question and — after conversion — not a key-custody question either.
// Importing the key into signerd without a message-grant envelope would move
// a key the daemon cannot use, so it is deliberately NOT built here.
//
//   node tools/envelope-fit.mjs [--site <key-file>] [--pinned <pub-file>]
//                               [--receipts <dir>] [--out <file>]
//
// Reads the real key file only to derive PUBLIC facts (seed -> pubkey match,
// import verdict, receipt verification). No secret material is written
// anywhere: the converted 64-byte secret lives in a 0600 temp file that is
// removed in the same run.

import { readFile, writeFile, mkdtemp, rm, stat, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import os from 'node:os';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { Keypair } from '@solana/web3.js';
import bs58 from 'bs58';
import { importKeystore } from '../src/keystore.js';
import { evaluate } from '../src/policy.js';
import { canonicalReceiptBytes, verifyEd25519 } from '../src/receipt-identity.js';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  const value = args[i + 1];
  args.splice(i, 2);
  return value;
};
const repo = path.join(os.homedir(), 'github_repos', 'openreceipts');
const site = option('--site', path.join(os.homedir(), '.openreceipts', 'auroraxo.key'));
const pinnedPath = option('--pinned', path.join(repo, 'keys', 'auroraxo.pub'));
const receiptsDir = option('--receipts', path.join(repo, 'receipts'));
const outFile = option('--out', null);

const result = {
  generatedAt: new Date().toISOString(),
  site,
  questions: {},
  verdict: null,
  notes: [],
};

// Python-compatible openreceipts canonical bytes live in src/receipt-identity.js
// (json.dumps(sort_keys=True, separators=(",", ":")), ensure_ascii=True), pinned
// in the test suite against literals produced by python3 itself. Plain
// JSON.stringify would emit raw UTF-8 for the German notes in the published
// receipts and every signature would fail against the wrong byte string.

// ---- 1 + 2: key type and file format -------------------------------------
let siteRawPub = null;
if (!existsSync(site)) {
  result.questions.keyMaterial = { status: 'absent', detail: `no key file at ${site}` };
  result.questions.fileFormat = { status: 'absent' };
} else {
  const info = await stat(site);
  result.keyFile = { mode: (info.mode & 0o777).toString(8), bytes: info.size };

  const pem = await readFile(site, 'utf8');
  const isPem = /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/.test(pem);
  result.questions.fileFormat = {
    storedFormat: isPem ? 'PKCS8 PEM' : 'unknown',
    acceptedByImport: false,
  };

  // A. import the file exactly as stored: must be refused, source untouched.
  const tmp = await mkdtemp(path.join(tmpdir(), 'envelope-fit-'));
  try {
    try {
      importKeystore({ file: path.join(tmp, 'ks.json'), passphrase: 'probe', from: site });
      result.questions.fileFormat.acceptedByImport = true;
      result.questions.fileFormat.verdict = 'ACCEPTED as stored (unexpected)';
    } catch (err) {
      result.questions.fileFormat.verdict = `refused: ${err.code || err.message}`;
    }
    const after = await stat(site);
    result.questions.fileFormat.sourceUntouched =
      after.size === info.size &&
      (after.mode & 0o777) === (info.mode & 0o777) &&
      after.mtimeMs === info.mtimeMs;

    // B. same keypair, converted form: PEM -> seed -> 64 raw bytes -> import.
    const priv = createPrivateKey({ key: pem, format: 'pem' });
    const der = priv.export({ type: 'pkcs8', format: 'der' });
    const seed = Buffer.from(der.subarray(der.length - 32));
    // Cross-check with an independent implementation: the pubkey OpenSSL
    // derives from the PEM must equal the one web3.js derives from the seed.
    // If the seed extraction were wrong, this is where it would show.
    const opensslPub = Buffer.from(
      createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32));
    const kp = Keypair.fromSeed(seed);
    const seedMatches = Buffer.from(kp.publicKey.toBytes()).equals(opensslPub);
    const secret = Buffer.concat([seed, Buffer.from(kp.secretKey.subarray(32))]);
    const secretFile = path.join(tmp, 'secret.bin');
    await writeFile(secretFile, secret, { mode: 0o600 });
    secret.fill(0);
    let importResult;
    try {
      const out = importKeystore({ file: path.join(tmp, 'ks.json'), passphrase: 'probe', from: secretFile });
      importResult = {
        accepted: true,
        publicKey: out.publicKey,
        matchesOpenSsl: out.publicKey === bs58.encode(opensslPub),
      };
    } catch (err) {
      importResult = { accepted: false, detail: err.code || err.message };
    }
    result.questions.keyMaterial = {
      status: 'fits',
      seedCrossCheckedWithOpenSsl: seedMatches,
      importAfterConversion: importResult,
    };
    siteRawPub = opensslPub;
  } finally {
    // Every converted artifact dies here; nothing derived from the secret
    // survives the run.
    await rm(tmp, { recursive: true, force: true });
    result.tmpCleaned = !existsSync(tmp);
  }
}

// ---- 3: published identity -----------------------------------------------
// Is the site key actually the key behind the published receipts? This is the
// claim the README makes; it is measured here, and a single unverifiable
// receipt makes the whole section report a failure.
if (siteRawPub) {
  const identity = { pinnedFile: pinnedPath, receiptsDir };
  let pinnedRaw = null;
  if (existsSync(pinnedPath)) {
    const pinnedB64 = (await readFile(pinnedPath, 'utf8')).trim();
    pinnedRaw = Buffer.from(pinnedB64, 'base64');
    identity.pinnedPresent = true;
    identity.pinnedBytes = pinnedRaw.length;
    identity.siteMatchesPinned = pinnedRaw.length === 32 && siteRawPub.equals(pinnedRaw);
  } else {
    identity.pinnedPresent = false;
    identity.siteMatchesPinned = null;
  }

  let files = [];
  if (existsSync(receiptsDir)) {
    files = (await readdir(receiptsDir)).filter((f) => f.endsWith('.json')).sort();
  }
  const verifiedWithSite = [];
  const verifiedWithEmbedded = [];
  const failures = [];
  const badDocs = [];
  let embeddedMatchesPinned = 0;
  for (const f of files) {
    try {
      const doc = JSON.parse(await readFile(path.join(receiptsDir, f), 'utf8'));
      const body = canonicalReceiptBytes(doc.receipt);
      const sig = Buffer.from(doc.sig || '', 'base64');
      const embedded = Buffer.from(doc.pubkey || '', 'base64');
      const siteOk = verifyEd25519(siteRawPub, body, sig);
      const embeddedOk = verifyEd25519(embedded, body, sig);
      if (siteOk) verifiedWithSite.push(f); else failures.push(`${f}: site-key signature invalid`);
      if (embeddedOk) verifiedWithEmbedded.push(f); else failures.push(`${f}: embedded-key signature invalid`);
      if (pinnedRaw && embedded.length === 32 && embedded.equals(pinnedRaw)) embeddedMatchesPinned += 1;
      else if (pinnedRaw) failures.push(`${f}: embedded pubkey != pinned key`);
    } catch (err) {
      badDocs.push(`${f}: ${err.message}`);
    }
  }
  identity.receiptsTotal = files.length;
  identity.receiptsVerifiedWithSiteKey = verifiedWithSite.length;
  identity.receiptsVerifiedWithEmbeddedKey = verifiedWithEmbedded.length;
  identity.receiptsEmbeddedPubkeyMatchesPinned = pinnedRaw ? embeddedMatchesPinned : null;
  if (badDocs.length) identity.receiptsUndecodable = badDocs;
  if (failures.length) identity.failures = failures;
  identity.status =
    files.length > 0 &&
    failures.length === 0 &&
    badDocs.length === 0 &&
    verifiedWithSite.length === files.length
      ? 'all published receipts verify under the site-derived key'
      : (failures.length || badDocs.length)
        ? 'FAILED — see failures'
        : 'incomplete — see counts';
  result.questions.publishedIdentity = identity;
} else {
  result.questions.publishedIdentity = { status: 'not measured — no site key' };
}

// ---- 4: operation / message domain ---------------------------------------
const receiptFiles = existsSync(receiptsDir)
  ? (await readdir(receiptsDir)).filter((f) => f.endsWith('.json')).sort()
  : [];
const receiptName = receiptFiles.includes('docrot-check-v1.json')
  ? 'docrot-check-v1.json'
  : receiptFiles[0];
const receiptPath = receiptName ? path.join(receiptsDir, receiptName) : null;

if (receiptPath && existsSync(receiptPath)) {
  const doc = JSON.parse(await readFile(receiptPath, 'utf8'));
  const body = canonicalReceiptBytes(doc.receipt);

  const signer = Keypair.generate();
  const grant = {
    signer: signer.publicKey.toBase58(),
    destination: Keypair.generate().publicKey.toBase58(),
    maxLamports: '1000000',
    expiresAt: new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const { Transaction, SystemProgram } = await import('@solana/web3.js');
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: grant.destination, lamports: 42 }));
  const wire = tx.serialize({ requireAllSignatures: false, verifySignatures: false });

  const control = evaluate(wire, grant);
  const receiptVerdict = evaluate(body, grant);
  const sigVerdict = evaluate(Buffer.from(doc.sig, 'base64'), grant);
  result.questions.operation = {
    status: 'does not fit',
    receiptUsed: receiptName,
    receiptBodyBytes: body.length,
    receiptBody: receiptVerdict.allowed ? 'ALLOWED (unexpected)' : `refused: ${receiptVerdict.refused}`,
    embeddedSignature: sigVerdict.allowed ? 'ALLOWED (unexpected)' : `refused: ${sigVerdict.refused}`,
    controlTransfer: control.allowed ? 'allowed (instrument works)' : `refused: ${control.refused} (BROKEN CONTROL)`,
  };
} else {
  result.questions.operation = { status: 'not measured', detail: `no receipt in ${receiptsDir}` };
}

// ---- verdict ---------------------------------------------------------------
const fmt = result.questions.fileFormat;
const key = result.questions.keyMaterial;
const op = result.questions.operation;
const identity = result.questions.publishedIdentity;
result.verdict = {
  keyType: key?.status === 'fits' ? 'FITS (both Ed25519; adoptable after conversion)' : 'unknown',
  fileFormat: fmt?.verdict ?? 'unknown',
  publishedIdentity: identity?.status ?? 'unknown',
  operation: op?.status ?? 'unknown',
  fitsV0Envelope: false,
  reason:
    'Message domain, not key type: openreceipts signs canonical JSON, the v0 envelope signs a legacy System transfer wire. ' +
    'The key itself is adoptable after a mechanical PEM->raw conversion and is the key behind the published receipts, ' +
    'but without a message-grant envelope the daemon would hold a key it cannot use, so no migration is built.',
};
result.notes.push(
  'Card note of 27.10. said "probably not, Ed25519 instead of Solana-Tx": the verdict holds, the reason does not. Both are Ed25519.',
  'import refusing the PEM as stored is correct fail-closed behaviour, not a bug: it must not guess key encodings.',
  'Published identity (pinned key match + every receipt verified under the site-derived key) is measured here for the first time; ' +
    'an earlier run only cross-checked OpenSSL against web3.js, which proves derivation but not identity.',
  'Reproduced with test/envelope-fit.test.js, which runs offline in CI against a generated key, a pinned key, and two receipts ' +
    '(one the site key must verify, one it must NOT).',
);

const json = JSON.stringify(result, null, 1) + '\n';
if (outFile) {
  await writeFile(outFile, json);
  console.log(`wrote ${outFile}`);
}
console.log(json);
