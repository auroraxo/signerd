#!/usr/bin/env node
'use strict';
// Measure whether the GRANT-FILE WRITE PATHS will create a file the DAEMON
// refuses to run — one key per file, enforced at write time or not at all.
//
// WHY (measured 2026-11-17, tree after v0.2.31):
//
//   signerd holds exactly ONE key. `#reloadGrants()` (src/daemon.js) checks
//   EVERY grant in the file against that key and throws on the first
//   mismatch, so a single grant naming another key makes the daemon refuse
//   to START — and every request against every OTHER grant fails with it.
//
//   The write path disagrees. `grant-add --append` (extendGrantFile) and the
//   message bootstrap (addGrantToFile) run THE LOADER as their judge, and the
//   loader has no key to judge against: it validates shape, mode, owner,
//   directory, lease and seal — never agreement. So:
//
//     $ signerd grant-add --grants g.json --name good  --keystore a.key ...
//     {"ok":true,...}
//     $ signerd grant-add --grants g.json --name foreign --append \
//           --signer <some other pubkey> ...
//     {"ok":true,"appended":true,...}          <- written
//     $ signerd run --keystore a.key ... --grants g.json
//     grant_signer_mismatch: foreign           <- the WHOLE file is dead,
//                                                 including `good`
//
//   `ok:true` for a write the product itself will not read is the exact
//   class this repo has closed three times already: the keygen loop
//   (2026-11-05), the cap domain (2026-11-09), the past expiry
//   (2026-11-11), the non-canonical pubkey (2026-11-11). The house rule,
//   printed in src/grantadd.js three times over: "a file that would be
//   refused at run time is refused here".
//
//   The KEY is the same key in two encodings: a tx grant pins it base58 in
//   `signer`, a message grant pins it base64 in `pubkey` (messagePublicKey
//   is the raw key base64-encoded). Uniformity therefore has to compare the
//   DECODED 32 bytes, not the strings.
//
// FACES:
//   K1 append-foreign-tx      extendGrantFile with a signer that is not the
//                            file's key: is it written (ok:true) or refused?
//   K2 run-after-k1          does the daemon then refuse the FILE — and with
//                            it the grant that was perfectly valid before?
//   K3 append-foreign-msg    the message bootstrap (addGrantToFile) drops a
//                            message grant with a foreign pubkey into a file
//                            whose tx grant pins a different key
//   K4 append-same-key-msg   CROSS-ENCODING guard: a message grant whose
//                            pubkey is the SAME key as the file's tx signer
//                            must still be accepted (base64 vs base58)
//   K5 append-same-key-tx    the happy path: a second tx grant under the
//                            same signer must still be accepted
//   K6 remove-repairs        after a foreign grant is in the file,
//                            `grant-remove` of THAT name must make the file
//                            runnable again (the documented repair)
//
// A face is DEFECTIVE when the write path says ok:true for a file no daemon
// can run (K1/K3), or when the happy/cross-encoding paths are refused
// (K4/K5), or when the repair does not repair (K6). K2 is the BLAST RADIUS
// measurement: it counts how many grants stop working.
//
// Usage:
//   node tools/measure-grant-key-uniformity.js [--out <file>] [--published <dir>]
//
//   --published <dir>  measure an INSTALLED signerd (the published package)
//                      instead of this checkout.
//   --out <file>       where to write the JSON verdict (default:
//                      research/grant-key-uniformity-<date>.json).
//
// No network. No writes outside os.tmpdir() and the output file.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const args = process.argv.slice(2);
function argValue(flag) {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}
const publishedDir = argValue('--published');
const outFile = argValue('--out')
  || path.join('research', `grant-key-uniformity-${new Date().toISOString().slice(0, 10)}.json`);

const ROOT = path.resolve(__dirname, '..');
// With --published we load the INSTALLED package's sources, so the defect is
// measured on the bytes a stranger installs; otherwise this checkout.
const TARGET = publishedDir ? path.resolve(publishedDir) : ROOT;

/**
 * Resolve a dependency of the TARGET tree.
 *
 * An installed package hoists its dependencies to the APP's node_modules, so
 * the target's own node_modules often does not exist. Walk up from the
 * target until the module is found, and fall back to this checkout.
 */
function dep(name) {
  const candidates = [];
  let dir = TARGET;
  for (let i = 0; i < 6; i += 1) {
    candidates.push(path.join(dir, 'node_modules', name));
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  candidates.push(path.join(ROOT, 'node_modules', name));
  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (err) {
      if (!err || err.code !== 'MODULE_NOT_FOUND') throw err;
    }
  }
  throw new Error(`cannot resolve dependency ${name} from ${TARGET}`);
}

function req(rel) {
  return require(path.join(TARGET, 'src', rel));
}

const { writeGrantFile, extendGrantFile, addGrantToFile, removeGrantFromFile, buildTxGrant } =
  req('grantadd.js');
const { createKeystore, readKeystorePublicKey, loadKeystore } = req('keystore.js');
const { messagePublicKey } = req('signer-message.js');
const { Keypair } = dep('@solana/web3.js');
const bs58 = dep('bs58');
const decodeB58 = (s) => (bs58.default ? bs58.default.decode(s) : bs58.decode(s));

const FACE_LIST = [
  'K1', 'K2', 'K3', 'K4', 'K5', 'K6',
];

/** Run `fn` and turn anything it throws into a named outcome. */
function attempt(fn) {
  try {
    const value = fn();
    return { threw: false, code: null, value };
  } catch (err) {
    return { threw: true, code: (err && err.code) || (err && err.message) || 'unknown' };
  }
}

/** Start the daemon constructor the way `signerd run` does; does it refuse? */
function daemonRuns({ dir, keystore, grantFile }) {
  const { Daemon } = req('daemon.js');
  const out = attempt(() => {
    const d = new Daemon({
      socketPath: path.join(dir, 's-probe.sock'),
      keystorePath: keystore,
      passphrase: PASSPHRASE,
      grantFile,
      ledgerFile: path.join(dir, 'journal-probe.jsonl'),
    });
    return d;
  });
  if (out.threw) return { started: false, code: out.code };
  return { started: true, code: null };
}

const PASSPHRASE = 'measure-grant-key-uniformity';
const futureIso = () =>
  new Date(Date.now() + 48 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

function txGrant(signer, name) {
  return buildTxGrant({
    name,
    signer,
    destination: Keypair.generate().publicKey.toBase58(),
    maxLamports: '1000000',
    windowMaxLamports: '500000',
    windowSeconds: '3600',
    expiresAt: futureIso(),
  });
}

function msgGrant(pubkeyB64, name, issuer) {
  // The message schema is validated by src/grantfile.js; build it directly
  // so the measurement never depends on a CLI-only constructor.
  return {
    kind: 'message',
    issuer: issuer || 'measure',
    type: 'receipt',
    subject: 'key-uniformity',
    pubkey: pubkeyB64,
    maxBytes: '700',
    expiresAt: futureIso(),
    windowMaxMessages: '100',
    windowSeconds: '3600',
  };
}

const faces = {};
const notes = [];

function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-kuniform-'));
  fs.chmodSync(dir, 0o700);
  const keystore = path.join(dir, 'ops.key');
  const grantFile = path.join(dir, 'grants.json');

  createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const fileKeyBase58 = readKeystorePublicKey({ file: keystore });
  const foreignBase58 = Keypair.generate().publicKey.toBase58();

  // The file's OWN key, in both encodings: base58 for tx grants, base64 for
  // message grants (same 32 bytes — that is what makes K4 a real guard).
  const fileKeyBase64 = Buffer.from(decodeB58(fileKeyBase58)).toString('base64');

  // K0 sanity: the base58 and base64 spellings really are ONE key, and
  // messagePublicKey(keystore) agrees — otherwise K4 proves nothing.
  const keystoreKeyBase64 = messagePublicKey(
    loadKeystore({ file: keystore, passphrase: PASSPHRASE }),
  );
  const encodingsAgree = keystoreKeyBase64 === fileKeyBase64;

  // ---------------------------------------------------------------- create
  const created = attempt(() => writeGrantFile({
    file: grantFile, name: 'good', grant: txGrant(fileKeyBase58, 'good'),
  }));
  const createdOk = !created.threw;

  // ------------------------------------------------- K1 foreign tx append
  const k1 = createdOk
    ? attempt(() => extendGrantFile({
      file: grantFile, name: 'foreign', grant: txGrant(foreignBase58, 'foreign'),
    }))
    : { threw: true, code: 'setup_failed' };
  const k1Written = !k1.threw && k1.value && k1.value.appended === true;

  // ------------------------------------------------------- K2 blast radius
  // Count the grants that were servable BEFORE K1 and AFTER K1.
  const k2 = k1Written
    ? daemonRuns({ dir, keystore, grantFile })
    : { started: null, code: 'not_reached' };
  // Which grants are servable? The daemon refuses the whole file, so:
  const servableBefore = ['good'];
  const servableAfter = k2.started === true ? ['good', 'foreign'] : [];
  const collateral = servableBefore.filter((g) => !servableAfter.includes(g));

  // ---------------------------------------------------- K6 repair by remove
  // The repair must work on a file that is ALREADY poisoned - one written
  // before the fix existed, or hand-edited. So the poisoned file is built
  // here directly, not produced by K1 (which now refuses the write).
  const poisonedFile = path.join(dir, 'poisoned.json');
  fs.writeFileSync(poisonedFile, JSON.stringify({
    version: 1,
    grants: {
      good: txGrant(fileKeyBase58, 'good'),
      foreign: txGrant(foreignBase58, 'foreign'),
    },
  }, null, 2), { mode: 0o600 });
  const k6Before = daemonRuns({ dir, keystore, grantFile: poisonedFile });
  const k6Removed = attempt(() => removeGrantFromFile({
    file: poisonedFile, name: 'foreign',
  }));
  const k6 = !k6Removed.threw
    ? daemonRuns({ dir, keystore, grantFile: poisonedFile })
    : { started: null, code: 'not_reached' };

  // ------------------------------------------- K5 second tx, SAME signer
  const k5 = attempt(() => extendGrantFile({
    file: grantFile, name: 'good-2', grant: txGrant(fileKeyBase58, 'good-2'),
  }));
  const k5Ok = !k5.threw;

  // ---------------------------- K4 message grant, SAME key, other encoding
  const k4 = attempt(() => addGrantToFile({
    file: grantFile, name: 'receipts', grant: msgGrant(fileKeyBase64, 'receipts'),
  }));
  const k4Ok = !k4.threw;

  // --------------------------------- K3 message grant, FOREIGN key, into file
  const foreignKeyBase64 = Buffer.from(
    Keypair.generate().publicKey.toBytes(),
  ).toString('base64');
  const k3 = attempt(() => addGrantToFile({
    file: grantFile, name: 'rogue-receipts', grant: msgGrant(foreignKeyBase64, 'rogue-receipts', 'rogue'),
  }));
  const k3Written = !k3.threw && k3.value && k3.value.bootstrapped !== false;

  // Does the file survive all of that? Final blast radius measurement.
  const k2final = daemonRuns({ dir, keystore, grantFile });
  const finalServable = k2final.started === true
    ? ['good', 'good-2', 'receipts', 'rogue-receipts']
    : (k3Written && !k2final.started ? ['good', 'good-2', 'receipts'] : null);

  // ------------------------------------------------------------- record
  const k1Refused = k1.threw && typeof k1.code === 'string' && k1.code.startsWith('grant');
  faces.K1 = {
    name: 'append-foreign-tx',
    defect: k1Written,
    written: k1Written,
    verdict: k1Written ? 'ok:true, foreign signer written' : `refused: ${k1.code}`,
    detail: k1.threw ? String(k1.code) : JSON.stringify(k1.value),
  };
  faces.K2 = {
    name: 'run-after-foreign-tx',
    defect: k1Written && k2.started === false && collateral.length > 0,
    daemonStarted: k2.started,
    refusal: k2.code,
    servableBefore,
    servableAfter,
    collateralDamage: collateral,
    verdict: k1Written
      ? `daemon ${k2.started ? 'starts' : `refuses (${k2.code})`}; ` +
        `${collateral.length} previously-valid grant(s) stop working`
      : 'not reached (K1 refused the write)',
  };
  faces.K3 = {
    name: 'append-foreign-message',
    defect: k3Written,
    written: k3Written,
    verdict: k3Written
      ? 'ok:true, foreign-pubkey message grant written into a file pinned to another key'
      : `refused: ${k3.code}`,
    detail: k3.threw ? String(k3.code) : JSON.stringify(k3.value),
  };
  faces.K4 = {
    name: 'append-same-key-message-other-encoding',
    defect: !k4Ok,
    ok: k4Ok,
    encodingsAgree,
    verdict: k4Ok
      ? 'accepted (base64 pubkey == base58 signer, one key)'
      : `refused: ${k4.code} — same key rejected across encodings`,
  };
  faces.K5 = {
    name: 'append-same-key-tx',
    defect: !k5Ok,
    ok: k5Ok,
    verdict: k5Ok ? 'accepted' : `refused: ${k5.code} — the happy path broke`,
  };
  faces.K6 = {
    name: 'remove-repairs-the-file',
    defect: !(k6Removed.threw === false && k6.started === true),
    removeOk: k6Removed.threw === false,
    daemonBeforeRemove: k6Before.started,
    daemonAfterRemove: k6.started,
    refusal: k6.code,
    verdict: k6Removed.threw
      ? `grant-remove refused: ${k6Removed.code}`
      : (k6.started ? 'file runs again after removing the foreign grant'
        : `still refused after remove: ${k6.code}`),
  };

  // The verdict is the SHAPE of the disagreement: writes that no daemon can
  // read are DEFECTS (K1/K3); everything else must stay open.
  const writeFaceDefects = ['K1', 'K3'].filter((f) => faces[f].defect);
  const guardDefects = ['K4', 'K5', 'K6'].filter((f) => faces[f].defect);
  const verdict = writeFaceDefects.length > 0
    ? 'grant-file-key-uniformity-enforced-at-writetime'
    : 'grant-file-key-uniformity-held';
  const defectFaces = writeFaceDefects.length;
  const guardFaces = guardDefects.length;

  const result = {
    tool: 'measure-grant-key-uniformity',
    version: require(path.join(TARGET, 'package.json')).version,
    measured: publishedDir ? path.resolve(publishedDir) : 'checkout',
    measuredAt: new Date().toISOString(),
    faces,
    faceOrder: FACE_LIST,
    defectFaces,
    guardDefects,
    totalFaces: FACE_LIST.length,
    finalServable,
    notes,
    verdict,
  };

  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2) + '\n');

  const failing = writeFaceDefects.concat(guardDefects);
  process.stdout.write(
    `${result.verdict}: ${defectFaces} write-face defect(s), ` +
    `${guardDefects.length} guard defect(s) of ${FACE_LIST.length} faces\n`,
  );
  for (const f of FACE_LIST) {
    process.stdout.write(
      `  ${faces[f].defect ? 'DEFECT' : '  ok  '} ${f} ${faces[f].name}: ${faces[f].verdict}\n`,
    );
  }
  process.stdout.write(`artifact: ${outFile}\n`);
  if (failing.length > 0) process.exitCode = 1;
}

try {
  main();
} catch (err) {
  process.stderr.write(`grant-key-uniformity harness failed: ${err && err.stack}\n`);
  process.exit(3);
}
