#!/usr/bin/env node
// Measure, on TWO trees with the SAME probe: does `sign-message --add-grant`
// judge the BODY it bootstraps from, or only the grant it writes?
//
// WHAT IT MEASURES: the one-flag message bootstrap (bin/signerd.js, the
// --add-grant path) reads issuer/type/subject/claimKeys out of the --body
// file and writes a scope from them. The ENVELOPE (src/policy-message.js
// evaluateMessage) refuses bodies for six good reasons - a missing
// issued_at, a claim value over 256 characters, more than 32 claims, an
// unknown top-level key, claims that are not an object, a schema other than
// openreceipts/v1 - and one more (an issued_at more than 24h in the future).
//
// The cap-lag fix (16bea8e, 2026-11-14) made maxBytes cover the body; the
// SHAPE of the body was still unjudged. Measured on the published v0.2.25
// tree: the bootstrap reported {"ok":true,...,"bootstrapped":true} and wrote
// a scope for seven of the faces, and the FIRST sign of that very body was
// refused (envelope / claims / issued_at_in_future / invalid_schema). The
// scope was created FOR that body and could not sign it.
//
// The probe drives each tree's own CLI and, for every face, records:
//   - the bootstrap verdict (ok / bootstrapped / exit code),
//   - whether a grant was written,
//   - the FIRST sign of the SAME body against a live daemon (the pre-fix
//     tree answers the refusal here, the fixed tree refuses earlier).
// The control body (well formed) must be signed on BOTH trees: a control
// that fails means the instrument is broken, not the product.
//
// HOW: the pre-fix tree is materialized with `git archive <ref>` into a
// temp dir; node_modules are supplied through NODE_PATH (no network, no
// install). The daemon is the tree's own `signerd run`.
//
// Usage:
//   node tools/measure-bootstrap-body-judge.js \
//     --prefix 6ab3718 \
//     --out research/bootstrap-body-judge-v0.2.25-2026-11-15.json \
//     --out-fixed research/bootstrap-body-judge-fixed-2026-11-15.json
//
// EXIT: 0 when the measurement is sound AND the fixed tree refuses every
// defect face while the control still signs; 1 otherwise.

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn, execFileSync } = require('node:child_process');

const args = process.argv.slice(2);
function opt(name, fallback) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return args[i + 1];
}

const REPO = path.resolve(__dirname, '..');
const PREFIX = opt('prefix', null);
const OUT = opt('out', null);
const OUT_FIXED = opt('out-fixed', null);
const DEAD_SOCKET = '/tmp/signerd-measure-bodyjudge-none.sock';

function sh(cmd, opts = {}) {
  return spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, ...opts });
}

function materialize(ref) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-bodyjudge-'));
  const tar = execFileSync('git', ['-C', REPO, 'archive', ref], { maxBuffer: 256 * 1024 * 1024 });
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: tar, timeout: 120000 });
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  return dir;
}

function envFor() {
  return { ...process.env, NODE_PATH: path.join(REPO, 'node_modules') };
}

function baseBody() {
  return {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-15T21:00:00+00:00',
    claims: { 'message-grant': 'live' },
  };
}

// The faces: [name, what the face is, mutate, the envelope's own reason].
const FACES = [
  ['missing-issued-at', 'the body has no issued_at', (b) => { delete b.issued_at; }, 'envelope'],
  ['claim-value-too-long', 'a claim value of 257 characters', (b) => { b.claims.big = 'x'.repeat(257); }, 'claims'],
  ['too-many-claims', '33 claims (the ceiling is 32)', (b) => {
    b.claims = {};
    for (let i = 0; i < 33; i += 1) b.claims[`c${i}`] = 'v';
  }, 'claims'],
  ['unknown-top-level-key', 'the body carries an unknown key', (b) => { b.extra = 'nope'; }, 'envelope'],
  ['claims-not-an-object', 'claims is a string', (b) => { b.claims = 'not-a-map'; }, 'claims'],
  ['issued-at-in-future', 'issued_at is a year in the future', (b) => { b.issued_at = '2027-11-15T21:00:00+00:00'; }, 'issued_at_in_future'],
  ['wrong-schema', 'the schema is not openreceipts/v1', (b) => { b.schema = 'openreceipts/v2'; }, 'invalid_schema'],
];

function jsonLine(text) {
  const line = String(text || '').trim().split('\n').find((l) => l.startsWith('{'));
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
}

function caseDir(treeCli, tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-bodyjudge-${tag}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'measure body judge\n', { mode: 0o600 });
  const kg = sh([process.execPath, treeCli, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], { env: envFor() });
  if (kg.status !== 0) throw new Error(`keygen failed (${tag}): ${kg.stderr}`);
  // The daemon reads the grant file on EVERY request and refuses to start
  // without one (grant_file_unreadable). An EMPTY grant file (the product's
  // own shape) lets the daemon come up before the bootstrap writes the
  // scope - and the file is re-read per request, so the scope is picked up
  // afterwards.
  const grantsFile = path.join(cfg, 'grants.json');
  fs.writeFileSync(grantsFile, JSON.stringify({ version: 1, grants: {} }, null, 2) + '\n', { mode: 0o600 });
  return {
    root,
    cfg,
    keystore: path.join(cfg, 'ops.key'),
    pass,
    grants: grantsFile,
    socket: path.join(cfg, 's.sock'),
    ledger: path.join(cfg, 'journal.jsonl'),
  };
}

function writeBody(c, name, body) {
  const p = path.join(c.cfg, `${name}.json`);
  fs.writeFileSync(p, JSON.stringify(body, null, 2) + '\n');
  return p;
}

// Artifacts are committed: they must not carry host paths (the test pins
// that). Temp workdirs and the synthetic socket are replaced by their
// role names before a line of stderr lands in an artifact.
function redact(text) {
  return String(text)
    .replace(/\/tmp\/signerd-measure-bodyjudge-none\.sock/g, '<socket>')
    .replace(/\/tmp\/signerd-bodyjudge-[A-Za-z0-9-]+\/[A-Za-z0-9/_-]*/g, '<workdir>');
}

function bootstrap(treeCli, c, bodyPath, grantName) {
  const r = sh([process.execPath, treeCli, 'sign-message', '--socket', DEAD_SOCKET,
    '--grant', grantName, '--body', bodyPath,
    '--add-grant', '--keystore', c.keystore, '--grants', c.grants, '--dry'], { env: envFor() });
  const verdict = jsonLine(r.stderr);
  return {
    code: r.status,
    ok: verdict ? verdict.ok === true : false,
    bootstrapped: verdict ? verdict.bootstrapped === true : false,
    reason: (String(r.stderr).match(/\b([a-z_]+):/g) || []).slice(0, 1)[0]
      ? String(r.stderr).match(/\b([a-z_]+):/)[1] : null,
    stderr: redact(String(r.stderr)).slice(0, 300),
  };
}

function sign(treeCli, c, bodyPath, grantName) {
  const r = sh([process.execPath, treeCli, 'sign-message', '--socket', c.socket,
    '--grant', grantName, '--body', bodyPath], { env: envFor() });
  const parsed = jsonLine(r.stdout);
  return {
    ok: parsed ? parsed.ok === true : false,
    error: parsed ? (parsed.error || null) : null,
    raw: parsed ? null : String(r.stdout).slice(0, 200),
  };
}

// The daemon is started DETACHED with its own stdio: a child that inherits
// this process's stdout keeps the pipe open, and a spawnSync that waits for
// the pipe would block until its timeout and report NO pid - the daemon
// would then look "not started" although it was running.
function startDaemon(treeCli, c) {
  const child = spawn(process.execPath, [
    treeCli, 'run', '--keystore', c.keystore, '--passphrase-file', c.pass,
    '--grants', c.grants, '--ledger', c.ledger, '--socket', c.socket,
  ], { env: envFor(), detached: true, stdio: 'ignore' });
  child.unref();
  return child.pid && child.pid > 0 ? child.pid : null;
}

function waitForSocket(c, ms = 8000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try { if (fs.statSync(c.socket).isSocket()) return true; } catch { /* retry */ }
    spawnSync('sleep', ['0.1']);
  }
  return false;
}

function killDaemon(pid) {
  if (!pid) return;
  // Detached: the daemon leads its own process group, so the group is
  // signalled (children such as the lease helper go with it).
  try { process.kill(-pid, 'SIGTERM'); } catch { /* group gone */ }
  try { process.kill(pid, 'SIGTERM'); } catch { /* gone */ }
}

function grantNames(c) {
  if (!fs.existsSync(c.grants)) return [];
  try {
    return Object.keys(JSON.parse(fs.readFileSync(c.grants, 'utf8')).grants || {});
  } catch {
    return [];
  }
}

function runTree(treeCli, tag, ref) {
  const cases = [];
  const c = caseDir(treeCli, tag);

  // The CONTROL: a well-formed body. It must be signed on BOTH trees - a
  // control that fails means the instrument is broken.
  const controlPath = writeBody(c, 'control', baseBody());
  const controlBoot = bootstrap(treeCli, c, controlPath, 'g_control');
  const controlWritten = grantNames(c).includes('g_control');
  const pid = startDaemon(treeCli, c);
  const up = pid !== null && waitForSocket(c);
  let controlSign = { ok: false, error: 'daemon-not-started' };
  if (up) controlSign = sign(treeCli, c, controlPath, 'g_control');
  killDaemon(pid);

  const control = {
    case: 'control',
    control: true,
    bootstrap: controlBoot,
    grantWritten: controlWritten,
    firstSign: controlSign,
  };
  if (!controlBoot.ok || !controlWritten || controlSign.ok !== true) {
    throw new Error(`the control body was not signed on the ${tag} tree: ` +
      JSON.stringify(control).slice(0, 500));
  }
  cases.push(control);

  // The faces. Each one gets its own grant name in the SAME grant file; the
  // daemon re-reads the file on every request.
  const faceDir = caseDir(treeCli, `${tag}-face`);
  const facePid = startDaemon(treeCli, faceDir);
  const faceUp = facePid !== null && waitForSocket(faceDir);
  if (!faceUp) throw new Error(`the daemon did not start on the ${tag} tree`);

  for (const [name, what, mutate, reason] of FACES) {
    const body = baseBody();
    mutate(body);
    const bodyPath = writeBody(faceDir, name, body);
    const grantName = `g_${name.replace(/-/g, '_')}`;
    const boot = bootstrap(treeCli, faceDir, bodyPath, grantName);
    const wrote = grantNames(faceDir).includes(grantName);
    const firstSign = wrote ? sign(treeCli, faceDir, bodyPath, grantName)
      : { ok: false, error: null, skipped: 'no scope written' };
    cases.push({
      case: name,
      what,
      envelopeReason: reason,
      defectFace: true,
      bootstrap: boot,
      grantWritten: wrote,
      firstSign,
      // The defect: the bootstrap blessed a scope the envelope refuses.
      defect: boot.ok === true && boot.bootstrapped === true && wrote && firstSign.ok !== true,
    });
  }
  killDaemon(facePid);

  const defects = cases.filter((x) => x.defect);
  return {
    ref,
    verdict: defects.length > 0 ? 'bootstrap-body-not-judged' : 'bootstrap-body-judged',
    defectCount: defects.length,
    defectCases: defects.map((x) => x.case),
    cases,
  };
}

function main() {
  if (!PREFIX) throw new Error('--prefix <pre-fix ref> is required (the tree the faces are RED on)');
  if (!OUT || !OUT_FIXED) throw new Error('--out and --out-fixed are required');
  const started = new Date().toISOString();
  const preDir = materialize(PREFIX);
  const preCli = path.join(preDir, 'bin', 'signerd.js');
  const fixedCli = path.join(REPO, 'bin', 'signerd.js');
  const fixedRef = sh(['git', '-C', REPO, 'rev-parse', '--short', 'HEAD']).stdout.trim();

  const published = runTree(preCli, 'pre', PREFIX);
  published.measuredAt = started;
  published.what = 'does sign-message --add-grant judge the body it bootstraps from?';
  published.tree = { role: 'published', ref: PREFIX };

  const fixed = runTree(fixedCli, 'fixed', fixedRef);
  fixed.measuredAt = started;
  fixed.what = 'does sign-message --add-grant judge the body it bootstraps from?';
  fixed.tree = { role: 'fixed', ref: fixedRef };

  const answer = {
    measuredAt: started,
    what: 'does sign-message --add-grant judge the body it bootstraps from?',
    published,
    fixed,
    verdict: published.defectCount > 0 && fixed.defectCount === 0
      ? 'bootstrap-body-judged' : 'measurement-unsound',
    summary: `published tree (${PREFIX}): ${published.defectCount}/${FACES.length} defect faces; ` +
      `fixed tree (${fixedRef}): ${fixed.defectCount}/${FACES.length}`,
  };
  fs.writeFileSync(OUT, JSON.stringify(published, null, 2) + '\n');
  fs.writeFileSync(OUT_FIXED, JSON.stringify(fixed, null, 2) + '\n');
  console.log(JSON.stringify({
    verdict: answer.verdict,
    summary: answer.summary,
    publishedDefects: published.defectCases,
    fixedDefects: fixed.defectCases,
    out: [OUT, OUT_FIXED],
  }, null, 2));
  process.exit(answer.verdict === 'bootstrap-body-judged' ? 0 : 1);
}

main();
