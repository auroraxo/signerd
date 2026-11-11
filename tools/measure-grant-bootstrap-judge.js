#!/usr/bin/env node
// Measure the MESSAGE BOOTSTRAP's judgement of an EXISTING grant file on
// TWO trees: the PRE-FIX tree and the FIXED tree, with the SAME probe.
//
// WHAT IT MEASURES: whether `sign-message --add-grant` (the quickstart's
// one-flag bootstrap, src/grantadd.js addGrantToFile) refuses an existing
// grant file that the PRODUCT's own loader (src/grantfile.js) refuses —
// the rule the sibling write paths (`grant-add --append`, `grant-remove`)
// already keep — instead of hand-rolling a JSON.parse and writing anyway.
//
// The four defect faces (all measured live on the pre-fix tree
// 29fc8c5 = published v0.2.16, probes /tmp/pulseT*, /tmp/pulseU*):
//   B1  broken-file      an existing tx grant the loader refuses
//                        (windowMaxLamports:"1") — the bootstrap EXTENDED
//                        it and reported {"ok":true,"bootstrapped":true};
//                        `run` then died grant_field_invalid.
//   B2  mode-0664        a group-writable grant file was REWRITTEN at 0600
//                        while verify-grants and grant-add --append refuse
//                        it (grant_file_mode: 664) — the silent
//                        chmod-repair that manufactures trust.
//   B3  symlink          a symlink at the grant path was followed and
//                        REPLACED with a regular file (the defect
//                        grant-add measured 2026-11-05).
//   B4  exists-broken    a broken file that ALREADY held the grant name
//                        short-circuited to {"ok":true,...,"bootstrapped":false}
//                        — a success verdict for a dead-on-arrival file.
// The guards (must hold on BOTH trees — the fix must not break the
// documented quickstart): missing-file creation, valid-file extension,
// sealed-file refusal with the seal intact.
//
// HOW: each case runs the tree's own CLI (`node <tree>/bin/signerd.js
// sign-message ... --add-grant`) against a dead socket — the bootstrap
// verdict is fully observable before the request fails (quickstart
// ordering) — and records the verdict line, the refusal reason, and the
// file state (bytes, mode, link) before/after. The pre-fix tree is
// materialized with `git archive <ref>` into a temp dir; node_modules are
// supplied through NODE_PATH (no network, no install).
//
// Usage:
//   node tools/measure-grant-bootstrap-judge.js \
//     --prefix 29fc8c5 --out research/grant-bootstrap-judge-2026-11-11.json
//
// EXIT: 0 when the measurement is sound AND the fixed tree refuses every
// defect face with every guard holding; 1 otherwise (instrument unsound =
// the pre-fix tree does not show a face, or the fixed tree shows one).

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');

const args = process.argv.slice(2);
function opt(name, fallback) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return args[i + 1];
}

const OUT = opt('out', null);
const PREFIX = opt('prefix', null);
const REPO = path.resolve(__dirname, '..');
const DEAD_SOCKET = '/tmp/signerd-measure-bootstrap-none.sock';

const DESTINATION = 'So11111111111111111111111111111111111111112';

function sh(cmd, opts = {}) {
  return spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 120000, ...opts });
}

function materialize(ref) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-boot-judge-'));
  // git archive writes a BINARY tar stream: capture it as bytes, not text.
  const tar = execFileSync('git', ['-C', REPO, 'archive', ref], { maxBuffer: 256 * 1024 * 1024 });
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: tar, timeout: 120000 });
  if (untar.status !== 0) throw new Error(`tar extract failed: ${untar.stderr}`);
  return dir;
}

/** One isolated case directory with a keystore and a body. */
function caseDir(treeCli, tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `signerd-bootjudge-${tag}-`));
  const cfg = path.join(root, 'cfg');
  fs.mkdirSync(cfg, { mode: 0o700 });
  const pass = path.join(cfg, 'pass');
  fs.writeFileSync(pass, 'correct horse battery staple\n', { mode: 0o600 });
  const kg = sh([process.execPath, treeCli, 'keygen', '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', pass], { env: envFor() });
  if (kg.status !== 0) throw new Error(`keygen failed (${tag}): ${kg.stderr}`);
  const body = path.join(cfg, 'body.json');
  fs.writeFileSync(body, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'probe', type: 'release',
    subject: 'probe/repo',
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    claims: { version: 'v1' },
  }, null, 2));
  return { root, cfg, pass, body, grants: path.join(cfg, 'grants.json') };
}

function envFor() {
  return { ...process.env, NODE_PATH: path.join(REPO, 'node_modules') };
}

function bootstrap(treeCli, c) {
  const a = [process.execPath, treeCli, 'sign-message', '--socket', DEAD_SOCKET,
    '--grant', 'releases', '--body', c.body,
    '--out', path.join(c.root, 'out.json'),
    '--add-grant', '--keystore', path.join(c.cfg, 'ops.key'), '--grants', c.grants];
  const r = sh(a, { env: envFor() });
  return {
    status: r.status,
    stdout: r.stdout,
    stderr: r.stderr,
    okVerdict: /"ok":true/.test(r.stderr),
    bootstrappedTrue: /"bootstrapped":true/.test(r.stderr),
    reason: (r.stderr.match(/(grant_[a-z_]+|grant_field_invalid):/) || [])[1] || null,
  };
}

function fileState(p) {
  let st;
  try {
    st = fs.lstatSync(p);
  } catch (err) {
    return { isSymlink: false, missing: true, mode: null, bytes: null };
  }
  return {
    isSymlink: st.isSymbolicLink(),
    missing: false,
    mode: st.mode & 0o777,
    bytes: st.isSymbolicLink() ? null : fs.readFileSync(p, 'utf8'),
  };
}

function brokenDoc(name = 'broken') {
  return { version: 1, grants: { [name]: {
    signer: DESTINATION, destination: DESTINATION, maxLamports: '500000000',
    expiresAt: '2030-01-01T00:00:00Z', windowMaxLamports: '1', windowSeconds: '60',
  } } };
}

function runCase(treeCli, tag, name) {
  const c = caseDir(treeCli, tag);
  const events = [];

  if (name === 'broken') {
    fs.writeFileSync(c.grants, JSON.stringify(brokenDoc(), null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
  } else if (name === 'mode-0664') {
    const add = sh([process.execPath, treeCli, 'grant-add', '--grants', c.grants, '--name', 'ops-24h',
      '--keystore', path.join(c.cfg, 'ops.key'), '--destination', DESTINATION,
      '--max-lamports', '500000000', '--window-max-lamports', '500000000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { env: envFor() });
    if (add.status !== 0) throw new Error(`grant-add setup failed (${tag}/${name}): ${add.stderr}`);
    fs.chmodSync(c.grants, 0o664);
  } else if (name === 'symlink') {
    const target = path.join(c.cfg, 'real-target.json');
    const add = sh([process.execPath, treeCli, 'grant-add', '--grants', target, '--name', 'ops-24h',
      '--keystore', path.join(c.cfg, 'ops.key'), '--destination', DESTINATION,
      '--max-lamports', '500000000', '--window-max-lamports', '500000000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { env: envFor() });
    if (add.status !== 0) throw new Error(`grant-add setup failed (${tag}/${name}): ${add.stderr}`);
    fs.symlinkSync(target, c.grants);
    events.push('target=' + path.basename(target));
  } else if (name === 'exists-broken') {
    fs.writeFileSync(c.grants, JSON.stringify(brokenDoc('releases'), null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(c.grants, 0o600);
  } else if (name === 'valid') {
    const add = sh([process.execPath, treeCli, 'grant-add', '--grants', c.grants, '--name', 'ops-24h',
      '--keystore', path.join(c.cfg, 'ops.key'), '--destination', DESTINATION,
      '--max-lamports', '500000000', '--window-max-lamports', '500000000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { env: envFor() });
    if (add.status !== 0) throw new Error(`grant-add setup failed (${tag}/${name}): ${add.stderr}`);
  } else if (name === 'missing') {
    // nothing to prepare
  } else if (name === 'sealed') {
    const add = sh([process.execPath, treeCli, 'grant-add', '--grants', c.grants, '--name', 'ops-24h',
      '--keystore', path.join(c.cfg, 'ops.key'), '--destination', DESTINATION,
      '--max-lamports', '500000000', '--window-max-lamports', '500000000',
      '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { env: envFor() });
    if (add.status !== 0) throw new Error(`grant-add setup failed (${tag}/${name}): ${add.stderr}`);
    const sealPass = path.join(c.cfg, 'seal.pass');
    fs.writeFileSync(sealPass, 'the real seal phrase\n', { mode: 0o600 });
    const seal = sh([process.execPath, treeCli, 'seal-grants', '--grants', c.grants,
      '--seal-passphrase-file', sealPass], { env: envFor() });
    if (seal.status !== 0) throw new Error(`seal-grants setup failed (${tag}/${name}): ${seal.stderr}`);
    events.push('sealPassFile=' + sealPass);
  } else {
    throw new Error(`unknown case ${name}`);
  }

  const before = fileState(c.grants);
  const readTarget = () => {
    try {
      const st = fs.lstatSync(c.grants);
      if (!st.isSymbolicLink()) return null; // replaced with a regular file
      return fs.readFileSync(fs.readlinkSync(c.grants), 'utf8');
    } catch { return '<gone>'; }
  };
  const targetBefore = before.isSymlink ? readTarget() : null;
  const r = bootstrap(treeCli, c);
  const after = fileState(c.grants);
  const targetAfter = before.isSymlink ? readTarget() : null;

  const observed = {
    status: r.status,
    okVerdict: r.okVerdict,
    bootstrappedTrue: r.bootstrappedTrue,
    reason: r.reason,
    fileChanged: before.bytes !== after.bytes || before.missing !== after.missing,
    modeBefore: before.mode,
    modeAfter: after.mode,
    linkIntact: before.isSymlink && after.isSymlink,
    targetChanged: before.isSymlink ? targetBefore !== targetAfter : null,
  };
  return { case: name, observed, stderr: r.stderr.slice(0, 400) };
}

function classify(name, o) {
  // DEFECT: the bootstrap wrote (or blessed) a file the product refuses.
  switch (name) {
    case 'broken':
      return (o.okVerdict && o.fileChanged) ? 'defect' : 'refused';
    case 'mode-0664':
      return (o.okVerdict || o.fileChanged || o.modeAfter !== o.modeBefore) ? 'defect' : 'refused';
    case 'symlink':
      return (!o.linkIntact || o.targetChanged === true) ? 'defect' : 'refused';
    case 'exists-broken':
      return o.okVerdict ? 'defect' : 'refused';
    default:
      throw new Error(`classify: unknown face ${name}`);
  }
}

function guardVerdict(name, o) {
  switch (name) {
    case 'missing':
      return o.bootstrappedTrue ? 'holds' : 'broken';
    case 'valid':
      return (o.bootstrappedTrue && o.fileChanged) ? 'holds' : 'broken';
    case 'sealed':
      return (o.reason === 'grant_file_sealed' && !o.okVerdict) ? 'holds' : 'broken';
    default:
      throw new Error(`guardVerdict: unknown guard ${name}`);
  }
}

const FACES = ['broken', 'mode-0664', 'symlink', 'exists-broken'];
const GUARDS = ['missing', 'valid', 'sealed'];

function main() {
  if (!PREFIX) throw new Error('--prefix <pre-fix ref> is required (the tree the faces are RED on)');
  const started = new Date().toISOString();
  const preDir = materialize(PREFIX);
  const preCli = path.join(preDir, 'bin', 'signerd.js');
  const fixedCli = path.join(REPO, 'bin', 'signerd.js');
  const fixedRef = sh(['git', '-C', REPO, 'rev-parse', '--short', 'HEAD']).stdout.trim();

  const preFix = { ref: PREFIX, faces: {}, guards: {} };
  const fixed = { ref: fixedRef, faces: {}, guards: {} };

  for (const name of FACES) {
    preFix.faces[name] = runCase(preCli, 'pre', name);
    preFix.faces[name].classification = classify(name, preFix.faces[name].observed);
    fixed.faces[name] = runCase(fixedCli, 'fixed', name);
    fixed.faces[name].classification = classify(name, fixed.faces[name].observed);
  }
  for (const name of GUARDS) {
    preFix.guards[name] = runCase(preCli, 'pre', name);
    preFix.guards[name].classification = guardVerdict(name, preFix.guards[name].observed);
    fixed.guards[name] = runCase(fixedCli, 'fixed', name);
    fixed.guards[name].classification = guardVerdict(name, fixed.guards[name].observed);
  }

  const preFaceCount = FACES.filter((n) => preFix.faces[n].classification === 'defect').length;
  const fixedFaceCount = FACES.filter((n) => fixed.faces[n].classification === 'defect').length;
  const fixedGuardBroken = GUARDS.filter((n) => fixed.guards[n].classification !== 'holds').length;
  const preGuardBroken = GUARDS.filter((n) => preFix.guards[n].classification !== 'holds').length;

  const sound = preFaceCount === FACES.length; // the instrument MUST show every face on the pre-fix tree
  const fixedClean = fixedFaceCount === 0 && fixedGuardBroken === 0;
  const verdict = !sound ? `instrument-unsound:${FACES.length - preFaceCount}-faces-missing`
    : fixedClean ? 'violations-present -> refusals-present' : `fixed-tree-defective:${fixedFaceCount}-faces-${fixedGuardBroken}-guards`;

  const report = {
    tool: 'tools/measure-grant-bootstrap-judge.js',
    generatedAt: started.slice(0, 10),
    measuredAt: started,
    preFix,
    fixed,
    preFixFaceCount: preFaceCount,
    fixedFaceCount,
    fixedGuardBrokenCount: fixedGuardBroken,
    preFixGuardBrokenCount: preGuardBroken,
    verdict,
  };
  // A committed artifact that names the measuring host is a snapshot, not a
  // measurement: every case directory and the dead socket get replaced with
  // stable placeholders before anything is written.
  let serialized = JSON.stringify(report, null, 2);
  serialized = serialized
    .replace(/\/tmp\/signerd-bootjudge-(?:pre|fixed)-[A-Za-z0-9]+/g, '<case-dir>')
    .replace(/\/tmp\/signerd-measure-bootstrap-none\.sock/g, '<dead-socket>')
    .replace(/\/home\/[^"'\s]*/g, '<host-path>');

  if (OUT) {
    fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
    fs.writeFileSync(OUT, `${serialized}\n`, { mode: 0o644 });
  }
  process.stdout.write(`${JSON.stringify({ verdict, preFixFaceCount: preFaceCount, fixedFaceCount, fixedGuardBrokenCount: fixedGuardBroken, out: OUT })}\n`);
  fs.rmSync(preDir, { recursive: true, force: true });
  process.exit(sound && fixedClean ? 0 : 1);
}

main();
