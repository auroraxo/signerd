#!/usr/bin/env node
'use strict';

/**
 * Measure the SOCKET PATH DOMAIN end to end: what the kernel allows, what
 * the PUBLISHED tag (v0.2.11) did with each case, and what this tree does.
 *
 * MEASURED, not argued:
 *   - the kernel's own limit comes from real bind+connect round trips
 *     (107/108/109 bytes), not from a header somebody read;
 *   - the baseline runs the CASES against `git archive v0.2.11` - the code a
 *     stranger installs - never against this working tree;
 *   - every case is a real CLI invocation (`run` / `sign`) in a throwaway
 *     home, and the verdict is derived from exit code + stderr text.
 *
 * Output: research/socket-path-domain-2026-11-09.json
 * Pinned by: test/socket-path-measurement.test.js
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'research', 'socket-path-domain-2026-11-09.json');

/** Bind+connect round trip at `len` bytes: the kernel's answer, measured. */
async function kernelRoundTrip(len) {
  const base = fs.mkdtempSync(path.join(os.homedir(), '.local', 'share', 'sockdom-'));
  const suffix = '/s.sock';
  const p = `${base}${'a'.repeat(len - base.length - suffix.length)}${suffix}`;
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  let verdict;
  try {
    const server = net.createServer((c) => c.end('ok'));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(p, resolve); });
    await new Promise((resolve, reject) => {
      const c = net.connect(p);
      c.once('error', reject);
      c.on('data', () => resolve());
      c.end();
    });
    verdict = 'bind+connect ok';
    server.close();
  } catch (err) {
    verdict = `refused: ${err.code || err.message}`;
  }
  // Cleanup NEVER decides the verdict: a socket path the server already
  // dropped makes unlink throw ENOENT, and that is not the kernel's answer
  // about the LENGTH (first run of this tool reported 107/108 as ENOENT for
  // exactly this reason).
  try { fs.unlinkSync(p); } catch { /* already gone */ }
  fs.rmSync(base, { recursive: true, force: true });
  return verdict;
}

/** Extract a tagged tree into a scratch dir (the published baseline). */
function extractTag(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `sockdom-${tag}-`));
  const res = spawnSync('sh', ['-c', `git archive ${tag} | tar -x -C "${dir}"`], { cwd: ROOT, encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`git archive ${tag} failed: ${res.stderr}`);
  fs.cpSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'), { recursive: true });
  return dir;
}

/** Build a throwaway home with keystore + grants + a real tx file. */
function makeHome(socketPath) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sockdom-home-'));
  const pass = path.join(dir, 'pass');
  fs.writeFileSync(pass, 'a passphrase for measurement only\n');
  fs.chmodSync(pass, 0o600);
  const keystore = path.join(dir, 'ops.key');
  const grantFile = path.join(dir, 'grants.json');
  const txFile = path.join(dir, 'tx.bin');
  fs.writeFileSync(txFile, Buffer.alloc(215));
  const cli = path.join(dir, 'cli.js');
  return { dir, pass, keystore, grantFile, txFile, cli, socketPath };
}

/**
 * Scrub the MEASURING HOST out of a stderr excerpt before it is committed.
 *
 * The refusal text embeds the socket path it was handed, and that path lives
 * in this machine's temp directory. A committed artifact that names the
 * measuring host is a snapshot, not a measurement (the same defect this
 * repo fixed for research/ in the v0.7.x line): the artifact keeps the byte
 * count, the code and the repair, and the path becomes a marker.
 */
function scrubExcerpt(text, socketPath) {
  return String(text)
    .split(socketPath).join('<socket-path>')
    .replace(/\/tmp\/[A-Za-z0-9._\-/ä]+/g, '<temp-path>')
    .replace(/\/home\/[A-Za-z0-9._\-/]+/g, '<home-path>');
}

function runCli(cliPath, home, args) {
  const res = spawnSync(process.execPath, [cliPath, ...args], {
    encoding: 'utf8', timeout: 30000, env: { ...process.env, HOME: home.dir },
  });
  return { status: res.status, stderr: res.stderr || '', stdout: res.stdout || '' };
}

/** Set up keystore+grants inside `home` using `cliPath`. */
function setUp(cliPath, home) {
  const k = runCli(cliPath, home, ['keygen', '--keystore', home.keystore, '--passphrase-file', home.pass]);
  if (k.status !== 0) throw new Error(`keygen failed: ${k.stderr}`);
  const g = runCli(cliPath, home, [
    'grant-add', '--grants', home.grantFile, '--name', 'ops', '--keystore', home.keystore,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z',
  ]);
  if (g.status !== 0) throw new Error(`grant-add failed: ${g.stderr}`);
}

/** The four cases, each named by the rule it exercises. */
function cases(base) {
  const mk = (bytes) => {
    const suffix = '/signerd.sock';
    return `${base}${'a'.repeat(bytes - base.length - suffix.length)}${suffix}`;
  };
  const multibyteDir = path.join(base, 'm');
  fs.mkdirSync(multibyteDir, { recursive: true, mode: 0o700 });
  const suffix = '/signerd.sock';
  // Target: exactly 90 CHARACTERS that are 135 BYTES. Each "ä" is one
  // character and two bytes, so 45 of them add 45 bytes without adding a
  // single character - the case the pre-fix check (characters vs 100)
  // could not see, and the one the OS rejects at 109 bytes.
  const multibyteRun = 45;
  const ascii = 90 - multibyteDir.length - multibyteRun - suffix.length;
  assert.ok(ascii >= 1, 'the fixture directory is too long to build a 90-character path');
  const multibyte = `${multibyteDir}${'a'.repeat(ascii)}${'ä'.repeat(multibyteRun)}${suffix}`;
  assert.equal(multibyte.length, 90, 'the path must be 90 characters');
  assert.equal(Buffer.byteLength(multibyte), 135, '... and 135 bytes');
  return [
    {
      id: 'over-limit-121',
      rule: 'S1/S2: a path over the kernel limit is refused with code, value and repair',
      socketPath: mk(121),
      argv: (h) => ['sign', '--socket', h.socketPath, '--grant', 'ops', '--tx', h.txFile],
      expect: (r) => r.status !== 0 && /socket_path_too_long: \S/.test(r.stderr)
        && /is 121 bytes/.test(r.stderr) && /^ {2}fix: /m.test(r.stderr)
        && !/EINVAL|undefined:undefined/.test(r.stderr),
    },
    {
      id: 'multibyte-90chars-135bytes',
      rule: 'S3: the unit is BYTES, not characters',
      socketPath: multibyte,
      argv: (h) => ['sign', '--socket', h.socketPath, '--grant', 'ops', '--tx', h.txFile],
      expect: (r) => r.status !== 0 && /socket_path_too_long: \S/.test(r.stderr)
        && /is 135 bytes/.test(r.stderr)
        && !/EINVAL/.test(r.stderr),    },
    {
      id: 'inside-domain-105',
      rule: 'S4: a path the kernel ACCEPTS must not be refused (the old false refusal)',
      socketPath: mk(105),
      // Not an argv run: the daemon must CONSTRUCT and START. Handled below.
      daemonStart: true,
      expect: null,
    },
  ];
}

async function measureDaemonStart(cliPath, socketPath, home) {
  // Start the daemon for a bounded window and read its stdout verdict.
  const { spawn } = require('node:child_process');
  const ledger = path.join(home.dir, 'journal.jsonl');
  const child = spawn(process.execPath, [
    cliPath, 'run', '--keystore', home.keystore, '--passphrase-file', home.pass,
    '--grants', home.grantFile, '--ledger', ledger, '--socket', socketPath,
  ], { env: { ...process.env, HOME: home.dir } });
  const out = await new Promise((resolve) => {
    let buf = '';
    const timer = setTimeout(() => { child.kill('SIGTERM'); resolve({ timedOut: true, buf }); }, 6000);
    child.stdout.on('data', (d) => {
      buf += d;
      if (buf.includes('\n')) { clearTimeout(timer); child.kill('SIGTERM'); resolve({ timedOut: false, buf }); }
    });
    child.on('exit', (code) => { clearTimeout(timer); resolve({ code, buf }); });
    child.stderr.on('data', (d) => { buf += d; });
  });
  await new Promise((r) => setTimeout(r, 300));
  try { fs.unlinkSync(socketPath); } catch { /* gone with the daemon */ }
  return out;
}

async function main() {
  const kernel = {};
  for (const len of [107, 108, 109]) kernel[`${len} bytes`] = await kernelRoundTrip(len);

  const publishedTag = 'v0.2.11';
  const baselineDir = extractTag(publishedTag);
  const baselineCli = path.join(baselineDir, 'bin', 'signerd.js');
  const fixedCli = path.join(ROOT, 'bin', 'signerd.js');

  const scratchBase = fs.mkdtempSync(path.join(os.tmpdir(), 'sockdom-paths-'));
  const rows = [];
  for (const c of cases(scratchBase)) {
    const row = { id: c.id, rule: c.rule, socketPathBytes: Buffer.byteLength(c.socketPath), socketPathChars: c.socketPath.length };

    // BASELINE: the published tag a stranger installs.
    {
      const home = makeHome(c.socketPath);
      setUp(baselineCli, home);
      if (c.daemonStart) {
        const started = await measureDaemonStart(baselineCli, c.socketPath, home);
        const ok = /"ok":true/.test(started.buf || '');
        row.baseline = ok ? 'daemon started, served ok' : `refused/crashed: ${scrubExcerpt((started.buf || '').trim().slice(0, 200), c.socketPath)}`;
        row.baselineConforms = ok;
      } else {
        const r = runCli(baselineCli, home, c.argv(home));
        row.baseline = { status: r.status, stderr: scrubExcerpt(r.stderr.trim().slice(0, 300), c.socketPath) };
        row.baselineConforms = c.expect(r);
      }
      fs.rmSync(home.dir, { recursive: true, force: true });
    }

    // THIS TREE.
    {
      const home = makeHome(c.socketPath);
      setUp(fixedCli, home);
      if (c.daemonStart) {
        const started = await measureDaemonStart(fixedCli, c.socketPath, home);
        const ok = /"ok":true/.test(started.buf || '');
        row.fixed = ok ? 'daemon started, served ok' : `refused/crashed: ${scrubExcerpt((started.buf || '').trim().slice(0, 200), c.socketPath)}`;
        row.fixedConforms = ok;
      } else {
        const r = runCli(fixedCli, home, c.argv(home));
        row.fixed = { status: r.status, stderr: scrubExcerpt(r.stderr.trim().slice(0, 300), c.socketPath) };
        row.fixedConforms = c.expect(r);
      }
      fs.rmSync(home.dir, { recursive: true, force: true });
    }
    rows.push(row);
  }

  fs.rmSync(scratchBase, { recursive: true, force: true });
  fs.rmSync(baselineDir, { recursive: true, force: true });

  const violations = rows.filter((r) => !r.baselineConforms).length;
  const conformFixed = rows.filter((r) => r.fixedConforms).length;
  const report = {
    tool: 'tools/measure-socket-path-domain.js',
    measuredAt: new Date().toISOString(),
    host: { platform: process.platform, node: process.version },
    baseline: `${publishedTag} (published tag, extracted with git archive)`,
    kernelDomain: {
      method: 'real bind+connect round trip at each byte length',
      limits: kernel,
      unit: 'bytes of the string handed to bind(), not characters',
    },
    cases: rows,
    verdict: {
      baselineViolations: violations,
      fixedConforms: conformFixed,
      ofCases: rows.length,
    },
  };
  if (violations === rows.length && conformFixed === rows.length) report.verdict.verdict = 'fixed';
  else report.verdict.verdict = 'unexpected';

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify(report.verdict, null, 2) + '\n');
}

main().catch((err) => { process.stderr.write(`${err.stack}\n`); process.exit(1); });
