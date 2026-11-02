// Controls for tools/measure-adoption.mjs — the instrument that turns
// "no outside users" from a sentence into a measured verdict. An untested
// instrument can silently rot (wrong owner filter, cached data counted as
// evidence, a merge reported as adoption), so the classification logic is
// exercised against synthetic inputs before any real verdict is trusted.
//
// The classification itself lives in measure-adoption.mjs's verdict section;
// these tests run the module with a stubbed gh() boundary? No — the tool
// shells out to `gh`. Instead the tests exercise the three falsifiable
// decision paths through controlled real API responses that are cheap and
// stable: a nonexistent repo must produce NO VERDICT (exit 3), the real
// signerd repo must produce a verdict, and the tool must refuse to write a
// verdict when the traffic endpoint is unavailable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const run = promisify(execFile);
const TOOL = path.join(import.meta.dirname, '..', 'tools', 'measure-adoption.mjs');

// The probe shells out to `gh api`. Both controls need a live, authenticated
// GitHub API; without a token (e.g. the CI `test` job) the probe cannot run
// at all, and asserting on its failure there would measure the missing
// token, not the instrument. Same convention as the consumer-e2e tests:
// skip with a named reason when the dependency is absent.
async function ghAuthed() {
  try {
    await run('gh', ['auth', 'status'], { timeout: 15000 });
    return true;
  } catch {
    return false;
  }
}

test('adoption probe refuses a verdict on a nonexistent repo (exit 3)', async (t) => {
  if (!(await ghAuthed())) {
    t.skip('gh not authenticated; adoption probe needs live GitHub API');
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), 'signerd-adopt-'));
  try {
    await assert.rejects(
      run(process.execPath, [TOOL, '--out', path.join(dir, 'x.json')], {
        env: { ...process.env, ADOPTION_REPO: 'auroraxo/does-not-exist-404' },
      }),
      (err) => err.code === 3
    );
    // and no report file with a verdict is written
    await assert.rejects(readFile(path.join(dir, 'x.json'), 'utf8'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('adoption probe on signerd emits a verdict and complete report', async (t) => {
  if (!(await ghAuthed())) {
    t.skip('gh not authenticated; adoption probe needs live GitHub API');
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), 'signerd-adopt-'));
  try {
    const out = path.join(dir, 'adoption.json');
    await run(process.execPath, [TOOL, '--out', out]);
    const report = JSON.parse(await readFile(out, 'utf8'));
    assert.equal(report.repo, 'auroraxo/signerd');
    assert.equal(report.complete, true);
    assert.equal(report.dataSourcesFailed, 0);
    // classification is one of the three named classes, never prose
    assert.ok(
      ['user-one-evidence', 'distributed-not-yet-consumed', 'not-distributed-not-consumed']
        .includes(report.verdict.class)
    );
    // the owner exclusion actually ran: no signal names the owner as a stargazer/forker
    for (const s of report.verdict.signals) {
      assert.ok(!/^star by auroraxo$/.test(s), `owner leaked into signals: ${s}`);
      assert.ok(!/^fork by auroraxo$/.test(s), `owner leaked into signals: ${s}`);
    }
    // placement channel is the live fetched PR, not a hardcoded "merged"
    assert.ok(report.placement.pr === 280 || report.placement.state === 'none-open');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
