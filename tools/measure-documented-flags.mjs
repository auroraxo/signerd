// The DOCUMENTED-SURFACE INSTRUMENT: does the README a stranger reads
// describe invocations that actually RUN, with the flags the CLI expects?
//
// WHY (measured 2026-11-06, this repo):
//
// The front-page README renders on GitHub; the installed package ships the
// TAG's README. Two separate questions follow from that, and only one of
// them was answered until now:
//
//   (1) does the TAG ship the command?   -> test/installed-tag-journey.test.js
//       (J1: dispatch, J2: the tag's own README documents it)
//   (2) does the documented invocation RUN? -> THIS instrument.
//
// (1) was green at v0.2.3 while (2) was not. The tag's README documents
//
//   signerd seal-grants --grants <file> --grant-seal-passphrase-file <file>
//   signerd seal-journal --ledger <file> --journal-seal-passphrase-file <file>
//   signerd run ... --grant-seal-passphrase-file <file>
//
// and the CLI answers `missing --seal-passphrase-file` / `missing --journal`
// (the tools read --seal-passphrase-file and --journal; the README used the
// DAEMON's flag names for the TOOLS), while the third line is not an
// executable command at all - `run ...` is a placeholder. A name-level check
// cannot see either: all three command NAMES are shipped by the tag.
//
// THE RULES (pure, offline-pinnable; the execution is the expensive part):
//
//   D1 every documented `signerd <command>` invocation must be accepted by
//      the CLI it addresses - the CLI must not answer `missing --<flag>`.
//      That answer means the README's flags and the CLI's flags disagree,
//      or the README omits a flag the CLI needs.
//   D2 no documented invocation may contain a `...` placeholder: a line a
//      reader copies must be a line that runs.
//   D3 a documented invocation that fails for any OTHER reason (a file that
//      is not there yet, a socket nobody serves) is NOT a defect - the
//      README describes a SEQUENCE, and only the flags are the claim.
//
// Usage:
//   node tools/measure-documented-flags.mjs --cli <path/to/bin/signerd.js> \
//        --readme <path/to/README.md> [--label <name>] [--out <file>]
//   Exit 0 = clean, 1 = defects found, 2 = bad usage.
'use strict';

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export const USAGE_BANNER = 'signerd — scoped signing daemon for Solana (early prototype)';

/**
 * Every `signerd <command>` invocation a reader can copy out of a fenced
 * code block, with its line continuations joined back into one command.
 * Prose mentions are ignored on purpose: a sentence that names a command it
 * does not run is not a promise to ship it. Fences are read regardless of
 * their language tag (same rule as installed-tag-journey's
 * documentedCommands): a command line a reader can copy counts.
 */
export function documentedInvocations(markdown) {
  const lines = String(markdown).split('\n');
  let inFence = false;
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*```/.test(line)) { inFence = !inFence; continue; }
    if (!inFence) continue;
    if (!/^\s*(?:\$\s*)?signerd\s/.test(line)) continue;
    const parts = [line];
    while (/\\\s*$/.test(parts[parts.length - 1]) && i + 1 < lines.length) {
      i += 1;
      parts.push(lines[i]);
    }
    const text = parts.join('\n');
    const m = /signerd ([a-z][a-z0-9-]*)/.exec(text);
    out.push({ command: m[1], text, flags: flagsIn(text) });
  }
  return out;
}

/** The `--flag` names a documented invocation carries. */
export function flagsIn(text) {
  const out = new Set();
  const re = /--([a-z][a-z0-9-]*)/g;
  let m;
  while ((m = re.exec(text)) !== null) out.add(m[1]);
  return [...out].sort();
}

/** A `...` placeholder inside a documented invocation. */
export function placeholderLines(invocations) {
  return invocations
    .filter((inv) => /(^|\s)\.\.\.(\s|$)/.test(inv.text))
    .map((inv) => inv.text.split('\n')[0].trim());
}

/**
 * The CLI's answer to one documented invocation, reduced to the verdict the
 * rules care about:
 *   { kind: 'missing-flag', flag }  the CLI asked for a flag the README
 *                                    did not give (or named differently)
 *   { kind: 'placeholder' }         the invocation is not executable
 *   { kind: 'unknown-command' }     the CLI does not know the command at all
 *   { kind: 'other', reason }       it ran but failed for a reason the README
 *                                    does not claim (missing file, dead
 *                                    socket, ...); exit 0 = accepted
 *   { kind: 'ok' }                  the invocation exited 0 as written
 */
export function classifyRun(invocation, result) {
  const out = `${result.stdout || ''}${result.stderr || ''}`;
  if (result.signal) return { kind: 'other', reason: `signal ${result.signal}` };
  if (/Cannot find module/.test(out)) return { kind: 'other', reason: 'measurement broken' };
  const first = (out.split('\n')[0] || '').trim();
  if (first === USAGE_BANNER) return { kind: 'unknown-command' };
  const missing = /^missing --([^\s]+)/m.exec(out);
  if (missing) return { kind: 'missing-flag', flag: missing[1] };
  if (/(^|\s)\.\.\.(\s|$)/.test(invocation.text)) return { kind: 'placeholder' };
  if (result.status === 0) return { kind: 'ok' };
  // D3: a failure the README does not claim (its own sequence puts the file
  // there first) is not a defect - but it is not a pass either.
  const reason = (out.split('\n').find((l) => l.trim()) || `exit ${result.status}`).trim().slice(0, 160);
  return { kind: 'other', reason };
}

/** Run one documented invocation against a CLI, in a throwaway HOME. */
export function runInvocation(cliPath, invocation) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-documented-surface-'));
  try {
    const script = invocation.text
      .split('\n')
      .map((l) => l.replace(/(^|\s)signerd(\s|$)/, `$1"${process.execPath}" "${cliPath}"$2`))
      .join('\n');
    const result = spawnSync('sh', ['-c', script], {
      encoding: 'utf8', timeout: 30000, env: { ...process.env, HOME: home },
    });
    return classifyRun(invocation, result);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}

/**
 * The pure rule: rows (one per documented invocation, with the CLI's verdict)
 * -> the defects and the verdict. Offline-pinnable: a test can hand it
 * rows without running anything.
 */
export function derive(rows) {
  const defects = [];
  for (const row of rows) {
    const v = row.verdict || {};
    if (v.kind === 'missing-flag') {
      defects.push({
        kind: 'missing-flag',
        command: row.command,
        flag: v.flag,
        text: row.text,
        why: `the README does not give the flag --${v.flag} that the CLI asks for`,
      });
    } else if (v.kind === 'placeholder') {
      defects.push({
        kind: 'placeholder',
        command: row.command,
        text: row.text,
        why: 'a documented invocation contains a ... placeholder, so it is not executable',
      });
    } else if (v.kind === 'unknown-command') {
      defects.push({
        kind: 'unknown-command',
        command: row.command,
        text: row.text,
        why: 'the CLI does not know this command at all',
      });
    }
  }
  return { verdict: defects.length === 0 ? 'clean' : 'defective', defects };
}

/** Measure a README against a CLI: parse, run, derive. */
export function measure(readmePath, cliPath) {
  const invocations = documentedInvocations(fs.readFileSync(readmePath, 'utf8'));
  const rows = invocations.map((inv) => ({
    command: inv.command,
    flags: inv.flags,
    text: inv.text.split('\n')[0].trim(),
    verdict: runInvocation(cliPath, inv),
  }));
  return { rows, ...derive(rows) };
}

function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const cli = arg('cli');
  const readme = arg('readme');
  const label = arg('label') || readme;
  const out = arg('out');
  if (!cli || !readme) {
    process.stderr.write(
      'usage: measure-documented-flags.mjs --cli <cli.js> --readme <README.md> ' +
      '[--label <name>] [--out <file>]\n');
    return 2;
  }
  const report = { label, readme, cli, measuredAt: new Date().toISOString(), ...measure(readme, cli) };
  const json = `${JSON.stringify(report, null, 2)}\n`;
  if (out) fs.writeFileSync(out, json);
  process.stdout.write(json);
  return report.verdict === 'clean' ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  process.exit(main(process.argv.slice(2)));
}
