'use strict';

/**
 * Preflight an output file path: does the destination directory exist,
 * is it writable, and if the target already exists is it a regular writable
 * file (not a directory or read-only file)?
 *
 * WHY (measured 2026-11-07, live):
 *
 * When an output path is unwritable (e.g. parent directory does not exist,
 * or permission denied):
 *   * In `signerd sign --out <unwritable>`: the daemon signs the wire, charges
 *     the budget, appends a record to the journal, and fs.writeFileSync then
 *     CRASHES with ENOENT/EACCES. The signed wire is never delivered or saved,
 *     and because the daemon already recorded the spend/replay, a retry with
 *     a corrected --out is permanently REFUSED `replay`!
 *   * In `signerd sign-message --out <unwritable>`: the same thing happens for
 *     message grants (the journal is written, the receipt file is not, retry
 *     is refused with `replay`).
 *   * In `examples/user-zero-client.js --out <unwritable>`: exactly the same:
 *     the socket round trip signs, budget is burned, then fs.writeFileSync
 *     throws an uncaught ENOENT/EACCES.
 *
 * By checking BEFORE the request/write is initiated, unwritable paths are
 * refused with a clean exit 2 and fix message, and the signing budget and
 * replay state remain 100% UNTOUCHED.
 */

const fs = require('node:fs');
const path = require('node:path');

function checkOutWritable(outPath) {
  if (typeof outPath !== 'string' || outPath.length === 0) return { ok: true };
  const resolved = path.resolve(outPath);
  const dir = path.dirname(resolved);

  try {
    const dirStat = fs.statSync(dir);
    if (!dirStat.isDirectory()) {
      return {
        ok: false,
        code: 'out_parent_not_directory',
        path: outPath,
        parent: dir,
        message: `the parent path ${dir} is not a directory`,
      };
    }
    fs.accessSync(dir, fs.constants.W_OK);
  } catch (err) {
    return {
      ok: false,
      code: 'out_parent_unwritable',
      path: outPath,
      parent: dir,
      message: `the output directory ${dir} is not writable: ${err && err.message ? err.message : String(err)}`,
    };
  }

  try {
    if (fs.existsSync(resolved)) {
      const stat = fs.statSync(resolved);
      if (stat.isDirectory()) {
        return {
          ok: false,
          code: 'out_is_directory',
          path: outPath,
          message: `the output path ${outPath} is an existing directory`,
        };
      }
      fs.accessSync(resolved, fs.constants.W_OK);
    }
  } catch (err) {
    return {
      ok: false,
      code: 'out_unwritable',
      path: outPath,
      message: `the output file ${outPath} is not writable: ${err && err.message ? err.message : String(err)}`,
    };
  }

  return { ok: true };
}

module.exports = { checkOutWritable };
