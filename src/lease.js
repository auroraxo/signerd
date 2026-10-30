'use strict';

// Read a file while the kernel proves that nobody holds it open for writing.
//
// WHY: R4-1. A file's mode says who MAY open it; it says nothing about
// descriptors opened BEFORE the mode was tightened. chmod does not revoke a
// descriptor, so a stranger that opened the file while it was group/other
// writable can still write through it afterwards, and the daemon would re-read
// forged grants on the next request and sign attacker-chosen transactions.
//
// The previous approach - scanning /proc for open write handles - was measured
// and found defective in three ways:
//   D1  its verdict was cached under dev:ino:ctime:size, so a writer that
//       already held the file made the scan return "free" forever (the cache
//       key does not change when someone OPENS a file);
//   D2  it skipped every process of another uid, so a foreign writer was
//       invisible (measured: writers:[] while a root-held handle existed);
//   D3  it cost ~7.8 ms on EVERY request.
// F_SETLEASE answers the same question in ~0.01 ms, and the KERNEL decides it
// for every uid.
//
// WHAT WE TAKE: a READ lease (F_RDLCK), because it conflicts only with openers
// for writing. A write lease (F_WRLCK) conflicts with every other opener, so a
// single `cat grants.json` would make the daemon refuse to sign - measured:
// reader -> refused under F_WRLCK, reader -> granted under F_RDLCK.
//
// The bytes are read THROUGH the fd that holds the lease, and the lease is
// re-checked afterwards: a writer that got in mid-read leaves lease=broken and
// we refuse instead of handing over bytes we can no longer vouch for.
//
// LIMITS, STATED NOT HIDDEN:
//   * Linux only (F_SETLEASE). On a kernel without leases the helper exits 4
//     and we REFUSE - we never report a pass we could not observe.
//   * Point-in-time: it proves the state at read time, not that the file was
//     never written before the daemon started. The mode/owner/directory checks
//     in grantfile.js still carry that part.
//   * The helper binary must be present; if it is missing it is compiled once
//     from tools/leasecheck.c, and if that is impossible we refuse.

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const HELPER = path.join(__dirname, '..', 'tools', 'leasecheck');
const SOURCE = `${HELPER}.c`;
// Grant files are small JSON documents; the cap only exists so a hostile or
// corrupted helper cannot stream the daemon into oblivion.
const MAX_BYTES = 16 * 1024 * 1024;
const HELPER_TIMEOUT_MS = 10000;

function fail(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

let built = false;

/** Compile the helper once, on demand. Never uses a shell. */
function buildHelper() {
  const cc = process.env.CC || 'cc';
  const res = spawnSync(cc, ['-O2', '-o', HELPER, SOURCE], {
    encoding: 'utf8',
    timeout: 30000,
  });
  if (res.error || res.status !== 0) {
    const detail = res.error ? res.error.message : (res.stderr || `exit ${res.status}`).trim();
    throw fail('grant_file_lease_unavailable', detail);
  }
}

function helper() {
  if (fs.existsSync(HELPER)) return HELPER;
  if (!fs.existsSync(SOURCE)) {
    throw fail('grant_file_lease_unavailable', `missing ${path.basename(HELPER)}`);
  }
  if (!built) {
    buildHelper();
    built = true;
  }
  if (!fs.existsSync(HELPER)) {
    throw fail('grant_file_lease_unavailable', 'helper did not build');
  }
  return HELPER;
}

const LEASE_ERROR = {
  3: 'grant_file_held_writer',
  4: 'grant_file_lease_unsupported',
  5: 'grant_file_unreadable',
  6: 'grant_file_invalid',
  7: 'grant_file_lease_denied',
};

// Exit 5 means the open failed; the helper prints the errno name. Two of them
// are not "unreadable" in the sense the caller means, and existing callers key
// on these codes.
const OPEN_ERROR = {
  ELOOP: 'grant_file_invalid',
  ENOENT: 'grant_file_unreadable',
  ENOTDIR: 'grant_file_unreadable',
  EACCES: 'grant_file_unreadable',
};

function parseMeta(line) {
  // LC1 dev=... ino=... uid=... mode=... size=... lease=held|broken
  // mode is printed in OCTAL (that is how modes are written everywhere else
  // in this codebase); parsing it as decimal silently turned 0600 into 600 and
  // the subsequent mask produced 0130 - a mode that never existed.
  const m = /^LC1 dev=(\d+) ino=(\d+) uid=(\d+) mode=(\d+) size=(\d+) lease=(held|broken)$/.exec(line);
  if (!m) throw fail('grant_file_lease_unavailable', `bad helper output: ${line.slice(0, 80)}`);
  return {
    dev: Number(m[1]),
    ino: Number(m[2]),
    uid: Number(m[3]),
    mode: parseInt(m[4], 8),
    size: Number(m[5]),
    lease: m[6],
  };
}

/**
 * Read `file` under a kernel-enforced read lease.
 *
 * Returns { meta, bytes }. meta carries the stat of the fd the bytes were
 * actually read from - not of the path, which could have been swapped between
 * two syscalls.
 *
 * Throws a fail-coded error when a writer holds the file, when the lease broke
 * during the read, or when leases are unavailable on this platform.
 */
function readUnderLease(file) {
  const bin = helper();
  const res = spawnSync(bin, [file], {
    encoding: 'buffer',
    maxBuffer: MAX_BYTES,
    timeout: HELPER_TIMEOUT_MS,
  });

  if (res.error) {
    if (res.error.code === 'ENOENT') throw fail('grant_file_lease_unavailable', 'helper not found');
    if (res.error.code === 'ETIMEDOUT') throw fail('grant_file_lease_unavailable', 'helper timed out');
    throw fail('grant_file_lease_unavailable', res.error.message);
  }

  const status = res.status;
  if (status !== 0) {
    const code = LEASE_ERROR[status];
    if (code) {
      // Prefer the helper's errno name when it gives one, so a symlink keeps
      // reporting grant_file_invalid rather than a generic unreadable.
      const errName = (res.stderr || '').toString().trim().split('\n')[0];
      if (status === 5 && OPEN_ERROR[errName]) throw fail(OPEN_ERROR[errName], errName);
      if (status === 5 && errName) throw fail('grant_file_unreadable', errName);
      if (status === 4) throw fail(code, 'F_SETLEASE unsupported on this kernel');
      if (status === 7) throw fail(code, 'lease denied - file is not ours');
      throw fail(code);
    }
    throw fail('grant_file_lease_unavailable',
      `helper exited ${status}${res.signal ? ` (${res.signal})` : ''}: ${(res.stderr || '').toString().trim()}`);
  }

  const out = res.stdout;
  const nl = out.indexOf(0x0a);
  if (nl < 0) throw fail('grant_file_lease_unavailable', 'helper produced no metadata line');
  const meta = parseMeta(out.slice(0, nl).toString('utf8'));
  const bytes = out.slice(nl + 1);

  // The writer got in while we were reading: the bytes are no longer ours to
  // vouch for, even though the helper delivered them for a precise error.
  if (meta.lease !== 'held') throw fail('grant_file_held_writer', 'writer opened during the read');

  return { meta, bytes };
}

module.exports = { readUnderLease, HELPER };
