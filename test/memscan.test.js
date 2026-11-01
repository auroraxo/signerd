'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const { scanForPattern, scanIsComplete, unexplainedHoles, swappedHoles } = require('../scripts/memscan');

// Mirrors the chunk size the chunked scanner reads per syscall; kept local so
// the chunk-bounded-loss assertion does not depend on a new export.
const CHUNK = 1024 * 1024;

/** A live child to scan, plus its real maps text. */
function child() {
  const c = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  return c;
}

test('a read failure is bounded to ONE chunk, not the whole mapping', async (t) => {
  const c = child();
  try {
    await new Promise((r) => setTimeout(r, 300));
    const secret = crypto.randomBytes(64);
    const maps = fs.readFileSync(`/proc/${c.pid}/maps`, 'utf8');
    // Pick a writable mapping wider than one chunk: a whole-mapping read
    // failure loses all of it, a chunked read loses only the failing chunk.
    const line = maps.split('\n').find((l) => l.includes('rw-p') &&
      parseInt(l.split('-')[1], 16) - parseInt(l.split('-')[0], 16) > CHUNK);
    assert.ok(line, 'need a writable mapping wider than one chunk');
    const target = parseInt(line.split('-')[0], 16);

    const realReadSync = fs.readSync;
    const realReadFileSync = fs.readFileSync;
    let failedOnce = false;
    let mapsReads = 0;
    // Fail every read inside the first chunk of this mapping: a real
    // unreadable chunk must not lose the whole mapping, only its pages.
    fs.readSync = function patched(fd, buf, off, len, pos) {
      if (typeof pos === 'number' && pos >= target && pos < target + CHUNK) {
        failedOnce = true;
        const err = new Error('EIO');
        err.code = 'EIO';
        throw err;
      }
      return realReadSync.call(fs, fd, buf, off, len, pos);
    };
    fs.readFileSync = function patchedRead(p, ...rest) {
      const out = realReadFileSync.call(fs, p, ...rest);
      if (typeof p === 'string' && /^\/proc\/\d+\/maps$/.test(p)) mapsReads += 1;
      return out;
    };
    t.after(() => {
      fs.readSync = realReadSync;
      fs.readFileSync = realReadFileSync;
    });

    const scan = scanForPattern(c.pid, secret, { attempts: 1 });
    assert.equal(failedOnce, true, 'the injected failure must have fired');
    const entries = [...scan.regionsFailed, ...scan.regionsEmpty]
      .filter((e) => /w/.test(e.perms) && !e.swapped);
    assert.ok(entries.length > 0, 'the unreadable chunk must be reported, page-pinned');
    for (const e of entries) {
      assert.ok(e.offset !== undefined && e.offset < CHUNK,
        `every hole is pinned inside the failed chunk, got offset=${e.offset}`);
      assert.ok(e.pageAddr >= target && e.pageAddr < target + CHUNK,
        'no page outside the failed chunk is a hole');
    }
    assert.ok(scan.bytesScanned > CHUNK,
      'the rest of the mapping was still read');
    // Injected pages were READABLE pages turned EIO by the patch: present in
    // pagemap, so they can hold data and must count as holes.
    assert.ok(unexplainedHoles(scan).length > 0, 'the injected hole must be unexplained');
    assert.equal(scanIsComplete(scan), false, 'a lost writable chunk is not evidence');
  } finally {
    c.kill('SIGKILL');
  }
});

test('a read-only kernel mapping that fails does NOT invalidate the scan', async (t) => {
  const c = child();
  try {
    await new Promise((r) => setTimeout(r, 300));
    const secret = crypto.randomBytes(64);
    const realReadSync = fs.readSync;
    const maps = fs.readFileSync(`/proc/${c.pid}/maps`, 'utf8');
    // A read-only kernel mapping, exactly like [vvar]: EIO here must never
    // become a hole, because the process cannot have written key material
    // into a read-only page.
    const line = maps.split('\n').find((l) => /r--p/.test(l) && l.includes('[vvar]')) ||
      maps.split('\n').find((l) => /r--p/.test(l));
    assert.ok(line, 'need a read-only mapping to fail');
    const roStart = parseInt(line.split('-')[0], 16);
    const roEnd = parseInt(line.split('-')[1].split(/\s+/)[0], 16);
    fs.readSync = function patched(fd, buf, off, len, pos) {
      if (typeof pos === 'number' && pos >= roStart && pos < roEnd) {
        const err = new Error('EIO');
        err.code = 'EIO';
        throw err;
      }
      return realReadSync.call(fs, fd, buf, off, len, pos);
    };
    t.after(() => { fs.readSync = realReadSync; });

    const scan = scanForPattern(c.pid, secret);
    const entries = [...scan.regionsFailed, ...scan.regionsEmpty];
    assert.ok(entries.length > 0, 'the injected EIO must show up (failed or proven-empty)');
    const lineRange = line.split(/\s+/)[0];
    const injected = entries.filter((e) => e.label.startsWith(lineRange));
    assert.ok(injected.length > 0, 'the read-only mapping must be reported');
    assert.ok(injected.every((f) => !/w/.test(f.perms)),
      'a read-only mapping must never become a hole');
    assert.ok(unexplainedHoles(scan).length === 0,
      'the scan has no writable hole other than injected read-only failures');
    // Environmental swapped pages (runner has swap) may exist; they are
    // named, not asserted away.
    t.diagnostic(`${swappedHoles(scan).length} writable holes explained by swapping`);
    assert.equal(scanIsComplete(scan), unexplainedHoles(scan).length === 0 &&
      swappedHoles(scan).length === 0, 'completeness = no writable hole at all');
  } finally {
    c.kill('SIGKILL');
  }
});

test('the scanner finds a known pattern where it actually is (positive control)', async (t) => {
  const c = child();
  try {
    await new Promise((r) => setTimeout(r, 300));
    const secret = crypto.randomBytes(64);
    const scan = scanForPattern(c.pid, secret);
    assert.equal(unexplainedHoles(scan).length, 0,
      'no writable hole that swapping does not explain in a quiet process');
    assert.equal(scanIsComplete(scan), swappedHoles(scan).length === 0,
      'completeness holds iff no swapped page is unreadable');
    assert.equal(scan.hits.length, 0, 'a random pattern is absent');
    assert.ok(scan.bytesScanned > 0, 'the scan actually read memory');
  } finally {
    c.kill('SIGKILL');
  }
});

test('a stale snapshot is rescanned: holes from a changed address space are superseded', async (t) => {
  const c = child();
  try {
    await new Promise((r) => setTimeout(r, 300));
    const secret = crypto.randomBytes(64);
    const realReadSync = fs.readSync;
    const realReadFileSync = fs.readFileSync;
    let mapsReads = 0;
    let injected = false;

    // Attempt 1: one writable chunk answers EIO (the mapping moved between
    // the snapshot and the read). The stability check then reports a DIFFERENT
    // address space, which is exactly the condition for a retry.
    fs.readSync = function patched(fd, buf, off, len, pos) {
      const r = realReadSync.call(fs, fd, buf, off, len, pos);
      if (mapsReads === 1 && !injected && typeof pos === 'number') {
        injected = true;
        const err = new Error('EIO');
        err.code = 'EIO';
        throw err;
      }
      return r;
    };
    fs.readFileSync = function patchedRead(p, ...rest) {
      const out = realReadFileSync.call(fs, p, ...rest);
      if (typeof p === 'string' && /^\/proc\/\d+\/maps$/.test(p)) {
        mapsReads += 1;
        // Every SECOND maps read claims a moved address space (drop [vvar]
        // lines): that is the retry trigger, and it must not be a hole itself.
        if (mapsReads % 2 === 0) {
          return out.split('\n').filter((l) => !l.includes('[vvar]')).join('\n');
        }
      }
      return out;
    };
    t.after(() => { fs.readSync = realReadSync; fs.readFileSync = realReadFileSync; });

    const scan = scanForPattern(c.pid, secret);
    assert.ok(scan.attempts >= 2, `retry must happen, got attempts=${scan.attempts}`);
    // The injected hole (a PRESENT page made unreadable) must be gone after
    // the retry; environmental swapped pages are reported separately.
    assert.equal(unexplainedHoles(scan).length, 0,
      `the rescan supersedes the stale hole, holes=${JSON.stringify([...scan.regionsFailed, ...scan.regionsEmpty])}`);
    assert.equal(scan.hits.length, 0, 'absence still reported after the retry');
  } finally {
    c.kill('SIGKILL');
  }
});
