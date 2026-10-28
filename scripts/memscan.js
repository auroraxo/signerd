'use strict';

const fs = require('node:fs');

// A readable mapping larger than this is skipped rather than copied. Node
// processes are nowhere near this, so any skip is reported and must be zero
// for a caller to treat "not found" as evidence.
const MAX_REGION_BYTES = 1024 * 1024 * 1024;

/**
 * Scan a LIVE process's readable memory for an exact byte pattern.
 *
 * This exists because "the key is not in the client" is an empirical claim
 * about a running process, not a property of its source. Scanning is done
 * against /proc/<pid>/mem, which needs ptrace-level rights; on Linux those are
 * granted to an ancestor, so a parent can scan its own child but not a peer.
 *
 * Returns how much was actually read, because a scan that read nothing and a
 * scan that read everything and found nothing must never look the same:
 *   hits           absolute addresses where the pattern occurs
 *   regionsRead    mappings that were read end to end
 *   regionsSkipped mappings skipped for size (a skipped region is a hole)
 *   regionsFailed  mappings that could not be read (errno), with their perms
 *   bytesScanned   total bytes read
 *
 * Callers that claim absence MUST assert scanIsComplete() is true: an unread
 * writable mapping cannot be searched, and an absence claim over an
 * unreadable heap is not evidence.
 */
function scanForPattern(pid, pattern) {
  const needle = Buffer.from(pattern);
  if (!needle.length) throw new TypeError('pattern must be non-empty');
  const maps = fs.readFileSync(`/proc/${pid}/maps`, 'utf8');
  const fd = fs.openSync(`/proc/${pid}/mem`, 'r');
  const result = {
    pid,
    hits: [],
    regionsRead: 0,
    regionsSkipped: [],
    regionsFailed: [],
    bytesScanned: 0,
  };
  try {
    for (const line of maps.split('\n')) {
      if (!line) continue;
      const parts = line.split(/\s+/);
      if (parts.length < 2) continue;
      const [range, perms] = parts;
      if (!perms.includes('r')) continue;
      const name = parts.slice(5).join(' ');
      const [startHex, endHex] = range.split('-');
      const start = parseInt(startHex, 16);
      const end = parseInt(endHex, 16);
      const size = end - start;
      const label = `${range} ${perms}${name ? ` ${name}` : ''}`;
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || size <= 0) continue;
      if (size > MAX_REGION_BYTES) {
        result.regionsSkipped.push({ label, perms, size });
        continue;
      }
      let buffer;
      try {
        buffer = Buffer.alloc(size);
        fs.readSync(fd, buffer, 0, size, start);
      } catch (err) {
        result.regionsFailed.push({ label, perms, size, code: err.code || err.message });
        continue;
      }
      result.regionsRead += 1;
      result.bytesScanned += size;
      let index = buffer.indexOf(needle);
      while (index !== -1) {
        result.hits.push(start + index);
        index = buffer.indexOf(needle, index + 1);
      }
    }
  } finally {
    fs.closeSync(fd);
  }
  return result;
}

/**
 * True only when the scan is complete enough to support an absence claim:
 * every readable mapping was read, none was skipped, and no WRITABLE mapping
 * was lost to an errno (those are where a heap or stack lives).
 *
 * A read-only kernel mapping that cannot be read (e.g. [vvar]) does not
 * invalidate the claim: it is not writable by the process, so the process
 * cannot have placed key material there.
 */
function scanIsComplete(scan) {
  if (scan.regionsSkipped.length > 0) return false;
  return scan.regionsFailed.every((f) => !/w/.test(f.perms));
}

module.exports = { scanForPattern, scanIsComplete, MAX_REGION_BYTES };
