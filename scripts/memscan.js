'use strict';

const fs = require('node:fs');

// A readable mapping larger than this is skipped rather than copied. Node
// processes are nowhere near this, so any skip is reported and must be zero
// for a caller to treat "not found" as evidence.
const MAX_REGION_BYTES = 1024 * 1024 * 1024;

// How much of one mapping is read per syscall. A mapping can change under us
// while it is being read (the kernel returns EIO for a hole that is no longer
// mapped at that address); reading in chunks bounds that loss to one chunk
// instead of the whole mapping.
const CHUNK_BYTES = 1024 * 1024;

// How many times a scan is retried when the address space changed under it.
const DEFAULT_ATTEMPTS = 3;

/** Parse /proc/<pid>/maps into the mappings we may read. */
function readMappings(pid) {
  const maps = fs.readFileSync(`/proc/${pid}/maps`, 'utf8');
  const regions = [];
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
    regions.push({ start, end, size, perms, label });
  }
  return regions;
}

/** The address-space fingerprint a scan was taken against. */
function fingerprint(regions) {
  return regions.map((r) => `${r.start}-${r.end}`).join(',');
}

/**
 * Scan a LIVE process's readable memory for an exact byte pattern.
 *
 * This exists because "the key is not in the client" is an empirical claim
 * about a running process, not a property of its source. Scanning is done
 * against /proc/<pid>/mem, which needs ptrace-level rights; on Linux those are
 * granted to an ancestor, so a parent can scan its own child but not a peer.
 *
 * The scan is taken against a FRESH maps snapshot and is repeated while the
 * address space changes under it: a mapping that was unmapped between the
 * snapshot and the read makes the kernel answer EIO for that address, and an
 * EIO on a writable mapping is a hole in the evidence, not a pass.
 *
 * Returns how much was actually read, because a scan that read nothing and a
 * scan that read everything and found nothing must never look the same:
 *   hits           absolute addresses where the pattern occurs
 *   regionsRead    mappings that were read end to end
 *   regionsSkipped mappings skipped for size (a skipped region is a hole)
 *   regionsFailed  chunks that could not be read (errno), with their perms
 *   bytesScanned   total bytes read
 *   attempts       how many scans it took to get a stable address space
 *
 * Callers that claim absence MUST assert scanIsComplete() is true: an unread
 * writable mapping cannot be searched, and an absence claim over an
 * unreadable heap is not evidence.
 */
function scanForPattern(pid, pattern, options = {}) {
  const needle = Buffer.from(pattern);
  if (!needle.length) throw new TypeError('pattern must be non-empty');
  const attempts = options.attempts ?? DEFAULT_ATTEMPTS;

  let best = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const result = scanOnce(pid, needle);
    result.attempts = attempt;
    // Keep the most informative scan: the one with the fewest holes, and on a
    // tie the one that read the most.
    if (!best || holeCount(result) < holeCount(best) ||
        (holeCount(result) === holeCount(best) && result.bytesScanned > best.bytesScanned)) {
      best = result;
    }
    // Did the address space move while we read it? If it did, the holes are
    // stale and another attempt may read them.
    let after;
    try {
      after = fingerprint(readMappings(pid));
    } catch {
      break;
    }
    if (after === result.fingerprint) break;
    result.addressSpaceChanged = true;
  }
  return best;
}

/** Number of holes (failed chunks + skipped regions) a scan carries. */
function holeCount(scan) {
  return scan.regionsFailed.length + scan.regionsSkipped.length;
}

/** One pass over the process, chunk by chunk. */
function scanOnce(pid, needle) {
  const regions = readMappings(pid);
  const fd = fs.openSync(`/proc/${pid}/mem`, 'r');
  const result = {
    pid,
    hits: [],
    regionsRead: 0,
    regionsSkipped: [],
    regionsFailed: [],
    bytesScanned: 0,
    fingerprint: fingerprint(regions),
  };
  try {
    for (const region of regions) {
      if (region.size > MAX_REGION_BYTES) {
        result.regionsSkipped.push({
          label: region.label,
          perms: region.perms,
          size: region.size,
        });
        continue;
      }
      let regionComplete = true;
      for (let offset = 0; offset < region.size; offset += CHUNK_BYTES) {
        const length = Math.min(CHUNK_BYTES, region.size - offset);
        const buffer = Buffer.alloc(length);
        let read;
        try {
          read = fs.readSync(fd, buffer, 0, length, region.start + offset);
        } catch (err) {
          result.regionsFailed.push({
            label: region.label,
            perms: region.perms,
            size: region.size,
            offset,
            chunkBytes: length,
            code: err.code || err.message,
          });
          regionComplete = false;
          continue;
        }
        result.bytesScanned += read;
        let index = buffer.indexOf(needle);
        while (index !== -1) {
          result.hits.push(region.start + offset + index);
          index = buffer.indexOf(needle, index + 1);
        }
      }
      if (regionComplete) result.regionsRead += 1;
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

module.exports = {
  scanForPattern,
  scanIsComplete,
  MAX_REGION_BYTES,
  CHUNK_BYTES,
  DEFAULT_ATTEMPTS,
};
