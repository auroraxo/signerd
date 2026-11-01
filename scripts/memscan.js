'use strict';

const fs = require('node:fs');

// A readable mapping larger than this is skipped rather than copied. Node
// processes are nowhere near this, so any skip is reported and must be zero
// for a caller to treat "not found" as evidence.
const MAX_REGION_BYTES = 1024 * 1024 * 1024;

// How much of one mapping is read per syscall. A multi-page read can fail as
// a whole on some kernels (ubuntu-26.04 runners EIO the first chunk of a
// mapping while its pages read fine one by one), so a chunk is the coarse
// unit and every failed chunk is re-read page by page.
const CHUNK_BYTES = 1024 * 1024;

// How many times a scan is retried when the address space changed under it.
const DEFAULT_ATTEMPTS = 3;

const PAGE_BYTES = 4096;

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
 * The page-table state of one page, from /proc/<pid>/pagemap.
 *
 *   present -> a frame backs the page: it can hold data.
 *   swapped -> a swap slot backs the page: it can hold data.
 *   neither -> the kernel says this page holds NOTHING right now: no frame,
 *              no swap slot. Reading it cannot surface content that was
 *              never written; an unreadable page in that state cannot
 *              contain a copy of anything.
 *   null    -> pagemap was unreadable: we learned nothing, and "we learned
 *              nothing" must never count as "it is empty".
 */
function pageTableState(pid, pageAddr) {
  let fd;
  try {
    fd = fs.openSync(`/proc/${pid}/pagemap`, 'r');
    const buf = Buffer.alloc(8);
    const read = fs.readSync(fd, buf, 0, 8, Math.floor(pageAddr / PAGE_BYTES) * 8);
    if (read !== 8) return null;
    const entry = buf.readBigUInt64LE(0);
    return {
      present: (entry & (1n << 63n)) !== 0n,
      swapped: (entry & (1n << 62n)) !== 0n,
    };
  } catch {
    return null;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already gone */ } }
  }
}

/**
 * Decide what an UNREADABLE page means for an absence claim. Fail closed:
 * only a page the kernel proves backingless is `empty`; present, swapped, or
 * unknown state stays a `hole` (unproven is not proven empty).
 */
function classifyUnreadable(state) {
  if (state && !state.present && !state.swapped) return 'empty';
  return 'hole';
}

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
 *   regionsRead    mappings that were read end to end (every page readable
 *                  or provably backingless)
 *   regionsSkipped mappings skipped for size (a skipped region is a hole)
 *   regionsFailed  unreadable pages that are NOT proven empty; writable ones
 *                  are holes in the evidence, with perms, pagemap state
 *   regionsEmpty   unreadable pages the kernel proves backingless (no frame,
 *                  no swap slot): recorded with their pagemap entry so the
 *                  exclusion is auditable, never silently dropped
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
  let performed = 0;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const result = scanOnce(pid, needle);
    performed = attempt;
    result.attempts = attempt;
    // Keep the most informative scan: the one with the fewest holes, and on a
    // tie the one that read the most.
    if (!best || holeCount(result) < holeCount(best) ||
        (holeCount(result) === holeCount(best) && result.bytesScanned > best.bytesScanned)) {
      best = result;
    }
    // Did the address space move while we read it? If it did, the holes may
    // be stale and another attempt may read them.
    let after;
    try {
      after = fingerprint(readMappings(pid));
    } catch {
      break;
    }
    if (after === result.fingerprint) break;
    result.addressSpaceChanged = true;
  }
  // Report how many scans it actually took, not which one was kept.
  best.attempts = performed;
  return best;
}

/** How many real holes (failed pages + skipped regions) a scan carries. */
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
    regionsEmpty: [],
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
          // The chunk failed as a unit. Isolate it to the pages that actually
          // fail and ask the kernel what backs each of them.
          const unread = isolateFailedPages(result, needle, region, offset, length);
          if (unread > 0) regionComplete = false;
          continue;
        }
        result.bytesScanned += read;
        if (read > 0) {
          let index = buffer.indexOf(needle);
          while (index !== -1) {
            result.hits.push(region.start + offset + index);
            index = buffer.indexOf(needle, index + 1);
          }
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
 * Re-read a failed chunk page by page and classify each failing page.
 * Returns how many pages in the chunk could not be read (hole or proven
 * empty): any such page means the mapping was not read end to end.
 * Pages that read fine individually are scanned for the pattern here, so a
 * multi-page read artifact costs no coverage and no hits.
 */
function isolateFailedPages(result, needle, region, offset, length) {
  const fd = fs.openSync(`/proc/${result.pid}/mem`, 'r');
  let unread = 0;
  try {
    for (let pageOff = 0; pageOff < length; pageOff += PAGE_BYTES) {
      const pageSize = Math.min(PAGE_BYTES, length - pageOff);
      const addr = region.start + offset + pageOff;
      const buf = Buffer.alloc(pageSize);
      let read;
      try {
        read = fs.readSync(fd, buf, 0, pageSize, addr);
      } catch (err) {
        const state = pageTableState(result.pid, addr);
        const entry = {
          label: region.label,
          perms: region.perms,
          size: region.size,
          offset: offset + pageOff,
          pageAddr: addr,
          chunkBytes: pageSize,
          code: err.code || err.message,
          pagemap: state,
        };
        if (classifyUnreadable(state) === 'empty') result.regionsEmpty.push(entry);
        else result.regionsFailed.push(entry);
        unread += 1;
        continue;
      }
      result.bytesScanned += read;
      if (read > 0) {
        let index = buf.indexOf(needle);
        while (index !== -1) {
          result.hits.push(addr + index);
          index = buf.indexOf(needle, index + 1);
        }
      }
    }
  } finally {
    fs.closeSync(fd);
  }
  return unread;
}

/**
 * True only when the scan is complete enough to support an absence claim:
 * every readable mapping was read (or every unreadable page was proven
 * backingless), nothing was skipped, and no WRITABLE page that could hold
 * data was lost to an errno (those are where a heap or stack lives).
 *
 * Two documented exclusions:
 *  - a read-only kernel mapping that cannot be read (e.g. [vvar]) does not
 *    invalidate the claim: the process cannot have placed key material in a
 *    read-only page;
 *  - an unreadable page with no frame and no swap slot (regionsEmpty) holds
 *    no bytes; its pagemap entry is kept as the evidence, and unknown
 *    pagemap state never lands there (it stays a hole).
 */
function scanIsComplete(scan) {
  if (scan.regionsSkipped.length > 0) return false;
  return scan.regionsFailed.every((f) => !/w/.test(f.perms));
}

module.exports = {
  scanForPattern,
  scanIsComplete,
  pageTableState,
  classifyUnreadable,
  MAX_REGION_BYTES,
  CHUNK_BYTES,
  DEFAULT_ATTEMPTS,
  PAGE_BYTES,
};
