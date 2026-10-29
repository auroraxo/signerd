'use strict';

// Explicit, fail-closed journal migration: format 1 -> format 3.
//
// A format-1 record carries only the WIRE hash, not the message identity, and
// sha256 cannot be inverted. The only way to restore "one message approved at
// most once, ever" is therefore to be handed the original wires (the client
// holds them; the daemon returned them). Without them the operator may
// explicitly accept the loss: spend accounting is kept, message identity
// becomes null ("unknown"), and the gap is reported by Ledger.legacyState().

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  parseJournal, messageImage, assertJournalPath, chainHash, JOURNAL_FORMAT, GENESIS_HASH,
} = require('./ledger');

function fail(code, detail) {
  const err = new Error(detail === undefined ? code : `${code}: ${detail}`);
  err.code = code;
  return err;
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function indexWires(dir) {
  const byHash = new Map();
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (err) {
    throw fail('wires_dir_unreadable', err.code);
  }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const bytes = fs.readFileSync(path.join(dir, entry.name));
    byHash.set(sha256(bytes), bytes);
  }
  return byHash;
}

function migrateJournal({ file, wiresDir = null, discardLegacy = false }) {
  if (typeof file !== 'string' || file.length === 0) throw fail('ledger_file_required');
  const resolved = path.resolve(file);
  // Never rewrite a journal under a live daemon (even a stale lock blocks).
  if (fs.existsSync(`${resolved}.lock`)) throw fail('ledger_locked', 'remove or stop the daemon first');
  assertJournalPath(resolved);
  let raw;
  try { raw = fs.readFileSync(resolved); } catch (err) {
    throw fail(err.code === 'ENOENT' ? 'ledger_missing' : 'ledger_unreadable');
  }
  const parsed = parseJournal(raw);
  if (parsed.tailTorn) throw fail('ledger_torn_tail', 'start the daemon once to repair it, then migrate');
  const legacy = parsed.records.filter((r) => r.v === undefined);
  if (legacy.length === 0) {
    return { migrated: false, reason: 'already_current', records: parsed.records.length };
  }

  const resolvedM = new Map(); // wire hash -> message hash
  if (wiresDir !== null) {
    const wires = indexWires(wiresDir);
    const missing = [];
    for (const r of legacy) {
      const wire = wires.get(r.w);
      if (wire === undefined) { missing.push(`seq ${r.s} ${r.w}`); continue; }
      resolvedM.set(r.w, sha256(messageImage(wire)));
    }
    if (missing.length > 0) throw fail('legacy_wire_missing', missing.join('; '));
  } else if (!discardLegacy) {
    throw fail('legacy_wire_required',
      `${legacy.length} legacy record(s); pass --wires <dir> or explicitly --discard-legacy`);
  }

  let prev = GENESIS_HASH;
  const lines = parsed.records.map((r) => {
    const m = r.v === undefined ? (resolvedM.get(r.w) ?? null) : r.m;
    const body = { v: JOURNAL_FORMAT, s: r.s, t: r.t, w: r.w, m, a: r.a, f: r.f, k: r.k };
    const rec = { ...body, h: chainHash(prev, body) };
    prev = rec.h;
    return JSON.stringify(rec);
  });
  const out = Buffer.from(`${lines.join('\n')}\n`, 'utf8');
  // Self-check before touching disk.
  const check = parseJournal(out);
  if (check.legacyRecords !== 0 || check.records.length !== parsed.records.length) {
    throw fail('migration_self_check_failed');
  }

  const backup = `${resolved}.pre-migrate.bak`;
  const tmp = `${resolved}.migrate.tmp`;
  fs.writeFileSync(backup, raw, { mode: 0o600 });
  fs.chmodSync(backup, 0o600);
  const fd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeSync(fd, out); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, resolved);
  const dfd = fs.openSync(path.dirname(resolved), 'r');
  try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }

  return {
    migrated: true,
    records: parsed.records.length,
    legacyRecords: legacy.length,
    resolved: resolvedM.size === 0 ? 0 : legacy.length,
    unknownMessageRecords: wiresDir === null ? legacy.length : 0,
    backup,
  };
}

module.exports = { migrateJournal };
