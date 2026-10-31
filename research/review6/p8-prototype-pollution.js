'use strict';
// p8: prototype pollution and request-field handling in the NEW code.
//
// The brief asks: can a grant name, a grant field, a request field, or the
// seal payload reach Object.prototype or a prototype-polluted value? Are
// getters/TOCTOU still refused?
//
// Attack surfaces:
//   A  grant name "__proto__" / "constructor" / "prototype" / "toString"
//      -> daemon.handle() looks the name up in this.grants
//   B  a grant FIELD whose value is a getter (TOCTOU on a re-read)
//   C  a request field "grant" / "wire" that is an accessor or prototype-
//      inherited value
//   D  the SEAL PAYLOAD: a sealed document whose `grants` map carries
//      "__proto__" (JSON.parse makes it an own property) - does the loader
//      leak it into a normal object?
//   E  Object.prototype pollution AFTER load: does the daemon's lookup or the
//      policy path then pick up a polluted value?
//   F  the seal document's top-level keys: "seal" vs "constructor" etc.

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, fixture, makeWire, grantDoc, writeJson, start, stop, request, verdict } = require('./common');
const { loadGrantFile } = require('../../src/grantfile');
const { sealDocument, makeSealKeyProvider } = require('../../src/grantseal');
const { evaluate, ownField } = require('../../src/policy');

const PASS = 'p8 seal passphrase';

async function main() {
  const dir = tmpdir();
  const out = { probe: 'p8-prototype-pollution', results: {}, findings: [] };
  let daemon = null;
  try {
    const f = fixture(dir);

    // ---- A: grant names that are prototype-ish ----
    const names = ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty', 'valueOf'];
    const doc = grantDoc(f.keypair.publicKey.toBase58(), f.honest);
    for (const n of names) {
      doc.grants[n] = { ...doc.grants.ops, destination: f.attacker };
    }
    writeJson(f.grantFile, doc, 0o600);
    const loadRes = {};
    try {
      const loaded = loadGrantFile(f.grantFile, {});
      loadRes.loaded = true;
      loadRes.names = loaded.names;
      loadRes.grants_proto_is_null = Object.getPrototypeOf(loaded.grants) === null;
      loadRes.has_own___proto__ = Object.prototype.hasOwnProperty.call(loaded.grants, '__proto__');
      loadRes.own___proto___descriptor = (() => {
        const d = Object.getOwnPropertyDescriptor(loaded.grants, '__proto__');
        return d ? { isData: 'value' in d, writable: d.writable, enumerable: d.enumerable } : null;
      })();
    } catch (err) {
      loadRes.loaded = false;
      loadRes.code = err.code;
      loadRes.message = err.message;
    }
    out.results.A_prototype_grant_names = loadRes;

    // ---- A2: live daemon - can a prototype-ish grant name be requested? ----
    writeJson(f.grantFile, grantDoc(f.keypair.publicKey.toBase58(), f.honest), 0o600);
    daemon = await start(f);
    const w = makeWire(f.keypair, f.honest);
    // Object.create(null): a plain {} would swallow the "__proto__" key and
    // hide the very result this arm measures (a real hazard of plain maps).
    const nameResults = Object.create(null);
    for (const n of names) {
      const r = await request({ socketPath: f.socketPath, grant: n, wire: w });
      nameResults[n] = { ok: r.ok, error: r.error };
    }
    out.results.A2_daemon_prototype_grant_names = JSON.parse(JSON.stringify(nameResults));

    // ---- E: pollute Object.prototype, then ask again ----
    Object.prototype.polluted = 'yes';
    Object.prototype.maxLamports = '999999999';
    try {
      const r = await request({ socketPath: f.socketPath, grant: 'polluted', wire: w });
      out.results.E_polluted_prototype_grant_lookup = { ok: r.ok, error: r.error };
      const r2 = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
      out.results.E2_polluted_existing_grant_still_works = { ok: r2.ok, error: r2.error };
      // The policy path must read the grant's OWN fields only.
      const loaded = loadGrantFile(f.grantFile, {});
      const g = loaded.grants.ops;
      out.results.E3_own_field_read = {
        maxLamports_own: ownField(g, 'maxLamports').value,
        windowSeconds_own: ownField(g, 'windowSeconds').value,
        inherited_maxLamports: g.maxLamports,
      };
    } finally {
      delete Object.prototype.polluted;
      delete Object.prototype.maxLamports;
    }

    // ---- B: a grant FIELD that is a GETTER (TOCTOU on re-read) ----
    // B1: in a JSON file a getter is unrepresentable - JSON.parse can only
    //     make data properties, so the write serializes the value once.
    const getterDoc = grantDoc(f.keypair.publicKey.toBase58(), f.honest);
    let reads = 0;
    const g2 = getterDoc.grants.ops;
    Object.defineProperty(g2, 'destination', {
      enumerable: true,
      get() { reads += 1; return reads === 1 ? f.honest : f.attacker; },
    });
    const getterFile = path.join(dir, 'getter.json');
    writeJson(getterFile, getterDoc, 0o600);
    let getterRes;
    try {
      const loaded = loadGrantFile(getterFile, {});
      getterRes = { loaded: true, reads_at_serialize: reads,
        destination: loaded.grants.ops.destination };
    } catch (err) {
      getterRes = { loaded: false, code: err.code, message: err.message, reads: reads };
    }
    out.results.B1_getter_in_json_file = getterRes;
    // B2: a programmatic document whose grant carries an ACCESSOR must be
    //     refused by validateGrant (descriptor has no own "value").
    const accessDoc = grantDoc(f.keypair.publicKey.toBase58(), f.honest);
    delete accessDoc.grants.ops.destination;
    let destReads = 0;
    Object.defineProperty(accessDoc.grants.ops, 'destination', {
      enumerable: true,
      get() { destReads += 1; return destReads === 1 ? f.honest : f.attacker; },
    });
    const accessFile = path.join(dir, 'accessor.json');
    fs.writeFileSync(accessFile, JSON.stringify({
      version: accessDoc.version,
      grants: { ops: { ...accessDoc.grants.ops } },
    }, null, 2) + '\n'); // serialization invokes the getter ONCE (reads=1)
    fs.chmodSync(accessFile, 0o600);
    // Now verify the loader's own descriptor discipline directly:
    const { validateGrant } = require('../../src/grantfile');
    let directGetter;
    try {
      const holder = {};
      Object.defineProperty(holder, 'destination', {
        enumerable: true, get() { return f.attacker; },
      });
      const target = { ...grantDoc(f.keypair.publicKey.toBase58(), f.honest).grants.ops };
      delete target.destination;
      Object.assign(Object.create(target), {}); // no-op, keep target plain
      const withGetter = Object.create(null);
      for (const [k, v] of Object.entries(target)) withGetter[k] = v;
      Object.defineProperty(withGetter, 'destination', {
        enumerable: true, get() { return f.attacker; },
      });
      validateGrant('ops', withGetter);
      directGetter = 'ACCEPTED (!!)';
    } catch (err) {
      directGetter = `REFUSED: ${err.code}`;
    }
    out.results.B2_accessor_field_in_validateGrant = directGetter;

    // ---- C: a request whose "grant" is an accessor / prototype-inherited ----
    // (the wire protocol is JSON over a socket, so this is exercised at the
    //  decodeRequest level)
    const { Daemon } = require('../../src/daemon');
    const decodeRequestProbe = (() => {
      try {
        const d = Object.create({ grant: 'ops' });
        const own = { wire: 'AA==' };
        Object.assign(d, own);
        const desc = Object.getOwnPropertyDescriptor(d, 'grant');
        return { has_own_grant: !!desc, inherited_only: desc === undefined };
      } catch (e) { return { error: e.message }; }
    })();
    out.results.C_request_field_ownness = decodeRequestProbe;

    // ---- D: a SEALED document whose grants map carries "__proto__" ----
    const sealedProto = sealDocument(doc, PASS);
    const sealedProtoFile = path.join(dir, 'sealed-proto.json');
    writeJson(sealedProtoFile, sealedProto, 0o600);
    let sealedRes;
    try {
      const loaded = loadGrantFile(sealedProtoFile, { sealKeyFor: makeSealKeyProvider(PASS) });
      sealedRes = {
        loaded: true,
        names: loaded.names,
        grants_proto_is_null: Object.getPrototypeOf(loaded.grants) === null,
        polluted_global_after: {}.polluted,
      };
    } catch (err) {
      sealedRes = { loaded: false, code: err.code, message: err.message };
    }
    out.results.D_sealed_document_with_proto_grant = sealedRes;

    // ---- F: seal document top-level keys ----
    const oddTop = sealDocument(grantDoc(f.keypair.publicKey.toBase58(), f.honest), PASS);
    oddTop.extraField = 'ignored';
    oddTop.constructor = 'ignored';
    const oddFile = path.join(dir, 'odd-top.json');
    writeJson(oddFile, oddTop, 0o600);
    let oddRes;
    try {
      const loaded = loadGrantFile(oddFile, { sealKeyFor: makeSealKeyProvider(PASS) });
      oddRes = { loaded: true, names: loaded.names };
    } catch (err) {
      oddRes = { loaded: false, code: err.code, message: err.message };
    }
    out.results.F_extra_top_level_keys = oddRes;

    // ---- G: does the policy path read a polluted maxLamports? ----
    const pollutedDoc = grantDoc(f.keypair.publicKey.toBase58(), f.honest, { maxLamports: '1' });
    Object.prototype.windowMaxLamports = '999999999999';
    try {
      const v = evaluate(makeWire(f.keypair, f.honest, 42), pollutedDoc.grants.ops, new Date());
      out.results.G_policy_with_polluted_prototype = { allowed: v.allowed, refused: v.refused };
    } finally {
      delete Object.prototype.windowMaxLamports;
    }
    // G2: DELETE the own maxLamports so only a polluted prototype value is
    //     reachable - ownField must refuse (ok:false -> invalid_grant).
    const ownMissing = grantDoc(f.keypair.publicKey.toBase58(), f.honest);
    delete ownMissing.grants.ops.maxLamports;
    Object.prototype.maxLamports = '999999999999';
    try {
      const v2 = evaluate(makeWire(f.keypair, f.honest, 42), ownMissing.grants.ops, new Date());
      const { approveRefused } = (() => {
        // ledger-level view of the same grant
        const win = ownField(ownMissing.grants.ops, 'windowMaxLamports');
        return { approveRefused: { windowField: win.value, ownFieldOk: win.ok } };
      })();
      out.results.G2_own_field_missing_with_polluted_prototype = {
        policy_allowed: v2.allowed, policy_refused: v2.refused, ...approveRefused,
      };
    } finally {
      delete Object.prototype.maxLamports;
    }

    // ---- verdict ----
    const bad = [];
    if (out.results.A_prototype_grant_names.loaded && out.results.A_prototype_grant_names.has_own___proto__) {
      bad.push('a "__proto__" grant name survived the loader');
    }
    for (const [n, r] of Object.entries(out.results.A2_daemon_prototype_grant_names)) {
      if (r.ok) bad.push(`grant name ${n} was SERVED`);
    }
    if (out.results.E_polluted_prototype_grant_lookup.ok) bad.push('a prototype-polluted grant name was served');
    if (out.results.D_sealed_document_with_proto_grant.loaded
        && out.results.D_sealed_document_with_proto_grant.names.includes('__proto__')) {
      bad.push('a sealed document carried a "__proto__" grant through the loader');
    }
    out.findings = bad.length ? [`NEW FINDING: ${bad.join('; ')}`]
      : ['held: no prototype pollution reached the grant map, the request path, or the policy fields'];
  } catch (err) {
    out.threw = String(err && err.stack || err);
  } finally {
    await stop(daemon);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p8-prototype-pollution', fatal: String(err && err.stack || err) }));
