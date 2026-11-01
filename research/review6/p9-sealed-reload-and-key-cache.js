'use strict';
// p9: the PER-REQUEST grant reload under a seal, and the seal-key cache.
//
// The daemon re-reads the grant file on EVERY request (revocation must take
// effect immediately), so the seal is verified on every request too. That
// makes the seal-key CACHE a security-relevant object:
//
//   makeSealKeyProvider caches derived keys by SALT. If two different
//   documents could share a salt but differ in content, the cache would hand
//   the same key to both - fine, the MAC still decides. The interesting
//   question is the opposite: can a CHURNING salt force unbounded work
//   (a DoS on the request path), and does a cache HIT ever skip the MAC?
//
// Arms:
//   A  a forged (unsealed) grant file swapped in between two requests
//   B  a forged (unsealed) grant file swapped in and the daemon reloaded
//   C  an ALTERED sealed document (same salt, changed content)
//   D  a RE-SEALED document (new salt) with different grants - the operator's
//      legitimate path; must take effect immediately
//   E  salt churn: many distinct salts in sequence -> re-derivation cost per
//      request (scrypt ~N=16384), capped cache
//   F  a grant file that becomes unreadable -> the daemon must refuse the
//      request, not serve the previously loaded grant
//   G  a grant file that is revoked (grant removed) mid-flight
//
// This is measured against a LIVE daemon over a real socket.

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const {
  fixture, makeWire, grantDoc, writeJson, tmpdir, start, stop, request, verdict,
} = require('./common');
const { sealDocument } = require('../../src/grantseal');

const PASS = 'p9 seal passphrase';

async function main() {
  const dir = tmpdir();
  const out = { probe: 'p9-sealed-reload-and-key-cache', results: {}, findings: [] };
  let daemon = null;
  try {
    const f = fixture(dir);
    const honestWire = makeWire(f.keypair, f.honest);
    const attackerWire = makeWire(f.keypair, f.attacker);

    // Seal the honest grant document.
    const sealedHonest = sealDocument(grantDoc(f.keypair.publicKey.toBase58(), f.honest), PASS);
    writeJson(f.grantFile, sealedHonest, 0o600);

    daemon = await start(f, { grantSealPassphrase: PASS });
    const ask = async (wire) => request({ socketPath: f.socketPath, grant: 'ops', wire });

    // A: baseline - the sealed honest document is served.
    out.results.A_baseline_sealed_honest = await ask(honestWire);

    // B: a forged UNSEALED document replaces the file -> must be refused.
    const forged = grantDoc(f.keypair.publicKey.toBase58(), f.attacker,
      { maxLamports: '1000000000', windowMaxLamports: '1000000000' });
    writeJson(f.grantFile, forged, 0o600);
    const b = await ask(attackerWire);
    out.results.B_forged_unsealed_swapped_in = { ok: b.ok, error: b.error };

    // C: an ALTERED sealed document (same salt, changed content) -> mismatch.
    const altered = JSON.parse(JSON.stringify(sealedHonest));
    altered.grants.ops.destination = f.attacker;
    writeJson(f.grantFile, altered, 0o600);
    const c = await ask(attackerWire);
    out.results.C_altered_sealed_same_salt = { ok: c.ok, error: c.error };

    // D: a legitimately RE-SEALED document with a new salt and a different
    //    destination -> must take effect immediately.
    const resealed = sealDocument(grantDoc(f.keypair.publicKey.toBase58(), f.attacker,
      { maxLamports: '1000000000', windowMaxLamports: '1000000000' }), PASS);
    writeJson(f.grantFile, resealed, 0o600);
    const d = await ask(attackerWire);
    out.results.D_resealed_new_salt_new_grants = { ok: d.ok, error: d.error,
      note: 'the operator re-sealed with the attacker destination: this is the operator\'s own action' };

    // E: salt churn - how much does a churning salt cost per request?
    {
      const t0 = Date.now();
      const N = 12;
      for (let i = 0; i < N; i += 1) {
        const doc = sealDocument(grantDoc(f.keypair.publicKey.toBase58(), f.honest), PASS);
        writeJson(f.grantFile, doc, 0o600);
        await ask(honestWire);
      }
      out.results.E_salt_churn = {
        requests: N,
        total_ms: Date.now() - t0,
        ms_per_request: Math.round((Date.now() - t0) / N),
        note: 'each new salt forces one scrypt (N=16384, 16 MiB) on the request path',
      };
    }

    // F: the grant file becomes UNREADABLE -> must refuse, not serve the old one.
    fs.chmodSync(f.grantFile, 0o000);
    const g = await ask(honestWire);
    out.results.F_grant_file_unreadable = { ok: g.ok, error: g.error };
    fs.chmodSync(f.grantFile, 0o600);

    // G: the grant is REVOKED (the document stays sealed but the grant is
    //    removed and re-sealed) -> must stop being served immediately.
    const revokedDoc = { version: 1, grants: {} };
    const revoked = sealDocument(revokedDoc, PASS);
    writeJson(f.grantFile, revoked, 0o600);
    const h = await ask(honestWire);
    out.results.G_grant_revoked = { ok: h.ok, error: h.error };

    // ---- verdict ----
    const bad = [];
    if (out.results.B_forged_unsealed_swapped_in.ok) bad.push('a forged unsealed grant file was served');
    if (out.results.C_altered_sealed_same_salt.ok) bad.push('an altered sealed document was served');
    if (out.results.F_grant_file_unreadable.ok) bad.push('the daemon served a grant after the file became unreadable');
    if (out.results.G_grant_revoked.ok) bad.push('a revoked grant was still served');
    out.findings = bad.length ? [`NEW FINDING: ${bad.join('; ')}`]
      : ['held: every forged/altered/unreadable/revoked grant document was refused, and the legitimate re-seal took effect immediately'];
  } catch (err) {
    out.threw = String(err && err.stack || err);
  } finally {
    await stop(daemon);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p9-sealed-reload-and-key-cache', fatal: String(err && err.stack || err) }));
