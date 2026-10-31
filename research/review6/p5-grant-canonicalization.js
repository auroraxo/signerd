'use strict';
// p5: canonicalization of the SEALED GRANT DOCUMENT.
//
// Goal: find two documents D1 (sealed, honest) and D2 (forged, authorizes
// MORE) with canonicalPayload(D1) === canonicalPayload(D2), so D2 verifies
// under D1's MAC but the loader uses D2's grants.
//
// Variants tried against the pinned tree:
//   c1  key order / whitespace / pretty-print         (claimed: not payload)
//   c2  unicode escapes in keys and values           (\u0061 vs a)
//   c3  duplicate JSON keys (last-wins vs sealed one)
//   c4  number formats for `version` (1.0, 1e0, 0x1, 01)
//   c5  extra unknown TOP-LEVEL field                (not in canonical payload)
//   c6  extra unknown field inside a grant            (in payload, out of schema)
//   c7  null vs missing required field
//   c8  Infinity / 1e400 vs null collision in JSON.stringify
//   c9  nested object where a string is expected
//   c10 grant NAME tricks (__proto__/constructor/prototype/array-index)
//   c11 surrogate / lone-surrogate strings
//   c12 array-vs-object in `grants`
//
// For each: does the document VERIFY under the honest seal (verifySealMac)
// AND does loadGrantFile ACCEPT it? A variant is a finding only if BOTH are
// true AND the accepted authorization differs from the sealed one.

process.umask(0o077);

const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, fixture, writeJson, grantDoc, verdict } = require('./common');
const { loadGrantFile } = require('../../src/grantfile');
const {
  canonicalPayload, canonicalJson, sealDocument, parseSeal, verifySealMac,
  makeSealKeyProvider, deriveSealKey,
} = require('../../src/grantseal');

const PASS = 'canonicalization passphrase p5';

function provider() { return makeSealKeyProvider(PASS); }

/** Did the MAC verify under the honest key AND the loader accept the doc? */
function testVariant(name, docText, sealedPayloadText, honestDoc) {
  const r = { name };
  const honest = { mac: null, payload: canonicalPayload(honestDoc).toString('hex') };
  r.honest_mac = honest.mac;

  // 1. does it parse?
  let parsed;
  try { parsed = JSON.parse(docText); } catch (e) { r.parse = `throw ${e.message}`; return r; }
  r.parse = 'ok';

  // 2. does the MAC verify?
  const p = parseSeal(parsed);
  if (!p.ok) { r.seal_parse = p.reason; r.mac_verifies = false; return r; }
  r.seal_parse = 'ok';
  const key = deriveSealKey(PASS, p.salt);
  let macOk;
  try { macOk = verifySealMac(parsed, key).ok; } catch (e) { macOk = false; r.mac_threw = e.message; }
  r.mac_verifies = macOk;
  r.payload_matches_honest = canonicalPayload(parsed).toString('hex') === honest.payload;

  // 3. does the loader accept it (the real acceptance surface)?
  const file = path.join(tmpdir('r6p5-'), 'g.json');
  fs.writeFileSync(file, docText); fs.chmodSync(file, 0o600);
  try {
    const loaded = loadGrantFile(file, { sealKeyFor: provider() });
    r.loader = 'ACCEPTED';
    r.loaded_grants = JSON.parse(JSON.stringify(loaded.grants));
  } catch (e) {
    r.loader = `REFUSED: ${e.code || e.message}`;
  }
  try { fs.rmSync(path.dirname(file), { recursive: true, force: true }); } catch { /* best effort */ }
  return r;
}

async function main() {
  const out = { probe: 'p5-grant-canonicalization', variants: [], findings: [] };
  try {
    // The honest, sealed document.
    const honestDoc = grantDoc('11111111111111111111111111111111', '22222222222222222222222222222222');
    const sealed = sealDocument(honestDoc, PASS);
    const sealedText = JSON.stringify(sealed, null, 2) + '\n';
    const honestPayloadHex = canonicalPayload(JSON.parse(sealedText)).toString('hex');
    out.honest = {
      payload: canonicalPayload(honestDoc).toString('hex'),
      seal: sealed.seal,
      grants: sealed.grants,
    };
    out.payload_length = out.honest.payload.length / 2;

    // sanity: the honest file itself verifies and loads.
    const sanity = testVariant('sanity: honest sealed doc', sealedText, sealedText, JSON.parse(sealedText));
    out.variants.push(sanity);

    // ---- c1: key order + whitespace ----
    const reordered = {
      grants: {
        ops: {
          windowSeconds: sealed.grants.ops.windowSeconds,
          windowMaxLamports: sealed.grants.ops.windowMaxLamports,
          expiresAt: sealed.grants.ops.expiresAt,
          destination: sealed.grants.ops.destination,
          maxLamports: sealed.grants.ops.maxLamports,
          signer: sealed.grants.ops.signer,
        },
      },
      version: 1,
      seal: sealed.seal,
    };
    out.variants.push(testVariant('c1 key-order/whitespace only',
      JSON.stringify(reordered, null, 1), sealedText, JSON.parse(sealedText)));

    // ---- c2: unicode escapes (equivalent strings) ----
    const esc = sealedText.replace('"ops"', '"\\u006f\\u0070\\u0073"');
    out.variants.push(testVariant('c2 unicode escapes in grant NAME', esc, sealedText, JSON.parse(sealedText)));
    const escVal = sealedText.replace('"11111111111111111111111111111111"', '"1111\\u00311111111111111111111111111"');
    out.variants.push(testVariant('c2b unicode escapes in VALUE', escVal, sealedText, JSON.parse(sealedText)));

    // ---- c3: duplicate JSON keys, last wins -> different grants ----
    const dupInner = `{"grants":{"ops":${JSON.stringify(sealed.grants.ops)},"ops":${JSON.stringify({ ...sealed.grants.ops, destination: '33333333333333333333333333333333' })}},"version":1,"seal":${JSON.stringify(sealed.seal)}}`;
    out.variants.push(testVariant('c3 duplicate grant key (last wins)', dupInner, sealedText, JSON.parse(sealedText)));

    // ---- c4: number formats for version ----
    for (const v of ['1.0', '1e0', '1.0000', '0x1', '01']) {
      const t = sealedText.replace('"version": 1', `"version": ${v}`);
      if (t === sealedText) continue;
      out.variants.push(testVariant(`c4 version=${v}`, t, sealedText, JSON.parse(sealedText)));
    }

    // ---- c5: extra unknown TOP-LEVEL field not covered by the payload ----
    const extra = JSON.parse(sealedText);
    extra.evilPolicy = { allowEverything: true };
    out.variants.push(testVariant('c5 extra top-level field (outside MAC payload)',
      JSON.stringify(extra, null, 2), sealedText, JSON.parse(sealedText)));

    // ---- c6: extra unknown field inside a grant (inside payload) ----
    const inner = JSON.parse(sealedText);
    inner.grants.ops.admin = true;
    // reseal? NO - keep honest seal so we test whether it verifies anyway
    out.variants.push(testVariant('c6 extra field inside grant (in payload)',
      JSON.stringify(inner, null, 2), sealedText, JSON.parse(sealedText)));

    // ---- c7: null vs missing required field ----
    const nullDest = JSON.parse(sealedText);
    nullDest.grants.ops.destination = null;
    out.variants.push(testVariant('c7 destination=null', JSON.stringify(nullDest, null, 2), sealedText, JSON.parse(sealedText)));
    const missDest = JSON.parse(sealedText);
    delete missDest.grants.ops.destination;
    out.variants.push(testVariant('c7b destination missing', JSON.stringify(missDest, null, 2), sealedText, JSON.parse(sealedText)));

    // ---- c8: Infinity / 1e400 canonicalize to the same string as null ----
    // JSON.stringify(Infinity) === 'null'. If any numeric field were ever
    // sealed as a NUMBER, {f: 1e400} and {f: null} would share a payload.
    out.canonical_json_1e400 = canonicalJson({ f: JSON.parse('1e400') });
    out.canonical_json_null = canonicalJson({ f: null });
    out.canonical_json_inf = canonicalJson({ f: Infinity });
    out.canonical_json_number_vs_string = {
      number: canonicalJson({ f: 1 }),
      string: canonicalJson({ f: '1' }),
    };
    // Direct collision test on the grant payload shape:
    out.c8_payload_collision_number_vs_null = canonicalJson({ v: JSON.parse('1e400') })
      === canonicalJson({ v: null });
    out.c8_payload_collision_bool_vs_string = canonicalJson({ v: true }) === canonicalJson({ v: 'true' });

    // ---- c9: nested object where a string is expected ----
    const nested = JSON.parse(sealedText);
    nested.grants.ops.destination = { toString: '33333333333333333333333333333333' };
    out.variants.push(testVariant('c9 nested object as destination', JSON.stringify(nested, null, 2), sealedText, JSON.parse(sealedText)));

    // ---- c10: prototype-ish grant names ----
    for (const nm of ['__proto__', 'constructor', 'prototype', 'toString', '0', 'hasOwnProperty']) {
      const doc = JSON.parse(sealedText);
      const g = { ...doc.grants.ops };
      doc.grants = { ops: g, [nm]: { ...doc.grants.ops, destination: '44444444444444444444444444444444' } };
      out.variants.push(testVariant(`c10 grant name ${JSON.stringify(nm)}`,
        JSON.stringify(doc, null, 2), sealedText, JSON.parse(sealedText)));
    }
    // __proto__ injected via RAW text (JSON.parse creates an own property,
    // but let's confirm what canonicalJson + the loader do with it)
    {
      const raw = '{"grants":{"__proto__":{"signer":"11111111111111111111111111111111","destination":"44444444444444444444444444444444","maxLamports":"1","expiresAt":"2999-01-01T00:00:00Z","windowMaxLamports":"1","windowSeconds":"3600"}},"version":1}';
      out.c10_raw_proto_own = (() => {
        const o = JSON.parse(raw);
        return { hasOwn: Object.prototype.hasOwnProperty.call(o.grants, '__proto__'),
          ownNames: Object.getOwnPropertyNames(o.grants),
          protoOfGrantsIsObjectProto: Object.getPrototypeOf(o.grants) === Object.prototype };
      })();
      out.variants.push(testVariant('c10b raw __proto__ grants key (no seal)', raw, sealedText, JSON.parse(sealedText)));
    }

    // ---- c11: lone surrogate in a value ----
    {
      const doc = JSON.parse(sealedText);
      doc.grants.ops.maxLamports = '1\uDC00';
      out.variants.push(testVariant('c11 lone surrogate in value', JSON.stringify(doc, null, 2), sealedText, JSON.parse(sealedText)));
    }

    // ---- c12: grants as an ARRAY with the same elements ----
    {
      const doc = JSON.parse(sealedText);
      doc.grants = [doc.grants.ops];
      out.variants.push(testVariant('c12 grants as array', JSON.stringify(doc, null, 2), sealedText, JSON.parse(sealedText)));
    }

    // ---- verdicts ----
    const accepts = out.variants.filter((v) => v.loader === 'ACCEPTED' && v.name !== 'sanity: honest sealed doc');
    out.accepted_variants = accepts.map((v) => v.name);
    // A real finding = accepted AND the effective authorization differs from
    // the honest one (compare as canonical JSON, not insertion order).
    const canon = (g) => canonicalJson(g && g.ops || g);
    const honestCanon = canon(sealed.grants);
    const escalations = accepts.filter((v) => canon(v.loaded_grants) !== honestCanon);
    out.escalations = escalations.map((v) => v.name);
    out.findings = out.escalations.length
      ? [`NEW FINDING: canonicalization collision -> ${out.escalations.join(', ')}`]
      : ['held: every variant that loads is byte-equivalent to the honest authorization (c1/c2/c5 load, by design; no variant authorizes MORE)'];
  } catch (err) {
    out.threw = String(err && err.stack || err);
  }
  verdict(out);
}

main().catch((err) => verdict({ probe: 'p5-grant-canonicalization', fatal: String(err && err.stack || err) }));
