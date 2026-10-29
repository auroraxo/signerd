// Canonical openreceipts/v1 message bytes + Ed25519 identity helpers.
//
// openreceipts signs `json.dumps(obj, sort_keys=True, separators=(",", ":"))`
// (Python, ensure_ascii=True by default). That is NOT plain JSON.stringify:
//   - Python escapes every non-ASCII code point as \uXXXX (astral as a
//     surrogate pair), JavaScript emits the raw UTF-8 characters;
//   - Python's default separators are "," and ":" (JSON.stringify is the
//     same for these two, but the escaping difference alone changes bytes).
//
// Signing or verifying the wrong byte string yields a "correct" answer about
// the wrong message, so the canonicalization is implemented here once and
// pinned by tests against literals produced by python3 itself.
//
// Reference implementation mirrored here: openreceipts/verify.mjs (pyEsc).

'use strict';

const { createPublicKey, verify: edVerify } = require('node:crypto');

function pyEsc(str) {
  let out = '';
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp > 0x7e) {
      if (cp > 0xffff) {
        const v = cp - 0x10000;
        out += '\\u' + (0xd800 + (v >> 10)).toString(16).padStart(4, '0');
        out += '\\u' + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, '0');
      } else {
        out += '\\u' + cp.toString(16).padStart(4, '0');
      }
    } else out += ch;
  }
  return out;
}

// Canonical bytes of an openreceipts receipt body.
function canonicalReceiptBytes(obj) {
  const canonical = (v) => {
    if (v === null) return 'null';
    if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
    if (typeof v === 'object') {
      return (
        '{' +
        Object.keys(v)
          .sort()
          .map((k) => pyEsc(JSON.stringify(k)) + ':' + canonical(v[k]))
          .join(',') +
        '}'
      );
    }
    if (typeof v === 'string') return pyEsc(JSON.stringify(v));
    return JSON.stringify(v);
  };
  return Buffer.from(canonical(obj), 'utf8');
}

// Raw 32-byte Ed25519 public key from a JWK-shaped object {x: base64url}.
function rawPublicKeyFromJwk(raw) {
  if (!raw || raw.length !== 32) throw new Error('public key is not 32 raw bytes');
  return createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
    format: 'jwk',
  });
}

// Verify an Ed25519 signature over `message` with a raw 32-byte public key.
function verifyEd25519(rawPub, message, sig) {
  if (!rawPub || rawPub.length !== 32) return false;
  if (!sig || sig.length !== 64) return false;
  try {
    return edVerify(null, message, rawPublicKeyFromJwk(rawPub), sig);
  } catch {
    return false;
  }
}

// Raw 32-byte Ed25519 public key behind a PKCS8 PEM private key.
function rawPublicKeyFromPkcs8Pem(pem) {
  const { createPrivateKey } = require('node:crypto');
  const priv = createPrivateKey({ key: pem, format: 'pem' });
  const der = priv.export({ type: 'pkcs8', format: 'der' });
  const seed = Buffer.from(der.subarray(der.length - 32));
  const raw = Buffer.from(
    createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32),
  );
  return { raw, seed };
}

module.exports = {
  canonicalReceiptBytes,
  pyEsc,
  rawPublicKeyFromJwk,
  rawPublicKeyFromPkcs8Pem,
  verifyEd25519,
};
