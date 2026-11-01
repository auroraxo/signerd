'use strict';
// P17: R3-2 bypass attempts — can a format-1 record be smuggled past the
// legacy refusal?
//   (i)   a format-1 record with an explicit "v":1 field (chain re-computed by
//         the operator, i.e. the file is otherwise valid)
//   (ii)  a format-1 record that also carries "m" (looks like format 2)
//   (iii) mixed journal: format-3 record first, format-1 record second
//   (iv)  format-3 record with m=null + m=null twice (identity-unknown abuse)
//   Each must be REFUSED (or, for a legitimately migrated file, loaded).
const fs = require('node:fs');
const path = require('node:path');
const { tmpdir, Keypair } = require('./common');
const { Ledger, parseJournal, chainHash, GENESIS_HASH } = require('../../src/ledger');

const signer = Keypair.generate();
const dest = Keypair.generate().publicKey;
void signer; void dest;

const dir = tmpdir('signerd-r5-p17-');
const out = {};
const { spawnSync } = require('node:child_process');

function rechain(recs) {
  let prev = GENESIS_HASH;
  return recs.map((r) => {
    const h = chainHash(prev, r);
    prev = h;
    return JSON.stringify({ ...r, h });
  }).join('\n') + '\n';
}

function tryLoad(name, content) {
  const f = path.join(dir, `${name}.jsonl`);
  fs.writeFileSync(f, content);
  fs.chmodSync(f, 0o600);
  try {
    const l = new Ledger({ file: f });
    out[name] = { observed: 'ACCEPTED', snapshot: l.snapshot(), legacyState: l.legacyState() };
  } catch (err) {
    out[name] = { observed: `REFUSED ${err.code || err.message}` };
  }
}

// a genuine format-1 record (no v, no m) from the repo fixture
const fixture = fs.readFileSync(
  path.join(__dirname, '..', '..', 'test', 'fixtures', 'format1-ledger.jsonl'), 'utf8');
out.fixture_parse = (() => {
  try { const p = parseJournal(Buffer.from(fixture)); return { legacyRecords: p.legacyRecords }; }
  catch (e) { return { error: e.message }; }
})();

// (i) format-1 record + explicit v:1
{
  const recs = fixture.trim().split('\n').map((l) => JSON.parse(l));
  const withV = recs.map((r) => ({ ...r, v: 1 }));
  tryLoad('i_format1_with_v1', rechain(withV));
}

// (ii) format-1 record + m field
{
  const recs = fixture.trim().split('\n').map((l) => JSON.parse(l));
  const withM = recs.map((r) => ({
    ...r, m: 'a'.repeat(64),
  }));
  tryLoad('ii_format1_with_m', rechain(withM));
}

// (iii) mixed: format-3 record then format-1 record
{
  const recs = fixture.trim().split('\n').map((l) => JSON.parse(l));
  const first = recs[0];
  const fmt3 = {
    v: 3, s: 1, t: first.t, w: first.w, m: 'b'.repeat(64),
    a: first.a, f: first.f, k: first.k,
  };
  const legacy2 = { ...recs[1], s: 2 };
  delete legacy2.v;
  tryLoad('iii_mixed_3_then_1', rechain([fmt3, legacy2]));
}

// (iv) two format-3 records with m=null and identical m=null (identity unknown)
{
  const recs = fixture.trim().split('\n').map((l) => JSON.parse(l));
  const r1 = {
    v: 3, s: 1, t: recs[0].t, w: recs[0].w, m: null,
    a: recs[0].a, f: recs[0].f, k: recs[0].k,
  };
  const r2 = {
    v: 3, s: 2, t: recs[1].t, w: recs[1].w, m: null,
    a: recs[1].a, f: recs[1].f, k: recs[1].k,
  };
  tryLoad('iv_two_null_m', rechain([r1, r2]));
}

// (v) duplicate m across two format-3 records (same message identity twice)
{
  const recs = fixture.trim().split('\n').map((l) => JSON.parse(l));
  const r1 = {
    v: 3, s: 1, t: recs[0].t, w: recs[0].w, m: 'c'.repeat(64),
    a: recs[0].a, f: recs[0].f, k: recs[0].k,
  };
  const r2 = {
    v: 3, s: 2, t: recs[1].t, w: recs[1].w, m: 'c'.repeat(64),
    a: recs[1].a, f: recs[1].f, k: recs[1].k,
  };
  tryLoad('v_duplicate_m', rechain([r1, r2]));
}

// (vi) CLI: does `signerd status` really refuse a format-1 journal (fail closed)?
{
  const f = path.join(dir, 'cli-format1.jsonl');
  fs.copyFileSync(path.join(__dirname, '..', '..', 'test', 'fixtures', 'format1-ledger.jsonl'), f);
  fs.chmodSync(f, 0o600);
  const grants = path.join(dir, 'g.json');
  fs.writeFileSync(grants, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: signer.publicKey.toBase58(), destination: dest.toBase58(),
        maxLamports: '1000', expiresAt: '2099-01-01T00:00:00Z',
        windowMaxLamports: '1000', windowSeconds: '60',
      },
    },
  }));
  fs.chmodSync(grants, 0o600);
  const r = spawnSync(process.execPath,
    [path.join(__dirname, '..', '..', 'bin', 'signerd.js'), 'status',
      '--grants', grants, '--ledger', f],
    { encoding: 'utf8' });
  out.vi_cli_status = { status: r.status, firstLine: (r.stderr || '').split('\n')[0] };
}

console.log(JSON.stringify(out, null, 2));
fs.rmSync(dir, { recursive: true, force: true });
