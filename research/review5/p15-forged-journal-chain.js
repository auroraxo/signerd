'use strict';
// P15: does the journal's hash chain protect against a FORGER?
//
// The code comment says: "the chain hash is unkeyed sha256, so a forged
// journal validates. Content provenance is broken once a stranger can write".
// Probe: a stranger (uid nobody) who had write access ONCE (journal 0666)
// forges journal records with a RECOMPUTED chain, then the operator tightens
// the mode to 0600 and the daemon loads the forged journal.
//
//   f1 forged journal with a recomputed chain loads
//   f2 a forged record that LOWERS the recorded spend -> the window budget is
//      reset -> the daemon signs beyond the cap
//   f3 a forged journal that DROPS the record of an already-signed message ->
//      the daemon signs the SAME message again (double sign)
//   control: an in-place edit WITHOUT re-chaining is refused (ledger_tampered)
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { tmpdir, grantDoc, writeGrants, makeWire, request, Keypair } = require('./common');
const { Daemon } = require('../../src/daemon');

(async () => {
  const dir = tmpdir('signerd-r5-p15-');
  fs.chmodSync(dir, 0o755);
  const out = {};
  const keypair = Keypair.generate();
  const recipient = Keypair.generate().publicKey;
  const grantsFile = path.join(dir, 'grants.json');
  // tight window: 10000 lamports cap, so a forged spend reduction is visible
  const gdoc = grantDoc(keypair.publicKey.toBase58(), recipient.toBase58(),
    { windowMaxLamports: '10000', windowSeconds: '3600' });
  writeGrants(grantsFile, gdoc);
  const socketPath = path.join(dir, 'p15.sock');
  const ledgerFile = path.join(dir, 'p15-journal.jsonl');

  // 1. daemon signs two messages
  const d1 = new Daemon({ socketPath, keypair, grantFile: grantsFile, ledgerFile });
  await d1.start();
  const wireA = makeWire(keypair, recipient, 42);
  const wireB = makeWire(keypair, recipient, 43);
  const firstA = await request({ socketPath, grant: 'ops', wire: wireA });
  const firstB = await request({ socketPath, grant: 'ops', wire: wireB });
  out.signs = {
    A: { ok: firstA.ok, seq: firstA.seq, spent: firstA.windowSpentLamports },
    B: { ok: firstB.ok, seq: firstB.seq, spent: firstB.windowSpentLamports },
  };
  out.control_resend_A_with_intact_journal =
    await request({ socketPath, grant: 'ops', wire: Buffer.from(firstA.signed, 'base64') });
  // a third request must be refused by the window cap (42+43+5000+5000 > 10000)
  out.control_third_request_window_capped =
    await request({ socketPath, grant: 'ops', wire: makeWire(keypair, recipient, 44) });
  await d1.stop();
  const originalJournal = fs.readFileSync(ledgerFile, 'utf8');
  out.journal_lines = originalJournal.trim().split('\n').length;

  // helper python: re-chain a list of record dicts
  const forge = (mode) => `
import json, hashlib, os
p = ${JSON.stringify(ledgerFile)}
recs = [json.loads(l) for l in open(p).read().split('\\n') if l.strip()]
mode = ${JSON.stringify(mode)}
if mode == 'drop_last':
    recs = recs[:-1]
elif mode == 'drop_first':
    recs = recs[1:]
    for i, r in enumerate(recs):
        r['s'] = i + 1
elif mode == 'zero_amount':
    recs[-1]['a'] = '0'
def body(r):
    m = 'null' if r.get('m') is None else r['m']
    return '\\x00'.join([str(r['v']), str(r['s']), str(r['t']), str(r['w']), m, str(r['a']), str(r['f']), str(r['k'])])
prev = '0'*64
out = []
for r in recs:
    r['h'] = hashlib.sha256((prev + '\\x00' + body(r)).encode()).hexdigest()
    prev = r['h']
    out.append(json.dumps(r, separators=(',',':')))
payload = (('\\n'.join(out) + '\\n') if out else '').encode()
fd = os.open(p, os.O_WRONLY | os.O_TRUNC)
os.write(fd, payload)
os.close(fd)
print('forged', len(out), 'records', flush=True)
`;

  // control: an in-place edit WITHOUT re-chaining must be refused
  const tampered = path.join(dir, 'tampered.jsonl');
  fs.writeFileSync(tampered, originalJournal.replace('"a":"42"', '"a":"12"'));
  fs.chmodSync(tampered, 0o600);
  try {
    const { Ledger } = require('../../src/ledger');
    new Ledger({ file: tampered });
    out.control_unchained_edit = 'ACCEPTED (no integrity!)';
  } catch (err) {
    out.control_unchained_edit = `REFUSED ${err.code || err.message}`;
  }

  // ---- f2: forged record with a LOWERED amount -> window budget reset ----
  fs.chmodSync(ledgerFile, 0o666);
  const fr2 = spawnSync('sudo', ['-n', '-u', 'nobody', 'python3', '-c', forge('zero_amount')],
    { encoding: 'utf8' });
  out.forge_zero_amount = (fr2.stdout || fr2.stderr || '').trim();
  fs.chmodSync(ledgerFile, 0o600);
  let d2 = null;
  try {
    d2 = new Daemon({ socketPath: path.join(dir, 'p15b.sock'), keypair, grantFile: grantsFile, ledgerFile });
    await d2.start();
    out.f2_forged_journal_loaded = true;
    out.f2_snapshot = d2.ledger.snapshot();
    out.f2_records = d2.ledger.records.map((r) => ({ s: r.s, a: r.a, f: r.f }));
  } catch (err) {
    out.f2_forged_journal_loaded = `REFUSED ${err.code || err.message}`;
  }
  if (d2) {
    // the window cap should now be much larger than before the forgery
    const third = await request({
      socketPath: path.join(dir, 'p15b.sock'), grant: 'ops', wire: makeWire(keypair, recipient, 44),
    });
    out.f2_request_that_was_capped_before =
      third.ok ? { ok: true, seq: third.seq, spent: third.windowSpentLamports }
        : { ok: false, error: third.error };
    await d2.stop();
  }

  // ---- f3: forged journal that DROPS the record of message A -> double sign ----
  fs.chmodSync(ledgerFile, 0o666);
  const fr3 = spawnSync('sudo', ['-n', '-u', 'nobody', 'python3', '-c', forge('drop_first')],
    { encoding: 'utf8' });
  out.forge_drop_last = (fr3.stdout || fr3.stderr || '').trim();
  fs.chmodSync(ledgerFile, 0o600);
  const sock3 = path.join(dir, 'p15c.sock');
  let d3 = null;
  try {
    d3 = new Daemon({ socketPath: sock3, keypair, grantFile: grantsFile, ledgerFile });
    await d3.start();
    out.f3_forged_journal_loaded = true;
    out.f3_snapshot = d3.ledger.snapshot();
  } catch (err) {
    out.f3_forged_journal_loaded = `REFUSED ${err.code || err.message}`;
  }
  if (d3) {
    // A was dropped: the signed artifact of A must be signed AGAIN
    out.f3_resend_signed_A_after_forgery =
      await request({ socketPath: sock3, grant: 'ops', wire: Buffer.from(firstA.signed, 'base64') });
    await d3.stop();
  }

  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
