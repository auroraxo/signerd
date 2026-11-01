'use strict';
// P5: R2-5 (one request per connection, refused BEFORE handle()) and R2-6
// (strict canonical base64). All against a LIVE daemon over a real socket.
const net = require('node:net');
const fs = require('node:fs');
const { tmpdir, makeWire, startDaemon, request, Keypair } = require('./common');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function exchange(socketPath, chunks, readMs = 2000) {
  return new Promise((resolve) => {
    const sock = net.connect(socketPath);
    let buf = '';
    let settled = false;
    const done = () => { if (!settled) { settled = true; resolve(buf); } };
    sock.on('connect', () => {
      (async () => { for (const c of chunks) { sock.write(c); await sleep(150); } })();
    });
    sock.on('data', (d) => { buf += d.toString(); });
    sock.on('close', done);
    sock.on('error', done);
    setTimeout(() => { try { sock.destroy(); } catch { /* */ } done(); }, readMs);
  });
}

(async () => {
  const dir = tmpdir('signerd-r5-p5-');
  const out = {};
  const { daemon, socketPath, recipient } = await startDaemon(dir, { name: 'p5' });
  const kp = daemon.keypair;
  const records = () => daemon.ledger.snapshot().records;
  const frame = (w) =>
    JSON.stringify({ grant: 'ops', wire: Buffer.from(w).toString('base64') }) + '\n';
  const fresh = (n) => makeWire(kp, recipient, n);

  // control: one fresh message, one connection
  out.control_single = await request({ socketPath, grant: 'ops', wire: fresh(1000) });
  out.records_after_control = records();

  // R2-5a: TWO complete frames in one write, both fresh messages.
  // If the second frame reached handle() it would be signed -> 2 records and
  // two ok lines instead of one ok + one refusal.
  out.r2_5a_pipelined_raw = await exchange(socketPath, [frame(fresh(1001)) + frame(fresh(1002))]);
  out.records_after_pipelined = records();

  // R2-5b: second frame sent AFTER the response arrived, same connection.
  const lateResult = await new Promise((resolve) => {
    const sock = net.connect(socketPath);
    const state = { firstLine: null, secondFrameAnswer: null, eof: false };
    let buf = '';
    let phase = 0;
    sock.on('connect', () => sock.write(frame(fresh(1003))));
    sock.on('data', (d) => {
      buf += d.toString();
      if (phase === 0 && buf.includes('\n')) {
        state.firstLine = buf.split('\n')[0];
        buf = '';
        phase = 1;
        sock.write(frame(fresh(1004)));
        setTimeout(() => {
          state.unanswered_tail = buf;
          try { sock.end(); } catch { /* */ }
        }, 1000);
      } else if (phase === 1) {
        state.secondFrameAnswer = buf;
      }
    });
    sock.on('close', () => { state.eof = true; resolve(state); });
    sock.on('error', () => resolve(state));
    setTimeout(() => resolve(state), 5000);
  });
  out.r2_5b_late_second_frame = lateResult;
  out.records_after_late = records();

  // R2-6: encodings that must all be request_invalid (not a policy refusal)
  const b64 = Buffer.from(fresh(1005)).toString('base64');
  // base64url: standard base64 with '+' -> '-' and '/' -> '_'. Node's decoder
  // accepts BOTH alphabets, so this is the case R2-6 must refuse.
  let urlVariant = null;
  let sawSpecial = false;
  for (let i = 0; i < 400 && urlVariant === null; i += 1) {
    const s = Buffer.from(fresh(2000 + i)).toString('base64');
    if (s.includes('+') || s.includes('/')) {
      sawSpecial = true;
      urlVariant = s.replace(/\+/g, '-').replace(/\//g, '_');
    }
  }
  if (!sawSpecial) urlVariant = 'a-_b';
  const cases = {
    byte_array: { grant: 'ops', wire: Array.from(Buffer.from(fresh(1006)).slice(0, 32)) },
    base64url: { grant: 'ops', wire: urlVariant },
    leading_space: { grant: 'ops', wire: ` ${b64}` },
    leading_tab: { grant: 'ops', wire: `\t${b64}` },
    empty_string: { grant: 'ops', wire: '' },
    noncanonical_bits: { grant: 'ops', wire: 'QR==' },
    valid: { grant: 'ops', wire: b64 },
  };
  if (b64.endsWith('=')) cases.unpadded = { grant: 'ops', wire: b64.replace(/=+$/, '') };
  out.r2_6 = {};
  for (const [name, body] of Object.entries(cases)) {
    out.r2_6[name] = JSON.parse((await exchange(socketPath,
      [JSON.stringify(body) + '\n'], 2500)).split('\n')[0] || 'null');
  }
  out.records_after_base64_cases = records();

  await daemon.stop();
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => { console.error('PROBE ERROR', err); process.exit(1); });
