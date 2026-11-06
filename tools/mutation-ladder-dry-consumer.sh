#!/usr/bin/env bash
# MUTATION LADDER for the dry-run consumer falsification.
#
# WHY (measured 2026-11-06): test/dry-consumer-falsification.test.js claims
# "an allowed dry run leaves the machine untouched, so the identical body
# still signs for real afterwards". A claim like that can pass for the wrong
# reason: a test that only checks the happy path also passes when the dry
# path quietly journals, or when the refusal reason is different from the real
# one. Each mutation below breaks ONE of the promises the way a plausible
# regression would; the ladder passes only if EVERY mutation turns the test
# RED and the tree comes back byte-identical.
#
# The ladder restores the tree from a BYTE COPY (not `git checkout --`):
# a checkout would silently DISCARD an uncommitted fix, which happened twice
# in this repo (measured 2026-11-06).
#
# Usage: tools/mutation-ladder-dry-consumer.sh
# Exit 0 = every mutation was caught, the tree is byte-identical again.

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TEST="test/dry-consumer-falsification.test.js"
SNAP="$(mktemp -d /tmp/signerd-ladder-dry-XXXXXX)"
cp -a bin src "$SNAP/"
trap 'rm -rf "$SNAP"' EXIT

restore() { rm -rf bin src; cp -a "$SNAP/bin" "$SNAP/src" .; }

tree_hash() {
  { find bin src -type f -print0 | sort -z | xargs -0 sha256sum; } | sha256sum | cut -d' ' -f1
}

BEFORE="$(tree_hash)"

run_test() { timeout 180 node --test --test-reporter=spec "$TEST" 2>&1; }

FAILED=0
CAUGHT=0

# mutate <name> <node-mutation-file>
# The mutation file is a Node script: it receives the repo root as argv[2] and
# edits exactly one thing. It exits non-zero if its anchor was not found —
# a mutation that does not apply would silently "pass" the ladder.
mutate() {
  local name="$1" script="$2"
  restore
  if ! node "$script" "$ROOT"; then
    echo "MUTATION SETUP FAILED: $name (anchor not found)"
    FAILED=$((FAILED + 1))
    restore
    return
  fi
  local out
  out="$(run_test)"
  if echo "$out" | grep -qE '^. fail [1-9]'; then
    echo "CAUGHT: $name"
    CAUGHT=$((CAUGHT + 1))
  else
    echo "NOT CAUGHT: $name  <-- the test cannot see this regression"
    FAILED=$((FAILED + 1))
    echo "$out" | tail -14
  fi
  restore
}

MUTDIR="$(mktemp -d /tmp/signerd-ladder-mut-XXXXXX)"

# M1: the dry path journals anyway (the journal grows; the identical body
#     would then be refused as `replay` on the real sign).
cat > "$MUTDIR/m1.js" <<'EOF'
const fs = require('node:fs');
const p = process.argv[2] + '/src/daemon.js';
let s = fs.readFileSync(p, 'utf8');
const anchor = `        const preview = previewMessageApproved({
          body: parsed.body, grant, ledger: this.ledger, keypair: this.keypair, now: new Date(),
        });`;
if (!s.includes(anchor)) { console.error('anchor M1 missing'); process.exit(1); }
s = s.replace(anchor, `        const preview = signMessageApproved({
          body: parsed.body, grant, ledger: this.ledger, keypair: this.keypair, now: new Date(),
        });`);
fs.writeFileSync(p, s);
EOF

# M2: the CLI writes --out even on a dry run.
cat > "$MUTDIR/m2.js" <<'EOF'
const fs = require('node:fs');
const p = process.argv[2] + '/bin/signerd.js';
let s = fs.readFileSync(p, 'utf8');
const n = s.split('if (response.ok && !response.dry && typeof args.out === \'string\')').length - 1;
if (n < 2) { console.error('anchor M2 missing: ' + n); process.exit(1); }
s = s.split('if (response.ok && !response.dry && typeof args.out === \'string\')')
     .join('if (response.ok && typeof args.out === \'string\')');
fs.writeFileSync(p, s);
EOF

# M3: the dry value typing is permissive (a string "true" degrades into a
#     real signature instead of failing closed).
cat > "$MUTDIR/m3.js" <<'EOF'
const fs = require('node:fs');
const p = process.argv[2] + '/src/daemon.js';
let s = fs.readFileSync(p, 'utf8');
const anchor = "if (dryField !== undefined && (typeof dryField.value !== 'boolean')) {";
if (!s.includes(anchor)) { console.error('anchor M3 missing'); process.exit(1); }
s = s.replace(anchor, 'if (false) {');
fs.writeFileSync(p, s);
EOF

# M4: the dry path answers "allowed" without running the policy at all.
cat > "$MUTDIR/m4.js" <<'EOF'
const fs = require('node:fs');
const p = process.argv[2] + '/src/signer-message.js';
let s = fs.readFileSync(p, 'utf8');
const anchor = '  const verdict = evaluateMessage(body, grant, now);\n  if (!verdict.allowed) return verdict;';
const idx = s.lastIndexOf(anchor);
if (idx === -1) { console.error('anchor M4 missing'); process.exit(1); }
// The LAST occurrence is the one inside previewMessageApproved.
s = s.slice(0, idx) + '  const verdict = { allowed: true, messageBytes: Buffer.from("{}"), messageSha256: "0".repeat(64) };'
   + s.slice(idx + anchor.length);
fs.writeFileSync(p, s);
EOF

# M5: the dry path refuses with a DIFFERENT reason than the real path
#     ("dry allowed" stays green, but "refusals are identical" becomes false).
cat > "$MUTDIR/m5.js" <<'EOF'
const fs = require('node:fs');
const p = process.argv[2] + '/src/daemon.js';
let s = fs.readFileSync(p, 'utf8');
const anchor = 'if (!preview.allowed) return { ok: false, error: preview.refused, detail: preview };';
if (!s.includes(anchor)) { console.error('anchor M5 missing'); process.exit(1); }
s = s.replace(anchor, 'if (!preview.allowed) return { ok: false, error: "request_invalid", detail: preview };');
fs.writeFileSync(p, s);
EOF

mutate "M1 the dry run journals the message" "$MUTDIR/m1.js"
mutate "M2 --out is written on a dry run" "$MUTDIR/m2.js"
mutate "M3 the dry value typing is permissive" "$MUTDIR/m3.js"
mutate "M4 dry skips the policy evaluation" "$MUTDIR/m4.js"
mutate "M5 the dry refusal reason differs from the real one" "$MUTDIR/m5.js"

rm -rf "$MUTDIR"
restore
AFTER="$(tree_hash)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "TREE NOT BYTE-IDENTICAL after the ladder ($BEFORE -> $AFTER)"
  FAILED=$((FAILED + 1))
fi

echo
echo "ladder: $CAUGHT mutations caught, $FAILED problems"
[ "$FAILED" -eq 0 ]
