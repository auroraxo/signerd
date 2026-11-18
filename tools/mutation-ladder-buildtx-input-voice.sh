#!/usr/bin/env bash
# MUTATION LADDER for the build-tx value-input voice
# (src/buildtx.js + bin/signerd.js).
#
# Each mutation breaks ONE property of the fix. The ladder is CAUGHT when the
# mutated tree fails a gate; the tree must be byte-identical afterwards.
#
# GATES = the new class gate (test/buildtx-input-voice.test.js) plus the
# measurement pin (test/buildtx-input-voice-measurement.test.js) plus the
# neighbouring client-surface gate (test/client-verification.test.js), so a
# mutation cannot hide behind one over-fitted gate.
#
# The mutations are applied by NODE reading snippet files from $WORK - not
# by sed: the strings under test contain backticks, ${...} and parentheses,
# and shell quoting turned one mutation into a NO-OP that the ladder then
# counted (measured 2026-11-18: M5 VACUUM was the LADDER's bug, found by
# its own apply-check). A mutation that does not apply aborts the ladder:
# it is a failure of the ladder, never a pass.
#
# Usage: bash tools/mutation-ladder-buildtx-input-voice.sh
set -u
cd "$(dirname "$0")/.." || exit 1
GATES="test/buildtx-input-voice.test.js test/buildtx-input-voice-measurement.test.js test/client-verification.test.js"
WORK="$(mktemp -d)"
trap 'restore; rm -rf "$WORK"' EXIT

snapshot() {
  cp src/buildtx.js "$WORK/buildtx.js"
  cp bin/signerd.js "$WORK/signerd.js"
}
restore() {
  [ -f "$WORK/buildtx.js" ] && cp "$WORK/buildtx.js" src/buildtx.js
  [ -f "$WORK/signerd.js" ] && cp "$WORK/signerd.js" bin/signerd.js
  return 0
}
snapshot

MUTATION_VACUUM=0

echo "mutation ladder for the build-tx input voice"
echo "baseline:"
node --test $GATES 2>&1 | grep -E "^ℹ (pass|fail)" | sed 's/^/  /'

caught() {  # $1 = label
  local out
  out=$(node --test $GATES 2>&1)
  if echo "$out" | grep -qE "^ℹ fail [1-9]"; then
    echo "  CAUGHT  $1"
  else
    echo "  VACUUM  $1  <-- a gate passed on a broken tree"
    MUTATION_VACUUM=1
  fi
  restore
}

# mutate <target-file> <snippet-file>
# The snippet is a JS module body: `after` is the file text, assign the
# mutated text to it. Applying an identity leaves the file unchanged, which
# is reported as BROKEN and aborts the ladder.
mutate() {
  local file="$1" snippet="$2"
  node -e '
    const fs = require("node:fs");
    const p = process.argv[1];
    const s = process.argv[2];
    const before = fs.readFileSync(p, "utf8");
    const run = require("node:module")._compile ? null : null;
    const fn = new Function("after", require("node:fs").readFileSync(s, "utf8"));
    const after = fn(before);
    if (typeof after !== "string" || after === before) {
      console.error("MUTATION DID NOT APPLY: " + s);
      process.exit(7);
    }
    fs.writeFileSync(p, after);
  ' "$file" "$snippet" || { echo "  BROKEN  a mutation did not apply - fix the ladder"; exit 8; }
}

# --- M1: skip the decode check (bad base58 reaches web3.js again) --------
cat > "$WORK/m1.js" <<'SNIP'
return after.replace('raw = bs58.decode(value);', 'raw = Buffer.alloc(32);');
SNIP
mutate src/buildtx.js "$WORK/m1.js"; caught "M1 skip-base58-decode"

# --- M2: skip the length check (31-byte values reach the builder) --------
cat > "$WORK/m2.js" <<'SNIP'
return after.replace('if (raw.length !== 32) {', 'if (false) {');
SNIP
mutate src/buildtx.js "$WORK/m2.js"; caught "M2 skip-length-check"

# --- M3: the refusal loses the FLAG (generic message) --------------------
cat > "$WORK/m3.js" <<'SNIP'
return after.replace('build-tx: ${flag} must be base58 (got a character base58 does not know)',
                     'build-tx: a value is not base58');
SNIP
mutate src/buildtx.js "$WORK/m3.js"; caught "M3 message-drops-the-flag"

# --- M4: the fix loses the FLAG (repair names no flag, no command) -------
cat > "$WORK/m4.js" <<'SNIP'
return after.replace('pass ${flag} as a base58 value - ${flag} <pubkey-or-blockhash>   ',
                     'pass a base58 value instead');
SNIP
mutate src/buildtx.js "$WORK/m4.js"; caught "M4 fix-drops-the-flag"

# --- M5: the fix becomes the ECHO of the message again -------------------
# The original defect: a `fix:` line that restates the error in the same
# words. The carried fix becomes the MESSAGE TEXT ITSELF - the exact
# pre-fix shape (fix === detail), not a phrase that merely repeats it.
cat > "$WORK/m5.js" <<'SNIP'
const from = "      `pass ${flag} as a base58 value - ${flag} <pubkey-or-blockhash>   ` +\n" +
             "      '# base58 knows no 0, O, I or l; copy the value instead of retyping it');";
const to = "      `build-tx: ${flag} must be base58 (got a character base58 does not know)`);";
return after.replace(from, to);
SNIP
mutate src/buildtx.js "$WORK/m5.js"; caught "M5 fix-becomes-the-echo"

# --- M6: the CLI drops the carried fix (err.fix never printed) -----------
cat > "$WORK/m6.js" <<'SNIP'
return after.replace('`  fix: ${err.fix}`', '`  fix: ${detailOf(err)}`');
SNIP
mutate bin/signerd.js "$WORK/m6.js"; caught "M6 cli-drops-the-carried-fix"

# --- M7: the residual wire_build_failed loses its repair -----------------
# (the echo returns: the fix line restates the failure instead of the
# rebuild command)
cat > "$WORK/m7.js" <<'SNIP'
let out = after.replace('rebuild the file from the values you know are right: ', 'build-tx: ');
out = out.replace("signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>');",
                  'build-tx: ${err && err.message ? err.message : String(err)}');
return out;
SNIP
mutate src/buildtx.js "$WORK/m7.js"; caught "M7 wire-build-fix-becomes-echo"

echo "byte-identical restore:"
IDENTICAL=1
for f in src/buildtx.js bin/signerd.js; do
  if ! cmp -s "$WORK/$(basename "$f")" "$f"; then
    echo "  BROKEN  $f differs from the pre-ladder snapshot"
    IDENTICAL=0
    MUTATION_VACUUM=1
  fi
done
if [ "$IDENTICAL" -eq 1 ]; then
  echo "  OK      the tree is byte-identical after the ladder"
fi

if [ "$MUTATION_VACUUM" -eq 0 ]; then
  echo "RESULT: all mutations CAUGHT, tree byte-identical"
  exit 0
fi
echo "RESULT: at least one mutation escaped - fix the gates first"
exit 1
