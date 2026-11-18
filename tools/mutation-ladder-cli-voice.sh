#!/usr/bin/env bash
# MUTATION LADDER for the CLI voice — the refusals bin/signerd.js mints at
# its own ad-hoc sites (bin/signerd.js + src/keystore.js), with the repair
# map they consult (src/refusal-voice.js).
#
# Each mutation breaks ONE property of the fix. The ladder is CAUGHT when
# the mutated tree fails a gate; the tree must be byte-identical afterwards.
#
# GATES = the class gate (test/cli-voice.test.js) plus the two gates that
# share the repair map (test/refusal-voice-coverage.test.js and
# test/refusal-voice.test.js), so a mutation cannot hide behind one
# over-fitted gate. Several properties of this class are visible to NO
# source-scraping gate (the codes live in bin/, outside the coverage
# scrape's verdict modules) - M11 exists to prove exactly that gap is
# covered by the class gate.
#
# The mutations are applied by NODE reading snippet files from $WORK - not
# by sed: the strings under test contain backticks, ${...} and parentheses,
# and shell quoting turns such a mutation into a NO-OP that the ladder then
# counted (measured 2026-11-18 on the build-tx ladder: an M5 VACUUM was the
# LADDER's bug, found by its own apply-check). A mutation that does not
# apply aborts the ladder: it is a failure of the ladder, never a pass.
#
# Usage: bash tools/mutation-ladder-cli-voice.sh
set -u
cd "$(dirname "$0")/.." || exit 1
GATES="test/cli-voice.test.js test/refusal-voice-coverage.test.js test/refusal-voice.test.js"
WORK="$(mktemp -d)"
trap 'restore; rm -rf "$WORK"' EXIT

snapshot() {
  cp bin/signerd.js "$WORK/signerd.js"
  cp src/keystore.js "$WORK/keystore.js"
  cp src/refusal-voice.js "$WORK/refusal-voice.js"
}
restore() {
  [ -f "$WORK/signerd.js" ] && cp "$WORK/signerd.js" bin/signerd.js
  [ -f "$WORK/keystore.js" ] && cp "$WORK/keystore.js" src/keystore.js
  [ -f "$WORK/refusal-voice.js" ] && cp "$WORK/refusal-voice.js" src/refusal-voice.js
  return 0
}
snapshot

MUTATION_VACUUM=0

echo "mutation ladder for the cli voice"
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
    const fn = new Function("after", require("node:fs").readFileSync(s, "utf8"));
    const after = fn(before);
    if (typeof after !== "string" || after === before) {
      console.error("MUTATION DID NOT APPLY: " + s);
      process.exit(7);
    }
    fs.writeFileSync(p, after);
  ' "$file" "$snippet" || { echo "  BROKEN  a mutation did not apply - fix the ladder"; exit 8; }
}

# --- M1: the keygen keystore_exists refusal loses its repair (D2) --------
cat > "$WORK/m1.js" <<'SNIP'
const from = "          `keystore_exists: ${file} already holds a key\\n` +\n" +
             "          `  fix: add --overwrite   # replace ${file} with the NEW key (the old key is gone), or\\n` +\n" +
             "          `  fix: signerd keygen --keystore <other-file> --passphrase-file <file>   # generate elsewhere; this file keeps its key\\n`);";
const to = "          `keystore_exists: ${file} already holds a key\\n`);";
return after.replace(from, to);
SNIP
mutate bin/signerd.js "$WORK/m1.js"; caught "M1 keygen-keystore_exists-drops-the-fix"

# --- M2: the keygen keystore_exists refusal falls back to exit 1 (X) -----
cat > "$WORK/m2.js" <<'SNIP'
const from = "          `  fix: signerd keygen --keystore <other-file> --passphrase-file <file>   # generate elsewhere; this file keeps its key\\n`);\n        process.exit(2);";
const to = "          `  fix: signerd keygen --keystore <other-file> --passphrase-file <file>   # generate elsewhere; this file keeps its key\\n`);\n        process.exit(1);";
return after.replace(from, to);
SNIP
mutate bin/signerd.js "$WORK/m2.js"; caught "M2 keygen-keystore_exists-exits-1"

# --- M3: the keystore_write_failed refusal loses its repair (D3) ---------
cat > "$WORK/m3.js" <<'SNIP'
const from = "          `keystore_write_failed: ${detailOf(err)}\\n` +\n" +
             "          `  fix: point --keystore at a writable FILE path that is not a directory:\\n` +\n" +
             "          `       signerd keygen --keystore <file> --passphrase-file <file>\\n`);";
const to = "          `keystore_write_failed: ${detailOf(err)}\\n`);";
return after.replace(from, to);
SNIP
mutate bin/signerd.js "$WORK/m3.js"; caught "M3 keystore_write_failed-drops-the-fix"

# --- M4: the library's write reason reverts to a raw errno (D3) ----------
cat > "$WORK/m4.js" <<'SNIP'
return after.replace("throw fail('keystore_write_failed', `${file} is ${writeFailureReason(err)}`);",
                     "throw fail('keystore_write_failed', `${file}: ${err.code}`);");
SNIP
mutate src/keystore.js "$WORK/m4.js"; caught "M4 write-reason-reverts-to-errno"

# --- M5: the import secret_key_invalid face stops naming the formats (D4)
# The property is FACE-WIDE: neither the detail (what was tried) nor the
# fix (what to pass) may keep the three accepted formats. Measured on the
# first ladder run: stripping only the fix left "(tried id.json/JSON and
# base58)" in the detail, the gate stayed green, and the mutation was
# VACUOUS - the ladder's bug, not the gate's.
cat > "$WORK/m5.js" <<'SNIP'
let out = after.replace("  fix: point --from at one of the three accepted formats - a solana-keygen id.json (a JSON array of 64 numbers), a base58 secret key, or a raw 64-byte file:\\n",
                        "  fix: point --from at the key file\\n");
out = out.replace(" (tried id.json/JSON and base58)", "");
return out;
SNIP
mutate bin/signerd.js "$WORK/m5.js"; caught "M5 secret_key_invalid-drops-the-formats"

# --- M6: the body_invalid face never consults the map (D5) ---------------
cat > "$WORK/m6.js" <<'SNIP'
return after.replace("const mapped = refusalFix('body_invalid');",
                     "const mapped = null; // MUTATION: the map is never consulted");
SNIP
mutate bin/signerd.js "$WORK/m6.js"; caught "M6 body_invalid-skips-the-map"

# --- M7: the map's body_invalid repair becomes null (D5 + coverage C1b) --
cat > "$WORK/m7.js" <<'SNIP'
const needle = "  body_invalid: 'the `body` file must hold a JSON OBJECT";
const i = after.indexOf(needle);
if (i < 0) { process.exit(7); }
const j = after.indexOf('\n', i) + 1;
return after.slice(0, i) + "  body_invalid: null,\n" + after.slice(j);
SNIP
mutate src/refusal-voice.js "$WORK/m7.js"; caught "M7 map-body_invalid-repair-null"

# --- M8: the grant-add refusal loses its code again (D6) -----------------
cat > "$WORK/m8.js" <<'SNIP'
return after.replace("`grant_add_signer_required: grant-add needs a signer - give --signer <pubkey>, or let it be read from a keystore\\n` +",
                     "`grant-add needs --signer <pubkey> or --keystore <file>\\n` +");
SNIP
mutate bin/signerd.js "$WORK/m8.js"; caught "M8 grant_add_signer_required-loses-the-code"

# --- M9: the passphrase owner refusal loses its code (D7) ----------------
cat > "$WORK/m9.js" <<'SNIP'
return after.replace("`passphrase_file_owner: ${flag} must be owned by the operator (uid ${lstat.uid})\\n` +",
                     "`${flag} must be owned by the operator (uid ${lstat.uid})\\n` +");
SNIP
mutate bin/signerd.js "$WORK/m9.js"; caught "M9 passphrase_file_owner-loses-the-code"

# --- M10: the passphrase owner refusal loses chown (D7) ------------------
cat > "$WORK/m10.js" <<'SNIP'
return after.replace("`  fix: chown ${process.getuid()}:${process.getgid()} ${file}   # the passphrase unlocks the keystore; only you may read it\\n`);",
                     "`  fix: repair the ownership\\n`);");
SNIP
mutate bin/signerd.js "$WORK/m10.js"; caught "M10 passphrase_file_owner-drops-chown"

# --- M11: the map loses grant_add_signer_required entirely (D6) ----------
# The code lives in bin/, OUTSIDE the coverage scrape's verdict modules -
# only the class gate sees this mutation.
cat > "$WORK/m11.js" <<'SNIP'
const needle = "  grant_add_signer_required:";
const i = after.indexOf(needle);
if (i < 0) { process.exit(7); }
const j = after.indexOf('\n', i) + 1;
return after.slice(0, i) + after.slice(j);
SNIP
mutate src/refusal-voice.js "$WORK/m11.js"; caught "M11 map-loses-grant_add_signer_required"

diff <(cat "$WORK/signerd.js") bin/signerd.js >/dev/null \
  && diff <(cat "$WORK/keystore.js") src/keystore.js >/dev/null \
  && diff <(cat "$WORK/refusal-voice.js") src/refusal-voice.js >/dev/null \
  && echo "  byte-identical: all three files match the pre-ladder tree" \
  || { echo "  TREE NOT RESTORED"; exit 1; }

if [ "$MUTATION_VACUUM" = "1" ]; then
  echo "LADDER FAILED: at least one mutation was VACUOUS"
  exit 1
fi
echo "ladder complete: 11/11 CAUGHT"
