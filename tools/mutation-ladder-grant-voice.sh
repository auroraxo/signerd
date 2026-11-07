#!/usr/bin/env bash
# The mutation ladder for THE GRANT-FILE REFUSAL VOICE (2026-11-08).
#
# Breaks each property of the fix in a plausible way. The pinned test file
# (test/grant-refusal-voice.test.js) must catch every mutation, and the
# tree must be restored byte-identically afterwards.
#
# Mutations:
#   M1 re-double grant_file_mode (detailOf -> err.message on the append printer)
#   M2 re-double grant_file_unreadable (detailOf -> err.message on remove)
#   M3 drop the read-only write handler from the create path (bare errno again)
#   M4 drop the create-path try/catch in writeGrantFile (raw write again)
#   M5 drop the fix: line from the read-only refusal
#
# Usage: bash tools/mutation-ladder-grant-voice.sh
set -u
cd "$(dirname "$0")/.."
TEST="test/grant-refusal-voice.test.js"
FAIL=0
SNAP="$(mktemp -d)"
trap 'rm -rf "$SNAP"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

run_tests() {
  timeout 300 node --test "$TEST" 2>&1 | grep -E "^. (pass|fail)" | tr '\n' ' '
}

fails_of() { printf '%s' "$1" | sed -n 's/.*fail \([0-9]*\).*/\1/p'; }

check() {
  local label="$1" expect="$2" file="$3" before="$4"
  local after out fails
  out=$(run_tests)
  fails=$(fails_of "$out")
  printf '  %-52s %s\n' "$label" "$out"
  if [ "$expect" = "expect-red" ] && [ "${fails:-0}" = "0" ]; then
    echo "  !! MUTATION SURVIVED: $label"; FAIL=1
  fi
  if [ "$expect" = "expect-green" ] && [ "${fails:-0}" != "0" ]; then
    echo "  !! control is red: $label"; FAIL=1
  fi
  cp "$SNAP/$(basename "$file")" "$file"
  after=$(sha "$file")
  if [ "$after" != "$before" ]; then
    echo "  !! NOT restored byte-identically: $file"; FAIL=1
  fi
}

mutate() {
  local file="$1"
  cp "$file" "$SNAP/$(basename "$file")"
  python3 - || {
    echo "  !! mutation script failed"; FAIL=1
    cp "$SNAP/$(basename "$file")" "$file"
    return 1
  }
}

echo "Control run (unmodified tree):"
cp bin/signerd.js "$SNAP/signerd.js"; cp src/grantadd.js "$SNAP/grantadd.js"
check "control (unmodified)" "expect-green" "bin/signerd.js" "$(sha bin/signerd.js)"

echo "Mutation ladder:"

# M1: re-double grant_file_mode (the --append printer goes back to err.message)
BEFORE=$(sha bin/signerd.js)
mutate bin/signerd.js <<'PY'
c = open('bin/signerd.js').read()
old = """            `${err.code}: ${detailOf(err)}\\n` +
            `  fix: chmod 600 ${grants}   # a grant file another user can write must not be extended\\n`);"""
new = """            `${err.code}: ${err.message}\\n` +
            `  fix: chmod 600 ${grants}   # a grant file another user can write must not be extended\\n`);"""
assert old in c, 'anchor M1 missing'
open('bin/signerd.js', 'w').write(c.replace(old, new))
PY
check "M1 re-double grant_file_mode" "expect-red" "bin/signerd.js" "$BEFORE"

# M2: re-double grant_file_unreadable (the remove printer)
BEFORE=$(sha bin/signerd.js)
mutate bin/signerd.js <<'PY'
c = open('bin/signerd.js').read()
old = """          `${err.code}: ${detailOf(err)}\\n` +
          `  fix: nothing to remove"""
new = """          `${err.code}: ${err.message}\\n` +
          `  fix: nothing to remove"""
assert old in c, 'anchor M2 missing'
open('bin/signerd.js', 'w').write(c.replace(old, new))
PY
check "M2 re-double grant_file_unreadable" "expect-red" "bin/signerd.js" "$BEFORE"

# M3: drop the read-only write handler from the create path
BEFORE=$(sha bin/signerd.js)
mutate bin/signerd.js <<'PY'
c = open('bin/signerd.js').read()
old = """      if (err && err.code === 'grant_file_write_failed') {
        process.stderr.write(
          `${err.code}: ${err.detail || 'the grant file could not be written'}\\n` +
          `  fix: make the directory writable (chmod 700 $(dirname ${grants})) and retry\\n` +
          `  fix: or point --grants at a file in a directory you own\\n`);
        process.exit(1);
      }"""
assert old in c, 'anchor M3 missing'
open('bin/signerd.js', 'w').write(c.replace(old, ''))
PY
check "M3 drop read-only write handler" "expect-red" "bin/signerd.js" "$BEFORE"

# M4: drop the create-path try/catch in writeGrantFile (raw write again)
BEFORE=$(sha src/grantadd.js)
mutate src/grantadd.js <<'PY'
c = open('src/grantadd.js').read()
old = """  try {
    fs.writeFileSync(resolved, JSON.stringify(doc, null, 2) + '\\n', { mode: 0o600 });
    fs.chmodSync(resolved, 0o600); // writeFileSync's mode applies on create only
  } catch (err) {
    try { fs.unlinkSync(resolved); } catch { /* never landed */ }
    throw writeFailed(err, resolved);
  }"""
new = """  fs.writeFileSync(resolved, JSON.stringify(doc, null, 2) + '\\n', { mode: 0o600 });
  fs.chmodSync(resolved, 0o600);"""
assert old in c, 'anchor M4 missing'
open('src/grantadd.js', 'w').write(c.replace(old, new))
PY
check "M4 raw write again in create path" "expect-red" "src/grantadd.js" "$BEFORE"

# M5: drop the fix: line from the read-only refusal (code only)
BEFORE=$(sha bin/signerd.js)
mutate bin/signerd.js <<'PY'
c = open('bin/signerd.js').read()
old = """          `  fix: make the directory writable (chmod 700 $(dirname ${grants})) and retry\\n` +
          `  fix: or point --grants at a file in a directory you own\\n`);"""
new = """          `  (no repair named)`);"""
assert old in c, 'anchor M5 missing'
open('bin/signerd.js', 'w').write(c.replace(old, new))
PY
check "M5 drop the repair line" "expect-red" "bin/signerd.js" "$BEFORE"

echo
if [ "$FAIL" = "0" ]; then
  echo "All 5 mutations caught. Tree restored byte-identically."
  exit 0
else
  echo "Mutation ladder FAILED."
  exit 1
fi
