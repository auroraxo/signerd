#!/usr/bin/env bash
# Mutation ladder for the grant-file write durability fix (src/grantadd.js).
#
# Each mutation re-introduces ONE of the defects the fix closes (or breaks a
# guard), runs the ladder test file, and requires the ladder to CATCH it
# (test failures > 0). CONTROL must stay green. After every mutation the tree
# is restored byte-identically (verified by sha256 of the whole source file).
#
# Usage: tools/mutation-ladder-grant-dir-fsync.sh
set -uo pipefail

cd "$(dirname "$0")/.."
SRC="src/grantadd.js"
TESTFILE="test/grant-write-dir-fsync.test.js"
LADDER="test/grant-write-dir-fsync.test.js"

CONTROL_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
FAILED=0

restore() {
  [ -f "$CONTROL_SHA.backup" ] || return 0
  cp "$CONTROL_SHA.backup" "$SRC"
  local now
  now=$(sha256sum "$SRC" | cut -d' ' -f1)
  if [ "$now" != "$CONTROL_SHA" ]; then
    echo "VACUUM FAIL: $SRC not restored (expected $CONTROL_SHA, got $now)"
    exit 2
  fi
}
trap restore EXIT

cp "$SRC" "$CONTROL_SHA.backup"

run_ladder() {
  local out fails
  out=$(node --test "$LADDER" 2>&1)
  # node --test prints either TAP ("# fail N") or spec ("ℹ fail N") summaries.
  fails=$(printf '%s\n' "$out" | grep -E "^(ℹ|#) fail [0-9]+" | tail -1 | grep -oE '[0-9]+$')
  printf '%s\n' "${fails:-}"
}

expect_caught() {
  local name="$1" mutation="$2"
  cp "$CONTROL_SHA.backup" "$SRC"
  apply_mutation "$mutation" || { echo "ESCAPED: $name (mutation did not apply)"; FAILED=1; return; }
  local fails
  fails=$(run_ladder)
  if [ "${fails:-0}" -gt 0 ] 2>/dev/null; then
    echo "CAUGHT: $name (fail=$fails)"
  else
    echo "ESCAPED: $name (ladder stayed green — mutation not caught)"
    FAILED=1
  fi
}

apply_mutation() {
  case "$1" in
    no-dir-fsync)
      python3 - "$SRC" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
start = s.index("  // Durability of the NAME, after the rename")
end = s.index("}\n", s.index("catch { /* platform-dependent; the house convention is best-effort here */ }"))
s = s[:start] + s[end:]
open(p, "w").write(s)
PY
      ;;
    dir-fsync-before-rename)
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
block = """  // Durability of the NAME, after the rename — best effort (see header).
  try {
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch { /* platform-dependent; the house convention is best-effort here */ }
"""
assert block in s, "block not found"
s = s.replace(block, "")
anchor = "    fs.renameSync(tmp, target);"
assert anchor in s
s = s.replace(anchor, block + anchor)
open(p, "w").write(s)
PY
      ;;
    no-temp-fsync)
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "    fs.fsyncSync(fd);\n    fs.fchmodSync(fd, 0o600);"
assert a in s
s = s.replace(a, "    fs.fchmodSync(fd, 0o600);", 1)
open(p, "w").write(s)
PY
      ;;
    dir-fsync-failure-aborts)
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = """  try {
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch { /* platform-dependent; the house convention is best-effort here */ }"""
assert a in s
s = s.replace(a, """  {
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  }""")
open(p, "w").write(s)
PY
      ;;
    wrong-dir-fsync)
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "    const dfd = fs.openSync(dir, 'r');"
assert a in s
s = s.replace(a, "    const dfd = fs.openSync(path.dirname(path.dirname(dir)) || '/', 'r');", 1)
open(p, "w").write(s)
PY
      ;;
    create-path-truncate-write)
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = """  const doc = { version: 1, grants: { [name]: grant } };"""
i = s.index(a)
j = s.index("  writeAtomic(resolved, doc);", i)
k = s.index("\n", j) + 1
s = s[:j] + """  fs.writeFileSync(resolved, JSON.stringify(doc, null, 2) + '\\n', { mode: 0o600 });
  fs.chmodSync(resolved, 0o600);
""" + s[k:]
open(p, "w").write(s)
PY
      ;;
    *) echo "unknown mutation: $1"; return 1 ;;
  esac
}

echo "== CONTROL =="
fails=$(run_ladder)
if [ "${fails:-0}" -gt 0 ] 2>/dev/null; then
  echo "VACUUM FAIL: CONTROL ladder red (fail=$fails)"; exit 2
fi
echo "CONTROL green"

expect_caught "M1 remove the parent-directory fsync" no-dir-fsync
expect_caught "M2 directory fsync BEFORE the rename" dir-fsync-before-rename
expect_caught "M3 no temp-file fsync" no-temp-fsync
expect_caught "M4 directory fsync failure aborts the write" dir-fsync-failure-aborts
expect_caught "M5 fsync the wrong directory" wrong-dir-fsync
expect_caught "M6 create path back to a truncate write" create-path-truncate-write

# final vacuum check
cp "$CONTROL_SHA.backup" "$SRC"
rm -f "$CONTROL_SHA.backup"
final=$(sha256sum "$SRC" | cut -d' ' -f1)
[ "$final" = "$CONTROL_SHA" ] || { echo "VACUUM FAIL at exit"; exit 2; }

if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: ESCAPES PRESENT"
  exit 1
fi
echo "RESULT: 6/6 caught, control green, tree byte-identical"
