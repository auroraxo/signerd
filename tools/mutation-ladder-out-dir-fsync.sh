#!/usr/bin/env bash
# The falsification of the --out directory-fsync fix.
#
# Each mutation breaks ONE part of the contract in src/out-preflight.js and
# the ladder test must go RED for it. A ladder that stays green under every
# mutation proves nothing — it only proves the test cannot see the change.
#
# The tree is restored byte-identically after each mutation (sha256 of the
# file is compared before and after).
set -uo pipefail
cd "$(dirname "$0")/.."

SRC="src/out-preflight.js"
TEST="test/out-dir-fsync.test.js"
BEFORE="$(sha256sum "$SRC" | cut -d' ' -f1)"
TMP="$(mktemp -d)"
cp "$SRC" "$TMP/orig.js"
# Restore the mutated file to the pristine backup. The backup itself is
# removed ONLY by the EXIT trap: an earlier version of this script deleted
# it inside every restore(), so from the second case on the restore failed
# silently and the mutations accumulated (the ladder then reported on a
# tree nobody had measured).
restore() {
  cp "$TMP/orig.js" "$SRC"
}
cleanup() {
  cp "$TMP/orig.js" "$SRC" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fails=0

run_case() {
  local name="$1"; shift
  local expect_red="$1"; shift
  local out
  out="$(node --test "$TEST" 2>&1)" || true
  local pass_count fail_count
  pass_count="$(printf '%s\n' "$out" | grep -E '^(✔|✖)' | grep '✔' | wc -l | tr -d ' ')"
  fail_count="$(printf '%s\n' "$out" | grep -E '^(✔|✖)' | grep '✖' | wc -l | tr -d ' ')"
  if [ "$expect_red" = "red" ]; then
    if [ "$fail_count" -ge 1 ]; then
      echo "CAUGHT  $name ($fail_count red)"
    else
      echo "MISSED  $name — the ladder stayed green under this mutation"
      fails=$((fails + 1))
    fi
  else
    if [ "$fail_count" -eq 0 ]; then
      echo "CLEAN   $name ($pass_count pass)"
    else
      echo "BROKE   $name — the control went red ($fail_count red)"
      fails=$((fails + 1))
    fi
  fi
  restore
}

echo "== control: unmutated tree must be green =="
run_case "control" green

echo "== M1: the directory fsync is removed entirely =="
python3 - <<'PY'
import re
p = "src/out-preflight.js"
s = open(p).read()
s = s.replace("""    try {
      const dfd = fs.openSync(dir, 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* platform-dependent; the delivery itself already succeeded */ }
""", "")
open(p, "w").write(s)
PY
run_case "M1 no dir fsync" red

echo "== M2: the directory fsync happens BEFORE the rename =="
python3 - <<'PY'
p = "src/out-preflight.js"
s = open(p).read()
block = """    try {
      const dfd = fs.openSync(dir, 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* platform-dependent; the delivery itself already succeeded */ }
"""
s = s.replace(block, "")
# insert it before the rename
s = s.replace("""    // rename is atomic within the directory: no reader ever sees a truncated
    // or half-written target, and the new node carries the temp's 0600.
    fs.renameSync(tmp, target);""",
"""    try {
      const dfd = fs.openSync(dir, 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* platform-dependent */ }
    // rename is atomic within the directory: no reader ever sees a truncated
    // or half-written target, and the new node carries the temp's 0600.
    fs.renameSync(tmp, target);""")
open(p, "w").write(s)
PY
run_case "M2 dir fsync before rename" red

echo "== M3: the temp file's own fsync is dropped =="
python3 - <<'PY'
p = "src/out-preflight.js"
s = open(p).read()
s = s.replace("    fs.fsyncSync(fd);\n    fs.closeSync(fd);", "    fs.closeSync(fd);")
open(p, "w").write(s)
PY
run_case "M3 no temp-file fsync" red

echo "== M4: a failing directory fsync fails the delivery =="
python3 - <<'PY'
p = "src/out-preflight.js"
s = open(p).read()
s = s.replace("""    } catch { /* platform-dependent; the delivery itself already succeeded */ }
    return { ok: true, path: target };""",
"""    } catch (err) {
      try { fs.unlinkSync(tmp); } catch { /* gone */ }
      return {
        ok: false,
        code: 'out_write_failed',
        path: target,
        errno: (err && err.code) || 'EIO',
        message: err && err.message ? err.message : String(err),
      };
    }
    return { ok: true, path: target };""")
open(p, "w").write(s)
PY
run_case "M4 dir fsync failure fails delivery" red

echo "== M5: the directory fsync is done on the WRONG directory (the temp's parent is the same, so use a fixed /tmp) =="
python3 - <<'PY'
p = "src/out-preflight.js"
s = open(p).read()
s = s.replace("      const dfd = fs.openSync(dir, 'r');", "      const dfd = fs.openSync('/tmp', 'r');")
open(p, "w").write(s)
PY
run_case "M5 wrong directory" red

AFTER="$(sha256sum "$SRC" | cut -d' ' -f1)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "TREE NOT RESTORED: $BEFORE != $AFTER"
  fails=$((fails + 1))
else
  echo "tree restored byte-identically ($AFTER)"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "LADDER COMPLETE: every mutation was caught, the control stayed green"
  exit 0
fi
echo "LADDER INCOMPLETE: $fails problem(s)"
exit 1
