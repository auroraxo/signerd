#!/bin/bash
# MUTATION LADDER for the ONE-WRITER-AT-A-TIME grant-file lock (2026-11-17).
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour (or a drift the fix's own contract forbids).
# A rung counts as CAUGHT only when the gate goes RED on the mutated tree
# AND the control (an UNTOUCHED run of the same gate) stays green right
# after restore - otherwise a red result could be vacuous (broken fixture,
# not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard inside every mutator: an anchor count != 1 ABORTS the rung
# instead of mutating silently), and the tree must be byte-identical to the
# fixed tree after restore. The fix lives in FOUR files (bin/signerd.js,
# src/grantadd.js, src/grant-file-lock.js, src/refusal-voice.js), so all
# four are snapshotted.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATES=(test/grant-file-lock.test.js test/grant-file-lock-unit.test.js test/grant-refusal-voice.test.js)
WORK="$(mktemp -d /tmp/mutation-grantlock.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="$REPO/bin/signerd.js"
GA="$REPO/src/grantadd.js"
GL="$REPO/src/grant-file-lock.js"
RV="$REPO/src/refusal-voice.js"
FIXED_HASH="$(sha256sum "$CLI" "$GA" "$GL" "$RV" | sha256sum | awk '{print $1}')"

snapshot() { # $1=tag
  cp "$CLI" "$WORK/$1.cli"
  cp "$GA" "$WORK/$1.grantadd"
  cp "$GL" "$WORK/$1.grantlock"
  cp "$RV" "$WORK/$1.refusal"
}
restore() { # $1=tag
  cp "$WORK/$1.cli" "$CLI"
  cp "$WORK/$1.grantadd" "$GA"
  cp "$WORK/$1.grantlock" "$GL"
  cp "$WORK/$1.refusal" "$RV"
}
run_gates() { # -> 0 when ALL gates pass
  (cd "$REPO" && node --test "${GATES[@]}" >"$WORK/gate.log" 2>&1)
}

CAUGHT=0
MISSED=0
run_gauge() { # $1=tag $2=mutation-description $3=mutator-fn
  local tag="$1" desc="$2" mutator="$3"
  snapshot "$tag"
  if ! "$mutator"; then
    echo "VACUUM $tag: the mutation did not match exactly one place - FIX THE LADDER"
    restore "$tag"
    MISSED=$((MISSED + 1))
    return
  fi
  if run_gates; then
    echo "ESCAPED $tag: gates stayed green after: $desc"
    MISSED=$((MISSED + 1))
  else
    echo "CAUGHT $tag: $desc"
    CAUGHT=$((CAUGHT + 1))
  fi
  restore "$tag"
  # control: the untouched fixed tree must be green right after restore
  if ! run_gates; then
    echo "CONTROL-RED $tag: the restored fixed tree must be green"
    echo "--- tail of gate.log ---"; tail -20 "$WORK/gate.log"
    exit 1
  fi
  local after
  after="$(sha256sum "$CLI" "$GA" "$GL" "$RV" | sha256sum | awk '{print $1}')"
  if [ "$after" != "$FIXED_HASH" ]; then
    echo "RESTORE-DRIFT $tag: tree is not byte-identical after restore"
    exit 1
  fi
}

# --- rung definitions (each with an exact-one vacuum guard) ------------------

m_no_lock() { # the pre-fix behaviour: no mutual exclusion at all
  python3 - "$GA" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "  return withGrantFileLock(resolved, fn);"
new = "  return fn(); // MUTANT: no exclusion at all"
assert s.count(old) == 1, "anchor count != 1"
s = s.replace(old, new)
open(p, 'w').write(s)
PY
}

m_append_unlocked() { # extendGrantFile races again
  python3 - "$GA" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
# unique to extendGrantFile: the comment names the create branch, and the
# returned object carries `appended: true`
old = """  // ONE WRITER AT A TIME: the judge-then-rename sequence below is
  // serialized against the other writers of this file (measured
  // 2026-11-17, see src/grant-file-lock.js). The create branch above takes
  // the lock inside writeGrantFile instead - the lock is never nested.
  return underGrantFileLock(resolved, () => {
"""
assert s.count(old) == 1, "opening anchor count != 1"
s = s.replace(old, "  // MUTANT: extendGrantFile runs without the lock.\n")
old2 = """    appended: true,
    grants: Object.keys(grants).sort(),
    sealed: sealPassphrase !== undefined,
  };
  });
}
"""
assert s.count(old2) == 1, "closing anchor count != 1"
s = s.replace(old2, """    appended: true,
    grants: Object.keys(grants).sort(),
    sealed: sealPassphrase !== undefined,
  };
}
""")
open(p, 'w').write(s)
PY
}

m_remove_unlocked() { # grant-remove races again
  python3 - "$GA" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
# unique to removeGrantFromFile: the revocation comment
old = """  // ONE WRITER AT A TIME: a revocation that races another writer must not
  // come back as a lost update - the daemon re-reads this file on EVERY
  // request, so a resurrected grant is a silent revocation undo (measured
  // 2026-11-17, see src/grant-file-lock.js). The judge-then-rename sequence
  // below runs under the file's lock; the refusal voices join the refusal map.
  return underGrantFileLock(resolved, () => {
"""
assert s.count(old) == 1, "opening anchor count != 1"
s = s.replace(old, "  // MUTANT: removeGrantFromFile runs without the lock.\n")
old2 = """    removed: name,
    grants: Object.keys(grants).sort(),
    sealed: sealPassphrase !== undefined,
  };
  });
}
"""
assert s.count(old2) == 1, "closing anchor count != 1"
s = s.replace(old2, """    removed: name,
    grants: Object.keys(grants).sort(),
    sealed: sealPassphrase !== undefined,
  };
}
""")
open(p, 'w').write(s)
PY
}

m_seal_unlocked() { # seal-grants races again
  python3 - "$CLI" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "const sealedSummary = withGrantFileLock(resolved, () => {"
new = "const sealedSummary = ((() => { // MUTANT: seal-grants without the lock"
assert s.count(old) == 1, "opening anchor count != 1"
s = s.replace(old, new)
old2 = """        out,
      };
    });"""
assert s.count(old2) == 1, "closing anchor count != 1"
s = s.replace(old2, """        out,
      };
    })());""")
open(p, 'w').write(s)
PY
}

m_no_release() { # a leaked lock bricks every later write
  python3 - "$GL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "          if (now && now.token === token) fs.unlinkSync(lockFile);"
new = "          if (false && now && now.token === token) fs.unlinkSync(lockFile);"
assert s.count(old) == 1, "anchor count != 1"
s = s.replace(old, new)
open(p, 'w').write(s)
PY
}

m_no_token_check() { # release removes a lock it no longer owns (takeover race)
  python3 - "$GL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "          if (now && now.token === token) fs.unlinkSync(lockFile);"
new = "          if (now) fs.unlinkSync(lockFile); // MUTANT: no token check"
assert s.count(old) == 1, "anchor count != 1"
s = s.replace(old, new)
open(p, 'w').write(s)
PY
}

m_no_dead_takeover() { # a dead writer's lock bricks the file forever
  python3 - "$GL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "    if (pidAlive(owner.pid)) {"
new = "    if (pidAlive(owner.pid) || true) { // MUTANT: never take over a dead owner"
assert s.count(old) == 1, "anchor count != 1"
s = s.replace(old, new)
open(p, 'w').write(s)
PY
}

m_no_wait() { # refuse instantly instead of serializing (8 writers -> refusals)
  python3 - "$GL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "  return Number.isInteger(n) && n >= 0 ? n : DEFAULT_WAIT_MS;"
new = "  return 0; // MUTANT: no wait budget"
assert s.count(old) == 1, "anchor count != 1"
s = s.replace(old, new)
open(p, 'w').write(s)
PY
}

m_lock_failed_voice() { # a read-only dir reports the NEW code, not grant_file_write_failed
  python3 - "$GL" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "  if (err && (err.code === 'EACCES' || err.code === 'EROFS')) {"
new = "  if (false && err && (err.code === 'EACCES' || err.code === 'EROFS')) {"
assert s.count(old) == 1, "anchor count != 1"
s = s.replace(old, new)
open(p, 'w').write(s)
PY
}

m_no_refusal_voice() { # the map loses the grant_file_locked repair
  python3 - "$RV" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
start = s.index("  grant_file_locked:")
end = s.index("\n", s.index("',", start)) + 1
assert s.count("  grant_file_locked:") == 1, "anchor count != 1"
s = s[:start] + s[end:]
open(p, 'w').write(s)
PY
}

# --- run ----------------------------------------------------------------------

echo "control run on the untouched fixed tree..."
if ! run_gates; then
  echo "CONTROL-RED: the fixed tree must be green before mutating"
  tail -30 "$WORK/gate.log"
  exit 1
fi

run_gauge m_no_lock "underGrantFileLock becomes a pass-through (no exclusion at all)" m_no_lock
run_gauge m_append_unlocked "extendGrantFile runs without the lock" m_append_unlocked
run_gauge m_remove_unlocked "removeGrantFromFile runs without the lock" m_remove_unlocked
run_gauge m_seal_unlocked "seal-grants runs without the lock" m_seal_unlocked
run_gauge m_no_release "the lock is never released after a successful write" m_no_release
run_gauge m_no_token_check "release ignores the token (removes a lock it lost)" m_no_token_check
run_gauge m_no_dead_takeover "a dead writer's lock is never taken over" m_no_dead_takeover
run_gauge m_no_wait "no wait budget: a live holder is refused instantly" m_no_wait
run_gauge m_lock_failed_voice "EACCES on the lock reports grant_file_lock_failed instead of grant_file_write_failed" m_lock_failed_voice
run_gauge m_no_refusal_voice "the refusal-voice map loses the grant_file_locked repair" m_no_refusal_voice

echo "----------------------------------------"
echo "CAUGHT=$CAUGHT MISSED=$MISSED"
[ "$MISSED" -eq 0 ] || exit 1
[ "$CAUGHT" -ge 8 ] || { echo "expected at least 8 CAUGHT"; exit 1; }
echo "tree byte-identical to the fixed tree after every restore"
exit 0
