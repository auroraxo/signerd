#!/bin/bash
# MUTATION LADDER for the seal-grants judge fix (2026-11-13).
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour. A rung counts as CAUGHT only when the gate
# (test/seal-grants-judge.test.js) goes RED on the mutated tree AND the
# control (an UNTOUCHED copy of the fixed tree) stays green — otherwise a
# red result could be vacuous (broken fixture, not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard), and the tree must be byte-identical to the fixed tree
# after restore.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="test/seal-grants-judge.test.js"
WORK="$(mktemp -d /tmp/mutation-sealjudge.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

FIXED_HASH="$(sha256sum "$REPO/bin/signerd.js" | awk '{print $1}')"

# --- helpers ---------------------------------------------------------------

snapshot() { # $1=dir: byte-copy of bin/signerd.js for restore
  cp "$REPO/bin/signerd.js" "$1.signerd.js"
}

restore() { # $1=dir
  cp "$1.signerd.js" "$REPO/bin/signerd.js"
}

runs_gate() { # -> exit 0 when the gate passes, 1 when it fails
  (cd "$REPO" && node --test "$GATE" >/tmp/mutation-ladder-gate.log 2>&1)
}

# vacuums: count how many places the pattern matches (must be exactly 1)
count_matches() { # $1=regex, $2=file
  grep -c -E "$1" "$2"
}

# --- rung driver -----------------------------------------------------------

CAUGHT=0
ESCAPED=0

run_rung() { # $1=mutation-id, $2=pattern, $3=sed-expression
  local id="$1" pattern="$2" expr="$3"
  local back="$WORK/back-$id"
  snapshot "$back"
  local n
  n="$(count_matches "$pattern" "$REPO/bin/signerd.js")"
  if [ "$n" -ne 1 ]; then
    echo "VACUUM  $id: pattern matched $n places (expected 1) — mutation NOT applied"
    restore "$back"
    ESCAPED=$((ESCAPED + 1))
    return
  fi
  sed -i "$expr" "$REPO/bin/signerd.js"
  if cmp -s "$back.signerd.js" "$REPO/bin/signerd.js"; then
    echo "VACUUM  $id: sed changed nothing"
    restore "$back"
    ESCAPED=$((ESCAPED + 1))
    return
  fi
  if runs_gate; then
    echo "ESCAPED $id: gate still GREEN after the mutation"
    ESCAPED=$((ESCAPED + 1))
  else
    echo "CAUGHT  $id: gate RED on the mutated tree"
    CAUGHT=$((CAUGHT + 1))
  fi
  restore "$back"
}

# --- control ---------------------------------------------------------------
# The untouched fixed tree must stay GREEN, or every red above is vacuous.

if runs_gate; then
  echo "CONTROL green (gate passes on the untouched fixed tree)"
else
  echo "CONTROL RED — the gate does not pass on the fixed tree; ladder is invalid"
  exit 1
fi

# --- rungs -----------------------------------------------------------------
# M1: no judge at all — seal whatever the file holds (the pre-fix behaviour).
run_rung "M1-no-judge" \
  'loaded = loadGrantFile\(file\);' \
  's|loaded = loadGrantFile(file);|const rawDoc = JSON.parse(require("node:fs").readFileSync(file, "utf8")); loaded = { names: Object.keys(rawDoc.grants).sort(), grants: rawDoc.grants };|'

# M2: the named symlink gate removed — the loader still refuses (ELOOP), but
# with the wrong voice: grant_file_invalid, not grant_file_symlink.
run_rung "M2-symlink-gate" \
  'if \(link !== null && link.isSymbolicLink\(\)\) \{' \
  's|if (link !== null \&\& link.isSymbolicLink()) {|if (false) {|'

# M3: the link PROBE follows the link (lstat -> stat): a symlink looks like a
# regular file to the gate, so the named refusal never fires.
run_rung "M3-lstat-follow" \
  'const link = lstatOrNull\(resolved\);' \
  's|const link = lstatOrNull(resolved);|const link = fs.existsSync(resolved) ? fs.statSync(resolved) : null;|'

# M4: the loader is consulted but its verdict is swallowed (a refusal that
# seals anyway — the dangerous direction for a fail-closed product).
run_rung "M4-swallow-verdict" \
  'loaded = loadGrantFile\(file\);' \
  's|loaded = loadGrantFile(file);|try { loaded = loadGrantFile(file); } catch (_) { const rawDoc = JSON.parse(require("node:fs").readFileSync(file, "utf8")); loaded = { names: Object.keys(rawDoc.grants).sort(), grants: rawDoc.grants }; }|'

# --- verdict ---------------------------------------------------------------
echo "----"
echo "caught=$CAUGHT escaped=$ESCAPED"
if [ "$ESCAPED" -ne 0 ]; then
  echo "LADDER FAILED: $ESCAPED mutation(s) escaped or were vacuous"
  exit 1
fi
if [ "$CAUGHT" -lt 4 ]; then
  echo "LADDER FAILED: only $CAUGHT caught (minimum 4)"
  exit 1
fi
echo "LADDER PASS: $CAUGHT/$CAUGHT caught, control green, tree byte-identical"
RESTORE_HASH="$(sha256sum "$REPO/bin/signerd.js" | awk '{print $1}')"
if [ "$RESTORE_HASH" = "$FIXED_HASH" ]; then
  echo "TREE BYTE-IDENTICAL after restore"
else
  echo "TREE DIRTY after restore ($RESTORE_HASH vs $FIXED_HASH)"
  exit 1
fi
