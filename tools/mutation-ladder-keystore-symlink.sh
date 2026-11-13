#!/bin/bash
# MUTATION LADDER for the keystore symlink + atomic-write fix (2026-11-13).
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour of src/keystore.js. A rung counts as CAUGHT only when
# the gate (test/keystore-symlink.test.js) goes RED on the mutated tree AND
# the control (the UNTOUCHED fixed tree) stays green — otherwise a red result
# could be vacuous (broken fixture, not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard), and the file must be byte-identical to the fixed tree after
# restore.
#
# Ladder measured 2026-11-13 against the published v0.2.21 baseline: the gate
# is 5 GREEN / 11 RED there (research/keystore-symlink-2026-11-13.json).
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="test/keystore-symlink.test.js"
FILE="$REPO/src/keystore.js"
WORK="$(mktemp -d /tmp/mutation-keystoresym.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

FIXED_HASH="$(sha256sum "$FILE" | awk '{print $1}')"

# --- helpers ---------------------------------------------------------------

snapshot() { cp "$FILE" "$1.keystore.js"; }
restore()  { cp "$1.keystore.js" "$FILE"; }

runs_gate() { (cd "$REPO" && node --test "$GATE" >"$WORK/gate.log" 2>&1); }

# count non-overlapping matches of a perl regex over the WHOLE file (-0777)
count_matches() { # $1=perl-pattern
  perl -0777 -ne '$c = () = /'"$1"'/g; print $c + 0' "$FILE"
}

mutate() { # $1=perl-pattern, $2=perl-replacement
  perl -0777 -pi -e 's/'"$1"'/'"$2"'/s' "$FILE"
}

# --- rung driver -----------------------------------------------------------

CAUGHT=0
ESCAPED=0

run_rung() { # $1=mutation-id, $2=perl-pattern, $3=perl-replacement
  local id="$1" pattern="$2" expr="$3"
  local back="$WORK/back-$id"
  snapshot "$back"
  local n
  n="$(perl -0777 -ne '$c = () = /'"$pattern"'/gs; print $c + 0' "$FILE")"
  if [ "$n" -ne 1 ]; then
    echo "VACUUM  $id: pattern matched $n places (expected 1) — mutation NOT applied"
    restore "$back"
    ESCAPED=$((ESCAPED + 1))
    return
  fi
  mutate "$pattern" "$expr"
  if cmp -s "$back.keystore.js" "$FILE"; then
    echo "VACUUM  $id: mutation changed nothing"
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

if runs_gate; then
  echo "CONTROL green (gate passes on the untouched fixed tree)"
else
  echo "CONTROL RED — the gate does not pass on the fixed tree; ladder is invalid"
  exit 1
fi

# --- rungs -----------------------------------------------------------------

# M1: the probe FOLLOWS the link (lstat -> stat): a symlink at the keystore
# path looks like a regular file, so no caller refuses it — the pre-fix
# behaviour exactly (the loader then judges whatever the link lands on).
run_rung "M1-lstat-follow" \
  'st = fs\.lstatSync\(file\);' \
  'st = fs.statSync(file);'

# M2: the LOADER accepts a symlink — the judge of the state reports the mode
# of a file the operator never named.
run_rung "M2-loader-follows-link" \
  'function loadKeystore\(\{ file, passphrase \}\) \{.*?assertNotSymlink\(file\);' \
  'function loadKeystore({ file, passphrase }) {'

# M3: the PUBLIC-KEY READER accepts a symlink — build-tx and grant pinning
# learn the identity of whatever the link points at.
run_rung "M3-reader-follows-link" \
  'function readKeystorePublicKey\(\{ file \}\) \{.*?assertNotSymlink\(resolved\);' \
  'function readKeystorePublicKey({ file }) {'

# M4: the refusal is SILENT — the link is seen but never named: a fail-closed
# product must not swallow the verdict it exists to deliver (D1-D6 go green
# in the WORST way: nothing throws, the victim is clobbered).
run_rung "M4-silent-accept" \
  'if \(st\.isSymbolicLink\(\)\)' \
  'if (false && st.isSymbolicLink())'

# M5: the write goes IN PLACE (truncate the target before the content
# exists) — the pre-fix v0.2.21 shape; an interrupted replacement then tears
# the keystore that a working daemon signs with.
run_rung "M5-in-place-write" \
  'fs\.renameSync\(tmp, file\);' \
  'fs.writeFileSync(file, fs.readFileSync(tmp, "utf8")); fs.unlinkSync(tmp);'

# --- verdict ---------------------------------------------------------------
echo "----"
echo "caught=$CAUGHT escaped=$ESCAPED"
if [ "$ESCAPED" -ne 0 ]; then
  echo "LADDER FAILED: $ESCAPED mutation(s) escaped or were vacuous"
  exit 1
fi
if [ "$CAUGHT" -lt 5 ]; then
  echo "LADDER FAILED: only $CAUGHT caught (minimum 5)"
  exit 1
fi
echo "LADDER PASS: $CAUGHT/$CAUGHT caught, control green, tree byte-identical"
RESTORE_HASH="$(sha256sum "$FILE" | awk '{print $1}')"
if [ "$RESTORE_HASH" = "$FIXED_HASH" ]; then
  echo "TREE BYTE-IDENTICAL after restore"
else
  echo "TREE DIRTY after restore ($RESTORE_HASH vs $FIXED_HASH)"
  exit 1
fi
