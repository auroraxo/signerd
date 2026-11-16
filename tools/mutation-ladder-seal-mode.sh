#!/bin/bash
# MUTATION LADDER for the seal-mode fix (2026-11-16): a keyless read of a
# SEALED grant file is refused (grant_file_sealed) instead of degrading.
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour (or a new drift the fix's own contract forbids).
# A rung counts as CAUGHT only when the gate (test/seal-mode.test.js) goes
# RED on the mutated tree AND the control (an UNTOUCHED copy of the fixed
# tree) stays green - otherwise a red result could be vacuous (broken
# fixture, not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard), and the tree must be byte-identical to the fixed tree
# after restore. The fix lives in src/grantfile.js (the refusal) and
# bin/signerd.js (the one escape hatch for re-sealing).
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="test/seal-mode.test.js"
WORK="$(mktemp -d /tmp/mutation-sealmode.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="$REPO/bin/signerd.js"
GF="$REPO/src/grantfile.js"
FIXED_HASH="$(sha256sum "$CLI" "$GF" | sha256sum | awk '{print $1}')"

# --- helpers ---------------------------------------------------------------

snapshot() { # $1=dir: byte-copy of both fixed files for restore
  cp "$CLI" "$1.signerd.js"
  cp "$GF" "$1.grantfile.js"
}

restore() { # $1=dir
  cp "$1.signerd.js" "$CLI"
  cp "$1.grantfile.js" "$GF"
}

runs_gate() { # -> exit 0 when the gate passes, 1 when it fails
  (cd "$REPO" && node --test "$GATE" >/tmp/mutation-ladder-sealmode-gate.log 2>&1)
}

count_matches() { # $1=regex (ERE, or PCRE with \n = a real newline), $2=file
  if [[ "$1" == *'\n'* ]]; then
    # Slurped Perl match: grep would match line by line and never span
    # lines, so the one multiline mutation needs a real text search.
    MATCHES="$1" perl -0ne 'my $c = () = /$ENV{MATCHES}/g; print "$c\n"' "$2"
  else
    grep -c -E "$1" "$2"
  fi
}

# --- rung driver -----------------------------------------------------------

CAUGHT=0
ESCAPED=0

run_rung() { # $1=mutation-id, $2=pattern (ERE, must match exactly once),
             # $3=file, $4=perl replacement expression (multiline safe)
  local id="$1" pattern="$2" file="$3" expr="$4"
  local back="$WORK/back-$id"
  snapshot "$back"
  local n
  n="$(count_matches "$pattern" "$file")"
  if [ "$n" -ne 1 ]; then
    echo "VACUUM  $id: pattern matched $n places (expected 1) - mutation NOT applied"
    restore "$back"
    ESCAPED=$((ESCAPED + 1))
    return
  fi
  perl -0pi -e "$expr" "$file"
  if cmp -s "$back.signerd.js" "$CLI" && cmp -s "$back.grantfile.js" "$GF"; then
    echo "VACUUM  $id: the mutation changed nothing"
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
  echo "CONTROL RED - the gate does not pass on the fixed tree; ladder is invalid"
  exit 1
fi

# --- rungs -----------------------------------------------------------------

# M1: the pre-fix behaviour - the keyless branch is skipped entirely, so a
# sealed file loads unsealed (F1/F2/F3 all come back).
run_rung "M1-keyless-branch-disabled" \
  '\} else if \(!allowSealedWithoutKey &&' \
  "$GF" \
  's/\} else if \(!allowSealedWithoutKey &&/} else if (false \&\&/'

# M2: the escape hatch stops being an escape hatch - seal-grants can no
# longer judge a sealed payload, so the documented re-seal repair breaks
# (the G2 guard must catch this; the refusal itself cannot).
run_rung "M2-escape-hatch-dead" \
  'const allowSealedWithoutKey = options && options.allowSealedWithoutKey === true;' \
  "$GF" \
  's/const allowSealedWithoutKey = options && options\.allowSealedWithoutKey === true;/const allowSealedWithoutKey = false;/'

# M3: the shape check is dropped from the keyless branch, so a broken seal
# block reports the missing passphrase instead of its own real reason (S4).
run_rung "M3-shape-check-dropped" \
  'const parsed = parseSeal\(doc\);\n    if \(!parsed\.ok\) throw fail\(parsed\.reason\);\n    throw fail\('"'"'grant_file_sealed'"'"'' \
  "$GF" \
  's/    const parsed = parseSeal\(doc\);\n    if \(!parsed\.ok\) throw fail\(parsed\.reason\);\n    throw fail\('"'"'grant_file_sealed'"'"'/    throw fail('"'"'grant_file_sealed'"'"'/'

# M4: the branch fires for every document, sealed or not - the legacy
# opt-in path dies and an UNSEALED file is refused keylessly (G1).
run_rung "M4-unsealed-refused-too" \
  "Object\.getOwnPropertyDescriptor\(doc, 'seal'\) !== undefined" \
  "$GF" \
  "s/Object\.getOwnPropertyDescriptor\(doc, 'seal'\) !== undefined/true/"

# M5: the refusal loses its name - every caller that matches on
# grant_file_sealed (status, the daemon's stderr, the write paths) breaks
# (S1/S2/S3).
run_rung "M5-refusal-renamed" \
  "throw fail\('grant_file_sealed'," \
  "$GF" \
  "s/throw fail\('grant_file_sealed',/throw fail('grant_file_locked',/"

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
RESTORE_HASH="$(sha256sum "$CLI" "$GF" | sha256sum | awk '{print $1}')"
if [ "$RESTORE_HASH" = "$FIXED_HASH" ]; then
  echo "TREE BYTE-IDENTICAL after restore"
else
  echo "TREE DIRTY after restore ($RESTORE_HASH vs $FIXED_HASH)"
  exit 1
fi
