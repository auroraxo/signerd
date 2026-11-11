#!/usr/bin/env bash
# Mutation ladder for the request-frame surface (test/request-frame.test.js).
# Each mutation removes ONE face of the fix; the ladder must catch it (>= 1
# failing case in the ladder file), and the CONTROL must leave the tree
# byte-identical. Vacuum gate: a run with 0 parsed failures is a HARNESS
# failure, not a pass. (Born with a stash-based backup: `git stash push` on
# an already-clean file is a no-op and the following pop hit "No stash
# entries found" - file copies are the honest backup here.)
set -u
cd "$(dirname "$0")/.."

SRC=src/daemon.js
LADDER=test/request-frame.test.js

fail_count() {
  node --test "$LADDER" 2>&1 | grep -E '^ℹ fail' | grep -oE '[0-9]+'
}

mutate_and_run() {
  local name="$1"; shift
  cp "$SRC" "$SRC.ladder-bak" || exit 3
  eval "$@" || { mv "$SRC.ladder-bak" "$SRC"; echo "MUTATION-FAILED $name (sed/node edit errored)"; exit 3; }
  if ! diff -q "$SRC" "$SRC.ladder-bak" >/dev/null; then
    local fails
    fails=$(fail_count)
    local parsed="yes"
    case "$fails" in
      ''|*[!0-9]*) fails="unparseable"; parsed="no" ;;
    esac
    mv "$SRC.ladder-bak" "$SRC"
    if [ "$parsed" != "yes" ]; then
      echo "VACUUM  $name (fail count unparseable)"
    elif [ "$fails" -ge 1 ]; then
      echo "CAUGHT  $name ($fails failing)"
    else
      echo "ESCAPED $name"
    fi
  else
    mv "$SRC.ladder-bak" "$SRC"
    echo "VACUUM  $name (mutation changed nothing)"
  fi
}

BEFORE=$(git hash-object "$SRC")

echo "== control: unmutated tree must be green =="
ctrl=$(fail_count)
if [ "${ctrl:-x}" = "0" ]; then echo "CONTROL green (0 failing)"; else echo "CONTROL NOT GREEN (${ctrl:-unparseable}) - aborting"; exit 1; fi

mutate_and_run "M1 cap back to the false 8704 derivation" \
  "sed -i 's/const MAX_REQUEST_BYTES = 25_600;/const MAX_REQUEST_BYTES = 8_704;/' $SRC"

mutate_and_run "M2 over-cap refusal silenced (destroy, no verdict)" \
  "node -e \"
const fs=require('fs');let s=fs.readFileSync('$SRC','utf8');
const start=s.indexOf('        if (!handled) {\n          handled = true;\n          const verdict');
const end=s.indexOf('        return;\n      }\n      const newline');
if (start===-1||end===-1) process.exit(1);
s=s.slice(0,start)+'        socket.destroy();\n'+s.slice(end+'        return;\n'.length);
fs.writeFileSync('$SRC',s);\""

mutate_and_run "M3 client close handler made inert (clock blame returns)" \
  "sed -i \"/^    socket\\.on('close', () => {\$/s//if (false) &/\" $SRC"

mutate_and_run "M4 refusal loses the named repair line (fix line renamed)" \
  "sed -i 's/the request frame must stay within/the transport frame stays within/g' $SRC"

mutate_and_run "M5 body-char contract removed (G2 backstop gone)" \
  "sed -i 's/bodyField.value.length > 4096/bodyField.value.length > 40960000/' $SRC"

AFTER=$(git hash-object "$SRC")
if [ "$BEFORE" = "$AFTER" ]; then
  echo "TREE byte-identical after ladder"
else
  echo "TREE CHANGED - ladder left a mutation behind"
  git checkout -q -- "$SRC"
  exit 1
fi
