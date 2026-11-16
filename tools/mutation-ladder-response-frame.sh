#!/usr/bin/env bash
# Mutation ladder for the response-frame surface
# (test/response-frame.test.js).
# Each mutation removes ONE face of the fix; the ladder must catch it
# (>= 1 failing case in the ladder file), and the CONTROL must leave the
# tree byte-identical. Vacuum gate: a run with 0 parsed failures is a
# HARNESS failure, not a pass. (File copies are the backup: `git stash push`
# on an already-clean file is a no-op and the pop then hits "No stash
# entries found".)
set -u
cd "$(dirname "$0")/.."

SRC=src/daemon.js
LADDER=test/response-frame.test.js

fail_count() {
  node --test "$LADDER" 2>&1 | grep -E '^ℹ fail' | grep -oE '[0-9]+'
}

mutate_and_run() {
  local name="$1"; shift
  cp "$SRC" "$SRC.ladder-bak" || exit 3
  eval "$@" || { mv "$SRC.ladder-bak" "$SRC"; echo "MUTATION-FAILED $name (edit errored)"; exit 3; }
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

mutate_and_run "M1 the response cap removed (the buffer grows without limit again)" \
  "sed -i 's/const MAX_RESPONSE_BYTES = 8192;/const MAX_RESPONSE_BYTES = 1024 * 1024 * 1024;/' $SRC"

mutate_and_run "M2 the cap refusal loses its named code" \
  "sed -i \"s/refuse('response_too_large',/refuse('response_error',/g\" $SRC"

mutate_and_run "M3 the cap refusal loses its bound (a repair that says nothing checkable)" \
  "sed -i 's/a sign answer is about 2450 bytes at the wire ceiling/a sign answer is small/g' $SRC"

mutate_and_run "M4 a non-JSON frame resolves again (the bare Error returns)" \
  "sed -i 's/const err = fail(.response_invalid., .the daemon answer was not JSON.);/const err = new Error(\"response_invalid\");/' $SRC"

mutate_and_run "M5 the verdict shape check removed (nobody's answer is relayed again)" \
  "node -e \"
const fs=require('fs');let s=fs.readFileSync('$SRC','utf8');
const start=s.indexOf('        if (response === null || typeof response !== ');
if (start===-1) process.exit(1);
const end=s.indexOf('        resolve(response);', start);
if (end===-1) process.exit(1);
s=s.slice(0,start)+s.slice(end);
fs.writeFileSync('$SRC',s);\""

mutate_and_run "M6 the close refusal loses its repair (the operator sees nothing)" \
  "sed -i \"s|err.fix = '  fix: the connection died before a verdict arrived;|err.fix = ''; //|\" $SRC"

AFTER=$(git hash-object "$SRC")
if [ "$BEFORE" = "$AFTER" ]; then
  echo "TREE byte-identical after ladder"
else
  echo "TREE CHANGED - ladder left a mutation behind"
  git checkout -q -- "$SRC"
  exit 1
fi
