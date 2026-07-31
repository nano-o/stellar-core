#!/bin/bash
# DPOR investigation throughput benchmark + correctness fingerprint.
#   ./bench-dpor.sh bench   -> timing for the perf suite
#   ./bench-dpor.sh check   -> exact execution counts (must be byte-identical across versions)
#   ./bench-dpor.sh head    -> headline: user's exact command, time-boxed rate
# Runnable from any directory; set BIN to point at an out-of-tree binary.
#
# Exits nonzero if any scenario process fails, so `check` output can be trusted
# as a fingerprint rather than silently degrading to empty lines.
set -u -o pipefail

# Default to the in-tree binary regardless of the caller's cwd. Out-of-tree
# builds should pass BIN explicitly.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
BIN=${BIN:-$REPO_ROOT/src/scp-dpor-investigation}
W=${W:---workers 8}
FAILED=0

U="--nodes 3 --fifo --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-externalize"
V="--nodes 4 --fifo --txset-status always-valid --download-time below --stop-on-prepare"
X="--nodes 3 --txset-status always-valid --download-time below --stop-on-commit"
Y="--nodes 3 --fifo --txset-status always-valid --download-time below --stop-on-commit"

run_scenario() { # out_file, args...   -> returns the binary's own status
  local out=$1; shift
  "$BIN" "$@" $W > "$out" 2>&1
}

bench_one() { # name, args...
  local name=$1; shift
  local best=99999 t out
  out=$(mktemp)
  for _ in 1 2 3; do
    local start end status
    start=$(date +%s.%N)
    run_scenario "$out" "$@"
    status=$?
    if [ "$status" -ne 0 ]; then
      printf 'BENCH %-6s FAILED (exit %d)\n' "$name" "$status"
      cat "$out" >&2
      FAILED=1
      rm -f "$out"
      return
    fi
    end=$(date +%s.%N)
    t=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b-a}')
    awk -v a="$t" -v b="$best" 'BEGIN{exit !(a<b)}' && best=$t
  done
  rm -f "$out"
  printf 'BENCH %-6s %8s s\n' "$name" "$best"
}

check_one() { # name, args...
  local name=$1; shift
  local out status
  out=$(mktemp)
  run_scenario "$out" "$@"
  status=$?
  if [ "$status" -ne 0 ]; then
    printf 'CHECK %-6s FAILED (exit %d)\n' "$name" "$status"
    cat "$out" >&2
    FAILED=1
  else
    printf 'CHECK %-6s %s\n' "$name" "$(tail -1 "$out")"
  fi
  rm -f "$out"
}

case "${1:-bench}" in
bench)
  bench_one S1 $U --depth 50
  bench_one S2 $V --depth 52
  bench_one S3 $X --depth 46
  bench_one S4 $Y --depth 200
  ;;
check)
  check_one C1 --nodes 3 --fifo --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-prepare --depth 200
  check_one C2 --nodes 3 --fifo --with-nomination-timers --txset-status always-valid --download-time below --stop-on-prepare --depth 200
  check_one C3 --nodes 3 --fifo --txset-status downloading-then-valid --download-time nondet --stop-on-prepare --depth 200
  check_one C4 --nodes 3 --fifo --txset-status always-downloading --download-time above --stop-on-prepare --depth 200
  check_one C5 $Y --depth 200
  check_one C6 --nodes 3 --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-prepare --depth 200
  check_one C7 $V --depth 50
  check_one C8 --nodes 3 --fifo --init unique --txset-status always-valid --download-time below --with-nomination-timers --stop-on-prepare --depth 200
  check_one C9 --nodes 3 --fifo --with-balloting-timers --max-balloting-timers-round 2 --txset-status always-valid --download-time below --stop-on-prepare --depth 200
  check_one CA --nodes 3 --fifo --download-succeeds-in-round 1 --txset-status downloading-then-valid --download-time nondet --stop-on-prepare --depth 200
  check_one CB --nodes 4 --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-prepare --depth 40
  check_one CC $U --depth 46
  check_one CD $X --depth 42
  ;;
head)
  SECS=${SECS:-60}
  LOG=$(mktemp)
  # timeout is expected to kill this run, so its status is not a failure signal;
  # the awk stage below fails if no progress lines were produced.
  timeout "$SECS" "$BIN" --nodes 3 --fifo --txset-status downloading-then-valid \
      --nomination-always-downloading --download-time nondet --stop-on-externalize \
      --depth 200 $W --print-stats 5 > "$LOG" 2>&1
  awk '
    /^progress/ {
      for (i=1;i<=NF;i++) { split($i,kv,"="); v[kv[1]]=kv[2] }
      ms=v["elapsed_ms"]; n=v["terminal_executions"]
      if (ms<=20500 && ms>=19500) { t0=ms; n0=n }
      tl=ms; nl=n
      seen=1
    }
    END {
      if (!seen) { print "HEAD  FAILED: no progress output"; exit 1 }
      if (t0=="") { t0=0; n0=0 }
      printf "HEAD  window=[%.1fs,%.1fs] execs=%d rate=%.0f exec/s (overall %.0f exec/s)\n",
             t0/1000, tl/1000, nl-n0, (nl-n0)/((tl-t0)/1000), nl/(tl/1000)
    }' "$LOG" || { cat "$LOG" >&2; FAILED=1; }
  rm -f "$LOG"
  ;;
esac

exit $FAILED
