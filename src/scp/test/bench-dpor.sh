#!/bin/bash
# DPOR investigation throughput benchmark + correctness fingerprint.
#   ./bench-dpor.sh bench   -> timing for the perf suite
#   ./bench-dpor.sh check   -> exact execution counts (must be byte-identical across versions)
#   ./bench-dpor.sh head    -> headline: user's exact command, time-boxed rate
#   ./bench-dpor.sh scale   -> opt-in parallel-scaling regression check (slow)
# Runnable from any directory; set BIN to point at an out-of-tree binary.
#
# Exits nonzero if any scenario process fails, so `check` output can be trusted
# as a fingerprint rather than silently degrading to empty lines.
#
# `scale` is deliberately not part of any default run: it takes minutes, and it
# only asserts on one exact machine shape (see the scale) branch below).
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

# ---------------------------------------------------------------------------
# scale-mode helpers
# ---------------------------------------------------------------------------

expand_cpu_list() { # "0-3,8" -> one CPU number per line
  local spec=$1 part lo hi i
  local -a parts=()
  IFS=',' read -ra parts <<< "$spec"
  for part in "${parts[@]}"; do
    if [[ $part == *-* ]]; then
      lo=${part%%-*}; hi=${part##*-}
      for ((i = lo; i <= hi; i++)); do printf '%s\n' "$i"; done
    elif [ -n "$part" ]; then
      printf '%s\n' "$part"
    fi
  done
}

usable_cpus() { # CPUs this process is actually allowed to run on
  local line spec
  if line=$(taskset -pc $$ 2>/dev/null); then
    spec=${line##*: }
    expand_cpu_list "$spec"
    return
  fi
  # No taskset: fall back to every online CPU.
  expand_cpu_list "$(cat /sys/devices/system/cpu/online 2>/dev/null || echo "0-$(($(nproc) - 1))")"
}

# cgroup v2 cpu.max is invisible to sched_getaffinity, so a 32-CPU mask can sit
# under a quota worth far less. Walk leaf -> root and take the tightest quota.
cgroup_cpu_quota() { # prints CPU-equivalents, or "max"
  local rel dir quota period cpus best=""
  rel=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup 2>/dev/null)
  [ -n "$rel" ] || { printf 'max\n'; return; }
  dir=/sys/fs/cgroup${rel%/}
  while :; do
    if [ -r "$dir/cpu.max" ]; then
      read -r quota period < "$dir/cpu.max" || true
      if [ "${quota:-max}" != max ] && [ -n "${period:-}" ] && [ "$period" -ne 0 ]; then
        cpus=$(awk -v q="$quota" -v p="$period" 'BEGIN { printf "%.3f", q / p }')
        if [ -z "$best" ] || awk -v a="$cpus" -v b="$best" 'BEGIN { exit !(a < b) }'; then
          best=$cpus
        fi
      fi
    fi
    [ "$dir" = /sys/fs/cgroup ] && break
    dir=$(dirname "$dir")
  done
  [ -n "$best" ] && printf '%s\n' "$best" || printf 'max\n'
}

# Build a 32-CPU mask covering exactly 16 SMT2 physical cores, or print nothing.
# core_id is only unique within a package, so cores are keyed by
# (physical_package_id, core_id). Requiring the exact reference shape rather
# than a lower bound is deliberate: a 32-core non-SMT host hands --workers 32
# twice the physical hardware the pathology was measured on, so a lower bound
# would let a still-broken scheduler pass. Constructing the mask instead of
# merely demanding it makes larger SMT2 machines eligible rather than excluded.
reference_cpu_mask() {
  local cpu pkg core key sibs nsibs
  local -A group=()
  local -a keys=()
  while read -r cpu; do
    [ -n "$cpu" ] || continue
    local topo=/sys/devices/system/cpu/cpu$cpu/topology
    [ -r "$topo/core_id" ] && [ -r "$topo/physical_package_id" ] || return 0
    pkg=$(cat "$topo/physical_package_id")
    core=$(cat "$topo/core_id")
    sibs=$(cat "$topo/thread_siblings_list" 2>/dev/null || echo "$cpu")
    nsibs=$(expand_cpu_list "$sibs" | wc -l)
    # Only true SMT2 cores qualify; an SMT4 core with 2 usable siblings is a
    # different machine shape and must not be treated as the reference.
    [ "$nsibs" -eq 2 ] || continue
    key=$pkg:$core
    if [ -z "${group[$key]:-}" ]; then
      group[$key]=$cpu
      keys+=("$key")
    else
      group[$key]="${group[$key]},$cpu"
    fi
  done < <(usable_cpus | sort -n)

  local -a chosen=()
  for key in "${keys[@]}"; do
    # Both siblings must be usable, else this core is only half available.
    [ "$(expand_cpu_list "${group[$key]}" | wc -l)" -eq 2 ] || continue
    chosen+=("${group[$key]}")
    [ "${#chosen[@]}" -eq 16 ] && break
  done

  [ "${#chosen[@]}" -eq 16 ] || return 0
  local IFS=,
  printf '%s\n' "${chosen[*]}"
}

median() { sort -g | awk '
  { a[NR] = $1 }
  END {
    if (NR == 0) { print "0"; exit }
    if (NR % 2) { printf "%.2f", a[(NR + 1) / 2] }
    else { printf "%.2f", (a[NR / 2] + a[NR / 2 + 1]) / 2 }
  }'; }

# Relative median absolute deviation: dispersion of one worker point, as a
# fraction of its own median. Deliberately not (max-min)/median -- with a
# handful of repetitions the range is set by a single outlier, and the shortest
# worker point would then dictate the tolerance for every comparison.
rel_mad() { # values as one argument
  local m
  m=$(printf '%s\n' $1 | median)
  printf '%s\n' $1 |
    awk -v m="$m" '{ d = $1 - m; print (d < 0) ? -d : d }' |
    sort -g |
    awk -v m="$m" '
      { a[NR] = $1 }
      END {
        if (NR == 0 || m <= 0) { printf "0.000"; exit }
        md = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
        printf "%.3f", md / m
      }'
}

# Tolerance for comparing two worker points: their dispersions add, floored at
# MIN_MARGIN so a suspiciously quiet machine cannot produce a hair-trigger gate.
pair_margin() { # dispA, dispB, floor
  awk -v a="$1" -v b="$2" -v f="$3" 'BEGIN { s = a + b; printf "%.3f", (s > f) ? s : f }'
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
  # C1's scenario under a per-thread event bound. Chosen because it splits
  # across all three of full/blocked/thread-event-limit, so the fingerprint is
  # sensitive to terminal *classification*, not just to the explored count.
  check_one CE --nodes 3 --fifo --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-prepare --depth 200 --thread-event-depth 9
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
scale)
  # Opt-in parallel-scaling regression check.
  #
  # Every assertion here is a performance claim, so it is only meaningful
  # relative to the machine. The gate therefore runs only on one exact shape --
  # 16 usable SMT2 physical cores presenting 32 logical CPUs, with a CPU
  # bandwidth quota covering all 32 -- and is reporting-only everywhere else.
  # A gate that runs everywhere and fails for environmental reasons trains
  # people to ignore it; one that runs everywhere and passes for environmental
  # reasons is worse.
  #
  # S2 is pinned exactly: it is the scenario that inverts (0.61x at 32 workers
  # versus 1 worker on the reference host), and the worker points are fixed
  # rather than derived from nproc, because derived points silently move the
  # gate off the counts where the pathology was demonstrated.
  REPS=${REPS:-5}
  MIN_MARGIN=${MIN_MARGIN:-0.10}
  S2="--nodes 3 --fifo --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-externalize --depth 56"
  REFERENCE_POINTS="1 8 16 32"
  POINTS=${SCALE_WORKERS:-$REFERENCE_POINTS}

  eligible=1
  reasons=""
  disqualify() { eligible=0; reasons="$reasons  - $1"$'\n'; }

  [ "$POINTS" = "$REFERENCE_POINTS" ] ||
    disqualify "worker points overridden ($POINTS != $REFERENCE_POINTS)"

  MASK=""
  if command -v taskset > /dev/null 2>&1; then
    MASK=$(reference_cpu_mask)
    [ -n "$MASK" ] || disqualify "no 16 fully-usable SMT2 physical cores found"
  else
    disqualify "taskset not available, cannot pin to the reference shape"
  fi

  QUOTA=$(cgroup_cpu_quota)
  if [ "$QUOTA" != max ]; then
    awk -v q="$QUOTA" 'BEGIN { exit !(q >= 32) }' ||
      disqualify "cgroup cpu.max quota is $QUOTA CPUs, below the 32 required"
  fi

  if [ "$eligible" -eq 1 ]; then
    printf 'SCALE mode=gated cpus=%s quota=%s reps=%d\n' "$MASK" "$QUOTA" "$REPS"
    PIN=(taskset -c "$MASK")
  else
    printf 'SCALE mode=reporting-only reps=%d\n%s' "$REPS" "$reasons"
    PIN=()
    [ -n "$MASK" ] && PIN=(taskset -c "$MASK")
  fi

  declare -A TIMES=()
  EXECS=""
  scale_failed=0
  for w in $POINTS; do TIMES[$w]=""; done

  # Alternate across worker counts within one session so that any drift in
  # machine load lands on every point rather than on whichever ran last.
  for rep in $(seq 1 "$REPS"); do
    for w in $POINTS; do
      out=$(mktemp)
      start=$(date +%s.%N)
      "${PIN[@]}" "$BIN" $S2 --workers "$w" > "$out" 2>&1
      status=$?
      end=$(date +%s.%N)
      if [ "$status" -ne 0 ]; then
        printf 'SCALE  w=%-3s FAILED (exit %d)\n' "$w" "$status"
        cat "$out" >&2
        FAILED=1
        scale_failed=1
        rm -f "$out"
        continue
      fi
      # The final summary line is exact even for --workers N; progress lines
      # are not. A scheduler that explores a different set makes every timing
      # below meaningless, so disagreement is a hard failure.
      n=$(sed -n 's/.*executions=\([0-9]*\).*/\1/p' "$out" | tail -1)
      if [ -z "$EXECS" ]; then
        EXECS=$n
      elif [ "$n" != "$EXECS" ]; then
        printf 'SCALE  w=%-3s FAILED: executions=%s but earlier runs saw %s\n' "$w" "$n" "$EXECS"
        FAILED=1
        scale_failed=1
      fi
      t=$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.2f", b - a }')
      TIMES[$w]="${TIMES[$w]} $t"
      rm -f "$out"
    done
  done

  if [ "$scale_failed" -ne 0 ]; then
    printf 'SCALE aborted: scenario runs did not all succeed with identical counts\n'
    exit 1
  fi

  # Noise floor, measured rather than assumed, per worker point.
  declare -A MED=() DISP=()
  printf 'SCALE executions=%s (identical at every worker count)\n' "$EXECS"
  printf 'SCALE %-8s %9s %9s %9s %9s %8s\n' workers median min max speedup relmad
  for w in $POINTS; do
    MED[$w]=$(printf '%s\n' ${TIMES[$w]} | median)
    DISP[$w]=$(rel_mad "${TIMES[$w]}")
    lo=$(printf '%s\n' ${TIMES[$w]} | sort -g | head -1)
    hi=$(printf '%s\n' ${TIMES[$w]} | sort -g | tail -1)
    sp=$(awk -v b="${MED[${POINTS%% *}]}" -v m="${MED[$w]}" \
      'BEGIN { printf "%.2f", (m > 0) ? b / m : 0 }')
    printf 'SCALE %-8s %9s %9s %9s %8sx %7s%%\n' "$w" "${MED[$w]}" "$lo" "$hi" "$sp" \
      "$(awk -v s="${DISP[$w]}" 'BEGIN { printf "%.1f", s * 100 }')"
  done

  if [ "$eligible" -ne 1 ]; then
    printf 'SCALE reporting-only: no assertions made\n'
    exit "$FAILED"
  fi

  # Primary gate: the established pathology. w=32 must not be materially
  # slower than w=1.
  m1=$(pair_margin "${DISP[32]}" "${DISP[1]}" "$MIN_MARGIN")
  if awk -v a="${MED[32]}" -v b="${MED[1]}" -v m="$m1" 'BEGIN { exit !(a > b * (1 + m)) }'; then
    printf 'SCALE FAIL primary: w=32 (%ss) is materially slower than w=1 (%ss), margin %s%%\n' \
      "${MED[32]}" "${MED[1]}" "$(awk -v m="$m1" 'BEGIN { printf "%.1f", m * 100 }')"
    FAILED=1
  else
    printf 'SCALE PASS primary: w=32 (%ss) vs w=1 (%ss), margin %s%%\n' \
      "${MED[32]}" "${MED[1]}" "$(awk -v m="$m1" 'BEGIN { printf "%.1f", m * 100 }')"
  fi

  # Secondary gate: scaling through physical-core count.
  #
  # Deliberately NOT asserted: that w=32 beats w=8. On an SMT2 host that
  # compares SMT-shared cores against unshared ones, and a
  # memory-bandwidth-bound exploration workload can lose that comparison with a
  # perfectly correct scheduler.
  m2=$(pair_margin "${DISP[16]}" "${DISP[8]}" "$MIN_MARGIN")
  if awk -v a="${MED[16]}" -v b="${MED[8]}" -v m="$m2" 'BEGIN { exit !(a < b * (1 - m)) }'; then
    printf 'SCALE PASS secondary: w=16 (%ss) improves on w=8 (%ss), margin %s%%\n' \
      "${MED[16]}" "${MED[8]}" "$(awk -v m="$m2" 'BEGIN { printf "%.1f", m * 100 }')"
  else
    printf 'SCALE FAIL secondary: w=16 (%ss) does not improve on w=8 (%ss), margin %s%%\n' \
      "${MED[16]}" "${MED[8]}" "$(awk -v m="$m2" 'BEGIN { printf "%.1f", m * 100 }')"
    FAILED=1
  fi
  ;;
esac

exit $FAILED
