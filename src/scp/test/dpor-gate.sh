#!/bin/bash
# Batch-gate runner for the stellar-core DPOR integration (engine
# docs/simplification_refactoring_plan.md, Phase 0 "Build-time and
# gate-automation baseline").
#
# Wraps the documented build/test commands and the bench-dpor.sh scenario
# harness, and archives logs, fingerprints, revisions, and timings in a
# comparable artifact directory. bench-dpor.sh remains the underlying harness;
# this adds build/smoke/full modes plus archiving.
#
# Usage:
#   dpor-gate.sh smoke       build DPOR binaries + [scp][dpor][smoke] tests
#   dpor-gate.sh check       exact execution-count fingerprint (bench-dpor.sh check)
#   dpor-gate.sh full        smoke + the full [scp] suite
#   dpor-gate.sh perf        bench-dpor.sh bench + head (machine-qualified)
#   dpor-gate.sh scale       opt-in: bench-dpor.sh scale (documented machine shape only)
#   dpor-gate.sh buildtime   warm rebuild cost after touching dpor/algo/dpor.hpp
#
# Environment:
#   GATE_ARTIFACTS_ROOT     default $HOME/dpor-gate-artifacts
#   W                       worker args forwarded to bench-dpor.sh (default "--workers 8")
#   GATE_STEP_TIMEOUT_SECS  hard time box per step (default 3600); a step that
#                           exceeds it FAILS — time-boxed evidence only
#
# The tree must already be configured per the documented DPOR workflow
# (configure --enable-dpor --enable-nsc-sccache CC=clang-20 CXX=clang++-20).
set -u -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
MODE="${1:-}"
shift || true

if [ -z "$MODE" ]; then
  sed -n '2,25p' "${BASH_SOURCE[0]}"
  exit 2
fi

if [ ! -f "$REPO_ROOT/src/Makefile" ]; then
  echo "error: $REPO_ROOT is not configured; run the documented DPOR configure first" >&2
  exit 2
fi

SHORTREV=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ART="${GATE_ARTIFACTS_ROOT:-$HOME/dpor-gate-artifacts}/stellar/${STAMP}-${MODE}-${SHORTREV}"
mkdir -p "$ART"

ENGINE_DIR="$REPO_ROOT/external/dpor"
BENCH="$SCRIPT_DIR/bench-dpor.sh"
TESTS_BIN="$REPO_ROOT/src/stellar-core-dpor-tests"
INVESTIGATION_BIN="$REPO_ROOT/src/scp-dpor-investigation"

manifest() {
  {
    echo "gate: stellar-dpor"
    echo "mode: $MODE"
    echo "args: $*"
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host: $(hostname)"
    echo "kernel: $(uname -sr)"
    echo "nproc: $(nproc)"
    echo "git_head: $(git -C "$REPO_ROOT" rev-parse HEAD)"
    echo "git_branch: $(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
    echo "engine_rev: $(git -C "$ENGINE_DIR" rev-parse HEAD 2>/dev/null || echo unavailable)"
    if [ -n "$(git -C "$ENGINE_DIR" status --porcelain 2>/dev/null)" ]; then
      echo "engine_dirty: yes"
    else
      echo "engine_dirty: no"
    fi
    echo "cxx: $(grep -m1 '^CXX = ' "$REPO_ROOT/src/Makefile" | sed 's/^CXX = //')"
    echo "bench_workers: ${W:---workers 8}"
  } > "$ART/manifest.txt"
}

finish() {
  local status=$1
  if [ "$status" -eq 0 ]; then
    echo "result: PASS" >> "$ART/manifest.txt"
    echo "gate $MODE: PASS  (artifacts: $ART)"
  else
    echo "result: FAIL" >> "$ART/manifest.txt"
    echo "gate $MODE: FAIL  (artifacts: $ART)" >&2
  fi
  exit "$status"
}

STEP_TIMEOUT="${GATE_STEP_TIMEOUT_SECS:-3600}"

run_logged() { # logname, cmd...
  local log="$ART/$1.log"
  shift
  echo "== $* (log: $(basename "$log"), time box: ${STEP_TIMEOUT}s)"
  local start end rc
  start=$(date +%s.%N)
  timeout --kill-after=30 "$STEP_TIMEOUT" "$@" > "$log" 2>&1
  rc=$?
  end=$(date +%s.%N)
  if [ "$rc" -eq 0 ]; then
    awk -v a="$start" -v b="$end" 'BEGIN{printf "   ok in %.1fs\n", b-a}'
  elif [ "$rc" -eq 124 ]; then
    echo "   TIMED OUT after ${STEP_TIMEOUT}s — investigate before raising GATE_STEP_TIMEOUT_SECS" >&2
    tail -40 "$log" >&2
  else
    awk -v a="$start" -v b="$end" -v r="$rc" 'BEGIN{printf "   FAILED (exit %d) in %.1fs\n", r, b-a}' >&2
    tail -40 "$log" >&2
  fi
  return "$rc"
}

build_dpor() {
  run_logged build make -C "$REPO_ROOT/src" -j"$(nproc)" \
    stellar-core-dpor-tests scp-dpor-investigation
}

manifest "$@"

case "$MODE" in
  smoke)
    build_dpor || finish 1
    run_logged smoke-tests "$TESTS_BIN" "[scp][dpor][smoke]" || finish 1
    finish 0
    ;;

  check)
    [ -x "$INVESTIGATION_BIN" ] || build_dpor || finish 1
    echo "== bench-dpor.sh check (fingerprint: fingerprint.txt, time box: ${STEP_TIMEOUT}s)"
    if timeout --kill-after=30 "$STEP_TIMEOUT" env BIN="$INVESTIGATION_BIN" "$BENCH" check > "$ART/fingerprint.txt" 2>&1; then
      cat "$ART/fingerprint.txt"
      finish 0
    else
      cat "$ART/fingerprint.txt" >&2
      finish 1
    fi
    ;;

  full)
    build_dpor || finish 1
    run_logged smoke-tests "$TESTS_BIN" "[scp][dpor][smoke]" || finish 1
    run_logged full-scp-tests "$TESTS_BIN" "[scp]" || finish 1
    finish 0
    ;;

  perf)
    [ -x "$INVESTIGATION_BIN" ] || build_dpor || finish 1
    run_logged bench env BIN="$INVESTIGATION_BIN" "$BENCH" bench || finish 1
    run_logged head env BIN="$INVESTIGATION_BIN" "$BENCH" head || finish 1
    cat "$ART/bench.log"
    finish 0
    ;;

  scale)
    [ -x "$INVESTIGATION_BIN" ] || build_dpor || finish 1
    run_logged scale env BIN="$INVESTIGATION_BIN" "$BENCH" scale || finish 1
    finish 0
    ;;

  buildtime)
    # Warm-cache rebuild cost after touching the main engine header: the DPOR
    # binaries recompile every DPOR TU and relink the full test suite.
    touch "$ENGINE_DIR/include/dpor/algo/dpor.hpp"
    start=$(date +%s.%N)
    build_dpor || finish 1
    end=$(date +%s.%N)
    awk -v a="$start" -v b="$end" 'BEGIN{printf "warm_rebuild_s: %.1f\n", b-a}' \
      | tee -a "$ART/manifest.txt"
    finish 0
    ;;

  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac
