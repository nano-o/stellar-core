#!/usr/bin/env bash
set -euo pipefail

shopt -s nullglob

perf_bin=""
for candidate in /usr/lib/linux-tools/*/perf /usr/lib/linux-tools-*/perf; do
  if [[ -x "${candidate}" ]]; then
    perf_bin="${candidate}"
  fi
done

if [[ -z "${perf_bin}" ]]; then
  echo "perf binary not found under /usr/lib/linux-tools*" >&2
  exit 127
fi

exec "${perf_bin}" "$@"
