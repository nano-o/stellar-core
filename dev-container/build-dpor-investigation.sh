#!/usr/bin/env bash
set -euo pipefail

repo_root="${REPO_ROOT:-/home/dev/stellar-core}"
jobs="${BUILD_JOBS:-$(nproc)}"
build_native="${DPOR_BUILD_NATIVE:-1}"
strip_binary="${STRIP_BINARY:-0}"

export CC="${CC:-clang-20}"
export CXX="${CXX:-clang++-20}"

if [[ -z "${CFLAGS:-}" ]]; then
  CFLAGS="-O3 -g1 -fno-omit-frame-pointer -DNDEBUG"
  if [[ "${build_native}" != "0" ]]; then
    CFLAGS="${CFLAGS} -march=native"
  fi
  export CFLAGS
fi

if [[ -z "${CXXFLAGS:-}" ]]; then
  export CXXFLAGS="${CFLAGS}"
fi

cd "${repo_root}"

./autogen.sh
./configure --enable-dpor CC="${CC}" CXX="${CXX}" CFLAGS="${CFLAGS}" CXXFLAGS="${CXXFLAGS}"
make -C src -j"${jobs}" scp-dpor-investigation

if [[ "${strip_binary}" != "0" ]]; then
  strip src/scp-dpor-investigation
fi
