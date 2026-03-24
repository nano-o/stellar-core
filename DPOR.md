# DPOR

This repository has an opt-in DPOR build island for SCP. The DPOR code is not
compiled into the main `stellar-core` test binary.

## Prerequisites

Initialize submodules and clone the header-only DPOR dependency:

```bash
git submodule update --init --recursive
git clone https://github.com/nano-o/CPP-DPOR.git external/dpor
```

By default, configure looks for DPOR in `external/dpor`.

## Configure

Generate autotools files and configure with tests and DPOR enabled:

```bash
./autogen.sh
./configure --enable-tests --enable-dpor CC=clang-20 CXX=clang++-20
```

If DPOR is cloned somewhere else, point configure at it explicitly:

```bash
./configure \
  --enable-tests \
  --enable-dpor \
  --with-dpor-dir=/abs/path/to/CPP-DPOR \
  CC=clang-20 \
  CXX=clang++-20
```

In the current container, the following variant also works and avoids the local
allocator issue:

```bash
./configure --enable-tests --enable-dpor --enable-asan CC=clang-20 CXX=clang++-20
```

## Build

Build just the DPOR binaries:

```bash
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

This produces:

- `./src/stellar-core-dpor-tests`
- `./src/scp-dpor-investigation`

## Run

Run the DPOR smoke tests:

```bash
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"
```

Run the investigation binary:

```bash
./src/scp-dpor-investigation --depth 12
```

Useful investigation flags:

```bash
./src/scp-dpor-investigation --workers 8 --depth 12
./src/scp-dpor-investigation --fifo --depth 12
./src/scp-dpor-investigation --dump-initial-steps 3
./src/scp-dpor-investigation --dump-terminal-trace --depth 12
```
