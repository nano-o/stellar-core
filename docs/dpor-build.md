# DPOR (Dynamic Partial Order Reduction) build

DPOR is an opt-in, test-only build target for SCP model-checking. It requires
C++20 and an external header-only dependency.

## Build target: post-CAP-0083 only

The DPOR build targets post-CAP-0083 (empty-tx-set) `stellar-core` only, so
every `configure` invocation below includes
`--enable-next-protocol-version-unsafe-for-production`. That flag defines
`CAP_0083` in the **global** `AM_CPPFLAGS`, which compiles in the empty-tx-set
code path and — critically — keeps the DPOR-rebuilt SCP subset and the linked
non-DPOR objects agreeing on the `SCPDriver` vtable layout. Never add
`-DCAP_0083` to the DPOR target flags alone: that produces a silent vtable/ODR
mismatch, not a build error. See
[`dpor-integration-status.md`](./dpor-integration-status.md) for the rationale.

Because this flag changes both preprocessor defines and generated XDR, turn it
on (or off) with a clean rebuild — run `make clean` first; an incremental
`make` will not reliably pick up the change.

`configure` enforces this build contract: `--enable-dpor` without
`--enable-next-protocol-version-unsafe-for-production` fails with a direct
configuration error. The fast-development profile also satisfies the
requirement because it enables the next protocol version before the check.

> **This recipe is expected to change as stellar-core development
> progresses.** The empty-tx-set feature is gated behind the "next protocol
> version" switch only until that protocol version ships. Once it is released,
> `CAP_0083` stops living behind
> `--enable-next-protocol-version-unsafe-for-production` (it becomes always-on
> and the `CAP_0083` conditional may be retired), while that flag advances to a
> still-newer protocol version. The build-flag layout also shifts periodically
> on its own (e.g. the recent addition of
> `--enable-fastdev-unsafe-for-production`). Re-check the flag and update these
> docs when the empty-tx-set protocol version is released or the flag layout
> changes again.

## Quick start

```bash
# Initialize dependencies, including the pinned DPOR revision (once, after clone)
git submodule update --init --recursive

# Configure with DPOR enabled (post-CAP-0083 target — see "Build target" above)
./autogen.sh
./configure --enable-dpor \
  --enable-next-protocol-version-unsafe-for-production \
  CC=clang-20 CXX=clang++-20

# Build library dependencies first (required on a clean tree)
make -C lib -j"$(nproc)"

# Build DPOR binaries (must use make -C src, not make from repo root)
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation

# Run smoke tests
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"

# Run investigation
./src/scp-dpor-investigation --depth 12
```

`external/dpor` is a submodule pinned by `stellar-core`. Do not check out the
DPOR `main` branch for a normal build: `git submodule update --init
external/dpor` restores the revision selected by the parent repository. Use
`--with-dpor-dir=PATH` only when intentionally testing another CPP-DPOR
checkout.

To confirm that the checkout matches the pin:

```bash
git submodule status external/dpor
```

The output should begin with a space. A leading `+` means the checkout is at a
different commit; rerun `git submodule update --init external/dpor` to restore
the pinned revision.

## Building with Namespace-backed sccache

To cache the normal C/C++ object graph, the DPOR-specific C++20 objects, and
Rust compilation, authenticate `nsc` and confirm that the `sccache` selected
from `PATH` has WebDAV support:

```bash
nsc auth check-login
sccache --help | sed -n '/Enabled features:/,$p'
```

Then add `--enable-nsc-sccache` when configuring:

```bash
./autogen.sh
./configure --enable-dpor \
  --enable-next-protocol-version-unsafe-for-production \
  --enable-nsc-sccache \
  CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

This option implies `--enable-sccache` and cannot be combined with
`--enable-ccache`. Configure runs `nsc cache sccache setup --cache_name
stellar`, starts the cache daemon with the returned WebDAV credentials, and
verifies that `sccache -s` reports WebDAV storage.

## Out-of-tree builds

Out-of-tree builds are supported — run `configure` from a separate build
directory to keep the source tree clean:

```bash
mkdir -p /path/to/build && cd /path/to/build
/path/to/stellar-core/configure --enable-dpor \
  --enable-next-protocol-version-unsafe-for-production \
  CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

## Important: always use `make -C src`

DPOR binaries use `EXTRA_PROGRAMS` and are not built by the default `make`
target. You must request them explicitly. Always build from the `src`
subdirectory:

```bash
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

Do **not** use `make src/stellar-core-dpor-tests` from the repo root — the
top-level recursive Makefile has no dependency tracking for DPOR targets and
will silently skip recompilation when sources change.

## Clean-tree builds require `make -C lib` first

On a clean tree, `make -C src` alone will fail because the library
dependencies (`libsodium`, `xdrpp`) have not been built yet. The `src`
Makefile has rules that reach into `lib/` to build individual targets, but
these race on a parallel build — xdrpp's library compilation starts before
`xdrc` has generated the required `.hh` files from `.x` sources.

Run `make -C lib` once before `make -C src`:

```bash
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

After the initial lib build, `make -C src` alone is sufficient for incremental
rebuilds.
