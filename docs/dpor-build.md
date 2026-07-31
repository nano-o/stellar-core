# DPOR (Dynamic Partial Order Reduction) build

DPOR is an opt-in, test-only build target for SCP model-checking. It requires
C++20 and an external header-only dependency.

## Build target: post-CAP-0083 (now just `master`)

The DPOR build targets post-CAP-0083 (empty-tx-set) `stellar-core`. Upstream's
"Ungate CAP-0083 and CAP-0085, bump to protocol 28" (#5397) made that the
default: `CAP_0083` no longer exists as an automake conditional or a
preprocessor define, the `#ifdef CAP_0083` guards are gone from the SCP and
herder sources, and empty-tx-set support is compiled in unconditionally.

Consequently `--enable-dpor` **no longer requires**
`--enable-next-protocol-version-unsafe-for-production`, and `configure` no
longer enforces that pairing. The flag remains the whole-build next-protocol
switch: among other effects, it defines
`ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION`, advances
`Config::CURRENT_LEDGER_PROTOCOL_VERSION`, and enables Soroban `next` features.
Those effects are orthogonal to DPOR's empty-tx-set build contract, so the
`configure` invocations below omit it.

> **Historical note.** While `CAP_0083` was a real define it had to live in the
> **global** `AM_CPPFLAGS` and never in the DPOR target flags alone, because it
> changed the `SCPDriver` vtable layout while the DPOR binaries link non-DPOR
> objects from the normal build — a DPOR-only `-DCAP_0083` produced a silent
> vtable/ODR mismatch rather than a build error. That rule still governs any
> **future** protocol define that touches the `SCPDriver` vtable, and toggling
> such a define still warrants a clean rebuild (`make clean` first), since an
> incremental `make` will not reliably pick up a define or generated-XDR change.
> See [`dpor-integration-status.md`](./dpor-integration-status.md).

> **This recipe is still expected to drift as stellar-core develops.** The
> build-flag layout shifts periodically on its own (e.g. the addition of
> `--enable-fastdev-unsafe-for-production`, and this CAP-0083 ungating).
> Re-check the flags and update these docs whenever a protocol version ships
> or the flag layout changes again.

## Quick start

```bash
# Initialize dependencies, including the pinned DPOR revision (once, after clone)
git submodule update --init --recursive

# Configure with DPOR enabled (post-CAP-0083 target — see "Build target" above)
./autogen.sh
./configure --enable-dpor CC=clang-20 CXX=clang++-20

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
/path/to/stellar-core/configure --enable-dpor CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

## Generating compile commands with compiledb

Optionally, use
[`compiledb`](https://github.com/nickdiego/compiledb) to generate
`compile_commands.json` from Make's dry-run output. Run it from the configured
build root:

```bash
compiledb -f -n -d "$PWD/src" make -C src \
  stellar-core-dpor-tests scp-dpor-investigation
```

`-f` replaces any existing database, while `-d "$PWD/src"` gives the parser
the initial directory for commands emitted by `make -C src`. The two DPOR
targets pull in the required library dependency commands, so a separate
`make -C lib` pass is unnecessary. `compiledb -n` does not execute the build,
so this workflow does not require `make clean`, a rebuild, or `-j`. It
recognizes `sccache` as a compiler wrapper and emits the underlying compiler
command, so keep `--enable-nsc-sccache` enabled if that is the desired build
configuration.

For an in-tree build, the build root is the repository root. For an
out-of-tree build, it is the separate build directory, and the compilation
database is written there. Rerun the command after reconfiguring or after
changing build wiring or source lists; no clean build is required.

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
