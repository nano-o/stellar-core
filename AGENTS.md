# AGENTS.md

## Project

`stellar-core` — the C++ implementation of the Stellar Consensus Protocol (SCP)
and the ledger-closing pipeline for the Stellar network.

## Current work

Branch: `dpor-on-master` (the DPOR work rebased onto upstream `master`, which
now includes the merged CAP-0083 empty-tx-set feature; the pre-rebase branch
`skip-ledgers-p26-dpor` remains as reference)

Status: the first DPOR (Dynamic Partial Order Reduction) integration for SCP
has already landed. `stellar-core` now has an opt-in, test-only DPOR build
island with dedicated binaries, a split support layer, and an initial scenario
surface.

The DPOR investigation feature is part of that landed integration. The
`scp-dpor-investigation` binary is the manual exploration and debugging tool
for scenario work: use it to inspect executions, replay traces, boundary
behavior, and performance characteristics while iterating on scenarios or
build-shape changes.

Current phase: optimize DPOR performance and iterate on scenario coverage.
Prioritize work that:
- improves replay/exploration throughput or investigation ergonomics
- expands or hardens scenario coverage for SCP behaviors already modeled
- tightens smoke tests and investigation workflows around the checked-in
  integration
- reduces compile cost or exploration cost without weakening the build island

Before starting DPOR implementation work, read
[docs/dpor-integration-status.md](docs/dpor-integration-status.md). Use it as
the source of truth for what is already integrated and what limitations remain.
For trace-capture or replay work, also read
[docs/dpor-replay-notes.md](docs/dpor-replay-notes.md).

Previous attempt: branch `dpor-skip-ledgers-p25` (accessible via
`git log dpor-skip-ledgers-p25` in this repo). That branch has 64 commits of
working DPOR/SCP integration code. Use it as a reference for what worked, but
prefer extending the current in-tree decomposition (`types` / `bridge` /
`node` / `replay` / `scenario`) rather than reviving the old monolithic
adapter.

## Build system

stellar-core uses **autotools**, not CMake.

Key files:
- `configure.ac` — compiler flags, `--enable-*` options, `AC_SUBST` exports
- `src/Makefile.am` — source lists, binary targets, link flags
- `make-mks` — generates `src/src.mk` from git-tracked files; classifies
  sources into `SRC_CXX_FILES`, `SRC_TEST_CXX_FILES`, etc.
- `common.mk` — shared `AM_CPPFLAGS` and `AM_CXXFLAGS`

The project is **C++20** (`AX_CXX_COMPILE_STDCXX(20, noext, mandatory)` in
configure.ac bakes `-std=c++20` into `CXX`), which is the standard DPOR
requires anyway. DPOR targets still carry their own flags via `DPOR_CXXFLAGS`,
defaulting to `-std=c++20 -DFMT_CONSTEVAL= -DSTELLAR_DISABLE_LOGGING`. The
`-std=c++20` is now redundant with the baseline but harmless.

The DPOR build targets **post-CAP-0083 (empty-tx-set) `stellar-core`**, which
since upstream's "Ungate CAP-0083 and CAP-0085, bump to protocol 28" (#5397) is
just plain `master`. `CAP_0083` no longer exists as an automake conditional or
a preprocessor define and empty-tx-set support is unconditional, so
`--enable-dpor` **no longer requires**
`--enable-next-protocol-version-unsafe-for-production`. That flag remains the
whole-build next-protocol switch: among other effects, it defines
`ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION`, advances
`Config::CURRENT_LEDGER_PROTOCOL_VERSION`, and enables Soroban `next` features.
Those effects are orthogonal to DPOR's empty-tx-set build contract.

The rule that flag existed to enforce still applies to any future protocol
define that alters the `SCPDriver` vtable: it must stay global in
`AM_CPPFLAGS` and never become a DPOR-target-only flag, because the DPOR
binaries link non-DPOR objects from the normal build, so a DPOR-only define
would silently corrupt the vtable rather than fail to build. Toggling such a
flag needs a clean rebuild (`make clean` first). See
[docs/dpor-build.md](docs/dpor-build.md) and
[docs/dpor-integration-status.md](docs/dpor-integration-status.md) for details.

Always configure with `--enable-nsc-sccache` — see
[Compiler cache](#compiler-cache-always-use---enable-nsc-sccache) below.

Normal build:
```bash
git submodule update --init --recursive
./autogen.sh
./configure --enable-nsc-sccache CC=clang-20 CXX=clang++-20
make -j"$(nproc)"
```

Tests are compiled into the main `stellar-core` binary and run via
`./src/stellar-core test`. DPOR code must NOT be compiled into this binary.

Current DPOR build workflow:
```bash
git submodule update --init --recursive
./autogen.sh
./configure --enable-dpor --enable-nsc-sccache CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

Notes:
- Tests are enabled by default, but DPOR still currently depends on
  `BUILD_TESTS`; `--disable-tests --enable-dpor` is not supported.
- On a clean tree, build `lib/` before the DPOR binaries. `make -C src ...`
  alone can fail because required library artifacts and generated headers have
  not been built yet.
- The practical DPOR build entry point is `make -C src ...`, not a repo-root
  `make stellar-core-dpor-tests` or `make src/stellar-core-dpor-tests`.
- After the initial `make -C lib ...`, incremental rebuilds can use
  `make -C src ...` directly.
- Useful verification commands:
  - `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"`
  - `./src/scp-dpor-investigation --depth 12`
  - `./src/scp-dpor-investigation --fail-on-first-terminal --trace-dir "$PWD/dpor-traces" --depth 12`
  - `./src/scp-dpor-investigation --replay-trace-json PATH --replay-node N|all`
- `--fail-on-first-blocked` / `--fail-on-first-terminal` exit nonzero both when
  they capture a matching execution and when they find none, so an exit code of
  0 from them is never a silent "nothing to see". The blocked variant needs a
  depth deep enough to reach a blocking receive: for `--stop-on-prepare
  --txset-status always-downloading --download-time above` that is `--depth 18`,
  not 12.

### Benchmarking

**On `pop-os-desktop` only** (check `hostname`): that machine is a shared
desktop with unrelated work running on it, so exploration-throughput numbers
move around a lot between runs of the *same* binary. There, treat any difference
below **20%** as noise — do not report a sub-20% change as a speedup or a
regression, and do not go hunting for the cause of one. Sustained multi-hour
benchmarking sessions on it have produced 10%+ spreads on identical binaries with
no thermal throttling and no visible competing process. On dedicated or otherwise
quiet hardware, establish the noise floor by measuring one binary several times
before trusting any threshold.

`src/scp/test/bench-dpor.sh` drives all of this and is runnable from any
directory (set `BIN` for an out-of-tree binary). It exits nonzero if any
scenario process fails, so its output can be trusted rather than silently
degrading:
- `bench-dpor.sh check` prints exact execution counts for 13 scenarios — the
  correctness fingerprint. Diff it against a known-good capture.
- `bench-dpor.sh bench` times four terminating scenarios, best of three.
- `bench-dpor.sh head` reports the rate for the externalize-boundary scenario
  over a time-boxed window.

Regardless of machine:
- To claim a real change, measure old and new **back to back in the same
  session** and take a median of several runs. A ratio built against a baseline
  measured hours earlier is not trustworthy.
- Prefer terminating scenarios (fixed total work, so wall-clock is directly
  comparable) over time-boxed rate windows when the size of an effect matters.
- Correctness fingerprints are a different matter: exact execution counts must
  match exactly, with no tolerance. `--workers N` runs report approximate counts
  in `--print-stats` progress lines (`counts_exact=false`) but the final summary
  line is exact.

### Compiler cache: always use `--enable-nsc-sccache`

Pass `--enable-nsc-sccache` to every `configure` invocation, normal and DPOR,
in-tree and out-of-tree. The DPOR binaries link the whole test suite, so a cold
rebuild is expensive and the shared cache is what makes iteration practical.

What the flag does (`configure.ac`, `AC_ARG_ENABLE([nsc-sccache])`):
- runs `nsc cache sccache setup --cache_name stellar` and evals the result into
  configure's environment, which exports `SCCACHE_WEBDAV_ENDPOINT`,
  `SCCACHE_WEBDAV_KEY_PREFIX` and `SCCACHE_WEBDAV_TOKEN` so the sccache daemon
  it starts inherits the remote-cache credentials;
- implies `--enable-sccache`, which wraps `CC`/`CXX` and sets `RUSTC_WRAPPER`;
- sets `SCCACHE_BASEDIRS` so absolute paths in the source and build trees are
  normalized. That is what lets separate worktrees and out-of-tree build
  directories share cache entries instead of each missing.

Requirements and constraints:
- `nsc` must be on `PATH`; configure hard-errors with
  `--enable-nsc-sccache requested but nsc was not found` otherwise.
- Mutually exclusive with `--enable-ccache`; configure errors if both are given.
- The flag only takes effect at configure time. An existing build directory
  configured without it keeps compiling uncached — re-run `configure`.

Verify it actually took effect before trusting build times:
```bash
grep -m1 '^CXX = ' src/Makefile        # expect: sccache clang++-20 ...
grep -m1 '^RUSTC_WRAPPER' src/Makefile # expect: sccache
sccache --show-stats | head            # compile requests / hit rate
```

## DPOR dependency

Upstream: `https://github.com/nano-o/CPP-DPOR.git` (branch `main`)

DPOR is header-only C++20 and pinned as the `external/dpor` submodule at
commit `23e1998`. Initialize the revision selected by `stellar-core` before
configuring:
```bash
git submodule update --init external/dpor
```

The configure integration looks for it there by default. Use
`--with-dpor-dir=PATH` only when intentionally testing another checkout.

The 2PC timeout example at `external/dpor/examples/two_phase_commit_timeout/`
(once initialized) is the reference pattern for the types / bridge / scenario
split.
Key files in that example:
- `sim/dpor_types.hpp` — value type + DPOR aliases
- `sim/bridge.hpp` — encode/decode between domain objects and DPOR values
- `sim/crash_before_decision.hpp` — scenario: Options, ReplayState, Environment,
  thread functions, `make_program()`

## SCP code orientation

SCP implementation:
- `src/scp/SCP.h` / `src/scp/SCP.cpp` — top-level SCP class
- `src/scp/SCPDriver.h` — virtual driver interface (the seam DPOR hooks into)
- `src/scp/Slot.h` / `src/scp/Slot.cpp` — per-slot state machine
- `src/scp/NominationProtocol.h/.cpp` — nomination sub-protocol
- `src/scp/BallotProtocol.h/.cpp` — ballot sub-protocol

Existing SCP tests:
- `src/scp/test/SCPTests.cpp` — main SCP test file with `TestSCP` driver

DPOR harness files go in `src/scp/test/`, but must be excluded from
`SRC_TEST_CXX_FILES` via `make-mks`. This includes both the historical
`Dpor*` / `SCPDpor*` names and the newer `ScpDpor*` files used by the current
integration.

## Current priorities

1. Keep the build island isolated: no DPOR code in `stellar-core`, no DPOR
   routing through `stellar-core test`, and no leakage of DPOR flags into
   global build settings.
2. Improve performance: pay attention to compile surface, relink behavior,
   exploration depth/cost tradeoffs, and investigation-runner throughput.
3. Expand scenario coverage: use the existing `types` / `bridge` / `node` /
   `replay` / `scenario` split to add and exercise more SCP behaviors.
4. Strengthen validation: keep smoke tests and manual investigation flows in
   sync with the current integration, and verify emitted compile/link commands
   when build wiring changes.
5. Keep production SCP hooks minimal. Add new testability hooks only when the
   replay/scenario work cannot be expressed cleanly with the existing seams.
6. Keep [docs/dpor-integration-status.md](docs/dpor-integration-status.md)
   aligned with reality when the DPOR build shape, runtime surface, or verified
   behavior changes.

## Container environment

Build and enter the dev container:
```bash
dev-container/build-image.sh
dev-container/run-container.sh
```

Inside the container:
- Working directory: `/home/dev/stellar-core`
- Compiler: `clang++-20` (default), `g++-14` (alternative)
- User: `dev` (non-root, UID/GID matched to host)
- DPOR dependency: the pinned `external/dpor` submodule

### Out-of-tree builds in containers

When running inside a container (i.e. `/home/dev/stellar-core` is the source
directory), prefer **out-of-tree builds** to keep the source tree clean and
avoid polluting the bind-mounted volume with build artifacts. If the directory
`/home/dev/stellar-core-build/` exists, use it as the build directory.

Out-of-tree normal build:
```bash
cd /home/dev/stellar-core-build
/home/dev/stellar-core/configure --enable-nsc-sccache CC=clang-20 CXX=clang++-20
make -j"$(nproc)"
```

Out-of-tree DPOR build:
```bash
cd /home/dev/stellar-core-build
/home/dev/stellar-core/configure --enable-dpor --enable-nsc-sccache \
    CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

Detection: check whether `/home/dev/stellar-core-build/` exists before
building. If it does, `cd` into it and invoke `configure` via its absolute
source-tree path. If it does not exist, fall back to an in-tree build as
documented above. Run `autogen.sh` from the source tree before the first
configure in either case. As with in-tree builds, a clean DPOR build should
run `make -C lib ...` before `make -C src ...`; incremental rebuilds can then
use `make -C src ...` alone.

## Git notes

- This repo may have `commit.gpgsign=true` in `.git/config`, but the local
  SSH signing agent is not always available in this workspace.
- When making local commits here, disable signing for the commit command:
  `git -c commit.gpgsign=false commit ...`

## Style and conventions

- Follow existing stellar-core coding style (look at surrounding code)
- No new documentation files unless explicitly requested
- DPOR test files use Catch v2 (vendored at `lib/catch.hpp`)
- DPOR code should confine `#include <dpor/...>` to the support layer;
  scenario and test files should include through the local bridge/types headers
- Header-only DPOR scenario files (`.h`) are acceptable, following the 2PC
  example pattern
- Keep changes to production SCP headers minimal; prefer `friend` declarations
  over making members public

## Key constraints

- Do not add DPOR sources to `stellar_core_SOURCES`
- Do not add DPOR binaries to `noinst_PROGRAMS` or automake `TESTS`
- Do not route DPOR tests through `stellar-core test`
- Do not add `$(DPOR_CPPFLAGS)` to global `AM_CPPFLAGS`
- Use `EXTRA_PROGRAMS` for strict build-avoidance
- The `ScpDporValue` type must provide `operator==`, `operator<`, and
  `std::hash`; it carries payload only (slot + envelope/choice), not
  routing metadata
