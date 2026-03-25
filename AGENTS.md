# AGENTS.md

## Project

`stellar-core` — the C++ implementation of the Stellar Consensus Protocol (SCP)
and the ledger-closing pipeline for the Stellar network.

## Current work

Branch: `skip-ledgers-p25-dpor-2`

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

The project is **C++17** (`AX_CXX_COMPILE_STDCXX(17)` in configure.ac bakes
`-std=c++17` into `CXX`). DPOR requires **C++20**. DPOR targets must use
per-target flags exported via `DPOR_CXXFLAGS` to override the baseline. Unless
a local build proves otherwise, `DPOR_CXXFLAGS` should include
`-std=c++20 -DFMT_CONSTEVAL=`. The `-DFMT_CONSTEVAL=` workaround is required
because the vendored fmt/spdlog headers are not currently safe under C++20
without it.

Normal build:
```bash
git submodule update --init --recursive
./autogen.sh
./configure CC=clang-20 CXX=clang++-20
make -j"$(nproc)"
```

Tests are compiled into the main `stellar-core` binary and run via
`./src/stellar-core test`. DPOR code must NOT be compiled into this binary.

Current DPOR build workflow:
```bash
git submodule update --init --recursive
git clone https://github.com/nano-o/CPP-DPOR.git external/dpor
./autogen.sh
./configure --enable-dpor CC=clang-20 CXX=clang++-20
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

Notes:
- Tests are enabled by default, but DPOR still currently depends on
  `BUILD_TESTS`; `--disable-tests --enable-dpor` is not supported.
- The practical DPOR build entry point is `make -C src ...`, not a repo-root
  `make stellar-core-dpor-tests`.
- Useful verification commands:
  - `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"`
  - `./src/scp-dpor-investigation --depth 12`

## DPOR dependency

Upstream: `https://github.com/nano-o/CPP-DPOR.git` (branch `main`)

DPOR is header-only C++20. Clone it before configuring:
```bash
git clone https://github.com/nano-o/CPP-DPOR.git external/dpor
```

`external/dpor` is gitignored. The current configure integration looks for it
there by default.

The 2PC timeout example at `external/dpor/examples/two_phase_commit_timeout/`
(once cloned) is the reference pattern for the types / bridge / scenario split.
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
- DPOR clone target: `git clone https://github.com/nano-o/CPP-DPOR.git external/dpor`

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
