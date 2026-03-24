# AGENTS.md

## Project

`stellar-core` — the C++ implementation of the Stellar Consensus Protocol (SCP)
and the ledger-closing pipeline for the Stellar network.

## Current work

Branch: `skip-ledgers-p25-dpor-2`

Goal: integrate the DPOR (Dynamic Partial Order Reduction) model checker as an
opt-in, test-only build island for SCP. The full plan is in
[docs/dpor-integration-plan.md](docs/dpor-integration-plan.md). Read it before
starting implementation work.

Previous attempt: branch `dpor-skip-ledgers-p25` (accessible via
`git log dpor-skip-ledgers-p25` in this repo). That branch has 64 commits of
working DPOR/SCP integration code. Use it as a reference for what worked, but
follow the new plan's decomposition (types / bridge / scenario), not the old
monolithic adapter.

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
per-target `_CXXFLAGS = -std=c++20 -DFMT_CONSTEVAL=` to override the baseline.
The `-DFMT_CONSTEVAL=` workaround is required because the vendored fmt version
misuses `consteval` under C++20.

Normal build:
```bash
git submodule update --init --recursive
./autogen.sh
./configure --enable-tests CC=clang-20 CXX=clang++-20
make -j"$(nproc)"
```

Tests are compiled into the main `stellar-core` binary and run via
`./src/stellar-core test`. DPOR code must NOT be compiled into this binary.

## DPOR dependency

Upstream: `https://github.com/nano-o/CPP-DPOR.git` (branch `main`)

DPOR is header-only C++20. Clone it before configuring:
```bash
git clone https://github.com/nano-o/CPP-DPOR.git external/dpor
```

`external/dpor` is gitignored. The plan's configure integration will look for
it there by default.

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

DPOR harness files go in `src/scp/test/` with `Dpor*` or `SCPDpor*` prefixes,
but must be excluded from `SRC_TEST_CXX_FILES` via `make-mks`.

## Implementation order (from the plan)

1. `configure.ac`: add `--enable-dpor`, `--with-dpor-dir`, `DPOR_CPPFLAGS`,
   `DPOR_CXXFLAGS`, `ENABLE_DPOR` conditional, compile probe
2. `make-mks`: carve `Dpor*` and `SCPDpor*` files out of `SRC_TEST_*`
3. `src/Makefile.am`: add convenience library with target-local C++20 flags
4. `src/Makefile.am`: add `EXTRA_PROGRAMS` for test binary and investigation
   runner behind `ENABLE_DPOR`
5. `ScpDporTypes.h`, `ScpDporBridge.h` — value type and encoding layer
6. `DporScpNode.h/.cpp`, `ScpDporReplaySupport.h/.cpp` — deterministic SCP
   driver + DPOR-facing replay support
7. `ScpDporThreeNodePrepareBoundaryScenario.h` — first scenario
8. `SCPDporSmokeTests.cpp`, `DporScpInvestigationMain.cpp` — test + runner
9. Verify emitted compile/link commands
10. Expand replay model; add SCP-header testability hooks only if needed

Create stub files for steps 1-4 in parallel with steps 5-6, since the build
skeleton needs at least one real source file to validate against.

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
