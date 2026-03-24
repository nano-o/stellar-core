# DPOR Build Integration Plan

## Scope

This note describes a minimal, opt-in build integration for experimenting with
the DPOR model checker in `stellar-core`.

The immediate goal is to make it possible to build and run:

- DPOR-based smoke and property tests for SCP
- a separate manual investigation runner for deeper nomination/balloting
  experiments

without changing the normal `stellar-core` binary or the default local build
and test pipeline.

Non-goals for this phase:

- no routing through `src/stellar-core test`
- no addition to automake `TESTS`
- no requirement that CI or routine developer workflows build or run DPOR code
- no commitment yet to the detailed nomination/balloting replay model

## Constraints From The Current Build

`stellar-core` is currently built with autotools, not CMake:

- [configure.ac](/home/nano/code/stellar-core/configure.ac)
- [Makefile.am](/home/nano/code/stellar-core/Makefile.am)
- [src/Makefile.am](/home/nano/code/stellar-core/src/Makefile.am)
- [make-mks](/home/nano/code/stellar-core/make-mks)

Important consequences:

- existing test sources are compiled into the main `stellar-core` binary when
  `BUILD_TESTS` is enabled
- DPOR is a header-only C++20 library
- `stellar-core` is still a C++17 project, and the current configure flow bakes
  `-std=c++17` into `CXX`
- the earlier `dpor-skip-ledgers-p25` integration ended up keeping reusable
  DPOR/SCP harness code under `src/scp/test/`, not in a generic `src/test/dpor`
  subtree
- that earlier branch also needed both Catch-based tests and a dedicated
  command-line investigation runner

Because of this, DPOR code should not be mixed into the existing
`stellar-core` test target. It needs its own build island with target-local
include paths and target-local C++20 flags.

## Proposed Integration

### 1. Add An Optional Configure Gate And DPOR Location

In [configure.ac](/home/nano/code/stellar-core/configure.ac):

- add `--enable-dpor`, default `no`
- make it valid only when tests are enabled
- add `--with-dpor-dir=PATH`
- support both a sibling checkout such as `../dpor` and an in-tree pinned copy
  such as `external/dpor`
- export:
  - `DPOR_DIR`
  - `DPOR_CPPFLAGS`
  - `DPOR_CXXFLAGS`
  - automake conditional `ENABLE_DPOR`

Recommended default behavior:

- if `--with-dpor-dir` is passed, use it
- otherwise prefer `external/dpor` if present
- otherwise fall back to `../dpor`

This keeps local iteration convenient while still leaving room for a pinned,
reproducible in-tree DPOR checkout.

Configure-time checks should verify:

- the DPOR include tree exists under `$(DPOR_DIR)/include`
- a tiny translation unit including `dpor/algo/dpor.hpp` compiles using the
  same flags intended for real DPOR targets

That compile probe should use the actual target-local compatibility flags, not
just plain `-std=c++20`. In practice this may include a workaround such as
`-DFMT_CONSTEVAL=` if the same issue seen in `dpor-skip-ledgers-p25` still
applies.

### 2. Keep DPOR Sources Out Of The Main Test Source Bucket

The first reusable DPOR/SCP harness should live next to the existing SCP tests
under `src/scp/test/`, not in a new generic `src/test/dpor/` subtree.

Rationale:

- the code will sit on SCP-specific seams
- it will likely mirror and borrow patterns from `src/scp/test/SCPTests.cpp`
- the previous integration converged on `src/scp/test/`

In [make-mks](/home/nano/code/stellar-core/make-mks), explicitly carve the DPOR
files out of the normal `SRC_TEST_*` buckets instead of letting them fall into
the main `stellar-core` test binary.

Recommended generated variables:

- `SRC_DPOR_SUPPORT_CXX_FILES`
- `SRC_DPOR_SUPPORT_H_FILES`
- `SRC_DPOR_TEST_CXX_FILES`
- `SRC_DPOR_MAIN_CXX_FILES`

The exact names are flexible. The important point is that the chosen
`src/scp/test/Dpor*` and `src/scp/test/SCPDpor*` files must not remain in
`SRC_TEST_CXX_FILES`.

This is the key isolation step. Without it, any new DPOR harness file under
`src/scp/test/` will silently get compiled into the ordinary `stellar-core`
test target.

### 3. Build Shared DPOR/SCP Support With Target-Local C++20 Flags

In [src/Makefile.am](/home/nano/code/stellar-core/src/Makefile.am), build the
reusable DPOR/SCP support code separately from the main `stellar-core` sources.

That shared support will likely include:

- deterministic SCP driver/node support
- the DPOR replay adapter
- small utility helpers shared by both tests and the investigation runner

The previous branch needed this split immediately, not as a later cleanup.
There are likely to be at least two DPOR-facing binaries that reuse the same
support code.

Acceptable shapes:

- a DPOR-only convenience library, if we are comfortable with
  `--enable-dpor` making `make` build that shared support
- or an equivalent shared source grouping linked only into explicit DPOR
  binaries, if stricter build avoidance is still a requirement

In either case:

- do not add DPOR sources to `stellar_core_SOURCES`
- compile the shared DPOR support with `$(DPOR_CXXFLAGS)`
- keep `$(DPOR_CPPFLAGS)` target-local rather than adding it to all test builds

### 4. Build Two Explicit DPOR Binaries

The build should distinguish between:

- a Catch-based DPOR test binary
- a CLI-style investigation runner for manual exploration

Recommended examples:

- `stellar-core-dpor-tests`
- `scp-dpor-investigation`

The earlier branch shows why both matter:

- Catch tests are good for smoke checks and small `verify(...)` properties
- manual investigation quickly grows CLI needs such as worker count, depth,
  communication model, scenario selection, and property toggles

If the non-goal remains "do not build DPOR code during default `make` or
`make check` flows", prefer explicit build targets such as `EXTRA_PROGRAMS`
plus direct developer invocation.

Important automake detail:

- `noinst_PROGRAMS` are built by `make all`
- `check_PROGRAMS` are built by `make check`

So `noinst_PROGRAMS` is not a build-avoidance mechanism. If we want DPOR to be
strictly explicit, `noinst_PROGRAMS` is the wrong default.

### 5. Reuse Catch For Tests, Not For Manual Investigation

The repo already vendors Catch v2 via:

- [lib/catch.hpp](/home/nano/code/stellar-core/lib/catch.hpp)
- [src/test/Catch2.h](/home/nano/code/stellar-core/src/test/Catch2.h)
- [src/test/test.cpp](/home/nano/code/stellar-core/src/test/test.cpp)

The DPOR test binary should reuse this stack rather than adding a second test
framework dependency.

Practical implication:

- give the DPOR test binary its own small Catch `main`
- reuse existing local Catch support pieces as needed
- do not try to route DPOR tests through `stellar-core test`
- keep the investigation runner as a separate non-Catch executable

Routing DPOR through the existing `test` subcommand would drag the DPOR code
back into the main binary, which defeats the C++17/C++20 separation.

### 6. Keep Manual And Smoke Runs At The Binary Level

The operational model for this phase should be explicit binary invocation.

For example:

```bash
make stellar-core-dpor-tests
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"

make scp-dpor-investigation
./src/scp-dpor-investigation --workers 8 --scenario two-followers --depth 12
```

The exact target names may vary, but the workflow should stay direct.

Recommended split:

- `[scp][dpor][smoke]` for very small Catch-based runs
- `[scp][dpor][property]` for modest `verify(...)` checks
- the investigation binary for deeper scenario-driven or multi-worker searches

## Likely Source Layout

Recommended location:

- `src/scp/test/`

Possible first files:

- `src/scp/test/DporNominationNode.h`
- `src/scp/test/DporNominationNode.cpp`
- `src/scp/test/DporNominationDporAdapter.h`
- `src/scp/test/DporNominationDporAdapter.cpp`
- `src/scp/test/SCPDporSmokeTests.cpp`
- `src/scp/test/SCPDporNominationTests.cpp`
- `src/scp/test/DporNominationInvestigationMain.cpp`

The exact names can change, but the important build assumption is that DPOR
support should live near SCP tests while still being explicitly excluded from
the ordinary test-source buckets.

## Harness Design Considerations That Affect Build Integration

The detailed driver design is out of scope for this phase, but a few points do
matter to the build plan.

### Reuse Existing SCP Test Infrastructure Carefully

There is already substantial SCP test support in
[src/scp/test/SCPTests.cpp](/home/nano/code/stellar-core/src/scp/test/SCPTests.cpp),
including a `TestSCP` driver built on top of:

- [src/scp/SCP.h](/home/nano/code/stellar-core/src/scp/SCP.h)
- [src/scp/SCPDriver.h](/home/nano/code/stellar-core/src/scp/SCPDriver.h)

That code is useful as a reference, but it is not yet packaged as a reusable
library component.

Implication:

- the first DPOR harness should extract or duplicate only the deterministic
  support it actually needs
- it should not depend on `SCPTests.cpp` as if it were already a reusable
  module

### Expect Some Small SCP Testability Hooks

The earlier branch did not stay completely isolated to new files. It ended up
adding a small number of testability hooks such as `friend` declarations in SCP
headers so the replay layer could inspect or snapshot internal state.

Implication:

- prefer avoiding production-path changes
- but do not write the build plan as if zero SCP-header changes are guaranteed
- allow for small, targeted test-only visibility adjustments if the replay
  layer genuinely needs them

### Shared DPOR Support Is Likely Part Of The Initial Shape

If the DPOR harness includes both Catch tests and an investigation runner, a
shared DPOR/SCP support layer is likely part of the first implementation, not a
later refactor.

A broader repo-wide library reorganization can still wait. The immediate goal is
just to avoid duplicating the adapter/node layer across multiple binaries.

## Main Risks

### C++ Standard Override And Flag Mismatch

The current build embeds `-std=c++17` in `CXX`, not just in `CXXFLAGS`.

Risks:

- per-target `..._CXXFLAGS = -std=c++20` may or may not override cleanly
- the configure probe can pass while the real target still fails if the probe
  does not use the exact same compatibility flags

Mitigation:

- verify the emitted compile command for the new DPOR targets
- make the configure probe use the same `DPOR_CXXFLAGS` as the actual target
- if needed, use a dedicated compile rule or dedicated compiler variable for
  DPOR targets

### Source Classification Drift

Because [make-mks](/home/nano/code/stellar-core/make-mks) auto-generates
[src/src.mk](/home/nano/code/stellar-core/src/src.mk), the chosen
`src/scp/test/Dpor*` and `src/scp/test/SCPDpor*` files must be explicitly
carved out there. Otherwise future files will silently get absorbed into the
normal test build.

### Accidental Workflow Expansion

Even a build-only hook into routine targets can make an experiment feel more
official than intended.

Mitigation:

- do not add DPOR binaries to automake `TESTS`
- do not use `noinst_PROGRAMS` if strict build avoidance is desired
- avoid routing the code through `stellar-core test`
- prefer explicit developer invocation

### Multi-Worker Runtime Overhead

The old branch eventually needed runtime support changes around logging because
DPOR worker-heavy runs put unusual pressure on hot paths.

Mitigation:

- treat build integration as phase 0, not the whole effort
- expect follow-on support work if multi-worker investigations are slow or noisy

## Recommended Implementation Order

1. Add `--enable-dpor`, `--with-dpor-dir`, `DPOR_CPPFLAGS`, and
   `DPOR_CXXFLAGS` in configure, and make the compile probe use those exact
   flags.
2. Decide the initial `src/scp/test/Dpor*` and `src/scp/test/SCPDpor*` file
   set, then update `make-mks` to keep those files out of `SRC_TEST_*`.
3. Add the shared DPOR/SCP support build unit in `src/Makefile.am`, compiled
   with target-local C++20 flags.
4. Add an explicit Catch-based DPOR test binary and an explicit investigation
   runner binary behind `ENABLE_DPOR`.
5. Add one trivial smoke test and one trivial investigation mode to prove both
   binary paths work.
6. Inspect the emitted compile and link commands before iterating on the real
   SCP nomination/balloting harness.
7. Only after that, start expanding the replay model, allowing small SCP-header
   testability hooks if they prove necessary.

## Summary

The right first step is not to integrate DPOR into the existing test runner.
It is to add a strictly optional DPOR build island that:

- is enabled only with `--enable-dpor`
- resolves DPOR from either a sibling checkout or a pinned in-tree copy
- keeps reusable DPOR/SCP support under `src/scp/test/` but outside the normal
  `SRC_TEST_*` buckets
- compiles DPOR targets with their own C++20 compatibility flags
- provides two explicit entry points: Catch smoke/property tests and a CLI
  investigation runner
- stays out of `stellar-core test` and out of the default `make` / `make check`
  workflows if we keep the DPOR binaries on explicit automake targets

That gets the build-system boundary right and matches what the earlier
`dpor-skip-ledgers-p25` integration actually converged toward.
