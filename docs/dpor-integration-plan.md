# DPOR Build Integration Plan

## Scope

This note describes a minimal build-system integration for experimenting with
the `../dpor` model checker in `stellar-core`.

The goal is to make it possible to build and run DPOR-based smoke tests and
manual experiments for SCP, nomination, and balloting without changing the
normal test pipeline.

Non-goals for this phase:

- no integration with `make check`
- no addition to automake `TESTS`
- no requirement that CI or routine developer workflows build or run DPOR code
- no commitment yet to the detailed design of the SCP/nomination/balloting
  driver itself

## Constraints From The Current Build

`stellar-core` is currently built with autotools, not CMake:

- [configure.ac](/home/nano/code/stellar-core/configure.ac)
- [Makefile.am](/home/nano/code/stellar-core/Makefile.am)
- [src/Makefile.am](/home/nano/code/stellar-core/src/Makefile.am)
- [make-mks](/home/nano/code/stellar-core/make-mks)

Important consequences:

- Existing test sources are compiled into the main `stellar-core` binary when
  `BUILD_TESTS` is enabled.
- `../dpor` is a header-only C++20 library.
- `stellar-core` is still a C++17 project, and the current configure flow bakes
  `-std=c++17` into `CXX`.

Because of this, DPOR code should not be mixed into the existing
`stellar-core` test target. It should live in a separate executable with
target-local include paths and target-local C++20 flags.

## Proposed Integration

### 1. Add An Optional Configure Flag

In [configure.ac](/home/nano/code/stellar-core/configure.ac):

- add `--enable-dpor`, default `no`
- make it valid only when tests are enabled
- add `--with-dpor-dir=PATH`, defaulting to `../dpor`
- export:
  - `DPOR_DIR`
  - `DPOR_CPPFLAGS`
  - automake conditional `ENABLE_DPOR`

Configure-time checks should verify:

- the DPOR include tree exists under `$(DPOR_DIR)/include`
- a tiny translation unit including `dpor/algo/dpor.hpp` compiles with C++20

This keeps failure early and explicit.

### 2. Keep DPOR Sources Out Of The Main Test Source Bucket

In [make-mks](/home/nano/code/stellar-core/make-mks), split
`src/test/dpor/**` into separate variables instead of letting those files fall
into `SRC_TEST_CXX_FILES` and `SRC_TEST_H_FILES`.

Recommended generated variables:

- `SRC_DPOR_CXX_FILES`
- `SRC_DPOR_H_FILES`

and exclude `test/dpor/` from the normal `SRC_TEST_*` buckets.

This is the key isolation step. Without it, any new file under
`src/test/dpor/` would be compiled into the existing `stellar-core` target.

### 3. Build A Separate Experimental Executable

In [src/Makefile.am](/home/nano/code/stellar-core/src/Makefile.am), add a
standalone target built only when `ENABLE_DPOR` is set.

Shape:

- `check_PROGRAMS += stellar-core-dpor-tests`
  or `noinst_PROGRAMS += stellar-core-dpor-tests`
- sources:
  - `$(SRC_DPOR_CXX_FILES)`
  - whichever existing test-only support files the DPOR tests reuse
- include paths:
  - the existing repo include paths from `common.mk`
  - `-I$(DPOR_DIR)/include`
- per-target flags:
  - append `-std=c++20`

This target should be runnable directly by developers and should not be wired
into `TESTS`.

`check_PROGRAMS` is slightly nicer if we want `make check` to build the binary
without running it. `noinst_PROGRAMS` is slightly cleaner if we want even build
avoidance unless explicitly requested. Either is acceptable; the deciding
question is whether merely compiling the DPOR experiment should be part of
normal local `check` builds. For an experiment, `noinst_PROGRAMS` is a
reasonable default.

### 4. Reuse The Existing Catch Harness

The repo already vendors Catch v2 via:

- [lib/catch.hpp](/home/nano/code/stellar-core/lib/catch.hpp)
- [src/test/Catch2.h](/home/nano/code/stellar-core/src/test/Catch2.h)
- [src/test/test.cpp](/home/nano/code/stellar-core/src/test/test.cpp)

The DPOR executable should reuse this test stack rather than adding a second
test framework dependency.

Practical implication:

- give the DPOR executable its own small `main`
- or reuse the existing local Catch support pieces needed for reporters and
  stringification
- but do not try to route DPOR tests through `stellar-core test`

Routing through the `test` subcommand would drag the DPOR code back into the
main binary, which defeats the C++17/C++20 separation.

### 5. Keep Manual And Smoke Runs At The Binary Level

Since this phase explicitly avoids `make check`, the operational model should
be:

- build the DPOR executable explicitly
- run it explicitly with Catch filters

For example:

```bash
make stellar-core-dpor-tests
./src/stellar-core-dpor-tests "[dpor][smoke]"
./src/stellar-core-dpor-tests "[dpor][manual]"
```

The exact binary path may vary slightly depending on how automake emits the
target, but the workflow should stay direct and explicit.

Recommended tag split:

- `[dpor][smoke]` for very small runs that finish quickly
- `[dpor][manual]` or hidden `[.]` tags for expensive exploration

This preserves a clear distinction between "safe to try quickly" and
"developer-invoked experiment".

## Likely Source Layout

Recommended new directory:

- `src/test/dpor/`

Possible first files:

- `src/test/dpor/DporMain.cpp`
- `src/test/dpor/ScpDporTypes.h`
- `src/test/dpor/ScpDporBridge.h`
- `src/test/dpor/ScpSmokeTests.cpp`

The exact names can change, but the build should assume a dedicated subtree for
DPOR-only code.

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

- the first DPOR harness should probably extract or duplicate only the minimal
  deterministic SCP-driver support it needs
- it should not depend on `SCPTests.cpp` as if it were a reusable module

### A Larger Refactor May Become Desirable Later

If the DPOR harness eventually needs to link a broad slice of core code without
linking the full `stellar-core` binary, a later cleanup may be warranted:

- factor common non-main C++ sources into a convenience library
- link both `stellar-core` and `stellar-core-dpor-tests` against that library

That refactor does not need to happen for the initial build-system experiment,
but it is the obvious escape hatch if source duplication becomes too painful.

## Main Risks

### C++ Standard Override

The current build embeds `-std=c++17` in `CXX`, not just in `CXXFLAGS`.

Risk:

- per-target `..._CXXFLAGS = -std=c++20` may or may not override cleanly,
  depending on final argument ordering and compiler behavior

Mitigation:

- verify the emitted compile command for the new DPOR target
- if needed, use a dedicated compile rule or dedicated compiler variable for
  the DPOR executable

### Source Classification Drift

Because [make-mks](/home/nano/code/stellar-core/make-mks) auto-generates
[src/src.mk](/home/nano/code/stellar-core/src/src.mk), the DPOR subtree must be
explicitly carved out there. Otherwise future files added under `src/test/dpor`
will silently get absorbed into the normal test build.

### Accidental Workflow Expansion

Even a build-only hook into routine targets can make an experiment feel more
official than intended.

Mitigation:

- do not add DPOR binaries to automake `TESTS`
- do not add selftest wrapper scripts
- prefer explicit developer invocation

## Recommended Implementation Order

1. Add `--enable-dpor` and `--with-dpor-dir` in configure.
2. Update `make-mks` to emit `SRC_DPOR_*` and exclude `src/test/dpor/` from
   ordinary test buckets.
3. Add the standalone DPOR executable in `src/Makefile.am`.
4. Add one trivial smoke test file under `src/test/dpor/` to prove the build
   works.
5. Only after that, start iterating on the real SCP/nomination/balloting
   harness design.

## Summary

The right first step is not to integrate DPOR into the existing test runner.
It is to add a strictly optional, separately-built experimental executable that:

- is enabled only with `--enable-dpor`
- consumes `../dpor` through an explicit path option
- compiles only its own DPOR subtree with C++20
- is run manually by developers

That gets the build-system boundary right before any protocol-modeling work
starts.
