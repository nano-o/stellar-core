# Post-CAP-0083 DPOR Scenario Update Plan

## Goal

Update the SCP DPOR model, investigation surface, replay artifacts, and smoke
tests to model post-CAP-0083 empty-tx-set behavior faithfully.

The implementation must exercise and distinguish:

1. A value that is structurally valid but whose transaction set is still
   downloading or has been downloaded and found invalid. This value remains
   eligible for CAP-0083 empty-tx-set replacement.
2. A value that is outright invalid for a non-txset reason, such as malformed
   encoding, an invalid close time or signature, invalid upgrades, or invalid
   empty-tx-set context. SCP must reject this value without trying
   empty-tx-set replacement.

Keep the work inside the existing DPOR build island. No new production SCP
hooks should be necessary.

## Model Semantics

Model transaction-set state independently from outright value validity.

### Transaction-set state

Rename or reinterpret `DporScpTxSetStatus` so that it represents:

```cpp
enum class DporScpTxSetStatus
{
    Valid,
    Downloading,
    Invalid
};
```

The intended behavior is:

| Txset state | `validateValue()` | `getTxSetDownloadWaitTime()` | Ballot behavior |
| --- | --- | --- | --- |
| `Valid` | `kFullyValidatedValue` | `nullopt` | Continue with the original value |
| `Downloading` | `kStructurallyValidValue` | Below or above timeout | Keep waiting or replace after timeout |
| `Invalid` | `kStructurallyValidValue` | `nullopt` | Replace immediately with an empty-tx-set value |

`Downloading` is unresolved and may later become either `Valid` or `Invalid`.
`Valid` and `Invalid` are terminal per node/value and must remain latched
across later validation calls and replay restoration.

The current `Invalid -> kInvalidValue` mapping must be removed. A downloaded
invalid txset is structurally valid in the post-CAP-0083 protocol.

### Outright value invalidity

Outright invalidity must not be another txset status. Configure it
deterministically per node/value, for example with:

```cpp
std::map<NodeID, std::set<Value>> mOutrightInvalidValuesByNode;
```

Outright validity should not be a DPOR nondeterministic choice. Properties
such as encoding, close time, and signatures are intrinsic to the payload;
allowing them to change between validation calls would create impossible
executions.

The node validation order should be:

1. If the value is configured as outright invalid, return `kInvalidValue`.
2. If the value is an empty-tx-set value:
   - return `kInvalidValue` during nomination;
   - return `kFullyValidatedValue` during balloting.
3. Otherwise apply the configured transaction-set state.

This ordering also permits a malformed empty-tx-set value to be configured as
outright invalid.

## Implementation Steps

### 1. Correct the txset status implementation

Update:

- `src/scp/test/DporScpNode.h`
- `src/scp/test/DporScpNode.cpp`
- `src/scp/test/ScpDporBridge.h`

Changes:

- Rename `Waiting` to `Downloading` internally.
- Change the validation mapping for `Invalid` to
  `kStructurallyValidValue`.
- Keep wait-time eligibility only for `Downloading`.
- Ensure `Invalid` clears pending wait-time eligibility, so
  `getTxSetDownloadWaitTime()` returns `nullopt`.
- Keep status history keyed by `Value`.
- Rebranch only while the last status is `Downloading`.
- Latch both `Valid` and `Invalid`.
- Update diagnostic formatting and error messages to use `downloading`.

The investigation CLI should accept only `downloading` for this status.

### 2. Add deterministic outright-invalid values to `DporScpNode`

Add per-node outright-invalid value configuration to
`DporScpNode::Configuration`.

During `applyConfiguration()`, extract the current node's invalid-value set
into node-local immutable configuration. Add a helper such as:

```cpp
bool isOutrightInvalidValue(Value const& value) const;
```

Check this before empty-tx-set handling and txset-status handling in
`validateValue()`.

Outright-invalid validation must not:

- consume a txset-status choice;
- create txset download wait-time eligibility;
- mutate txset state;
- be treated as replaceable by CAP-0083.

### 3. Correct empty-tx-set validation

Update `DporScpNode::validateValue()` so a well-formed test empty-tx-set value
is:

- invalid during nomination;
- fully valid during balloting.

Retain the existing `EMPTY:` test encoding and derivation. Empty values remain
ordinary SCP envelope payloads, so do not add a new `ScpDporValue::Kind`.

### 4. Make download success per-value

Replace the node-wide `mTxSetDownloadSucceeded` boolean with per-value state,
for example:

```cpp
std::set<Value> mTxSetDownloadsSucceeded;
```

Update:

- `validateValue()`;
- `getTxSetDownloadWaitTime()`;
- replay snapshots and restore;
- replay reset;
- the `download-succeeds-in-round` implementation.

When a configured-round `PREPARE` is emitted:

- mark only that ballot value as downloaded;
- do nothing if the emitted ballot value is already an empty-tx-set value;
- clear status and wait-time history only for the resolved value;
- do not clear choices or state for unrelated values.

If deterministic wait-time sequencing can leak between values, replace the
global wait-time call count with per-value counts and include them in replay
baselines.

### 5. Extend default scenario options

Update:

- `src/scp/test/ScpDporDefaultScenario.h`
- `src/scp/test/DporScpInvestigationMain.cpp`

Add a serializable per-node invalid-value collection to
`ScpDporDefaultScenario::Options`, aligned with the validator list, such as:

```cpp
std::vector<std::vector<Value>> mOutrightInvalidValuesByNode;
```

Rules:

- An empty outer vector means no outright-invalid values.
- Otherwise the outer size must equal the validator count.
- Reject malformed sizes and duplicate entries.
- Convert node indices to `NodeID` entries in `buildNodeConfiguration()`.

Add an investigation preset:

```text
--invalid-proposer N
```

Semantics:

- Require unique initial values.
- Every node except proposer `N` treats proposer `N`'s initial value as
  outright invalid.
- Proposer `N` still treats its own value as valid, allowing the scenario to
  model an adversarial proposer emitting a value that honest peers reject.
- Persist the expanded per-node mapping in trace JSON so replay does not
  depend on reconstructing the CLI preset.

### 6. Update txset scenario modes

Update `ScpDporDefaultScenario::TxSetStatusMode` and its configuration mapping:

- `valid`: explore `Downloading -> Valid`;
- `downloading`: stay `Downloading`;
- `invalid`: explore `Downloading -> Invalid`;
- `nondet`: explore `Downloading`, `Valid`, and `Invalid`.

The `invalid` mode now means an eventually downloaded-invalid txset, not an
outright invalid SCP value.

Update CLI help and documentation to make this distinction explicit.

### 7. Remove the pre-protocol behavior from normal scenarios

Remove `mProtocolAllowsEmptyTxSetValues` as a normal scenario option. A normal
post-CAP-0083 DPOR node should always return `true` from
`protocolAllowsEmptyTxSetValues()`.

The existing error-capture tests still require a reproducible SCP assertion.
Replace the misleading protocol option with an explicitly named test-only
fault injection, for example:

```cpp
bool mInjectEmptyTxSetProtocolGateFailureForTesting{false};
```

Requirements:

- Default to `false`.
- Do not expose it as a normal investigation CLI option.
- Serialize it in the new trace schema so captured error executions remain
  replayable.
- Use it only in error-capture smoke fixtures.
- Document that it intentionally violates the post-CAP driver contract.

Do not use outright-invalid values as the error source. SCP is expected to
reject them normally, not throw.

### 8. Version replay artifacts

Update:

- `src/scp/test/ScpDporTraceJson.h`
- `src/scp/test/ScpDporTraceJson.cpp`
- `src/scp/test/ScpDporReplaySupport.h`
- `src/scp/test/ScpDporReplaySupport.cpp`, if state shape requires it

Changing the meaning of `"invalid"` makes version-1 traces semantically
incompatible. Bump trace bundles to version 2.

Version-2 changes:

- Canonical txset status strings:
  - `valid`
  - `downloading`
  - `invalid`
- Serialize per-node outright-invalid value lists using the existing value
  byte/base64 representation.
- Rename the protocol flag to the explicit test fault-injection field.
- Validate the per-node list size and contents at load time.
- Check the bundle version before parsing version-dependent scenario
  semantics.
- Reject version-1 bundles with a direct error explaining that pre-CAP txset
  status traces are incompatible.

Do not silently reinterpret version-1 `"invalid"` observations.

### 9. Update replay baselines

Replay baselines must preserve:

- resolved per-value txset status;
- pending per-value download eligibility;
- per-value wait-time history;
- per-value successful downloads;
- per-value wait-time call counts, if introduced;
- empty-tx-set boundary and emitted-envelope state.

Outright-invalid sets are immutable configuration and do not need to be
snapshotted, but loaded trace options must reconstruct them identically.

## Smoke-Test Work

Update `src/scp/test/SCPDporSmokeTests.cpp`.

### Low-level txset tests

Revise existing tests so:

- resolved `Invalid` expects `kStructurallyValidValue`;
- resolved `Invalid` remains latched;
- `getTxSetDownloadWaitTime()` returns `nullopt` for resolved `Invalid`;
- snapshot/restore preserves resolved-invalid state;
- `Downloading` continues to rebranch until resolution;
- `Valid` and `Invalid` stop further status choices;
- wait-time choices are consumed only for `Downloading`.

### Validation precedence tests

Add tests for:

- outright-invalid value with a valid txset -> `kInvalidValue`;
- outright-invalid value with a downloading txset -> `kInvalidValue`;
- outright-invalid value with an invalid txset -> `kInvalidValue`;
- otherwise-valid value with invalid txset ->
  `kStructurallyValidValue`;
- empty value during balloting -> `kFullyValidatedValue`;
- empty value during nomination -> `kInvalidValue`.

The outright-invalid cases must not consume hidden DPOR choices.

### Direct SCP replacement tests

Add focused tests for:

1. Downloading below timeout:
   - emitted `PREPARE` contains the original value;
   - the wait-time hook was consulted.

2. Downloading above timeout:
   - emitted `PREPARE` contains
     `makeEmptyTxSetValueFromValue(original)`;
   - the above-threshold wait time is visible in replay diagnostics.

3. Downloaded-invalid txset:
   - validation is structurally valid;
   - wait time is `nullopt`;
   - emitted `PREPARE` contains the derived empty value;
   - no wait-time choice or wait-time side effect occurs.

### Outright-invalid SCP tests

Add tests in which a node receives:

- a `NOMINATE` containing an outright-invalid value;
- a `PREPARE` whose ballot value is outright invalid;
- a `PREPARE` whose prepared value is outright invalid, where applicable.

Assert:

- the envelope is rejected;
- no local envelope is emitted because of it;
- the invalid value is not made replaceable;
- no `"moved to a bad state (ballot protocol)"` error occurs.

### Bounded DPOR exploration tests

Add bounded exploration tests that stop as soon as they witness:

- an empty `PREPARE` caused by download timeout;
- an empty `PREPARE` caused by a downloaded-invalid txset;
- no wait-time observation on the downloaded-invalid path;
- rejection of an outright-invalid proposer value;
- agreement among any nodes observed externalizing an empty value.

Also run a bounded nondeterministic txset scenario and assert it produces no
error executions.

Avoid exhaustive deep sweeps in the smoke suite. Prefer:

- FIFO where it removes irrelevant schedules;
- callbacks that stop once the property is witnessed;
- prepare boundaries for replacement checks;
- direct-envelope SCP tests for deeper empty-value lifecycle behavior if full
  DPOR externalization is too expensive.

### Error and JSON tests

Update the current error-capture tests to use the explicit fault-injection
fixture rather than a normal pre-protocol scenario.

Retain coverage for:

- wrapping thread exceptions as DPOR error executions;
- preserving replay lead-in to an SCP assertion;
- writing and loading an error trace;
- replaying the same error from loaded options;
- file-and-line context from assert-throw mode.

Update JSON round-trip tests to include:

- `Downloading`;
- downloaded-invalid status;
- per-node outright-invalid mappings;
- the renamed fault-injection option;
- trace bundle version 2.

Add replay assertions that:

- downloaded-invalid remains structurally valid after restore;
- no wait-time choice appears for it;
- replay regenerates the same empty ballot;
- outright-invalid peer values are rejected identically after reload;
- version-1 traces fail with the intended compatibility error.

## Build-Contract Hardening

Update `configure.ac` after parsing the next-protocol option.

Reject `--enable-dpor` unless
`--enable-next-protocol-version-unsafe-for-production` is active.

Keep `CAP_0083` global through `AM_CPPFLAGS`. Do not add `-DCAP_0083` to
`DPOR_CXXFLAGS`, and do not change the existing build-island source routing.

Test the negative configure case in a disposable out-of-tree build directory
so the working build is not disturbed.

## Validation Sequence

### Incremental build

Use the existing configured build directory according to `AGENTS.md`.

```bash
make -C src -j"$(nproc)" \
  stellar-core-dpor-tests scp-dpor-investigation
```

### Smoke suite

```bash
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"
```

### Focused investigation cases

Downloaded-invalid txset:

```bash
./src/scp-dpor-investigation \
  --txset-status invalid \
  --stop-on-prepare \
  --depth 12
```

Download timeout:

```bash
./src/scp-dpor-investigation \
  --txset-status downloading \
  --download-time above \
  --stop-on-prepare \
  --depth 12
```

Still downloading below timeout:

```bash
./src/scp-dpor-investigation \
  --txset-status downloading \
  --download-time below \
  --depth 12
```

Outright-invalid proposer:

```bash
./src/scp-dpor-investigation \
  --init unique \
  --invalid-proposer 0 \
  --depth 12
```

Nondeterministic txset behavior:

```bash
./src/scp-dpor-investigation \
  --txset-status nondet \
  --download-time nondet \
  --depth 12
```

Repeat the nondeterministic case with:

```bash
--parallel --workers 4
```

and compare terminal counts with the sequential run.

### Trace capture and replay

Capture a version-2 trace that includes either downloaded-invalid replacement
or an outright-invalid proposer, then replay it with:

```bash
./src/scp-dpor-investigation \
  --replay-trace-json PATH \
  --replay-node all
```

Also verify that a version-1 fixture is rejected with the intended
compatibility message.

### Configure guard

In a disposable out-of-tree directory:

- verify `--enable-dpor` without the next-protocol option fails;
- verify the documented post-CAP invocation succeeds.

## Documentation Updates

Update existing documents only:

- `docs/dpor-integration-status.md`
  - remove the pre-CAP scenario limitation;
  - describe txset invalidity versus outright invalidity;
  - document both empty-tx-set replacement routes;
  - update the runtime surface;
  - refresh smoke assertion/test counts and verified investigation counts.

- `docs/dpor-replay-notes.md`
  - document trace version 2;
  - explain version-1 rejection;
  - describe deterministic per-node outright-invalid mappings;
  - update baseline-state documentation.

- `docs/dpor-build.md`
  - document the configure-time enforcement of the post-CAP option
    combination.

Do not add further documentation files.

## Recommended Implementation Order

1. Correct node validation semantics and make download resolution per-value.
2. Add direct low-level and SCP behavior tests for the two invalidity classes.
3. Add scenario-level per-node outright-invalid values and the investigation
   preset.
4. Update CLI names and scenario mode descriptions.
5. Update replay state and implement trace version 2.
6. Refactor the error-capture fixture.
7. Add bounded DPOR exploration tests.
8. Add the configure guard.
9. Build, run all validation cases, and update existing documentation with
   measured results.

## Acceptance Criteria

The work is complete when:

- a downloaded-invalid txset validates as structurally valid;
- that state returns no download wait time and produces an empty-tx-set
  ballot;
- a downloading txset below timeout retains the original ballot value;
- a downloading txset at or above timeout produces an empty-tx-set ballot;
- an outright-invalid value returns `kInvalidValue` and is rejected without
  replacement;
- empty-tx-set values are valid only on the ballot path;
- download-success state is isolated per value;
- replay reproduces all of the above;
- version-1 traces are rejected rather than reinterpreted;
- the bounded smoke suite has no unexpected error executions;
- sequential and parallel investigation agree for the checked bounded
  configuration;
- `--enable-dpor` cannot be configured without the required post-CAP build
  flag;
- the main `stellar-core` binary and global non-DPOR build flags remain
  untouched;
- the existing DPOR status, replay, and build documentation matches the
  verified implementation.
