# DPOR harness simplification plan

Status: proposed (not started).

Decisions so far:

- 2026-08-07: Phase 6b approved as **v8-only** (option (a)). The owner
  explicitly does not need old bundles readable, so no converter is
  required either — the old reader is simply deleted.

Source: a five-way file review of the DPOR harness (~10,100 lines under
`src/scp/test/`) plus the build wiring, conducted 2026-08-07 on
`dpor-on-master`. The review's verdict: the architecture is right-sized
(types / bridge / node / replay / scenario split, replay cache, per-event
memoization all earn their keep; every CLI flag is live), but roughly
1,300–1,600 lines are removable edge accretion. This plan sequences that
removal into independently verifiable phases, safest first.

## Goals and non-goals

Goals:

- Delete dead/speculative API surface so the class and option surface that
  the planned engineer-facing skill exposes is as small as possible.
- Collapse logic that exists in two or more places into one, especially
  where the copies can drift (enum name tables, replay loops, property
  checkers).
- No capability loss: every documented flag, scenario knob, and verified
  behavior in `docs/dpor-integration-status.md` keeps working.

Non-goals (reviewed and deliberately kept as-is):

- The replay cache (`ReplayCursor`, LRU multi-slot, generation counters) —
  complexity is documented and load-bearing; a simpler design was already
  tried and replaced.
- Per-event `TxSetEventDecision` memoization, wrapped-baseline cache,
  envelope payload with precomputed digest — benchmarked performance
  machinery.
- `ExternalEventScope`'s depth counter (nesting genuinely occurs).
- The strict `require*` context-string parsing style in the trace reader.
- Inconsistent stat key spellings between progress lines and the final
  summary (`full_executions=` vs `full=`) — both are baked into docs and
  `bench-dpor.sh`; unifying breaks documented interfaces for zero gain.
- `mSlotIndex` / `mPreviousValue` scenario options: never varied, but
  threaded everywhere and cheap.

## Verification protocol (every phase)

Each phase is one commit, verified before moving on:

1. Build both binaries:
   `make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation`
   (after `make -C lib` on a clean tree; `--enable-nsc-sccache` configured).
2. Run the full DPOR test binary: `./src/stellar-core-dpor-tests` (not just
   the smoke tag — several phases touch test code itself).
3. Run `src/scp/test/bench-dpor.sh check` and diff the execution-count
   fingerprint against the Phase 0 capture. Counts must match **exactly**
   in every phase, including Phase 6 — 6b changes only trace-file shape,
   never exploration behavior.
4. Spot-run the documented investigation flows:
   - `./src/scp-dpor-investigation --depth 12`
   - `--fail-on-first-terminal --trace-dir ... --depth 12`, then
     `--replay-trace-json PATH --replay-node all`
   - `--stop-on-prepare --thread-event-depth 8`
5. Commit with `git -c commit.gpgsign=false commit`.

## Phase 0 — capture baselines

- Record `bench-dpor.sh check` output to a scratch file kept for the whole
  effort.
- Capture one trace bundle with the current binary
  (`--fail-on-first-terminal --trace-dir`) and stash it outside the tree;
  Phase 6b uses it to confirm old bundles are rejected with the documented
  message.

## Phase 1 — delete dead surface (zero-risk, ~350 lines)

All items verified zero-caller by tree-wide grep during review; re-verify
each grep before deleting (the tree may have moved).

`DporScpNode` (`src/scp/test/DporScpNode.h` / `.cpp`):

- Methods: `setStateFromEnvelope` (cpp:229), `getStoredQuorumSet` (:195),
  `hasActiveTimer` (:250), node-level `hasReachedPrepareBoundary` /
  `getPrepareBoundaryEnvelope` (:720–737).
- `BoundaryMode::NominationRound` and its only user
  `getNominationRoundForEnvelope` (cpp:1526–1559, h:41, h:406). The
  `--max-nomination-round` cap works through `setupTimer` and is unaffected.
- Config knobs nothing sets: `mValueHash` / `mCombineCandidates` (h:99–101,
  members 411–413, wiring cpp:1278–1285, dispatch 1101/1108–1111 — inline
  the defaults), `mTxSetDownloadWaitTimesByNode` (h:114–115,
  cpp:1332–1341), `mBallotingTimerSetLimit` (h:118, member 455,
  cpp:1229–1231, 1345 — collapses the `timerSetLimit` lambda).
- The delegating 2-arg constructor **stays**: `Configuration` is a nested
  class with default member initializers, and clang++-20 rejects
  `Configuration const& config = {}` as a default argument inside the
  enclosing class definition ("default member initializer ... needed within
  definition of enclosing class"; verified). The delegating constructor is
  the simplest conforming spelling.

Scenario (`src/scp/test/ScpDporDefaultScenario.h`):

- Zero-caller wrappers at :278–319: `hasReachedBoundary`,
  `getBoundaryEnvelope`, `getEmittedEnvelopes`, `hasReachedPrepareBoundary`,
  `getPrepareBoundaryEnvelope`.
- `makeDefaultOptions()` no-arg overload → default argument.

Investigation main (`src/scp/test/DporScpInvestigationMain.cpp`):

- `dumpTerminalExecution`'s `bool dumpReplayTrace` parameter (`true` at all
  three call sites; the `false` path at :960–963 is dead).
- `failOnFirstTerminalFailureMessage()` — inline the constant.

Smoke tests (`src/scp/test/SCPDporSmokeTests.cpp`):

- `limitThreadSteps` (:29–48) → inline a cap-at-one-step lambda at its one
  call site (:1570).

The six scenario Options fields originally flagged as dead
(`mPrepareBoundaryCounter`, the four nomination/ballot timeout fields,
`mNominationTimerSetLimit`) are **retained**: they are functional scenario
knobs — prepare-boundary detection, `computeTimeout()` and round
inference, and `setupTimer()`'s nomination cap all consume them — reachable
from C++ scenarios and from loaded scenario options; they merely lack CLI
flags. Removing them would narrow the scenario surface, not delete dead
code. If CLI exposure is ever wanted, wire flags rather than deleting the
plumbing. Their JSON encode/decode also stays — a trace bundle must
recreate the effective scenario, so dropping only the serialization while
keeping the C++ members would silently replay custom-option traces under
defaults. The serialized fields Phase 6b drops are unrelated to these six:
the derivable `observed_count` and `focus_thread_id`, plus the
`communication_model` read requirement.

## Phase 2 — one source of truth for enum↔string tables (~120 lines)

`ScpDporTraceJson.cpp:189–330` and `DporScpInvestigationMain.cpp` both map
the same enums to the same strings (download-time modes, txset-status
modes, terminal kinds, communication models). Every enum extension must
currently land in two files with no compile-time cross-check.

- Move the `xName` / `parseX` pairs into `ScpDporTraceJson.h` (Main already
  includes it) or a small new shared header if that feels wrong-layered.
- Delete Main's copies, including `terminalExecutionKindName` (a second
  name for the same terminal-kind mapping).
- Parsers compare against the `xName(...)` calls rather than re-spelling
  literals (the pattern `parseInitMode` at Main :424 already uses).

This is the highest-value single change: it removes the one active drift
hazard found in the review.

## Phase 3 — dedup inside the investigation main (~200 lines)

`src/scp/test/DporScpInvestigationMain.cpp`:

- **Capture-and-stop helper.** The `on_terminal_execution` callback
  (:1431–1601) repeats a ~30-line lock / first-failure-message /
  dump-once / `Stop` ritual five times (error, `--must-externalize`,
  `--check-agreement`, `--fail-on-first-blocked`,
  `--fail-on-first-terminal`). Extract one local
  `stopWithCapture(message, focusNode, kind)` lambda; each branch becomes
  predicate + message + one call. The "first failure wins, dump once"
  invariant then exists in exactly one place. (~110 lines)
- **One dump core, two error policies.** `dumpTerminalExecution` (:946),
  `dumpErrorExecution` (:977), and `dumpReplayBundle` (:1062) share headers
  and the per-node inspect/print loop; `dumpReplayBundle` literally
  re-implements both headers. Share the header formatting and the loop, but
  keep the error policy a parameter rather than always catching: live
  error-capture dumping stays best-effort (the existing try/catch — the
  execution is already known bad), while the explicit `--replay-trace-json`
  path must keep letting inspection errors escape to `main` so a malformed
  or incompatible bundle still exits nonzero (`loadTraceBundle()`
  deliberately skips scenario-level semantic checks). Also preserve
  `replayNodeOrder()` for `--replay-node`, which is not the all-node order
  used by live capture. (~40 lines)
- **Truncation-hint helper.** The "; N execution(s) hit --depth /
  --thread-event-depth" epilogues at :1684–1711 and :1718–1746 become one
  `appendTruncationHints`. Keep the distinct exit codes (1 vs 2) and lead
  sentences — documented behavior. (~15 lines)
- **Parse-helper pruning.** Fold `parseUint32Value` / `parseSizeValue` /
  `parsePositive*` into `parseStrictUnsignedValue<T>` plus one
  `parsePositive<T>`. Keep the strict-parsing rationale comment
  (:441–449). (~30 lines)
- `AgreementFailure` / `ExternalizedValueRecord`: drop the unused `mValue`
  from the failure record.
- The `on_fatal_error` inline formatter (:1624) → call the existing
  `formatWithStream`.

Also move `findExternalizedValue`, `findNodeMissingExternalize`, and
`findAgreementFailure` (plus their small record types) from Main into
`ScpDporInvestigationUtils.h`, next to `isMaximalExecution` /
`findErrorExecution`. While moving them, make the checkers return evidence
alongside the verdict — how many emitted envelopes were examined and how
many externalized values were compared — so Phase 5's tests can assert
that the predicates actually ran on data, not on an empty set. This is
preparation for Phase 5 (tests will call the shipped checkers) and shrinks
Main. While in that header: collapse
`findErrorExecution` / `findBlockedExecution` into one
`findLastEventThread(validatorCount, execution, predicate)` helper, and
dedup the two catch blocks in `wrapProgramExceptionsAsErrorExecutions`.

## Phase 4 — scenario replay-loop helpers (~70 lines)

`src/scp/test/ScpDporDefaultScenario.h`: the replay state machine is
transcribed three times (`inspectThreadReplayTrace` :321, `replayTrace`
:745, `captureNextEvent` :820). Extract the invariant-critical fragments —
do **not** attempt the full three-way merge (the lean `replayTrace` path
must not pay for step/debug recording; it sits under Main's per-execution
verification):

- `decodeAndValidateTimerChoice(observed, activeTimers)` — the ~15-line
  decode / membership-check / three `logic_error` messages, currently at
  :377–395, :763–776, :890–911.
- `makeTimerChoices(activeTimers)` — the 7-line vector construction at
  :369–375 and :874–880.
- `resolveTimerToFire(...)` — the "selected timer, else the single active
  timer" logic at :412–416, :781–784, :934–938 (the `nonBlocking`
  computation falls out of it).

Also:

- Collapse `makeReceiveLabel` / `makeNonBlockingReceiveLabel` (:627–646)
  into one function over a shared matcher; drop the unused `std::size_t`
  parameter.
- Make `ReplayInspection` public and return it from both `inspectBoundary`
  and `inspectEmittedEnvelopes`, deleting the `BoundaryInspection` and
  `EmittedEnvelopeInspection` shim structs and their field-copy bodies.
- Replace `ScenarioBaseline` (one-vector wrapper, :479–482) with the vector
  itself.

`DporScpNode.cpp` mechanical dedup (same commit or a sibling one):

- One private timer-search helper replacing the four identical predicate
  lambdas (`fireTimer` :270, both `findTimer` overloads :1351/:1362,
  `clearTimer` :1384) and the near-copy in `findTimerSetCount` :1398.
- Merge `TimerSetCountEntry` (h:354) into `ReplayTimerSetCountSnapshot`
  (h:189) — field-for-field identical; snapshot/restore become plain
  assignments. (Leave `ReplayTimerSnapshot` vs `TimerState` alone — the
  callback genuinely cannot be snapshotted.)
- One `consumeChoice(pending, cursor, supported)` helper for the
  status-choice and wait-time-choice paths (:56–80, :882–896); optionally a
  single `template <typename T> ChoiceRequired` exception.
- Micro: shared `kPrefix` for `makeEmptyTxSetValueFromValue` /
  `isEmptyTxSetValue` (:1025–1046), and make the prefix check a static so
  the smoke tests' `isTestEmptyTxSetValue` can call it (used in Phase 5);
  simplify the `applyConfiguration` supported-choices block (:1304–1325);
  drop the impossible `if (!mBoundaryEnvelope)` guard in `emitEnvelope`
  (:928); `combine` lambda in `std::hash<ScpDporValue>`
  (ScpDporTypes.h:186–213).

## Phase 5 — smoke-test consolidation (~300 lines, one deleted TEST_CASE)

`src/scp/test/SCPDporSmokeTests.cpp`:

- **Explore helper.** One file-local
  `explorationFinds(scenario, maxDepth, predicate, commModel)` (plus a
  variant returning the `VerifyResult` for tests asserting on counters)
  replaces the ~20-line skeleton copy-pasted across nine tests (:917, :951,
  :1219, :1281, :1314, :1405, :1467, :1516, :1561).
- **Gate-failure trio.** Delete the TEST_CASE at :876 — its only unique
  assertion (message contains `"BallotProtocol.cpp"`) moves into the test
  at :738; extract the shared scenario setup used by :738 and :795. Drops
  one redundant multi-second exploration from the smoke run (a second is
  dropped independently by the :361/:653 merge below).
- **Use the shipped property checkers** (moved and evidence-enriched in
  Phase 3): tests :1467 and :1516 call `findNodeMissingExternalize` /
  `findAgreementFailure` and assert the evidence counts they return — a
  nonempty emitted-envelope set before accepting "missing externalize", at
  least two compared externalized values before accepting "agreement" — so
  neither test can pass vacuously if envelope recording regresses. Only
  then delete the local `hasExternalizeEnvelope` / `findExternalizedValue`
  / `collectExternalizedValues` (:127–191).
- **Version-rejection table.** One table-driven TEST_CASE over
  `{version, expected-substring}` replaces the four one-assertion cases at
  :587/:622/:633/:643 and the duplicate `tooOld` block at :1209 (keep
  `tooNew`). Phase 6 will shrink this table further.
- **Single-node replay harness.** A small struct helper replaces the
  three ~30-line copies at :1936, :2380, :2428 (unique per-test seeds are
  unnecessary).
- Use existing helpers everywhere: `makeTestValue` at the ~12 hand-rolled
  `push_back('x')` sites; `makeTestPrepareEnvelope` at :2190 and :2247;
  the `DporScpNode` static prefix check instead of `isTestEmptyTxSetValue`.
- Merge the duplicated smoke exploration: test :361 keeps only its
  distinctive assertions (throws on 0, works with capacity 1) and stops
  re-running the whole of test :653.
- Clarity-only, do opportunistically: SECTION-split the six-concern test at
  :1130 and the four-configuration test at :1596; parameterize the 3- and
  4-validator fan-out checks over validator count.

Intent check after this phase: every remaining TEST_CASE's predicate should
be the first thing a reader sees; the latch/checkpoint and depth-budget
tests keep their narrative comments untouched.

## Phase 6 — trace-layer pruning (6a) and bundle format v8 (6b, decided: v8-only)

### 6a — no format change (~170 lines)

Reader-internal simplifications; bundles written before and after this
phase remain mutually compatible:

- Replace the bespoke v1–v5 rejection diagnostics (cpp:996–1023) with one
  generic message ("unsupported trace bundle version N (supported: 6–7);
  capture a fresh trace with the current binary") and delete the duplicate
  version re-check in `validateTraceBundle` (:557–561); shrink the Phase 5
  rejection-table test accordingly.
- Replace `requireBase64` (:399–441) with decode + re-encode + compare
  (the encoder is already imported at :396).
- Shrink `requireUint64` / `requireInt64` (:93–167) to `isIntegral()` +
  sign/range checks.
- Replay-support small fry (`ScpDporReplaySupport.cpp`): dead
  `ReplayStateCacheEntry::mGeneration` / `mNodeIndex` fields; inline
  `acquireCacheEntry` into `acquireNode` (every caller clears the
  thread-local cache first, so it is a node factory, not a cache lookup);
  drop `ReplayObservationProgress::mConsumedStepCount`
  (= `mConsumedTraceEntries - 1` at all three return sites).

### 6b — bundle format v8 (~110 lines; **decided: v8-only**)

This was gated because the documented contract writes v7, reads v6–v7, and
promises that saved bundles keep working. The go/no-go has been decided:
**v8-only, no converter** — the owner does not need old bundles readable
(2026-08-07). Record the change in `docs/dpor-integration-status.md` as an
approved exception to this plan's no-capability-loss goal, and update the
back-compat promise in `docs/dpor-replay-notes.md`.

Consequences of v8-only:

- Write and read version 8 exclusively; every other version gets the one
  generic rejection message ("unsupported trace bundle version N
  (supported: 8); capture a fresh trace with the current binary"). The
  6a message wording is superseded by this one once 6b lands — if 6a and
  6b ship together, write the final wording once.
- The v6 legacy-load smoke coverage and the version-6 reader path go away
  entirely, which slightly raises the savings estimate (~110 lines).

Changes:

- Flatten `thread_traces` to a positional array of trace arrays indexed by
  node. Deletes `ThreadTraceRecord` (h:36–40) and its to/from JSON
  (cpp:521–552), the `seenThreadIDs` validation loop (:582–602), the
  per-record loop in `makeTraceBundle` (:1077–1084), and Main's
  `findThreadTrace` linear search. `TraceBundle::mThreadTraces` becomes
  `std::vector<ThreadTrace>`.
- Drop `observed_count` (duplicates array length) and `focus_thread_id`
  (validated equal to `focus_node_index`; derive at print time).
- Stop requiring `communication_model` on read (keep writing it as
  informational, like `annotation`).

Verification beyond the standard protocol (both tiers): capture a fresh
trace, replay it with `--replay-node all` and per-node, diff the replay
output against a pre-phase capture of the same scenario. For 6b, feed the
Phase 0 stashed bundle in and confirm it is rejected with the documented
message. Update `docs/dpor-replay-notes.md` (format description) and
`docs/dpor-integration-status.md` (version story).

## Phase 7 — build and util small fry (~50 lines)

- `configure.ac`: keep **both** DPOR compile probes. The first attributes
  "cannot compile DPOR at all" (bad include path, incompatible flags); the
  second attributes "DPOR API too old" (stale checkout). A merged probe
  would report the stale-checkout message for every failure mode. At most,
  share the probe boilerplate.
- `src/Makefile.am`: drop the duplicate `rust/RustBridge.h`
  (`SCP_DPOR_GENERATED_FILES` vs `SCP_DPOR_GENERATED_SOURCE_FILES`).
- `src/util/GlobalChecks.cpp`: one `maybeThrowOrAbort(message)` helper for
  the four repeated `if (gAssertThrowMode) throw ...` blocks.
- `bench-dpor.sh`: `head` uses `$U` instead of re-spelling its flags; the
  `scale` branch renames its `S2` (collides with `bench`'s `S2`, a
  different scenario) to `SCEN` built from `$U`; one `report_fail` helper
  for the duplicated FAILED blocks in `check_one` / `bench_one`.

## Phase 8 — judgment calls (each needs an explicit go/no-go)

Listed with recommendations; none block the phases above.

1. **CLI parsing** (`DporScpInvestigationMain.cpp` :1118–1349 parse chain +
   :206–378 usage text). Full option-table rewrite trades transparent
   dumbness for `std::function` indirection — recommend **no** for now.
   Middle ground worth doing: a `nextValue(i, argc, argv, arg)` helper to
   centralize the ~25 repeated `i + 1 < argc` checks (an omission today
   silently turns a value option into "unknown argument"), and a
   `matchesRound(arg, base)` helper for the four `-round`/`-rounds` alias
   pairs. (~40 lines, keeps the flat chain readable)
2. **`bench-dpor.sh` scale-gate topology detection** (:78–201, ~100 lines
   of CPU-mask / cgroup forensics guarding the opt-in `scale` check).
   Recommend replacing auto-detection with an explicit `SCALE_GATE=1`
   opt-in or hostname check (the repo already encodes machine-specific
   benchmarking rules in CLAUDE.md). The in-file comments say the
   complexity is intentional, so this one is the author's call.
3. **Full merge of `inspectThreadReplayTrace` into `replayTrace`** with an
   optional step-recorder callback (~60–80 further lines after Phase 4).
   Recommend **no** unless Phase 4 leaves the two loops still hard to keep
   in sync — the lean path serves per-execution verification and should
   stay lean.

## Expected totals

| Phase | Scope | ~Lines removed |
|---|---|---|
| 1 | Dead surface | 340 |
| 2 | Shared enum tables | 120 |
| 3 | Investigation-main dedup | 190 |
| 4 | Scenario/node dedup | 130 |
| 5 | Smoke-test consolidation | 300 |
| 6a | Trace-layer pruning | 170 |
| 6b | Bundle format v8 (decided: v8-only) | 110 |
| 7 | Build/util | 40 |
| 8 | Judgment calls (if taken) | 40–200 |
| **Total** | | **~1,400 firm, +40–200 gated (Phase 8)** |

Roughly 14% of the harness comes out firm. Two behavioral deltas remain,
both in Phase 6: 6a collapses the v1–v5 rejection diagnostics into one
generic message (diagnostic wording only), and 6b's approved v8-only
format makes old bundles unreadable, recorded in
`docs/dpor-integration-status.md` as an accepted exception to the
no-capability-loss goal.

## Review — 2026-08-07

Verdict: **changes requested before implementation**. The overall diagnosis is
good: the support-layer split and replay machinery should stay, and most of the
enum, parser, and replay-loop deduplication is well targeted. The following
issues need to be resolved in the plan first.

1. **Blocking: the proposed `DporScpNode` constructor default argument does
   not compile with the project's compiler.** `Configuration` is nested in
   `DporScpNode` and has default member initializers. While the enclosing class
   is still being defined, `clang++-20` rejects both
   `Configuration const& config = Configuration{}` and `config = {}` with
   "default member initializer ... needed within definition of enclosing
   class". Keep the delegating two-argument constructor, or use a factory whose
   default `Configuration` is constructed after the class is complete. Phase 1
   cannot be described as zero-risk with the current instruction.

2. **High: always catching inspection errors in the merged dump function
   changes replay failures into successful commands.** The catch in
   `dumpErrorExecution` is intentional best-effort diagnostics for an execution
   already known to be erroneous. `dumpReplayBundle`, by contrast, currently
   lets semantic replay errors escape to `main`, which reports the error and
   exits nonzero. This matters because `loadTraceBundle()` deliberately does
   not perform every scenario-level semantic check. If the Phase 3 `dumpBundle`
   catches every inspection exception and returns normally, a malformed or
   incompatible `--replay-trace-json` input can print `replay-dump-error=` and
   exit 0. Share the formatting and loop, but parameterize or otherwise
   preserve the error policy: live error-capture dumping may continue after an
   inspection error; an explicit replay command must still fail. Also preserve
   `replayNodeOrder()` for `--replay-node`, which is not the all-node order used
   by live capture.

3. **High: replacing the two property smoke tests with the shipped checkers
   makes their success conditions vacuous.** The test at current
   `SCPDporSmokeTests.cpp:1467` deliberately requires a nonempty emitted-envelope
   set before accepting "missing externalize", so a regression that drops all
   recorded envelopes cannot pass the test. `findNodeMissingExternalize()` has
   no such evidence requirement and would report the first node immediately.
   Similarly, `findAgreementFailure() == nullopt` conflates genuine agreement
   among multiple externalizers with zero or one observed externalizer; the
   current test explicitly waits until at least two values were compared.
   Either keep those coverage assertions/local collection helpers, or make the
   shipped checkers return enough evidence (emitted-envelope and compared-node
   counts) for the tests to prove that the predicates actually ran.

4. **High: the six Phase 6 scenario fields are reachable behavior, not dead or
   write-only surface.** `mPrepareBoundaryCounter` directly changes prepare
   boundary detection; the four timeout fields feed both `computeTimeout()` and
   round inference; and `mNominationTimerSetLimit` changes `setupTimer()`.
   `ScpDporDefaultScenario::buildNodeConfiguration()` forwards every field,
   `optionsFromJson()` reads every field, and the existing round-trip test
   explicitly varies five of the six. They lack CLI flags, but C++ scenarios
   and loaded scenario options can use them. Deleting the round-trip assertions
   together with the fields would let the default-only execution fingerprint
   remain unchanged while silently removing this capability. Retain them, or
   make their removal an explicit scenario-surface decision that narrows the
   stated no-capability-loss goal; calling them dead is not accurate.

5. **Medium: v8-only compatibility must be an explicit go/no-go, not the
   default simplification.** The current documented contract writes v7, reads
   v6 and v7, and specifically promises that saved bundles keep working. Option
   (a) breaks every bundle produced by the current binary, not merely v6, so the
   decision test at line 271 must ask whether *v6 or v7* traces are in use.
   Re-capture is also not necessarily cheap for a rare execution found by a
   long campaign or for a source revision that has moved. If v8-only is chosen,
   record it as an approved exception to the no-capability-loss goal and
   consider a one-shot v6/v7-to-v8 converter; otherwise retain the old reader
   path. The Phase 0 rejection check demonstrates the break but does not
   mitigate it.

6. **Medium: merging the two configure probes loses useful failure
   attribution.** The first probe currently establishes that the headers build
   with `DPOR_CPPFLAGS`/`DPOR_CXXFLAGS`; the second attributes a successful
   header build with missing symbols to an old checkout. A single API-heavy
   compile cannot distinguish a bad include path, incompatible flags, or a
   general compiler error from a genuinely stale DPOR API, and will tend to
   report the minimum-commit message for all of them. Deduplicate the probe
   source/setup if worthwhile, but retain separate diagnostics (and therefore
   separate checks) for "cannot compile DPOR" and "DPOR API too old".

7. **Medium: Phase 7 misses an existing duplicate in the correctness
   fingerprint.** `bench-dpor.sh check` invokes the identical `CA` scenario
   twice. There are 14 unique scenarios but 15 `check_one` calls, so Phase 0
   will preserve a redundant output line and the phase-by-phase byte diff will
   make removing it appear forbidden. Add its removal to Phase 7 and make that
   the other explicitly allowed fingerprint-shape change (all 14 unique labels
   and their exact counts must remain). Preferably, make the check driver reject
   duplicate scenario labels so this cannot recur.

Minor: the expected-total row says `~1,400 (+8)` even though Phase 8 contributes
an optional 40–200 lines; spell this as `~1,400 (+40–200 if Phase 8 is taken)`.

END REVIEW

## Response to review — 2026-08-07

Six of the seven points are accepted and the plan text above has been
updated in place; one is rejected on evidence. Point by point:

1. **Accepted, verified.** Reproduced the failure with clang++-20 on a
   minimal nested-class-with-NSDMI test case; the diagnostic matches the
   review's quote. Phase 1 now keeps the delegating 2-arg constructor and
   records why, so a future simplification pass does not re-flag it.

2. **Accepted.** The original wording ("always wraps inspection in the
   try/catch") would indeed have let a malformed `--replay-trace-json`
   input print `replay-dump-error=` and exit 0. Phase 3 now specifies one
   shared dump core with error policy as a parameter — best-effort for
   live error capture, propagate-to-`main` for the explicit replay
   command — and explicitly preserves `replayNodeOrder()`. Estimated
   saving reduced 50 → 40 lines.

3. **Accepted.** The review is right that the local test helpers were not
   mere duplication: the tests carry evidence preconditions (nonempty
   emitted-envelope set; at least two compared externalized values) that
   the shipped checkers lack. Rather than keeping two copies, Phase 3 now
   has the moved checkers return evidence counts and Phase 5 has the tests
   assert on them, which preserves the anti-vacuity coverage.
   *[Corrected after round 2: the evidence counts are consumed by the
   smoke tests only. No CLI aggregation, output, or exit-code change is
   part of this plan — extending `inconclusive:` semantics to these
   checkers would be a separate property-semantics decision.]*

4. **Accepted, verified.** Confirmed the consumption sites
   (`computeTimeout` at DporScpNode.cpp:1267, round inference at :1140,
   `setupTimer` at :1226, prepare-boundary at :1286–1287). "Dead" was the
   wrong classification — these are functional scenario knobs without CLI
   exposure, settable from C++ scenarios and loaded options. All six
   fields are now retained, with a note that CLI flags, not deletion, are
   the right response if they are wanted more broadly. Phase 6's estimate
   drops accordingly.

5. **Accepted.** Phase 6 is now split: 6a is reader-internal pruning with
   no format change (v1–v5 message consolidation, base64, integer
   ladders, replay-support small fry, ~170 lines); 6b is the v8 format
   change, gated on an explicit go/no-go with three spelled-out options
   (v8-only with a converter and a documented capability exception; dual
   reader; skip). The plan no longer presents v8-only as a default, and
   the text now acknowledges that the break covers v7 bundles too and
   that re-capture can be genuinely expensive.
   *[Superseded 2026-08-07, after this response was written: the owner
   approved option (a) as v8-only with **no** converter — old bundles are
   explicitly not needed. The Decisions log at the top and the Phase 6b
   body reflect the decided state and override this item.]*

6. **Accepted.** Phase 7 now keeps both configure probes for their
   distinct failure attributions ("cannot compile DPOR" vs "DPOR API too
   old") and limits any cleanup to shared boilerplate.

7. **Rejected — the claimed duplicate does not exist.** `bench-dpor.sh
   check` contains exactly 14 `check_one` invocations with 14 unique
   labels, C1–C9 and CA–CE (lines 211–227; verified by
   `grep -n check_one`); CA appears once, at line 220. The 14-scenario
   count also matches CLAUDE.md's description of the fingerprint. No plan
   change. The suggestion to make the check driver reject duplicate
   labels is harmless but guards against a mistake no one has made in a
   14-line hand-maintained list; it is omitted to keep the script small,
   which is the point of this plan.

Minor totals-row wording: fixed; the table now separates firm phases
from gated ones. *[Corrected after round 2: the figures first quoted here
(~1,250 firm, +130–290 gated) were wrong — firm-without-6b is ~1,290, and
with 6b approved the firm total is ~1,400, leaving only Phase 8 (+40–200)
gated. The Expected totals table is the authoritative sum.]*

END RESPONSE

## Review round 2 — 2026-08-07

Verdict: **small but important changes requested**. The substantive blockers
from the first review are resolved in the plan body: the delegating constructor
stays, explicit replay still propagates inspection errors, the property tests
retain non-vacuity evidence, all six functional scenario options stay, and the
two configure probes keep their separate diagnostics. No architectural blocker
remains. The document still needs the following consistency fixes before it is
safe to implement literally.

1. **High: the response and final Phase 6b decision describe different
   plans.** The body and the decision log say v8-only has been approved, with
   no converter (`lines 5–9` and `311–328`). The response instead says 6b is
   still gated on three options and describes its v8-only option as including a
   converter (`lines 540–547`). It also says the plan no longer presents
   v8-only as the selected path. An implementer reading the audit trail has two
   incompatible instructions. Amend response item 5, or add an explicit
   post-response decision section saying that the owner subsequently selected
   v8-only/no-converter and that it supersedes item 5. Rename the Phase 6
   heading from “6b, gated” as well; 6b is now firm, while only Phase 8 remains
   gated.

2. **High: remove the stale claim that retained scenario options have
   “write-only serialized fields” handled in Phase 6b.** The parenthetical at
   `lines 127–128` has no corresponding Phase 6b change, and no such
   write-only versions of the six options exist: their JSON fields are both
   written and read, and they must remain serialized if a trace is to recreate
   the effective scenario. Deleting only their JSON encode/decode while
   retaining the C++ members would make custom-option traces replay under
   defaults, which is worse than deleting the options outright because the
   artifact would misrepresent its execution. Remove the parenthetical. If it
   was intended to refer to `observed_count`, `focus_thread_id`, or
   `annotation`, name those fields precisely; the first two are currently read
   and validated, while only `annotation` is ignored on read.

3. **Medium: the totals are arithmetically inconsistent in both the body and
   response.** The listed firm rows through approved Phase 6b plus Phase 7 sum
   to approximately 1,400 lines, not 1,360:
   `340 + 120 + 190 + 130 + 300 + 170 + 110 + 40 = 1,400`.
   With the current decision, the correct summary is therefore about 1,400
   firm, plus 40–200 if Phase 8 is taken. The response's “~1,250 firm” omits
   Phase 7 (firm without 6b is ~1,290), and its “+130–290” does not equal the
   listed 6b plus Phase 8 range (110 + 40–200 = 150–310). Update the table,
   prose, and response to one decision state and one sum.

4. **Medium: the response overstates what the evidence-enriched property
   checkers will do for the CLI.** The plan says the returned evidence is used
   by the smoke tests to prevent vacuous test success. The response additionally
   says it gives the CLI checkers a way to report “checked nothing”, but no CLI
   aggregation, output, or exit-code change is specified. That would also be a
   semantic decision: agreement is a safety property and can legitimately hold
   when fewer than two nodes externalize; `--must-externalize` is the separate
   liveness check. Remove the CLI claim, or specify exactly which command is
   inconclusive under which aggregate evidence condition and add it to the
   behavior/verification sections. Do not let this sentence silently expand
   Phase 3 into a property-semantics change.

5. **Low: two remaining prose claims should be corrected.** Phase 6a changes
   the user-visible v1–v5 rejection diagnostics from semantic explanations to
   one generic message, so Phase 6b is not literally the only behavioral delta;
   call 6a a diagnostic-only behavior change. Also, deleting the gate-failure
   TEST_CASE at current line 876 removes one exploration, not two; the second
   redundant exploration is removed separately by the replay-cache test merge
   later in Phase 5. Attribute one saving to each item so the verification plan
   matches the actual test topology.

The response's rejection of finding 7 is **accepted**. The checked-in
`bench-dpor.sh` has exactly 14 `check_one` calls with 14 unique labels,
`C1`–`C9` and `CA`–`CE`; `CA` appears once. The first review's duplicate claim
was a false positive caused by displaying two overlapping `sed` ranges that
both included the same boundary line. No benchmark-script change is needed for
that finding.

END REVIEW

## Response to review round 2 — 2026-08-07

All five points accepted; all are consistency fixes applied in place:

1. The Phase 6 heading now reads "6b, decided: v8-only", and response
   item 5 of round 1 carries an explicit supersession note pointing to the
   Decisions log. One decision state throughout: v8-only, no converter;
   only Phase 8 remains gated.

2. The Phase 1 parenthetical is rewritten: the six retained options keep
   their JSON encode/decode (a bundle must recreate the effective
   scenario — dropping serialization while keeping the members would
   silently replay custom-option traces under defaults), and the fields
   6b drops are named precisely (`observed_count`, `focus_thread_id`, the
   `communication_model` read requirement).

3. Totals corrected everywhere to one sum: **~1,400 firm**
   (340+120+190+130+300+170+110+40), +40–200 if Phase 8 is taken. The
   erroneous figures in the round-1 response are struck with a correction
   note rather than silently rewritten.

4. The "CLI checkers report checked-nothing" claim is withdrawn via a
   correction note in the round-1 response: evidence counts are consumed
   by the smoke tests only, and any extension of `inconclusive:`
   semantics to `--check-agreement` (a safety property that legitimately
   holds with fewer than two externalizers) is out of scope for this
   plan.

5. The closing prose now names both behavioral deltas (6a's
   diagnostic-wording change and 6b's format break), and the two
   redundant smoke explorations are attributed one each to the
   gate-failure TEST_CASE deletion and the :361/:653 merge.

Noted with thanks: the round-1 duplicate-`CA` claim is confirmed closed as
a tooling false positive; no script change needed.

END RESPONSE
