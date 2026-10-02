# Results

This is a summary of what the Isabelle/HOL model in `formal/` covers, what
is proved about it, how it is tied to the C++ in this tree, and what is
still open. Theorem names refer to the theories in `formal/OfferExchange/`;
the theories themselves state every result in English next to its formal
statement. The tree is stellar-core `release/v29.0.0`, where protocol 29
changes the offer-crossing arithmetic (commit
[`cb257d2810`](https://github.com/stellar/stellar-core/commit/cb257d2810bb3ca78e7d50d05af1fbaf7ef96a54),
"Improve DEX offer crossing accuracy"). Everything below is stated for
protocol 28, protocol 29, or both.

## What is modeled

The model is bit-precise and executable. It has one definition per C++
function, uses the C++ argument order and fixed-width words, and spells out
every cast and every failure the C++ can raise (assertion, detected
overflow, `std::runtime_error`), in the order the C++ checks them.

- **Wide arithmetic** (`Offer_Exchange_Divide_Layered.thy`): `bigMultiply`,
  `bigDivide`, `bigDivideUnsigned`, `bigDivideOrThrow` and their 128-bit
  variants from `src/util/numeric.cpp`, each modeled separately.
- **Exchange arithmetic** (`Offer_Exchange_Arithmetic.thy`): the
  `exchangeV10` call tree in `src/transactions/OfferExchange.cpp`. That is
  the offer values, `calculateOfferAmountFromValue`, the price-error bound
  and its thresholds, `exchangeV10WithoutPriceErrorThresholds` and
  `exchangeV10`, in all three rounding modes (normal, path-payment strict
  send, and strict receive).
- **Adjustment and liabilities** (`Offer_Exchange_Adjustment.thy`):
  `adjustOffer`, the stored-offer liability helpers of
  `TransactionUtils.cpp`, and the ManageBuy request-time liabilities.
- **Offer lifecycle** (`Offer_Exchange_Lifecycle.thy`): posting through
  `ManageOfferOpFrameBase` (ManageSell and ManageBuy), and crossing through
  `crossOfferV10`. Crossing covers liability release, preventative
  adjustment, the exchange, balance moves, and erase or shrink-and-reacquire.
  Each party's balances, trustline limits and liabilities are explicit
  parameters. The maker's state at crossing is a free parameter, so other
  operations may change it between posting and crossing.
- **Protocol mapping**: `exchange_options_at_version` is the only link
  between a ledger version and the arithmetic. Versions below 29 select
  `legacy_exchange_options` and 29 onward select `repaired_exchange_options`.
  The option record exists in the model so that one proof can cover both
  protocols. `mixed_exchange_options_are_unreachable` shows that no ledger
  version selects either of the two one-sided settings, which survive only
  as diagnostic mutants.
- **Migration** (`Offer_Exchange_Migration.thy`): offers posted at protocol
  28 and crossed at protocol 29.
- **Specification** (`Offer_Exchange_Specification.thy`): an abstract model
  of posting and crossing over rationals. It is written for simplicity
  rather than to follow the C++, and is connected to the code-level model
  by `Offer_Exchange_Posting_Refinement.thy`.
- **Test interface** (`Offer_Exchange_Test_Interface.thy`): the exported
  entry points that the differential harness evaluates.

`docs/offer-lifecycle.md` surveys the lifecycle and its property catalogue.
`docs/exact-cap-liability-semantics.md` explains the protocol-29 repair and
why it needs no liability migration. `docs/resting-offer-receive-cap.md`
explains why crossing does not refine the specification even at protocol
29.

## What is proved

The session has no `sorry` and no `oops`; `isabelle build -D
formal/OfferExchange` checks every result below. One stated property is
unproved; it is listed under Open items.

### Exchange arithmetic

- Success conditions for the checked helpers:
  `big_divide_or_throw_success_iff` and
  `big_divide_or_throw128_success_iff`. The layered helper definitions are
  equal to the collapsed ones: `big_divide_or_throw_layered_eq`,
  `big_divide_or_throw128_layered_eq` and `big_multiply_layered_eq`.
- Exact integer characterizations of every stage, up to
  `exchange_v10_integer_characterization`. Also
  `exchange_v10_wellformed_characterization`, and the normal-mode and
  path-mode forms `exchange_v10_normal_characterization` and
  `exchange_v10_path_characterization`.
- Result contracts:
  - `exchange_v10_result_contract`, which gives signed bounds, the four cap
    bounds and the exact `wheatStays` condition;
  - `exchange_v10_positive_trade_contract`: a positive trade favors the
    seller marked as staying and meets the one-percent price-error bound;
  - `exchange_v10_zero_iff`: outside strict send, both assets move or
    neither does;
  - `exchange_v10_strict_send_sheep_positive` and its iff form.
- The same contracts hold for every option record, without the
  well-formedness precondition `exchange_v10_pre`:
  `exchange_v10_strict_send_sheep_positive_any_options`,
  `exchange_v10_zero_iff_any_options`,
  `exchange_v10_positive_trade_contract_any_options` and
  `exchange_v10_strict_receive_contract_any_options`. Their protocol-29
  instances are `exchange_v10_strict_send_sheep_positive_p29`,
  `exchange_v10_zero_iff_p29`, `exchange_v10_positive_trade_contract_p29` and
  `exchange_v10_strict_receive_contract_p29`.
- `legacy_strict_send_positivity_implies_repaired`: wherever protocol 28
  computes a positive strict-send pair, protocol 29 does too.

### Lifecycle properties

`Offer_Exchange_Lifecycle.thy` states the intended properties together, in
the "Intended properties" subsection, before any proof. Their status at
each protocol:

- **Rounding favors the offer that stays.** Holds at both protocols:
  `successful_exchange_favors_offer_that_stays` does not depend on the
  options. The protocol-29 instance is `rounding_favors_offer_that_stays_p29`.
- **Positive normal crosses are maximal.** Every successful positive normal
  exchange returns the largest cap-respecting pair that rounds in favor of
  the staying offer. Proved at protocol 29:
  `positive_normal_crosses_are_maximal_p29`. It fails before protocol 29.
  The theory explains the `99/100` witness, but no negative theorem is
  packaged for it.
- **Coverage implies adjustment stability.** If the maker still covers the
  offer's booked liabilities, the preventative adjustment at crossing leaves
  the posted amount alone. Proved at protocol 29:
  `cover_implies_adjust_stable_p29`. False at protocol 28, shown by the
  reservation anomaly below (`covering_does_not_imply_adjust_stability`).
- **Takeability after lowering the maker's buying limit.** If the maker
  only lowers its buying limit, and the new limit still covers the booked
  liability, the offer stays takeable. Proved at protocol 29:
  `limit_adjustment_stable_p29`, and `buy_limit_adjustment_stable_p29` for
  ManageBuy. False at protocol 28: `limit_adjustment_stable_counterexample`
  and `limit_adjustment_stable_p28_false`. Protocol 28's overlay filter
  exists to refuse exactly these offers. The pair of results explains why
  stellar-core switches that filter off from protocol 29.
- **Takeability after any covering maker-state change.** Proved at protocol
  29: `posted_offers_remain_takeable_p29`,
  `posted_buy_offers_remain_takeable_p29`, and
  `posted_request_offers_remain_takeable_p29`, which covers both request
  kinds. A maker left exactly as posting returned it is a special case.
  False at protocol 28: `no_taker_can_take_the_griefed_offer`.
- **A fully taken posted offer transfers its stored amount.** Proved at
  protocol 29: `fully_taken_posted_offer_exchanges_posted_amount_p29`. False
  at protocol 28: `fully_taken_posted_offer_exchanges_posted_amount_p28_false`.
- **A fully taken incoming offer transfers its amount.** Not promised by
  protocol 29 either:
  `fully_taken_incoming_offer_exchanges_incoming_amount_p29_false`.
- **Agreement with a continuous ideal.** At protocol 29 a positive normal
  exchange refines the exchange computed over the reals:
  `exchange_v10_p29_positive_normal_refines_ideal`.

### The reservation anomaly at protocol 28

Executable lemmas replay the griefing walkthrough of
`docs/offer-lifecycle.md` §5 end to end: `alice_posts_her_offer`,
`bob_takes_the_offer` and `carol_griefs_alice`. A third party's payment
leaves the maker covering the offer's booked liabilities. Even so, the
preventative adjustment clips the offer, and
`no_taker_can_take_the_griefed_offer` shows that every admissible taker
then exchanges nothing. Protocol 29 repairs this. The positive results
above are the repaired statements.

### Migration from protocol 28 to 29

- `persistent_liabilities_agree_across_activation`: a stored offer has the
  same booked liabilities at every ledger version, so activation needs no
  liability rewrite. It depends on the retained `INT64_MAX * priceD` clamp.
- `manage_buy_request_liabilities_change_at_activation`: ManageBuy
  request-time liabilities do change at the boundary. A four-unit request
  at price `100/101` books three units before protocol 29 and four from
  29 on.
- Offers posted at protocol 28 behave safely when crossed at protocol 29:
  - `legacy_post_cover_implies_repaired_adjust_stable`;
  - `p28_offer_crossed_at_p29_preserves_invariants`;
  - `p28_stored_offer_has_safe_full_cross_at_p29`, so no old offer is
    frozen;
  - `legacy_fully_taken_posted_offer_exchanges_posted_amount_repaired`, so
    there is no phantom full take;
  - `p29_cross_remainder_remains_safely_takeable`, for a partial remainder.
- `buy_post_created_is_stored_offer`: an offer created by ManageBuy is an
  intrinsic stored offer at every ledger version. This puts ManageBuy on
  the same migration ladder.

### Specification and refinement

`Offer_Exchange_Specification.thy` proves
`successfully_posted_offer_has_unrestricted_taker`: a successfully posted
offer is fully taken by a large enough counteroffer.
`post_sell_offer_refines_post_sell_wheat_offer` shows that bit-precise
ManageSell posting with the repaired arithmetic implements the
specification's posting.

Crossing does not refine the specification, even at protocol 29. The C++
passes all of the maker's released buying headroom to `exchangeV10` as the
resting offer's receive cap, while the specification caps it at the offer's
booked buying liability. Spare headroom can therefore change which offer
stays, and with it the rounding direction, and can reduce a positive trade
to zero (`docs/resting-offer-receive-cap.md` has a one-unit example). The
theory keeps a matching unconstrained-maker benchmark as diagnostic material,
not as an intended property. Whether the specification or the C++ is
normative here is a protocol-design question.

### A precondition protocol 29 sharpens

`repaired_strict_send_threshold_rejection_probe` is a strict-send exchange
that succeeds at protocol 28 and raises a runtime error at protocol 29.
`repaired_strict_send_rejection_needs_unadjusted_offer` shows that the
offer in this example was not adjusted at protocol 29. `crossOfferV10`
always adjusts before exchanging, so the crossing path never hands over
such an offer. The precondition (the offer has been adjusted at the
current version) was harmless before protocol 29 and is load-bearing from
it on. The C++ test "ExchangeV10 strict modes require an offer adjusted at
the current protocol version" pins the same behavior down in
stellar-core.

## How the model is tied to the C++

- **Code shape.** Each definition names the C++ function it models and
  follows it statement by statement. Simplified forms, such as the integer
  characterizations, are theorems about the definitions, not replacements
  for them.
- **Export check.** The harness evaluates code exported from the theories.
  The tooling's export check audits every exported code equation, and every
  fact collected under `export_audit`, for oracles and for project axioms
  that are not definitions.
- **Differential testing.** `differential/run.sh` generates a deterministic
  corpus of boundary, regression, exhaustive small-domain and randomized
  cases: 667,238 records across 19 tags. It evaluates the exported model on
  them and compares every result, including which failure fires, with
  stellar-core built from this tree, through the `[isabelle-offer-exchange]`
  test case in `src/transactions/test/ExchangeTests.cpp`.
  - The arithmetic, adjustment and liability tags run at ledger versions 28
    and 29.
  - The two lifecycle tags apply real ManageSell or ManageBuy, ChangeTrust
    and ManageBuy-counteroffer transactions, 211 cases each in a protocol-28
    and in a protocol-29 ledger.
  - For every tag, a perturbed result and a rotated error code must both be
    rejected, so a comparison that silently checks nothing cannot pass.
  - A committed 40-record-per-tag subset, `differential/golden/expected.tsv`,
    is checked by ordinary test runs without Isabelle.
- **C++ regression tests.** `ExchangeTests.cpp` also gains:
  - "ExchangeV10 randomized bounds";
  - "Liabilities survive crossing at minimum limits";
  - "Offer shrinks at minimum trustline limit";
  - "Buying liability versus the capacity a crossing needs";
  - the strict-send precondition test above.

  Each runs at protocols 28 and 29.

## Open items

- The specification's
  `sufficiently_large_incoming_offer_fully_takes_covered_posted_offer` is
  stated in a comment and not proved.
- Nothing proves in general that an `adjust_offer` fixed point at protocol
  29 satisfies the tight price-error bound in both strict modes.
  `bounded_p29_adjusted_strict_search` checks it over a small grid, and only
  the crossing path is covered.
- Crossing refinement to the specification is false at both protocols, as
  described above; it needs a protocol-design decision.
- The overlay-admission filter (`offerCanClearForZero` and
  `ManageOfferOpFrameBase::doCheckValidForOverlay`) is not modeled.
- Each lifecycle differential row posts and crosses within one protocol. No
  C++ test yet posts an offer at protocol 28, upgrades the ledger to 29 and
  crosses it; the migration theorems above cover that path in the model
  only.
- Not modeled: liquidity pools, order-book offer selection and
  `convertWithOffers`, and the rest of the path-payment machinery above
  `exchangeV10`.
- Undefined behavior is excluded by preconditions. The differential corpus
  has not yet been run under UBSan.
