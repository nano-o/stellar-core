theory Offer_Exchange_Migration
  imports Offer_Exchange_Stored_Offers
begin

section \<open>Exact-cap protocol migration\<close>

text \<open>
  This theory studies a protocol boundary rather than a same-version
  lifecycle.  A resting offer may have been admitted and had its liabilities
  acquired using @{const legacy_exchange_options}; after activation, liability
  release is still flag-free, while preventative adjustment and
  @{const cross_offer_v10} use @{const repaired_exchange_options}.  The
  stored-offer theory shows that every covered offer satisfying the
  invariant @{const stored_offer} remains safe to cross and has a
  maximum-capacity full-take witness at protocol 29.  This theory applies
  those results to offers posted at protocol 28: it establishes the
  invariant for them and restates the results through the protocol mapping.

  The invariant is proved for the modeled creation routes: a successful
  protocol-28 @{const post_offer}, a successful @{const post_buy_offer} at
  any ledger version, and any positive remainder left by a successful
  crossing under either option record.  The local model does not prove that
  every historical ledger entry has such provenance.  Applying an intrinsic
  result to passive offers, offer updates, or offers that survived earlier
  protocol migrations or an administrative upgrade pass additionally requires
  a reachability argument that those live entries satisfy the intrinsic
  invariant.  In real ledger state,
  the local assumption @{const maker_covers_offer_liabilities} is supplied by
  the global invariant relating aggregate liabilities to all open offers.
\<close>

subsection \<open>Counterexample-first executable probes\<close>

definition migration_probe_maker :: party_state where
  "migration_probe_maker =
    \<lparr>sell_balance = 8, sell_liabilities = 0,
     buy_limit = 32, buy_balance = 0, buy_liabilities = 0\<rparr>"

definition small_upgrade_case ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> bool"
  where
    "small_upgrade_case price_n price_d amount \<longleftrightarrow>
      (case post_offer price_n price_d amount migration_probe_maker
          legacy_exchange_options of
         Cxx_Ok (Post_Created posted maker_after) \<Rightarrow>
           stored_offer price_n price_d posted \<and>
           party_state_wf maker_after \<and>
           maker_covers_offer_liabilities price_n price_d posted
             maker_after \<and>
           (case cross_offer_v10 price_n price_d posted maker_after
               maximum_capacity_taker int64_max Exchange_Normal
               repaired_exchange_options of
              Cxx_Ok crossed \<Rightarrow>
                cross_wheat_received crossed = posted \<and>
                0 < sint (cross_sheep_send crossed) \<and>
                \<not> cross_wheat_stays crossed \<and>
                cross_offer_amount crossed = 0 \<and>
                party_state_wf (cross_maker crossed) \<and>
                party_state_wf (cross_taker crossed)
            | Cxx_Err _ \<Rightarrow> False)
       | _ \<Rightarrow> True)"

text \<open>
  This bounded search covers all positive price numerators, denominators, and
  amounts from one through four.  Every created legacy offer in that grid is
  an unlimited legacy fixed point, its acquired maker state is well formed and
  covers the stored liabilities, and a repaired maximum-capacity cross is a
  safe positive full take.  Thus the small search found no instance of the
  liability, preventative-adjustment, maximum-taker, invariant, or phantom-
  erasure failure classes.  Non-created requests are outside the implication,
  exactly as in the later provenance results.
\<close>

lemma bounded_small_upgrade_search:
  "list_all (\<lambda>price_n.
     list_all (\<lambda>price_d.
       list_all (\<lambda>amount.
         small_upgrade_case price_n price_d amount)
         ([1, 2, 3, 4] :: int64 list))
       ([1, 2, 3, 4] :: int32 list))
     ([1, 2, 3, 4] :: int32 list)"
text \<open>
  Proof sketch: execute the finite sixty-four-case grid against the bit-precise
  posting, liability, adjustment, crossing, and party-state functions.
\<close>
  by eval

text \<open>
  The first concrete boundary witness is the historical one-unit offer at
  price @{term "(101::int) / 100"}.  Its maker is exactly at both booked
  liabilities after an intervening balance increase.  The legacy crossing
  erased it at zero, whereas the repaired crossing transfers the stored unit
  and leaves both parties well formed.
\<close>

lemma legacy_alice_offer_crosses_safely_after_upgrade:
  "party_state_wf
      \<lparr>sell_balance = 1, sell_liabilities = 1,
       buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr> \<and>
   maker_covers_offer_liabilities 101 100 1
      \<lparr>sell_balance = 1, sell_liabilities = 1,
       buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr> \<and>
   (case cross_offer_v10 101 100 1
       \<lparr>sell_balance = 1, sell_liabilities = 1,
        buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>
       maximum_capacity_taker int64_max Exchange_Normal
       repaired_exchange_options of
      Cxx_Ok crossed \<Rightarrow>
        cross_wheat_received crossed = 1 \<and>
        cross_sheep_send crossed = 1 \<and>
        \<not> cross_wheat_stays crossed \<and>
        cross_offer_amount crossed = 0 \<and>
        party_state_wf (cross_maker crossed) \<and>
        party_state_wf (cross_taker crossed)
    | Cxx_Err _ \<Rightarrow> False)"
text \<open>
  Proof sketch: evaluate liability coverage, repaired exact-cap arithmetic,
  the four checked balance moves, and the final no-remainder record.
\<close>
  by eval

text \<open>
  A reciprocal-side witness exercises the symmetric repaired branch.  The
  resting offer is priced at one hundred sheep per one hundred one wheat.  A
  taker capped at ninety-nine units on both sides produces a positive
  ninety-nine-for-ninety-nine partial fill; the maker remains well formed and
  covers the positive remainder.
\<close>

lemma symmetric_repaired_branch_partial_remainder_probe:
  "(case post_offer 100 101 200
       \<lparr>sell_balance = 200, sell_liabilities = 0,
        buy_limit = 199, buy_balance = 0, buy_liabilities = 0\<rparr>
       legacy_exchange_options of
     Cxx_Ok (Post_Created posted maker_after) \<Rightarrow>
       (case cross_offer_v10 100 101 posted maker_after
           \<lparr>sell_balance = 99, sell_liabilities = 0,
            buy_limit = 99, buy_balance = 0, buy_liabilities = 0\<rparr>
           99 Exchange_Normal repaired_exchange_options of
          Cxx_Ok crossed \<Rightarrow>
            cross_wheat_received crossed = 99 \<and>
            cross_sheep_send crossed = 99 \<and>
            cross_wheat_stays crossed \<and>
            0 < sint (cross_offer_amount crossed) \<and>
            party_state_wf (cross_maker crossed) \<and>
            party_state_wf (cross_taker crossed) \<and>
            maker_covers_offer_liabilities 100 101
              (cross_offer_amount crossed) (cross_maker crossed)
        | Cxx_Err _ \<Rightarrow> False)
   | _ \<Rightarrow> False)"
text \<open>
  Proof sketch: execute legacy posting followed by a repaired constrained
  cross, including repaired post-trade adjustment and liability reacquisition.
\<close>
  by eval

text \<open>
  A particular incoming offer may still exchange nothing.  Here the maker has
  unrelated extra buying headroom, while a one-sheep incoming cap is too small
  for an integer unit at price @{term "(101::int) / 100"}.  The safe outcome
  keeps the covered resting unit; this is a particular-taker liveness limit,
  not a migration safety failure or an intrinsically frozen offer.
\<close>

lemma repaired_particular_taker_zero_fill_is_safe:
  "(case cross_offer_v10 101 100 1
       \<lparr>sell_balance = 1, sell_liabilities = 1,
        buy_limit = 3, buy_balance = 0, buy_liabilities = 1\<rparr>
       \<lparr>sell_balance = 1, sell_liabilities = 0,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr>
       1 Exchange_Normal repaired_exchange_options of
      Cxx_Ok crossed \<Rightarrow>
        cross_wheat_received crossed = 0 \<and>
        cross_sheep_send crossed = 0 \<and>
        cross_wheat_stays crossed \<and>
        cross_offer_amount crossed = 1 \<and>
        party_state_wf (cross_maker crossed) \<and>
        party_state_wf (cross_taker crossed) \<and>
        maker_covers_offer_liabilities 101 100 1 (cross_maker crossed)
    | Cxx_Err _ \<Rightarrow> False)"
text \<open>
  Proof sketch: evaluate the integer-rounding zero trade, the unchanged
  balance moves, repaired remainder adjustment, and liability reacquisition.
\<close>
  by eval

text \<open>
  The two path-payment modes are exercised separately from normal mode.  With
  a maximum-capacity taker they both fully consume a representative legacy
  fixed point and cannot bypass the final cap checks.
\<close>

lemma repaired_strict_mode_full_take_probes:
  "(\<forall>rounding \<in>
      {Exchange_Strict_Send, Exchange_Strict_Receive}.
     case cross_offer_v10 3 2 4
         \<lparr>sell_balance = 4, sell_liabilities = 4,
          buy_limit = 6, buy_balance = 0, buy_liabilities = 6\<rparr>
         maximum_capacity_taker int64_max rounding
         repaired_exchange_options of
       Cxx_Ok crossed \<Rightarrow>
         cross_wheat_received crossed = 4 \<and>
         0 < sint (cross_sheep_send crossed) \<and>
         \<not> cross_wheat_stays crossed \<and>
         cross_offer_amount crossed = 0 \<and>
         party_state_wf (cross_maker crossed) \<and>
         party_state_wf (cross_taker crossed)
     | Cxx_Err _ \<Rightarrow> False)"
text \<open>
  Proof sketch: enumerate the two strict rounding constructors and execute
  both complete repaired crossings.
\<close>
  by eval

text \<open>
  Finally, equality and fixed-point evaluation at the largest signed words
  exercises the retained saturation clamp rather than only small arithmetic.
\<close>

lemma signed_saturation_upgrade_probe:
  "stored_offer 2147483647 2147483647 int64_max \<and>
   exchange_v10_without_price_error_thresholds_with_options
       2147483647 2147483647 int64_max int64_max int64_max int64_max
       Exchange_Normal repaired_exchange_options =
     exchange_v10_without_price_error_thresholds_with_options
       2147483647 2147483647 int64_max int64_max int64_max int64_max
       Exchange_Normal legacy_exchange_options"
text \<open>
  Proof sketch: execute both unlimited calculations at maximal signed price
  and amount, where the products require the modeled unsigned wide arithmetic.
\<close>
  by eval

subsection \<open>Dependency map for the migration proofs\<close>

text \<open>
  The results below apply the stored-offer theory to offers posted at
  protocol 28.  They reuse @{const stored_offer},
  @{thm [source] legacy_positive_adjustment_replays_unlimited},
  @{thm [source] stored_offer_repaired_adjust_stable},
  @{thm [source] stored_offer_nonstaying_repaired_cross_is_full_take},
  @{thm [source] stored_offer_has_safe_full_cross_repaired},
  @{thm [source] stored_offer_repaired_cross_preserves_invariants},
  @{thm [source] repaired_cross_remainder_remains_safely_takeable}, and
  @{thm [source] buy_post_created_is_stored_offer}.  The lifecycle results
  those proofs rely on are listed at the start of the stored-offer theory.
\<close>

subsection \<open>Offers posted at protocol 28\<close>

text \<open>
  A successful protocol-28 @{const post_offer} establishes the stored-offer
  invariant.  Composed with the stored-offer theory, this gives preventative
  adjustment stability, the absence of a phantom full take, and an
  existential safe full take for the posted offer at protocol 29.
\<close>

lemma legacy_post_created_is_stored_offer:
  assumes maker_wf: "party_state_wf maker_at_post"
    and post:
      "post_offer price_n price_d amount maker_at_post
         legacy_exchange_options =
       Cxx_Ok (Post_Created posted maker_after)"
  shows "stored_offer price_n price_d posted"
text \<open>
  Proof sketch: invert the created posting branch to recover its positive
  legacy adjustment and the actual posted amount.  Well-formedness makes both
  posting capacities non-negative.
  @{thm [source] legacy_positive_adjustment_replays_unlimited} lifts that
  positive result to the unlimited legacy fixed point, while the created-
  outcome facts supply positivity of the price and stored amount.
\<close>
proof -
  note positive = post_created_positive_facts [OF post]
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and posted_positive: "0 < sint posted"
    using positive by simp_all
  note post' = post[unfolded post_offer_def preflight_offer_def Let_def]
  obtain requested_buying where requested_buying:
      "offer_buying_liabilities price_n price_d amount =
       Cxx_Ok requested_buying"
    using post'
    by (cases "offer_buying_liabilities price_n price_d amount")
       (simp_all split: if_splits)
  obtain requested_selling where requested_selling:
      "offer_selling_liabilities price_n price_d amount =
       Cxx_Ok requested_selling"
    using post' requested_buying
    by (cases "offer_selling_liabilities price_n price_d amount")
       (simp_all split: if_splits)
  obtain adjusted where adjustment:
      "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) legacy_exchange_options =
       Cxx_Ok adjusted"
    using post' requested_buying requested_selling
    by (cases "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) legacy_exchange_options")
       (simp_all split: if_splits)
  obtain acquired where acquire:
      "acquire_offer_liabilities price_n price_d adjusted maker_at_post =
       Cxx_Ok acquired"
    using post' requested_buying requested_selling adjustment
    by (cases "acquire_offer_liabilities price_n price_d adjusted
         maker_at_post")
       (simp_all split: if_splits)
  have adjusted_posted: "adjusted = posted"
    using post' requested_buying requested_selling adjustment acquire
    by (simp split: if_splits)
  have send_nonnegative:
      "0 \<le> sint
        (signed_min64 amount (can_sell_at_most maker_at_post))"
    using amount_positive can_sell_at_most_nonnegative [OF maker_wf]
    by (auto simp add: signed_min64_def split: if_splits)
  have receive_nonnegative:
      "0 \<le> sint (can_buy_at_most maker_at_post)"
    using can_buy_at_most_nonnegative [OF maker_wf] .
  have unlimited:
      "adjust_offer_with_options price_n price_d posted int64_max
         legacy_exchange_options = Cxx_Ok posted"
    using legacy_positive_adjustment_replays_unlimited
      [OF pn pd send_nonnegative receive_nonnegative adjustment]
      posted_positive adjusted_posted
    by simp
  show ?thesis
    using pn pd posted_positive unlimited
    by (simp add: stored_offer_def)
qed

theorem legacy_post_cover_implies_repaired_adjust_stable:
  assumes post_wf: "party_state_wf maker_at_post"
    and cross_wf: "party_state_wf maker_at_cross"
    and post:
      "post_offer price_n price_d amount maker_at_post
         legacy_exchange_options =
       Cxx_Ok (Post_Created posted maker_after)"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and release:
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released"
  shows
    "adjust_stable price_n price_d posted released
       repaired_exchange_options"
text \<open>
  Proof sketch: legacy posting establishes the intrinsic stored-offer
  invariant, after which the cross-version stability theorem uses only the
  crossing-time well-formedness, coverage, and actual release result.
\<close>
  using stored_offer_repaired_adjust_stable
    [OF legacy_post_created_is_stored_offer [OF post_wf post]
      cross_wf cover release] .

theorem legacy_fully_taken_posted_offer_exchanges_posted_amount_repaired:
  assumes post_wf: "party_state_wf maker_at_post"
    and cross_wf: "party_state_wf maker_at_cross"
    and post:
      "post_offer price_n price_d amount maker_at_post
         legacy_exchange_options =
       Cxx_Ok (Post_Created posted maker_after)"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and cross:
      "cross_offer_v10 price_n price_d posted maker_at_cross taker
         taker_amount rounding repaired_exchange_options = Cxx_Ok crossed"
    and nonstaying: "\<not> cross_wheat_stays crossed"
  shows
    "cross_wheat_received crossed = posted \<and>
     cross_offer_amount crossed = 0"
text \<open>
  Proof sketch: legacy posting establishes the intrinsic fixed point;
  @{thm [source] stored_offer_nonstaying_repaired_cross_is_full_take} then
  applies to the independently supplied covered
  crossing state, arbitrary taker, and arbitrary rounding mode.
\<close>
  using stored_offer_nonstaying_repaired_cross_is_full_take
    [OF legacy_post_created_is_stored_offer [OF post_wf post]
      cross_wf cover cross nonstaying] .

corollary legacy_posted_offer_has_safe_full_cross_repaired:
  assumes post_wf: "party_state_wf maker_at_post"
    and cross_wf: "party_state_wf maker_at_cross"
    and post:
      "post_offer price_n price_d amount maker_at_post
         legacy_exchange_options =
       Cxx_Ok (Post_Created posted maker_after)"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
  shows
    "\<exists>crossed.
      cross_offer_v10 price_n price_d posted maker_at_cross
        maximum_capacity_taker int64_max Exchange_Normal
        repaired_exchange_options = Cxx_Ok crossed \<and>
      cross_wheat_received crossed = posted \<and>
      0 < sint (cross_sheep_send crossed) \<and>
      \<not> cross_wheat_stays crossed \<and>
      cross_offer_amount crossed = 0 \<and>
      party_state_wf (cross_maker crossed) \<and>
      party_state_wf (cross_taker crossed)"
text \<open>
  Proof sketch: successful legacy ManageSell posting establishes the intrinsic
  stored-offer premise, and the existential theorem uses only the later
  well-formed covered maker state.
\<close>
  using stored_offer_has_safe_full_cross_repaired
    [OF legacy_post_created_is_stored_offer [OF post_wf post]
      cross_wf cover] .

subsection \<open>Reachability boundary\<close>

text \<open>
  The intrinsic theorems of the stored-offer theory apply to an offer from
  any origin once @{const stored_offer} is established.  This theory
  proves that provenance for every successful modeled legacy
  @{const post_offer}, which is the ManageSell creation route, and the
  stored-offer theory proves it for every positive legacy or repaired
  crossing remainder.  Neither derivation uses any overlay-admission filter:
  a successful posting already yields the unlimited legacy fixed point.

  ManageBuy creation is a separate route, because @{const post_buy_offer}
  inverts the submitted price and computes its request-time liabilities from
  the finite buy amount rather than from an unlimited receive cap.  The
  stored-offer theory establishes its provenance separately, as
  @{thm [source] buy_post_created_is_stored_offer}.

  Applying the intrinsic results to arbitrary historical ledger entries still
  assumes the real ledger's global liabilities-match-offers invariant, which
  supplies local @{const maker_covers_offer_liabilities}, and a protocol-upgrade
  reachability argument that every live entry came from a covered modeled
  origin or otherwise satisfies @{const stored_offer}.  Native reserve,
  authorization, sponsorship, order-book selection, and aggregation across
  multiple offers remain outside this single-offer lifecycle model.  Thus the
  results establish the arithmetic and local-ledger migration obligation, not
  by themselves the complete network-state reachability argument.
\<close>


section \<open>The migration ladder at the real protocol boundary\<close>

text \<open>
  The ladder above and the stored-offer results are phrased with
  @{const legacy_exchange_options} for creation and provenance and
  @{const repaired_exchange_options} for adjustment and crossing.  Those are exactly the two configurations
  @{const exchange_options_at_version} selects, and
  @{thm [source] exchange_options_at_version_legacy} and
  @{thm [source] exchange_options_at_version_repaired} are simplification
  rules, so each of those theorems applies verbatim once a ledger
  version and its side of the boundary are known.

  The definitions below name the two sides, and the corollaries restate the
  two load-bearing results in those terms: the universal safety of a
  protocol-29 cross of a protocol-28 offer, and the existence of a
  counterparty that takes such an offer completely.
\<close>

definition ledger_version_before_v29 :: "uint32 \<Rightarrow> bool"
  where
    "ledger_version_before_v29 ledger_version \<longleftrightarrow>
       \<not> protocol_version_starts_from ledger_version protocol_version_v29"

definition ledger_version_from_v29 :: "uint32 \<Rightarrow> bool"
  where
    "ledger_version_from_v29 ledger_version \<longleftrightarrow>
       protocol_version_starts_from ledger_version protocol_version_v29"

lemma options_before_v29 [simp]:
  "ledger_version_before_v29 ledger_version \<Longrightarrow>
   exchange_options_at_version ledger_version = legacy_exchange_options"
  by (simp add: ledger_version_before_v29_def)

lemma options_from_v29 [simp]:
  "ledger_version_from_v29 ledger_version \<Longrightarrow>
   exchange_options_at_version ledger_version = repaired_exchange_options"
  by (simp add: ledger_version_from_v29_def)

definition stored_offer_created_before_v29 ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> bool"
  where
    "stored_offer_created_before_v29 creation_version price_n price_d
        posted \<longleftrightarrow>
       0 < sint price_n \<and>
       0 < sint price_d \<and>
       0 < sint posted \<and>
       adjust_offer creation_version price_n price_d posted int64_max =
         Cxx_Ok posted"

text \<open>
  @{const stored_offer_created_before_v29} is the intrinsic stored-offer
  invariant expressed through the protocol-facing @{const adjust_offer}: a
  positive stored amount that a pre-29 unlimited adjustment leaves unchanged.
  It is @{const stored_offer} with the option record replaced by the
  ledger version that selects it.
\<close>

lemma stored_offer_created_before_v29_eq [simp]:
  "ledger_version_before_v29 creation_version \<Longrightarrow>
   stored_offer_created_before_v29 creation_version price_n price_d posted =
   stored_offer price_n price_d posted"
  by (simp add: stored_offer_created_before_v29_def stored_offer_def
      adjust_offer_def)

corollary p28_offer_crossed_at_p29_preserves_invariants:
  assumes creation: "ledger_version_before_v29 creation_version"
    and activation: "ledger_version_from_v29 crossing_version"
    and stored:
      "stored_offer_created_before_v29 creation_version price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and taker_wf: "party_state_wf taker"
    and cross:
      "cross_offer_v10 price_n price_d posted maker_at_cross taker
         taker_amount rounding
         (exchange_options_at_version crossing_version) = Cxx_Ok crossed"
  shows "party_state_wf (cross_maker crossed) \<and>
      party_state_wf (cross_taker crossed)"
  \<comment> \<open>Every successful protocol-29 cross of a covered protocol-28 offer leaves
    both parties well formed.\<close>
  text \<open>
    Proof sketch: the activation hypothesis turns the versioned options into
    the repaired record, and the ladder's successful-cross safety theorem
    applies to the resulting call unchanged.
  \<close>
proof -
  have legacy: "stored_offer price_n price_d posted"
    using stored creation by simp
  show ?thesis
    using stored_offer_repaired_cross_preserves_invariants
      [OF legacy maker_wf cover taker_wf] cross activation
    by simp
qed

corollary p28_stored_offer_has_safe_full_cross_at_p29:
  assumes creation: "ledger_version_before_v29 creation_version"
    and activation: "ledger_version_from_v29 crossing_version"
    and stored:
      "stored_offer_created_before_v29 creation_version price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
  shows
    "\<exists>crossed.
      cross_offer_v10 price_n price_d posted maker_at_cross
        maximum_capacity_taker int64_max Exchange_Normal
        (exchange_options_at_version crossing_version) = Cxx_Ok crossed \<and>
      cross_wheat_received crossed = posted \<and>
      0 < sint (cross_sheep_send crossed) \<and>
      \<not> cross_wheat_stays crossed \<and>
      cross_offer_amount crossed = 0 \<and>
      party_state_wf (cross_maker crossed) \<and>
      party_state_wf (cross_taker crossed)"
  \<comment> \<open>Every covered protocol-28 stored offer still has a maximum-capacity
    protocol-29 counterparty that takes it completely.\<close>
  text \<open>
    Proof sketch: as above, the activation hypothesis reduces the versioned
    options to the repaired record and the ladder's existential full-take
    theorem supplies the witness.
  \<close>
proof -
  have legacy: "stored_offer price_n price_d posted"
    using stored creation by simp
  show ?thesis
    using stored_offer_has_safe_full_cross_repaired
      [OF legacy maker_wf cover] activation
    by simp
qed

corollary p29_cross_remainder_remains_safely_takeable:
  assumes creation: "ledger_version_before_v29 creation_version"
    and activation: "ledger_version_from_v29 crossing_version"
    and stored:
      "stored_offer_created_before_v29 creation_version price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and taker_wf: "party_state_wf taker"
    and cross:
      "cross_offer_v10 price_n price_d posted maker_at_cross taker
         taker_amount rounding
         (exchange_options_at_version crossing_version) = Cxx_Ok crossed"
    and remainder_positive: "0 < sint (cross_offer_amount crossed)"
  shows
    "maker_covers_offer_liabilities price_n price_d
       (cross_offer_amount crossed) (cross_maker crossed) \<and>
     (\<exists>next.
       cross_offer_v10 price_n price_d (cross_offer_amount crossed)
         (cross_maker crossed) maximum_capacity_taker int64_max
         Exchange_Normal (exchange_options_at_version crossing_version) =
         Cxx_Ok next \<and>
       cross_wheat_received next = cross_offer_amount crossed \<and>
       0 < sint (cross_sheep_send next) \<and>
       \<not> cross_wheat_stays next \<and>
       cross_offer_amount next = 0 \<and>
       party_state_wf (cross_maker next) \<and>
       party_state_wf (cross_taker next))"
  \<comment> \<open>A positive remainder left by a protocol-29 cross of a protocol-28 offer
    is itself covered, and is taken completely by a maximum-capacity
    counterparty.\<close>
  text \<open>
    Proof sketch: the activation hypothesis reduces the versioned options to
    the repaired record, and the ladder's remainder-closure theorem then
    applies to the resulting call unchanged.
  \<close>
proof -
  have legacy: "stored_offer price_n price_d posted"
    using stored creation by simp
  show ?thesis
    using repaired_cross_remainder_remains_safely_takeable
      [OF legacy maker_wf cover taker_wf] cross remainder_positive activation
    by simp
qed

text \<open>
  \<^bold>\<open>Reachability.\<close>  The corollaries above assume
  @{const stored_offer}, the intrinsic stored-offer invariant, and
  @{const maker_covers_offer_liabilities}.  The first is established for
  the modeled fresh manage-sell route by
  @{thm [source] legacy_post_created_is_stored_offer} from a successful
  protocol-28 @{const post_offer}, for manage-buy creation by
  @{thm [source] buy_post_created_is_stored_offer}, and for any positive
  remainder of a successful crossing by
  @{thm [source] legacy_positive_cross_remainder_is_stored_offer} and
  @{thm [source] repaired_positive_cross_remainder_is_stored_offer}; the last
  three are in the stored-offer theory.  It is \<^emph>\<open>not\<close> established for
  passive sell offers, offer updates, or offers that survived earlier
  protocol migrations or an administrative upgrade pass.
  Applying these results to such an entry requires a separate argument that it
  satisfies the intrinsic invariant.

  The second assumption is supplied in real execution by the global
  liabilities-match-offers invariant.  The local model does not prove that
  global invariant, so these are local safety results about a covered offer,
  not a proof of complete network migration safety.  The missing induction
  over historical ledger state is recorded as follow-up work.
\<close>


section \<open>The ManageBuy route at protocol 29\<close>

text \<open>
  The ladder assumes only @{const stored_offer}, whatever route created the
  offer, but the protocol-28 corollaries above discharge that premise through
  @{const post_offer}, the ManageSell route.  The stored-offer theory
  establishes the invariant for
  offers created by @{const post_buy_offer} at any ledger version, as
  @{thm [source] buy_post_created_is_stored_offer}.  The probes below test
  ManageBuy-created offers on both sides of the boundary, and the
  corollaries apply the ladder to them.
\<close>

subsection \<open>Counterexample-first executable probes\<close>

definition small_buy_upgrade_case ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> bool"
  where
    "small_buy_upgrade_case ledger_version price_n price_d buy_amount \<longleftrightarrow>
      (case post_buy_offer ledger_version price_n price_d buy_amount
          migration_probe_maker of
         Cxx_Ok (Post_Created posted maker_after) \<Rightarrow>
           stored_offer price_d price_n posted \<and>
           party_state_wf maker_after \<and>
           maker_covers_offer_liabilities price_d price_n posted
             maker_after \<and>
           (case cross_offer_v10 price_d price_n posted maker_after
               maximum_capacity_taker int64_max Exchange_Normal
               (exchange_options_at_version ledger_version) of
              Cxx_Ok crossed \<Rightarrow>
                cross_wheat_received crossed = posted \<and>
                0 < sint (cross_sheep_send crossed) \<and>
                \<not> cross_wheat_stays crossed \<and>
                cross_offer_amount crossed = 0 \<and>
                party_state_wf (cross_maker crossed) \<and>
                party_state_wf (cross_taker crossed)
            | Cxx_Err _ \<Rightarrow> False)
       | _ \<Rightarrow> True)"

text \<open>
  @{const small_buy_upgrade_case} is the ManageBuy counterpart of
  @{const small_upgrade_case}.  It differs in the three ways the buy route
  differs: the request goes through @{const post_buy_offer} so its liabilities
  are the versioned ManageBuy ones and its receive cap is the requested buy
  amount, every stored-offer claim is made at the inverted price
  @{term "(price_d, price_n)"}, and the crossing options come from the same
  ledger version rather than being fixed.  The search below therefore probes
  the created offer for the same five failure classes on both sides of the
  boundary at once.
\<close>

lemma bounded_small_buy_upgrade_search:
  "list_all (\<lambda>ledger_version.
     list_all (\<lambda>price_n.
       list_all (\<lambda>price_d.
         list_all (\<lambda>buy_amount.
           small_buy_upgrade_case ledger_version price_n price_d buy_amount)
           ([1, 2, 3, 4] :: int64 list))
         ([1, 2, 3, 4] :: int32 list))
       ([1, 2, 3, 4] :: int32 list))
     ([28, 29] :: uint32 list)"
text \<open>
  Proof sketch: execute the finite one-hundred-and-twenty-eight-case grid
  against the bit-precise ManageBuy posting, liability, adjustment, crossing,
  and party-state functions.
\<close>
  by eval

text \<open>
  The grid is not vacuous: eighty-five of its one hundred and twenty-eight
  requests create an offer, so the conjunction above is actually tested.  The
  two witnesses below pin that down for a single case on the protocol-29 side,
  where the created offer rests at the inverted price @{term "(2::int)"} over
  @{term "(3::int)"} and the maximum-capacity counterparty takes it whole.
\<close>

lemma post_buy_offer_created_at_v29_witness:
  "post_buy_offer 29 3 2 4 migration_probe_maker =
   Cxx_Ok (Post_Created 6
     \<lparr>sell_balance = 8, sell_liabilities = 6,
      buy_limit = 32, buy_balance = 0, buy_liabilities = 4\<rparr>)"
text \<open>
  Proof sketch: evaluate the executable ManageBuy posting path at protocol 29.
\<close>
  by eval

lemma small_buy_upgrade_case_v29_witness:
  "small_buy_upgrade_case 29 3 2 4"
text \<open>
  Proof sketch: evaluate the probe on the created case above.
\<close>
  by eval

subsection \<open>ManageBuy-created offers crossed at protocol 29\<close>

text \<open>
  @{thm [source] buy_post_created_is_stored_offer} holds at every ledger
  version, not just before protocol 29, because the intrinsic invariant is
  about the \<^emph>\<open>stored\<close> projection and both configurations of the adjustment
  produce a legacy unlimited fixed point when they succeed positively.  Unlike
  @{thm [source] legacy_post_created_is_stored_offer}, which is stated for
  ManageSell posting in the legacy configuration, it covers every creation
  version and needs no well-formedness assumption on the posting state.  The request-time liabilities remain genuinely
  version-dependent, as
  @{thm [source] manage_buy_request_liabilities_change_at_activation} records;
  they influence \<^emph>\<open>whether\<close> a buy request is admitted, not what the created
  offer looks like once it is.

  With provenance in hand, every ladder theorem applies to a ManageBuy-created
  offer verbatim.  The two load-bearing ones are restated below.
\<close>

corollary buy_post_created_offer_has_safe_full_cross_at_p29:
  assumes post:
      "post_buy_offer creation_version price_n price_d buy_amount
         maker_at_post = Cxx_Ok (Post_Created posted maker_after)"
    and activation: "ledger_version_from_v29 crossing_version"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_d price_n posted maker_at_cross"
  shows
    "\<exists>crossed.
      cross_offer_v10 price_d price_n posted maker_at_cross
        maximum_capacity_taker int64_max Exchange_Normal
        (exchange_options_at_version crossing_version) = Cxx_Ok crossed \<and>
      cross_wheat_received crossed = posted \<and>
      0 < sint (cross_sheep_send crossed) \<and>
      \<not> cross_wheat_stays crossed \<and>
      cross_offer_amount crossed = 0 \<and>
      party_state_wf (cross_maker crossed) \<and>
      party_state_wf (cross_taker crossed)"
  \<comment> \<open>A covered ManageBuy-created offer still has a maximum-capacity
    protocol-29 counterparty that takes it completely.\<close>
text \<open>
  Proof sketch: buy provenance gives the intrinsic invariant at the inverted
  price, the activation hypothesis reduces the versioned options to the
  repaired record, and the ladder's existential full-take theorem supplies the
  witness.
\<close>
  using stored_offer_has_safe_full_cross_repaired
    [OF buy_post_created_is_stored_offer [OF post] maker_wf cover] activation
  by simp

corollary buy_post_created_offer_crossed_at_p29_preserves_invariants:
  assumes post:
      "post_buy_offer creation_version price_n price_d buy_amount
         maker_at_post = Cxx_Ok (Post_Created posted maker_after)"
    and activation: "ledger_version_from_v29 crossing_version"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_d price_n posted maker_at_cross"
    and taker_wf: "party_state_wf taker"
    and cross:
      "cross_offer_v10 price_d price_n posted maker_at_cross taker
         taker_amount rounding
         (exchange_options_at_version crossing_version) = Cxx_Ok crossed"
  shows "party_state_wf (cross_maker crossed) \<and>
      party_state_wf (cross_taker crossed)"
  \<comment> \<open>Every successful protocol-29 cross of a covered ManageBuy-created offer
    leaves both parties well formed.\<close>
text \<open>
  Proof sketch: as above, with the ladder's successful-cross safety theorem in
  place of the existential full take.
\<close>
  using stored_offer_repaired_cross_preserves_invariants
    [OF buy_post_created_is_stored_offer [OF post] maker_wf cover taker_wf]
    cross activation
  by simp

end
