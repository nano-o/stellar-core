theory Offer_Exchange_Migration
  imports Offer_Exchange_Lifecycle
begin

section \<open>Exact-cap protocol migration\<close>

text \<open>
  This theory studies a protocol boundary rather than a same-version
  lifecycle.  A resting offer may have been admitted and had its liabilities
  acquired using @{const legacy_exchange_options}; after activation, liability
  release is still flag-free, while preventative adjustment and
  @{const cross_offer_v10} use @{const repaired_exchange_options}.  The target
  is to show that every covered old offer satisfying an intrinsic stored-offer
  invariant remains safe to cross and has a maximum-capacity full-take witness.

  The local model does not prove that every historical ledger entry has such
  provenance.  A theorem derived from a successful legacy @{const post_offer}
  covers the modeled fresh manage-sell route.  Applying an intrinsic result to
  offers created by other operation variants, passive offers, updates, or
  partial-fill remainders additionally requires a reachability argument that
  those live entries satisfy the intrinsic invariant.  In real ledger state,
  the local assumption @{const maker_covers_offer_liabilities} is supplied by
  the global invariant relating aggregate liabilities to all open offers.
\<close>

definition legacy_stored_offer ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> bool" where
  "legacy_stored_offer price_n price_d posted \<longleftrightarrow>
     0 < sint price_n \<and>
     0 < sint price_d \<and>
     0 < sint posted \<and>
     adjust_offer_with_options price_n price_d posted int64_max
       legacy_exchange_options = Cxx_Ok posted"

text \<open>
  @{const legacy_stored_offer} is deliberately offer-local: it records positive
  price components, a positive stored amount, and the unlimited legacy
  adjustment fixed point that crossing needs.  It does not duplicate
  @{const adjust_stable}, which also depends on a particular party state and
  its current capacities.  The same unlimited fixed-point equation already
  occurs as premises or conclusions of lifecycle lemmas, but the imported
  theories do not give that conjunction a name.

  The following evaluations cover the legacy Alice offer from
  @{thm [source] alice_posts_her_offer} and the non-unit three-halves resting
  offer used by @{thm [source]
  fully_taken_incoming_offer_positive_partial_witness}.  They confirm that the
  intrinsic predicate accepts representative existing witnesses on both the
  near-unit and larger-price cases.
\<close>

lemma legacy_stored_offer_representative_examples:
  "legacy_stored_offer 101 100 1"
  "legacy_stored_offer 3 2 4"
text \<open>
  Proof sketch: unfold the executable predicate and evaluate the two positive
  unlimited legacy adjustments.
\<close>
  by (eval, eval)

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
           legacy_stored_offer price_n price_d posted \<and>
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
  "legacy_stored_offer 2147483647 2147483647 int64_max \<and>
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
  The substantive proof should reuse the following imported results rather
  than unfold the bit-precise arithmetic again.

  \<^item> Protocol boundary and provenance: @{const legacy_exchange_options},
    @{const repaired_exchange_options}, @{const post_offer},
    @{const post_buy_offer}, @{const cross_offer_v10}, and @{thm [source]
    post_created_positive_facts}.  Legacy request routes can additionally use
    @{thm [source] post_offer_request_created_facts}.  The unlimited fixed
    point of a successful legacy posting comes from the legacy replay lemma
    proved below, with no admission filter involved.

  \<^item> Persistent liabilities and preventative adjustment:
    @{thm [source] offer_liabilities_result}, @{thm [source]
    covered_offer_release}, @{thm [source]
    unlimited_positive_adjustment_identifies_liabilities}, @{thm [source]
    exact_cap_replays_unlimited_positive_adjustment}, and @{thm [source]
    adjust_offer_symmetric_irrelevant}.  The same-version packaging in
    @{thm [source] cover_implies_adjust_stable_exact_any_symmetric} is a useful
    proof template, but its posting premise must not be reused as if it crossed
    a protocol boundary.

  \<^item> Option compatibility at unlimited caps: @{thm [source]
    exchange_v10_amounts_exact_irrelevant_if_not_wheat_more}, @{thm [source]
    exchange_v10_exact_irrelevant_if_not_wheat_more}, @{thm [source]
    exchange_v10_amounts_symmetric_irrelevant_if_not_wheat_stays}, and
    @{thm [source] exact_receive_cap_value_int}.  The repaired integer
    characterizations @{thm [source]
    exchange_v10_without_repaired_integer_characterization} and @{thm [source]
    exchange_v10_repaired_integer_characterization} expose the retained
    saturation clamp when a direct compatibility proof needs it.

  \<^item> Successful-cross safety: @{thm [source]
    exchange_without_thresholds_bounds_any_cap}, @{thm [source]
    exchange_normal_positive_result_bounds_any_cap}, @{thm [source]
    party_receive_within_capacity}, @{thm [source]
    party_spend_within_capacity}, and @{thm [source]
    successful_nonstaying_cross_fields}.  These separate cap safety and checked
    party updates from the repaired branch arithmetic.

  \<^item> Full-take and existential witness: @{thm [source]
    exchange_v10_nonstaying_matches_positive_adjustment}, @{thm [source]
    exchange_against_unlimited_counterparty_does_not_leave_wheat}, @{thm
    [source] maximum_capacity_taker_equations}, and the proof structure of
    @{thm [source]
    fully_taken_posted_offer_exchanges_posted_amount_exact_any_symmetric}.
\<close>

subsection \<open>Persistent liability compatibility\<close>

lemma unrestricted_repaired_amounts_match_legacy:
  assumes wheat_value:
      "calculate_offer_value price_n price_d posted int64_max =
       Cxx_Ok wheat_value"
    and sheep_value:
      "calculate_offer_value price_d price_n int64_max int64_max =
       Cxx_Ok sheep_value"
  shows
  "exchange_v10_amounts price_n price_d wheat_value sheep_value posted
      int64_max int64_max int64_max wheat_stays Exchange_Normal
      repaired_exchange_options =
   exchange_v10_amounts price_n price_d wheat_value sheep_value posted
      int64_max int64_max int64_max wheat_stays Exchange_Normal
      legacy_exchange_options"
text \<open>
  Proof sketch: split on the stored-offer side and relative price order.  The
  two option-sensitive branches then use an unrestricted receive cap, where
  the retained clamp makes the exact value equal the plain value.
\<close>
  by (cases wheat_stays;
      cases "sint price_n > sint price_d";
      simp add: exchange_v10_amounts_def repaired_exchange_options_def
        legacy_exchange_options_def
        exact_receive_cap_collapses_at_unlimited_receive wheat_value
        sheep_value)

lemma unrestricted_repaired_exchange_matches_legacy:
  "exchange_v10_without_price_error_thresholds_with_options
      price_n price_d posted int64_max int64_max int64_max
      Exchange_Normal repaired_exchange_options =
   exchange_v10_without_price_error_thresholds_with_options
      price_n price_d posted int64_max int64_max int64_max
      Exchange_Normal legacy_exchange_options"
text \<open>
  Proof sketch: both option-sensitive receive caps are the signed maximum.
  The retained global clamp therefore collapses each relaxed offer-value call
  to its plain counterpart, after which both branch calculations and final
  bounds checks are syntactically identical.
\<close>
proof (cases
    "calculate_offer_value price_n price_d posted int64_max")
  case (Cxx_Err error)
  then show ?thesis
    by (simp add: exchange_v10_without_price_error_thresholds_with_options_def)
next
  case wheat_ok: (Cxx_Ok wheat_value)
  show ?thesis
  proof (cases
      "calculate_offer_value price_d price_n int64_max int64_max")
    case (Cxx_Err error)
    then show ?thesis
      using wheat_ok
      by (simp add: exchange_v10_without_price_error_thresholds_with_options_def)
  next
    case sheep_ok: (Cxx_Ok sheep_value)
    have amounts:
      "exchange_v10_amounts price_n price_d wheat_value sheep_value posted
          int64_max int64_max int64_max (wheat_value > sheep_value)
          Exchange_Normal repaired_exchange_options =
       exchange_v10_amounts price_n price_d wheat_value sheep_value posted
          int64_max int64_max int64_max (wheat_value > sheep_value)
          Exchange_Normal legacy_exchange_options"
      using unrestricted_repaired_amounts_match_legacy
        [OF wheat_ok sheep_ok] .
    show ?thesis
      using wheat_ok sheep_ok amounts
      by (simp add: exchange_v10_without_price_error_thresholds_with_options_def Let_def)
  qed
qed

corollary unrestricted_repaired_adjustment_matches_legacy:
  "adjust_offer_with_options price_n price_d posted int64_max
      repaired_exchange_options =
   adjust_offer_with_options price_n price_d posted int64_max
      legacy_exchange_options"
text \<open>
  Proof sketch: adjustment projects the wheat field of the unrestricted
  normal exchange, so the preceding cross-version equality applies directly.
\<close>
  using unrestricted_repaired_exchange_matches_legacy
  by (simp add: adjust_offer_with_options_def exchange_v10_with_options_def)

text \<open>
  Stored liabilities themselves remain option-free.  The preceding results
  additionally show that explicitly threading both repaired flags through an
  unrestricted projection would compute the same exchange record as the
  legacy projection; this is the clamp-dependent protocol-boundary fact.
\<close>

subsection \<open>Legacy stored-offer provenance\<close>

lemma legacy_positive_adjustment_replays_unlimited:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_nonnegative: "0 \<le> sint max_wheat"
    and sheep_nonnegative: "0 \<le> sint max_sheep"
    and adjusted:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         legacy_exchange_options = Cxx_Ok result"
    and result_positive: "0 < sint result"
  shows "adjust_offer_with_options price_n price_d result int64_max
      legacy_exchange_options = Cxx_Ok result"
text \<open>
  Proof sketch: when wheat is not more valuable, the exact option is inert, so
  the established positive exact-adjustment replay theorem applies.  When
  wheat is more valuable, characterize the successful legacy result in
  integers.  Its wheat quotient proves that the returned amount-price product
  fits under the original receive cap and hence under the retained global
  clamp.  Replacing both caps by the signed maximum therefore reproduces the
  same amount pair and the same successful threshold decision.
\<close>
proof (cases "sint price_n > sint price_d")
  case not_more: False
  have exact_adjusted:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         \<lparr>exact_receive_cap = True,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"
    using adjusted adjust_offer_exact_irrelevant_if_not_wheat_more
      [OF not_more, of max_wheat max_sheep]
    by (simp add: legacy_exchange_options_def)
  show ?thesis
    using positive_adjustment_replays_unlimited
      [OF pn pd wheat_nonnegative sheep_nonnegative exact_adjusted
        result_positive]
    by (simp add: legacy_exchange_options_def)
next
  case wheat_more: True
  have pre:
      "exchange_v10_pre price_n price_d max_wheat int64_max int64_max
         max_sheep"
    using pn pd wheat_nonnegative sheep_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  let ?amounts =
    "exchange_v10_amounts_int price_n price_d max_wheat int64_max
       int64_max max_sheep Exchange_Normal"
  note characterization = exchange_v10_normal_characterization [OF pre]
  have result_word:
      "result = (word_of_int (fst ?amounts) :: int64)"
    using adjusted characterization result_positive
    by (auto simp add: legacy_exchange_options_def adjust_offer_with_options_def
        make_exchange_result_def Let_def split: if_splits)
  have result_condition:
      "0 < fst ?amounts \<and> 0 < snd ?amounts \<and>
       price_error_bound_spec price_n price_d
         (word_of_int (fst ?amounts))
         (word_of_int (snd ?amounts)) False"
    using adjusted characterization result_positive
    by (auto simp add: legacy_exchange_options_def adjust_offer_with_options_def
        make_exchange_result_def Let_def split: if_splits)
  have result_sint: "sint result = fst ?amounts"
    using result_word
      exchange_v10_amounts_integer_characterization(2)
        [OF pre, of Exchange_Normal]
    by simp
  have wheat_product_bounded:
      "sint max_wheat * sint price_n \<le>
       sint int64_max * sint price_n"
    using sint64_upper_bound[of max_wheat] less_imp_le[OF pn]
    by (simp add: int64_max_def mult_right_mono)
  have sheep_product_bounded:
      "sint max_sheep * sint price_d \<le>
       sint int64_max * sint price_d"
    using sint64_upper_bound[of max_sheep] less_imp_le[OF pd]
    by (simp add: int64_max_def mult_right_mono)
  have no_stays:
      "\<not> exchange_wheat_value_int price_n price_d max_wheat max_sheep >
       exchange_sheep_value_int price_n price_d int64_max int64_max"
    using wheat_product_bounded sheep_product_bounded
    by (simp add: exchange_wheat_value_int_def
        exchange_sheep_value_int_def min_def split: if_splits)
  have amounts_formula:
      "?amounts =
       (exchange_wheat_value_int price_n price_d max_wheat max_sheep
          div sint price_n,
        (exchange_wheat_value_int price_n price_d max_wheat max_sheep
          div sint price_n) * sint price_n div sint price_d)"
    unfolding exchange_v10_amounts_int_def
    using wheat_more no_stays
    by (simp add: Let_def)
  have result_formula:
      "sint result =
       exchange_wheat_value_int price_n price_d max_wheat max_sheep
         div sint price_n"
    using result_sint amounts_formula by simp
  have result_product_le_value:
      "sint result * sint price_n \<le>
       exchange_wheat_value_int price_n price_d max_wheat max_sheep"
    unfolding result_formula
    using int_div_mult_le [OF pn] .
  have result_product_le_cap:
      "sint result * sint price_n \<le> sint max_sheep * sint price_d"
    using result_product_le_value
    by (auto simp add: exchange_wheat_value_int_def intro: order_trans)
  have unsaturated:
      "sint result * sint price_n \<le>
       int64_max_int * sint price_d"
  proof -
    have "sint max_sheep * sint price_d \<le>
        int64_max_int * sint price_d"
      using mult_right_mono
        [OF sint64_upper_bound[of max_sheep] less_imp_le[OF pd]] .
    with result_product_le_cap show ?thesis
      by (rule order_trans)
  qed
  have full_pre:
      "exchange_v10_pre price_n price_d result int64_max int64_max
         int64_max"
    using pn pd result_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  have full_wheat_value:
      "exchange_wheat_value_int price_n price_d result int64_max =
       sint result * sint price_n"
    using unsaturated
    by (simp add: exchange_wheat_value_int_def int64_max_def min_def)
  have full_no_stays:
      "\<not> exchange_wheat_value_int price_n price_d result int64_max >
       exchange_sheep_value_int price_n price_d int64_max int64_max"
    using unsaturated wheat_more
    by (simp add: exchange_wheat_value_int_def
        exchange_sheep_value_int_def int64_max_def min_def
        mult_left_mono mult_right_mono split: if_splits)
  let ?full_amounts =
    "exchange_v10_amounts_int price_n price_d result int64_max int64_max
       int64_max Exchange_Normal"
  have full_formula:
      "?full_amounts =
       (sint result, sint result * sint price_n div sint price_d)"
    unfolding exchange_v10_amounts_int_def
    using pn wheat_more full_no_stays full_wheat_value
    by (simp add: Let_def)
  have original_formula:
      "?amounts =
       (sint result, sint result * sint price_n div sint price_d)"
    using amounts_formula result_formula by simp
  have same_amounts: "?full_amounts = ?amounts"
    using full_formula original_formula by simp
  note full_characterization = exchange_v10_normal_characterization [OF full_pre]
  show ?thesis
    using full_characterization same_amounts result_condition result_word
      full_no_stays
    by (simp add: legacy_exchange_options_def adjust_offer_with_options_def
        make_exchange_result_def Let_def)
qed

lemma legacy_post_created_is_stored_offer:
  assumes maker_wf: "party_state_wf maker_at_post"
    and post:
      "post_offer price_n price_d amount maker_at_post
         legacy_exchange_options =
       Cxx_Ok (Post_Created posted maker_after)"
  shows "legacy_stored_offer price_n price_d posted"
text \<open>
  Proof sketch: invert the created posting branch to recover its positive
  legacy adjustment and the actual posted amount.  Well-formedness makes both
  posting capacities non-negative.  The preceding replay lemma lifts that
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
    by (simp add: legacy_stored_offer_def)
qed

subsection \<open>Cross-version preventative adjustment\<close>

lemma legacy_stored_offer_repaired_adjust_stable:
  assumes stored: "legacy_stored_offer price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and release:
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released"
  shows
    "adjust_stable price_n price_d posted released
       repaired_exchange_options"
text \<open>
  Proof sketch: the intrinsic invariant supplies the positive unlimited legacy
  fixed point.  Covered release identifies its selling liability with the
  stored amount and exposes at least that selling capacity plus the booked
  buying capacity.  The exact-cap replay lemma therefore preserves the full
  amount at the released receive cap.  Adjustment never takes the symmetric
  branch against its unlimited counterparty, so enabling the second repaired
  flag preserves the result as well.
\<close>
proof -
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and posted_positive: "0 < sint posted"
    and unlimited:
      "adjust_offer_with_options price_n price_d posted int64_max
         legacy_exchange_options = Cxx_Ok posted"
    using stored by (simp_all add: legacy_stored_offer_def)
  obtain selling buying released' where selling:
      "offer_selling_liabilities price_n price_d posted = Cxx_Ok selling"
    and buying:
      "offer_buying_liabilities price_n price_d posted = Cxx_Ok buying"
    and release':
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released'"
    and released_wf': "party_state_wf released'"
    and selling_fits:
      "sint selling \<le> sint (can_sell_at_most released')"
    and buying_fits:
      "sint buying \<le> sint (can_buy_at_most released')"
    using covered_offer_release
      [OF pn pd less_imp_le[OF posted_positive] maker_wf cover]
    by blast
  have released_eq: "released' = released"
    using release release' by simp
  have released_wf: "party_state_wf released"
    using released_wf' released_eq by simp
  have selling_posted: "selling = posted"
    and buying_positive: "0 < sint buying"
    using unlimited_positive_adjustment_identifies_liabilities
      [OF posted_positive _ selling buying]
      unlimited
    by (simp_all add: legacy_exchange_options_def)
  have posted_fits:
      "sint posted \<le> sint (can_sell_at_most released)"
    using selling_fits selling_posted released_eq by simp
  have maker_send:
      "signed_min64 posted (can_sell_at_most released) = posted"
    using posted_fits by (simp add: signed_min64_def)
  have buy_nonnegative:
      "0 \<le> sint (can_buy_at_most released)"
    using can_buy_at_most_nonnegative [OF released_wf] .
  have exact_adjustment:
      "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
         \<lparr>exact_receive_cap = True,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    using exact_cap_replays_unlimited_positive_adjustment
      [OF pn pd posted_positive buy_nonnegative _ buying _]
      unlimited buying_fits released_eq
    by (simp add: legacy_exchange_options_def)
  have repaired_adjustment:
      "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
         repaired_exchange_options = Cxx_Ok posted"
  proof -
    have equal:
        "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
           repaired_exchange_options =
         adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
           \<lparr>exact_receive_cap = True,
             symmetric_exact_receive_cap = False\<rparr>"
      using adjust_offer_symmetric_irrelevant
        [OF pn pd less_imp_le[OF posted_positive] buy_nonnegative,
          of True True]
      by (simp add: repaired_exchange_options_def)
    show ?thesis
      using equal exact_adjustment by simp
  qed
  show ?thesis
    using maker_send repaired_adjustment
    by (simp add: adjust_stable_def)
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
  using legacy_stored_offer_repaired_adjust_stable
    [OF legacy_post_created_is_stored_offer [OF post_wf post]
      cross_wf cover release] .

subsection \<open>Successful-cross safety infrastructure\<close>

lemma party_receive_within_capacity_nonnegative:
  assumes wf: "party_state_wf party"
    and delta_nonnegative: "0 \<le> sint delta"
    and within: "sint delta \<le> sint (can_buy_at_most party)"
    and receive: "party_receive_buy_asset party delta = Cxx_Ok after"
  shows
    "party_state_wf after \<and>
     can_sell_at_most after = can_sell_at_most party"
text \<open>
  Proof sketch: a zero delta is the identity.  A nonzero non-negative signed
  word is positive, so the established checked-receive lemma supplies the
  unique successful state and its unchanged selling capacity.
\<close>
proof (cases "delta = 0")
  case True
  then show ?thesis
    using wf receive by (simp_all add: party_receive_buy_asset_def)
next
  case False
  have sint_nonzero: "sint delta \<noteq> 0"
    using False word_zero_iff_sint_zero [of delta] by auto
  have positive: "0 < sint delta"
    using delta_nonnegative sint_nonzero by linarith
  obtain after' where receive':
      "party_receive_buy_asset party delta = Cxx_Ok after'"
    and after_wf: "party_state_wf after'"
    and unchanged:
      "can_sell_at_most after' = can_sell_at_most party"
    using party_receive_within_capacity [OF wf positive within] by blast
  have "after = after'"
    using receive receive' by simp
  then show ?thesis
    using after_wf unchanged by simp_all
qed

lemma party_spend_within_capacity_nonnegative:
  assumes wf: "party_state_wf party"
    and delta_nonnegative: "0 \<le> sint delta"
    and within: "sint delta \<le> sint (can_sell_at_most party)"
    and spend: "party_spend_sell_asset party delta = Cxx_Ok after"
  shows "party_state_wf after"
text \<open>
  Proof sketch: spending zero is the identity.  Otherwise non-negativity makes
  the delta positive, and the established checked-spend lemma supplies the
  unique well-formed result.
\<close>
proof (cases "delta = 0")
  case True
  then show ?thesis
    using wf spend by (simp add: party_spend_sell_asset_def)
next
  case False
  have sint_nonzero: "sint delta \<noteq> 0"
    using False word_zero_iff_sint_zero [of delta] by auto
  have positive: "0 < sint delta"
    using delta_nonnegative sint_nonzero by linarith
  obtain after' where spend':
      "party_spend_sell_asset party delta = Cxx_Ok after'"
    and after_wf: "party_state_wf after'"
    using party_spend_within_capacity [OF wf positive within] by blast
  have "after = after'"
    using spend spend' by simp
  then show ?thesis using after_wf by simp
qed

lemma add_liability_checked_success_bounds:
  assumes result:
      "add_liability_checked cap current delta = Cxx_Ok updated"
    and cap_max: "cap \<le> int64_max_int"
  shows "0 \<le> sint updated" "sint updated \<le> cap"
text \<open>
  Proof sketch: a successful checked addition has an exact integer total
  between zero and its supplied cap.  Since that cap is within the positive
  signed range, conversion back to the signed word preserves the total.
\<close>
proof -
  let ?total = "sint current + delta"
  have total_nonnegative: "0 \<le> ?total"
    and total_cap: "?total \<le> cap"
    and updated_word: "updated = (word_of_int ?total :: int64)"
    using result
    by (auto simp add: add_liability_checked_def Let_def split: if_splits)
  have total_max: "?total \<le> int64_max_int"
    using total_cap cap_max by linarith
  have updated_sint: "sint updated = ?total"
    using updated_word
      sint_word_of_int_nonnegative_int64 [OF total_nonnegative total_max]
    by simp
  show "0 \<le> sint updated" "sint updated \<le> cap"
    using total_nonnegative total_cap updated_sint by simp_all
qed

lemma acquire_offer_liabilities_preserves_wf:
  assumes wf: "party_state_wf maker"
    and acquire:
      "acquire_offer_liabilities price_n price_d amount maker =
       Cxx_Ok maker_after"
  shows "party_state_wf maker_after"
text \<open>
  Proof sketch: invert the two liability projections and checked additions.
  The selling cap is the maker's balance and the buying cap is its limit minus
  balance; well-formedness places both inside the signed maximum.  Successful
  checked additions leave the new totals between zero and those caps, which is
  precisely the party-state invariant after updating the two liability fields.
\<close>
proof -
  obtain buying where buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    using acquire
    by (cases "offer_buying_liabilities price_n price_d amount")
       (auto simp add: acquire_offer_liabilities_def)
  obtain new_buying where add_buying:
      "add_liability_checked
         (sint (buy_limit maker) - sint (buy_balance maker))
         (buy_liabilities maker) (sint buying) = Cxx_Ok new_buying"
    using acquire buying
    by (cases "add_liability_checked
         (sint (buy_limit maker) - sint (buy_balance maker))
         (buy_liabilities maker) (sint buying)")
       (auto simp add: acquire_offer_liabilities_def)
  obtain selling where selling:
      "offer_selling_liabilities price_n price_d amount = Cxx_Ok selling"
    using acquire buying add_buying
    by (cases "offer_selling_liabilities price_n price_d amount")
       (auto simp add: acquire_offer_liabilities_def)
  obtain new_selling where add_selling:
      "add_liability_checked (sint (sell_balance maker))
         (sell_liabilities maker) (sint selling) = Cxx_Ok new_selling"
    using acquire buying add_buying selling
    by (cases "add_liability_checked (sint (sell_balance maker))
         (sell_liabilities maker) (sint selling)")
       (auto simp add: acquire_offer_liabilities_def)
  have maker_after_eq:
      "maker_after =
       maker\<lparr>buy_liabilities := new_buying,
             sell_liabilities := new_selling\<rparr>"
    using acquire buying add_buying selling add_selling
    by (simp add: acquire_offer_liabilities_def)
  have buy_balance_nonnegative: "0 \<le> sint (buy_balance maker)"
    and sell_balance_nonnegative: "0 \<le> sint (sell_balance maker)"
    using wf by (auto simp add: party_state_wf_def)
  have buy_cap_max:
      "sint (buy_limit maker) - sint (buy_balance maker) \<le>
       int64_max_int"
    using buy_balance_nonnegative sint64_upper_bound[of "buy_limit maker"]
    by linarith
  have sell_cap_max: "sint (sell_balance maker) \<le> int64_max_int"
    using sint64_upper_bound[of "sell_balance maker"] .
  note buy_bounds = add_liability_checked_success_bounds
    [OF add_buying buy_cap_max]
  note sell_bounds = add_liability_checked_success_bounds
    [OF add_selling sell_cap_max]
  show ?thesis
    using wf buy_bounds sell_bounds maker_after_eq
    by (auto simp add: party_state_wf_def)
qed

theorem legacy_offer_repaired_cross_preserves_invariants:
  assumes stored: "legacy_stored_offer price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and taker_wf: "party_state_wf taker"
    and cross:
      "cross_offer_v10 price_n price_d posted maker_at_cross taker
         taker_amount rounding repaired_exchange_options = Cxx_Ok crossed"
  shows
    "party_state_wf (cross_maker crossed) \<and>
     party_state_wf (cross_taker crossed) \<and>
     (cross_offer_amount crossed = 0 \<or>
      maker_covers_offer_liabilities price_n price_d
        (cross_offer_amount crossed) (cross_maker crossed))"
text \<open>
  Proof sketch: covered release yields a well-formed maker with the stored
  liabilities restored to live capacity.  The common exchange bounds apply to
  every successful repaired result and every rounding mode, including zero
  results.  They justify each checked maker and taker balance move, preserving
  both party invariants.  A non-staying or dust-erasure branch has zero
  remainder.  Otherwise the positive branch succeeds only after reacquiring
  the adjusted remainder's liabilities; checked acquisition preserves maker
  well-formedness and makes that exact remainder covered.
\<close>
proof -
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and posted_positive: "0 < sint posted"
    using stored by (simp_all add: legacy_stored_offer_def)
  note cross' = cross[unfolded cross_offer_v10_def Let_def]
  have taker_limits:
      "\<not> (sint (can_buy_at_most taker) \<le> 0 \<or>
        sint (signed_min64 taker_amount (can_sell_at_most taker)) \<le> 0)"
    using cross'
    by (cases "sint (can_buy_at_most taker) \<le> 0 \<or>
        sint (signed_min64 taker_amount (can_sell_at_most taker)) \<le> 0")
       simp_all
  obtain released where release:
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released"
    using cross' taker_limits
    by (cases "release_offer_liabilities price_n price_d posted
         maker_at_cross")
       (simp_all split: if_splits)
  obtain adjusted where adjustment:
      "adjust_offer_with_options price_n price_d
         (signed_min64 posted (can_sell_at_most released))
         (can_buy_at_most released) repaired_exchange_options =
       Cxx_Ok adjusted"
    using cross' taker_limits release
    by (cases "adjust_offer_with_options price_n price_d
         (signed_min64 posted (can_sell_at_most released))
         (can_buy_at_most released) repaired_exchange_options")
       (simp_all split: if_splits)
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d
         (signed_min64 adjusted (can_sell_at_most released))
         (can_buy_at_most taker)
         (signed_min64 taker_amount (can_sell_at_most taker))
         (can_buy_at_most released) rounding repaired_exchange_options =
       Cxx_Ok exchanged"
    using cross' taker_limits release adjustment
    by (cases "exchange_v10_with_options price_n price_d
         (signed_min64 adjusted (can_sell_at_most released))
         (can_buy_at_most taker)
         (signed_min64 taker_amount (can_sell_at_most taker))
         (can_buy_at_most released) rounding repaired_exchange_options")
       (simp_all split: if_splits)
  obtain maker_credited where maker_receive:
      "party_receive_buy_asset released (num_sheep_send exchanged) =
       Cxx_Ok maker_credited"
    using cross' taker_limits release adjustment exchange
    by (cases "party_receive_buy_asset released
         (num_sheep_send exchanged)") simp_all
  obtain maker_moved where maker_spend:
      "party_spend_sell_asset maker_credited
         (num_wheat_received exchanged) = Cxx_Ok maker_moved"
    using cross' taker_limits release adjustment exchange maker_receive
    by (cases "party_spend_sell_asset maker_credited
         (num_wheat_received exchanged)") simp_all
  obtain taker_credited where taker_receive:
      "party_receive_buy_asset taker (num_wheat_received exchanged) =
       Cxx_Ok taker_credited"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend
    by (cases "party_receive_buy_asset taker
         (num_wheat_received exchanged)") simp_all
  obtain taker_after where taker_spend:
      "party_spend_sell_asset taker_credited (num_sheep_send exchanged) =
       Cxx_Ok taker_after"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend taker_receive
    by (cases "party_spend_sell_asset taker_credited
         (num_sheep_send exchanged)") simp_all
  obtain released' where release':
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released'"
    and released_wf': "party_state_wf released'"
    using covered_offer_release
      [OF pn pd less_imp_le[OF posted_positive] maker_wf cover]
    by blast
  have released_eq: "released' = released"
    using release release' by simp
  have released_wf: "party_state_wf released"
    using released_wf' released_eq by simp
  note bounds = exchange_v10_bounds_any_cap [OF exchange]
  have wheat_nonnegative:
      "0 \<le> sint (num_wheat_received exchanged)"
    using bounds(1) .
  have sheep_nonnegative:
      "0 \<le> sint (num_sheep_send exchanged)"
    using bounds(3) .
  have sheep_fits_maker:
      "sint (num_sheep_send exchanged) \<le>
       sint (can_buy_at_most released)"
    using bounds(4) by simp
  have wheat_fits_taker:
      "sint (num_wheat_received exchanged) \<le>
       sint (can_buy_at_most taker)"
    using bounds(2) by simp
  have wheat_fits_maker:
      "sint (num_wheat_received exchanged) \<le>
       sint (can_sell_at_most released)"
    using bounds(2)
    by (auto simp add: signed_min64_def split: if_splits)
  have sheep_fits_taker:
      "sint (num_sheep_send exchanged) \<le>
       sint (can_sell_at_most taker)"
    using bounds(4)
    by (auto simp add: signed_min64_def split: if_splits)
  have maker_credited_wf: "party_state_wf maker_credited"
    and maker_sell_unchanged:
      "can_sell_at_most maker_credited = can_sell_at_most released"
    using party_receive_within_capacity_nonnegative
      [OF released_wf sheep_nonnegative sheep_fits_maker maker_receive]
    by blast+
  have wheat_fits_credited:
      "sint (num_wheat_received exchanged) \<le>
       sint (can_sell_at_most maker_credited)"
    using wheat_fits_maker maker_sell_unchanged by simp
  have maker_moved_wf: "party_state_wf maker_moved"
    using party_spend_within_capacity_nonnegative
      [OF maker_credited_wf wheat_nonnegative wheat_fits_credited maker_spend] .
  have taker_credited_wf: "party_state_wf taker_credited"
    and taker_sell_unchanged:
      "can_sell_at_most taker_credited = can_sell_at_most taker"
    using party_receive_within_capacity_nonnegative
      [OF taker_wf wheat_nonnegative wheat_fits_taker taker_receive]
    by blast+
  have sheep_fits_credited:
      "sint (num_sheep_send exchanged) \<le>
       sint (can_sell_at_most taker_credited)"
    using sheep_fits_taker taker_sell_unchanged by simp
  have taker_after_wf: "party_state_wf taker_after"
    using party_spend_within_capacity_nonnegative
      [OF taker_credited_wf sheep_nonnegative sheep_fits_credited taker_spend] .
  show ?thesis
  proof (cases "result_wheat_stays exchanged")
    case stays: True
    obtain adjusted_after where adjusted_after:
        "adjust_offer_with_options price_n price_d
           (signed_min64 (adjusted - num_wheat_received exchanged)
             (can_sell_at_most maker_moved))
           (can_buy_at_most maker_moved) repaired_exchange_options =
         Cxx_Ok adjusted_after"
      using cross' taker_limits release adjustment exchange maker_receive
        maker_spend taker_receive taker_spend stays
      by (cases "adjust_offer_with_options price_n price_d
           (signed_min64 (adjusted - num_wheat_received exchanged)
             (can_sell_at_most maker_moved))
           (can_buy_at_most maker_moved) repaired_exchange_options")
         simp_all
    show ?thesis
    proof (cases "adjusted_after = 0")
      case True
      have crossed_eq:
          "crossed = make_cross_result (num_wheat_received exchanged)
            (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
            maker_moved taker_after"
        using cross' taker_limits release adjustment exchange maker_receive
          maker_spend taker_receive taker_spend stays adjusted_after True
        by simp
      show ?thesis
        using crossed_eq maker_moved_wf taker_after_wf
        by (simp add: make_cross_result_def)
    next
      case False
      obtain maker_final where acquire:
          "acquire_offer_liabilities price_n price_d adjusted_after
             maker_moved = Cxx_Ok maker_final"
        using cross' taker_limits release adjustment exchange maker_receive
          maker_spend taker_receive taker_spend stays adjusted_after False
        by (cases "acquire_offer_liabilities price_n price_d adjusted_after
             maker_moved") simp_all
      have maker_final_wf: "party_state_wf maker_final"
        using acquire_offer_liabilities_preserves_wf
          [OF maker_moved_wf acquire] .
      have remainder_covered:
          "maker_covers_offer_liabilities price_n price_d adjusted_after
             maker_final"
        using acquired_offer_is_covered [OF maker_moved_wf acquire] .
      have crossed_eq:
          "crossed = make_cross_result (num_wheat_received exchanged)
            (num_sheep_send exchanged) (result_wheat_stays exchanged)
            adjusted_after maker_final taker_after"
        using cross' taker_limits release adjustment exchange maker_receive
          maker_spend taker_receive taker_spend stays adjusted_after False
          acquire
        by simp
      show ?thesis
        using crossed_eq maker_final_wf taker_after_wf remainder_covered
        by (simp add: make_cross_result_def)
    qed
  next
    case stays: False
    have crossed_eq:
        "crossed = make_cross_result (num_wheat_received exchanged)
          (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
          maker_moved taker_after"
      using cross' taker_limits release adjustment exchange maker_receive
        maker_spend taker_receive taker_spend stays
      by simp
    show ?thesis
      using crossed_eq maker_moved_wf taker_after_wf
      by (simp add: make_cross_result_def)
  qed
qed

subsection \<open>No phantom full take across the boundary\<close>

lemma legacy_stored_offer_nonstaying_repaired_cross_is_full_take:
  assumes stored: "legacy_stored_offer price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
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
  Proof sketch: invert the non-staying crossing to expose liability release,
  preventative adjustment, exchange, and the branch's zero remainder.  The
  cross-version stability bridge makes the preventative adjustment return the
  positive stored amount.  Positive idempotence identifies its send cap with
  that amount, and the flag-independent non-staying exchange theorem then
  forces every successful rounding mode to transfer the actual stored amount.
\<close>
proof -
  obtain released adjusted exchanged where release:
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released"
    and adjustment:
      "adjust_offer_with_options price_n price_d
         (signed_min64 posted (can_sell_at_most released))
         (can_buy_at_most released) repaired_exchange_options =
       Cxx_Ok adjusted"
    and exchange:
      "exchange_v10_with_options price_n price_d
         (signed_min64 adjusted (can_sell_at_most released))
         (can_buy_at_most taker)
         (signed_min64 taker_amount (can_sell_at_most taker))
         (can_buy_at_most released) rounding repaired_exchange_options =
       Cxx_Ok exchanged"
    and crossed_wheat:
      "cross_wheat_received crossed = num_wheat_received exchanged"
    and exchanged_nonstaying: "\<not> result_wheat_stays exchanged"
    and erased: "cross_offer_amount crossed = 0"
    using successful_nonstaying_cross_fields [OF cross nonstaying]
    by blast
  have stable:
      "adjust_stable price_n price_d posted released
         repaired_exchange_options"
    using legacy_stored_offer_repaired_adjust_stable
      [OF stored maker_wf cover release] .
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and posted_positive: "0 < sint posted"
    using stored by (simp_all add: legacy_stored_offer_def)
  obtain released' where release':
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released'"
    and released_wf': "party_state_wf released'"
    using covered_offer_release
      [OF pn pd less_imp_le[OF posted_positive] maker_wf cover]
    by blast
  have released_eq: "released' = released"
    using release release' by simp
  have released_wf: "party_state_wf released"
    using released_wf' released_eq by simp
  have sell_nonnegative:
      "0 \<le> sint (can_sell_at_most released)"
    using can_sell_at_most_nonnegative [OF released_wf] .
  have buy_nonnegative:
      "0 \<le> sint (can_buy_at_most released)"
    using can_buy_at_most_nonnegative [OF released_wf] .
  let ?maker_send =
    "signed_min64 posted (can_sell_at_most released)"
  have maker_send_nonnegative: "0 \<le> sint ?maker_send"
    using posted_positive sell_nonnegative
    by (auto simp add: signed_min64_def split: if_splits)
  have stable_adjustment:
      "adjust_offer_with_options price_n price_d ?maker_send
         (can_buy_at_most released) repaired_exchange_options =
       Cxx_Ok posted"
    using stable by (simp add: adjust_stable_def)
  have stable_fixed:
      "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
         repaired_exchange_options = Cxx_Ok posted \<and>
       sint posted \<le> sint ?maker_send"
    using adjust_offer_positive_idempotent
      [OF pn pd maker_send_nonnegative buy_nonnegative stable_adjustment
        posted_positive] .
  have maker_send_eq: "?maker_send = posted"
    using stable_fixed
    by (auto simp add: signed_min64_def split: if_splits)
  have direct_adjustment:
      "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
         repaired_exchange_options = Cxx_Ok posted"
    using stable_fixed by blast
  have adjusted_eq: "adjusted = posted"
    using adjustment stable_adjustment by simp
  have exchange_posted:
      "exchange_v10_with_options price_n price_d posted (can_buy_at_most taker)
         (signed_min64 taker_amount (can_sell_at_most taker))
         (can_buy_at_most released) rounding repaired_exchange_options =
       Cxx_Ok exchanged"
    using exchange adjusted_eq maker_send_eq by simp
  have full_wheat: "num_wheat_received exchanged = posted"
    using exchange_v10_nonstaying_matches_positive_adjustment
      [OF pn pd posted_positive buy_nonnegative direct_adjustment
        exchange_posted exchanged_nonstaying] .
  show ?thesis
    using crossed_wheat full_wheat erased by simp
qed

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
  Proof sketch: legacy posting establishes the intrinsic fixed point; the
  preceding theorem then applies to the independently supplied covered
  crossing state, arbitrary taker, and arbitrary rounding mode.
\<close>
  using legacy_stored_offer_nonstaying_repaired_cross_is_full_take
    [OF legacy_post_created_is_stored_offer [OF post_wf post]
      cross_wf cover cross nonstaying] .

subsection \<open>Existential safe full take\<close>

theorem legacy_stored_offer_has_safe_full_cross_repaired:
  assumes stored: "legacy_stored_offer price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
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
  Proof sketch: covered release restores at least the stored offer's selling
  and buying liabilities as live capacities.  Cross-version stability and
  positive idempotence make the preventative send cap exactly the stored
  amount.  The maximum-capacity taker realizes the same repaired exchange as
  adjustment, hence transfers all stored wheat and a positive sheep amount.
  Generic cap bounds justify all four checked balance moves, and an unlimited
  counterparty cannot leave wheat resting, so the constructed successful
  result has no remainder and both parties remain well formed.
\<close>
proof -
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and posted_positive: "0 < sint posted"
    using stored by (simp_all add: legacy_stored_offer_def)
  obtain selling buying released where selling:
      "offer_selling_liabilities price_n price_d posted = Cxx_Ok selling"
    and buying:
      "offer_buying_liabilities price_n price_d posted = Cxx_Ok buying"
    and release:
      "release_offer_liabilities price_n price_d posted maker_at_cross =
       Cxx_Ok released"
    and released_wf: "party_state_wf released"
    and selling_fits:
      "sint selling \<le> sint (can_sell_at_most released)"
    and buying_fits:
      "sint buying \<le> sint (can_buy_at_most released)"
    using covered_offer_release
      [OF pn pd less_imp_le[OF posted_positive] maker_wf cover]
    by blast
  have stable:
      "adjust_stable price_n price_d posted released
         repaired_exchange_options"
    using legacy_stored_offer_repaired_adjust_stable
      [OF stored maker_wf cover release] .
  have sell_nonnegative:
      "0 \<le> sint (can_sell_at_most released)"
    using can_sell_at_most_nonnegative [OF released_wf] .
  have buy_nonnegative:
      "0 \<le> sint (can_buy_at_most released)"
    using can_buy_at_most_nonnegative [OF released_wf] .
  let ?maker_send =
    "signed_min64 posted (can_sell_at_most released)"
  have maker_send_nonnegative: "0 \<le> sint ?maker_send"
    using posted_positive sell_nonnegative
    by (auto simp add: signed_min64_def split: if_splits)
  have stable_adjustment:
      "adjust_offer_with_options price_n price_d ?maker_send
         (can_buy_at_most released) repaired_exchange_options =
       Cxx_Ok posted"
    using stable by (simp add: adjust_stable_def)
  have stable_fixed:
      "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
         repaired_exchange_options = Cxx_Ok posted \<and>
       sint posted \<le> sint ?maker_send"
    using adjust_offer_positive_idempotent
      [OF pn pd maker_send_nonnegative buy_nonnegative stable_adjustment
        posted_positive] .
  have maker_send: "?maker_send = posted"
    using stable_fixed
    by (auto simp add: signed_min64_def split: if_splits)
  have preventative_adjustment:
      "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
         repaired_exchange_options = Cxx_Ok posted"
    using stable_fixed by blast
  note taker = maximum_capacity_taker_equations
  have taker_send:
      "signed_min64 int64_max
         (can_sell_at_most maximum_capacity_taker) = int64_max"
    using taker by (simp add: signed_min64_def)
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d posted int64_max int64_max
         (can_buy_at_most released) Exchange_Normal
         repaired_exchange_options = Cxx_Ok exchanged"
    and wheat: "num_wheat_received exchanged = posted"
    using preventative_adjustment
    by (cases "exchange_v10_with_options price_n price_d posted int64_max int64_max
         (can_buy_at_most released) Exchange_Normal
         repaired_exchange_options")
       (simp_all add: adjust_offer_with_options_def)
  have wheat_positive:
      "0 < sint (num_wheat_received exchanged)"
    using posted_positive wheat by simp
  have sheep_positive:
      "0 < sint (num_sheep_send exchanged)"
    using exchange_normal_positive_wheat_has_positive_sheep
      [OF exchange wheat_positive] .
  note bounds = exchange_v10_bounds_any_cap [OF exchange]
  have sheep_fits_maker:
      "sint (num_sheep_send exchanged) \<le>
       sint (can_buy_at_most released)"
    using bounds(4) by simp
  have wheat_fits_maker:
      "sint (num_wheat_received exchanged) \<le>
       sint (can_sell_at_most released)"
    using wheat maker_send
    by (auto simp add: signed_min64_def split: if_splits)
  have wheat_fits_taker:
      "sint (num_wheat_received exchanged) \<le>
       sint (can_buy_at_most maximum_capacity_taker)"
    using sint64_upper_bound [of "num_wheat_received exchanged"] taker
    by (simp add: int64_max_def)
  have sheep_fits_taker:
      "sint (num_sheep_send exchanged) \<le>
       sint (can_sell_at_most maximum_capacity_taker)"
    using sint64_upper_bound [of "num_sheep_send exchanged"] taker
    by (simp add: int64_max_def)
  obtain maker_credited where maker_receive:
      "party_receive_buy_asset released (num_sheep_send exchanged) =
       Cxx_Ok maker_credited"
    and maker_credited_wf: "party_state_wf maker_credited"
    and maker_sell_unchanged:
      "can_sell_at_most maker_credited = can_sell_at_most released"
    using party_receive_within_capacity
      [OF released_wf sheep_positive sheep_fits_maker]
    by blast
  have wheat_fits_credited:
      "sint (num_wheat_received exchanged) \<le>
       sint (can_sell_at_most maker_credited)"
    using wheat_fits_maker maker_sell_unchanged by simp
  obtain maker_moved where maker_spend:
      "party_spend_sell_asset maker_credited
         (num_wheat_received exchanged) = Cxx_Ok maker_moved"
    and maker_moved_wf: "party_state_wf maker_moved"
    using party_spend_within_capacity
      [OF maker_credited_wf wheat_positive wheat_fits_credited]
    by blast
  obtain taker_credited where taker_receive:
      "party_receive_buy_asset maximum_capacity_taker
         (num_wheat_received exchanged) = Cxx_Ok taker_credited"
    and taker_credited_wf: "party_state_wf taker_credited"
    and taker_sell_unchanged:
      "can_sell_at_most taker_credited =
       can_sell_at_most maximum_capacity_taker"
    using party_receive_within_capacity
      [OF taker(1) wheat_positive wheat_fits_taker]
    by blast
  have sheep_fits_credited:
      "sint (num_sheep_send exchanged) \<le>
       sint (can_sell_at_most taker_credited)"
    using sheep_fits_taker taker_sell_unchanged by simp
  obtain taker_after where taker_spend:
      "party_spend_sell_asset taker_credited
         (num_sheep_send exchanged) = Cxx_Ok taker_after"
    and taker_after_wf: "party_state_wf taker_after"
    using party_spend_within_capacity
      [OF taker_credited_wf sheep_positive sheep_fits_credited]
    by blast
  have no_stays: "\<not> result_wheat_stays exchanged"
    using exchange_against_unlimited_counterparty_does_not_leave_wheat
      [OF pn pd less_imp_le[OF posted_positive] buy_nonnegative exchange] .
  let ?crossed =
    "make_cross_result (num_wheat_received exchanged)
       (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
       maker_moved taker_after"
  have crossed:
      "cross_offer_v10 price_n price_d posted maker_at_cross
         maximum_capacity_taker int64_max Exchange_Normal
         repaired_exchange_options = Cxx_Ok ?crossed"
    using taker(2,3) taker_send release maker_send
      preventative_adjustment exchange maker_receive maker_spend
      taker_receive taker_spend no_stays
    by (simp add: cross_offer_v10_def Let_def int64_max_def)
  show ?thesis
    using crossed wheat sheep_positive no_stays maker_moved_wf taker_after_wf
    by (intro exI[where x = ?crossed])
       (simp add: make_cross_result_def)
qed

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
  using legacy_stored_offer_has_safe_full_cross_repaired
    [OF legacy_post_created_is_stored_offer [OF post_wf post]
      cross_wf cover] .

subsection \<open>Positive remainder provenance and recursive takeability\<close>

lemma positive_repaired_adjustment_is_legacy_stored_offer:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         repaired_exchange_options = Cxx_Ok result"
    and result_positive: "0 < sint result"
  shows "legacy_stored_offer price_n price_d result"
text \<open>
  Proof sketch: expose the full exchange behind the positive adjustment.  Its
  common cap bounds make both adjustment caps non-negative, and its positive
  wheat result implies a positive sheep result.  Symmetric irrelevance reduces
  the repaired adjustment to the exact-only form; the established positive
  exact replay then supplies the unlimited legacy fixed point required by the
  intrinsic stored-offer invariant.
\<close>
proof -
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d max_wheat int64_max int64_max max_sheep
         Exchange_Normal repaired_exchange_options = Cxx_Ok exchanged"
    and wheat: "num_wheat_received exchanged = result"
    using adjustment
    by (cases "exchange_v10_with_options price_n price_d max_wheat int64_max int64_max
         max_sheep Exchange_Normal repaired_exchange_options")
       (simp_all add: adjust_offer_with_options_def)
  have wheat_positive:
      "0 < sint (num_wheat_received exchanged)"
    using result_positive wheat by simp
  have sheep_positive:
      "0 < sint (num_sheep_send exchanged)"
    using exchange_normal_positive_wheat_has_positive_sheep
      [OF exchange wheat_positive] .
  note bounds = exchange_v10_bounds_any_cap [OF exchange]
  have wheat_cap_nonnegative: "0 \<le> sint max_wheat"
    using bounds(2) wheat_positive by simp
  have sheep_cap_nonnegative: "0 \<le> sint max_sheep"
    using bounds(4) sheep_positive by simp
  have exact_adjustment:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         \<lparr>exact_receive_cap = True,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"
    using adjustment adjust_offer_symmetric_irrelevant
      [OF pn pd wheat_cap_nonnegative sheep_cap_nonnegative,
        of True True]
    by (simp add: repaired_exchange_options_def)
  have unlimited:
      "adjust_offer_with_options price_n price_d result int64_max
         legacy_exchange_options = Cxx_Ok result"
    using positive_adjustment_replays_unlimited
      [OF pn pd wheat_cap_nonnegative sheep_cap_nonnegative exact_adjustment
        result_positive]
    by (simp add: legacy_exchange_options_def)
  show ?thesis
    using pn pd result_positive unlimited
    by (simp add: legacy_stored_offer_def)
qed

lemma positive_legacy_adjustment_is_stored_offer:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         legacy_exchange_options = Cxx_Ok result"
    and result_positive: "0 < sint result"
  shows "legacy_stored_offer price_n price_d result"
text \<open>
  Proof sketch: the successful positive adjustment's exchange bounds imply
  non-negative send and receive caps.  The legacy replay theorem then lifts
  the returned amount directly to its unlimited fixed point.
\<close>
proof -
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d max_wheat int64_max int64_max max_sheep
         Exchange_Normal legacy_exchange_options = Cxx_Ok exchanged"
    and wheat: "num_wheat_received exchanged = result"
    using adjustment
    by (cases "exchange_v10_with_options price_n price_d max_wheat int64_max int64_max
         max_sheep Exchange_Normal legacy_exchange_options")
       (simp_all add: adjust_offer_with_options_def)
  have wheat_positive:
      "0 < sint (num_wheat_received exchanged)"
    using result_positive wheat by simp
  have sheep_positive:
      "0 < sint (num_sheep_send exchanged)"
    using exchange_normal_positive_wheat_has_positive_sheep
      [OF exchange wheat_positive] .
  note bounds = exchange_v10_bounds_any_cap [OF exchange]
  have wheat_cap_nonnegative: "0 \<le> sint max_wheat"
    using bounds(2) wheat_positive by simp
  have sheep_cap_nonnegative: "0 \<le> sint max_sheep"
    using bounds(4) sheep_positive by simp
  have unlimited:
      "adjust_offer_with_options price_n price_d result int64_max
         legacy_exchange_options = Cxx_Ok result"
    using legacy_positive_adjustment_replays_unlimited
      [OF pn pd wheat_cap_nonnegative sheep_cap_nonnegative adjustment
        result_positive] .
  show ?thesis
    using pn pd result_positive unlimited
    by (simp add: legacy_stored_offer_def)
qed

lemma successful_positive_cross_remainder_has_adjustment:
  assumes cross:
      "cross_offer_v10 price_n price_d offer_amount maker taker taker_amount
         rounding options = Cxx_Ok crossed"
    and remainder_positive: "0 < sint (cross_offer_amount crossed)"
  obtains max_wheat max_sheep where
    "adjust_offer_with_options price_n price_d max_wheat max_sheep options =
     Cxx_Ok (cross_offer_amount crossed)"
text \<open>
  Proof sketch: invert a successful crossing through release, preventative
  adjustment, exchange, and all four balance moves.  A non-staying branch and
  the dust-erasure sub-branch both expose a zero remaining amount, contradicting
  positivity.  The only remaining branch is the successful post-trade
  adjustment followed by liability acquisition, and its adjusted amount is
  exactly the positive amount stored in the crossing result.
\<close>
proof -
  note cross' = cross[unfolded cross_offer_v10_def Let_def]
  have taker_limits:
      "\<not> (sint (can_buy_at_most taker) \<le> 0 \<or>
        sint (signed_min64 taker_amount (can_sell_at_most taker)) \<le> 0)"
    using cross'
    by (cases "sint (can_buy_at_most taker) \<le> 0 \<or>
        sint (signed_min64 taker_amount (can_sell_at_most taker)) \<le> 0")
       simp_all
  obtain released where release:
      "release_offer_liabilities price_n price_d offer_amount maker =
       Cxx_Ok released"
    using cross' taker_limits
    by (cases "release_offer_liabilities price_n price_d offer_amount maker")
       (simp_all split: if_splits)
  obtain adjusted where adjustment:
      "adjust_offer_with_options price_n price_d
         (signed_min64 offer_amount (can_sell_at_most released))
         (can_buy_at_most released) options = Cxx_Ok adjusted"
    using cross' taker_limits release
    by (cases "adjust_offer_with_options price_n price_d
         (signed_min64 offer_amount (can_sell_at_most released))
         (can_buy_at_most released) options")
       (simp_all split: if_splits)
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d
         (signed_min64 adjusted (can_sell_at_most released))
         (can_buy_at_most taker)
         (signed_min64 taker_amount (can_sell_at_most taker))
         (can_buy_at_most released) rounding options = Cxx_Ok exchanged"
    using cross' taker_limits release adjustment
    by (cases "exchange_v10_with_options price_n price_d
         (signed_min64 adjusted (can_sell_at_most released))
         (can_buy_at_most taker)
         (signed_min64 taker_amount (can_sell_at_most taker))
         (can_buy_at_most released) rounding options")
       (simp_all split: if_splits)
  obtain maker_credited where maker_receive:
      "party_receive_buy_asset released (num_sheep_send exchanged) =
       Cxx_Ok maker_credited"
    using cross' taker_limits release adjustment exchange
    by (cases "party_receive_buy_asset released
         (num_sheep_send exchanged)") simp_all
  obtain maker_moved where maker_spend:
      "party_spend_sell_asset maker_credited
         (num_wheat_received exchanged) = Cxx_Ok maker_moved"
    using cross' taker_limits release adjustment exchange maker_receive
    by (cases "party_spend_sell_asset maker_credited
         (num_wheat_received exchanged)") simp_all
  obtain taker_credited where taker_receive:
      "party_receive_buy_asset taker (num_wheat_received exchanged) =
       Cxx_Ok taker_credited"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend
    by (cases "party_receive_buy_asset taker
         (num_wheat_received exchanged)") simp_all
  obtain taker_after where taker_spend:
      "party_spend_sell_asset taker_credited (num_sheep_send exchanged) =
       Cxx_Ok taker_after"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend taker_receive
    by (cases "party_spend_sell_asset taker_credited
         (num_sheep_send exchanged)") simp_all
  have stays: "result_wheat_stays exchanged"
  proof (rule ccontr)
    assume not_stays: "\<not> result_wheat_stays exchanged"
    have crossed_eq:
        "crossed = make_cross_result (num_wheat_received exchanged)
          (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
          maker_moved taker_after"
      using cross' taker_limits release adjustment exchange maker_receive
        maker_spend taker_receive taker_spend not_stays
      by simp
    have "cross_offer_amount crossed = 0"
      using crossed_eq by (simp add: make_cross_result_def)
    with remainder_positive show False by simp
  qed
  let ?max_wheat =
    "signed_min64 (adjusted - num_wheat_received exchanged)
       (can_sell_at_most maker_moved)"
  let ?max_sheep = "can_buy_at_most maker_moved"
  obtain adjusted_after where adjusted_after:
      "adjust_offer_with_options price_n price_d ?max_wheat ?max_sheep options =
       Cxx_Ok adjusted_after"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend taker_receive taker_spend stays
    by (cases "adjust_offer_with_options price_n price_d ?max_wheat ?max_sheep options")
       simp_all
  have adjusted_after_nonzero: "adjusted_after \<noteq> 0"
  proof
    assume zero: "adjusted_after = 0"
    have crossed_eq:
        "crossed = make_cross_result (num_wheat_received exchanged)
          (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
          maker_moved taker_after"
      using cross' taker_limits release adjustment exchange maker_receive
        maker_spend taker_receive taker_spend stays adjusted_after zero
      by simp
    have "cross_offer_amount crossed = 0"
      using crossed_eq by (simp add: make_cross_result_def)
    with remainder_positive show False by simp
  qed
  obtain maker_final where acquire:
      "acquire_offer_liabilities price_n price_d adjusted_after maker_moved =
       Cxx_Ok maker_final"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend taker_receive taker_spend stays adjusted_after
      adjusted_after_nonzero
    by (cases "acquire_offer_liabilities price_n price_d adjusted_after
         maker_moved") simp_all
  have crossed_eq:
      "crossed = make_cross_result (num_wheat_received exchanged)
        (num_sheep_send exchanged) (result_wheat_stays exchanged)
        adjusted_after maker_final taker_after"
    using cross' taker_limits release adjustment exchange maker_receive
      maker_spend taker_receive taker_spend stays adjusted_after
      adjusted_after_nonzero acquire
    by simp
  have remainder_eq: "cross_offer_amount crossed = adjusted_after"
    using crossed_eq by (simp add: make_cross_result_def)
  show thesis
    using that[of ?max_wheat ?max_sheep] adjusted_after remainder_eq by simp
qed

lemma repaired_positive_cross_remainder_is_stored_offer:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and cross:
      "cross_offer_v10 price_n price_d offer_amount maker taker taker_amount
         rounding repaired_exchange_options = Cxx_Ok crossed"
    and remainder_positive: "0 < sint (cross_offer_amount crossed)"
  shows
    "legacy_stored_offer price_n price_d (cross_offer_amount crossed)"
text \<open>
  Proof sketch: a positive remainder exposes the repaired post-trade
  adjustment that wrote it; every positive repaired adjustment result is an
  unlimited legacy fixed point because the clamp makes unrestricted repaired
  and legacy projections coincide.
\<close>
proof -
  obtain max_wheat max_sheep where adjustment:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         repaired_exchange_options =
       Cxx_Ok (cross_offer_amount crossed)"
    using successful_positive_cross_remainder_has_adjustment
      [OF cross remainder_positive] by blast
  show ?thesis
    using positive_repaired_adjustment_is_legacy_stored_offer
      [OF pn pd adjustment remainder_positive] .
qed

lemma legacy_positive_cross_remainder_is_stored_offer:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and cross:
      "cross_offer_v10 price_n price_d offer_amount maker taker taker_amount
         rounding legacy_exchange_options = Cxx_Ok crossed"
    and remainder_positive: "0 < sint (cross_offer_amount crossed)"
  shows
    "legacy_stored_offer price_n price_d (cross_offer_amount crossed)"
text \<open>
  Proof sketch: the same successful-remainder inversion exposes a positive
  legacy adjustment, whose result is an unlimited legacy fixed point by the
  legacy replay theorem.
\<close>
proof -
  obtain max_wheat max_sheep where adjustment:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         legacy_exchange_options =
       Cxx_Ok (cross_offer_amount crossed)"
    using successful_positive_cross_remainder_has_adjustment
      [OF cross remainder_positive] by blast
  show ?thesis
    using positive_legacy_adjustment_is_stored_offer
      [OF pn pd adjustment remainder_positive] .
qed

theorem repaired_cross_remainder_remains_safely_takeable:
  assumes stored: "legacy_stored_offer price_n price_d posted"
    and maker_wf: "party_state_wf maker_at_cross"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and taker_wf: "party_state_wf taker"
    and cross:
      "cross_offer_v10 price_n price_d posted maker_at_cross taker
         taker_amount rounding repaired_exchange_options = Cxx_Ok crossed"
    and remainder_positive: "0 < sint (cross_offer_amount crossed)"
  shows
    "maker_covers_offer_liabilities price_n price_d
       (cross_offer_amount crossed) (cross_maker crossed) \<and>
     (\<exists>next.
       cross_offer_v10 price_n price_d (cross_offer_amount crossed)
         (cross_maker crossed) maximum_capacity_taker int64_max
         Exchange_Normal repaired_exchange_options = Cxx_Ok next \<and>
       cross_wheat_received next = cross_offer_amount crossed \<and>
       0 < sint (cross_sheep_send next) \<and>
       \<not> cross_wheat_stays next \<and>
       cross_offer_amount next = 0 \<and>
       party_state_wf (cross_maker next) \<and>
       party_state_wf (cross_taker next))"
text \<open>
  Proof sketch: universal successful-cross safety makes the final maker well
  formed and covers every nonzero reacquired remainder.  Successful positive
  remainder provenance shows that the repaired post-trade adjustment wrote an
  intrinsic legacy fixed point.  Applying the existential theorem to that
  final amount and maker state constructs a second safe repaired cross that
  consumes the entire remainder with the maximum-capacity taker.
\<close>
proof -
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    using stored by (simp_all add: legacy_stored_offer_def)
  have safety:
      "party_state_wf (cross_maker crossed) \<and>
       party_state_wf (cross_taker crossed) \<and>
       (cross_offer_amount crossed = 0 \<or>
        maker_covers_offer_liabilities price_n price_d
          (cross_offer_amount crossed) (cross_maker crossed))"
    using legacy_offer_repaired_cross_preserves_invariants
      [OF stored maker_wf cover taker_wf cross] .
  have remainder_nonzero: "cross_offer_amount crossed \<noteq> 0"
    using remainder_positive
      word_zero_iff_sint_zero [of "cross_offer_amount crossed"]
    by auto
  have final_wf: "party_state_wf (cross_maker crossed)"
    and final_cover:
      "maker_covers_offer_liabilities price_n price_d
         (cross_offer_amount crossed) (cross_maker crossed)"
    using safety remainder_nonzero by blast+
  have remainder_stored:
      "legacy_stored_offer price_n price_d (cross_offer_amount crossed)"
    using repaired_positive_cross_remainder_is_stored_offer
      [OF pn pd cross remainder_positive] .
  have next_cross:
      "\<exists>next.
       cross_offer_v10 price_n price_d (cross_offer_amount crossed)
         (cross_maker crossed) maximum_capacity_taker int64_max
         Exchange_Normal repaired_exchange_options = Cxx_Ok next \<and>
       cross_wheat_received next = cross_offer_amount crossed \<and>
       0 < sint (cross_sheep_send next) \<and>
       \<not> cross_wheat_stays next \<and>
       cross_offer_amount next = 0 \<and>
       party_state_wf (cross_maker next) \<and>
       party_state_wf (cross_taker next)"
    using legacy_stored_offer_has_safe_full_cross_repaired
      [OF remainder_stored final_wf final_cover] .
  show ?thesis
    using final_cover next_cross by blast
qed

subsection \<open>Reachability boundary\<close>

text \<open>
  The intrinsic theorems above apply to an offer from any origin once
  @{const legacy_stored_offer} is established.  This theory proves that
  provenance for every successful modeled legacy @{const post_offer}, which is
  the ManageSell creation route, and for every positive legacy or repaired
  crossing remainder.  Neither derivation uses any overlay-admission filter:
  a successful posting already yields the unlimited legacy fixed point.

  ManageBuy creation is a separate route, because @{const post_buy_offer}
  inverts the submitted price and computes its request-time liabilities from
  the finite buy amount rather than from an unlimited receive cap.  Its
  provenance is established separately.

  Applying the intrinsic results to arbitrary historical ledger entries still
  assumes the real ledger's global liabilities-match-offers invariant, which
  supplies local @{const maker_covers_offer_liabilities}, and a protocol-upgrade
  reachability argument that every live entry came from a covered modeled
  origin or otherwise satisfies @{const legacy_stored_offer}.  Native reserve,
  authorization, sponsorship, order-book selection, and aggregation across
  multiple offers remain outside this single-offer lifecycle model.  Thus the
  results establish the arithmetic and local-ledger migration obligation, not
  by themselves the complete network-state reachability argument.
\<close>


section \<open>The migration ladder at the real protocol boundary\<close>

text \<open>
  The ladder above is phrased with @{const legacy_exchange_options} for
  creation and provenance and @{const repaired_exchange_options} for
  adjustment and crossing.  Those are exactly the two configurations
  @{const exchange_options_at_version} selects, and
  @{thm [source] exchange_options_at_version_legacy} and
  @{thm [source] exchange_options_at_version_repaired} are simplification
  rules, so every theorem in this theory applies verbatim once a ledger
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
  It is @{const legacy_stored_offer} with the option record replaced by the
  ledger version that selects it.
\<close>

lemma stored_offer_created_before_v29_eq [simp]:
  "ledger_version_before_v29 creation_version \<Longrightarrow>
   stored_offer_created_before_v29 creation_version price_n price_d posted =
   legacy_stored_offer price_n price_d posted"
  by (simp add: stored_offer_created_before_v29_def legacy_stored_offer_def
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
  have legacy: "legacy_stored_offer price_n price_d posted"
    using stored creation by simp
  show ?thesis
    using legacy_offer_repaired_cross_preserves_invariants
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
  have legacy: "legacy_stored_offer price_n price_d posted"
    using stored creation by simp
  show ?thesis
    using legacy_stored_offer_has_safe_full_cross_repaired
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
  have legacy: "legacy_stored_offer price_n price_d posted"
    using stored creation by simp
  show ?thesis
    using repaired_cross_remainder_remains_safely_takeable
      [OF legacy maker_wf cover taker_wf] cross remainder_positive activation
    by simp
qed

text \<open>
  \<^bold>\<open>Reachability.\<close>  The corollaries above assume
  @{const legacy_stored_offer}, the intrinsic stored-offer invariant, and
  @{const maker_covers_offer_liabilities}.  The first is established here for
  the modeled fresh manage-sell route, by
  @{thm [source] legacy_post_cover_implies_repaired_adjust_stable} from a
  successful protocol-28 @{const post_offer}.  It is \<^emph>\<open>not\<close> established for
  manage-buy creation, passive sell offers, offer updates, positive
  partial-fill remainders carried over from earlier protocols, or offers that
  survived earlier protocol migrations or an administrative upgrade pass.
  Applying these results to such an entry requires a separate argument that it
  satisfies the intrinsic invariant.

  The second assumption is supplied in real execution by the global
  liabilities-match-offers invariant.  The local model does not prove that
  global invariant, so these are local safety results about a covered offer,
  not a proof of complete network migration safety.  The missing induction
  over historical ledger state is recorded as follow-up work.
\<close>


section \<open>Protocol-29 takeability and limit-adjustment stability\<close>

text \<open>
  Two properties of the predicate catalogue were previously available only at
  the mixed option record, or not at all.  Both follow from the migration
  ladder above, because the ladder's existential full-take theorem already
  produces a repaired cross by a maximum-capacity counterparty.  They are
  stated here rather than in the lifecycle theory because that is where the
  ladder lives.
\<close>

lemma maker_covers_offer_liabilities_buy_limit_update [simp]:
  "maker_covers_offer_liabilities price_n price_d amount
     (maker\<lparr>buy_limit := new_limit\<rparr>) =
   maker_covers_offer_liabilities price_n price_d amount maker"
  \<comment> \<open>Coverage reads only the maker's booked liabilities, so changing the
    buying limit cannot disturb it.\<close>
  by (simp add: maker_covers_offer_liabilities_def split: cxx_result.split)

theorem posted_offers_remain_takeable_repaired:
  "posted_offers_remain_takeable repaired_exchange_options"
  \<comment> \<open>From protocol 29 on, an offer created by a successful posting can still
    be crossed for positive amounts by some well-formed taker, whenever the
    maker covers its liabilities.\<close>
  text \<open>
    Proof sketch: the symmetric option is inert for a successful posting, so
    normalize the repaired post to a false symmetric option and replay it to
    the unlimited legacy fixed point.  With positive price and amount that is
    exactly the intrinsic stored-offer invariant, so the ladder's existential
    full-take theorem applies to the covered offer and its maximum-capacity
    counterparty is the required witness.
  \<close>
  unfolding posted_offers_remain_takeable_def
proof (intro allI impI)
  fix price_n price_d amount maker_at_post posted maker_after maker_at_cross
  assume prem:
    "party_state_wf maker_at_post \<and>
     party_state_wf maker_at_cross \<and>
     post_offer price_n price_d amount maker_at_post
       repaired_exchange_options = Cxx_Ok (Post_Created posted maker_after) \<and>
     maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
  have post_wf: "party_state_wf maker_at_post" using prem by blast
  have cross_wf: "party_state_wf maker_at_cross" using prem by blast
  have post:
      "post_offer price_n price_d amount maker_at_post
         repaired_exchange_options = Cxx_Ok (Post_Created posted maker_after)"
    using prem by blast
  have cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    using prem by blast
  have post_plain:
      "post_offer price_n price_d amount maker_at_post
         \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (Post_Created posted maker_after)"
    using post_offer_symmetric_irrelevant_if_created
      [OF post_wf post [unfolded repaired_exchange_options_def]] .
  note positive = post_created_positive_facts [OF post]
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and posted_positive: "0 < sint posted"
    using positive by simp_all
  have unlimited:
      "adjust_offer_with_options price_n price_d posted int64_max
         legacy_exchange_options = Cxx_Ok posted"
    using post_created_replays_unlimited [OF post_wf post_plain]
    by (simp add: legacy_exchange_options_def)
  have stored: "legacy_stored_offer price_n price_d posted"
    using pn pd posted_positive unlimited
    by (simp add: legacy_stored_offer_def)
  obtain crossed where cross:
      "cross_offer_v10 price_n price_d posted maker_at_cross
         maximum_capacity_taker int64_max Exchange_Normal
         repaired_exchange_options = Cxx_Ok crossed"
    and wheat: "cross_wheat_received crossed = posted"
    and sheep: "0 < sint (cross_sheep_send crossed)"
    using legacy_stored_offer_has_safe_full_cross_repaired
      [OF stored cross_wf cover]
    by blast
  have taker_wf: "party_state_wf maximum_capacity_taker" by eval
  have taker_buy: "0 < sint (can_buy_at_most maximum_capacity_taker)" by eval
  have taker_send:
      "0 < sint
        (signed_min64 int64_max (can_sell_at_most maximum_capacity_taker))"
    by eval
  show
    "\<exists>taker taker_amount crossed.
      party_state_wf taker \<and>
      0 < sint (can_buy_at_most taker) \<and>
      0 < sint (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
      cross_offer_v10 price_n price_d posted maker_at_cross taker
        taker_amount Exchange_Normal repaired_exchange_options =
        Cxx_Ok crossed \<and>
      0 < sint (cross_wheat_received crossed) \<and>
      0 < sint (cross_sheep_send crossed)"
    using taker_wf taker_buy taker_send cross sheep posted_positive wheat
    by blast
qed

theorem limit_adjustment_stable_repaired:
  "limit_adjustment_stable repaired_exchange_options"
  \<comment> \<open>From protocol 29 on, changing a maker's buying limit to any value that
    leaves it well formed cannot make its posted offer untakeable.\<close>
  text \<open>
    Proof sketch: a successful posting acquires the offer's liabilities, so
    the resulting maker covers them.  Changing only the buying limit leaves
    those booked liabilities untouched, so coverage survives the change, and
    protocol-29 takeability then supplies the taker.
  \<close>
  unfolding limit_adjustment_stable_def Let_def
proof (intro allI impI)
  fix price_n price_d amount maker_at_post posted maker_after new_sheep_limit
  assume prem:
    "party_state_wf maker_at_post \<and>
     post_offer price_n price_d amount maker_at_post
       repaired_exchange_options = Cxx_Ok (Post_Created posted maker_after)"
  assume cross_wf:
    "party_state_wf (maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>)"
  have post_wf: "party_state_wf maker_at_post" using prem by blast
  have post:
      "post_offer price_n price_d amount maker_at_post
         repaired_exchange_options = Cxx_Ok (Post_Created posted maker_after)"
    using prem by blast
  have acquire:
      "acquire_offer_liabilities price_n price_d posted maker_at_post =
       Cxx_Ok maker_after"
    using post_created_acquires_posted_liabilities [OF post] .
  have cover:
      "maker_covers_offer_liabilities price_n price_d posted
         (maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>)"
    using acquired_offer_is_covered [OF post_wf acquire] by simp
  show
    "\<exists>taker taker_amount crossed.
      party_state_wf taker \<and>
      0 < sint (can_buy_at_most taker) \<and>
      0 < sint (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
      cross_offer_v10 price_n price_d posted
        (maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>) taker taker_amount
        Exchange_Normal repaired_exchange_options = Cxx_Ok crossed \<and>
      0 < sint (cross_wheat_received crossed) \<and>
      0 < sint (cross_sheep_send crossed)"
    using posted_offers_remain_takeable_repaired
      [unfolded posted_offers_remain_takeable_def]
      post_wf cross_wf post cover
    by blast
qed

corollary posted_offers_remain_takeable_p29:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   posted_offers_remain_takeable (exchange_options_at_version ledger_version)"
  \<comment> \<open>The takeability property, stated through the protocol mapping.\<close>
  by (simp add: posted_offers_remain_takeable_repaired)

corollary limit_adjustment_stable_p29:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   limit_adjustment_stable (exchange_options_at_version ledger_version)"
  \<comment> \<open>Limit-adjustment stability, stated through the protocol mapping.\<close>
  by (simp add: limit_adjustment_stable_repaired)

corollary limit_adjustment_stable_p28_false:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   \<not> limit_adjustment_stable (exchange_options_at_version ledger_version)"
  \<comment> \<open>The same property is false before protocol 29, so this is a behavioral
    repair rather than a restatement.\<close>
  by (simp add: legacy_exchange_options_def
      limit_adjustment_stable_counterexample)

text \<open>
  @{thm [source] limit_adjustment_stable_p29} together with
  @{thm [source] limit_adjustment_stable_p28_false} explains a design choice
  in the protocol-29 change that is otherwise unexplained by this model.
  Before protocol 29, reducing a maker's buying limit to exactly its booked
  liability could make a posted offer untakeable, which is why stellar-core
  refuses such offers at overlay admission.  From protocol 29 the property
  holds outright, which is why \<open>doCheckValidForOverlay\<close> returns immediately at
  that version: the filter has nothing left to prevent.

  The overlay filter itself is out of scope here, and this pair is not a proof
  about it.  It is the statement of the ledger-level property the filter
  existed to protect, before and after the boundary.
\<close>


section \<open>The ManageBuy route at protocol 29\<close>

text \<open>
  Every result above enters the ladder through @{const post_offer}, the
  ManageSell route.  A \<open>ManageBuyOffer\<close> reaches the book through
  @{const post_buy_offer}, which differs in three ways that matter here: the
  resting offer sits at the inverted canonical price @{term "(price_d, price_n)"},
  the operation caps are an unlimited send cap and a finite receive cap of
  @{term buy_amount}, and the request-time liabilities are versioned.  None of
  the ladder theorems applied to it.

  This section supplies the missing provenance.  Its pivot is that neither
  @{thm [source] positive_legacy_adjustment_is_stored_offer} nor
  @{thm [source] positive_repaired_adjustment_is_legacy_stored_offer} mentions
  a party state or a cap shape: both recover cap non-negativity from the
  exchange bounds of the successful adjustment itself.  Composing either with
  the core created-branch inversion therefore gives stored-offer provenance for
  \<^emph>\<open>any\<close> posting through @{const post_offer_core}, at either side of the
  protocol boundary, with no well-formedness hypothesis at all.
\<close>

subsection \<open>Counterexample-first executable probes\<close>

definition small_buy_upgrade_case ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> bool"
  where
    "small_buy_upgrade_case ledger_version price_n price_d buy_amount \<longleftrightarrow>
      (case post_buy_offer ledger_version price_n price_d buy_amount
          migration_probe_maker of
         Cxx_Ok (Post_Created posted maker_after) \<Rightarrow>
           legacy_stored_offer price_d price_n posted \<and>
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

subsection \<open>Stored-offer provenance for the common posting core\<close>

lemma exchange_options_at_version_cases:
  "exchange_options_at_version ledger_version = legacy_exchange_options \<or>
   exchange_options_at_version ledger_version = repaired_exchange_options"
  \<comment> \<open>The protocol mapping has exactly the two configurations the ladder
    distinguishes.\<close>
  by (simp add: exchange_options_at_version_def)

lemma post_offer_core_created_is_legacy_stored_offer:
  assumes post:
      "post_offer_core price_n price_d request_valid buying_liability
         selling_liability max_send_cap max_receive_cap maker options =
       Cxx_Ok (Post_Created posted maker_after)"
    and options:
      "options = legacy_exchange_options \<or>
       options = repaired_exchange_options"
  shows "legacy_stored_offer price_n price_d posted"
text \<open>
  Proof sketch: the created-branch inversion supplies positive price
  components, a positive posted amount, and the adjustment call that returned
  it.  Whichever of the two configurations the post used, the matching
  positive-adjustment provenance lemma turns that successful adjustment into
  the unlimited legacy fixed point, recovering both non-negative caps from the
  adjustment's own exchange bounds.  No party-state well-formedness and no
  assumption about the cap shape is needed.
\<close>
proof -
  note facts = post_offer_core_created_facts [OF post]
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and posted_positive: "0 < sint posted"
    using facts by simp_all
  note adjustment = post_offer_core_created_adjustment [OF post]
  from options show ?thesis
  proof
    assume legacy: "options = legacy_exchange_options"
    show ?thesis
      by (rule positive_legacy_adjustment_is_stored_offer
            [OF pn pd adjustment [unfolded legacy] posted_positive])
  next
    assume repaired: "options = repaired_exchange_options"
    show ?thesis
      by (rule positive_repaired_adjustment_is_legacy_stored_offer
            [OF pn pd adjustment [unfolded repaired] posted_positive])
  qed
qed

theorem buy_post_created_is_stored_offer:
  assumes post:
      "post_buy_offer ledger_version price_n price_d buy_amount maker =
       Cxx_Ok (Post_Created posted maker_after)"
  shows "legacy_stored_offer price_d price_n posted"
  \<comment> \<open>An offer created by a \<open>ManageBuyOffer\<close> satisfies the intrinsic
    stored-offer invariant at its inverted canonical price.\<close>
text \<open>
  Proof sketch: unfold the buy wrapper into the common posting core and apply
  the core provenance lemma, whose two admissible configurations are exactly
  the range of the protocol mapping.  The core's price arguments are the
  submitted price components in the opposite order, which is where the
  inverted conclusion comes from.
\<close>
  using post_offer_core_created_is_legacy_stored_offer
    [OF post [unfolded post_buy_offer_def]
      exchange_options_at_version_cases] .

text \<open>
  @{thm [source] buy_post_created_is_stored_offer} holds at every ledger
  version, not just before protocol 29, because the intrinsic invariant is
  about the \<^emph>\<open>stored\<close> projection and both configurations of the adjustment
  produce a legacy unlimited fixed point when they succeed positively.  It is
  therefore strictly stronger than
  @{thm [source] legacy_post_created_is_stored_offer}, which is stated for the
  legacy configuration only.  The request-time liabilities remain genuinely
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
  using legacy_stored_offer_has_safe_full_cross_repaired
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
  using legacy_offer_repaired_cross_preserves_invariants
    [OF buy_post_created_is_stored_offer [OF post] maker_wf cover taker_wf]
    cross activation
  by simp

subsection \<open>Protocol-29 takeability and limit stability for ManageBuy\<close>

definition posted_buy_offers_remain_takeable :: "uint32 \<Rightarrow> bool"
  where
    "posted_buy_offers_remain_takeable ledger_version \<longleftrightarrow>
      (\<forall>price_n price_d buy_amount maker_at_post posted maker_after
         maker_at_cross.
        party_state_wf maker_at_post \<and>
        party_state_wf maker_at_cross \<and>
        post_buy_offer ledger_version price_n price_d buy_amount
            maker_at_post = Cxx_Ok (Post_Created posted maker_after) \<and>
        maker_covers_offer_liabilities price_d price_n posted
          maker_at_cross \<longrightarrow>
        (\<exists>taker taker_amount crossed.
          party_state_wf taker \<and>
          0 < sint (can_buy_at_most taker) \<and>
          0 < sint
            (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
          cross_offer_v10 price_d price_n posted maker_at_cross taker
            taker_amount Exchange_Normal
            (exchange_options_at_version ledger_version) = Cxx_Ok crossed \<and>
          0 < sint (cross_wheat_received crossed) \<and>
          0 < sint (cross_sheep_send crossed)))"

text \<open>
  @{const posted_buy_offers_remain_takeable} is
  @{const posted_offers_remain_takeable} for the ManageBuy route.  It is
  indexed by a ledger version rather than an option record because
  @{const post_buy_offer} is: the same version selects the request
  liabilities, the posting adjustment, and the crossing arithmetic.  The
  offer's canonical price is the submitted price inverted, so both the
  coverage hypothesis and the crossing call use
  @{term "(price_d, price_n)"}.
\<close>

definition buy_limit_adjustment_stable :: "uint32 \<Rightarrow> bool"
  where
    "buy_limit_adjustment_stable ledger_version \<longleftrightarrow>
      (\<forall>price_n price_d buy_amount maker_at_post posted maker_after
         new_sheep_limit.
        party_state_wf maker_at_post \<and>
        post_buy_offer ledger_version price_n price_d buy_amount
            maker_at_post = Cxx_Ok (Post_Created posted maker_after) \<longrightarrow>
        (let maker_at_cross =
           maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>
         in party_state_wf maker_at_cross \<longrightarrow>
           (\<exists>taker taker_amount crossed.
             party_state_wf taker \<and>
             0 < sint (can_buy_at_most taker) \<and>
             0 < sint
               (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
             cross_offer_v10 price_d price_n posted maker_at_cross taker
               taker_amount Exchange_Normal
               (exchange_options_at_version ledger_version) =
                 Cxx_Ok crossed \<and>
             0 < sint (cross_wheat_received crossed) \<and>
             0 < sint (cross_sheep_send crossed))))"

text \<open>
  @{const buy_limit_adjustment_stable} is @{const limit_adjustment_stable} for
  the ManageBuy route, with the same inversion of the canonical price.
\<close>

theorem posted_buy_offers_remain_takeable_p29:
  assumes activation:
    "protocol_version_starts_from ledger_version protocol_version_v29"
  shows "posted_buy_offers_remain_takeable ledger_version"
  \<comment> \<open>From protocol 29 on, an offer created by a successful \<open>ManageBuyOffer\<close>
    can still be crossed for positive amounts by some well-formed taker,
    whenever the maker covers its liabilities.\<close>
text \<open>
  Proof sketch: buy provenance turns the created post directly into the
  intrinsic stored-offer invariant at the inverted price --- no symmetric
  normalization and no replay step is needed here, because the provenance
  lemma already absorbed both.  The ladder's existential full-take theorem
  then applies to the covered offer, and its maximum-capacity counterparty is
  the required witness.
\<close>
proof -
  have from_v29: "ledger_version_from_v29 ledger_version"
    using activation by (simp add: ledger_version_from_v29_def)
  show ?thesis
    unfolding posted_buy_offers_remain_takeable_def
  proof (intro allI impI)
    fix price_n price_d buy_amount maker_at_post posted maker_after
      maker_at_cross
    assume prem:
      "party_state_wf maker_at_post \<and>
       party_state_wf maker_at_cross \<and>
       post_buy_offer ledger_version price_n price_d buy_amount
           maker_at_post = Cxx_Ok (Post_Created posted maker_after) \<and>
       maker_covers_offer_liabilities price_d price_n posted maker_at_cross"
    have cross_wf: "party_state_wf maker_at_cross" using prem by blast
    have post:
        "post_buy_offer ledger_version price_n price_d buy_amount
           maker_at_post = Cxx_Ok (Post_Created posted maker_after)"
      using prem by blast
    have cover:
        "maker_covers_offer_liabilities price_d price_n posted maker_at_cross"
      using prem by blast
    have posted_positive: "0 < sint posted"
      using post_offer_core_created_facts
        [OF post [unfolded post_buy_offer_def]]
      by simp
    obtain crossed where cross:
        "cross_offer_v10 price_d price_n posted maker_at_cross
           maximum_capacity_taker int64_max Exchange_Normal
           (exchange_options_at_version ledger_version) = Cxx_Ok crossed"
      and wheat: "cross_wheat_received crossed = posted"
      and sheep: "0 < sint (cross_sheep_send crossed)"
      using buy_post_created_offer_has_safe_full_cross_at_p29
        [OF post from_v29 cross_wf cover]
      by blast
    have taker_wf: "party_state_wf maximum_capacity_taker" by eval
    have taker_buy: "0 < sint (can_buy_at_most maximum_capacity_taker)"
      by eval
    have taker_send:
        "0 < sint
          (signed_min64 int64_max (can_sell_at_most maximum_capacity_taker))"
      by eval
    show
      "\<exists>taker taker_amount crossed.
        party_state_wf taker \<and>
        0 < sint (can_buy_at_most taker) \<and>
        0 < sint (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
        cross_offer_v10 price_d price_n posted maker_at_cross taker
          taker_amount Exchange_Normal
          (exchange_options_at_version ledger_version) = Cxx_Ok crossed \<and>
        0 < sint (cross_wheat_received crossed) \<and>
        0 < sint (cross_sheep_send crossed)"
      using taker_wf taker_buy taker_send cross sheep posted_positive wheat
      by blast
  qed
qed

theorem buy_limit_adjustment_stable_p29:
  assumes activation:
    "protocol_version_starts_from ledger_version protocol_version_v29"
  shows "buy_limit_adjustment_stable ledger_version"
  \<comment> \<open>From protocol 29 on, changing a maker's buying limit to any value that
    leaves it well formed cannot make its \<open>ManageBuyOffer\<close> untakeable.\<close>
text \<open>
  Proof sketch: a successful buy posting acquires the created offer's
  liabilities at the inverted canonical price, so the resulting maker covers
  them.  Changing only the buying limit leaves those booked liabilities
  untouched, so coverage survives the change, and protocol-29 ManageBuy
  takeability then supplies the taker.
\<close>
  unfolding buy_limit_adjustment_stable_def Let_def
proof (intro allI impI)
  fix price_n price_d buy_amount maker_at_post posted maker_after
    new_sheep_limit
  assume prem:
    "party_state_wf maker_at_post \<and>
     post_buy_offer ledger_version price_n price_d buy_amount maker_at_post =
       Cxx_Ok (Post_Created posted maker_after)"
  assume cross_wf:
    "party_state_wf (maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>)"
  have post_wf: "party_state_wf maker_at_post" using prem by blast
  have post:
      "post_buy_offer ledger_version price_n price_d buy_amount
         maker_at_post = Cxx_Ok (Post_Created posted maker_after)"
    using prem by blast
  have acquire:
      "acquire_offer_liabilities price_d price_n posted maker_at_post =
       Cxx_Ok maker_after"
    using post_offer_core_created_facts
      [OF post [unfolded post_buy_offer_def]]
    by simp
  have cover:
      "maker_covers_offer_liabilities price_d price_n posted
         (maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>)"
    using acquired_offer_is_covered [OF post_wf acquire] by simp
  show
    "\<exists>taker taker_amount crossed.
      party_state_wf taker \<and>
      0 < sint (can_buy_at_most taker) \<and>
      0 < sint (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
      cross_offer_v10 price_d price_n posted
        (maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>) taker taker_amount
        Exchange_Normal (exchange_options_at_version ledger_version) =
          Cxx_Ok crossed \<and>
      0 < sint (cross_wheat_received crossed) \<and>
      0 < sint (cross_sheep_send crossed)"
    using posted_buy_offers_remain_takeable_p29 [OF activation,
        unfolded posted_buy_offers_remain_takeable_def]
      post_wf cross_wf post cover
    by blast
qed

text \<open>
  Both routes are now covered at protocol 29.  The request-level corollaries
  below say so in one statement, over the @{type offer_request} constructor
  that @{const post_offer_request} dispatches on, without introducing a new
  predicate: the per-route theorems are the two cases.
\<close>

corollary posted_request_offers_remain_takeable_p29:
  assumes activation:
      "protocol_version_starts_from ledger_version protocol_version_v29"
    and post_wf: "party_state_wf maker_at_post"
    and cross_wf: "party_state_wf maker_at_cross"
    and post:
      "post_offer_request ledger_version request maker_at_post =
       Cxx_Ok (Post_Created posted maker_after)"
    and cover:
      "maker_covers_offer_liabilities (request_canonical_price_n request)
         (request_canonical_price_d request) posted maker_at_cross"
  shows
    "\<exists>taker taker_amount crossed.
      party_state_wf taker \<and>
      0 < sint (can_buy_at_most taker) \<and>
      0 < sint (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
      cross_offer_v10 (request_canonical_price_n request)
        (request_canonical_price_d request) posted maker_at_cross taker
        taker_amount Exchange_Normal
        (exchange_options_at_version ledger_version) = Cxx_Ok crossed \<and>
      0 < sint (cross_wheat_received crossed) \<and>
      0 < sint (cross_sheep_send crossed)"
  \<comment> \<open>From protocol 29 on, every offer created by either posting operation
    remains takeable while its maker covers it.\<close>
text \<open>
  Proof sketch: split on the request constructor.  The sell case is the
  established repaired takeability theorem applied through the sell-wrapper
  refinement, the buy case is the ManageBuy theorem above, and the canonical
  price projections are the arguments each route already uses.
\<close>
proof (cases request)
  case (Manage_Sell price_n price_d amount)
  have post_sell:
      "post_offer price_n price_d amount maker_at_post
         repaired_exchange_options =
       Cxx_Ok (Post_Created posted maker_after)"
    using post [unfolded Manage_Sell post_offer_request.simps]
      activation
    by (simp add: post_sell_offer_eq_post_offer
        exchange_options_at_version_def)
  show ?thesis
    using posted_offers_remain_takeable_repaired
      [unfolded posted_offers_remain_takeable_def]
      post_wf cross_wf post_sell cover activation Manage_Sell
    by (simp add: exchange_options_at_version_def)
next
  case (Manage_Buy price_n price_d buy_amount)
  have post_buy:
      "post_buy_offer ledger_version price_n price_d buy_amount
         maker_at_post = Cxx_Ok (Post_Created posted maker_after)"
    using post [unfolded Manage_Buy post_offer_request.simps] .
  show ?thesis
    using posted_buy_offers_remain_takeable_p29 [OF activation,
        unfolded posted_buy_offers_remain_takeable_def]
      post_wf cross_wf post_buy cover Manage_Buy
    by simp
qed

end
