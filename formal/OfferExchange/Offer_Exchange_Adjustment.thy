theory Offer_Exchange_Adjustment
  imports Offer_Exchange_Arithmetic
begin

section \<open>Offer adjustment and liabilities\<close>

text \<open>
  This theory isolates the maker-independent arithmetic surrounding
  @{const exchange_v10_with_options}.  It models offer adjustment and liability projection,
  then defines the offer and raw-request filters used before ledger state is
  consulted.  Party state, ordinary pre-flight, posting, liability mutation,
  and crossing belong to \<open>Offer_Exchange_Lifecycle\<close>.
\<close>

subsection \<open>Offer adjustment and offer liabilities\<close>

definition adjust_offer_with_options ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      exchange_options \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>adjustOffer(Price, \<dots>)\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "adjust_offer_with_options price_n price_d max_wheat_send max_sheep_receive
        options = do {
       result \<leftarrow> exchange_v10_with_options price_n price_d max_wheat_send int64_max
         int64_max max_sheep_receive Exchange_Normal options;
       Cxx_Ok (num_wheat_received result)
     }"

text \<open>
  @{const adjust_offer_with_options} is the price-level overload of \<open>adjustOffer\<close>
  (\<open>OfferExchange.cpp\<close>): the
  wheat side of a hypothetical cross against a counterparty without limits.
  The final argument is an @{typ exchange_options} record.  Its two exact-cap
  fields model the protocol gates threaded to ledger-level call sites; the
  lifecycle theory supplies the state-dependent caps at those sites.
\<close>

definition adjust_offer ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>adjustOffer\<close> with a ledger version (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "adjust_offer ledger_version price_n price_d max_wheat_send
        max_sheep_receive =
       adjust_offer_with_options price_n price_d max_wheat_send
         max_sheep_receive (exchange_options_at_version ledger_version)"

text \<open>
  @{const adjust_offer} is the protocol-facing overload of \<open>adjustOffer\<close> as
  protocol 29 leaves it: a leading ledger version, the price, the send cap, and the
  receive cap.  Threading the version here is what carries the repaired
  arithmetic into posting adjustment, preventative adjustment before a cross,
  and post-trade remainder adjustment, since all three go through this one
  helper.
\<close>

lemma adjust_offer_legacy:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   adjust_offer ledger_version price_n price_d max_wheat_send
     max_sheep_receive =
   adjust_offer_with_options price_n price_d max_wheat_send max_sheep_receive
     legacy_exchange_options"
  by (simp add: adjust_offer_def)

lemma adjust_offer_repaired:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   adjust_offer ledger_version price_n price_d max_wheat_send
     max_sheep_receive =
   adjust_offer_with_options price_n price_d max_wheat_send max_sheep_receive
     repaired_exchange_options"
  by (simp add: adjust_offer_def)

text \<open>
  The C++ liability helpers carry no \<open>exactReceiveCap\<close> flag, and the fix
  did not touch \<open>TransactionUtils.cpp\<close>: liabilities are computed against a
  counterparty with a receive cap of \<open>INT64_MAX\<close>, where the clamp inside
  \<open>calculateOfferAmountFromValue\<close> restores the plain cap.  The
  lemma records that agreement, so the flag-free liability definitions below
  match both protocol behaviors at once.  Proof sketch: after the shared
  send-side multiplication, both sides multiply @{const int64_max} by the price
  denominator; that product is below @{term "(2::int) ^ 126"} and the relaxed
  cap adds less than @{term "(2::int) ^ 64"}, so the 128-bit addition cannot
  wrap, the relaxed receive value is at least the plain one, and the extra
  minimum collapses.
\<close>

lemma exact_receive_cap_collapses_at_unlimited_receive:
  "calculate_offer_value_with_exact_receive_cap price_n price_d max_send
     int64_max =
   calculate_offer_value price_n price_d max_send int64_max"
proof (cases "big_multiply max_send (scast price_n)")
  case (Cxx_Err e)
  then show ?thesis
    by (simp add: calculate_offer_value_with_exact_receive_cap_def
        calculate_offer_value_def)
next
  case send_ok: (Cxx_Ok send_value)
  show ?thesis
  proof (cases "big_multiply int64_max (scast price_d)")
    case (Cxx_Err e)
    then show ?thesis
      using send_ok
      by (simp add: calculate_offer_value_with_exact_receive_cap_def
          calculate_offer_value_def)
  next
    case receive_ok: (Cxx_Ok receive_product)
    have factors_nonnegative: "0 \<le> sint int64_max"
        "0 \<le> sint (scast price_d :: int64)"
      and product_word: "receive_product =
        word_of_int (sint int64_max * sint (scast price_d :: int64))"
      using receive_ok
      by (simp_all add: big_multiply_def split: if_splits)
    have product_value: "uint receive_product =
        sint int64_max * sint (scast price_d :: int64)"
      using big_multiply_uint_value [OF factors_nonnegative] product_word
      by simp
    have product_bound: "sint int64_max *
        sint (scast price_d :: int64) < (2 :: int) ^ 126"
    proof -
      have "sint int64_max < (2 :: int) ^ 63"
        using sint_lt [of int64_max] by simp
      moreover have "sint (scast price_d :: int64) < (2 :: int) ^ 63"
        using sint_lt [of "scast price_d :: int64"] by simp
      ultimately have "sint int64_max *
          sint (scast price_d :: int64) < (2 :: int) ^ 63 * 2 ^ 63"
        using factors_nonnegative by (intro mult_strict_mono) simp_all
      then show ?thesis by simp
    qed
    have addend_bound:
      "uint (ucast (scast (price_d - 1) :: int64) :: uint128) <
        (2 :: int) ^ 64"
      using uint_lt2p [of "scast (price_d - 1) :: int64"]
      by (simp add: uint_up_ucast is_up)
    have no_wrap: "uint receive_product +
        uint (ucast (scast (price_d - 1) :: int64) :: uint128) <
        (2 :: int) ^ 128"
      using product_value product_bound addend_bound by simp
    have relaxed_ge: "receive_product \<le> receive_product +
        ucast (scast (price_d - 1) :: int64)"
      using no_wrap by (simp add: no_olen_add ac_simps)
    show ?thesis
      using send_ok receive_ok relaxed_ge
      by (simp add: calculate_offer_value_with_exact_receive_cap_def
          calculate_offer_value_def)
  qed
qed

corollary calculate_offer_amount_from_value_collapses_at_unlimited_receive:
  "calculate_offer_amount_from_value price_n price_d max_send int64_max =
     (calculate_offer_value price_n price_d max_send int64_max \<bind>
      (\<lambda>offer_value.
        big_divide_or_throw128 offer_value (scast price_n) Cxx_Round_Down))"
  \<comment> \<open>At an unlimited receive cap the protocol-29 helper computes the same
    amount as the protocol-28 calculation it replaces.\<close>
  text \<open>
    Proof sketch: the helper is the relaxed value followed by the round-down
    division, and at @{const int64_max} the retained clamp collapses the
    relaxed value to the plain one, so the two divisions have equal
    numerators.
  \<close>
  by (simp add: exact_receive_cap_collapses_at_unlimited_receive)

definition offer_selling_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>getOfferSellingLiabilities\<close> (\<open>TransactionUtils.cpp\<close>)\<close>
  where
    "offer_selling_liabilities price_n price_d amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds_with_options price_n price_d
         amount int64_max int64_max int64_max Exchange_Normal
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr>;
       Cxx_Ok (num_wheat_received result)
     }"

definition offer_buying_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>getOfferBuyingLiabilities\<close> (\<open>TransactionUtils.cpp\<close>)\<close>
  where
    "offer_buying_liabilities price_n price_d amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds_with_options price_n price_d
         amount int64_max int64_max int64_max Exchange_Normal
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr>;
       Cxx_Ok (num_sheep_send result)
     }"

text \<open>
  @{thm [source] calculate_offer_amount_from_value_collapses_at_unlimited_receive}
  is the reason these two definitions need no protocol parameter.  Both
  @{const offer_selling_liabilities} and @{const offer_buying_liabilities}
  value a stored offer against a counterparty whose receive cap is
  @{const int64_max}, and there the two protocols agree.  Protocol 29
  therefore recomputes exactly the liabilities protocol 28 booked, which is
  what makes activation safe without rewriting any stored offer.  Removing
  the \<open>INT64_MAX * priceD\<close> clamp would invalidate this, which is why
  protocol 29 retains it.
\<close>

subsection \<open>Protocol compatibility of the unlimited-cap projections\<close>

lemma pre_thresholds_options_irrelevant_at_unlimited_caps:
  "exchange_v10_without_price_error_thresholds_with_options price_n price_d
     max_wheat_send int64_max int64_max int64_max rounding options =
   exchange_v10_without_price_error_thresholds_with_options price_n price_d
     max_wheat_send int64_max int64_max int64_max rounding
     legacy_exchange_options"
  \<comment> \<open>With every counterparty cap at @{const int64_max} the exchange does not
    depend on the exact-cap options at all.\<close>
  text \<open>
    Proof sketch: the options are consulted in exactly two branches, and each
    consults them on a call whose receive cap is @{const int64_max}.  After
    naming the two offer values, the retained clamp collapses each relaxed
    value to the plain one, so both branches compute what the legacy
    configuration computes and the two runs agree everywhere.
  \<close>
proof (cases "calculate_offer_value price_n price_d max_wheat_send int64_max")
  case (Cxx_Err e)
  then show ?thesis
    by (simp add: exchange_v10_without_price_error_thresholds_with_options_def)
next
  case wheat_ok: (Cxx_Ok wheat_value)
  show ?thesis
  proof (cases "calculate_offer_value price_d price_n int64_max int64_max")
    case (Cxx_Err e)
    then show ?thesis
      using wheat_ok
      by (simp add:
          exchange_v10_without_price_error_thresholds_with_options_def)
  next
    case sheep_ok: (Cxx_Ok sheep_value)
    show ?thesis
      using wheat_ok sheep_ok
      by (simp add: exchange_v10_without_price_error_thresholds_with_options_def
          exchange_v10_amounts_def Let_def legacy_exchange_options_def
          exact_receive_cap_collapses_at_unlimited_receive)
  qed
qed

definition offer_selling_liabilities_at_version ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>getOfferSellingLiabilities\<close> (\<open>TransactionUtils.cpp\<close>,
    \<open>invariant/LiabilitiesMatchOffers.cpp\<close>)\<close>
  where
    "offer_selling_liabilities_at_version ledger_version price_n price_d
        amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds ledger_version
         price_n price_d amount int64_max int64_max int64_max Exchange_Normal;
       Cxx_Ok (num_wheat_received result)
     }"

definition offer_buying_liabilities_at_version ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>getOfferBuyingLiabilities\<close> (\<open>TransactionUtils.cpp\<close>,
    \<open>invariant/LiabilitiesMatchOffers.cpp\<close>)\<close>
  where
    "offer_buying_liabilities_at_version ledger_version price_n price_d
        amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds ledger_version
         price_n price_d amount int64_max int64_max int64_max Exchange_Normal;
       Cxx_Ok (num_sheep_send result)
     }"

text \<open>
  Protocol 29 threads the ledger version through both liability helpers in
  \<open>TransactionUtils.cpp\<close> and through the copies the
  \<open>LiabilitiesMatchOffers\<close> invariant keeps.  The two definitions above have
  those signatures.  The theorems below show the version makes no difference,
  which is why the flag-free projections used throughout the lifecycle theory
  remain correct for both protocols.
\<close>

theorem offer_selling_liabilities_version_independent:
  "offer_selling_liabilities_at_version ledger_version price_n price_d amount =
   offer_selling_liabilities price_n price_d amount"
  \<comment> \<open>Protocol 29 recomputes exactly the selling liability protocol 28
    booked.\<close>
  text \<open>
    Proof sketch: both project the same field out of a pre-threshold exchange
    whose counterparty caps are all @{const int64_max}, and there the exchange
    does not depend on the options the version selects.
  \<close>
  by (simp add: offer_selling_liabilities_at_version_def
      offer_selling_liabilities_def
      exchange_v10_without_price_error_thresholds_def
      pre_thresholds_options_irrelevant_at_unlimited_caps
        [where options = "exchange_options_at_version ledger_version"]
      legacy_exchange_options_def)

theorem offer_buying_liabilities_version_independent:
  "offer_buying_liabilities_at_version ledger_version price_n price_d amount =
   offer_buying_liabilities price_n price_d amount"
  \<comment> \<open>Protocol 29 recomputes exactly the buying liability protocol 28
    booked.\<close>
  text \<open>
    Proof sketch: as for the selling liability, with the other projection.
  \<close>
  by (simp add: offer_buying_liabilities_at_version_def
      offer_buying_liabilities_def
      exchange_v10_without_price_error_thresholds_def
      pre_thresholds_options_irrelevant_at_unlimited_caps
        [where options = "exchange_options_at_version ledger_version"]
      legacy_exchange_options_def)

theorem persistent_liabilities_agree_across_activation:
  "offer_selling_liabilities_at_version v28 price_n price_d amount =
   offer_selling_liabilities_at_version v29 price_n price_d amount"
  "offer_buying_liabilities_at_version v28 price_n price_d amount =
   offer_buying_liabilities_at_version v29 price_n price_d amount"
  \<comment> \<open>A stored offer has the same booked liabilities before and after the
    protocol-29 upgrade, at any two ledger versions.\<close>
  text \<open>
    Proof sketch: each side is version-independent, so both reduce to the same
    flag-free projection.
  \<close>
  by (simp_all add: offer_selling_liabilities_version_independent
      offer_buying_liabilities_version_independent)

text \<open>
  @{thm [source] persistent_liabilities_agree_across_activation} is the hinge
  of migration safety.  Liabilities acquired under protocol 28 are exactly the
  liabilities protocol 29 recomputes when it releases them, so activating
  protocol 29 needs no liability rewrite and no stored-offer migration pass.
  It depends on the retained \<open>INT64_MAX * priceD\<close> clamp: without that clamp
  the relaxed receive value would exceed the plain one even at an unlimited
  cap and the two protocols would disagree here.
\<close>

definition manage_buy_selling_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>ManageBuyOfferOpFrame::getOfferSellingLiabilities\<close>
    (\<open>ManageBuyOfferOpFrame.cpp\<close>)\<close>
  where
    "manage_buy_selling_liabilities price_n price_d buy_amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds_with_options
         price_d price_n int64_max int64_max int64_max buy_amount
         Exchange_Normal
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr>;
       Cxx_Ok (num_wheat_received result)
     }"

definition manage_buy_buying_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>ManageBuyOfferOpFrame::getOfferBuyingLiabilities\<close>
    (\<open>ManageBuyOfferOpFrame.cpp\<close>)\<close>
  where
    "manage_buy_buying_liabilities price_n price_d buy_amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds_with_options
         price_d price_n int64_max int64_max int64_max buy_amount
         Exchange_Normal
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr>;
       Cxx_Ok (num_sheep_send result)
     }"

definition manage_buy_selling_liabilities_at_version ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>ManageBuyOfferOpFrame::getOfferSellingLiabilities\<close>
    (\<open>ManageBuyOfferOpFrame.cpp\<close>)\<close>
  where
    "manage_buy_selling_liabilities_at_version ledger_version price_n price_d
        buy_amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds ledger_version
         price_d price_n int64_max int64_max int64_max buy_amount
         Exchange_Normal;
       Cxx_Ok (num_wheat_received result)
     }"

definition manage_buy_buying_liabilities_at_version ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>ManageBuyOfferOpFrame::getOfferBuyingLiabilities\<close>
    (\<open>ManageBuyOfferOpFrame.cpp\<close>)\<close>
  where
    "manage_buy_buying_liabilities_at_version ledger_version price_n price_d
        buy_amount = do {
       result \<leftarrow> exchange_v10_without_price_error_thresholds ledger_version
         price_d price_n int64_max int64_max int64_max buy_amount
         Exchange_Normal;
       Cxx_Ok (num_sheep_send result)
     }"

text \<open>
  Protocol 29 threads the ledger version through both manage-buy request helpers,
  exactly as it does for the stored-offer projections.  Here, however, the
  version genuinely matters.  A stored offer is valued against a counterparty
  whose every cap is @{const int64_max}, where the retained clamp makes the two
  protocols agree.  A manage-buy request instead places the finite submitted
  buy amount on the receive cap, which is precisely the cap the repaired
  non-staying branch consults, so
  @{thm [source] pre_thresholds_options_irrelevant_at_unlimited_caps} does not
  apply and the computed liabilities can move at the boundary.
\<close>

lemma manage_buy_liabilities_at_version_legacy:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   manage_buy_selling_liabilities_at_version ledger_version price_n price_d
     buy_amount = manage_buy_selling_liabilities price_n price_d buy_amount"
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   manage_buy_buying_liabilities_at_version ledger_version price_n price_d
     buy_amount = manage_buy_buying_liabilities price_n price_d buy_amount"
  \<comment> \<open>Before protocol 29 the versioned helpers are the existing flag-free
    ones, so every protocol-28 result about them still applies.\<close>
  by (simp_all add: manage_buy_selling_liabilities_at_version_def
      manage_buy_buying_liabilities_at_version_def
      manage_buy_selling_liabilities_def manage_buy_buying_liabilities_def
      exchange_v10_without_price_error_thresholds_def
      legacy_exchange_options_def)

lemma manage_buy_liabilities_at_version_repaired:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   manage_buy_selling_liabilities_at_version ledger_version price_n price_d
     buy_amount =
   (exchange_v10_without_price_error_thresholds_with_options price_d price_n
      int64_max int64_max int64_max buy_amount Exchange_Normal
      repaired_exchange_options \<bind>
    (\<lambda>result. Cxx_Ok (num_wheat_received result)))"
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   manage_buy_buying_liabilities_at_version ledger_version price_n price_d
     buy_amount =
   (exchange_v10_without_price_error_thresholds_with_options price_d price_n
      int64_max int64_max int64_max buy_amount Exchange_Normal
      repaired_exchange_options \<bind>
    (\<lambda>result. Cxx_Ok (num_sheep_send result)))"
  \<comment> \<open>From protocol 29 the versioned helpers use the repaired kernel.\<close>
  by (simp_all add: manage_buy_selling_liabilities_at_version_def
      manage_buy_buying_liabilities_at_version_def
      exchange_v10_without_price_error_thresholds_def)

lemma manage_buy_request_liabilities_change_at_activation:
  "manage_buy_selling_liabilities_at_version 28 100 101 4 = Cxx_Ok 3"
  "manage_buy_selling_liabilities_at_version 29 100 101 4 = Cxx_Ok 4"
  "manage_buy_buying_liabilities_at_version 28 100 101 4 = Cxx_Ok 3"
  "manage_buy_buying_liabilities_at_version 29 100 101 4 = Cxx_Ok 4"
  \<comment> \<open>A manage-buy request for four units at price \<open>100/101\<close> books three
    units of each liability before protocol 29 and four from protocol 29 on.\<close>
  by eval+

text \<open>
  @{thm [source] manage_buy_request_liabilities_change_at_activation} is the
  counterpart of
  @{thm [source] persistent_liabilities_agree_across_activation}, and it goes
  the other way.  Stored-offer liabilities are the same at every ledger
  version, which is what makes activation safe without rewriting any offer.
  Manage-buy request-time liabilities are not: the same submitted request
  books different amounts before and after the boundary.  This is an ordinary
  protocol-behavior change at request time, not a migration hazard, because
  nothing persists a request's liabilities -- only the resulting stored offer
  is persisted, and that is valued by the version-independent projections.
  The equality theorem for stored offers must therefore not be reused for this
  path.
\<close>

definition manage_buy_normalized_amount ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64"
  \<comment> \<open>the canonical resting selling amount of a manage-buy request;
    no standalone C++ entry point\<close>
  where
    "manage_buy_normalized_amount price_n price_d buy_amount =
      (let offer_n = sint price_d;
           offer_d = sint price_n;
           wheat_value =
             min (int64_max_int * offer_n)
               (sint buy_amount * offer_d);
           selling =
             (if offer_n > offer_d
              then wheat_value div offer_n
              else
                (let sheep = wheat_value div offer_d
                 in (sheep * offer_d + offer_n - 1) div offer_n))
       in word_of_int selling)"

text \<open>
  @{const offer_selling_liabilities} and @{const offer_buying_liabilities}
  are \<open>getOfferSellingLiabilities\<close> and \<open>getOfferBuyingLiabilities\<close>
  (\<open>TransactionUtils.cpp\<close>): the reservation demanded by an offer is
  defined as the outcome of its own unlimited cross, before the price-error
  thresholds.
\<close>

text \<open>
  The two manage-buy liability functions model
  \<open>ManageBuyOfferOpFrame::getOfferSellingLiabilities\<close> and
  \<open>getOfferBuyingLiabilities\<close> (\<open>ManageBuyOfferOpFrame.cpp\<close>).
  They invert the submitted price, leave
  the selling side unlimited, and put the submitted buy amount on the receive
  cap.  @{const manage_buy_normalized_amount} exposes the canonical resting
  selling amount computed by that exchange for the swapped price.  stellar-core
  has no standalone entry point for it.  It is deliberately a direct
  integer formula so request normalization remains executable without
  repeating it in the stateful lifecycle or the differential transport layer.
\<close>

subsection \<open>Reusable normalization and replay results\<close>

lemma adjustment_above_floor_cap_replays_unlimited:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and unsaturated:
      "sint amount * sint price_n \<le>
        int64_max_int * sint price_d"
    and cap_nonnegative: "0 \<le> sint max_sheep_receive"
    and above_floor:
      "(sint amount * sint price_n) div sint price_d <
       sint max_sheep_receive"
  shows "adjust_offer_with_options price_n price_d amount max_sheep_receive
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    adjust_offer_with_options price_n price_d amount int64_max
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: Euclidean division places the product strictly below the next
  multiple of the positive denominator.  An integral cap strictly above its
  floor is at least that next integer, so neither this cap nor the unlimited
  cap clips the wheat value.  The normal-exchange characterizations then have
  identical integer amounts, stays flag, and threshold result.
\<close>
proof -
  define floor_cap :: int where
    "floor_cap = (sint amount * sint price_n) div sint price_d"
  have floor_below: "floor_cap < sint max_sheep_receive"
    using above_floor by (simp add: floor_cap_def)
  have remainder_bound:
      "(sint amount * sint price_n) mod sint price_d < sint price_d"
    using pos_mod_bound [OF pd] .
  have division:
      "sint amount * sint price_n =
       floor_cap * sint price_d +
       (sint amount * sint price_n) mod sint price_d"
    using div_mod_decomp_int
      [of "sint amount * sint price_n" "sint price_d"]
    by (simp add: floor_cap_def)
  have send_below_next:
      "sint amount * sint price_n <
       (floor_cap + 1) * sint price_d"
  proof -
    have remainder_step:
        "floor_cap * sint price_d +
           (sint amount * sint price_n) mod sint price_d <
         floor_cap * sint price_d + sint price_d"
      using remainder_bound by (simp only: add_less_cancel_left)
    have before_next:
        "sint amount * sint price_n <
         floor_cap * sint price_d + sint price_d"
      using division remainder_step by linarith
    show ?thesis
      using before_next by (simp add: algebra_simps)
  qed
  have send_below_cap:
      "sint amount * sint price_n <
       sint max_sheep_receive * sint price_d"
  proof -
    have next_le: "floor_cap + 1 \<le> sint max_sheep_receive"
      using floor_below by simp
    have "(floor_cap + 1) * sint price_d \<le>
        sint max_sheep_receive * sint price_d"
      using mult_right_mono [OF next_le less_imp_le [OF pd]] .
    with send_below_next show ?thesis by linarith
  qed
  have wheat_cap:
      "exchange_wheat_value_int price_n price_d amount max_sheep_receive =
       sint amount * sint price_n"
    using send_below_cap
    by (simp add: exchange_wheat_value_int_def min_def)
  have wheat_unlimited:
      "exchange_wheat_value_int price_n price_d amount int64_max =
       sint amount * sint price_n"
    using unsaturated
    by (simp add: exchange_wheat_value_int_def int64_max_def min_def)
  have pre_cap:
      "exchange_v10_pre price_n price_d amount int64_max int64_max
         max_sheep_receive"
    using pn pd amount_positive cap_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  have pre_unlimited:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  note cap_characterization =
    exchange_v10_normal_characterization [OF pre_cap]
  note unlimited_characterization =
    exchange_v10_normal_characterization [OF pre_unlimited]
  have amounts_equal:
      "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         max_sheep_receive Exchange_Normal =
       exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         int64_max Exchange_Normal"
    using wheat_cap wheat_unlimited
    by (simp add: exchange_v10_amounts_int_def Let_def)
  have stays_equal:
      "(exchange_wheat_value_int price_n price_d amount max_sheep_receive >
         exchange_sheep_value_int price_n price_d int64_max int64_max) =
       (exchange_wheat_value_int price_n price_d amount int64_max >
         exchange_sheep_value_int price_n price_d int64_max int64_max)"
    using wheat_cap wheat_unlimited by simp
  show ?thesis
    unfolding adjust_offer_with_options_def
    using cap_characterization unlimited_characterization amounts_equal
      stays_equal
    by simp
qed

lemma manage_sell_request_liabilities_explicit:
  fixes wheat_value selling buying :: int
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
  defines "wheat_value \<equiv>
    min (sint amount * sint price_n)
      (int64_max_int * sint price_d)"
    and "selling \<equiv>
      (if sint price_n > sint price_d
       then wheat_value div sint price_n
       else
         (let sheep = wheat_value div sint price_d
          in (sheep * sint price_d + sint price_n - 1) div sint price_n))"
    and "buying \<equiv>
      (if sint price_n > sint price_d
       then (selling * sint price_n) div sint price_d
       else wheat_value div sint price_d)"
  shows
    "offer_selling_liabilities price_n price_d amount =
       Cxx_Ok (word_of_int selling)"
    "offer_buying_liabilities price_n price_d amount =
       Cxx_Ok (word_of_int buying)"
    "sint (word_of_int selling :: int64) = selling"
    "sint (word_of_int buying :: int64) = buying"
    "0 \<le> selling"
    "selling \<le> sint amount"
    "0 \<le> buying"
text \<open>
  Proof sketch: characterize the request's unlimited, pre-threshold liability
  exchange in unbounded integers.  Its wheat value is the stated minimum, the
  counteroffer is never the side that stays, and the normal rounding formulas
  are exactly the stated selling and buying amounts.  The two liability
  helpers project those fields from the same exchange result.
\<close>
proof -
  have pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  have amount_max: "sint amount \<le> int64_max_int"
    using sint64_upper_bound [of amount] by simp
  have wheat_value_formula:
      "exchange_wheat_value_int price_n price_d amount int64_max = wheat_value"
    by (simp add: exchange_wheat_value_int_def wheat_value_def
        int64_max_def)
  have stays_false:
      "\<not> exchange_wheat_value_int price_n price_d amount int64_max >
        exchange_sheep_value_int price_n price_d int64_max int64_max"
  proof (cases "sint price_n > sint price_d")
    case True
    then show ?thesis
      using wheat_value_formula
      by (simp add: wheat_value_def exchange_sheep_value_int_def
          int64_max_def min_def mult_left_mono split: if_splits)
  next
    case False
    have "sint amount * sint price_n \<le>
        int64_max_int * sint price_n"
      using amount_max less_imp_le [OF pn]
      by (simp add: mult_right_mono)
    then show ?thesis
      using False wheat_value_formula
      by (simp add: wheat_value_def exchange_sheep_value_int_def
          int64_max_def min_def mult_left_mono split: if_splits)
  qed
  have amounts:
      "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         int64_max Exchange_Normal = (selling, buying)"
    unfolding exchange_v10_amounts_int_def selling_def buying_def
    using stays_false wheat_value_formula pn pd
    by (simp add: Let_def split: if_splits)
  have exchange:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
         int64_max int64_max int64_max Exchange_Normal
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok
         (make_exchange_result (word_of_int selling) (word_of_int buying)
           False)"
    using exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, where rounding = Exchange_Normal]
      amounts stays_false
    by simp
  show
    "offer_selling_liabilities price_n price_d amount =
       Cxx_Ok (word_of_int selling)"
    "offer_buying_liabilities price_n price_d amount =
       Cxx_Ok (word_of_int buying)"
    "sint (word_of_int selling :: int64) = selling"
    "sint (word_of_int buying :: int64) = buying"
    "0 \<le> selling"
    "selling \<le> sint amount"
    "0 \<le> buying"
    using exchange
      exchange_v10_amounts_integer_characterization(2,3)
        [OF pre, where rounding = Exchange_Normal] amounts
      exchange_v10_without_price_error_thresholds_result_contract
        [OF pre exchange]
    by (simp_all add: offer_selling_liabilities_def
        offer_buying_liabilities_def make_exchange_result_def)
qed

lemma manage_buy_request_liabilities_explicit:
  fixes wheat_value selling buying :: int
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint buy_amount"
  defines "wheat_value \<equiv>
    min (int64_max_int * sint price_d)
      (sint buy_amount * sint price_n)"
    and "selling \<equiv>
      (if sint price_d > sint price_n
       then wheat_value div sint price_d
       else
         (let sheep = wheat_value div sint price_n
          in (sheep * sint price_n + sint price_d - 1) div sint price_d))"
    and "buying \<equiv>
      (if sint price_d > sint price_n
       then (selling * sint price_d) div sint price_n
       else wheat_value div sint price_n)"
  shows
    "manage_buy_selling_liabilities price_n price_d buy_amount =
       Cxx_Ok (word_of_int selling)"
    "manage_buy_buying_liabilities price_n price_d buy_amount =
       Cxx_Ok (word_of_int buying)"
    "manage_buy_normalized_amount price_n price_d buy_amount =
       word_of_int selling"
    "sint (word_of_int selling :: int64) = selling"
    "sint (word_of_int buying :: int64) = buying"
    "0 \<le> selling"
    "0 \<le> buying"
    "buying \<le> sint buy_amount"
text \<open>
  Proof sketch: characterize the unlimited-send exchange at the inverted raw
  price.  The submitted buy amount is its receive cap, so its wheat value is
  the stated minimum.  The opposing unlimited offer cannot be the smaller
  side, and NORMAL rounding therefore yields exactly the stated canonical
  selling and buying liabilities.  The generated-word bounds follow from the
  general integer characterization.
\<close>
proof -
  have pre:
      "exchange_v10_pre price_d price_n int64_max int64_max int64_max
         buy_amount"
    using pn pd amount_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  have amount_max: "sint buy_amount \<le> int64_max_int"
    using sint64_upper_bound [of buy_amount] by simp
  have wheat_value_formula:
      "exchange_wheat_value_int price_d price_n int64_max buy_amount =
       wheat_value"
    by (simp add: exchange_wheat_value_int_def wheat_value_def
        int64_max_def min.commute)
  have wheat_le_first:
      "wheat_value \<le> int64_max_int * sint price_d"
    unfolding wheat_value_def by simp
  have wheat_le_second:
      "wheat_value \<le> int64_max_int * sint price_n"
  proof -
    have "sint buy_amount * sint price_n \<le>
        int64_max_int * sint price_n"
      using amount_max less_imp_le [OF pn]
      by (simp add: mult_right_mono)
    then show ?thesis unfolding wheat_value_def by simp
  qed
  have stays_false:
      "\<not> exchange_wheat_value_int price_d price_n int64_max buy_amount >
        exchange_sheep_value_int price_d price_n int64_max int64_max"
    using wheat_value_formula wheat_le_first wheat_le_second
    by (simp add: exchange_sheep_value_int_def int64_max_def)
  have amounts:
      "exchange_v10_amounts_int price_d price_n int64_max int64_max
         int64_max buy_amount Exchange_Normal = (selling, buying)"
    unfolding exchange_v10_amounts_int_def selling_def buying_def
    using stays_false wheat_value_formula pn pd
    by (simp add: Let_def split: if_splits)
  have exchange:
      "exchange_v10_without_price_error_thresholds_with_options price_d price_n int64_max
         int64_max int64_max buy_amount Exchange_Normal
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok
         (make_exchange_result (word_of_int selling) (word_of_int buying)
           False)"
    using exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, where rounding = Exchange_Normal]
      amounts stays_false
    by simp
  have normalized:
      "manage_buy_normalized_amount price_n price_d buy_amount =
       word_of_int selling"
    by (simp add: manage_buy_normalized_amount_def wheat_value_def
        selling_def Let_def)
  show
    "manage_buy_selling_liabilities price_n price_d buy_amount =
       Cxx_Ok (word_of_int selling)"
    "manage_buy_buying_liabilities price_n price_d buy_amount =
       Cxx_Ok (word_of_int buying)"
    "manage_buy_normalized_amount price_n price_d buy_amount =
       word_of_int selling"
    "sint (word_of_int selling :: int64) = selling"
    "sint (word_of_int buying :: int64) = buying"
    "0 \<le> selling"
    "0 \<le> buying"
    "buying \<le> sint buy_amount"
    using exchange normalized
      exchange_v10_amounts_integer_characterization(2,3)
        [OF pre, where rounding = Exchange_Normal] amounts
      exchange_v10_without_price_error_thresholds_result_contract
        [OF pre exchange]
    by (simp_all add: manage_buy_selling_liabilities_def
        manage_buy_buying_liabilities_def make_exchange_result_def)
qed

lemma adjustment_at_exact_receive_value_replays_unlimited:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_nonnegative: "0 \<le> sint amount"
    and cap_nonnegative: "0 \<le> sint max_sheep_receive"
    and unsaturated:
      "sint amount * sint price_n \<le>
        int64_max_int * sint price_d"
    and exact_value:
      "sint amount * sint price_n =
        sint max_sheep_receive * sint price_d"
  shows "adjust_offer_with_options price_n price_d amount max_sheep_receive
      \<lparr>exact_receive_cap = False,
        symmetric_exact_receive_cap = False\<rparr> =
    adjust_offer_with_options price_n price_d amount int64_max
      \<lparr>exact_receive_cap = False,
        symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: at the finite cap, both arguments of the wheat-value minimum
  are the same exact product.  Unsaturation makes the unlimited cap select
  that product as well.  The normal exchange consequently has identical
  integer amounts and stay flag at the two receive caps.
\<close>
proof -
  have finite_wheat:
      "exchange_wheat_value_int price_n price_d amount max_sheep_receive =
       sint amount * sint price_n"
    using exact_value
    by (simp add: exchange_wheat_value_int_def)
  have unlimited_wheat:
      "exchange_wheat_value_int price_n price_d amount int64_max =
       sint amount * sint price_n"
    using unsaturated
    by (simp add: exchange_wheat_value_int_def int64_max_def min_def)
  have finite_pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max
         max_sheep_receive"
    using pn pd amount_nonnegative cap_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  have unlimited_pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  note finite_characterization =
    exchange_v10_normal_characterization [OF finite_pre]
  note unlimited_characterization =
    exchange_v10_normal_characterization [OF unlimited_pre]
  have amounts_equal:
      "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         max_sheep_receive Exchange_Normal =
       exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         int64_max Exchange_Normal"
    using finite_wheat unlimited_wheat
    by (simp add: exchange_v10_amounts_int_def Let_def)
  have stays_equal:
      "(exchange_wheat_value_int price_n price_d amount max_sheep_receive >
         exchange_sheep_value_int price_n price_d int64_max int64_max) =
       (exchange_wheat_value_int price_n price_d amount int64_max >
         exchange_sheep_value_int price_n price_d int64_max int64_max)"
    using finite_wheat unlimited_wheat by simp
  show ?thesis
    unfolding adjust_offer_with_options_def
    using finite_characterization unlimited_characterization amounts_equal
      stays_equal
    by simp
qed


lemma adjustment_int_le_div_from_product:
  fixes lower numerator divisor :: int
  assumes divisor_positive: "0 < divisor"
    and product_bound: "lower * divisor \<le> numerator"
  shows "lower \<le> numerator div divisor"
text \<open>
  Proof sketch: the lower value is its own product's quotient, and integer
  division by a positive divisor is monotone in the numerator.
\<close>
proof -
  have "lower = lower * divisor div divisor"
    using divisor_positive by simp
  also have "... \<le> numerator div divisor"
    using zdiv_mono1 [OF product_bound divisor_positive] .
  finally show ?thesis .
qed

lemma capped_normal_result_candidates:
  fixes wheat_value selling buying :: int
    and price_n price_d :: int32
    and request_send request_receive max_send max_receive posted :: int64
  defines "wheat_value \<equiv>
    min (sint request_send * sint price_n)
      (sint request_receive * sint price_d)"
    and "selling \<equiv> wheat_value div sint price_n"
    and "buying \<equiv>
      (selling * sint price_n) div sint price_d"
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and request_send_nonnegative: "0 \<le> sint request_send"
    and request_receive_nonnegative: "0 \<le> sint request_receive"
    and wheat_more: "sint price_n > sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
    and send_le_request: "sint max_send \<le> sint request_send"
    and receive_le_request: "sint max_receive \<le> sint request_receive"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_send max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_positive: "0 < sint posted"
  shows
    "sint posted = selling \<or>
     (sint posted = selling - 1 \<and>
      (selling * sint price_n) mod sint price_d \<noteq> 0)"
text \<open>
  Proof sketch: capacities covering the normalized selling and buying amounts
  sandwich the capped wheat value between the buying multiple and the raw
  request caps.  Dividing by the more valuable wheat price confines a
  positive successful NORMAL result to the normalized selling amount or its
  immediate predecessor.  Exact divisibility rules out the predecessor.
\<close>
proof -
  have selling_product_le_wheat:
      "selling * sint price_n \<le> wheat_value"
    unfolding selling_def
    using int_div_mult_le [OF pn, of wheat_value] .
  have buying_product_le_selling:
      "buying * sint price_d \<le> selling * sint price_n"
    unfolding buying_def
    using int_div_mult_le [OF pd, of "selling * sint price_n"] .
  have send_product_lower:
      "selling * sint price_n \<le> sint max_send * sint price_n"
    using selling_fits less_imp_le [OF pn]
    by (simp add: mult_right_mono)
  have receive_product_lower:
      "buying * sint price_d \<le> sint max_receive * sint price_d"
    using buying_fits less_imp_le [OF pd]
    by (simp add: mult_right_mono)
  have wheat_lower:
      "buying * sint price_d \<le>
       exchange_wheat_value_int price_n price_d max_send max_receive"
    using buying_product_le_selling send_product_lower receive_product_lower
    unfolding exchange_wheat_value_int_def by simp
  have send_product_upper:
      "sint max_send * sint price_n \<le>
       sint request_send * sint price_n"
    using send_le_request less_imp_le [OF pn]
    by (simp add: mult_right_mono)
  have receive_product_upper:
      "sint max_receive * sint price_d \<le>
       sint request_receive * sint price_d"
    using receive_le_request less_imp_le [OF pd]
    by (simp add: mult_right_mono)
  have wheat_upper:
      "exchange_wheat_value_int price_n price_d max_send max_receive
       \<le> wheat_value"
    using send_product_upper receive_product_upper
    unfolding exchange_wheat_value_int_def wheat_value_def
    by (rule min.mono; assumption)
  have posting_pre:
      "exchange_v10_pre price_n price_d max_send int64_max int64_max
         max_receive"
    using pn pd send_nonnegative receive_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  let ?amounts =
    "exchange_v10_amounts_int price_n price_d max_send int64_max
       int64_max max_receive Exchange_Normal"
  note characterization =
    exchange_v10_normal_characterization [OF posting_pre]
  have posted_word:
      "posted = (word_of_int (fst ?amounts) :: int64)"
    using adjustment characterization posted_positive
    by (auto simp add: adjust_offer_with_options_def make_exchange_result_def Let_def
        split: if_splits)
  have posted_sint: "sint posted = fst ?amounts"
    using posted_word
      exchange_v10_amounts_integer_characterization(2)
        [OF posting_pre, where rounding = Exchange_Normal]
    by simp
  have caps_bounded:
      "sint max_send * sint price_n \<le>
         sint int64_max * sint price_n"
      "sint max_receive * sint price_d \<le>
         sint int64_max * sint price_d"
    using sint64_upper_bound [of max_send]
      sint64_upper_bound [of max_receive]
      less_imp_le [OF pn] less_imp_le [OF pd]
    by (simp_all add: int64_max_def mult_right_mono)
  have stays_false:
      "\<not> exchange_wheat_value_int price_n price_d max_send max_receive >
        exchange_sheep_value_int price_n price_d int64_max int64_max"
    using caps_bounded
    by (simp add: exchange_wheat_value_int_def
        exchange_sheep_value_int_def min_def split: if_splits)
  have posted_formula:
      "sint posted =
       exchange_wheat_value_int price_n price_d max_send max_receive
         div sint price_n"
    using posted_sint stays_false wheat_more
    by (simp add: exchange_v10_amounts_int_def Let_def)
  have posted_upper: "sint posted \<le> selling"
    unfolding posted_formula selling_def
    using zdiv_mono1 [OF wheat_upper pn] .
  have predecessor_product_below_buying:
      "(selling - 1) * sint price_n < buying * sint price_d"
  proof -
    let ?r = "(selling * sint price_n) mod sint price_d"
    have remainder_less: "?r < sint price_d"
      using pos_mod_bound [OF pd] .
    have division:
        "selling * sint price_n = buying * sint price_d + ?r"
      unfolding buying_def
      using div_mod_decomp_int
        [of "selling * sint price_n" "sint price_d"]
      by simp
    have "selling * sint price_n - sint price_n <
        selling * sint price_n - ?r"
      using remainder_less wheat_more by linarith
    moreover have
        "(selling - 1) * sint price_n =
         selling * sint price_n - sint price_n"
      by (simp add: algebra_simps)
    moreover have
        "buying * sint price_d = selling * sint price_n - ?r"
      using division by linarith
    ultimately show ?thesis by simp
  qed
  have posted_lower: "selling - 1 \<le> sint posted"
  proof -
    have predecessor_below_wheat:
        "(selling - 1) * sint price_n <
         exchange_wheat_value_int price_n price_d max_send max_receive"
      using predecessor_product_below_buying wheat_lower by linarith
    show ?thesis
      unfolding posted_formula
      using adjustment_int_le_div_from_product
        [OF pn less_imp_le [OF predecessor_below_wheat]] .
  qed
  show ?thesis
  proof (cases "sint posted = selling")
    case True
    then show ?thesis by simp
  next
    case False
    have posted_predecessor: "sint posted = selling - 1"
      using posted_lower posted_upper False by linarith
    have remainder_nonzero:
        "(selling * sint price_n) mod sint price_d \<noteq> 0"
    proof
      assume zero:
        "(selling * sint price_n) mod sint price_d = 0"
      have exact_buying:
          "selling * sint price_n = buying * sint price_d"
        unfolding buying_def
        using div_mod_decomp_int
          [of "selling * sint price_n" "sint price_d"] zero
        by simp
      have selling_product_le_actual:
          "selling * sint price_n \<le>
           exchange_wheat_value_int price_n price_d max_send max_receive"
        using wheat_lower exact_buying by simp
      have "selling \<le> sint posted"
        unfolding posted_formula
        using adjustment_int_le_div_from_product
          [OF pn selling_product_le_actual] .
      then show False using posted_predecessor by simp
    qed
    show ?thesis using posted_predecessor remainder_nonzero by simp
  qed
qed

lemma capped_normal_manage_sell_result_candidates:
  fixes wheat_value selling buying :: int
    and price_n price_d :: int32
    and amount max_send max_receive posted :: int64
  defines "wheat_value \<equiv>
    min (sint amount * sint price_n)
      (int64_max_int * sint price_d)"
    and "selling \<equiv> wheat_value div sint price_n"
    and "buying \<equiv>
      (selling * sint price_n) div sint price_d"
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and wheat_more: "sint price_n > sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
    and send_le_amount: "sint max_send \<le> sint amount"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_send max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_positive: "0 < sint posted"
  shows
    "sint posted = selling \<or>
     (sint posted = selling - 1 \<and>
      (selling * sint price_n) mod sint price_d \<noteq> 0)"
text \<open>
  Proof sketch: specialize the general two-request-cap confinement theorem to
  a ManageSell request, whose receive cap is @{const int64_max}.
\<close>
proof -
  have amount_nonnegative: "0 \<le> sint amount"
    using amount_positive by simp
  have maximum_nonnegative: "0 \<le> sint int64_max"
    by (simp add: int64_max_def)
  have receive_le_maximum: "sint max_receive \<le> sint int64_max"
    using sint64_upper_bound [of max_receive]
    by (simp add: int64_max_def)
  have selling_fits_explicit:
      "min (sint amount * sint price_n)
          (sint int64_max * sint price_d) div sint price_n
       \<le> sint max_send"
    using selling_fits
    by (simp add: wheat_value_def selling_def int64_max_def)
  have buying_fits_explicit:
      "(min (sint amount * sint price_n)
          (sint int64_max * sint price_d) div sint price_n) *
          sint price_n div sint price_d
       \<le> sint max_receive"
    using buying_fits
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
  note candidates =
    capped_normal_result_candidates
      [OF pn pd amount_nonnegative maximum_nonnegative wheat_more
        send_nonnegative receive_nonnegative send_le_amount
        receive_le_maximum selling_fits_explicit buying_fits_explicit
        adjustment posted_positive]
  show ?thesis
    using candidates
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
qed

lemma capped_normal_manage_buy_result_candidates:
  fixes wheat_value selling buying :: int
    and price_n price_d :: int32
    and buy_amount max_send max_receive posted :: int64
  defines "wheat_value \<equiv>
    min (int64_max_int * sint price_d)
      (sint buy_amount * sint price_n)"
    and "selling \<equiv> wheat_value div sint price_d"
    and "buying \<equiv>
      (selling * sint price_d) div sint price_n"
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint buy_amount"
    and wheat_more: "sint price_d > sint price_n"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
    and receive_le_amount: "sint max_receive \<le> sint buy_amount"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
    and adjustment:
      "adjust_offer_with_options price_d price_n max_send max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_positive: "0 < sint posted"
  shows
    "sint posted = selling \<or>
     (sint posted = selling - 1 \<and>
      (selling * sint price_d) mod sint price_n \<noteq> 0)"
text \<open>
  Proof sketch: specialize the general confinement theorem to ManageBuy's
  unlimited send cap and submitted receive cap, after swapping the raw price
  components into canonical resting orientation.
\<close>
proof -
  have amount_nonnegative: "0 \<le> sint buy_amount"
    using amount_positive by simp
  have maximum_nonnegative: "0 \<le> sint int64_max"
    by (simp add: int64_max_def)
  have send_le_maximum: "sint max_send \<le> sint int64_max"
    using sint64_upper_bound [of max_send]
    by (simp add: int64_max_def)
  have selling_fits_explicit:
      "min (sint int64_max * sint price_d)
          (sint buy_amount * sint price_n) div sint price_d
       \<le> sint max_send"
    using selling_fits
    by (simp add: wheat_value_def selling_def int64_max_def)
  have buying_fits_explicit:
      "(min (sint int64_max * sint price_d)
          (sint buy_amount * sint price_n) div sint price_d) *
          sint price_d div sint price_n
       \<le> sint max_receive"
    using buying_fits
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
  note candidates =
    capped_normal_result_candidates
      [OF pd pn maximum_nonnegative amount_nonnegative wheat_more
        send_nonnegative receive_nonnegative send_le_maximum
        receive_le_amount selling_fits_explicit buying_fits_explicit
        adjustment posted_positive]
  show ?thesis
    using candidates
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
qed

lemma capped_normal_result_replays_unlimited:
  fixes wheat_value selling buying :: int
    and price_n price_d :: int32
    and request_send request_receive max_send max_receive posted :: int64
  defines "wheat_value \<equiv>
    min (sint request_send * sint price_n)
      (sint request_receive * sint price_d)"
    and "selling \<equiv> wheat_value div sint price_n"
    and "buying \<equiv>
      (selling * sint price_n) div sint price_d"
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and request_send_nonnegative: "0 \<le> sint request_send"
    and request_receive_nonnegative: "0 \<le> sint request_receive"
    and wheat_more: "sint price_n > sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
    and send_le_request: "sint max_send \<le> sint request_send"
    and receive_le_request: "sint max_receive \<le> sint request_receive"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_send max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_positive: "0 < sint posted"
    and fixed:
      "adjust_offer_with_options price_n price_d posted max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_unsaturated:
      "sint posted * sint price_n \<le>
       int64_max_int * sint price_d"
  shows
    "adjust_offer_with_options price_n price_d posted int64_max
       \<lparr>exact_receive_cap = False,
         symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
text \<open>
  Proof sketch: use the confinement theorem to split on the normalized amount
  and its fractional predecessor.  A predecessor's buying floor lies strictly
  below the covered receive cap, so raising that cap to unlimited replays the
  result.  The full candidate either has the same strict-floor argument or the
  receive cap is exactly the normalized liability; in the latter case the
  successful capped exchange forces an exact price product and the exact-value
  replay theorem applies.
\<close>
proof -
  have selling_fits_explicit:
      "(min (sint request_send * sint price_n)
          (sint request_receive * sint price_d) div sint price_n)
       \<le> sint max_send"
    using selling_fits by (simp add: wheat_value_def selling_def)
  have buying_fits_explicit:
      "((min (sint request_send * sint price_n)
          (sint request_receive * sint price_d) div sint price_n) *
          sint price_n div sint price_d) \<le> sint max_receive"
    using buying_fits
    by (simp add: wheat_value_def selling_def buying_def)
  note candidates_explicit =
    capped_normal_result_candidates
      [OF pn pd request_send_nonnegative request_receive_nonnegative
        wheat_more send_nonnegative receive_nonnegative send_le_request
        receive_le_request selling_fits_explicit buying_fits_explicit
        adjustment posted_positive]
  have candidates:
      "sint posted = selling \<or>
       (sint posted = selling - 1 \<and>
        (selling * sint price_n) mod sint price_d \<noteq> 0)"
    using candidates_explicit
    by (simp add: wheat_value_def selling_def buying_def)
  have buying_product_le_selling:
      "buying * sint price_d \<le> selling * sint price_n"
    unfolding buying_def
    using int_div_mult_le [OF pd, of "selling * sint price_n"] .
  have send_product_lower:
      "selling * sint price_n \<le> sint max_send * sint price_n"
    using selling_fits less_imp_le [OF pn]
    by (simp add: mult_right_mono)
  have receive_product_lower:
      "buying * sint price_d \<le> sint max_receive * sint price_d"
    using buying_fits less_imp_le [OF pd]
    by (simp add: mult_right_mono)
  have wheat_lower:
      "buying * sint price_d \<le>
       exchange_wheat_value_int price_n price_d max_send max_receive"
    using buying_product_le_selling send_product_lower receive_product_lower
    unfolding exchange_wheat_value_int_def by simp
  have posting_pre:
      "exchange_v10_pre price_n price_d max_send int64_max int64_max
         max_receive"
    using pn pd send_nonnegative receive_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  let ?amounts =
    "exchange_v10_amounts_int price_n price_d max_send int64_max
       int64_max max_receive Exchange_Normal"
  note characterization =
    exchange_v10_normal_characterization [OF posting_pre]
  have posted_word:
      "posted = (word_of_int (fst ?amounts) :: int64)"
    using adjustment characterization posted_positive
    by (auto simp add: adjust_offer_with_options_def make_exchange_result_def Let_def
        split: if_splits)
  have posted_sint: "sint posted = fst ?amounts"
    using posted_word
      exchange_v10_amounts_integer_characterization(2)
        [OF posting_pre, where rounding = Exchange_Normal]
    by simp
  have caps_bounded:
      "sint max_send * sint price_n \<le>
         sint int64_max * sint price_n"
      "sint max_receive * sint price_d \<le>
         sint int64_max * sint price_d"
    using sint64_upper_bound [of max_send]
      sint64_upper_bound [of max_receive]
      less_imp_le [OF pn] less_imp_le [OF pd]
    by (simp_all add: int64_max_def mult_right_mono)
  have stays_false:
      "\<not> exchange_wheat_value_int price_n price_d max_send max_receive >
        exchange_sheep_value_int price_n price_d int64_max int64_max"
    using caps_bounded
    by (simp add: exchange_wheat_value_int_def
        exchange_sheep_value_int_def min_def split: if_splits)
  have posted_formula:
      "sint posted =
       exchange_wheat_value_int price_n price_d max_send max_receive
         div sint price_n"
    using posted_sint stays_false wheat_more
    by (simp add: exchange_v10_amounts_int_def Let_def)
  show ?thesis
  proof (rule disjE [OF candidates])
    assume posted_selling: "sint posted = selling"
    show ?thesis
    proof (cases "buying < sint max_receive")
      case True
      have posted_floor:
          "(sint posted * sint price_n) div sint price_d = buying"
        using posted_selling buying_def by simp
      have replay:
          "adjust_offer_with_options price_n price_d posted max_receive
             \<lparr>exact_receive_cap = False,
               symmetric_exact_receive_cap = False\<rparr> =
           adjust_offer_with_options price_n price_d posted int64_max
             \<lparr>exact_receive_cap = False,
               symmetric_exact_receive_cap = False\<rparr>"
        using adjustment_above_floor_cap_replays_unlimited
          [OF pn pd posted_positive posted_unsaturated receive_nonnegative]
          True posted_floor by simp
      show ?thesis using fixed replay by simp
    next
      case False
      have receive_buying: "sint max_receive = buying"
        using buying_fits False by simp
      have selling_product_le_actual:
          "selling * sint price_n \<le>
           exchange_wheat_value_int price_n price_d max_send max_receive"
        unfolding posted_selling[symmetric] posted_formula
        using int_div_mult_le [OF pn, of
          "exchange_wheat_value_int price_n price_d max_send max_receive"]
        by simp
      have actual_le_buying:
          "exchange_wheat_value_int price_n price_d max_send max_receive
           \<le> buying * sint price_d"
        using receive_buying
        by (simp add: exchange_wheat_value_int_def)
      have exact_product:
          "sint posted * sint price_n =
           sint max_receive * sint price_d"
      proof -
        have "selling * sint price_n = buying * sint price_d"
          using buying_product_le_selling selling_product_le_actual
            actual_le_buying by linarith
        then show ?thesis using posted_selling receive_buying by simp
      qed
      have replay:
          "adjust_offer_with_options price_n price_d posted max_receive
             \<lparr>exact_receive_cap = False,
               symmetric_exact_receive_cap = False\<rparr> =
           adjust_offer_with_options price_n price_d posted int64_max
             \<lparr>exact_receive_cap = False,
               symmetric_exact_receive_cap = False\<rparr>"
        using adjustment_at_exact_receive_value_replays_unlimited
          [OF pn pd less_imp_le [OF posted_positive] receive_nonnegative
            posted_unsaturated exact_product] .
      show ?thesis using fixed replay by simp
    qed
  next
    assume predecessor_case:
      "sint posted = selling - 1 \<and>
       (selling * sint price_n) mod sint price_d \<noteq> 0"
    then have posted_predecessor: "sint posted = selling - 1" by simp
    let ?q = "(sint posted * sint price_n) div sint price_d"
    have quotient_below_buying: "?q < buying"
    proof -
      have quotient_product:
          "?q * sint price_d \<le> sint posted * sint price_n"
        using int_div_mult_le [OF pd] .
      have next_product:
          "(?q + 1) * sint price_d \<le> selling * sint price_n"
      proof -
        have "?q * sint price_d + sint price_d \<le>
            sint posted * sint price_n + sint price_d"
          using quotient_product by linarith
        also have "... \<le> selling * sint price_n"
        proof -
          have "sint posted * sint price_n + sint price_d =
              (selling - 1) * sint price_n + sint price_d"
            using posted_predecessor by simp
          also have "... \<le> selling * sint price_n"
            using wheat_more by (simp add: algebra_simps)
          finally show ?thesis .
        qed
        finally show ?thesis by (simp add: algebra_simps)
      qed
      have "?q + 1 \<le>
          (selling * sint price_n) div sint price_d"
        using adjustment_int_le_div_from_product [OF pd next_product] .
      then show ?thesis using buying_def by simp
    qed
    have above_floor: "?q < sint max_receive"
      using quotient_below_buying buying_fits by linarith
    have replay:
        "adjust_offer_with_options price_n price_d posted max_receive
           \<lparr>exact_receive_cap = False,
             symmetric_exact_receive_cap = False\<rparr> =
         adjust_offer_with_options price_n price_d posted int64_max
           \<lparr>exact_receive_cap = False,
             symmetric_exact_receive_cap = False\<rparr>"
      using adjustment_above_floor_cap_replays_unlimited
        [OF pn pd posted_positive posted_unsaturated receive_nonnegative
          above_floor] .
    show ?thesis using fixed replay by simp
  qed
qed

lemma capped_normal_manage_sell_result_replays_unlimited:
  fixes wheat_value selling buying :: int
    and price_n price_d :: int32
    and amount max_send max_receive posted :: int64
  defines "wheat_value \<equiv>
    min (sint amount * sint price_n)
      (int64_max_int * sint price_d)"
    and "selling \<equiv> wheat_value div sint price_n"
    and "buying \<equiv>
      (selling * sint price_n) div sint price_d"
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and wheat_more: "sint price_n > sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
    and send_le_amount: "sint max_send \<le> sint amount"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_send max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_positive: "0 < sint posted"
    and fixed:
      "adjust_offer_with_options price_n price_d posted max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_unsaturated:
      "sint posted * sint price_n \<le>
       int64_max_int * sint price_d"
  shows
    "adjust_offer_with_options price_n price_d posted int64_max
       \<lparr>exact_receive_cap = False,
         symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
text \<open>
  Proof sketch: specialize the two-request-cap replay theorem to an unlimited
  ManageSell receive cap.
\<close>
proof -
  have amount_nonnegative: "0 \<le> sint amount"
    using amount_positive by simp
  have maximum_nonnegative: "0 \<le> sint int64_max"
    by (simp add: int64_max_def)
  have receive_le_maximum: "sint max_receive \<le> sint int64_max"
    using sint64_upper_bound [of max_receive]
    by (simp add: int64_max_def)
  have selling_fits_explicit:
      "min (sint amount * sint price_n)
          (sint int64_max * sint price_d) div sint price_n
       \<le> sint max_send"
    using selling_fits
    by (simp add: wheat_value_def selling_def int64_max_def)
  have buying_fits_explicit:
      "(min (sint amount * sint price_n)
          (sint int64_max * sint price_d) div sint price_n) *
          sint price_n div sint price_d
       \<le> sint max_receive"
    using buying_fits
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
  note replay =
    capped_normal_result_replays_unlimited
      [OF pn pd amount_nonnegative maximum_nonnegative wheat_more
        send_nonnegative receive_nonnegative send_le_amount
        receive_le_maximum selling_fits_explicit buying_fits_explicit
        adjustment posted_positive fixed posted_unsaturated]
  show ?thesis
    using replay
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
qed

lemma capped_normal_manage_buy_result_replays_unlimited:
  fixes wheat_value selling buying :: int
    and price_n price_d :: int32
    and buy_amount max_send max_receive posted :: int64
  defines "wheat_value \<equiv>
    min (int64_max_int * sint price_d)
      (sint buy_amount * sint price_n)"
    and "selling \<equiv> wheat_value div sint price_d"
    and "buying \<equiv>
      (selling * sint price_d) div sint price_n"
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint buy_amount"
    and wheat_more: "sint price_d > sint price_n"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
    and receive_le_amount: "sint max_receive \<le> sint buy_amount"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
    and adjustment:
      "adjust_offer_with_options price_d price_n max_send max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_positive: "0 < sint posted"
    and fixed:
      "adjust_offer_with_options price_d price_n posted max_receive
         \<lparr>exact_receive_cap = False,
           symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    and posted_unsaturated:
      "sint posted * sint price_d \<le>
       int64_max_int * sint price_n"
  shows
    "adjust_offer_with_options price_d price_n posted int64_max
       \<lparr>exact_receive_cap = False,
         symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
text \<open>
  Proof sketch: specialize the two-request-cap replay theorem to ManageBuy's
  unlimited send cap and submitted receive cap, in canonical price order.
\<close>
proof -
  have amount_nonnegative: "0 \<le> sint buy_amount"
    using amount_positive by simp
  have maximum_nonnegative: "0 \<le> sint int64_max"
    by (simp add: int64_max_def)
  have send_le_maximum: "sint max_send \<le> sint int64_max"
    using sint64_upper_bound [of max_send]
    by (simp add: int64_max_def)
  have selling_fits_explicit:
      "min (sint int64_max * sint price_d)
          (sint buy_amount * sint price_n) div sint price_d
       \<le> sint max_send"
    using selling_fits
    by (simp add: wheat_value_def selling_def int64_max_def)
  have buying_fits_explicit:
      "(min (sint int64_max * sint price_d)
          (sint buy_amount * sint price_n) div sint price_d) *
          sint price_d div sint price_n
       \<le> sint max_receive"
    using buying_fits
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
  note replay =
    capped_normal_result_replays_unlimited
      [OF pd pn maximum_nonnegative amount_nonnegative wheat_more
        send_nonnegative receive_nonnegative send_le_maximum
        receive_le_amount selling_fits_explicit buying_fits_explicit
        adjustment posted_positive fixed posted_unsaturated]
  show ?thesis
    using replay
    by (simp add: wheat_value_def selling_def buying_def int64_max_def)
qed

end
