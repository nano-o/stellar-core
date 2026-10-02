theory Offer_Exchange_Posting_Refinement
  imports Offer_Exchange_Specification Offer_Exchange_Adjustment "HOL.Real"
begin

hide_const (open)
  Offer_Exchange_Specification.price_n
  Offer_Exchange_Specification.price_d

section \<open>Minimal implementation posting slice\<close>

text \<open>
  This theory repeats the smallest implementation-facing slice needed to state
  and prove the posting refinement without importing the larger lifecycle
  development.  The record, invariants, capacities, liability reservation,
  pre-flight outcomes, and posting core below are copied definition-for-
  definition from \<open>Offer_Exchange_Lifecycle\<close>.  They model the corresponding
  protocol-10 path through \<open>ManageOfferOpFrameBase::doApply\<close>, the
  \<open>canSellAtMost\<close> and \<open>canBuyAtMost\<close> helpers in
  \<open>OfferExchange.cpp\<close>, and liability acquisition in
  \<open>TransactionUtils.cpp\<close>.  Keeping the definitions unchanged preserves
  their executable, bit-precise correspondence with the C++ code.
\<close>

record party_state =
  sell_balance :: int64
  sell_liabilities :: int64 \<comment> \<open>Committed to sell\<close>
  buy_limit :: int64
  buy_balance :: int64
  buy_liabilities :: int64 \<comment> \<open>Committed to buy\<close>

text \<open>
  A party is described by five quantities.  On the side of the asset it
  sells, @{const sell_balance} is the spendable balance (net of any reserve)
  and @{const sell_liabilities} the selling liabilities already reserved for
  open offers.  On the side of the asset it buys, @{const buy_limit} is the
  trustline limit, @{const buy_balance} the current balance, and
  @{const buy_liabilities} the buying liabilities already reserved.  The
  maker sells wheat and buys sheep; the taker sells sheep and buys wheat.
  The selling side carries no limit because nothing in the modeled code
  paths ever receives into it, and the buying side carries no selling
  liabilities because nothing ever spends from it.
\<close>

definition party_state_wf :: "party_state \<Rightarrow> bool"
  where
    "party_state_wf party \<longleftrightarrow>
      0 \<le> sint (sell_liabilities party) \<and>
      sint (sell_liabilities party) \<le> sint (sell_balance party) \<and>
      0 \<le> sint (buy_balance party) \<and>
      0 \<le> sint (buy_liabilities party) \<and>
      sint (buy_balance party) + sint (buy_liabilities party) \<le>
        sint (buy_limit party)"

text \<open>
  @{const party_state_wf} is the ledger invariant that operations preserve:
  liabilities are non-negative, selling liabilities fit inside the balance,
  and the balance together with the buying liabilities fits inside the
  limit.
\<close>

definition can_sell_at_most :: "party_state \<Rightarrow> int64"
  \<comment> \<open>C++: \<open>canSellAtMost\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "can_sell_at_most party =
      (let available =
          sint (sell_balance party) - sint (sell_liabilities party)
       in if available \<le> 0 then 0 else word_of_int available)"

definition can_buy_at_most :: "party_state \<Rightarrow> int64"
  \<comment> \<open>C++: \<open>canBuyAtMost\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "can_buy_at_most party =
      (let available =
          sint (buy_limit party) - sint (buy_balance party) -
            sint (buy_liabilities party)
       in if available \<le> 0 then 0 else word_of_int available)"

text \<open>
  @{const can_sell_at_most} and @{const can_buy_at_most} model the C++
  functions of the same names (\<open>OfferExchange.cpp\<close>): the
  available balance, respectively the available limit, clamped to zero from
  below.
\<close>

definition add_liability_checked ::
    "int \<Rightarrow> int64 \<Rightarrow> int \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>addBuyingLiabilities\<close> and \<open>addSellingLiabilities\<close>
    (\<open>TransactionUtils.cpp\<close>)\<close>
  where
    "add_liability_checked cap current delta =
      (let new_total = sint current + delta
       in if new_total < 0 \<or> cap < new_total
          then Cxx_Err Cxx_Runtime_Error
          else Cxx_Ok (word_of_int new_total))"

text \<open>
  @{const add_liability_checked} models the checked liability updates
  \<open>addBuyingLiabilities\<close> and \<open>addSellingLiabilities\<close>
  (\<open>TransactionUtils.cpp\<close>): adding the delta must keep the
  liability total between zero and the capacity supplied by the caller, and a
  violation is the runtime error that the C++ call sites raise.
\<close>

definition acquire_offer_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      party_state cxx_result"
  \<comment> \<open>C++: \<open>acquireLiabilities\<close> (\<open>TransactionUtils.cpp\<close>)\<close>
  where
    "acquire_offer_liabilities price_n price_d amount maker = do {
       buying \<leftarrow> offer_buying_liabilities price_n price_d amount;
       new_buying \<leftarrow> add_liability_checked
         (sint (buy_limit maker) - sint (buy_balance maker))
         (buy_liabilities maker) (sint buying);
       selling \<leftarrow> offer_selling_liabilities price_n price_d amount;
       new_selling \<leftarrow> add_liability_checked (sint (sell_balance maker))
         (sell_liabilities maker) (sint selling);
       Cxx_Ok (maker\<lparr>buy_liabilities := new_buying,
                     sell_liabilities := new_selling\<rparr>)
     }"

text \<open>
  @{const acquire_offer_liabilities} models \<open>acquireLiabilities\<close>
  (\<open>TransactionUtils.cpp\<close>), the acquiring direction of
  \<open>acquireOrReleaseLiabilities\<close>.  Following the C++, the buying side is
  updated before the selling side, each against the maker's trustline
  capacity.
\<close>

datatype offer_preflight_outcome =
    Preflight_Line_Full
  | Preflight_Underfunded
  | Preflight_Ready int64 int64

datatype post_outcome =
    Post_Malformed
  | Post_Line_Full
  | Post_Underfunded
  | Post_No_Offer
  | Post_Created int64 party_state

definition preflight_offer_core ::
    "int64 cxx_result \<Rightarrow> int64 cxx_result \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> party_state \<Rightarrow> offer_preflight_outcome cxx_result"
  \<comment> \<open>C++: \<open>ManageOfferOpFrameBase::computeOfferExchangeParameters\<close>
    (\<open>ManageOfferOpFrameBase.cpp\<close>)\<close>
  where
    "preflight_offer_core buying_liability selling_liability max_send_cap
        max_receive_cap maker = do {
       buying \<leftarrow> buying_liability;
       if sint (buy_limit maker) - sint (buy_balance maker) -
           sint (buy_liabilities maker) < sint buying
       then Cxx_Ok Preflight_Line_Full
       else do {
         selling \<leftarrow> selling_liability;
         if sint (sell_balance maker) - sint (sell_liabilities maker) <
             sint selling
         then Cxx_Ok Preflight_Underfunded
         else
           (let max_sheep_send =
                  signed_min64 max_send_cap (can_sell_at_most maker);
                max_wheat_receive =
                  (if max_receive_cap = int64_max
                   then can_buy_at_most maker
                   else signed_min64 max_receive_cap (can_buy_at_most maker))
            in if max_wheat_receive = 0
               then Cxx_Ok Preflight_Line_Full
               else Cxx_Ok
                 (Preflight_Ready max_sheep_send max_wheat_receive))
       }
     }"

text \<open>
  @{const preflight_offer_core} models the protocol-10 pre-flight tests of
  \<open>ManageOfferOpFrameBase::computeOfferExchangeParameters\<close>
  (\<open>ManageOfferOpFrameBase.cpp\<close>) together with the immediate check in
  \<open>doApply\<close> that reports \<open>LINE_FULL\<close> when \<open>maxWheatReceive\<close> is zero.  The
  request-specific liabilities and operation caps arrive as parameters; the
  cap minima model the sell and buy instantiations of
  \<open>applyOperationSpecificLimits\<close>.
\<close>

definition post_offer_core ::
    "int32 \<Rightarrow> int32 \<Rightarrow> bool \<Rightarrow> int64 cxx_result \<Rightarrow>
      int64 cxx_result \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      exchange_options \<Rightarrow> post_outcome cxx_result"
  \<comment> \<open>C++: \<open>ManageOfferOpFrameBase::doApply\<close> (\<open>ManageOfferOpFrameBase.cpp\<close>)\<close>
  where
    "post_offer_core price_n price_d request_valid buying_liability
        selling_liability max_send_cap max_receive_cap maker options =
      (if sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> \<not> request_valid
       then Cxx_Ok Post_Malformed
       else do {
         preflight \<leftarrow> preflight_offer_core buying_liability
           selling_liability max_send_cap max_receive_cap maker;
         case preflight of
           Preflight_Line_Full \<Rightarrow> Cxx_Ok Post_Line_Full
         | Preflight_Underfunded \<Rightarrow> Cxx_Ok Post_Underfunded
         | Preflight_Ready max_sheep_send max_wheat_receive \<Rightarrow> do {
             adjusted \<leftarrow> adjust_offer_with_options price_n price_d
               max_sheep_send max_wheat_receive options;
             if 0 < sint adjusted
             then do {
               maker_after \<leftarrow> acquire_offer_liabilities price_n price_d
                 adjusted maker;
               Cxx_Ok (Post_Created adjusted maker_after)
             }
             else Cxx_Ok Post_No_Offer
           }
       })"

text \<open>
  @{const post_offer_core} models the protocol-10 posting path of
  \<open>ManageOfferOpFrameBase::doApply\<close> (\<open>ManageOfferOpFrameBase.cpp\<close>) for
  an offer that crosses nothing on entry: malformed-request rejection,
  pre-flight, preventative adjustment through @{const adjust_offer_with_options}, and
  liability acquisition for the created offer.
\<close>

definition post_sell_offer ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      exchange_options \<Rightarrow> post_outcome cxx_result"
  \<comment> \<open>C++: \<open>doApply\<close> for \<open>ManageSellOfferOpFrame\<close>\<close>
  where
    "post_sell_offer price_n price_d amount maker options =
      post_offer_core price_n price_d (0 < sint amount)
        (offer_buying_liabilities price_n price_d amount)
        (offer_selling_liabilities price_n price_d amount)
        amount int64_max maker options"

text \<open>
  @{const post_sell_offer} instantiates the core for a \<open>ManageSellOffer\<close>:
  the liability arguments are
  \<open>ManageSellOfferOpFrame::getOfferBuyingLiabilities\<close> and
  \<open>getOfferSellingLiabilities\<close> (\<open>ManageSellOfferOpFrame.cpp\<close>),
  and the submitted amount caps the send side exactly as
  \<open>ManageSellOfferOpFrame::applyOperationSpecificLimits\<close> does.
\<close>

text \<open>
  The copied posting slice deliberately omits balance transfer, liability
  release, crossing, and lifecycle predicates: none is used by the refinement
  theorem.  The arithmetic lemmas below are included only where the repaired
  adjustment calculation needs them.
\<close>

subsection \<open>Posting-state invariant facts\<close>

lemma can_sell_at_most_nonnegative:
  assumes wf: "party_state_wf party"
  shows "0 \<le> sint (can_sell_at_most party)"
text \<open>
  Proof sketch: the well-formedness invariant makes the available selling
  balance non-negative and at most the signed-word maximum.  The clamping
  definition therefore returns either zero or a word with that same
  non-negative signed value.
\<close>
proof -
  have liabilities_nonnegative:
    "0 \<le> sint (sell_liabilities party)"
    using wf by (simp add: party_state_wf_def)
  have available_bounded:
    "sint (sell_balance party) - sint (sell_liabilities party) \<le>
      int64_max_int"
    using liabilities_nonnegative sint64_upper_bound[of "sell_balance party"]
    by linarith
  show ?thesis
    unfolding can_sell_at_most_def Let_def
    using sint_word_of_int_nonnegative_int64
      [of "sint (sell_balance party) - sint (sell_liabilities party)"]
      available_bounded
    by (auto split: if_splits)
qed

lemma can_buy_at_most_nonnegative:
  assumes wf: "party_state_wf party"
  shows "0 \<le> sint (can_buy_at_most party)"
text \<open>
  Proof sketch: well-formedness makes the unused buying capacity non-negative
  and bounds it by the trustline limit.  The clamping definition therefore
  preserves its non-negative signed value.
\<close>
proof -
  have balance_nonnegative: "0 \<le> sint (buy_balance party)"
    and liabilities_nonnegative: "0 \<le> sint (buy_liabilities party)"
    using wf by (simp_all add: party_state_wf_def)
  have available_bounded:
    "sint (buy_limit party) - sint (buy_balance party) -
       sint (buy_liabilities party) \<le> int64_max_int"
    using balance_nonnegative liabilities_nonnegative
      sint64_upper_bound[of "buy_limit party"]
    by linarith
  show ?thesis
    unfolding can_buy_at_most_def Let_def
    using sint_word_of_int_nonnegative_int64
      [of "sint (buy_limit party) - sint (buy_balance party) -
        sint (buy_liabilities party)"]
      available_bounded
    by (auto split: if_splits)
qed

subsection \<open>Repaired adjustment arithmetic\<close>

text \<open>
  The refinement uses the two repaired receive caps that are absent from the
  older plain-cap integer characterization.  The following word facts and
  repaired amount characterization are the exact dependency closure copied
  from \<open>Offer_Exchange_Lifecycle\<close>; later lifecycle maximality, crossing,
  and reachability results are intentionally not included.
\<close>

lemma exact_value_word_characterization:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d" and send: "0 \<le> sint max_send" and receive: "0 \<le> sint max_receive"
  shows "calculate_offer_value_with_exact_receive_cap price_n price_d       max_send max_receive =     Cxx_Ok       (min         (word_of_int (sint max_send * sint price_n) :: uint128)         (min           ((word_of_int (sint max_receive * sint price_d) ::               uint128) +             ucast (scast (price_d - 1) :: int64))           (word_of_int (sint int64_max * sint price_d) ::             uint128)))"
text \<open>
  Proof sketch: all operands are non-negative signed words, so the
  multiplications succeed with their integer products.  Unfolding the exact
  cap leaves the nested minimum displayed in the conclusion.
\<close>
    using assms
    by (simp add: calculate_offer_value_with_exact_receive_cap_def
        big_multiply_def int64_max_def)
lemma positive_price_denominator_minus_one_cast:
  fixes price_d :: int32
  assumes "0 < sint price_d"
  shows "sint (scast (price_d - 1) :: int64) = sint price_d - 1"
text \<open>
  Proof sketch: subtracting one from a positive signed 32-bit denominator does
  not wrap; widening that non-negative result to 64 bits preserves its signed
  integer value.
\<close>
proof -
  have lower: "- (2 ^ 31) \<le> sint price_d - 1"
    using assms by simp
  have upper: "sint price_d - 1 < 2 ^ 31"
    using sint_lt[of price_d] by simp
  have unwrapped:
      "signed_take_bit 31 (sint price_d - 1) = sint price_d - 1"
    using signed_take_bit_int_eq_self [OF lower upper] .
  have difference: "sint (price_d - 1) = sint price_d - 1"
    using unwrapped by (simp add: sint_word_ariths)
  show ?thesis
    using difference by simp
qed

lemma uint_eq_sint_nonnegative_int64:
  fixes word :: int64
  assumes "0 \<le> sint word"
  shows "uint word = sint word"
text \<open>
  Proof sketch: a non-negative signed 64-bit value lies in the unsigned
  64-bit range, so the unsigned truncation in @{thm Word.uint_sint} is the
  identity.
\<close>
proof -
  have upper: "sint word < (2 :: int) ^ 64"
    using sint_lt[of word] by simp
  have untruncated: "take_bit 64 (sint word) = sint word"
    using take_bit_int_eq_self [OF assms upper] .
  show ?thesis
    using untruncated by (simp add: Word.uint_sint)
qed
lemma int_le_div_from_product:
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

lemma int_div_below_next_multiple:
  fixes numerator divisor bound :: int
  assumes divisor_positive: "0 < divisor"
      and numerator_bound: "numerator \<le> bound * divisor + divisor - 1"
  shows "numerator div divisor \<le> bound"
  text \<open>
    Proof sketch: division monotonicity compares the numerator against the
    largest value below the next multiple of the divisor, whose quotient is
    exactly the bound.
  \<close>
proof -
  have expanded: "numerator \<le> bound * divisor + (divisor - 1)"
    using numerator_bound by simp
  have "numerator div divisor \<le>
      (bound * divisor + (divisor - 1)) div divisor"
    using zdiv_mono1 [OF expanded divisor_positive] .
  also have "... = bound + (divisor - 1) div divisor"
    using divisor_positive by (simp only: div_mult_self3)
  also have "... = bound"
    using divisor_positive by simp
  finally show ?thesis .
qed

lemma int_div_le_imp_below_next_multiple:
  fixes numerator divisor bound :: int
  assumes divisor_positive: "0 < divisor"
      and quotient_bound: "numerator div divisor \<le> bound"
  shows "numerator \<le> bound * divisor + divisor - 1"
  text \<open>
    Proof sketch: decompose the numerator into quotient multiple and
    remainder; the remainder is below the divisor and the quotient multiple
    is below the bound multiple.
  \<close>
proof -
  have remainder_less: "numerator mod divisor < divisor"
    using divisor_positive by simp
  have decomposition:
      "numerator mod divisor + numerator div divisor * divisor = numerator"
    by (rule mod_div_mult_eq)
  have quotient_multiple:
      "numerator div divisor * divisor \<le> bound * divisor"
    using mult_right_mono
      [OF quotient_bound less_imp_le [OF divisor_positive]] .
  show ?thesis
    using remainder_less decomposition quotient_multiple by linarith
qed

lemma exact_receive_cap_value_int:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
  obtains trade_word :: uint128 where
    "calculate_offer_value_with_exact_receive_cap price_n price_d max_send
       max_receive = Cxx_Ok trade_word"
    "uint trade_word =
       min (sint max_send * sint price_n)
         (min (sint max_receive * sint price_d + sint price_d - 1)
              (sint int64_max * sint price_d))"
  text \<open>
    Proof sketch: the word-level characterization gives a nested minimum of
    three 128-bit values.  The two products are exact by the multiplication
    range theorem, the relaxation addend is the denominator minus one, and
    the receive product is far below the 128-bit modulus, so the relaxed
    receive value is an exact sum and the unsigned minimum commutes with
    @{const uint}.
  \<close>
proof -
  let ?send_word =
    "word_of_int (sint max_send * sint price_n) :: uint128"
  let ?receive_word =
    "word_of_int (sint max_receive * sint price_d) :: uint128"
  let ?slack = "ucast (scast (price_d - 1) :: int64) :: uint128"
  let ?cap_word =
    "word_of_int (sint int64_max * sint price_d) :: uint128"
  have characterized:
      "calculate_offer_value_with_exact_receive_cap price_n price_d max_send
         max_receive =
       Cxx_Ok (min ?send_word (min (?receive_word + ?slack) ?cap_word))"
    using exact_value_word_characterization
      [OF pn pd send_nonnegative receive_nonnegative] .
  have send_uint: "uint ?send_word = sint max_send * sint price_n"
    using big_multiply_uint_value [of max_send "scast price_n :: int64"]
      send_nonnegative less_imp_le [OF pn]
    by simp
  have receive_uint: "uint ?receive_word = sint max_receive * sint price_d"
    using big_multiply_uint_value
      [of max_receive "scast price_d :: int64"]
      receive_nonnegative less_imp_le [OF pd]
    by simp
  have cap_uint: "uint ?cap_word = sint int64_max * sint price_d"
    using big_multiply_uint_value [of int64_max "scast price_d :: int64"]
      less_imp_le [OF pd]
    by (simp add: int64_max_def)
  have slack_sint: "sint (scast (price_d - 1) :: int64) =
      sint price_d - 1"
    using positive_price_denominator_minus_one_cast [OF pd] .
  have slack_nonnegative: "0 \<le> sint (scast (price_d - 1) :: int64)"
    using slack_sint pd by simp
  have slack_uint64: "uint (scast (price_d - 1) :: int64) =
      sint price_d - 1"
    using uint_eq_sint_nonnegative_int64 [OF slack_nonnegative] slack_sint
    by simp
  have slack_uint: "uint ?slack = sint price_d - 1"
    using slack_uint64 by (simp add: uint_up_ucast is_up)
  have receive_product_bound:
      "sint max_receive * sint price_d < (2 :: int) ^ 126"
  proof -
    have receive_lt: "sint max_receive < (2 :: int) ^ 63"
      using sint_lt [of max_receive] by simp
    have denominator_lt:
        "sint (scast price_d :: int64) < (2 :: int) ^ 63"
      using sint_lt [of "scast price_d :: int64"] by simp
    have "sint max_receive * sint price_d < (2 :: int) ^ 63 * 2 ^ 63"
      using receive_lt denominator_lt receive_nonnegative
        less_imp_le [OF pd]
      by (intro mult_strict_mono) simp_all
    then show ?thesis by simp
  qed
  have slack_bound: "uint ?slack < (2 :: int) ^ 64"
    using uint_lt2p [of "scast (price_d - 1) :: int64"]
    by (simp add: uint_up_ucast is_up)
  have no_wrap: "uint ?receive_word + uint ?slack < (2 :: int) ^ 128"
    using receive_uint receive_product_bound slack_bound by simp
  have relaxed_uint:
      "uint (?receive_word + ?slack) =
        sint max_receive * sint price_d + sint price_d - 1"
  proof -
    have sum_nonnegative: "0 \<le> uint ?receive_word + uint ?slack"
      by simp
    have "uint (?receive_word + ?slack) =
        (uint ?receive_word + uint ?slack) mod 2 ^ 128"
      by (simp add: uint_word_ariths)
    also have "... = uint ?receive_word + uint ?slack"
      using mod_pos_pos_trivial [OF sum_nonnegative no_wrap] .
    finally show ?thesis
      using receive_uint slack_uint by simp
  qed
  have trade_uint:
      "uint (min ?send_word (min (?receive_word + ?slack) ?cap_word)) =
       min (sint max_send * sint price_n)
         (min (sint max_receive * sint price_d + sint price_d - 1)
              (sint int64_max * sint price_d))"
    by (simp only: uint_min_word send_uint relaxed_uint cap_uint)
  show ?thesis
    using that characterized trade_uint by blast
qed

lemma exchange_v10_amounts_wheat_stays_down_repaired:
  fixes wheat_word sheep_word :: uint128
    and trade sheep_send wheat_receive :: int
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and sheep_more: "\<not> sint price_n > sint price_d"
    and receive_nonnegative: "0 \<le> sint max_wheat_receive"
    and send_nonnegative: "0 \<le> sint max_sheep_send"
    and symmetric: "symmetric_exact_receive_cap options"
  defines "trade \<equiv>
      min (sint max_sheep_send * sint price_d)
        (min (sint max_wheat_receive * sint price_n + sint price_n - 1)
             (sint int64_max * sint price_n))"
    and "sheep_send \<equiv> trade div sint price_d"
    and "wheat_receive \<equiv> sheep_send * sint price_d div sint price_n"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive True
      Exchange_Normal options =
    Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send)"
    and "sint (word_of_int wheat_receive :: int64) = wheat_receive"
    and "sint (word_of_int sheep_send :: int64) = sheep_send"
  text \<open>
    Proof sketch: the symmetric exact cap values the trade by the reversed
    exact receive-cap calculation.  Its value is at most the sheep-send
    product, so the first round-down division fits signed 64 bits; the
    resulting sheep multiple is at most the relaxed wheat-receive component,
    so the second round-down division is bounded by the wheat-receive cap.
  \<close>
proof -
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by simp
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by simp
  obtain trade_word :: uint128 where trade_result:
      "calculate_offer_value_with_exact_receive_cap price_d price_n
         max_sheep_send max_wheat_receive = Cxx_Ok trade_word"
    and trade_uint_raw:
      "uint trade_word =
        min (sint max_sheep_send * sint price_d)
          (min (sint max_wheat_receive * sint price_n + sint price_n - 1)
               (sint int64_max * sint price_n))"
    using exact_receive_cap_value_int
      [OF pd pn send_nonnegative receive_nonnegative] .
  have trade_uint: "uint trade_word = trade"
    using trade_uint_raw by (simp add: trade_def)
  have trade_le_send: "trade \<le> sint max_sheep_send * sint price_d"
    by (simp add: trade_def)
  have trade_le_receive:
      "trade \<le> sint max_wheat_receive * sint price_n + sint price_n - 1"
    by (simp add: trade_def)
  have word_pd_bound:
      "uint trade_word \<le>
        sint max_sheep_send * sint (scast price_d :: int64)"
    using trade_uint trade_le_send by simp
  note first = big_divide_or_throw128_down_bounded
    [OF pd_wide word_pd_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 trade_word (scast price_d) Cxx_Round_Down =
        Cxx_Ok (word_of_int sheep_send)"
    using first(1) trade_uint
    by (simp add: sheep_send_def)
  have first_sint: "sint (word_of_int sheep_send :: int64) = sheep_send"
    using first(2) trade_uint
    by (simp add: sheep_send_def)
  have trade_nonnegative: "0 \<le> trade"
  proof -
    have "0 \<le> sint max_sheep_send * sint price_d"
      using send_nonnegative less_imp_le [OF pd] by simp
    moreover have "0 \<le> sint max_wheat_receive * sint price_n"
      using receive_nonnegative less_imp_le [OF pn] by simp
    moreover have "0 \<le> sint int64_max * sint price_n"
      using less_imp_le [OF pn] by (simp add: int64_max_def)
    ultimately show ?thesis
      using pn by (auto simp add: trade_def)
  qed
  have SS0: "0 \<le> sheep_send"
    using trade_nonnegative pd
    by (simp add: sheep_send_def pos_imp_zdiv_nonneg_iff)
  have first_word_nonnegative:
      "0 \<le> sint (word_of_int sheep_send :: int64)"
    using first_sint SS0 by simp
  have product_le_trade: "sheep_send * sint price_d \<le> trade"
    unfolding sheep_send_def using int_div_mult_le [OF pd] .
  have product_le_receive:
      "sheep_send * sint price_d \<le>
        sint max_wheat_receive * sint price_n + sint price_n - 1"
    using product_le_trade trade_le_receive by linarith
  have WR_to_max: "wheat_receive \<le> sint max_wheat_receive"
    unfolding wheat_receive_def
    using int_div_below_next_multiple [OF pn product_le_receive] .
  have WR_max: "wheat_receive \<le> int64_max_int"
    using WR_to_max sint64_upper_bound [of max_wheat_receive] by linarith
  have rounded_bound:
      "rounded_quotient
        (sint (word_of_int sheep_send :: int64) *
          sint (scast price_d :: int64))
        (sint (scast price_n :: int64)) Cxx_Round_Down
       \<le> int64_max_int"
    using first_sint WR_max
    by (simp add: wheat_receive_def)
  have second_result:
      "big_divide_or_throw (word_of_int sheep_send) (scast price_d)
        (scast price_n) Cxx_Round_Down = Cxx_Ok (word_of_int wheat_receive)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pd_wide] pn_wide
          rounded_bound]
      first_sint
    by (simp add: wheat_receive_def)
  show "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive True
      Exchange_Normal options =
    Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send)"
    unfolding exchange_v10_amounts_def
    using sheep_more symmetric trade_result first_result second_result
    by (simp add: Let_def)
  show "sint (word_of_int wheat_receive :: int64) = wheat_receive"
    using big_divide_or_throw_success(2)
      [OF first_word_nonnegative less_imp_le [OF pd_wide] pn_wide
          rounded_bound]
      first_sint
    by (simp add: wheat_receive_def)
  show "sint (word_of_int sheep_send :: int64) = sheep_send"
    using first_sint .
qed

lemma exchange_v10_amounts_sheep_stays_wheat_more_repaired:
  fixes wheat_word sheep_word :: uint128
    and trade wheat_receive sheep_send :: int
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and wheat_more: "sint price_n > sint price_d"
    and send_nonnegative: "0 \<le> sint max_wheat_send"
    and receive_nonnegative: "0 \<le> sint max_sheep_receive"
    and exact: "exact_receive_cap options"
  defines "trade \<equiv>
      min (sint max_wheat_send * sint price_n)
        (min (sint max_sheep_receive * sint price_d + sint price_d - 1)
             (sint int64_max * sint price_d))"
    and "wheat_receive \<equiv> trade div sint price_n"
    and "sheep_send \<equiv> wheat_receive * sint price_n div sint price_d"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding options =
    Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send)"
    and "sint (word_of_int wheat_receive :: int64) = wheat_receive"
    and "sint (word_of_int sheep_send :: int64) = sheep_send"
  text \<open>
    Proof sketch: the exact receive cap values the trade by the exact
    calculation on the wheat offer's caps.  Its value is at most the
    wheat-send product, so the first round-down division fits signed 64
    bits; the resulting wheat multiple is at most the relaxed sheep-receive
    component, so the second round-down division is bounded by the
    sheep-receive cap.
  \<close>
proof -
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by simp
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by simp
  obtain trade_word :: uint128 where trade_result:
      "calculate_offer_value_with_exact_receive_cap price_n price_d
         max_wheat_send max_sheep_receive = Cxx_Ok trade_word"
    and trade_uint_raw:
      "uint trade_word =
        min (sint max_wheat_send * sint price_n)
          (min (sint max_sheep_receive * sint price_d + sint price_d - 1)
               (sint int64_max * sint price_d))"
    using exact_receive_cap_value_int
      [OF pn pd send_nonnegative receive_nonnegative] .
  have trade_uint: "uint trade_word = trade"
    using trade_uint_raw by (simp add: trade_def)
  have trade_le_send: "trade \<le> sint max_wheat_send * sint price_n"
    by (simp add: trade_def)
  have trade_le_receive:
      "trade \<le> sint max_sheep_receive * sint price_d + sint price_d - 1"
    by (simp add: trade_def)
  have word_pn_bound:
      "uint trade_word \<le>
        sint max_wheat_send * sint (scast price_n :: int64)"
    using trade_uint trade_le_send by simp
  note first = big_divide_or_throw128_down_bounded
    [OF pn_wide word_pn_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 trade_word (scast price_n) Cxx_Round_Down =
        Cxx_Ok (word_of_int wheat_receive)"
    using first(1) trade_uint
    by (simp add: wheat_receive_def)
  have first_sint:
      "sint (word_of_int wheat_receive :: int64) = wheat_receive"
    using first(2) trade_uint
    by (simp add: wheat_receive_def)
  have trade_nonnegative: "0 \<le> trade"
  proof -
    have "0 \<le> sint max_wheat_send * sint price_n"
      using send_nonnegative less_imp_le [OF pn] by simp
    moreover have "0 \<le> sint max_sheep_receive * sint price_d"
      using receive_nonnegative less_imp_le [OF pd] by simp
    moreover have "0 \<le> sint int64_max * sint price_d"
      using less_imp_le [OF pd] by (simp add: int64_max_def)
    ultimately show ?thesis
      using pd by (auto simp add: trade_def)
  qed
  have WR0: "0 \<le> wheat_receive"
    using trade_nonnegative pn
    by (simp add: wheat_receive_def pos_imp_zdiv_nonneg_iff)
  have first_word_nonnegative:
      "0 \<le> sint (word_of_int wheat_receive :: int64)"
    using first_sint WR0 by simp
  have product_le_trade: "wheat_receive * sint price_n \<le> trade"
    unfolding wheat_receive_def using int_div_mult_le [OF pn] .
  have product_le_receive:
      "wheat_receive * sint price_n \<le>
        sint max_sheep_receive * sint price_d + sint price_d - 1"
    using product_le_trade trade_le_receive by linarith
  have SS_to_max: "sheep_send \<le> sint max_sheep_receive"
    unfolding sheep_send_def
    using int_div_below_next_multiple [OF pd product_le_receive] .
  have SS_max: "sheep_send \<le> int64_max_int"
    using SS_to_max sint64_upper_bound [of max_sheep_receive] by linarith
  have rounded_bound:
      "rounded_quotient
        (sint (word_of_int wheat_receive :: int64) *
          sint (scast price_n :: int64))
        (sint (scast price_d :: int64)) Cxx_Round_Down
       \<le> int64_max_int"
    using first_sint SS_max
    by (simp add: sheep_send_def)
  have second_result:
      "big_divide_or_throw (word_of_int wheat_receive) (scast price_n)
        (scast price_d) Cxx_Round_Down = Cxx_Ok (word_of_int sheep_send)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pn_wide] pd_wide
          rounded_bound]
      first_sint
    by (simp add: sheep_send_def)
  show "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding options =
    Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send)"
    unfolding exchange_v10_amounts_def
    using wheat_more exact trade_result first_result second_result
    by (simp add: Let_def)
  show "sint (word_of_int wheat_receive :: int64) = wheat_receive"
    using first_sint .
  show "sint (word_of_int sheep_send :: int64) = sheep_send"
    using big_divide_or_throw_success(2)
      [OF first_word_nonnegative less_imp_le [OF pn_wide] pd_wide
          rounded_bound]
      first_sint
    by (simp add: sheep_send_def)
qed

definition exchange_v10_amounts_int_repaired ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> int \<times> int"
  where
    "exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive =
      (let wheat_value =
          exchange_wheat_value_int price_n price_d max_wheat_send
            max_sheep_receive;
         sheep_value =
          exchange_sheep_value_int price_n price_d max_sheep_send
            max_wheat_receive;
         wheat_stays = wheat_value > sheep_value
       in if wheat_stays then
            if sint price_n > sint price_d then
              let wheat_receive = sheep_value div sint price_n
              in (wheat_receive,
                  (wheat_receive * sint price_n + sint price_d - 1)
                    div sint price_d)
            else
              let trade =
                min (sint max_sheep_send * sint price_d)
                  (min (sint max_wheat_receive * sint price_n +
                      sint price_n - 1)
                    (sint int64_max * sint price_n));
                sheep_send = trade div sint price_d
              in (sheep_send * sint price_d div sint price_n, sheep_send)
          else if sint price_n > sint price_d then
            let trade =
              min (sint max_wheat_send * sint price_n)
                (min (sint max_sheep_receive * sint price_d +
                    sint price_d - 1)
                  (sint int64_max * sint price_d));
              wheat_receive = trade div sint price_n
            in (wheat_receive,
                wheat_receive * sint price_n div sint price_d)
          else
            let sheep_send = wheat_value div sint price_d
            in ((sheep_send * sint price_d + sint price_n - 1)
                  div sint price_n,
                sheep_send))"

text \<open>
  @{const exchange_v10_amounts_int_repaired} is the normal-mode amount pair
  computed with both receive-cap repairs enabled, phrased in unbounded
  integers.  The two branches selected when the staying offer is the more
  valuable side coincide with @{const exchange_v10_amounts_int}; the two
  corrected branches replace the plain offer value by the exact receive-cap
  minimum of the send-side product, the receive cap relaxed by one divisor
  unit, and the @{const int64_max} saturation ceiling.
\<close>

lemma repaired_wheat_stays_down_bounds:
  fixes price_n price_d imax max_wheat_send max_wheat_receive max_sheep_send
    max_sheep_receive trade sheep_send wheat_receive :: int
  assumes pn: "0 < price_n" and pd: "0 < price_d"
    and sheep_more: "price_n \<le> price_d"
    and imax_nonnegative: "0 \<le> imax"
    and receive_nonnegative: "0 \<le> max_wheat_receive"
    and send_nonnegative: "0 \<le> max_sheep_send"
    and wheat_stays:
      "min (max_sheep_send * price_d) (max_wheat_receive * price_n) <
       min (max_wheat_send * price_n) (max_sheep_receive * price_d)"
  defines "trade \<equiv>
      min (max_sheep_send * price_d)
        (min (max_wheat_receive * price_n + price_n - 1) (imax * price_n))"
    and "sheep_send \<equiv> trade div price_d"
    and "wheat_receive \<equiv> sheep_send * price_d div price_n"
  shows "0 \<le> wheat_receive"
    and "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    and "0 \<le> sheep_send"
    and "sheep_send \<le> min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: the exact trade value exceeds the plain sheep value by at
    most @{term "price_n - 1"}, and the plain sheep value is strictly below
    the wheat value, which both opposite-side caps bound.  Since the price
    numerator is at most the denominator, each floor quotient stays within
    the two caps of its output asset.
  \<close>
proof -
  have trade_le_send: "trade \<le> max_sheep_send * price_d"
    by (simp add: trade_def)
  have trade_le_receive:
      "trade \<le> max_wheat_receive * price_n + price_n - 1"
    by (simp add: trade_def)
  have trade_le_plain_slack:
      "trade \<le>
        min (max_sheep_send * price_d) (max_wheat_receive * price_n) +
        price_n - 1"
  proof (cases "max_sheep_send * price_d \<le> max_wheat_receive * price_n")
    case True
    then have "min (max_sheep_send * price_d)
        (max_wheat_receive * price_n) = max_sheep_send * price_d"
      by (simp add: min_def)
    then show ?thesis using trade_le_send pn by linarith
  next
    case False
    then have "min (max_sheep_send * price_d)
        (max_wheat_receive * price_n) = max_wheat_receive * price_n"
      by (simp add: min_def)
    then show ?thesis using trade_le_receive by linarith
  qed
  have stays_lt_send_cap:
      "min (max_sheep_send * price_d) (max_wheat_receive * price_n) <
        max_wheat_send * price_n"
    using wheat_stays min.cobounded1 less_le_trans by blast
  have stays_lt_receive_cap:
      "min (max_sheep_send * price_d) (max_wheat_receive * price_n) <
        max_sheep_receive * price_d"
    using wheat_stays min.cobounded2 less_le_trans by blast
  have trade_nonnegative: "0 \<le> trade"
  proof -
    have "0 \<le> max_sheep_send * price_d"
      using send_nonnegative less_imp_le [OF pd] by simp
    moreover have "0 \<le> max_wheat_receive * price_n"
      using receive_nonnegative less_imp_le [OF pn] by simp
    moreover have "0 \<le> imax * price_n"
      using imax_nonnegative less_imp_le [OF pn] by simp
    ultimately show ?thesis
      using pn by (auto simp add: trade_def)
  qed
  have SS0: "0 \<le> sheep_send"
    using trade_nonnegative pd
    by (simp add: sheep_send_def pos_imp_zdiv_nonneg_iff)
  show "0 \<le> sheep_send"
    using SS0 .
  have SS_send: "sheep_send \<le> max_sheep_send"
    unfolding sheep_send_def
    using int_div_upper_bound [OF pd trade_le_send] .
  have trade_le_msr: "trade \<le> max_sheep_receive * price_d + price_d - 1"
    using trade_le_plain_slack stays_lt_receive_cap sheep_more by linarith
  have SS_receive: "sheep_send \<le> max_sheep_receive"
    unfolding sheep_send_def
    using int_div_below_next_multiple [OF pd trade_le_msr] .
  show "sheep_send \<le> min max_sheep_receive max_sheep_send"
    using SS_send SS_receive by simp
  have product_nonnegative: "0 \<le> sheep_send * price_d"
    using SS0 less_imp_le [OF pd] by simp
  show "0 \<le> wheat_receive"
    unfolding wheat_receive_def
    using product_nonnegative pn by (simp add: pos_imp_zdiv_nonneg_iff)
  have product_le_trade: "sheep_send * price_d \<le> trade"
    unfolding sheep_send_def using int_div_mult_le [OF pd] .
  have product_le_receive:
      "sheep_send * price_d \<le> max_wheat_receive * price_n + price_n - 1"
    using product_le_trade trade_le_receive by linarith
  have WR_receive: "wheat_receive \<le> max_wheat_receive"
    unfolding wheat_receive_def
    using int_div_below_next_multiple [OF pn product_le_receive] .
  have product_le_send:
      "sheep_send * price_d \<le> max_wheat_send * price_n + price_n - 1"
    using product_le_trade trade_le_plain_slack stays_lt_send_cap
    by linarith
  have WR_send: "wheat_receive \<le> max_wheat_send"
    unfolding wheat_receive_def
    using int_div_below_next_multiple [OF pn product_le_send] .
  show "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    using WR_receive WR_send by simp
qed

lemma repaired_sheep_stays_wheat_more_bounds:
  fixes price_n price_d imax max_wheat_send max_wheat_receive max_sheep_send
    max_sheep_receive trade wheat_receive sheep_send :: int
  assumes pn: "0 < price_n" and pd: "0 < price_d"
    and wheat_more: "price_d < price_n"
    and imax_nonnegative: "0 \<le> imax"
    and send_nonnegative: "0 \<le> max_wheat_send"
    and receive_nonnegative: "0 \<le> max_sheep_receive"
    and sheep_stays:
      "min (max_wheat_send * price_n) (max_sheep_receive * price_d) \<le>
       min (max_sheep_send * price_d) (max_wheat_receive * price_n)"
  defines "trade \<equiv>
      min (max_wheat_send * price_n)
        (min (max_sheep_receive * price_d + price_d - 1) (imax * price_d))"
    and "wheat_receive \<equiv> trade div price_n"
    and "sheep_send \<equiv> wheat_receive * price_n div price_d"
  shows "0 \<le> wheat_receive"
    and "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    and "0 \<le> sheep_send"
    and "sheep_send \<le> min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: this is the mirror of the wheat-stays argument.  The exact
    trade value exceeds the plain wheat value by at most
    @{term "price_d - 1"}, the plain wheat value is at most the sheep value,
    and the price denominator is strictly below the numerator, so each floor
    quotient stays within the two caps of its output asset.
  \<close>
proof -
  have trade_le_send: "trade \<le> max_wheat_send * price_n"
    by (simp add: trade_def)
  have trade_le_receive:
      "trade \<le> max_sheep_receive * price_d + price_d - 1"
    by (simp add: trade_def)
  have trade_le_plain_slack:
      "trade \<le>
        min (max_wheat_send * price_n) (max_sheep_receive * price_d) +
        price_d - 1"
  proof (cases "max_wheat_send * price_n \<le> max_sheep_receive * price_d")
    case True
    then have "min (max_wheat_send * price_n)
        (max_sheep_receive * price_d) = max_wheat_send * price_n"
      by (simp add: min_def)
    then show ?thesis using trade_le_send pd by linarith
  next
    case False
    then have "min (max_wheat_send * price_n)
        (max_sheep_receive * price_d) = max_sheep_receive * price_d"
      by (simp add: min_def)
    then show ?thesis using trade_le_receive by linarith
  qed
  have stays_le_send_cap:
      "min (max_wheat_send * price_n) (max_sheep_receive * price_d) \<le>
        max_sheep_send * price_d"
    using sheep_stays min.cobounded1 order_trans by blast
  have stays_le_receive_cap:
      "min (max_wheat_send * price_n) (max_sheep_receive * price_d) \<le>
        max_wheat_receive * price_n"
    using sheep_stays min.cobounded2 order_trans by blast
  have trade_nonnegative: "0 \<le> trade"
  proof -
    have "0 \<le> max_wheat_send * price_n"
      using send_nonnegative less_imp_le [OF pn] by simp
    moreover have "0 \<le> max_sheep_receive * price_d"
      using receive_nonnegative less_imp_le [OF pd] by simp
    moreover have "0 \<le> imax * price_d"
      using imax_nonnegative less_imp_le [OF pd] by simp
    ultimately show ?thesis
      using pd by (auto simp add: trade_def)
  qed
  have WR0: "0 \<le> wheat_receive"
    using trade_nonnegative pn
    by (simp add: wheat_receive_def pos_imp_zdiv_nonneg_iff)
  show "0 \<le> wheat_receive"
    using WR0 .
  have WR_send: "wheat_receive \<le> max_wheat_send"
    unfolding wheat_receive_def
    using int_div_upper_bound [OF pn trade_le_send] .
  have trade_le_mwr: "trade \<le> max_wheat_receive * price_n + price_n - 1"
    using trade_le_plain_slack stays_le_receive_cap wheat_more by linarith
  have WR_receive: "wheat_receive \<le> max_wheat_receive"
    unfolding wheat_receive_def
    using int_div_below_next_multiple [OF pn trade_le_mwr] .
  show "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    using WR_receive WR_send by simp
  have product_nonnegative: "0 \<le> wheat_receive * price_n"
    using WR0 less_imp_le [OF pn] by simp
  show "0 \<le> sheep_send"
    unfolding sheep_send_def
    using product_nonnegative pd by (simp add: pos_imp_zdiv_nonneg_iff)
  have product_le_trade: "wheat_receive * price_n \<le> trade"
    unfolding wheat_receive_def using int_div_mult_le [OF pn] .
  have product_le_receive:
      "wheat_receive * price_n \<le> max_sheep_receive * price_d + price_d - 1"
    using product_le_trade trade_le_receive by linarith
  have SS_receive: "sheep_send \<le> max_sheep_receive"
    unfolding sheep_send_def
    using int_div_below_next_multiple [OF pd product_le_receive] .
  have product_le_send:
      "wheat_receive * price_n \<le> max_sheep_send * price_d + price_d - 1"
    using product_le_trade trade_le_plain_slack stays_le_send_cap
    by linarith
  have SS_send: "sheep_send \<le> max_sheep_send"
    unfolding sheep_send_def
    using int_div_below_next_multiple [OF pd product_le_send] .
  show "sheep_send \<le> min max_sheep_receive max_sheep_send"
    using SS_receive SS_send by simp
qed

lemma exchange_v10_amounts_int_repaired_bounds:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "0 \<le> fst (exchange_v10_amounts_int_repaired price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive)"
    and "fst (exchange_v10_amounts_int_repaired price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> snd (exchange_v10_amounts_int_repaired price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive)"
    and "snd (exchange_v10_amounts_int_repaired price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
  text \<open>
    Proof sketch: split on the offer-value comparison and the price order.
    The two branches whose staying offer is the more valuable side reuse the
    plain-cap branch bound lemmas; the two corrected branches are discharged
    by the repaired bound lemmas above.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d
    max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive"
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and ws: "0 \<le> sint max_wheat_send"
    and wr: "0 \<le> sint max_wheat_receive"
    and ss: "0 \<le> sint max_sheep_send"
    and sr: "0 \<le> sint max_sheep_receive"
    by (simp_all add: exchange_v10_pre_def)
  have imax_nonnegative: "0 \<le> sint int64_max"
    by (simp add: int64_max_def)
  have W0: "0 \<le> ?W"
    and Wws: "?W \<le> sint max_wheat_send * sint price_n"
    and Wsr: "?W \<le> sint max_sheep_receive * sint price_d"
    using exchange_wheat_value_int_bounds [OF pre] by auto
  have S0: "0 \<le> ?S"
    and Sss: "?S \<le> sint max_sheep_send * sint price_d"
    and Swr: "?S \<le> sint max_wheat_receive * sint price_n"
    using exchange_sheep_value_int_bounds [OF pre] by auto
  have result:
      "0 \<le> fst ?A \<and>
       fst ?A \<le> min (sint max_wheat_receive) (sint max_wheat_send) \<and>
       0 \<le> snd ?A \<and>
       snd ?A \<le> min (sint max_sheep_receive) (sint max_sheep_send)"
  proof (cases "?W > ?S")
    case wheat_stays: True
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      note bounds = exchange_amounts_wheat_stays_up_bounds
        [OF pn pd S0 Swr Sss wheat_stays Wws Wsr]
      from bounds wheat_stays True show ?thesis
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
    next
      case False
      then have price_order: "sint price_n \<le> sint price_d" by simp
      have stays_raw:
          "min (sint max_sheep_send * sint price_d)
             (sint max_wheat_receive * sint price_n) <
           min (sint max_wheat_send * sint price_n)
             (sint max_sheep_receive * sint price_d)"
        using wheat_stays
        by (simp add: exchange_wheat_value_int_def
            exchange_sheep_value_int_def)
      note bounds = repaired_wheat_stays_down_bounds
        [OF pn pd price_order imax_nonnegative wr ss stays_raw]
      show ?thesis
        unfolding exchange_v10_amounts_int_repaired_def
        apply (simp only: Let_def wheat_stays if_True False if_False
            prod.sel)
        using bounds
        by blast
    qed
  next
    case sheep_stays: False
    then have WS: "?W \<le> ?S" by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      have stays_raw:
          "min (sint max_wheat_send * sint price_n)
             (sint max_sheep_receive * sint price_d) \<le>
           min (sint max_sheep_send * sint price_d)
             (sint max_wheat_receive * sint price_n)"
        using WS
        by (simp add: exchange_wheat_value_int_def
            exchange_sheep_value_int_def)
      note bounds = repaired_sheep_stays_wheat_more_bounds
        [OF pn pd True imax_nonnegative ws sr stays_raw]
      show ?thesis
        unfolding exchange_v10_amounts_int_repaired_def
        apply (simp only: Let_def sheep_stays if_False True if_True
            prod.sel)
        using bounds
        by blast
    next
      case False
      note bounds = exchange_amounts_sheep_stays_sheep_more_bounds
        [OF pn pd W0 Wws Wsr WS Swr Sss]
      from bounds sheep_stays False show ?thesis
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
    qed
  qed
  from result show "0 \<le> fst ?A" by simp
  from result show
      "fst ?A \<le> min (sint max_wheat_receive) (sint max_wheat_send)" by simp
  from result show "0 \<le> snd ?A" by simp
  from result show
      "snd ?A \<le> min (sint max_sheep_receive) (sint max_sheep_send)" by simp
qed



theorem exchange_v10_amounts_repaired_integer_characterization:
  fixes wheat_word sheep_word :: uint128 and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "wheat_word \<equiv>
    min
      (word_of_int (sint max_wheat_send * sint price_n) :: uint128)
      (word_of_int (sint max_sheep_receive * sint price_d))"
    and "sheep_word \<equiv>
    min
      (word_of_int (sint max_sheep_send * sint price_d) :: uint128)
      (word_of_int (sint max_wheat_receive * sint price_n))"
    and "amounts \<equiv>
      exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      (wheat_word > sheep_word) Exchange_Normal
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
    Cxx_Ok
      (word_of_int (fst amounts), word_of_int (snd amounts))"
    and "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    and "sint (word_of_int (snd amounts) :: int64) = snd amounts"
  text \<open>
    Proof sketch: identify both 128-bit values with their exact integers,
    then split on the value comparison and the price ordering.  The
    unaffected branches use the existing plain-cap branch equations; the two
    corrected branches use the repaired branch equations.  The repaired
    bounds theorem makes both re-encoded result words faithful signed-64
    values.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and wr: "0 \<le> sint max_wheat_receive"
    and ws: "0 \<le> sint max_wheat_send"
    and ss: "0 \<le> sint max_sheep_send"
    and sr: "0 \<le> sint max_sheep_receive"
    by (simp_all add: exchange_v10_pre_def)
  have W_value: "uint wheat_word = ?W"
    using exchange_wheat_value_word [OF pre]
    unfolding wheat_word_def .
  have S_value: "uint sheep_word = ?S"
    using exchange_sheep_value_word [OF pre]
    unfolding sheep_word_def .
  have stays: "(wheat_word > sheep_word) = (?W > ?S)"
    by (simp only: word_less_def W_value S_value)
  have exact_field:
      "exact_receive_cap
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"
    by simp
  have symmetric_field:
      "symmetric_exact_receive_cap
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"
    by simp
  show amount_result:
      "exchange_v10_amounts price_n price_d wheat_word sheep_word
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        (wheat_word > sheep_word) Exchange_Normal
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
  proof (cases "?W > ?S")
    case wheat_stays: True
    have word_stays: "wheat_word > sheep_word"
      using stays wheat_stays by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      note branch = exchange_v10_amounts_wheat_stays_up
        [OF pre S_value, of Exchange_Normal wheat_word]
      from branch word_stays wheat_stays True show ?thesis
        by (simp add: amounts_def exchange_v10_amounts_int_repaired_def
            Let_def)
    next
      case False
      note branch = exchange_v10_amounts_wheat_stays_down_repaired
        [OF pn pd False wr ss symmetric_field]
      show ?thesis
        unfolding amounts_def exchange_v10_amounts_int_repaired_def
        apply (simp only: Let_def word_stays wheat_stays if_True False
            if_False prod.sel)
        using branch(1)
        by blast
    qed
  next
    case sheep_stays: False
    have word_stays: "\<not> wheat_word > sheep_word"
      using stays sheep_stays by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      note branch = exchange_v10_amounts_sheep_stays_wheat_more_repaired
        [OF pn pd True ws sr exact_field]
      show ?thesis
        unfolding amounts_def exchange_v10_amounts_int_repaired_def
        apply (simp only: Let_def word_stays sheep_stays if_False True
            if_True prod.sel)
        using branch(1)
        by blast
    next
      case False
      note branch = exchange_v10_amounts_sheep_stays_sheep_more
        [OF pre W_value False, of sheep_word Exchange_Normal]
      from branch word_stays sheep_stays False show ?thesis
        by (simp add: amounts_def exchange_v10_amounts_int_repaired_def
            Let_def)
    qed
  qed
  note bounds = exchange_v10_amounts_int_repaired_bounds [OF pre]
  have A0: "0 \<le> fst amounts"
    and A_bound:
      "fst amounts \<le> min (sint max_wheat_receive) (sint max_wheat_send)"
    and B0: "0 \<le> snd amounts"
    and B_bound:
      "snd amounts \<le> min (sint max_sheep_receive) (sint max_sheep_send)"
    using bounds by (simp_all add: amounts_def)
  have Amax: "fst amounts \<le> int64_max_int"
    using A_bound sint64_upper_bound [of max_wheat_receive] by linarith
  have Bmax: "snd amounts \<le> int64_max_int"
    using B_bound sint64_upper_bound [of max_sheep_receive] by linarith
  show "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    using sint_word_of_int_nonnegative_int64 [OF A0 Amax] .
  show "sint (word_of_int (snd amounts) :: int64) = snd amounts"
    using sint_word_of_int_nonnegative_int64 [OF B0 Bmax] .
qed

theorem exchange_v10_without_repaired_integer_characterization:
  fixes amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "exchange_v10_without_price_error_thresholds_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Normal
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
    Cxx_Ok
      (make_exchange_result
        (word_of_int (fst amounts)) (word_of_int (snd amounts))
        (exchange_wheat_value_int price_n price_d max_wheat_send
           max_sheep_receive >
         exchange_sheep_value_int price_n price_d max_sheep_send
           max_wheat_receive))"
  text \<open>
    Proof sketch: both offer-value calls succeed with their exact 128-bit
    minima under @{const exchange_v10_pre}.  Substitute the repaired amount
    characterization, then use its signed interpretations and the repaired
    bounds to prove that neither final runtime check is reachable.
  \<close>
proof -
  let ?WW =
    "min
      (word_of_int (sint max_wheat_send * sint price_n) :: uint128)
      (word_of_int (sint max_sheep_receive * sint price_d))"
  let ?SW =
    "min
      (word_of_int (sint max_sheep_send * sint price_d) :: uint128)
      (word_of_int (sint max_wheat_receive * sint price_n))"
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  have first_pre:
      "calculate_offer_value_pre price_n price_d max_wheat_send
        max_sheep_receive"
    using pre by (simp add: exchange_v10_pre_def
        calculate_offer_value_pre_def)
  have second_pre:
      "calculate_offer_value_pre price_d price_n max_sheep_send
        max_wheat_receive"
    using pre by (simp add: exchange_v10_pre_def
        calculate_offer_value_pre_def)
  have first:
      "calculate_offer_value price_n price_d max_wheat_send
        max_sheep_receive = Cxx_Ok ?WW"
    using calculate_offer_value_success [OF first_pre] .
  have second:
      "calculate_offer_value price_d price_n max_sheep_send
        max_wheat_receive = Cxx_Ok ?SW"
    using calculate_offer_value_success [OF second_pre] .
  have W_value: "uint ?WW = ?W"
    using exchange_wheat_value_word [OF pre] .
  have S_value: "uint ?SW = ?S"
    using exchange_sheep_value_word [OF pre] .
  have stays: "(?WW > ?SW) = (?W > ?S)"
    by (simp only: word_less_def W_value S_value)
  note amount_result =
    exchange_v10_amounts_repaired_integer_characterization [OF pre]
  have amount_call:
      "exchange_v10_amounts price_n price_d ?WW ?SW max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive (?WW > ?SW)
        Exchange_Normal
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
    using amount_result(1)
    unfolding amounts_def by simp
  have amount_call_integer:
      "exchange_v10_amounts price_n price_d ?WW ?SW max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive (?W > ?S)
        Exchange_Normal
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
    using amount_call stays by simp
  have A_sint:
      "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    using amount_result(2)
    unfolding amounts_def by simp
  have B_sint:
      "sint (word_of_int (snd amounts) :: int64) = snd amounts"
    using amount_result(3)
    unfolding amounts_def by simp
  note bounds = exchange_v10_amounts_int_repaired_bounds [OF pre]
  have A0: "0 \<le> fst amounts"
    and A_bound:
      "fst amounts \<le> min (sint max_wheat_receive) (sint max_wheat_send)"
    and B0: "0 \<le> snd amounts"
    and B_bound:
      "snd amounts \<le> min (sint max_sheep_receive) (sint max_sheep_send)"
    using bounds by (simp_all add: amounts_def)
  show ?thesis
    unfolding exchange_v10_without_as_checked_amounts
    apply (simp only: first second cxx_bind.simps)
    apply (simp only: stays)
    apply (simp only: Let_def amount_call_integer cxx_bind.simps)
    unfolding check_exchange_v10_result_def
    using A_sint B_sint A0 A_bound B0 B_bound
    by (auto simp add: Let_def)
qed

theorem exchange_v10_repaired_integer_characterization:
  fixes amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive Exchange_Normal
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
    apply_price_error_thresholds price_n price_d
      (word_of_int (fst amounts)) (word_of_int (snd amounts))
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      Exchange_Normal"
  text \<open>
    Proof sketch: the repaired pre-threshold characterization replaces the
    first call by its exact amount record; simplifying the record selectors
    leaves the threshold call shown here.
  \<close>
  using exchange_v10_without_repaired_integer_characterization [OF pre]
  unfolding exchange_v10_with_options_def amounts_def make_exchange_result_def
  by simp


subsection \<open>Posting refinement against the specification\<close>

text \<open>
  For a positive integer denominator, rational floor and ceiling agree with
  the integer division formulas used by the executable exchange model.
  Proof sketch: multiply the defining floor or ceiling interval by the
  positive denominator.  Euclidean division supplies the lower and upper
  endpoint inequalities.
\<close>

lemma floor_of_int_ratio:
  fixes numerator denominator :: int
  assumes denominator_positive: "0 < denominator"
  shows
    "\<lfloor>(of_int numerator :: rat) / of_int denominator\<rfloor> =
      numerator div denominator"
proof -
  have lower_int:
    "numerator div denominator * denominator \<le> numerator"
    using int_div_mult_le [OF denominator_positive, of numerator] .
  have lower_rat:
    "(of_int (numerator div denominator * denominator) :: rat) \<le>
      of_int numerator"
    using lower_int by (simp only: of_int_le_iff)
  have lower_product:
    "of_int (numerator div denominator) * of_int denominator \<le>
      (of_int numerator :: rat)"
    using lower_rat by (simp only: of_int_mult)
  have lower:
    "of_int (numerator div denominator) \<le>
      (of_int numerator :: rat) / of_int denominator"
    using lower_product
    by (simp add: le_divide_eq denominator_positive)
  have remainder_less: "numerator mod denominator < denominator"
    using denominator_positive by simp
  have decomposition:
    "numerator mod denominator +
       numerator div denominator * denominator = numerator"
    by (rule mod_div_mult_eq)
  have numerator_decomposition:
    "numerator = numerator div denominator * denominator +
      numerator mod denominator"
    using decomposition by (simp add: ac_simps)
  have upper_int:
    "numerator < (numerator div denominator + 1) * denominator"
  proof -
    have sum_less:
      "numerator div denominator * denominator +
         numerator mod denominator <
       numerator div denominator * denominator + denominator"
      using add_strict_left_mono [OF remainder_less,
          of "numerator div denominator * denominator"] .
    show ?thesis
    proof (subst numerator_decomposition)
      show
        "numerator div denominator * denominator +
           numerator mod denominator <
         (numerator div denominator + 1) * denominator"
        using sum_less by (simp add: algebra_simps)
    qed
  qed
  have upper_rat:
    "(of_int numerator :: rat) <
      of_int ((numerator div denominator + 1) * denominator)"
    using upper_int by (simp only: of_int_less_iff)
  have upper_product:
    "(of_int numerator :: rat) <
      (of_int (numerator div denominator) + 1) * of_int denominator"
    using upper_rat
    by (simp only: of_int_mult of_int_add of_int_1)
  have upper:
    "(of_int numerator :: rat) / of_int denominator <
      of_int (numerator div denominator) + 1"
    using upper_product
    by (simp add: divide_less_eq denominator_positive algebra_simps)
  show ?thesis
    by (rule floor_unique [OF lower upper])
qed

lemma ceiling_of_nonnegative_int_ratio:
  fixes numerator denominator :: int
  assumes numerator_nonnegative: "0 \<le> numerator"
    and denominator_positive: "0 < denominator"
  shows
    "\<lceil>(of_int numerator :: rat) / of_int denominator\<rceil> =
      (numerator + denominator - 1) div denominator"
proof -
  have product_below:
    "((numerator + denominator - 1) div denominator - 1) *
       denominator < numerator"
  proof -
    have product_bound:
      "(numerator + denominator - 1) div denominator * denominator \<le>
        numerator + denominator - 1"
      using int_div_mult_le [OF denominator_positive,
          of "numerator + denominator - 1"] .
    have
      "(numerator + denominator - 1) div denominator * denominator -
         denominator \<le> numerator - 1"
      using product_bound by linarith
    then show ?thesis
      by (simp add: algebra_simps)
  qed
  have product_below_rat:
    "of_int
       (((numerator + denominator - 1) div denominator - 1) *
          denominator) < (of_int numerator :: rat)"
    using product_below by (simp only: of_int_less_iff)
  have product_below_lifted:
    "(of_int ((numerator + denominator - 1) div denominator) - 1) *
       of_int denominator < (of_int numerator :: rat)"
    using product_below_rat
    by (simp only: of_int_mult of_int_diff of_int_1)
  have lower:
    "of_int ((numerator + denominator - 1) div denominator) - 1 <
      (of_int numerator :: rat) / of_int denominator"
    using product_below_lifted
    by (simp add: less_divide_eq denominator_positive algebra_simps)
  have upper_int:
    "numerator \<le>
      ((numerator + denominator - 1) div denominator) * denominator"
    using int_le_ceiling_div_mult [OF denominator_positive,
        of numerator] .
  have upper_rat:
    "(of_int numerator :: rat) \<le>
      of_int (((numerator + denominator - 1) div denominator) *
        denominator)"
    using upper_int by (simp only: of_int_le_iff)
  have upper_product:
    "(of_int numerator :: rat) \<le>
      of_int ((numerator + denominator - 1) div denominator) *
        of_int denominator"
    using upper_rat by (simp only: of_int_mult)
  have upper:
    "(of_int numerator :: rat) / of_int denominator \<le>
      of_int ((numerator + denominator - 1) div denominator)"
    using upper_product
    by (simp add: divide_le_eq denominator_positive)
  show ?thesis
    by (rule ceiling_unique [OF lower upper])
qed

text \<open>
  Specializing the preceding identities to a positive ledger price rewrites
  the specification's two rational round-trip equations into the canonical
  integer rounding equations of the implementation.  Proof sketch: unfold
  the ledger-price coercion, cancel the nonzero price component, and invoke
  the corresponding ratio identity.
\<close>

lemma floor_times_ledger_price:
  fixes numerator price_n price_d :: int
  assumes price_d_positive: "0 < price_d"
  shows
    "\<lfloor>(of_int numerator :: rat) *
       Offer_Exchange_Specification.Ledger_Price price_n price_d\<rfloor> =
      numerator * price_n div price_d"
proof -
  have ratio:
    "(of_int numerator :: rat) * (of_int price_n / of_int price_d) =
      of_int (numerator * price_n) / of_int price_d"
    by simp
  show ?thesis
    unfolding Offer_Exchange_Specification.rat_price_def
    using ratio floor_of_int_ratio [OF price_d_positive,
        of "numerator * price_n"]
    by simp
qed

lemma ceiling_div_ledger_price:
  fixes numerator price_n price_d :: int
  assumes numerator_nonnegative: "0 \<le> numerator"
    and price_n_positive: "0 < price_n"
    and price_d_positive: "0 < price_d"
  shows
    "\<lceil>(of_int numerator :: rat) /
       Offer_Exchange_Specification.Ledger_Price price_n price_d\<rceil> =
      (numerator * price_d + price_n - 1) div price_n"
proof -
  have ratio:
    "(of_int numerator :: rat) / (of_int price_n / of_int price_d) =
      of_int (numerator * price_d) / of_int price_n"
    by simp
  have product_nonnegative: "0 \<le> numerator * price_d"
    using numerator_nonnegative less_imp_le [OF price_d_positive] by simp
  show ?thesis
    unfolding Offer_Exchange_Specification.rat_price_def
    using ratio ceiling_of_nonnegative_int_ratio
      [OF product_nonnegative price_n_positive]
    by simp
qed

text \<open>
  The specification's declarative maximum unrestricted exchange is the same normalized
  pair computed by an unlimited implementation exchange.  Proof sketch:
  make the feasible wheat set explicit and split on the price ordering.  If
  wheat is more valuable, the implementation takes the largest wheat amount
  permitted by the request and the signed saturation bound; its rounded
  sheep amount round-trips and every feasible wheat amount is no larger.  If
  sheep is at least as valuable, first take the largest sheep amount below
  the requested wheat value and round it back up to wheat.  A zero sheep
  amount makes the feasible set empty; otherwise this pair is feasible and
  bounds every other round-tripping pair.  Finiteness then identifies the
  specification's @{const Max} with the implementation amount.
\<close>

lemma specification_max_unrestricted_exchange_explicit:
  fixes offer :: Offer_Exchange_Specification.sell_wheat_offer
    and price_n price_d amount wheat_value selling buying :: int
  assumes pn: "0 < price_n"
    and pd: "0 < price_d"
    and amount_positive: "0 < amount"
    and price_n_bound: "price_n \<le> int64_max_int"
    and price_d_bound: "price_d \<le> int64_max_int"
    and amount_bound: "amount \<le> int64_max_int"
    and offer_amount: "wheat_amount offer = amount"
    and offer_price:
      "sheep_per_wheat offer =
        Offer_Exchange_Specification.Ledger_Price price_n price_d"
  defines "wheat_value \<equiv>
    min (amount * price_n) (int64_max_int * price_d)"
    and "selling \<equiv>
      (if price_n > price_d
       then wheat_value div price_n
       else
         (let sheep = wheat_value div price_d
          in (sheep * price_d + price_n - 1) div price_n))"
    and "buying \<equiv>
      (if price_n > price_d
       then (selling * price_n) div price_d
       else wheat_value div price_d)"
  shows
    "Offer_Exchange_Specification.max_unrestricted_exchange offer =
      \<lparr>wheat_to_taker = selling,
       sheep_to_maker = buying\<rparr>"
proof -
  let ?price =
    "Offer_Exchange_Specification.Ledger_Price price_n price_d"
  let ?M = "int64_max_int :: int"
  let ?feasible = "{wheat. \<exists>sheep.
       wheat = \<lceil>(of_int sheep :: rat) / ?price\<rceil> \<and>
       wheat \<le> amount \<and>
       sheep = \<lfloor>(of_int wheat :: rat) * ?price\<rfloor> \<and>
       0 < wheat \<and> wheat \<le> ?M \<and>
       0 < sheep \<and> sheep \<le> ?M \<and>
       (of_int wheat :: rat) * ?price \<le> ?M}"
  have finite_feasible: "finite ?feasible"
  proof (rule finite_subset[where B = "{1..amount}"])
    show "?feasible \<subseteq> {1..amount}" by auto
    show "finite {1..amount}" by simp
  qed
  have M_positive: "0 < ?M" by simp
  have price_n_nonnegative: "0 \<le> price_n" using pn by simp
  have price_d_nonnegative: "0 \<le> price_d" using pd by simp
  have amount_nonnegative: "0 \<le> amount" using amount_positive by simp
  have feasible_set:
    "{wheat. \<exists>sheep.
       wheat = \<lceil>sheep / sheep_per_wheat offer\<rceil> \<and>
       wheat \<le> wheat_amount offer \<and>
       sheep = \<lfloor>wheat * sheep_per_wheat offer\<rfloor> \<and>
       0 < wheat \<and>
       wheat \<le> Offer_Exchange_Specification.int64_max \<and>
       0 < sheep \<and>
       sheep \<le> Offer_Exchange_Specification.int64_max \<and>
       wheat * sheep_per_wheat offer \<le>
         Offer_Exchange_Specification.int64_max} = ?feasible"
    using offer_amount offer_price
    by (simp add: Offer_Exchange_Specification.int64_max_def)
  have amounts_expanded:
    "Offer_Exchange_Specification.max_unrestricted_exchange offer =
      (if ?feasible = {}
       then \<lparr>wheat_to_taker = 0,
              sheep_to_maker = 0\<rparr>
       else \<lparr>wheat_to_taker = Max ?feasible,
              sheep_to_maker =
                \<lfloor>(of_int (Max ?feasible) :: rat) * ?price\<rfloor>\<rparr>)"
    unfolding Offer_Exchange_Specification.max_unrestricted_exchange_def
    apply (simp only: Let_def)
    apply (simp only: feasible_set)
    by (simp only: offer_price)
  show ?thesis
  proof (cases "price_n > price_d")
    case wheat_more: True
    let ?w = "wheat_value div price_n"
    let ?s = "?w * price_n div price_d"
    have amount_ge_one: "1 \<le> amount" using amount_positive by simp
    have price_d_ge_one: "1 \<le> price_d" using pd by simp
    have n_le_amount_product: "price_n \<le> amount * price_n"
      using mult_right_mono [OF amount_ge_one price_n_nonnegative] by simp
    have M_le_Md: "?M \<le> ?M * price_d"
      using mult_left_mono [OF price_d_ge_one less_imp_le [OF M_positive]]
      by simp
    have n_le_Md: "price_n \<le> ?M * price_d"
      using price_n_bound M_le_Md by linarith
    have n_le_value: "price_n \<le> wheat_value"
      using n_le_amount_product n_le_Md
      by (simp add: wheat_value_def)
    have w_positive: "0 < ?w"
      using pos_imp_zdiv_pos_iff [OF pn, of wheat_value] n_le_value by simp
    have w_nonnegative: "0 \<le> ?w" using w_positive by simp
    have wn_le_value: "?w * price_n \<le> wheat_value"
      using int_div_mult_le [OF pn, of wheat_value]
      unfolding wheat_value_def .
    have value_le_amount: "wheat_value \<le> amount * price_n"
      by (simp add: wheat_value_def)
    have value_le_saturation: "wheat_value \<le> ?M * price_d"
      by (simp add: wheat_value_def)
    have w_le_amount: "?w \<le> amount"
      using zdiv_mono1 [OF value_le_amount pn] pn
      by simp
    have w_le_M: "?w \<le> ?M"
      using w_le_amount amount_bound by linarith
    have s_nonnegative: "0 \<le> ?s"
      using w_nonnegative price_n_nonnegative pd
      by (simp add: pos_imp_zdiv_nonneg_iff)
    have d_le_wn: "price_d \<le> ?w * price_n"
    proof -
      have "price_d < price_n" using wheat_more by simp
      also have "price_n \<le> ?w * price_n"
        using mult_right_mono [of 1 ?w price_n]
          w_positive price_n_nonnegative by simp
      finally show ?thesis by simp
    qed
    have s_positive: "0 < ?s"
      using pos_imp_zdiv_pos_iff [OF pd, of "?w * price_n"] d_le_wn
      by simp
    have wn_le_saturation: "?w * price_n \<le> ?M * price_d"
      using wn_le_value value_le_saturation by linarith
    have s_le_M: "?s \<le> ?M"
      using int_div_upper_bound [OF pd wn_le_saturation] .
    have sd_le_wn: "?s * price_d \<le> ?w * price_n"
      using int_div_mult_le [OF pd, of "?w * price_n"] .
    have remainder_less:
      "(?w * price_n) mod price_d < price_d"
      using pd by simp
    have decomposition:
      "(?w * price_n) mod price_d + ?s * price_d = ?w * price_n"
      by (rule mod_div_mult_eq)
    have remainder_less_n:
      "(?w * price_n) mod price_d < price_n"
      using remainder_less wheat_more by linarith
    have previous_below_difference:
      "(?w - 1) * price_n <
        ?w * price_n - (?w * price_n) mod price_d"
      using remainder_less_n by (simp add: algebra_simps)
    have difference_eq:
      "?w * price_n - (?w * price_n) mod price_d = ?s * price_d"
      using decomposition by linarith
    have previous_below: "(?w - 1) * price_n < ?s * price_d"
      using previous_below_difference difference_eq by simp
    have wn_le_rounding_numerator:
      "?w * price_n \<le> ?s * price_d + price_n - 1"
      using previous_below by (simp add: algebra_simps)
    have w_le_round_up:
      "?w \<le> (?s * price_d + price_n - 1) div price_n"
      using int_le_div_from_product [OF pn wn_le_rounding_numerator] .
    have round_up_le_w:
      "(?s * price_d + price_n - 1) div price_n \<le> ?w"
      using int_ceiling_div_upper_bound [OF pn,
          of "?s * price_d" ?w]
        s_nonnegative price_d_nonnegative sd_le_wn
      by simp
    have round_trip:
      "(?s * price_d + price_n - 1) div price_n = ?w"
      using w_le_round_up round_up_le_w by linarith
    have sd_le_Mn: "?s * price_d \<le> ?M * price_n"
      using s_le_M price_d_bound wheat_more M_positive
      by (meson less_imp_le mult_mono order_trans price_d_nonnegative)
    have sd_le_Mn_rat:
      "(of_int ?s :: rat) * of_int price_d \<le>
        of_int ?M * of_int price_n"
    proof -
      have
        "(of_int (?s * price_d) :: rat) \<le>
          of_int (?M * price_n)"
        using sd_le_Mn by (simp only: of_int_le_iff)
      then show ?thesis by (simp only: of_int_mult)
    qed
    have sheep_capacity:
      "(of_int ?s :: rat) / ?price \<le> ?M"
      using sd_le_Mn_rat
      by (simp add: Offer_Exchange_Specification.rat_price_def
          divide_le_eq pn)
    have wn_le_Md_rat:
      "(of_int ?w :: rat) * of_int price_n \<le>
        of_int ?M * of_int price_d"
    proof -
      have
        "(of_int (?w * price_n) :: rat) \<le>
          of_int (?M * price_d)"
        using wn_le_saturation by (simp only: of_int_le_iff)
      then show ?thesis by (simp only: of_int_mult)
    qed
    have wheat_capacity:
      "(of_int ?w :: rat) * ?price \<le> ?M"
      using wn_le_Md_rat
      by (simp add: Offer_Exchange_Specification.rat_price_def
          divide_le_eq pd)
    have candidate_in: "?w \<in> ?feasible"
      apply (rule CollectI)
      apply (rule exI[where x = ?s])
      using round_trip w_le_amount w_positive w_le_M s_positive s_le_M
        sheep_capacity wheat_capacity
      by (simp add: floor_times_ledger_price [OF pd]
          ceiling_div_ledger_price [OF s_nonnegative pn pd])
    have every_le: "\<And>wheat. wheat \<in> ?feasible \<Longrightarrow> wheat \<le> ?w"
    proof -
      fix wheat
      assume wheat_in: "wheat \<in> ?feasible"
      from wheat_in have
        wheat_amount_le: "wheat \<le> amount"
        and wheat_price_le:
          "(of_int wheat :: rat) * ?price \<le> ?M"
        by auto
      have wheat_product_le_amount:
        "wheat * price_n \<le> amount * price_n"
        using mult_right_mono [OF wheat_amount_le price_n_nonnegative] .
      have wheat_product_le_saturation:
        "wheat * price_n \<le> ?M * price_d"
      proof -
        have product_rat:
          "(of_int wheat :: rat) * of_int price_n \<le>
            of_int ?M * of_int price_d"
          using wheat_price_le
          by (simp add: Offer_Exchange_Specification.rat_price_def
              divide_le_eq pd)
        have whole_rat:
          "(of_int (wheat * price_n) :: rat) \<le>
            of_int (?M * price_d)"
          using product_rat by (simp only: of_int_mult)
        show ?thesis
          using whole_rat by (simp only: of_int_le_iff)
      qed
      have wheat_product_le_value:
        "wheat * price_n \<le> wheat_value"
        using wheat_product_le_amount wheat_product_le_saturation
        by (simp add: wheat_value_def)
      show "wheat \<le> ?w"
        using int_le_div_from_product [OF pn wheat_product_le_value] .
    qed
    have max_eq: "Max ?feasible = ?w"
      using finite_feasible every_le candidate_in by (rule Max_eqI)
    have feasible_nonempty: "?feasible \<noteq> {}"
      using candidate_in by auto
    have amounts_nonempty:
      "Offer_Exchange_Specification.max_unrestricted_exchange offer =
        \<lparr>wheat_to_taker = Max ?feasible,
           sheep_to_maker =
             \<lfloor>(of_int (Max ?feasible) :: rat) * ?price\<rfloor>\<rparr>"
      apply (subst amounts_expanded)
      by (subst if_not_P[OF feasible_nonempty]) (rule refl)
    show ?thesis
      using amounts_nonempty max_eq offer_price wheat_more
      by (simp add: selling_def buying_def floor_times_ledger_price [OF pd])
  next
    case sheep_more: False
    have price_order: "price_n \<le> price_d" using sheep_more by simp
    have value_eq: "wheat_value = amount * price_n"
    proof -
      have "amount * price_n \<le> ?M * price_n"
        using mult_right_mono [OF amount_bound price_n_nonnegative] .
      also have "... \<le> ?M * price_d"
        using mult_left_mono [OF price_order less_imp_le [OF M_positive]] .
      finally show ?thesis by (simp add: wheat_value_def min_def)
    qed
    let ?s = "wheat_value div price_d"
    let ?w = "(?s * price_d + price_n - 1) div price_n"
    have s_nonnegative: "0 \<le> ?s"
      using amount_nonnegative price_n_nonnegative pd value_eq
      by (simp add: pos_imp_zdiv_nonneg_iff)
    show ?thesis
    proof (cases "?s = 0")
      case True
      have feasible_empty: "?feasible = {}"
      proof (rule ccontr)
        assume "?feasible \<noteq> {}"
        then obtain wheat where wheat_in: "wheat \<in> ?feasible" by auto
        then obtain sheep where
          wheat_le: "wheat \<le> amount"
          and sheep_floor:
            "sheep = \<lfloor>(of_int wheat :: rat) * ?price\<rfloor>"
          and sheep_positive: "0 < sheep"
          by auto
        have product_le:
          "wheat * price_n \<le> amount * price_n"
          using mult_right_mono [OF wheat_le price_n_nonnegative] .
        have quotient_le:
          "wheat * price_n div price_d \<le>
            amount * price_n div price_d"
          using zdiv_mono1 [OF product_le pd] .
        have "sheep \<le> ?s"
          using sheep_floor quotient_le value_eq
          by (simp add: floor_times_ledger_price [OF pd])
        with sheep_positive True show False by simp
      qed
      have predecessor_division:
        "(price_n - 1) div price_n = 0"
        using pn by simp
      have amounts_empty:
        "Offer_Exchange_Specification.max_unrestricted_exchange offer =
          \<lparr>wheat_to_taker = 0,
           sheep_to_maker = 0\<rparr>"
        apply (subst amounts_expanded)
        by (subst if_P[OF feasible_empty]) (rule refl)
      show ?thesis
        using amounts_empty sheep_more True value_eq
          predecessor_division
        by (simp add: selling_def buying_def)
    next
      case s_nonzero: False
      have s_positive: "0 < ?s" using s_nonnegative s_nonzero by simp
      have sd_le_value: "?s * price_d \<le> wheat_value"
        using int_div_mult_le [OF pd, of wheat_value] .
      have value_le_Md: "wheat_value \<le> ?M * price_d"
        by (simp add: wheat_value_def)
      have s_le_M: "?s \<le> ?M"
        using int_div_upper_bound [OF pd value_le_Md] .
      have sd_nonnegative: "0 \<le> ?s * price_d"
        using s_nonnegative price_d_nonnegative by simp
      have w_nonnegative: "0 \<le> ?w"
        using int_ceiling_div_nonnegative [OF sd_nonnegative pn] .
      have w_positive: "0 < ?w"
      proof -
        have sd_positive: "0 < ?s * price_d"
          using s_positive pd by simp
        have "price_n \<le> ?s * price_d + price_n - 1"
          using sd_positive by linarith
        then show ?thesis
          using pos_imp_zdiv_pos_iff [OF pn,
              of "?s * price_d + price_n - 1"]
          by simp
      qed
      have w_le_amount: "?w \<le> amount"
        using int_ceiling_div_upper_bound [OF pn sd_nonnegative]
          sd_le_value value_eq by simp
      have w_le_M: "?w \<le> ?M"
        using w_le_amount amount_bound by linarith
      have sd_le_wn: "?s * price_d \<le> ?w * price_n"
        using int_le_ceiling_div_mult [OF pn, of "?s * price_d"] .
      have w_lt_next:
        "?w * price_n < (?s + 1) * price_d"
      proof -
        have ceiling_le:
          "?w * price_n \<le> ?s * price_d + price_n - 1"
          using int_div_mult_le [OF pn,
              of "?s * price_d + price_n - 1"] .
        have slack_less: "price_n - 1 < price_d"
          using price_order by linarith
        have
          "?s * price_d + price_n - 1 < ?s * price_d + price_d"
          using slack_less by linarith
        with ceiling_le show ?thesis
          by (simp add: algebra_simps)
      qed
      have floor_round_trip: "?w * price_n div price_d = ?s"
      proof (rule antisym)
        have numerator_bound:
          "?w * price_n \<le> ?s * price_d + price_d - 1"
          using w_lt_next by (simp add: algebra_simps)
        show "?w * price_n div price_d \<le> ?s"
          using int_div_below_next_multiple [OF pd numerator_bound] .
        show "?s \<le> ?w * price_n div price_d"
          using int_le_div_from_product [OF pd sd_le_wn] .
      qed
      have sd_le_Mn: "?s * price_d \<le> ?M * price_n"
        using sd_le_value value_eq amount_bound price_n_nonnegative
        by (meson mult_right_mono order_trans)
      have wn_le_Md: "?w * price_n \<le> ?M * price_d"
        using w_le_M price_order M_positive
        by (meson less_imp_le mult_mono order_trans price_n_nonnegative)
      have sd_le_Mn_rat:
        "(of_int ?s :: rat) * of_int price_d \<le>
          of_int ?M * of_int price_n"
      proof -
        have
          "(of_int (?s * price_d) :: rat) \<le>
            of_int (?M * price_n)"
          using sd_le_Mn by (simp only: of_int_le_iff)
        then show ?thesis by (simp only: of_int_mult)
      qed
      have sheep_capacity:
        "(of_int ?s :: rat) / ?price \<le> ?M"
        using sd_le_Mn_rat
        by (simp add: Offer_Exchange_Specification.rat_price_def
            divide_le_eq pn)
      have wn_le_Md_rat:
        "(of_int ?w :: rat) * of_int price_n \<le>
          of_int ?M * of_int price_d"
      proof -
        have
          "(of_int (?w * price_n) :: rat) \<le>
            of_int (?M * price_d)"
          using wn_le_Md by (simp only: of_int_le_iff)
        then show ?thesis by (simp only: of_int_mult)
      qed
      have wheat_capacity:
        "(of_int ?w :: rat) * ?price \<le> ?M"
        using wn_le_Md_rat
        by (simp add: Offer_Exchange_Specification.rat_price_def
            divide_le_eq pd)
      have candidate_in: "?w \<in> ?feasible"
        apply (rule CollectI)
        apply (rule exI[where x = ?s])
        using w_le_amount floor_round_trip w_positive w_le_M
          sheep_capacity s_positive s_le_M wheat_capacity
        by (simp add: floor_times_ledger_price [OF pd]
            ceiling_div_ledger_price [OF s_nonnegative pn pd])
      have every_le: "\<And>wheat. wheat \<in> ?feasible \<Longrightarrow> wheat \<le> ?w"
      proof -
        fix wheat
        assume wheat_in: "wheat \<in> ?feasible"
        then obtain sheep where
          wheat_round:
            "wheat = \<lceil>(of_int sheep :: rat) / ?price\<rceil>"
          and wheat_le: "wheat \<le> amount"
          and sheep_floor:
            "sheep = \<lfloor>(of_int wheat :: rat) * ?price\<rfloor>"
          and sheep_positive: "0 < sheep"
          by auto
        have product_le:
          "wheat * price_n \<le> amount * price_n"
          using mult_right_mono [OF wheat_le price_n_nonnegative] .
        have sheep_le:
          "sheep \<le> ?s"
          using zdiv_mono1 [OF product_le pd] sheep_floor value_eq
          by (simp add: floor_times_ledger_price [OF pd])
        have ceiling_numerator_le:
          "sheep * price_d + price_n - 1 \<le>
            ?s * price_d + price_n - 1"
          using mult_right_mono [OF sheep_le price_d_nonnegative] by simp
        have ceiling_le:
          "(sheep * price_d + price_n - 1) div price_n \<le> ?w"
          using zdiv_mono1 [OF ceiling_numerator_le pn] .
        show "wheat \<le> ?w"
          using wheat_round ceiling_le less_imp_le [OF sheep_positive]
          by (simp add: ceiling_div_ledger_price [OF _ pn pd])
      qed
      have max_eq: "Max ?feasible = ?w"
        using finite_feasible every_le candidate_in by (rule Max_eqI)
      have feasible_nonempty: "?feasible \<noteq> {}"
        using candidate_in by auto
      have amounts_nonempty:
        "Offer_Exchange_Specification.max_unrestricted_exchange offer =
          \<lparr>wheat_to_taker = Max ?feasible,
           sheep_to_maker =
             \<lfloor>(of_int (Max ?feasible) :: rat) * ?price\<rfloor>\<rparr>"
        apply (subst amounts_expanded)
        by (subst if_not_P[OF feasible_nonempty]) (rule refl)
      show ?thesis
        using amounts_nonempty max_eq offer_price sheep_more
          s_nonzero value_eq floor_round_trip
        by (simp add: selling_def buying_def
            floor_times_ledger_price [OF pd])
    qed
  qed
qed

text \<open>
  Once pre-flight capacities cover the maximum unrestricted exchange, the
  repaired adjustment replays that exchange at the maker's actual caps.  Proof sketch: the
  two unrestricted counterparty caps make the wheat offer the non-staying
  side.  In the wheat-more branch, the exact receive slack covers the
  exchange's final division remainder; in the opposite branch, the rounded-up
  wheat amount covers the primary sheep amount.  Thus the repaired integer
  amount pair is exactly the maximum unrestricted exchange.  The normal
  price-error filter then either preserves it or returns the zero record.
\<close>

lemma repaired_adjust_offer_replays_max_unrestricted_exchange:
  fixes price_n price_d :: int32
    and amount max_send max_receive :: int64
    and wheat_value selling buying :: int
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and wheat_value_defn: "wheat_value =
      min (sint amount * sint price_n)
        (int64_max_int * sint price_d)"
    and selling_defn: "selling =
      (if sint price_n > sint price_d
       then wheat_value div sint price_n
       else
         (let sheep = wheat_value div sint price_d
          in (sheep * sint price_d + sint price_n - 1) div sint price_n))"
    and buying_defn: "buying =
      (if sint price_n > sint price_d
       then selling * sint price_n div sint price_d
       else wheat_value div sint price_d)"
    and selling_nonnegative: "0 \<le> selling"
    and buying_nonnegative: "0 \<le> buying"
    and selling_word:
      "sint (word_of_int selling :: int64) = selling"
    and buying_word:
      "sint (word_of_int buying :: int64) = buying"
    and zeroes: "selling = 0 \<longleftrightarrow> buying = 0"
    and max_send_nonnegative: "0 \<le> sint max_send"
    and max_receive_nonnegative: "0 \<le> sint max_receive"
    and max_send_le_amount: "sint max_send \<le> sint amount"
    and selling_fits: "selling \<le> sint max_send"
    and buying_fits: "buying \<le> sint max_receive"
  shows
    "adjust_offer_with_options price_n price_d max_send max_receive
       \<lparr>exact_receive_cap = True,
        symmetric_exact_receive_cap = True\<rparr> =
     Cxx_Ok
       (if 0 < selling \<and>
           price_error_bound_spec price_n price_d
             (word_of_int selling) (word_of_int buying) False
        then word_of_int selling else 0)"
proof -
  let ?M = "int64_max_int :: int"
  let ?W = "exchange_wheat_value_int price_n price_d max_send max_receive"
  let ?S = "exchange_sheep_value_int price_n price_d int64_max int64_max"
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d max_send
    int64_max int64_max max_receive"
  have pre:
    "exchange_v10_pre price_n price_d max_send int64_max int64_max max_receive"
    using pn pd max_send_nonnegative max_receive_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  have max_send_bound: "sint max_send \<le> ?M"
    using sint64_upper_bound [of max_send] by simp
  have max_receive_bound: "sint max_receive \<le> ?M"
    using sint64_upper_bound [of max_receive] by simp
  have W_le_send: "?W \<le> sint max_send * sint price_n"
    and W_le_receive: "?W \<le> sint max_receive * sint price_d"
    using exchange_wheat_value_int_bounds [OF pre] by auto
  have W_le_Mn: "?W \<le> ?M * sint price_n"
    using W_le_send mult_right_mono
      [OF max_send_bound less_imp_le [OF pn]] by linarith
  have W_le_Md: "?W \<le> ?M * sint price_d"
    using W_le_receive mult_right_mono
      [OF max_receive_bound less_imp_le [OF pd]] by linarith
  have S_formula:
    "?S = min (?M * sint price_d) (?M * sint price_n)"
    by (simp add: exchange_sheep_value_int_def int64_max_def)
  have stays_false: "\<not> ?W > ?S"
    using W_le_Mn W_le_Md S_formula by simp
  have amounts_eq: "?A = (selling, buying)"
  proof (cases "sint price_n > sint price_d")
    case wheat_more: True
    have selling_formula: "selling = wheat_value div sint price_n"
      using selling_defn wheat_more by simp
    have buying_formula:
      "buying = selling * sint price_n div sint price_d"
      using buying_defn wheat_more by simp
    let ?trade =
      "min (sint max_send * sint price_n)
        (min (sint max_receive * sint price_d + sint price_d - 1)
          (?M * sint price_d))"
    have selling_product_le_value:
      "selling * sint price_n \<le> wheat_value"
      using int_div_mult_le [OF pn, of wheat_value]
      unfolding selling_formula .
    have selling_product_le_send:
      "selling * sint price_n \<le> sint max_send * sint price_n"
      using mult_right_mono [OF selling_fits less_imp_le [OF pn]] .
    have selling_product_le_receive:
      "selling * sint price_n \<le>
        sint max_receive * sint price_d + sint price_d - 1"
    proof -
      have quotient_bound:
        "selling * sint price_n div sint price_d \<le> sint max_receive"
        using buying_fits buying_formula by simp
      show ?thesis
        using int_div_le_imp_below_next_multiple [OF pd quotient_bound] .
    qed
    have selling_product_le_saturation:
      "selling * sint price_n \<le> ?M * sint price_d"
      using selling_product_le_value wheat_value_defn by simp
    have selling_product_le_trade:
      "selling * sint price_n \<le> ?trade"
      using selling_product_le_send selling_product_le_receive
        selling_product_le_saturation
      by simp
    have trade_le_value: "?trade \<le> wheat_value"
    proof -
      have "?trade \<le> sint max_send * sint price_n" by simp
      also have "... \<le> sint amount * sint price_n"
        using mult_right_mono
          [OF max_send_le_amount less_imp_le [OF pn]] .
      moreover have "?trade \<le> ?M * sint price_d" by simp
      ultimately show ?thesis using wheat_value_defn by simp
    qed
    have quotient_lower: "selling \<le> ?trade div sint price_n"
      using int_le_div_from_product [OF pn selling_product_le_trade] .
    have quotient_upper:
      "?trade div sint price_n \<le> selling"
      using zdiv_mono1 [OF trade_le_value pn] selling_formula pn
      by simp
    have wheat_eq: "?trade div sint price_n = selling"
      using quotient_lower quotient_upper by linarith
    show ?thesis
      using stays_false wheat_more wheat_eq buying_formula
      by (simp add: exchange_v10_amounts_int_repaired_def Let_def
          int64_max_def)
  next
    case sheep_more: False
    have price_order: "sint price_n \<le> sint price_d"
      using sheep_more by simp
    have value_eq: "wheat_value = sint amount * sint price_n"
    proof -
      have amount_le_M: "sint amount \<le> ?M"
        using sint64_upper_bound [of amount] by simp
      have
        "sint amount * sint price_n \<le> ?M * sint price_n"
        using mult_right_mono
          [OF amount_le_M less_imp_le [OF pn]] .
      also have "... \<le> ?M * sint price_d"
        using mult_left_mono [OF price_order, of ?M] by simp
      finally show ?thesis using wheat_value_defn by simp
    qed
    have buying_formula: "buying = wheat_value div sint price_d"
      using buying_defn sheep_more by simp
    have selling_formula:
      "selling =
        (buying * sint price_d + sint price_n - 1) div sint price_n"
      using selling_defn buying_formula sheep_more by (simp add: Let_def)
    have buying_product_le_selling:
      "buying * sint price_d \<le> selling * sint price_n"
      using int_le_ceiling_div_mult [OF pn,
          of "buying * sint price_d"]
      unfolding selling_formula .
    have buying_product_le_send:
      "buying * sint price_d \<le> sint max_send * sint price_n"
    proof -
      have "selling * sint price_n \<le> sint max_send * sint price_n"
        using mult_right_mono [OF selling_fits less_imp_le [OF pn]] .
      with buying_product_le_selling show ?thesis by linarith
    qed
    have buying_product_le_receive:
      "buying * sint price_d \<le> sint max_receive * sint price_d"
      using mult_right_mono [OF buying_fits less_imp_le [OF pd]] .
    have buying_product_le_W:
      "buying * sint price_d \<le> ?W"
      using buying_product_le_send buying_product_le_receive
      by (simp add: exchange_wheat_value_int_def)
    have W_le_value: "?W \<le> wheat_value"
    proof -
      have "?W \<le> sint max_send * sint price_n" using W_le_send .
      also have "... \<le> sint amount * sint price_n"
        using mult_right_mono
          [OF max_send_le_amount less_imp_le [OF pn]] .
      finally show ?thesis using value_eq by simp
    qed
    have quotient_lower: "buying \<le> ?W div sint price_d"
      using int_le_div_from_product [OF pd buying_product_le_W] .
    have quotient_upper: "?W div sint price_d \<le> buying"
      using zdiv_mono1 [OF W_le_value pd] buying_formula pd by simp
    have sheep_eq: "?W div sint price_d = buying"
      using quotient_lower quotient_upper by linarith
    show ?thesis
      using stays_false sheep_more sheep_eq selling_formula
      by (simp add: exchange_v10_amounts_int_repaired_def Let_def
          int64_max_def)
  qed
  have exchange:
    "exchange_v10_with_options price_n price_d max_send int64_max int64_max max_receive
       Exchange_Normal
       \<lparr>exact_receive_cap = True,
        symmetric_exact_receive_cap = True\<rparr> =
     apply_price_error_thresholds price_n price_d
       (word_of_int selling) (word_of_int buying) False Exchange_Normal"
    using exchange_v10_repaired_integer_characterization [OF pre]
      amounts_eq stays_false
    by simp
  have favored:
    "favored_seller_ok price_n price_d
      (word_of_int selling) (word_of_int buying) False"
  proof -
    have product_order:
      "buying * sint price_d \<le> selling * sint price_n"
    proof (cases "sint price_n > sint price_d")
      case True
      then show ?thesis
        using buying_defn int_div_mult_le [OF pd,
            of "selling * sint price_n"]
        by simp
    next
      case False
      have buying_formula: "buying = wheat_value div sint price_d"
        using buying_defn False by simp
      have selling_formula:
        "selling =
          (buying * sint price_d + sint price_n - 1) div sint price_n"
        using selling_defn buying_formula False by (simp add: Let_def)
      show ?thesis
        using int_le_ceiling_div_mult [OF pn,
            of "buying * sint price_d"]
        unfolding selling_formula .
    qed
    show ?thesis
      using product_order selling_word buying_word
      by (simp add: favored_seller_ok_def Let_def)
  qed
  have threshold:
    "apply_price_error_thresholds price_n price_d
       (word_of_int selling) (word_of_int buying) False Exchange_Normal =
     Cxx_Ok
       (make_exchange_result
         (if 0 < selling \<and>
             price_error_bound_spec price_n price_d
               (word_of_int selling) (word_of_int buying) False
          then word_of_int selling else 0)
         (if 0 < selling \<and>
             price_error_bound_spec price_n price_d
               (word_of_int selling) (word_of_int buying) False
          then word_of_int buying else 0)
         False)"
  proof (cases "selling = 0")
    case True
    then have "buying = 0" using zeroes by simp
    with True show ?thesis
      unfolding apply_price_error_thresholds_characterization
      by (simp add: apply_price_error_thresholds_spec_def Let_def
          make_exchange_result_def selling_word buying_word)
  next
    case False
    then have selling_positive: "0 < selling"
      using selling_nonnegative by simp
    have buying_positive: "0 < buying"
      using False zeroes buying_nonnegative by simp
    show ?thesis
      unfolding apply_price_error_thresholds_characterization
      using selling_positive buying_positive selling_word buying_word
        pn pd favored
      by (simp add: apply_price_error_thresholds_spec_def Let_def)
  qed
  show ?thesis
    unfolding adjust_offer_with_options_def
    using exchange threshold
    by (simp add: make_exchange_result_def)
qed

text \<open>
  On a positive non-staying unrestricted exchange, the specification's rational
  one-percent price-error bound is exactly the implementation's scaled
  integer bound.  Proof sketch: put the two rational prices over the common
  positive denominator, multiply the inequality by the positive wheat,
  price-denominator, and percentage factors, and use preservation of
  absolute value by multiplication with the positive factor.
\<close>

lemma specification_price_error_iff_implementation:
  fixes price_n price_d :: int32 and wheat sheep :: int
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_positive: "0 < wheat"
    and wheat_word:
      "sint (word_of_int wheat :: int64) = wheat"
    and sheep_word:
      "sint (word_of_int sheep :: int64) = sheep"
  shows
    "Offer_Exchange_Specification.price_error_within_bound
       (Offer_Exchange_Specification.Ledger_Price
         (sint price_n) (sint price_d))
       \<lparr>wheat_to_taker = wheat,
        sheep_to_maker = sheep\<rparr> =
     price_error_bound_spec price_n price_d
       (word_of_int wheat) (word_of_int sheep) False"
proof -
  let ?n = "sint price_n"
  let ?d = "sint price_d"
  have wheat_nonzero: "(of_int wheat :: rat) \<noteq> 0"
    using wheat_positive by simp
  have denominator_nonzero: "(of_int ?d :: rat) \<noteq> 0"
    using pd by (intro notI) simp
  have common_denominator:
    "(of_int sheep :: rat) / of_int wheat - of_int ?n / of_int ?d =
      of_int (sheep * ?d - ?n * wheat) /
        of_int (wheat * ?d)"
    using wheat_nonzero denominator_nonzero
    by (simp add: divide_inverse algebra_simps)
  have denominator_positive: "0 < wheat * ?d"
    using wheat_positive pd by simp
  have numerator_rat_positive: "0 < (of_int ?n :: rat)"
    using pn by (rule of_int_pos)
  have denominator_rat_positive: "0 < (of_int ?d :: rat)"
    using pd by (rule of_int_pos)
  have wheat_rat_positive: "0 < (of_int wheat :: rat)"
    using wheat_positive by (rule of_int_pos)
  have product_rat_positive:
    "0 < (of_int (wheat * ?d) :: rat)"
    using denominator_positive by (rule of_int_pos)
  have rational_normalized:
    "(abs ((of_int (sheep * ?d - ?n * wheat) :: rat) /
          of_int (wheat * ?d)) \<le>
        (of_int ?n / of_int ?d) / 100) =
     ((of_int (100 * abs (sheep * ?d - ?n * wheat)) :: rat) \<le>
        of_int (?n * wheat))"
    using numerator_rat_positive denominator_rat_positive
      wheat_rat_positive product_rat_positive
    by (simp add: divide_le_eq algebra_simps)
  have normalized:
    "(abs ((of_int sheep :: rat) / of_int wheat -
          of_int ?n / of_int ?d) \<le>
        (of_int ?n / of_int ?d) / 100) =
     (100 * abs (sheep * ?d - ?n * wheat) \<le> ?n * wheat)"
  proof -
    have
      "(abs ((of_int sheep :: rat) / of_int wheat -
            of_int ?n / of_int ?d) \<le>
          (of_int ?n / of_int ?d) / 100) =
       (abs ((of_int (sheep * ?d - ?n * wheat) :: rat) /
            of_int (wheat * ?d)) \<le>
          (of_int ?n / of_int ?d) / 100)"
      using common_denominator by simp
    also have "... =
       ((of_int (100 * abs (sheep * ?d - ?n * wheat)) :: rat) \<le>
          of_int (?n * wheat))"
      using rational_normalized .
    also have "... =
       (100 * abs (sheep * ?d - ?n * wheat) \<le> ?n * wheat)"
      by (simp only: of_int_le_iff)
    finally show ?thesis .
  qed
  have scaled_abs:
    "abs (100 * ?n * wheat - 100 * ?d * sheep) =
      100 * abs (sheep * ?d - ?n * wheat)"
    by (simp add: abs_if algebra_simps)
  show ?thesis
    unfolding Offer_Exchange_Specification.price_error_within_bound_def
      Offer_Exchange_Specification.effective_sheep_per_wheat_def
      Offer_Exchange_Specification.rat_price_def
      price_error_bound_spec_def Let_def
    using normalized scaled_abs wheat_word sheep_word
    by simp
qed

text \<open>
  Recomputing liabilities for the positive normalized wheat amount returns
  the same pair.  Proof sketch: for a wheat-more price, the normalized wheat
  product is already under the saturation bound and division reproduces its
  rounded sheep amount.  For the other price order, the defining ceiling and
  floor round-trip equations reproduce both fields.  The explicit liability
  characterization then yields the two executable helper results.
\<close>

lemma explicit_sell_wheat_liabilities_recompute:
  fixes price_n price_d :: int32 and amount :: int64
    and wheat_value selling buying :: int
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and wheat_value_defn: "wheat_value =
      min (sint amount * sint price_n)
        (int64_max_int * sint price_d)"
    and selling_defn: "selling =
      (if sint price_n > sint price_d
       then wheat_value div sint price_n
       else
         (let sheep = wheat_value div sint price_d
          in (sheep * sint price_d + sint price_n - 1) div sint price_n))"
    and buying_defn: "buying =
      (if sint price_n > sint price_d
       then selling * sint price_n div sint price_d
       else wheat_value div sint price_d)"
    and selling_positive: "0 < selling"
    and selling_word:
      "sint (word_of_int selling :: int64) = selling"
  shows
    "offer_selling_liabilities price_n price_d (word_of_int selling) =
       Cxx_Ok (word_of_int selling)"
    "offer_buying_liabilities price_n price_d (word_of_int selling) =
       Cxx_Ok (word_of_int buying)"
proof -
  let ?M = "int64_max_int :: int"
  let ?next_value =
    "min (selling * sint price_n) (?M * sint price_d)"
  let ?next_selling =
    "if sint price_n > sint price_d
     then ?next_value div sint price_n
     else
       (let sheep = ?next_value div sint price_d
        in (sheep * sint price_d + sint price_n - 1) div sint price_n)"
  let ?next_buying =
    "if sint price_n > sint price_d
     then ?next_selling * sint price_n div sint price_d
     else ?next_value div sint price_d"
  have selling_nonnegative: "0 \<le> selling" using selling_positive by simp
  have selling_bound: "selling \<le> ?M"
    using sint64_upper_bound [of "word_of_int selling :: int64"] selling_word
    by simp
  have next_pair: "(?next_selling, ?next_buying) = (selling, buying)"
  proof (cases "sint price_n > sint price_d")
    case wheat_more: True
    have selling_formula: "selling = wheat_value div sint price_n"
      using selling_defn wheat_more by simp
    have buying_formula:
      "buying = selling * sint price_n div sint price_d"
      using buying_defn wheat_more by simp
    have selling_product_le_value:
      "selling * sint price_n \<le> wheat_value"
      using int_div_mult_le [OF pn, of wheat_value]
      unfolding selling_formula .
    have selling_product_le_saturation:
      "selling * sint price_n \<le> ?M * sint price_d"
      using selling_product_le_value wheat_value_defn by simp
    have next_value:
      "?next_value = selling * sint price_n"
      using selling_product_le_saturation by simp
    show ?thesis
      using wheat_more next_value buying_formula pn
      by (simp add: Let_def)
  next
    case sheep_more: False
    have price_order: "sint price_n \<le> sint price_d"
      using sheep_more by simp
    have value_eq: "wheat_value = sint amount * sint price_n"
    proof -
      have amount_bound: "sint amount \<le> ?M"
        using sint64_upper_bound [of amount] by simp
      have
        "sint amount * sint price_n \<le> ?M * sint price_n"
        using mult_right_mono
          [OF amount_bound less_imp_le [OF pn]] .
      also have "... \<le> ?M * sint price_d"
        using mult_left_mono [OF price_order, of ?M] by simp
      finally show ?thesis using wheat_value_defn by simp
    qed
    have buying_formula: "buying = wheat_value div sint price_d"
      using buying_defn sheep_more by simp
    have selling_formula:
      "selling =
        (buying * sint price_d + sint price_n - 1) div sint price_n"
      using selling_defn buying_formula sheep_more by (simp add: Let_def)
    have selling_product_le_saturation:
      "selling * sint price_n \<le> ?M * sint price_d"
    proof -
      have saturation_nonnegative: "0 \<le> ?M" by simp
      have price_n_nonnegative: "0 \<le> sint price_n"
        using pn by simp
      show ?thesis
        using mult_mono
          [OF selling_bound price_order saturation_nonnegative
            price_n_nonnegative] .
    qed
    have next_value:
      "?next_value = selling * sint price_n"
      using selling_product_le_saturation by simp
    have next_buying: "?next_value div sint price_d = buying"
    proof -
      have product_lower:
        "buying * sint price_d \<le> selling * sint price_n"
        using int_le_ceiling_div_mult [OF pn,
            of "buying * sint price_d"]
        unfolding selling_formula .
      have product_upper:
        "selling * sint price_n \<le>
          buying * sint price_d + sint price_n - 1"
        using int_div_mult_le [OF pn,
            of "buying * sint price_d + sint price_n - 1"]
        unfolding selling_formula .
      have numerator_bound:
        "selling * sint price_n \<le>
          buying * sint price_d + sint price_d - 1"
        using product_upper price_order by linarith
      have upper:
        "selling * sint price_n div sint price_d \<le> buying"
        using int_div_below_next_multiple [OF pd numerator_bound] .
      have lower:
        "buying \<le> selling * sint price_n div sint price_d"
        using int_le_div_from_product [OF pd product_lower] .
      show ?thesis
        using next_value lower upper by linarith
    qed
    show ?thesis
      using sheep_more next_value next_buying selling_formula
      by (simp add: Let_def)
  qed
  have next_amount_positive:
    "0 < sint (word_of_int selling :: int64)"
    using selling_positive selling_word by simp
  note explicit = manage_sell_request_liabilities_explicit
    [where amount = "word_of_int selling", OF pn pd next_amount_positive]
  have next_selling_eq: "?next_selling = selling"
    and next_buying_eq: "?next_buying = buying"
    using next_pair by simp_all
  have explicit_selling:
    "offer_selling_liabilities price_n price_d (word_of_int selling) =
      Cxx_Ok (word_of_int ?next_selling)"
    using explicit(1) selling_word by (simp add: Let_def)
  have explicit_buying:
    "offer_buying_liabilities price_n price_d (word_of_int selling) =
      Cxx_Ok (word_of_int ?next_buying)"
    using explicit(2) selling_word by (simp add: Let_def)
  show
    "offer_selling_liabilities price_n price_d (word_of_int selling) =
       Cxx_Ok (word_of_int selling)"
    "offer_buying_liabilities price_n price_d (word_of_int selling) =
       Cxx_Ok (word_of_int buying)"
    using explicit_selling explicit_buying next_selling_eq next_buying_eq
    by simp_all
qed

text \<open>
  The specification also recomputes the same maximum unrestricted exchange
  after replacing the requested amount by its positive normalized wheat
  amount.  Proof
  sketch: instantiate the executable characterization at that normalized
  amount.  The preceding fixed-point lemma identifies its two returned words
  with the original pair, while the characterization's signed round-trip
  clauses identify the underlying integers.  The declarative characterization
  at the updated offer then yields the same record.
\<close>

lemma specification_max_unrestricted_exchange_recompute:
  fixes price_n price_d :: int32 and amount :: int64
    and offer :: Offer_Exchange_Specification.sell_wheat_offer
    and wheat_value selling buying :: int
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and wheat_value_defn: "wheat_value =
      min (sint amount * sint price_n)
        (int64_max_int * sint price_d)"
    and selling_defn: "selling =
      (if sint price_n > sint price_d
       then wheat_value div sint price_n
       else
         (let sheep = wheat_value div sint price_d
          in (sheep * sint price_d + sint price_n - 1) div sint price_n))"
    and buying_defn: "buying =
      (if sint price_n > sint price_d
       then selling * sint price_n div sint price_d
       else wheat_value div sint price_d)"
    and selling_positive: "0 < selling"
    and selling_word:
      "sint (word_of_int selling :: int64) = selling"
    and buying_word:
      "sint (word_of_int buying :: int64) = buying"
    and offer_amount: "wheat_amount offer = selling"
    and offer_price:
      "sheep_per_wheat offer =
        Offer_Exchange_Specification.Ledger_Price
          (sint price_n) (sint price_d)"
  shows
    "Offer_Exchange_Specification.max_unrestricted_exchange offer =
      \<lparr>wheat_to_taker = selling,
       sheep_to_maker = buying\<rparr>"
proof -
  define next_value where
    "next_value = min (selling * sint price_n)
      (int64_max_int * sint price_d)"
  define next_selling where
    "next_selling =
      (if sint price_n > sint price_d
       then next_value div sint price_n
       else
         (let sheep = next_value div sint price_d
          in (sheep * sint price_d + sint price_n - 1) div sint price_n))"
  define next_buying where
    "next_buying =
      (if sint price_n > sint price_d
       then next_selling * sint price_n div sint price_d
       else next_value div sint price_d)"
  have next_amount_positive:
    "0 < sint (word_of_int selling :: int64)"
    using selling_positive selling_word by simp
  note next_explicit = manage_sell_request_liabilities_explicit
    [OF pn pd next_amount_positive,
     folded next_value_def next_selling_def next_buying_def]
  note recomputed = explicit_sell_wheat_liabilities_recompute
    [OF pn pd amount_positive wheat_value_defn selling_defn buying_defn
      selling_positive selling_word]
  note next_selling_output = next_explicit(1)
  note next_buying_output = next_explicit(2)
  note next_selling_word = next_explicit(3)
  note next_buying_word = next_explicit(4)
  have next_selling_output_normalized:
      "offer_selling_liabilities price_n price_d (word_of_int selling) =
       Cxx_Ok (word_of_int next_selling)"
    using next_selling_output selling_word
    by (simp add: next_value_def next_selling_def Let_def)
  have next_buying_output_normalized:
      "offer_buying_liabilities price_n price_d (word_of_int selling) =
       Cxx_Ok (word_of_int next_buying)"
    using next_buying_output selling_word
    by (simp add: next_value_def next_selling_def next_buying_def Let_def)
  have next_selling_word_normalized:
      "sint (word_of_int next_selling :: int64) = next_selling"
    using next_selling_word selling_word
    unfolding next_value_def next_selling_def
    by (simp only: selling_word)
  have next_buying_word_normalized:
      "sint (word_of_int next_buying :: int64) = next_buying"
    using next_buying_word selling_word
    unfolding next_value_def next_selling_def next_buying_def
    by (simp only: selling_word)
  have next_selling_result:
      "Cxx_Ok (word_of_int next_selling :: int64) =
       Cxx_Ok (word_of_int selling)"
  proof -
    have "Cxx_Ok (word_of_int next_selling :: int64) =
        offer_selling_liabilities price_n price_d (word_of_int selling)"
      using next_selling_output_normalized by (rule sym)
    also have "... = Cxx_Ok (word_of_int selling)"
      using recomputed(1) .
    finally show ?thesis .
  qed
  have next_selling_encoded:
      "(word_of_int next_selling :: int64) = word_of_int selling"
    using next_selling_result by (simp only: cxx_result.inject)
  have next_buying_result:
      "Cxx_Ok (word_of_int next_buying :: int64) =
       Cxx_Ok (word_of_int buying)"
  proof -
    have "Cxx_Ok (word_of_int next_buying :: int64) =
        offer_buying_liabilities price_n price_d (word_of_int selling)"
      using next_buying_output_normalized by (rule sym)
    also have "... = Cxx_Ok (word_of_int buying)"
      using recomputed(2) .
    finally show ?thesis .
  qed
  have next_buying_encoded:
      "(word_of_int next_buying :: int64) = word_of_int buying"
    using next_buying_result by (simp only: cxx_result.inject)
  have fixed_selling: "next_selling = selling"
  proof -
    have "next_selling = sint (word_of_int next_selling :: int64)"
      using next_selling_word_normalized by (rule sym)
    also have "... = sint (word_of_int selling :: int64)"
      using next_selling_encoded by (rule arg_cong)
    also have "... = selling"
      using selling_word .
    finally show ?thesis .
  qed
  have fixed_buying: "next_buying = buying"
  proof -
    have "next_buying = sint (word_of_int next_buying :: int64)"
      using next_buying_word_normalized by (rule sym)
    also have "... = sint (word_of_int buying :: int64)"
      using next_buying_encoded by (rule arg_cong)
    also have "... = buying"
      using buying_word .
    finally show ?thesis .
  qed
  have price_n_bound: "sint price_n \<le> int64_max_int"
    using sint_lt [of price_n] by simp
  have price_d_bound: "sint price_d \<le> int64_max_int"
    using sint_lt [of price_d] by simp
  have selling_bound: "selling \<le> int64_max_int"
    using sint64_upper_bound [of "word_of_int selling :: int64"]
      selling_word by simp
  note spec_amounts = specification_max_unrestricted_exchange_explicit
    [OF pn pd selling_positive price_n_bound price_d_bound selling_bound
      offer_amount offer_price,
     folded next_value_def next_selling_def next_buying_def]
  show ?thesis using spec_amounts fixed_selling fixed_buying by simp
qed

lemma post_sell_offer_refines_post_sell_wheat_offer [export_audit]:
  fixes price_n price_d :: int32
    and amount :: int64
    and passive_flag :: bool
    and maker :: party_state
    and offer :: Offer_Exchange_Specification.sell_wheat_offer
    and abstract_maker :: Offer_Exchange_Specification.maker_state
  defines
    "offer \<equiv>
      \<lparr>is_passive = passive_flag,
       wheat_amount = sint amount,
       sheep_per_wheat =
         Offer_Exchange_Specification.Ledger_Price
           (sint price_n) (sint price_d)\<rparr>"
    and
    "abstract_maker \<equiv>
      \<lparr>wheat_balance = sint (sell_balance maker),
       sheep_balance = sint (buy_balance maker),
       wheat_selling_liabilities = sint (sell_liabilities maker),
       sheep_limit = sint (buy_limit maker),
       sheep_buying_liabilities = sint (buy_liabilities maker)\<rparr>"
  assumes
    "party_state_wf maker"
    "Offer_Exchange_Specification.sell_wheat_offer_well_formed offer"
  shows
    "(case post_sell_offer price_n price_d amount maker
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> of
       Cxx_Err _ \<Rightarrow> False
     | Cxx_Ok Post_Malformed \<Rightarrow>
         Offer_Exchange_Specification.post_sell_wheat_offer
           offer abstract_maker =
         Offer_Exchange_Specification.Malformed
     | Cxx_Ok Post_Line_Full \<Rightarrow>
         Offer_Exchange_Specification.post_sell_wheat_offer
           offer abstract_maker =
         Offer_Exchange_Specification.Line_Full
     | Cxx_Ok Post_Underfunded \<Rightarrow>
         Offer_Exchange_Specification.post_sell_wheat_offer
           offer abstract_maker =
         Offer_Exchange_Specification.Underfunded
     | Cxx_Ok Post_No_Offer \<Rightarrow>
         Offer_Exchange_Specification.post_sell_wheat_offer
           offer abstract_maker =
         Offer_Exchange_Specification.No_Offer
     | Cxx_Ok (Post_Created posted concrete_maker) \<Rightarrow>
         Offer_Exchange_Specification.post_sell_wheat_offer
           offer abstract_maker =
         Offer_Exchange_Specification.Created
           (offer\<lparr>wheat_amount := sint posted\<rparr>)
           \<lparr>wheat_balance = sint (sell_balance concrete_maker),
            sheep_balance = sint (buy_balance concrete_maker),
            wheat_selling_liabilities =
              sint (sell_liabilities concrete_maker),
            sheep_limit = sint (buy_limit concrete_maker),
            sheep_buying_liabilities =
              sint (buy_liabilities concrete_maker)\<rparr>)"
text \<open>
  Proof sketch: first identify both models' maximum unrestricted exchange with
  the same explicit integer formulas, and identify the implementation's
  clamped capacities with the maker's raw specification headroom.  The first
  two failed capacity tests then give the same line-full and underfunded
  outcomes.  Zero receive capacity forces both exchanged amounts to zero, giving
  the remaining line-full case.  Otherwise the repaired adjustment replays
  the covered exchange; its integer price test is the specification's
  rational test.  A zero or rejected pair gives no offer.  For an accepted
  positive exchange, recomputation is a fixed point and both models reserve
  its two amounts as liabilities in the maker state, so their created offers and mapped states
  coincide bit-precisely.
\<close>
proof -
  let ?M = "int64_max_int :: int"
  let ?buy_available =
    "sint (buy_limit maker) - sint (buy_balance maker) -
      sint (buy_liabilities maker)"
  let ?sell_available =
    "sint (sell_balance maker) - sint (sell_liabilities maker)"
  have maker_wf: "party_state_wf maker" using assms(3) .
  have offer_wf:
    "Offer_Exchange_Specification.sell_wheat_offer_well_formed offer"
    using assms(4) .
  have pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    using offer_wf
    unfolding Offer_Exchange_Specification.sell_wheat_offer_well_formed_def
      Offer_Exchange_Specification.ledger_price_well_formed_def offer_def
    by simp_all
  have offer_amount: "wheat_amount offer = sint amount"
    and offer_price:
      "sheep_per_wheat offer =
        Offer_Exchange_Specification.Ledger_Price
          (sint price_n) (sint price_d)"
    unfolding offer_def by simp_all
  have price_n_bound: "sint price_n \<le> ?M"
    using sint_lt [of price_n] by simp
  have price_d_bound: "sint price_d \<le> ?M"
    using sint_lt [of price_d] by simp
  have amount_bound: "sint amount \<le> ?M"
    using sint64_upper_bound [of amount] by simp
  define wheat_value where
    "wheat_value = min (sint amount * sint price_n)
      (?M * sint price_d)"
  define selling where
    "selling =
      (if sint price_n > sint price_d
       then wheat_value div sint price_n
       else
         (let sheep = wheat_value div sint price_d
          in (sheep * sint price_d + sint price_n - 1) div sint price_n))"
  define buying where
    "buying =
      (if sint price_n > sint price_d
       then selling * sint price_n div sint price_d
       else wheat_value div sint price_d)"
  note implementation_liabilities =
    manage_sell_request_liabilities_explicit
      [OF pn pd amount_positive,
       folded wheat_value_def selling_def buying_def]
  have selling_liability:
    "offer_selling_liabilities price_n price_d amount =
      Cxx_Ok (word_of_int selling)"
    and buying_liability:
    "offer_buying_liabilities price_n price_d amount =
      Cxx_Ok (word_of_int buying)"
    and selling_word:
      "sint (word_of_int selling :: int64) = selling"
    and buying_word:
      "sint (word_of_int buying :: int64) = buying"
    and selling_nonnegative: "0 \<le> selling"
    and selling_le_amount: "selling \<le> sint amount"
    and buying_nonnegative: "0 \<le> buying"
    using implementation_liabilities by simp_all
  have specification_amounts:
    "Offer_Exchange_Specification.max_unrestricted_exchange offer =
      \<lparr>wheat_to_taker = selling,
       sheep_to_maker = buying\<rparr>"
    using specification_max_unrestricted_exchange_explicit
      [OF pn pd amount_positive price_n_bound price_d_bound amount_bound
        offer_amount offer_price,
       folded wheat_value_def selling_def buying_def] .
  have zeroes: "selling = 0 \<longleftrightarrow> buying = 0"
    using Offer_Exchange_Specification.max_unrestricted_exchange_all_zero_or_none
      [OF offer_wf]
      specification_amounts
    by simp
  have sell_available_nonnegative: "0 \<le> ?sell_available"
    and buy_available_nonnegative: "0 \<le> ?buy_available"
    and sell_available_max: "?sell_available \<le> ?M"
    and buy_available_max: "?buy_available \<le> ?M"
    using maker_wf sint64_upper_bound [of "sell_balance maker"]
      sint64_upper_bound [of "buy_limit maker"]
    unfolding party_state_wf_def
    by linarith+
  have can_sell_sint:
    "sint (can_sell_at_most maker) = ?sell_available"
    unfolding can_sell_at_most_def Let_def
    using sell_available_nonnegative sell_available_max
      sint_word_of_int_nonnegative_int64
        [OF sell_available_nonnegative sell_available_max]
    by simp
  have can_buy_sint:
    "sint (can_buy_at_most maker) = ?buy_available"
    unfolding can_buy_at_most_def Let_def
    using buy_available_nonnegative buy_available_max
      sint_word_of_int_nonnegative_int64
        [OF buy_available_nonnegative buy_available_max]
    by simp
  show ?thesis
  proof (cases "?buy_available < buying")
    case True
    have concrete:
      "post_sell_offer price_n price_d amount maker
         \<lparr>exact_receive_cap = True,
          symmetric_exact_receive_cap = True\<rparr> =
       Cxx_Ok Post_Line_Full"
      unfolding post_sell_offer_def post_offer_core_def
        preflight_offer_core_def
      using pn pd amount_positive buying_liability buying_word True
      by (simp add: Let_def)
    have abstract:
      "Offer_Exchange_Specification.post_sell_wheat_offer
         offer abstract_maker =
       Offer_Exchange_Specification.Line_Full"
      unfolding Offer_Exchange_Specification.post_sell_wheat_offer_def
        Offer_Exchange_Specification.ledger_price_well_formed_def
        Offer_Exchange_Specification.maker_sheep_headroom_def
        Offer_Exchange_Specification.maker_available_wheat_def
        abstract_maker_def
      using pn pd amount_positive specification_amounts offer_amount
        offer_price True
      by (simp add: Let_def)
    show ?thesis using concrete abstract by simp
  next
    case buy_fits: False
    show ?thesis
    proof (cases "?sell_available < selling")
      case True
      have selling_positive: "0 < selling"
        using True sell_available_nonnegative by linarith
      have buying_positive: "0 < buying"
        using zeroes buying_nonnegative selling_positive by auto
      have buy_available_positive: "0 < ?buy_available"
        using buy_fits buying_positive by linarith
      have concrete:
        "post_sell_offer price_n price_d amount maker
           \<lparr>exact_receive_cap = True,
            symmetric_exact_receive_cap = True\<rparr> =
         Cxx_Ok Post_Underfunded"
        unfolding post_sell_offer_def post_offer_core_def
          preflight_offer_core_def
        using pn pd amount_positive buying_liability selling_liability
          selling_word buying_word buy_fits True
        by (simp add: Let_def)
      have abstract:
        "Offer_Exchange_Specification.post_sell_wheat_offer
           offer abstract_maker =
         Offer_Exchange_Specification.Underfunded"
        unfolding Offer_Exchange_Specification.post_sell_wheat_offer_def
          Offer_Exchange_Specification.ledger_price_well_formed_def
          Offer_Exchange_Specification.maker_sheep_headroom_def
          Offer_Exchange_Specification.maker_available_wheat_def
          abstract_maker_def
        using pn pd amount_positive specification_amounts offer_amount
          offer_price buy_fits True buy_available_positive
        by (simp add: Let_def)
      show ?thesis using concrete abstract by simp
    next
      case sell_fits: False
      show ?thesis
      proof (cases "?buy_available = 0")
        case True
        have buying_zero: "buying = 0"
          using buy_fits True buying_nonnegative by linarith
        have selling_zero: "selling = 0"
          using zeroes buying_zero by simp
        have can_buy_zero: "can_buy_at_most maker = 0"
          unfolding can_buy_at_most_def Let_def
          using True by simp
        have concrete:
          "post_sell_offer price_n price_d amount maker
             \<lparr>exact_receive_cap = True,
              symmetric_exact_receive_cap = True\<rparr> =
           Cxx_Ok Post_Line_Full"
          unfolding post_sell_offer_def post_offer_core_def
            preflight_offer_core_def
          using pn pd amount_positive buying_liability selling_liability
            selling_word buying_word buy_fits sell_fits buying_zero
            selling_zero can_buy_zero
          by (simp add: Let_def)
        have abstract:
          "Offer_Exchange_Specification.post_sell_wheat_offer
             offer abstract_maker =
           Offer_Exchange_Specification.Line_Full"
          unfolding Offer_Exchange_Specification.post_sell_wheat_offer_def
            Offer_Exchange_Specification.ledger_price_well_formed_def
            Offer_Exchange_Specification.maker_sheep_headroom_def
            Offer_Exchange_Specification.maker_available_wheat_def
            abstract_maker_def
          using pn pd amount_positive specification_amounts offer_amount
            offer_price True
          by (simp add: Let_def)
        show ?thesis using concrete abstract by simp
      next
        case buy_nonzero: False
        let ?max_send =
          "signed_min64 amount (can_sell_at_most maker)"
        let ?max_receive = "can_buy_at_most maker"
        have buy_available_positive: "0 < ?buy_available"
          using buy_nonzero buy_available_nonnegative by linarith
        have selling_available: "selling \<le> ?sell_available"
          using sell_fits by linarith
        have buying_available: "buying \<le> ?buy_available"
          using buy_fits by linarith
        have max_receive_nonzero: "?max_receive \<noteq> 0"
          using can_buy_sint buy_available_positive by auto
        have max_send_nonnegative: "0 \<le> sint ?max_send"
          using amount_positive can_sell_at_most_nonnegative [OF maker_wf]
          by (simp add: signed_min64_def)
        have max_receive_nonnegative: "0 \<le> sint ?max_receive"
          using can_buy_at_most_nonnegative [OF maker_wf] .
        have max_send_le_amount: "sint ?max_send \<le> sint amount"
          by (simp add: signed_min64_def split: if_splits)
        have selling_fits_max_send: "selling \<le> sint ?max_send"
          using selling_le_amount selling_available can_sell_sint
          by (simp add: signed_min64_def split: if_splits)
        have buying_fits_max_receive: "buying \<le> sint ?max_receive"
          using buying_available can_buy_sint by simp
        have adjusted:
          "adjust_offer_with_options price_n price_d ?max_send ?max_receive
             \<lparr>exact_receive_cap = True,
              symmetric_exact_receive_cap = True\<rparr> =
           Cxx_Ok
             (if 0 < selling \<and>
                 price_error_bound_spec price_n price_d
                   (word_of_int selling) (word_of_int buying) False
              then word_of_int selling else 0)"
          using repaired_adjust_offer_replays_max_unrestricted_exchange
            [OF pn pd amount_positive wheat_value_def selling_def buying_def
              selling_nonnegative buying_nonnegative selling_word buying_word
              zeroes max_send_nonnegative max_receive_nonnegative
              max_send_le_amount selling_fits_max_send
              buying_fits_max_receive] .
        show ?thesis
        proof (cases "selling = 0")
          case True
          have buying_zero: "buying = 0" using zeroes True by simp
          have adjusted_zero:
            "adjust_offer_with_options price_n price_d ?max_send ?max_receive
               \<lparr>exact_receive_cap = True,
                symmetric_exact_receive_cap = True\<rparr> = Cxx_Ok 0"
            using adjusted True by simp
          have concrete:
            "post_sell_offer price_n price_d amount maker
               \<lparr>exact_receive_cap = True,
                symmetric_exact_receive_cap = True\<rparr> =
             Cxx_Ok Post_No_Offer"
            unfolding post_sell_offer_def post_offer_core_def
              preflight_offer_core_def
            using pn pd amount_positive buying_liability selling_liability
              selling_word buying_word buy_fits sell_fits
              max_receive_nonzero adjusted_zero
            by (simp add: Let_def)
          have abstract:
            "Offer_Exchange_Specification.post_sell_wheat_offer
               offer abstract_maker =
             Offer_Exchange_Specification.No_Offer"
            unfolding Offer_Exchange_Specification.post_sell_wheat_offer_def
              Offer_Exchange_Specification.ledger_price_well_formed_def
              Offer_Exchange_Specification.maker_sheep_headroom_def
              Offer_Exchange_Specification.maker_available_wheat_def
              abstract_maker_def
            using pn pd amount_positive specification_amounts offer_amount
              offer_price buy_fits sell_fits buy_available_positive True
            by (simp add: Let_def)
          show ?thesis using concrete abstract by simp
        next
          case selling_nonzero: False
          have selling_positive: "0 < selling"
            using selling_nonnegative selling_nonzero by simp
          have price_bridge:
            "Offer_Exchange_Specification.price_error_within_bound
               (Offer_Exchange_Specification.Ledger_Price
                 (sint price_n) (sint price_d))
               \<lparr>wheat_to_taker = selling,
                sheep_to_maker = buying\<rparr> =
             price_error_bound_spec price_n price_d
               (word_of_int selling) (word_of_int buying) False"
            using specification_price_error_iff_implementation
              [OF pn pd selling_positive selling_word buying_word] .
          show ?thesis
          proof (cases "price_error_bound_spec price_n price_d
              (word_of_int selling) (word_of_int buying) False")
            case False
            have adjusted_zero:
              "adjust_offer_with_options price_n price_d ?max_send ?max_receive
                 \<lparr>exact_receive_cap = True,
                  symmetric_exact_receive_cap = True\<rparr> = Cxx_Ok 0"
              using adjusted selling_positive False by simp
            have concrete:
              "post_sell_offer price_n price_d amount maker
                 \<lparr>exact_receive_cap = True,
                  symmetric_exact_receive_cap = True\<rparr> =
               Cxx_Ok Post_No_Offer"
              unfolding post_sell_offer_def post_offer_core_def
                preflight_offer_core_def
              using pn pd amount_positive buying_liability selling_liability
                selling_word buying_word buy_fits sell_fits
                max_receive_nonzero adjusted_zero
              by (simp add: Let_def)
            have abstract:
              "Offer_Exchange_Specification.post_sell_wheat_offer
                 offer abstract_maker =
               Offer_Exchange_Specification.No_Offer"
              unfolding Offer_Exchange_Specification.post_sell_wheat_offer_def
                Offer_Exchange_Specification.ledger_price_well_formed_def
                Offer_Exchange_Specification.maker_sheep_headroom_def
                Offer_Exchange_Specification.maker_available_wheat_def
                abstract_maker_def
              using pn pd amount_positive specification_amounts
                offer_amount offer_price buy_fits sell_fits
                buy_available_positive selling_positive price_bridge False
              by (simp add: Let_def)
            show ?thesis using concrete abstract by simp
          next
            case True
            let ?posted = "offer\<lparr>wheat_amount := selling\<rparr>"
            let ?new_buying =
              "sint (buy_liabilities maker) + buying"
            let ?new_selling =
              "sint (sell_liabilities maker) + selling"
            let ?abstract_after =
              "\<lparr>wheat_balance = sint (sell_balance maker),
                sheep_balance = sint (buy_balance maker),
                wheat_selling_liabilities = ?new_selling,
                sheep_limit = sint (buy_limit maker),
                sheep_buying_liabilities = ?new_buying\<rparr>"
            have adjusted_positive:
              "adjust_offer_with_options price_n price_d ?max_send ?max_receive
                 \<lparr>exact_receive_cap = True,
                  symmetric_exact_receive_cap = True\<rparr> =
               Cxx_Ok (word_of_int selling)"
              using adjusted selling_positive True by simp
            note recomputed = explicit_sell_wheat_liabilities_recompute
              [OF pn pd amount_positive wheat_value_def selling_def buying_def
                selling_positive selling_word]
            have posted_amount: "wheat_amount ?posted = selling" by simp
            have posted_price:
              "sheep_per_wheat ?posted =
                Offer_Exchange_Specification.Ledger_Price
                  (sint price_n) (sint price_d)"
              using offer_price by simp
            have posted_amounts:
              "Offer_Exchange_Specification.max_unrestricted_exchange
                 ?posted =
               \<lparr>wheat_to_taker = selling,
                sheep_to_maker = buying\<rparr>"
              using specification_max_unrestricted_exchange_recompute
                [where offer = ?posted,
                 OF pn pd amount_positive wheat_value_def selling_def
                   buying_def selling_positive selling_word buying_word
                   posted_amount posted_price] .
            have old_selling_nonnegative:
              "0 \<le> sint (sell_liabilities maker)"
              and old_buying_nonnegative:
              "0 \<le> sint (buy_liabilities maker)"
              and buy_balance_nonnegative:
              "0 \<le> sint (buy_balance maker)"
              using maker_wf by (simp_all add: party_state_wf_def)
            have new_buying_nonnegative: "0 \<le> ?new_buying"
              using old_buying_nonnegative buying_nonnegative by linarith
            have new_selling_nonnegative: "0 \<le> ?new_selling"
              using old_selling_nonnegative selling_nonnegative by linarith
            have new_buying_fits:
              "?new_buying \<le>
                sint (buy_limit maker) - sint (buy_balance maker)"
              using buying_available by linarith
            have new_selling_fits:
              "?new_selling \<le> sint (sell_balance maker)"
              using selling_available by linarith
            have new_buying_max: "?new_buying \<le> ?M"
              using new_buying_fits buy_balance_nonnegative
                sint64_upper_bound [of "buy_limit maker"]
              by linarith
            have new_selling_max: "?new_selling \<le> ?M"
              using new_selling_fits
                sint64_upper_bound [of "sell_balance maker"]
              by linarith
            have new_buying_word:
              "sint (word_of_int ?new_buying :: int64) = ?new_buying"
              using sint_word_of_int_nonnegative_int64
                [OF new_buying_nonnegative new_buying_max] .
            have new_selling_word:
              "sint (word_of_int ?new_selling :: int64) = ?new_selling"
              using sint_word_of_int_nonnegative_int64
                [OF new_selling_nonnegative new_selling_max] .
            have acquired:
              "acquire_offer_liabilities price_n price_d
                 (word_of_int selling) maker =
               Cxx_Ok
                 (maker\<lparr>buy_liabilities := word_of_int ?new_buying,
                         sell_liabilities := word_of_int ?new_selling\<rparr>)"
              unfolding acquire_offer_liabilities_def
                add_liability_checked_def
              using recomputed selling_word buying_word
                new_buying_nonnegative new_selling_nonnegative
                new_buying_fits new_selling_fits
              by (simp add: Let_def)
            have concrete:
              "post_sell_offer price_n price_d amount maker
                 \<lparr>exact_receive_cap = True,
                  symmetric_exact_receive_cap = True\<rparr> =
               Cxx_Ok
                 (Post_Created (word_of_int selling)
                   (maker\<lparr>buy_liabilities := word_of_int ?new_buying,
                           sell_liabilities := word_of_int ?new_selling\<rparr>))"
              unfolding post_sell_offer_def post_offer_core_def
                preflight_offer_core_def
              using pn pd amount_positive buying_liability selling_liability
                selling_positive selling_word buying_word buy_fits sell_fits
                max_receive_nonzero adjusted_positive acquired
              by (simp add: Let_def)
            have abstract:
              "Offer_Exchange_Specification.post_sell_wheat_offer
                 offer abstract_maker =
               Offer_Exchange_Specification.Created
                 ?posted ?abstract_after"
              unfolding Offer_Exchange_Specification.post_sell_wheat_offer_def
                Offer_Exchange_Specification.ledger_price_well_formed_def
                Offer_Exchange_Specification.maker_sheep_headroom_def
                Offer_Exchange_Specification.maker_available_wheat_def
                Offer_Exchange_Specification.reserve_sell_wheat_offer_liabilities_def
                abstract_maker_def
              using pn pd amount_positive specification_amounts
                offer_amount offer_price buy_fits sell_fits
                buy_available_positive selling_positive price_bridge True
                posted_amounts
              by (simp add: Let_def)
            show ?thesis
              apply (simp only: concrete cxx_result.case post_outcome.case
                  abstract selling_word)
              using new_buying_word new_selling_word
              by simp
          qed
        qed
      qed
    qed
  qed
qed

end
