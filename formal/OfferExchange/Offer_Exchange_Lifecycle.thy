theory Offer_Exchange_Lifecycle
  imports Offer_Exchange_Adjustment "HOL.Real"
begin

section \<open>Posting an offer and then crossing it\<close>

text \<open>
  This theory present a bit-precise model of the ledger-level life of a single resting offer around
  @{const exchange_v10_with_options}: a maker posts a wheat-for-sheep offer, which enters
  the order book, and a taker later crosses it.  Posting follows the
  protocol-10 branch of \<open>ManageOfferOpFrameBase::doApply\<close> for an offer that
  crosses nothing on entry; crossing follows \<open>crossOfferV10\<close>
  (\<open>OfferExchange.cpp\<close>).

  The balances, trustline limits, and existing liabilities of the parties
  are parameters at each step.  In particular the maker's state at posting
  time and at crossing time are independent inputs, so any intervening
  ledger activity by third parties---for example a payment that consumes the
  maker's trustline headroom---can be expressed by choosing the two states
  independently.  A predicate near the end of the theory captures the part
  of the reachability constraint that connects the two steps.

  Assets are named from the resting offer's perspective: the posted offer
  sells wheat and buys sheep, and its price quotes @{term "sint price_n"}
  sheep for @{term "sint price_d"} wheat.  Native-asset reserves, trustline
  authorization, and sponsorship are abstracted away: a party is reduced to
  the signed 64-bit quantities that the C++ helpers \<open>canSellAtMost\<close> and
  \<open>canBuyAtMost\<close> consume.

  The imported \<open>Offer_Exchange_Adjustment\<close> theory supplies the
  maker-independent offer adjustment, liability projection, and executable
  filtering arithmetic.  This theory begins where ledger state first matters.
\<close>

subsection \<open>Parties\<close>

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
  below.  The subtractions here are exact; under @{const party_state_wf}
  they stay within the signed 64-bit range, matching the ledger invariants
  that protect the C++ subtractions from overflowing.
\<close>

definition party_receive_buy_asset ::
    "party_state \<Rightarrow> int64 \<Rightarrow> party_state cxx_result"
  \<comment> \<open>C++: \<open>TrustLineWrapper::addBalance\<close> (\<open>ledger/TrustLineWrapper.cpp\<close>)\<close>
  where
    "party_receive_buy_asset party delta =
      (if delta = 0 then Cxx_Ok party
       else if sint (buy_limit party) - sint (buy_balance party) -
           sint (buy_liabilities party) < sint delta
       then Cxx_Err Cxx_Runtime_Error
       else Cxx_Ok
         (party\<lparr>buy_balance :=
            word_of_int (sint (buy_balance party) + sint delta)\<rparr>))"

definition party_spend_sell_asset ::
    "party_state \<Rightarrow> int64 \<Rightarrow> party_state cxx_result"
  \<comment> \<open>C++: \<open>TrustLineWrapper::addBalance\<close> (\<open>ledger/TrustLineWrapper.cpp\<close>)\<close>
  where
    "party_spend_sell_asset party delta =
      (if delta = 0 then Cxx_Ok party
       else if sint (sell_balance party) - sint (sell_liabilities party) <
           sint delta
       then Cxx_Err Cxx_Runtime_Error
       else Cxx_Ok
         (party\<lparr>sell_balance :=
            word_of_int (sint (sell_balance party) - sint delta)\<rparr>))"

text \<open>
  @{const party_receive_buy_asset} and @{const party_spend_sell_asset} model
  the trustline \<open>addBalance\<close> calls that move the traded amounts: receiving
  is bounded by the limit minus the balance and the buying liabilities,
  spending by the balance minus the selling liabilities, and a violation is
  the runtime error that \<open>crossOfferV10\<close> and
  \<open>ManageOfferOpFrameBase::doApply\<close> raise when a computed amount does not
  fit.  The C++ sites skip the call when the amount is zero, so neither
  function can fail on a zero amount.
\<close>

subsection \<open>State-dependent adjustment and offer liabilities\<close>

definition adjust_stable ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      exchange_options \<Rightarrow> bool"
  where
    "adjust_stable price_n price_d amount maker options \<longleftrightarrow>
      adjust_offer_with_options price_n price_d
        (signed_min64 amount (can_sell_at_most maker))
        (can_buy_at_most maker) options = Cxx_Ok amount"

text \<open>
  @{const adjust_stable} names the write-time invariant of the order book:
  an amount is adjust-stable at a party state when the adjustment computed
  from that state's capacities returns it unchanged.  Both ledger call
  sites of \<open>adjustOffer\<close> feed it exactly these arguments---posting
  against the maker's bare state, crossing against the state left by
  releasing the offer's liabilities---so a stable amount passes the
  preventative adjustment untouched while an unstable one is clipped.
  Every write to an offer entry goes through @{const adjust_offer_with_options}, so the
  book only ever records amounts that were stable at the moment of
  writing; but stability relates the amount to a state the entry does not
  record, and later balance or limit changes can destroy it while every
  ledger invariant still holds.  The lemmas closing the
  reservation-anomaly subsection record both halves on the walkthrough
  instance.
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

definition release_offer_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      party_state cxx_result"
  \<comment> \<open>C++: \<open>releaseLiabilities\<close> (\<open>TransactionUtils.cpp\<close>)\<close>
  where
    "release_offer_liabilities price_n price_d amount maker = do {
       buying \<leftarrow> offer_buying_liabilities price_n price_d amount;
       new_buying \<leftarrow> add_liability_checked
         (sint (buy_limit maker) - sint (buy_balance maker))
         (buy_liabilities maker) (- sint buying);
       selling \<leftarrow> offer_selling_liabilities price_n price_d amount;
       new_selling \<leftarrow> add_liability_checked (sint (sell_balance maker))
         (sell_liabilities maker) (- sint selling);
       Cxx_Ok (maker\<lparr>buy_liabilities := new_buying,
                     sell_liabilities := new_selling\<rparr>)
     }"

text \<open>
  Acquiring and releasing an offer's liabilities brackets every offer
  mutation (\<open>acquireLiabilities\<close> and \<open>releaseLiabilities\<close>,
  \<open>TransactionUtils.cpp\<close>).  Following the C++, the buying side is
  updated before the selling side, and a liability total that would leave
  its valid interval---from zero to the limit minus the balance on the
  buying side, from zero to the balance on the selling side---is the runtime
  error of the C++ helpers.
\<close>

subsection \<open>Posting an offer\<close>

text \<open>
  The pre-flight phase either rejects the requested offer or returns the two
  exchange limits computed for it.  The limits use the C++ names: the maker
  sells sheep and receives wheat in \<open>ManageOfferOpFrameBase\<close>; in this theory
  those assets are the resting offer's wheat and sheep, respectively.
\<close>

datatype offer_preflight_outcome =
    Preflight_Line_Full
  | Preflight_Underfunded
  | Preflight_Ready int64 int64

definition preflight_offer ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      offer_preflight_outcome cxx_result"
  \<comment> \<open>C++: \<open>ManageOfferOpFrameBase::computeOfferExchangeParameters\<close>
    (\<open>ManageOfferOpFrameBase.cpp\<close>)\<close>
  where
    "preflight_offer price_n price_d amount maker = do {
       buying \<leftarrow> offer_buying_liabilities price_n price_d amount;
       if sint (buy_limit maker) - sint (buy_balance maker) -
           sint (buy_liabilities maker) < sint buying
       then Cxx_Ok Preflight_Line_Full
       else do {
         selling \<leftarrow> offer_selling_liabilities price_n price_d amount;
         if sint (sell_balance maker) - sint (sell_liabilities maker) <
             sint selling
         then Cxx_Ok Preflight_Underfunded
         else
           (let max_sheep_send =
                  signed_min64 amount (can_sell_at_most maker);
                max_wheat_receive = can_buy_at_most maker
            in if max_wheat_receive = 0
               then Cxx_Ok Preflight_Line_Full
               else Cxx_Ok
                 (Preflight_Ready max_sheep_send max_wheat_receive))
       }
     }"

text \<open>
  @{const preflight_offer} models the protocol-10 pre-flight filtering for a
  \<open>ManageSellOffer\<close>.  It first performs the two unclamped tests in
  \<open>ManageOfferOpFrameBase::computeOfferExchangeParameters\<close>
  (\<open>ManageOfferOpFrameBase.cpp\<close>): the requested offer's buying
  liability must fit the available limit and its selling liability must fit
  the available balance.  It then applies the sell-offer-specific amount cap
  and models the immediate check in \<open>doApply\<close> that reports \<open>LINE_FULL\<close> when
  \<open>maxWheatReceive\<close> is zero.  This last check is distinct from adjustment: in
  particular, a positive request whose rounded buying liability is zero is
  rejected when the maker has no receive capacity, rather than succeeding
  without creating an offer.  Native-asset reserve bookkeeping, trustline
  authorization, and sponsorship remain abstracted away as described above.
\<close>

datatype post_outcome =
    Post_Malformed
  | Post_Line_Full
  | Post_Underfunded
  | Post_No_Offer
  | Post_Created int64 party_state

definition post_offer ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      exchange_options \<Rightarrow> post_outcome cxx_result"
  \<comment> \<open>C++: \<open>ManageOfferOpFrameBase::doApply\<close> (\<open>ManageOfferOpFrameBase.cpp\<close>)\<close>
  where
    "post_offer price_n price_d amount maker options =
      (if sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> sint amount \<le> 0
       then Cxx_Ok Post_Malformed
       else do {
         preflight \<leftarrow> preflight_offer price_n price_d amount maker;
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

definition post_buy_offer ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      party_state \<Rightarrow> post_outcome cxx_result"
  \<comment> \<open>C++: \<open>doApply\<close> for \<open>ManageBuyOfferOpFrame\<close>\<close>
  where
    "post_buy_offer ledger_version price_n price_d buy_amount maker =
      post_offer_core price_d price_n (0 < sint buy_amount)
        (manage_buy_buying_liabilities_at_version ledger_version price_n
           price_d buy_amount)
        (manage_buy_selling_liabilities_at_version ledger_version price_n
           price_d buy_amount)
        int64_max buy_amount maker
        (exchange_options_at_version ledger_version)"

text \<open>
  @{const preflight_offer_core} and @{const post_offer_core} factor the common
  no-crossing posting path.  They receive the request-specific liabilities
  and operation caps but always adjust and acquire liabilities at the
  canonical resting price.  @{const post_sell_offer} supplies the submitted
  sell amount as its send cap.  @{const post_buy_offer} swaps the submitted
  price, supplies the buy request's unlimited-send liabilities, and caps the
  receive side by the requested buy amount, exactly matching
  \<open>ManageBuyOfferOpFrame::applyOperationSpecificLimits\<close>.

  @{const post_buy_offer} takes a ledger version rather than an options record
  because it needs one for two distinct purposes, exactly as
  \<open>computeOfferExchangeParameters\<close> does: the version selects the exchange
  arithmetic, and it is also passed to
  \<open>ManageBuyOfferOpFrame::getOfferSellingLiabilities\<close> and
  \<open>getOfferBuyingLiabilities\<close>.  Those request-time liabilities really do
  move at the protocol boundary, so deriving them from a fixed configuration
  while adjusting with a versioned one would be unfaithful.
  @{const post_sell_offer} has no such obligation: its liabilities are the
  stored-offer projections, which are version-independent.

  The older @{const post_offer} remains the established ManageSell model.
  The refinement theorem below checks extensionally that the factored sell
  wrapper did not change any result, including malformed, ordinary rejection,
  no-offer, created-offer, or modeled C++ error outcomes.
\<close>

lemma signed_min64_int64_max_left [simp]:
  "signed_min64 int64_max value = value"
proof -
  have upper: "sint value \<le> int64_max_int"
    by (rule sint64_upper_bound)
  have recover:
      "(word_of_int (sint value) :: int64) = value"
    by (metis scast_eq scast_id)
  show ?thesis
  proof (cases "sint int64_max \<le> sint value")
    case True
    have "sint value = sint int64_max"
      using True upper by (simp add: int64_max_def)
    then have "value = int64_max"
      using recover by simp
    with True show ?thesis by (simp add: signed_min64_def)
  next
    case False
    then show ?thesis by (simp add: signed_min64_def)
  qed
qed

theorem post_sell_offer_eq_post_offer:
  "post_sell_offer price_n price_d amount maker options =
   post_offer price_n price_d amount maker options"
text \<open>
  Proof sketch: unfold both wrappers.  The common pre-flight specializes to
  the original liability calls and capacities; taking the signed minimum with
  @{const int64_max} is the identity.  Every following adjustment,
  acquisition, and outcome branch is consequently identical.
\<close>
proof -
  show ?thesis
    by (simp add: post_sell_offer_def post_offer_core_def
        preflight_offer_core_def post_offer_def preflight_offer_def Let_def)
qed

lemma post_offer_core_created_facts:
  assumes post:
    "post_offer_core price_n price_d request_valid buying_liability
       selling_liability max_send_cap max_receive_cap maker options =
     Cxx_Ok (Post_Created posted maker_after)"
  shows
    "0 < sint price_n"
    "0 < sint price_d"
    "request_valid"
    "0 < sint posted"
    "acquire_offer_liabilities price_n price_d posted maker =
       Cxx_Ok maker_after"
text \<open>
  Proof sketch: invert the only created branch of the common posting core.
  Reaching it excludes every malformed and ordinary pre-flight branch, the
  adjustment is positive, and the final bind is precisely liability
  acquisition for that adjusted canonical amount.
\<close>
proof -
  note post' = post[unfolded post_offer_core_def preflight_offer_core_def
    Let_def]
  have valid:
      "\<not> (sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or>
        \<not> request_valid)"
    using post'
    by (cases "sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or>
         \<not> request_valid") simp_all
  then show "0 < sint price_n" "0 < sint price_d" "request_valid"
    by auto
  obtain buying where buying: "buying_liability = Cxx_Ok buying"
    using post'
    by (cases buying_liability) (simp_all split: if_splits)
  obtain selling where selling: "selling_liability = Cxx_Ok selling"
    using post' buying
    by (cases selling_liability) (simp_all split: if_splits)
  let ?max_send =
    "signed_min64 max_send_cap (can_sell_at_most maker)"
  let ?max_receive =
    "if max_receive_cap = int64_max
     then can_buy_at_most maker
     else signed_min64 max_receive_cap (can_buy_at_most maker)"
  obtain adjusted where adjusted:
      "adjust_offer_with_options price_n price_d ?max_send ?max_receive options =
       Cxx_Ok adjusted"
    using post' buying selling
    by (cases "adjust_offer_with_options price_n price_d ?max_send ?max_receive options")
       (simp_all split: if_splits)
  obtain acquired where acquired:
      "acquire_offer_liabilities price_n price_d adjusted maker =
       Cxx_Ok acquired"
    using post' buying selling adjusted
    by (cases "acquire_offer_liabilities price_n price_d adjusted maker")
       (simp_all split: if_splits)
  show "0 < sint posted"
    using post' buying selling adjusted acquired
    by (simp split: if_splits)
  show "acquire_offer_liabilities price_n price_d posted maker =
      Cxx_Ok maker_after"
    using post' buying selling adjusted acquired
    by (simp split: if_splits)
qed

lemma post_offer_core_created_adjustment:
  assumes post:
    "post_offer_core price_n price_d request_valid buying_liability
       selling_liability max_send_cap max_receive_cap maker options =
     Cxx_Ok (Post_Created posted maker_after)"
  shows
    "adjust_offer_with_options price_n price_d
       (signed_min64 max_send_cap (can_sell_at_most maker))
       (if max_receive_cap = int64_max then can_buy_at_most maker
        else signed_min64 max_receive_cap (can_buy_at_most maker))
       options = Cxx_Ok posted"
text \<open>
  Proof sketch: invert the created branch of the common posting core once
  more, this time keeping the adjustment call itself rather than discarding
  it.  Reaching the created outcome forces the ready pre-flight branch, whose
  two capacities are exactly the send cap clipped by the maker's selling
  capacity and the receive cap clipped by the maker's buying capacity, with
  the unlimited receive cap left uncapped.  The adjusted amount returned there
  is the amount written to the book.

  Together with @{thm [source] post_offer_core_created_facts} this is the
  whole created-branch inversion: the two lemmas cover positivity, liability
  acquisition, and the adjustment that produced the posted amount, for both
  the ManageSell and the ManageBuy caps.
\<close>
proof -
  note post' = post[unfolded post_offer_core_def preflight_offer_core_def
    Let_def]
  obtain buying where buying: "buying_liability = Cxx_Ok buying"
    using post'
    by (cases buying_liability) (simp_all split: if_splits)
  obtain selling where selling: "selling_liability = Cxx_Ok selling"
    using post' buying
    by (cases selling_liability) (simp_all split: if_splits)
  let ?max_send =
    "signed_min64 max_send_cap (can_sell_at_most maker)"
  let ?max_receive =
    "if max_receive_cap = int64_max
     then can_buy_at_most maker
     else signed_min64 max_receive_cap (can_buy_at_most maker)"
  obtain adjusted where adjusted:
      "adjust_offer_with_options price_n price_d ?max_send ?max_receive options =
       Cxx_Ok adjusted"
    using post' buying selling
    by (cases "adjust_offer_with_options price_n price_d ?max_send ?max_receive options")
       (simp_all split: if_splits)
  obtain acquired where acquired:
      "acquire_offer_liabilities price_n price_d adjusted maker =
       Cxx_Ok acquired"
    using post' buying selling adjusted
    by (cases "acquire_offer_liabilities price_n price_d adjusted maker")
       (simp_all split: if_splits)
  have "adjusted = posted"
    using post' buying selling adjusted acquired
    by (simp split: if_splits)
  then show ?thesis
    using adjusted by simp
qed

text \<open>
  @{const post_offer} models a \<open>ManageSellOffer\<close> that creates a fresh offer
  crossing nothing on entry, so the requested offer goes straight into the
  book.  The operation is malformed unless the price components and the
  amount are positive (\<open>doCheckValid\<close>; a zero amount, an offer deletion in
  C++, is folded into @{const Post_Malformed} here).  It then delegates the
  liability and capacity filters to @{const preflight_offer}.  For a ready
  request, the amount actually written to the book is the returned selling
  limit clipped by @{const adjust_offer_with_options}
  (the \<open>adjustOffer\<close> call in \<open>doApply\<close>); an amount clipped to zero creates no
  offer; and a created offer reserves its liabilities.  The final
  @{typ exchange_options} argument carries the protocol choices that \<open>doApply\<close>
  passes to that \<open>adjustOffer\<close> call; the liability computations take no
  options, matching the C++ helpers.
\<close>

text \<open>
  In the comfortably funded walkthrough state, pre-flight preserves Alice's
  one-unit request and reports her receive capacity of two.
  Proof sketch: evaluate the liability checks and the two derived capacities.
\<close>

lemma preflight_offer_ready_example:
  "preflight_offer 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr> =
   Cxx_Ok (Preflight_Ready 1 2)"
  by eval

text \<open>
  At price one half, a one-unit request has zero rounded buying liability.
  The unclamped liability test therefore passes at zero headroom, but the
  following zero-\<open>maxWheatReceive\<close> filter reports line full; posting propagates
  that result instead of treating adjustment to zero as a successful no-offer.
  Proof sketch: unfold the executable pre-flight and posting definitions and
  evaluate both results.
\<close>

lemma preflight_zero_receive_capacity_is_line_full:
  "preflight_offer 1 2 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 0, buy_balance = 0, buy_liabilities = 0\<rparr> =
   Cxx_Ok Preflight_Line_Full"
  by eval

lemma post_zero_receive_capacity_is_line_full:
  "post_offer 1 2 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 0, buy_balance = 0, buy_liabilities = 0\<rparr>
     \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
   Cxx_Ok Post_Line_Full"
  by eval


subsection \<open>Crossing the posted offer\<close>

record cross_result_v10 =
  cross_wheat_received :: int64
  cross_sheep_send :: int64
  cross_wheat_stays :: bool
  cross_offer_amount :: int64
  cross_maker :: party_state
  cross_taker :: party_state

definition make_cross_result ::
    "int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow>
      party_state \<Rightarrow> cross_result_v10"
  where
    "make_cross_result wheat_received sheep_send wheat_stays remaining maker
        taker =
      \<lparr>cross_wheat_received = wheat_received,
       cross_sheep_send = sheep_send,
       cross_wheat_stays = wheat_stays,
       cross_offer_amount = remaining,
       cross_maker = maker,
       cross_taker = taker\<rparr>"

definition cross_offer_v10 ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow> party_state \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow>
      cross_result_v10 cxx_result"
  \<comment> \<open>C++: \<open>crossOfferV10\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "cross_offer_v10 price_n price_d offer_amount maker taker taker_amount
        rounding options =
      (let max_wheat_receive = can_buy_at_most taker;
           max_sheep_send = signed_min64 taker_amount (can_sell_at_most taker)
       in if sint max_wheat_receive \<le> 0 \<or> sint max_sheep_send \<le> 0
          then Cxx_Err Cxx_Assertion_Failed
          else do {
            maker_released \<leftarrow> release_offer_liabilities price_n price_d
              offer_amount maker;
            adjusted \<leftarrow> adjust_offer_with_options price_n price_d
              (signed_min64 offer_amount (can_sell_at_most maker_released))
              (can_buy_at_most maker_released) options;
            let max_wheat_send =
              signed_min64 adjusted (can_sell_at_most maker_released);
            let max_sheep_receive = can_buy_at_most maker_released;
            result \<leftarrow> exchange_v10_with_options price_n price_d max_wheat_send
              max_wheat_receive max_sheep_send max_sheep_receive rounding
              options;
            let wheat_received = num_wheat_received result;
            let sheep_send = num_sheep_send result;
            let wheat_stays = result_wheat_stays result;
            maker_credited \<leftarrow> party_receive_buy_asset maker_released
              sheep_send;
            maker_moved \<leftarrow> party_spend_sell_asset maker_credited
              wheat_received;
            taker_credited \<leftarrow> party_receive_buy_asset taker wheat_received;
            taker_after \<leftarrow> party_spend_sell_asset taker_credited sheep_send;
            if wheat_stays then do {
              adjusted_after \<leftarrow> adjust_offer_with_options price_n price_d
                (signed_min64 (adjusted - wheat_received)
                  (can_sell_at_most maker_moved))
                (can_buy_at_most maker_moved) options;
              if adjusted_after = 0
              then Cxx_Ok (make_cross_result wheat_received sheep_send
                wheat_stays 0 maker_moved taker_after)
              else do {
                maker_final \<leftarrow> acquire_offer_liabilities price_n price_d
                  adjusted_after maker_moved;
                Cxx_Ok (make_cross_result wheat_received sheep_send
                  wheat_stays adjusted_after maker_final taker_after)
              }
            } else
              Cxx_Ok (make_cross_result wheat_received sheep_send wheat_stays
                0 maker_moved taker_after)
          })"

text \<open>
  @{const cross_offer_v10} is the ledger bookkeeping of \<open>crossOfferV10\<close>
  (\<open>OfferExchange.cpp\<close>) around one call to @{const exchange_v10_with_options}, with
  the taker's limits derived from its party state the way
  \<open>ManageOfferOpFrameBase::computeOfferExchangeParameters\<close> derives them: the
  taker sends at most the smaller of its remaining operation amount
  @{term taker_amount} and its available sheep balance, and receives at most
  its available wheat limit.  The steps mirror the C++ order: assert the
  taker limits positive; release the resting offer's liabilities; apply the
  preventative @{const adjust_offer_with_options} that the C++ comment on the
  pre-exchange \<open>adjustOffer\<close> call claims ``should have no effect'';
  exchange; move
  the traded balances; and either erase the offer or shrink it, adjust it
  once more against the moved balances, and re-acquire liabilities for what
  remains.  The taker's balance updates, which the C++ performs in the
  operation frame after all crossings, are folded in here so that the result
  describes both parties.  The final @{typ exchange_options} argument carries
  the protocol choices: the C++ passes the exact-receive-cap choice to
  \<open>exchangeV10\<close> inside \<open>crossOfferV10\<close>, and the two bracketing adjustments
  derive the same choice from the ledger header in the ledger-level
  \<open>adjustOffer\<close> overload.
\<close>

subsection \<open>Executable offer lifecycle\<close>

datatype offer_request =
    Manage_Sell int32 int32 int64
  | Manage_Buy int32 int32 int64

fun request_canonical_price_n :: "offer_request \<Rightarrow> int32"
  where
    "request_canonical_price_n (Manage_Sell price_n price_d amount) = price_n"
  | "request_canonical_price_n (Manage_Buy price_n price_d buy_amount) = price_d"

fun request_canonical_price_d :: "offer_request \<Rightarrow> int32"
  where
    "request_canonical_price_d (Manage_Sell price_n price_d amount) = price_d"
  | "request_canonical_price_d (Manage_Buy price_n price_d buy_amount) = price_n"

fun post_offer_request ::
    "uint32 \<Rightarrow> offer_request \<Rightarrow> party_state \<Rightarrow>
      post_outcome cxx_result"
  where
    "post_offer_request ledger_version (Manage_Sell price_n price_d amount)
        maker =
       post_sell_offer price_n price_d amount maker
         (exchange_options_at_version ledger_version)"
  | "post_offer_request ledger_version (Manage_Buy price_n price_d buy_amount)
        maker =
       post_buy_offer ledger_version price_n price_d buy_amount maker"

definition maximum_capacity_taker :: party_state
  where
    "maximum_capacity_taker =
      \<lparr>sell_balance = int64_max, sell_liabilities = 0,
       buy_limit = int64_max, buy_balance = 0, buy_liabilities = 0\<rparr>"

record lifecycle_trace =
  lifecycle_request :: offer_request
  lifecycle_price_n :: int32
  lifecycle_price_d :: int32
  lifecycle_posted_amount :: int64
  lifecycle_maker_after_post :: party_state
  lifecycle_maker_after_limit :: party_state
  lifecycle_taker_before :: party_state
  lifecycle_cross_result :: cross_result_v10

record lifecycle_prefix =
  lifecycle_prefix_request :: offer_request
  lifecycle_prefix_price_n :: int32
  lifecycle_prefix_price_d :: int32
  lifecycle_prefix_posted_amount :: int64
  lifecycle_prefix_maker_after_post :: party_state
  lifecycle_prefix_maker_after_limit :: party_state
  lifecycle_prefix_taker_before :: party_state

datatype lifecycle_outcome =
    Post_Failed post_outcome
  | Post_Cxx_Error cxx_error
  | Limit_Change_Invalid lifecycle_prefix
  | Cross_Cxx_Error cxx_error lifecycle_prefix
  | Crossed lifecycle_trace

definition run_offer_lifecycle ::
    "uint32 \<Rightarrow> offer_request \<Rightarrow> party_state \<Rightarrow>
      int64 \<Rightarrow> lifecycle_outcome"
  where
    "run_offer_lifecycle ledger_version request maker_at_post new_buy_limit =
      (case post_offer_request ledger_version request maker_at_post of
           Cxx_Err error \<Rightarrow> Post_Cxx_Error error
         | Cxx_Ok post \<Rightarrow>
             (case post of
                Post_Created posted maker_after \<Rightarrow>
                  (let maker_at_cross =
                     maker_after\<lparr>buy_limit := new_buy_limit\<rparr>;
                       price_n = request_canonical_price_n request;
                       price_d = request_canonical_price_d request;
                       prefix =
                         \<lparr>lifecycle_prefix_request = request,
                          lifecycle_prefix_price_n = price_n,
                          lifecycle_prefix_price_d = price_d,
                          lifecycle_prefix_posted_amount = posted,
                          lifecycle_prefix_maker_after_post = maker_after,
                          lifecycle_prefix_maker_after_limit = maker_at_cross,
                          lifecycle_prefix_taker_before = maximum_capacity_taker\<rparr>
                   in if \<not> party_state_wf maker_at_cross
                      then Limit_Change_Invalid prefix
                      else
                        (case cross_offer_v10 price_n price_d posted
                            maker_at_cross maximum_capacity_taker int64_max
                            Exchange_Normal
                            (exchange_options_at_version ledger_version) of
                           Cxx_Err error \<Rightarrow> Cross_Cxx_Error error prefix
                         | Cxx_Ok crossed \<Rightarrow>
                             Crossed
                               \<lparr>lifecycle_request = request,
                                lifecycle_price_n = price_n,
                                lifecycle_price_d = price_d,
                                lifecycle_posted_amount = posted,
                                lifecycle_maker_after_post = maker_after,
                                lifecycle_maker_after_limit = maker_at_cross,
                                lifecycle_taker_before = maximum_capacity_taker,
                                lifecycle_cross_result = crossed\<rparr>))
              | failed \<Rightarrow> Post_Failed failed))"

text \<open>
  @{const run_offer_lifecycle} is the complete executable
  path in this phase.  The request retains its raw operation orientation;
  manage-buy swaps the price only in the posting wrapper and trace.  Overlay
  rejection, ordinary operation outcomes, a ledger-invalid limit change, and
  modeled C++ failures are distinct constructors.  A successful value embeds
  the actual @{typ cross_result_v10}, so its positive transfer and final
  balances are executable observations rather than a Boolean claim.

  The named taker has maximum signed capacity on both relevant sides.  The
  transaction-level C++ oracle materializes the same one-shot witness with a
  \<open>ManageBuyOffer\<close> that buys exactly the full posted wheat amount.  Its raw
  price is the canonical resting price, which the buy wrapper inverts into the
  reciprocal counteroffer price.  If the maker is taken, the exact-receive
  request is fully consumed and leaves no taker offer or liabilities, matching
  the abstract direct crossing.  A ceil-sized reciprocal \<open>ManageSellOffer\<close>
  is not equivalent: fractional prices can leave a one-unit taker offer after
  an otherwise successful crossing.  The abstract crossing call states the
  stronger maximum-capacity witness directly and therefore needs no redundant
  counter-price input.
\<close>

lemma maximum_capacity_taker_equations:
  "party_state_wf maximum_capacity_taker"
  "can_sell_at_most maximum_capacity_taker = int64_max"
  "can_buy_at_most maximum_capacity_taker = int64_max"
text \<open>
  Proof sketch: evaluate the record invariant and both capacity projections at
  zero liabilities and zero buying balance.
\<close>
  by (eval, eval, eval)

lemma legacy_sell_positive_crossing_example:
  "(case run_offer_lifecycle 28 (Manage_Sell 101 100 3)
       \<lparr>sell_balance = 3, sell_liabilities = 0,
        buy_limit = 4, buy_balance = 0, buy_liabilities = 0\<rparr> 3 of
      Crossed trace \<Rightarrow>
        0 < sint (cross_wheat_received (lifecycle_cross_result trace)) \<and>
        0 < sint (cross_sheep_send (lifecycle_cross_result trace))
    | _ \<Rightarrow> False)"
  by eval

lemma legacy_buy_positive_crossing_example:
  "(case run_offer_lifecycle 28 (Manage_Buy 100 101 4)
       \<lparr>sell_balance = 3, sell_liabilities = 0,
        buy_limit = 4, buy_balance = 0, buy_liabilities = 0\<rparr> 3 of
      Crossed trace \<Rightarrow>
        0 < sint (cross_wheat_received (lifecycle_cross_result trace)) \<and>
        0 < sint (cross_sheep_send (lifecycle_cross_result trace))
    | _ \<Rightarrow> False)"
  by eval

lemma post_offer_request_created_facts:
  assumes post:
      "post_offer_request ledger_version request maker =
       Cxx_Ok (Post_Created posted maker_after)"
  shows
    "0 < sint (request_canonical_price_n request)"
    "0 < sint (request_canonical_price_d request)"
    "0 < sint posted"
    "acquire_offer_liabilities (request_canonical_price_n request)
       (request_canonical_price_d request) posted maker = Cxx_Ok maker_after"
text \<open>
  Proof sketch: split on the raw request constructor and apply the common-core
  created-branch inversion theorem.  The buy case swaps the two raw price
  fields, exactly as the canonical price projections do.
\<close>
proof -
  have all_facts:
      "0 < sint (request_canonical_price_n request) \<and>
       0 < sint (request_canonical_price_d request) \<and>
       0 < sint posted \<and>
       acquire_offer_liabilities (request_canonical_price_n request)
         (request_canonical_price_d request) posted maker =
         Cxx_Ok maker_after"
  proof (cases request)
    case (Manage_Sell price_n price_d amount)
    note facts = post_offer_core_created_facts
      [OF post[unfolded Manage_Sell post_offer_request.simps
        post_sell_offer_def]]
    show ?thesis using facts Manage_Sell by simp
  next
    case (Manage_Buy price_n price_d buy_amount)
    note facts = post_offer_core_created_facts
      [OF post[unfolded Manage_Buy post_offer_request.simps
        post_buy_offer_def]]
    show ?thesis using facts Manage_Buy by simp
  qed
  show "0 < sint (request_canonical_price_n request)"
    "0 < sint (request_canonical_price_d request)"
    "0 < sint posted"
    "acquire_offer_liabilities (request_canonical_price_n request)
       (request_canonical_price_d request) posted maker = Cxx_Ok maker_after"
    using all_facts by blast+
qed

subsection \<open>The whole process\<close>

definition maker_covers_offer_liabilities ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow> bool"
  where
    "maker_covers_offer_liabilities price_n price_d offer_amount maker \<longleftrightarrow>
      (case (offer_selling_liabilities price_n price_d offer_amount,
             offer_buying_liabilities price_n price_d offer_amount) of
         (Cxx_Ok selling, Cxx_Ok buying) \<Rightarrow>
           sint selling \<le> sint (sell_liabilities maker) \<and>
           sint buying \<le> sint (buy_liabilities maker)
       | _ \<Rightarrow> False)"

definition post_then_cross ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow> party_state \<Rightarrow>
      party_state \<Rightarrow> int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow>
      (post_outcome \<times> cross_result_v10 option) cxx_result"
  where
    "post_then_cross price_n price_d amount maker_at_post maker_at_cross
        taker taker_amount rounding options = do {
       outcome \<leftarrow> post_offer price_n price_d amount maker_at_post
         options;
       (case outcome of
          Post_Created posted _ \<Rightarrow> do {
            crossed \<leftarrow> cross_offer_v10 price_n price_d posted maker_at_cross
              taker taker_amount rounding options;
            Cxx_Ok (outcome, Some crossed)
          }
        | _ \<Rightarrow> Cxx_Ok (outcome, None))
     }"

text \<open>
  @{const post_then_cross} chains the two steps.  The maker's state at the
  crossing step is a fresh parameter rather than the state returned by
  posting: between the two steps, third parties may move the maker's
  balances and limits.  @{const maker_covers_offer_liabilities} states the
  part of the ledger invariant that connects the two: whatever else changed,
  the maker's liability totals at crossing time still include the posted
  offer's own reservation.  A single @{typ exchange_options} value serves both
  steps: it models a post and a cross under the same protocol version, so an
  offer posted before a protocol upgrade and crossed after it is out of scope
  here.
  @{const maker_covers_offer_liabilities} needs no flag because the
  liability functions carry none.
\<close>


subsection \<open>Intended properties\<close>

text \<open>
  The principal properties below capture what the exchange lifecycle should
  guarantee.  The
  first assigns the rounding benefit to the offer that stays, and the second
  strengthens that direction guarantee to a maximal positive normal fill.  The
  third is local to the preventative adjustment at crossing time.  Several
  increasingly strong liveness properties say that a successfully posted
  offer has a positive crossing when its maker is unchanged, after any
  admissible change to only the maker's sheep limit, and finally after any
  admissible maker-state change when the exact receive cap is enabled.  This
  subsection only defines and explains the predicates; their supporting proofs
  and counterexamples appear in later top-level subsections.
\<close>

subsubsection \<open>Rounding favors the offer that stays\<close>

definition rounding_favors_offer_that_stays :: "exchange_options \<Rightarrow> bool"
  where
    "rounding_favors_offer_that_stays options \<longleftrightarrow>
      (\<forall>price_n price_d max_wheat_send max_wheat_receive max_sheep_send
         max_sheep_receive rounding result.
        exchange_v10_pre price_n price_d max_wheat_send max_wheat_receive
          max_sheep_send max_sheep_receive \<and>
        exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
          max_sheep_send max_sheep_receive rounding options =
            Cxx_Ok result \<and>
        0 < sint (num_wheat_received result) \<and>
        0 < sint (num_sheep_send result) \<longrightarrow>
        favored_seller_ok price_n price_d
          (num_wheat_received result) (num_sheep_send result)
          (result_wheat_stays result))"

text \<open>
  @{const rounding_favors_offer_that_stays} applies only to a successful
  positive exchange, because a zero exchange has no effective price or
  rounding beneficiary.  When the resting wheat offer stays, the predicate
  requires the effective price to favor its maker; when that offer is removed,
  it requires the effective price to favor the taker's sheep offer instead.
  Equivalently, it requires
  @{term "sint (num_wheat_received result) * sint price_n \<le>
    sint (num_sheep_send result) * sint price_d"} when
  @{term "result_wheat_stays result"}, and the reverse inequality otherwise.

  This property constrains the direction of rounding after the staying offer
  has been chosen; it does not itself specify how that choice is made.  The
  options argument is explicit so the shipped and exact-receive-cap paths can
  be verified separately.  Its proof is deferred to a later subsection.
\<close>



subsubsection \<open>Maximal positive normal crossing\<close>

definition canonical_favored_rounding ::
    "int32 \<Rightarrow> int32 \<Rightarrow> bool \<Rightarrow> int \<Rightarrow> int \<Rightarrow> bool"
  where
    "canonical_favored_rounding price_n price_d wheat_stays
        wheat_receive sheep_send \<longleftrightarrow>
      (if sint price_n > sint price_d
       then sheep_send =
         (if wheat_stays
          then (wheat_receive * sint price_n + sint price_d - 1)
            div sint price_d
          else wheat_receive * sint price_n div sint price_d)
       else wheat_receive =
         (if wheat_stays
          then sheep_send * sint price_d div sint price_n
          else (sheep_send * sint price_d + sint price_n - 1)
            div sint price_n))"

definition normal_favored_candidate ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> bool \<Rightarrow> int \<Rightarrow> int \<Rightarrow> bool"
  where
    "normal_favored_candidate price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive wheat_stays
        wheat_receive sheep_send \<longleftrightarrow>
      0 \<le> wheat_receive \<and>
      wheat_receive \<le>
        min (sint max_wheat_send) (sint max_wheat_receive) \<and>
      0 \<le> sheep_send \<and>
      sheep_send \<le>
        min (sint max_sheep_send) (sint max_sheep_receive) \<and>
      canonical_favored_rounding price_n price_d wheat_stays
        wheat_receive sheep_send \<and>
      (if sint price_n > sint price_d
       then wheat_receive * sint price_n \<le>
         sint int64_max * sint price_d
       else sheep_send * sint price_d \<le>
         sint int64_max * sint price_n)"

definition maximal_normal_favored_result ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_result_v10 \<Rightarrow> bool"
  where
    "maximal_normal_favored_result price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive result \<longleftrightarrow>
      normal_favored_candidate price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive
        (result_wheat_stays result)
        (sint (num_wheat_received result))
        (sint (num_sheep_send result)) \<and>
      (\<forall>wheat_receive sheep_send.
        normal_favored_candidate price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive
          (result_wheat_stays result) wheat_receive sheep_send \<longrightarrow>
        (if sint price_n > sint price_d
         then wheat_receive \<le> sint (num_wheat_received result)
         else sheep_send \<le> sint (num_sheep_send result)))"



definition positive_normal_crosses_are_maximal :: "exchange_options \<Rightarrow> bool"
  where
    "positive_normal_crosses_are_maximal options \<longleftrightarrow>
      (\<forall>price_n price_d max_wheat_send max_wheat_receive max_sheep_send
         max_sheep_receive result.
        exchange_v10_pre price_n price_d max_wheat_send max_wheat_receive
          max_sheep_send max_sheep_receive \<and>
        exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
          max_sheep_send max_sheep_receive Exchange_Normal
          options = Cxx_Ok result \<and>
        0 < sint (num_wheat_received result) \<and>
        0 < sint (num_sheep_send result) \<longrightarrow>
        maximal_normal_favored_result price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive result)"

text \<open>
  @{const canonical_favored_rounding} uses units of the more valuable asset as
  the primary measure of exchange size.  When wheat is more valuable, a wheat
  amount uniquely determines the sheep amount by rounding up if the wheat offer
  stays and down if the sheep offer stays.  When sheep is at least as valuable,
  the symmetric formulas derive wheat from a primary sheep amount.  These are
  the four normal-mode formulas that round by the least whole unit in favor of
  the offer marked as staying.

  @{const normal_favored_candidate} additionally requires both transferred
  amounts to lie within all four exchange caps.  Its final conjunct retains the
  implementation's saturation ceiling: even an exact receive cap does not
  admit a scaled value above what @{const int64_max} units of the other asset
  can represent.  @{const maximal_normal_favored_result} requires the returned
  pair itself to be such a candidate and says that no candidate has a larger
  primary amount.  Thus it maximizes wheat when wheat is more valuable and
  sheep otherwise, avoiding an arbitrary ordering between unlike assets.

  @{const positive_normal_crosses_are_maximal} lifts this specification to
  every successful positive normal exchange.  Zero results remain outside its
  scope because the current one-percent threshold may reject the initially
  selected pair without searching downward for a smaller positive pair.
  Strict-send and strict-receive need mode-specific objectives and are likewise
  outside this predicate.

  The model now carries two independently selectable receive-cap gates.  The
  @{const exact_receive_cap} field repairs the sheep-stays,
  wheat-more-valuable normal branch by applying
  @{const calculate_offer_value_with_exact_receive_cap} to the resting wheat
  offer's sheep-receive cap.  The @{const symmetric_exact_receive_cap} field
  repairs the mirror wheat-stays, sheep-more-valuable normal branch with the
  symmetric call
  @{term "calculate_offer_value_with_exact_receive_cap price_d price_n
    max_sheep_send max_wheat_receive"} before dividing the resulting value by
  @{term "sint price_d"}, treating the taker's wheat-receive cap as an exact
  unit cap.  Both repairs are implemented in \<open>OfferExchange.cpp\<close> behind their
  protocol gates and mirrored in @{const exchange_v10_amounts}, and neither
  changes the decision about which offer stays: \<open>wheatStays\<close> is still
  compared on the two unadjusted offer values.

  Without the symmetric gate the exact-receive-cap path does not satisfy the
  intended flag-on property.  For example, at the price with numerator
  @{term "(99 :: int)"} and denominator @{term "(100 :: int)"}, with
  wheat caps @{term "(102 :: int)"} and @{term "(101 :: int)"} and sheep caps
  @{term "(100 :: int)"} and @{term "(101 :: int)"}, it returns
  @{term "(100 :: int)"} wheat and @{term "(99 :: int)"} sheep with wheat
  staying.  The pair @{term "(101 :: int)"} wheat and @{term "(100 :: int)"}
  sheep is within every cap, uses the canonical favoring round, and is larger.
  With both gates enabled the same inputs produce that maximal
  @{term "(101 :: int)"}-wheat, @{term "(100 :: int)"}-sheep cross while
  \<open>wheatStays\<close> remains true.

  With both repairs enabled the property holds: the theorem
  \<open>positive_normal_crosses_are_maximal_repaired\<close>, proved in the maximality
  subsection below, establishes
  @{term "positive_normal_crosses_are_maximal
    \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"}.
\<close>

subsubsection \<open>Coverage implies adjustment stability\<close>

definition cover_implies_adjust_stable :: "exchange_options \<Rightarrow> bool"
  where
    "cover_implies_adjust_stable options \<longleftrightarrow>
      (\<forall>price_n price_d amount maker_at_post posted maker_after
         maker_at_cross released.
         party_state_wf maker_at_post \<and>
         party_state_wf maker_at_cross \<and>
         post_offer price_n price_d amount maker_at_post options =
           Cxx_Ok (Post_Created posted maker_after) \<and>
         maker_covers_offer_liabilities price_n price_d posted
           maker_at_cross \<and>
         release_offer_liabilities price_n price_d posted maker_at_cross =
           Cxx_Ok released \<longrightarrow>
         adjust_stable price_n price_d posted released options)"

text \<open>
  @{const cover_implies_adjust_stable} ranges only over amounts produced by a
  successful @{const post_offer}; this excludes arbitrary amounts that never
  entered the order book.  @{const maker_covers_offer_liabilities} then
  speaks about the maker's booked state at crossing time, in which the
  posted offer's selling and buying reservations are still present.
  Crossing first releases those reservations, so the property explicitly
  relates that booked state to the released state seen by
  @{const adjust_offer_with_options}.

  The intended implication says that every successfully posted offer, in
  every well-formed crossing state which still covers its liabilities, must
  remain stable after release.  If it holds, the preventative adjustment is
  the identity at every admissible crossing state: a balance or limit change
  that leaves the reservation covered cannot clip the offer.  The shipped
  behavior violates this property, as the reservation-anomaly walkthrough
  below demonstrates.
\<close>

subsubsection \<open>Takeability with an unchanged maker\<close>

definition unchanged_maker_offers_are_takeable :: "exchange_options \<Rightarrow> bool"
  where
    "unchanged_maker_offers_are_takeable options \<longleftrightarrow>
      (\<forall>price_n price_d amount maker_at_post posted maker_after.
        party_state_wf maker_at_post \<and>
        post_offer price_n price_d amount maker_at_post options =
          Cxx_Ok (Post_Created posted maker_after) \<longrightarrow>
        (\<exists>taker taker_amount crossed.
          party_state_wf taker \<and>
          0 < sint (can_buy_at_most taker) \<and>
          0 < sint
            (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
          cross_offer_v10 price_n price_d posted maker_after taker
            taker_amount Exchange_Normal options =
              Cxx_Ok crossed \<and>
          0 < sint (cross_wheat_received crossed) \<and>
          0 < sint (cross_sheep_send crossed)))"

text \<open>
  @{const unchanged_maker_offers_are_takeable} uses the state returned by
  successful posting directly as the maker state supplied to crossing.  It
  says that, for either exact-receive-cap setting, some well-formed normal-mode
  taker
  can cross the posted offer successfully and transfer strictly positive
  amounts of both assets.

  As with the changed-state property below, this is existential in the taker
  and does not promise a nonzero fill to every counterparty.  The
  unchanged-maker stability lemma proved below establishes only that the
  crossing-time adjustment is the identity; this property additionally states
  the positive end-to-end crossing result.  It is stated here without a proof.
\<close>

subsubsection \<open>Takeability after adjusting the maker's sheep limit\<close>

definition limit_adjustment_stable :: "exchange_options \<Rightarrow> bool"
  where
    "limit_adjustment_stable options \<longleftrightarrow>
      (\<forall>price_n price_d amount maker_at_post posted maker_after
         new_sheep_limit.
        party_state_wf maker_at_post \<and>
        post_offer price_n price_d amount maker_at_post options =
          Cxx_Ok (Post_Created posted maker_after) \<longrightarrow>
        (let maker_at_cross =
           maker_after\<lparr>buy_limit := new_sheep_limit\<rparr>
         in party_state_wf maker_at_cross \<longrightarrow>
           (\<exists>taker taker_amount crossed.
             party_state_wf taker \<and>
             0 < sint (can_buy_at_most taker) \<and>
             0 < sint
               (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
             cross_offer_v10 price_n price_d posted maker_at_cross taker
               taker_amount Exchange_Normal options =
                 Cxx_Ok crossed \<and>
             0 < sint (cross_wheat_received crossed) \<and>
             0 < sint (cross_sheep_send crossed))))"

text \<open>
  @{const limit_adjustment_stable} isolates changes to the maker's sheep
  trustline limit.  It starts with the booked maker state returned by a
  successful @{const post_offer}, changes only @{const buy_limit}, and requires
  every resulting well-formed state to retain some successful positive
  normal-mode crossing.  Thus no ledger-admissible sheep-limit adjustment may
  make the posted offer untakeable.

  Requiring @{const party_state_wf} after the update excludes limits below the
  maker's current sheep balance plus buying liabilities, which the ledger would
  not admit.  Every other field---including the offer's selling and buying
  liabilities---is held fixed.  As in the surrounding liveness properties,
  takeability is existential in the taker: the property does not promise a
  nonzero fill to every counterparty.
\<close>

definition offer_limit_adjustment_stable ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> bool"
  where
    "offer_limit_adjustment_stable price_n price_d amount \<longleftrightarrow>
      0 < sint price_n \<and>
      0 < sint price_d \<and>
      0 < sint amount \<and>
      adjust_offer_with_options price_n price_d amount int64_max
        \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok amount \<and>
      (\<exists>buying.
        offer_buying_liabilities price_n price_d amount = Cxx_Ok buying \<and>
        0 < sint buying \<and>
        (\<forall>max_sheep_receive.
          0 \<le> sint max_sheep_receive \<and>
          sint buying \<le> sint max_sheep_receive \<longrightarrow>
          (\<exists>adjusted.
            adjust_offer_with_options price_n price_d amount max_sheep_receive
              \<lparr>exact_receive_cap = False,
                symmetric_exact_receive_cap = False\<rparr> =
              Cxx_Ok adjusted \<and>
            0 < sint adjusted)))"

text \<open>
  @{const offer_limit_adjustment_stable} is the non-vacuous, offer-local
  stability notion used to state completeness of the maker-independent filter.
  It requires positive inputs and a positive buying liability, requires the
  unlimited receive cap to preserve the offered amount, and requires every
  nonnegative receive cap covering that liability to leave a strictly positive
  adjustment.

  This differs deliberately from @{const limit_adjustment_stable}, which is a
  global lifecycle property over all successfully posted offers and their maker
  states.  A direct per-offer converse cannot be stated using that global
  predicate.  The local notion also excludes malformed or unpostable offers
  that would otherwise satisfy a universally quantified stability condition
  vacuously.
\<close>

subsubsection \<open>Takeability after maker-state changes\<close>

definition posted_offers_remain_takeable :: "exchange_options \<Rightarrow> bool"
  where
    "posted_offers_remain_takeable options \<longleftrightarrow>
      (\<forall>price_n price_d amount maker_at_post posted maker_after
         maker_at_cross.
        party_state_wf maker_at_post \<and>
        party_state_wf maker_at_cross \<and>
        post_offer price_n price_d amount maker_at_post options =
          Cxx_Ok (Post_Created posted maker_after) \<and>
        maker_covers_offer_liabilities price_n price_d posted
          maker_at_cross \<longrightarrow>
        (\<exists>taker taker_amount crossed.
          party_state_wf taker \<and>
          0 < sint (can_buy_at_most taker) \<and>
          0 < sint
            (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
          cross_offer_v10 price_n price_d posted maker_at_cross taker
            taker_amount Exchange_Normal options =
              Cxx_Ok crossed \<and>
          0 < sint (cross_wheat_received crossed) \<and>
          0 < sint (cross_sheep_send crossed)))"

text \<open>
  @{const posted_offers_remain_takeable} is existential in the taker: it says
  that every successfully posted offer has some well-formed normal-mode
  counterparty for which crossing succeeds and transfers strictly positive
  amounts of both assets.  It does not say that every taker must receive a
  nonzero fill.

  The crossing-time maker state is universally quantified independently of the
  state returned by posting.  It may therefore reflect arbitrary intervening
  balance or limit changes, provided it remains well formed and still covers
  the posted offer's liabilities.  The successful fill may depend
  on the changed maker state; only existence and positivity are required.
  \<open>posted_offers_remain_takeable_exact\<close> below proves the property at the mixed
  record
  @{term "\<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"};
  the migration theory strengthens it to @{const repaired_exchange_options}
  and restates it through the protocol mapping as
  \<open>posted_offers_remain_takeable_repaired\<close> and
  \<open>posted_offers_remain_takeable_p29\<close>.
\<close>

subsubsection \<open>Exact amount when a posted offer is fully taken\<close>

definition fully_taken_posted_offer_exchanges_posted_amount ::
    "exchange_options \<Rightarrow> bool"
  where
    "fully_taken_posted_offer_exchanges_posted_amount options \<longleftrightarrow>
      (\<forall>price_n price_d amount maker_at_post posted maker_after
         maker_at_cross taker taker_amount rounding crossed.
        party_state_wf maker_at_post \<and>
        party_state_wf maker_at_cross \<and>
        post_offer price_n price_d amount maker_at_post options =
          Cxx_Ok (Post_Created posted maker_after) \<and>
        maker_covers_offer_liabilities price_n price_d posted
          maker_at_cross \<and>
        cross_offer_v10 price_n price_d posted maker_at_cross taker
          taker_amount rounding options = Cxx_Ok crossed \<and>
        \<not> cross_wheat_stays crossed \<longrightarrow>
        cross_wheat_received crossed = posted)"

text \<open>
  @{const fully_taken_posted_offer_exchanges_posted_amount} formalizes the
  resting-offer branch that \<open>crossOfferV10\<close> treats as fully taken.  The
  requested amount may have been clipped while posting, so the conclusion uses
  the actual @{term posted} amount returned by @{const post_offer}.  The maker
  state at crossing is independent of the state returned by posting and is
  constrained only by well-formedness and continued coverage of the posted
  liabilities.  The taker, its operation amount, and the rounding mode are all
  universally quantified; successful crossing supplies the operational
  admissibility checks needed for those otherwise arbitrary inputs.

  The premise @{term "\<not> cross_wheat_stays crossed"} is the branch condition
  that erases the resting offer and therefore also forces
  @{term "cross_offer_amount crossed = 0"}.  The converse is deliberately not
  used: when wheat nominally stays, the post-trade dust adjustment can still
  erase the remainder.  The exact receive cap is sufficient: the proof
  subsection establishes the property for either value of the symmetric cap,
  then packages the requested record with both flags true.  Its proof also
  explains why the final normal-mode threshold cannot turn this case into a
  zero trade: successful posting and liability coverage make the positive
  preventative adjustment replay exactly before the non-staying exchange.
  The legacy record with both flags false violates the property through the
  Alice-and-Carol reservation anomaly proved below.
\<close>

subsubsection \<open>Exact amount when an incoming offer is fully taken\<close>

definition fully_taken_incoming_offer_exchanges_incoming_amount ::
    "exchange_options \<Rightarrow> bool"
  where
    "fully_taken_incoming_offer_exchanges_incoming_amount options \<longleftrightarrow>
      (\<forall>price_n price_d resting_request maker_at_post posted maker_after
         maker_at_cross taker incoming_amount incoming_receive_cap rounding
         crossed.
        0 < sint price_n \<and>
        0 < sint price_d \<and>
        0 < sint incoming_amount \<and>
        party_state_wf maker_at_post \<and>
        party_state_wf maker_at_cross \<and>
        post_offer price_n price_d resting_request maker_at_post options =
          Cxx_Ok (Post_Created posted maker_after) \<and>
        maker_covers_offer_liabilities price_n price_d posted
          maker_at_cross \<and>
        party_state_wf taker \<and>
        preflight_offer price_d price_n incoming_amount taker =
          Cxx_Ok
            (Preflight_Ready incoming_amount incoming_receive_cap) \<and>
        cross_offer_v10 price_n price_d posted maker_at_cross taker
          incoming_amount rounding options = Cxx_Ok crossed \<and>
        cross_wheat_stays crossed \<longrightarrow>
        cross_sheep_send crossed = incoming_amount)"

text \<open>
  @{const fully_taken_incoming_offer_exchanges_incoming_amount} is the incoming
  sheep-selling mirror of the preceding resting-offer property.  A valid
  \<open>ManageSellOffer\<close> request is pre-flighted at the reciprocal price because
  the incoming party sells sheep and buys wheat.  Requiring
  @{term "preflight_offer price_d price_n incoming_amount taker =
    Cxx_Ok (Preflight_Ready incoming_amount incoming_receive_cap)"} does two
  important jobs: the ready send cap is the requested amount itself, rather
  than a request clipped by the taker's available balance, and the request's
  rounded buying liability has passed the taker's receive-headroom check.
  Thus @{term incoming_amount} is the actual operative sheep-send cap supplied
  to @{const cross_offer_v10}.

  The resting side has the same lifecycle premises as
  @{const fully_taken_posted_offer_exchanges_posted_amount}: a well-formed
  maker successfully posts an actual @{term posted} amount, and an arbitrary
  later well-formed maker state still covers that amount's liabilities.  The
  successful cross uses this actual posted amount rather than the raw resting
  request, so posting-time clipping cannot be mistaken for a later fill.

  The exposed flag @{term "cross_wheat_stays crossed"} is the crossing branch
  in which the resting wheat offer stays and the incoming sheep offer is the
  limiting side.  Nevertheless, the both-repairs claim is false even for a
  positive exact-price exchange: integer granularity can leave part of the
  incoming send cap too small to buy another whole unit of wheat while the
  true wheat-stays flag is preserved.  The counterexample at the end of this
  theory records that distinction explicitly within the full posting and
  crossing lifecycle.  It models the active incoming request before the
  caller makes any later decision about posting its leftover; unlike the
  resting side, its raw request has not already passed a stored-offer
  adjustment.
\<close>

subsection \<open>Proofs and counterexamples\<close>

subsubsection \<open>Rounding favors the offer that stays\<close>

text \<open>
  The rounding direction is enforced by the final price-error-threshold pass,
  independently of how the pre-threshold exchange amounts were calculated.
  Every successful threshold result is either the original result record or an
  explicit zero-amount record.  Consequently, a positive successful exchange
  must be the original record, and threshold success proves that its value
  inequality favors the offer marked as staying.  In particular, the exact
  receive cap may change the trade amount but cannot reverse this inequality.
\<close>

lemma successful_exchange_favors_offer_that_stays:
  assumes result:
    "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive rounding options =
        Cxx_Ok exchange_result"
    and positive:
      "0 < sint (num_wheat_received exchange_result) \<and>
       0 < sint (num_sheep_send exchange_result)"
  shows "favored_seller_ok price_n price_d
    (num_wheat_received exchange_result)
    (num_sheep_send exchange_result)
    (result_wheat_stays exchange_result)"
  text \<open>
    Proof sketch: expose the successful pre-threshold result and its subsequent
    threshold call.  The threshold result-choice theorem, together with the
    positive-output premise, rules out the zero record and identifies the
    returned record with the threshold input.  The threshold pass's
    favored-seller theorem then supplies the required inequality.
  \<close>
proof -
  obtain before_thresholds :: exchange_result_v10 where applied:
      "apply_price_error_thresholds price_n price_d
        (num_wheat_received before_thresholds)
        (num_sheep_send before_thresholds)
        (result_wheat_stays before_thresholds) rounding =
          Cxx_Ok exchange_result"
    using result
    unfolding exchange_v10_with_options_def
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
          max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
          rounding options")
       auto
  note choices = apply_price_error_thresholds_result_choices [OF applied]
  have result_record:
      "exchange_result =
        make_exchange_result
          (num_wheat_received before_thresholds)
          (num_sheep_send before_thresholds)
          (result_wheat_stays before_thresholds)"
    using choices positive
    by (auto simp add: make_exchange_result_def)
  have input_positive:
      "0 < sint (num_wheat_received before_thresholds) \<and>
       0 < sint (num_sheep_send before_thresholds)"
    using positive result_record
    by (simp add: make_exchange_result_def)
  note favored =
    apply_price_error_thresholds_positive_success_favored
      [OF input_positive applied]
  show ?thesis
    using favored unfolding result_record make_exchange_result_def by simp
qed

theorem rounding_favors_offer_that_stays_exact:
  "rounding_favors_offer_that_stays \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
  text \<open>
    The preceding result is flag-independent, so instantiating the intended
    property with the exact receive cap requires no additional arithmetic case.
  \<close>
  unfolding rounding_favors_offer_that_stays_def
  using successful_exchange_favors_offer_that_stays
  by blast

subsubsection \<open>Unchanged-maker adjustment stability\<close>

text \<open>
  The arithmetic fact needed here is that a positive amount returned by
  adjustment is a fixed point of the same adjustment and remains within its
  original selling cap.  At the lifecycle level, when the state presented at
  crossing is exactly the state returned by posting, releasing the offer's
  own liabilities reverses their acquisition and restores the maker's
  original capacities.  Successful posting and the unchanged-state premise
  actually make the explicit coverage premise conservative, but retaining it
  gives the lemma the same premise shape as the intended property.
\<close>

lemma adjust_offer_positive_idempotent_false:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d" and wheat_nonnegative: "0 \<le> sint max_wheat" and sheep_nonnegative: "0 \<le> sint max_sheep" and adjusted: "adjust_offer_with_options price_n price_d max_wheat max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =          Cxx_Ok result" and result_positive: "0 < sint result"
  shows "adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok result \<and> sint result \<le> sint max_wheat"
text \<open>
  Proof sketch: characterize both adjustments in unbounded integers.  A
  positive first result respects the send cap.  In the wheat-more branch it
  saturates the product used by the second adjustment; in the other branch,
  floor and ceiling inequalities show that the same sheep units are selected.
  The threshold inputs are therefore unchanged.
\<close>
proof -
  have pre: "exchange_v10_pre price_n price_d max_wheat int64_max int64_max        max_sheep"
    using pn pd wheat_nonnegative sheep_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
let ?amounts = "exchange_v10_amounts_int price_n price_d max_wheat int64_max        int64_max max_sheep Exchange_Normal"
  note exchange_char = exchange_v10_normal_characterization [OF pre]
  have result_word: "result = (word_of_int (fst ?amounts) :: int64)"
    using adjusted exchange_char result_positive
    by (auto simp: adjust_offer_with_options_def make_exchange_result_def Let_def split: if_splits)
  have result_condition: "0 < fst ?amounts \<and> 0 < snd ?amounts \<and>      price_error_bound_spec price_n price_d        (word_of_int (fst ?amounts)) (word_of_int (snd ?amounts)) False"
    using adjusted exchange_char result_positive
    by (auto simp: adjust_offer_with_options_def make_exchange_result_def Let_def split: if_splits)
let ?amounts' = "exchange_v10_amounts_int price_n price_d result int64_max        int64_max max_sheep Exchange_Normal"
  have pre': "exchange_v10_pre price_n price_d result int64_max int64_max max_sheep"
    using pn pd result_positive sheep_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  have result_sint: "sint result = fst ?amounts"
    using result_word exchange_v10_amounts_integer_characterization(2) [OF pre, of Exchange_Normal]
    by simp
  have result_nonnegative: "0 \<le> sint result" and result_le_wheat: "sint result \<le> sint max_wheat"
    using result_sint exchange_v10_amounts_int_bounds [OF pre refl]
    by simp_all
  have wheat_product_bounded: "sint max_wheat * sint price_n \<le> sint int64_max * sint price_n"
    using sint64_upper_bound[of max_wheat] less_imp_le[OF pn]
    by (simp add: int64_max_def mult_right_mono)
  have sheep_product_bounded: "sint max_sheep * sint price_d \<le> sint int64_max * sint price_d"
    using sint64_upper_bound[of max_sheep] less_imp_le[OF pd]
    by (simp add: int64_max_def mult_right_mono)
  have original_stays_false: "\<not> min (sint int64_max * sint price_d)           (sint int64_max * sint price_n) <        min (sint max_wheat * sint price_n)           (sint max_sheep * sint price_d)"
    using wheat_product_bounded sheep_product_bounded
    by (simp add: min_def split: if_splits)
  have result_product_bounded: "sint result * sint price_n \<le> sint int64_max * sint price_n"
    using result_le_wheat wheat_product_bounded less_imp_le[OF pn]
    by (meson mult_right_mono order_trans)
  have repeated_stays_false: "\<not> min (sint int64_max * sint price_d)           (sint int64_max * sint price_n) <        min (sint result * sint price_n)           (sint max_sheep * sint price_d)"
    using result_product_bounded sheep_product_bounded
    by (simp add: min_def split: if_splits)
  have amounts_fixed: "?amounts' = ?amounts"
proof (cases "sint price_n > sint price_d")
  case True
  have original_stays_false_named: "\<not> exchange_wheat_value_int price_n price_d max_wheat max_sheep >        exchange_sheep_value_int price_n price_d int64_max int64_max"
    using original_stays_false
    by (simp add: exchange_wheat_value_int_def exchange_sheep_value_int_def)
  have repeated_stays_false_named: "\<not> exchange_wheat_value_int price_n price_d result max_sheep >        exchange_sheep_value_int price_n price_d int64_max int64_max"
    using repeated_stays_false
    by (simp add: exchange_wheat_value_int_def exchange_sheep_value_int_def)
  have original_formula: "?amounts =       (exchange_wheat_value_int price_n price_d max_wheat max_sheep          div sint price_n,        (exchange_wheat_value_int price_n price_d max_wheat max_sheep           div sint price_n) * sint price_n div sint price_d)"
    unfolding exchange_v10_amounts_int_def
    using True original_stays_false_named
    by (simp add: Let_def)
  have repeated_formula: "?amounts' =       (exchange_wheat_value_int price_n price_d result max_sheep          div sint price_n,        (exchange_wheat_value_int price_n price_d result max_sheep           div sint price_n) * sint price_n div sint price_d)"
    unfolding exchange_v10_amounts_int_def
    using True repeated_stays_false_named
    by (simp add: Let_def)
  have result_formula: "sint result =        exchange_wheat_value_int price_n price_d max_wheat max_sheep          div sint price_n"
    using result_sint original_formula
    by simp
  have result_product_le_receive: "sint result * sint price_n \<le> sint max_sheep * sint price_d"
proof -
  have "sint result * sint price_n \<le>       exchange_wheat_value_int price_n price_d max_wheat max_sheep"
    unfolding result_formula
    using int_div_mult_le[OF pn] . also
  have "... \<le> sint max_sheep * sint price_d"
    by (simp add: exchange_wheat_value_int_def) finally
  show ?thesis .
qed
  have repeated_wheat_value: "exchange_wheat_value_int price_n price_d result max_sheep =        sint result * sint price_n"
    using result_product_le_receive
    by (simp add: exchange_wheat_value_int_def min_def)
  show ?thesis
    using original_formula repeated_formula repeated_wheat_value result_formula
    by simp
next
  case False
  have original_stays_false_named: "\<not> exchange_wheat_value_int price_n price_d max_wheat max_sheep >        exchange_sheep_value_int price_n price_d int64_max int64_max"
    using original_stays_false
    by (simp add: exchange_wheat_value_int_def exchange_sheep_value_int_def)
  have repeated_stays_false_named: "\<not> exchange_wheat_value_int price_n price_d result max_sheep >        exchange_sheep_value_int price_n price_d int64_max int64_max"
    using repeated_stays_false
    by (simp add: exchange_wheat_value_int_def exchange_sheep_value_int_def)
  have original_formula: "?amounts =       ((exchange_wheat_value_int price_n price_d max_wheat max_sheep           div sint price_d * sint price_d + sint price_n - 1)          div sint price_n,        exchange_wheat_value_int price_n price_d max_wheat max_sheep          div sint price_d)"
    unfolding exchange_v10_amounts_int_def
    using False original_stays_false_named
    by (simp add: Let_def)
  have repeated_formula: "?amounts' =       ((exchange_wheat_value_int price_n price_d result max_sheep           div sint price_d * sint price_d + sint price_n - 1)          div sint price_n,        exchange_wheat_value_int price_n price_d result max_sheep          div sint price_d)"
    unfolding exchange_v10_amounts_int_def
    using False repeated_stays_false_named
    by (simp add: Let_def)
  have result_formula: "sint result =       (exchange_wheat_value_int price_n price_d max_wheat max_sheep           div sint price_d * sint price_d + sint price_n - 1)         div sint price_n"
    using result_sint original_formula
    by simp
  have wheat_value_nonnegative: "0 \<le> exchange_wheat_value_int price_n price_d max_wheat max_sheep"
    using exchange_wheat_value_int_bounds [OF pre]
    by simp
  have sheep_units_nonnegative: "0 \<le> exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d"
    using wheat_value_nonnegative pd
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have repeated_product_lower: "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d * sint price_d \<le> sint result * sint price_n"
    unfolding result_formula
    using int_le_ceiling_div_mult [OF pn, of "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d * sint price_d"] .
  have repeated_product_upper: "sint result * sint price_n \<le>        exchange_wheat_value_int price_n price_d max_wheat max_sheep          div sint price_d * sint price_d + sint price_n - 1"
    unfolding result_formula
    using int_div_mult_le [OF pn, of "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d * sint price_d + sint price_n - 1"] .
  have sheep_cap_lower: "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d * sint price_d \<le> sint max_sheep * sint price_d"
proof -
  have "exchange_wheat_value_int price_n price_d max_wheat max_sheep       div sint price_d * sint price_d \<le>       exchange_wheat_value_int price_n price_d max_wheat max_sheep"
    using int_div_mult_le [OF pd] . also
  have "... \<le> sint max_sheep * sint price_d"
    by (simp add: exchange_wheat_value_int_def) finally
  show ?thesis .
qed
  have repeated_value_upper: "exchange_wheat_value_int price_n price_d result max_sheep <        exchange_wheat_value_int price_n price_d max_wheat max_sheep          div sint price_d * sint price_d + sint price_d"
proof -
  have "exchange_wheat_value_int price_n price_d result max_sheep \<le>       sint result * sint price_n"
    by (simp add: exchange_wheat_value_int_def) also
  have "... \<le>       exchange_wheat_value_int price_n price_d max_wheat max_sheep         div sint price_d * sint price_d + sint price_n - 1"
    using repeated_product_upper . also
  have "... <       exchange_wheat_value_int price_n price_d max_wheat max_sheep         div sint price_d * sint price_d + sint price_d"
    using False
    by linarith finally
  show ?thesis .
qed
  have repeated_value_lower: "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d * sint price_d \<le>      exchange_wheat_value_int price_n price_d result max_sheep"
proof -
  have "exchange_wheat_value_int price_n price_d max_wheat max_sheep       div sint price_d * sint price_d \<le>       min (sint result * sint price_n) (sint max_sheep * sint price_d)"
    using repeated_product_lower sheep_cap_lower
    by simp then
  show ?thesis
    by (simp only: exchange_wheat_value_int_def)
qed
  have repeated_units_lower: "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d \<le>      exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d"
proof -
  have "(exchange_wheat_value_int price_n price_d max_wheat max_sheep       div sint price_d * sint price_d) div sint price_d \<le>       exchange_wheat_value_int price_n price_d result max_sheep         div sint price_d"
    using zdiv_mono1 [OF repeated_value_lower pd] . then
  show ?thesis
    using pd
    by simp
qed
  have repeated_units_upper: "exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d \<le>      exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d"
proof (rule ccontr) assume not_bounded: "\<not> exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d \<le>      exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d"
  have next_unit: "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d + 1 \<le>      exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d"
    using zless_imp_add1_zle not_bounded
    by simp
  have next_multiple: "exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d * sint price_d + sint price_d \<le>      exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d * sint price_d"
    using mult_right_mono [OF next_unit less_imp_le[OF pd]]
    by (simp add: algebra_simps)
  have divided_lower: "exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d * sint price_d \<le>      exchange_wheat_value_int price_n price_d result max_sheep"
    using int_div_mult_le [OF pd] .
  show False
    using next_multiple divided_lower repeated_value_upper
    by (meson le_less_trans not_less)
qed
  have repeated_units: "exchange_wheat_value_int price_n price_d result max_sheep        div sint price_d =      exchange_wheat_value_int price_n price_d max_wheat max_sheep        div sint price_d"
    using repeated_units_lower repeated_units_upper
    by simp
  show ?thesis
    using original_formula repeated_formula repeated_units
    by simp
qed
  note repeated_exchange_char = exchange_v10_normal_characterization [OF pre']
  have stable:
"adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"

    using repeated_exchange_char amounts_fixed result_condition result_word

    by (simp add: adjust_offer_with_options_def make_exchange_result_def Let_def)
  show ?thesis
    using stable result_le_wheat
    by simp
qed

lemma exchange_v10_amounts_exact_irrelevant_if_not_wheat_more:
  assumes "\<not> sint price_n > sint price_d"
  shows "exchange_v10_amounts price_n price_d wheat_value sheep_value
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      wheat_stays rounding
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
    exchange_v10_amounts price_n price_d wheat_value sheep_value
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      wheat_stays rounding
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: when wheat is not the more valuable side, the exact-receive
  branch is not selected; unfolding the amount calculation makes the two
  flags identical.
\<close>
    using assms
    by (simp add: exchange_v10_amounts_def)

lemma exchange_v10_exact_irrelevant_if_not_wheat_more:
  assumes "\<not> sint price_n > sint price_d"
  shows "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive       max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =     exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive       max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: unfold the outer exchange composition and replace its amount
  calculation with the preceding equality.
\<close>
    using exchange_v10_amounts_exact_irrelevant_if_not_wheat_more [OF assms]
    unfolding exchange_v10_with_options_def exchange_v10_without_price_error_thresholds_with_options_def
    by (simp add: Let_def)

lemma adjust_offer_exact_irrelevant_if_not_wheat_more:
  assumes "\<not> sint price_n > sint price_d"
  shows "adjust_offer_with_options price_n price_d max_wheat max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =     adjust_offer_with_options price_n price_d max_wheat max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: unfold adjustment and apply the preceding exchange equality.
\<close>
    using exchange_v10_exact_irrelevant_if_not_wheat_more [OF assms]
    by (simp add: adjust_offer_with_options_def)

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

lemma adjust_offer_positive_idempotent_true_wheat_more:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d" and wheat_more: "sint price_n > sint price_d" and wheat_nonnegative: "0 \<le> sint max_wheat" and sheep_nonnegative: "0 \<le> sint max_sheep" and adjusted: "adjust_offer_with_options price_n price_d max_wheat max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =          Cxx_Ok result" and result_positive: "0 < sint result"
  shows "adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok result \<and> sint result \<le> sint max_wheat"
text \<open>
  Proof sketch: in the wheat-more exact-cap branch, divide the clamped trade
  value by the price numerator.  Reapplying adjustment to the positive
  quotient makes the send-side product the least cap, so both divisions and
  the price-threshold call repeat unchanged.  The runtime checks also yield
  the send bound.
\<close>
proof -
let ?trade = "min       (word_of_int (sint max_wheat * sint price_n) :: uint128)       (min         ((word_of_int (sint max_sheep * sint price_d) :: uint128) +           ucast (scast (price_d - 1) :: int64))         (word_of_int (sint int64_max * sint price_d) ::           uint128))"
  have trade: "calculate_offer_value_with_exact_receive_cap price_n price_d        max_wheat max_sheep = Cxx_Ok ?trade"
    using exact_value_word_characterization [OF pn pd wheat_nonnegative sheep_nonnegative] .
  have wheat_pre: "calculate_offer_value_pre price_n price_d max_wheat max_sheep"
    using pn pd wheat_nonnegative sheep_nonnegative
    by (simp add: calculate_offer_value_pre_def)
  have sheep_pre: "calculate_offer_value_pre price_d price_n int64_max int64_max"
    using pn pd
    by (simp add: calculate_offer_value_pre_def int64_max_def)
  obtain wheat_value where wheat_value: "calculate_offer_value price_n price_d max_wheat max_sheep =        Cxx_Ok wheat_value" "uint wheat_value =        min (sint max_wheat * sint price_n)          (sint max_sheep * sint price_d)"
    using calculate_offer_value_integer_characterization [OF wheat_pre] .
  obtain sheep_value where sheep_value: "calculate_offer_value price_d price_n int64_max int64_max =        Cxx_Ok sheep_value" "uint sheep_value =        min (sint int64_max * sint price_d)          (sint int64_max * sint price_n)"
    using calculate_offer_value_integer_characterization [OF sheep_pre] .
  have wheat_product_bounded: "sint max_wheat * sint price_n \<le> sint int64_max * sint price_n"
    using sint64_upper_bound[of max_wheat] less_imp_le[OF pn]
    by (simp add: int64_max_def mult_right_mono)
  have sheep_product_bounded: "sint max_sheep * sint price_d \<le> sint int64_max * sint price_d"
    using sint64_upper_bound[of max_sheep] less_imp_le[OF pd]
    by (simp add: int64_max_def mult_right_mono)
  have no_stays: "\<not> wheat_value > sheep_value"
    using wheat_value(2) sheep_value(2) wheat_product_bounded sheep_product_bounded
    by (simp add: word_less_def min_def split: if_splits)
  obtain wheat_receive where first_divide: "big_divide_or_throw128 ?trade (scast price_n) Cxx_Round_Down =        Cxx_Ok wheat_receive"
    using adjusted wheat_value(1) sheep_value(1) no_stays trade wheat_more
    by (cases "big_divide_or_throw128 ?trade (scast price_n)        Cxx_Round_Down") (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def exchange_v10_without_price_error_thresholds_with_options_def exchange_v10_amounts_def Let_def)
  obtain sheep_send where second_divide: "big_divide_or_throw wheat_receive (scast price_n) (scast price_d)        Cxx_Round_Down = Cxx_Ok sheep_send"
    using adjusted wheat_value(1) sheep_value(1) no_stays trade wheat_more first_divide
    by (cases "big_divide_or_throw wheat_receive (scast price_n)        (scast price_d) Cxx_Round_Down") (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def exchange_v10_without_price_error_thresholds_with_options_def exchange_v10_amounts_def Let_def)
  obtain final where threshold: "apply_price_error_thresholds price_n price_d wheat_receive sheep_send        False Exchange_Normal = Cxx_Ok final"
    using adjusted wheat_value(1) sheep_value(1) no_stays trade wheat_more first_divide second_divide
    by (cases "apply_price_error_thresholds price_n price_d wheat_receive        sheep_send False Exchange_Normal") (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def exchange_v10_without_price_error_thresholds_with_options_def exchange_v10_amounts_def make_exchange_result_def Let_def split: if_splits)
  have final_choice: "final = make_exchange_result wheat_receive sheep_send False \<or>      final = make_exchange_result 0 0 False"
    using apply_price_error_thresholds_normal_result [OF threshold] .
  have result_final: "result = num_wheat_received final"
    using adjusted wheat_value(1) sheep_value(1) no_stays trade wheat_more first_divide second_divide threshold
    by (simp add: adjust_offer_with_options_def exchange_v10_with_options_def exchange_v10_without_price_error_thresholds_with_options_def exchange_v10_amounts_def make_exchange_result_def Let_def split: if_splits)
  have result_wheat: "result = wheat_receive"
    using result_final final_choice result_positive
    by (auto simp: make_exchange_result_def)
  have wheat_receive_nonnegative: "0 \<le> sint wheat_receive" and wheat_receive_check: "\<not> min (sint int64_max) (sint max_wheat) < sint wheat_receive" and sheep_send_nonnegative: "0 \<le> sint sheep_send" and sheep_send_check: "\<not> min (sint max_sheep) (sint int64_max) < sint sheep_send"
    using adjusted wheat_value(1) sheep_value(1) no_stays trade wheat_more first_divide second_divide threshold
    by (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def exchange_v10_without_price_error_thresholds_with_options_def exchange_v10_amounts_def make_exchange_result_def Let_def split: if_splits)
  have wheat_receive_bounded: "sint wheat_receive \<le> sint max_wheat" and sheep_send_bounded: "sint sheep_send \<le> sint max_sheep"
    using wheat_receive_check sheep_send_check
    by simp_all
  have result_div: "result = word_of_int (uint ?trade div sint price_n)"
    using first_divide result_wheat
    unfolding big_divide_or_throw128_success_iff
    by simp
  have quotient_bounded: "uint ?trade div sint price_n \<le> int64_max_int"
    using first_divide
    unfolding big_divide_or_throw128_success_iff
    by simp
  have quotient_nonnegative: "0 \<le> uint ?trade div sint price_n"
    using pn
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have result_sint: "sint result = uint ?trade div sint price_n"
    unfolding result_div
    using sint_word_of_int_nonnegative_int64 [OF quotient_nonnegative quotient_bounded] .
  have result_product_le_trade: "sint result * sint price_n \<le> uint ?trade"
    unfolding result_sint
    using int_div_mult_le [OF pn, of "uint ?trade"] .
  have result_product_uint: "uint (word_of_int (sint result * sint price_n) :: uint128) =        sint result * sint price_n"
    using big_multiply_uint_value [of result "scast price_n :: int64"] less_imp_le[OF result_positive] less_imp_le[OF pn]
    by simp
  have result_product_le_trade_word: "(word_of_int (sint result * sint price_n) :: uint128) \<le> ?trade"
    using result_product_le_trade result_product_uint
    by (simp add: word_le_def)
  have result_product_le_receive_value: "(word_of_int (sint result * sint price_n) :: uint128) \<le>       (word_of_int (sint max_sheep * sint price_d) :: uint128) +         ucast (scast (price_d - 1) :: int64)"
    using result_product_le_trade_word
    by (meson min.cobounded2 min.cobounded1 order_trans)
  have result_product_le_receive_cap: "(word_of_int (sint result * sint price_n) :: uint128) \<le>       (word_of_int (sint int64_max * sint price_d) :: uint128)"
    using result_product_le_trade_word
    by (meson min.cobounded2 order_trans)
  have repeated_trade: "calculate_offer_value_with_exact_receive_cap price_n price_d        result max_sheep =      Cxx_Ok        (word_of_int (sint result * sint price_n) :: uint128)"
    using exact_value_word_characterization [OF pn pd less_imp_le[OF result_positive] sheep_nonnegative] result_product_le_receive_value result_product_le_receive_cap
    by (simp add: min_def)
  have repeated_wheat_pre: "calculate_offer_value_pre price_n price_d result max_sheep"
    using pn pd result_positive sheep_nonnegative
    by (simp add: calculate_offer_value_pre_def)
  obtain repeated_wheat_value where repeated_wheat_value: "calculate_offer_value price_n price_d result max_sheep =        Cxx_Ok repeated_wheat_value" "uint repeated_wheat_value =        min (sint result * sint price_n)          (sint max_sheep * sint price_d)"
    using calculate_offer_value_integer_characterization [OF repeated_wheat_pre] .
  have result_product_bounded: "sint result * sint price_n \<le> sint int64_max * sint price_n"
    using result_wheat wheat_receive_bounded wheat_product_bounded less_imp_le[OF pn]
    by (meson mult_right_mono order_trans)
  have repeated_no_stays: "\<not> repeated_wheat_value > sheep_value"
    using repeated_wheat_value(2) sheep_value(2) result_product_bounded sheep_product_bounded
    by (simp add: word_less_def min_def split: if_splits)
  have repeated_first_divide: "big_divide_or_throw128        (word_of_int (sint result * sint price_n) :: uint128)        (scast price_n) Cxx_Round_Down = Cxx_Ok result"
    unfolding big_divide_or_throw128_success_iff
    using pn result_product_uint result_positive sint64_upper_bound[of result]
    by simp
  have repeated_second_divide: "big_divide_or_throw result (scast price_n) (scast price_d)        Cxx_Round_Down = Cxx_Ok sheep_send"
    using second_divide result_wheat
    by simp
  have repeated_threshold: "apply_price_error_thresholds price_n price_d result sheep_send        False Exchange_Normal = Cxx_Ok final"
    using threshold result_wheat
    by simp
  have result_check: "\<not> sint result < 0 \<and>      \<not> min (sint int64_max) (sint result) < sint result"
    using result_positive sint64_upper_bound[of result]
    by (simp add: int64_max_def)
  have sheep_check_repeated: "\<not> sint sheep_send < 0 \<and>      \<not> min (sint max_sheep) (sint int64_max) < sint sheep_send"
    using sheep_send_nonnegative sheep_send_bounded sint64_upper_bound[of sheep_send]
    by (simp add: int64_max_def)
  have stable:
"adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"

    using repeated_wheat_value(1) sheep_value(1) repeated_no_stays
repeated_trade wheat_more repeated_first_divide repeated_second_divide
repeated_threshold result_final result_check sheep_check_repeated

    by (simp add: adjust_offer_with_options_def exchange_v10_with_options_def
exchange_v10_without_price_error_thresholds_with_options_def
exchange_v10_amounts_def make_exchange_result_def Let_def)
  show ?thesis

    using stable result_wheat wheat_receive_bounded
    by simp
qed

lemma exchange_v10_amounts_symmetric_irrelevant_if_not_wheat_stays:
  "exchange_v10_amounts price_n price_d wheat_value sheep_value
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr> =
    exchange_v10_amounts price_n price_d wheat_value sheep_value
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: when the sheep offer stays, the only branch that consults an
  option field is the wheat-more-valuable one, and it reads
  @{const exact_receive_cap}; unfolding the amount calculation makes the two
  symmetric settings identical.
\<close>
  by (simp add: exchange_v10_amounts_def)

lemma adjust_offer_symmetric_irrelevant:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and wheat_nonnegative: "0 \<le> sint max_wheat"
    and sheep_nonnegative: "0 \<le> sint max_sheep"
  shows "adjust_offer_with_options price_n price_d max_wheat max_sheep
      \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr> =
    adjust_offer_with_options price_n price_d max_wheat max_sheep
      \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: adjustment crosses against an unlimited counteroffer, whose
  sheep value is at least any well-formed wheat value, so the wheat offer
  never stays and the wheat-stays branch guarded by the symmetric field is
  unreachable.
\<close>
proof -
  have wheat_pre:
      "calculate_offer_value_pre price_n price_d max_wheat max_sheep"
    using pn pd wheat_nonnegative sheep_nonnegative
    by (simp add: calculate_offer_value_pre_def)
  have sheep_pre:
      "calculate_offer_value_pre price_d price_n int64_max int64_max"
    using pn pd by (simp add: calculate_offer_value_pre_def int64_max_def)
  obtain wheat_value where wheat_value:
      "calculate_offer_value price_n price_d max_wheat max_sheep =
        Cxx_Ok wheat_value"
    and wheat_value_uint:
      "uint wheat_value =
        min (sint max_wheat * sint price_n) (sint max_sheep * sint price_d)"
    using calculate_offer_value_integer_characterization [OF wheat_pre] .
  obtain sheep_value where sheep_value:
      "calculate_offer_value price_d price_n int64_max int64_max =
        Cxx_Ok sheep_value"
    and sheep_value_uint:
      "uint sheep_value =
        min (sint int64_max * sint price_d) (sint int64_max * sint price_n)"
    using calculate_offer_value_integer_characterization [OF sheep_pre] .
  have wheat_product_bounded:
      "sint max_wheat * sint price_n \<le> sint int64_max * sint price_n"
    using sint64_upper_bound[of max_wheat] less_imp_le[OF pn]
    by (simp add: int64_max_def mult_right_mono)
  have sheep_product_bounded:
      "sint max_sheep * sint price_d \<le> sint int64_max * sint price_d"
    using sint64_upper_bound[of max_sheep] less_imp_le[OF pd]
    by (simp add: int64_max_def mult_right_mono)
  have no_stays: "(wheat_value > sheep_value) = False"
    using wheat_value_uint sheep_value_uint wheat_product_bounded
      sheep_product_bounded
    by (simp add: word_less_def min_def split: if_splits)
  have amounts_eq:
      "exchange_v10_amounts price_n price_d wheat_value sheep_value
         max_wheat int64_max int64_max max_sheep False Exchange_Normal
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr> =
       exchange_v10_amounts price_n price_d wheat_value sheep_value
         max_wheat int64_max int64_max max_sheep False Exchange_Normal
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr>"
    using exchange_v10_amounts_symmetric_irrelevant_if_not_wheat_stays .
  show ?thesis
    unfolding adjust_offer_with_options_def exchange_v10_with_options_def
      exchange_v10_without_price_error_thresholds_with_options_def
    by (simp add: wheat_value sheep_value Let_def no_stays amounts_eq)
qed

lemma adjust_offer_positive_idempotent:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_nonnegative: "0 \<le> sint max_wheat"
    and sheep_nonnegative: "0 \<le> sint max_sheep"
    and adjusted:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep options =
        Cxx_Ok result"
    and result_positive: "0 < sint result"
  shows
    "adjust_offer_with_options price_n price_d result max_sheep options =
       Cxx_Ok result \<and>
     sint result \<le> sint max_wheat"
text \<open>
  Proof sketch: adjustment never reaches the wheat-stays branch, so the
  symmetric field is first normalized to @{term False}.  Then split on the
  exact flag and the relative prices: the plain branch uses its fixed-point
  lemma, and the exact branch either uses the wheat-more lemma or reduces to
  the plain calculation.
\<close>
proof -
  obtain cap sym_cap where options_eq:
      "options = \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr>"
    by (cases options) auto
  have result_nonnegative: "0 \<le> sint result"
    using result_positive by simp
  have adjusted_plain:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr> =
        Cxx_Ok result"
    using adjusted
      adjust_offer_symmetric_irrelevant
        [OF pn pd wheat_nonnegative sheep_nonnegative, of cap sym_cap]
    unfolding options_eq by simp
  have plain_fixed:
      "adjust_offer_with_options price_n price_d result max_sheep
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr> =
        Cxx_Ok result \<and>
       sint result \<le> sint max_wheat"
  proof (cases cap)
    case False
    then show ?thesis
      using adjust_offer_positive_idempotent_false
        [OF pn pd wheat_nonnegative sheep_nonnegative _ result_positive]
        adjusted_plain
      by simp
  next
    case exact: True
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case wheat_more: True
      then show ?thesis
        using adjust_offer_positive_idempotent_true_wheat_more
          [OF pn pd _ wheat_nonnegative sheep_nonnegative _ result_positive]
          adjusted_plain exact
        by simp
    next
      case not_wheat_more: False
      have adjusted_false:
        "adjust_offer_with_options price_n price_d max_wheat max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok result"
        using adjusted_plain exact
          adjust_offer_exact_irrelevant_if_not_wheat_more
            [OF not_wheat_more, of max_wheat max_sheep]
        by simp
      have fixed_false:
        "adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
           Cxx_Ok result \<and>
         sint result \<le> sint max_wheat"
        using adjust_offer_positive_idempotent_false
          [OF pn pd wheat_nonnegative sheep_nonnegative adjusted_false
            result_positive] .
      show ?thesis
        using fixed_false exact
          adjust_offer_exact_irrelevant_if_not_wheat_more
            [OF not_wheat_more, of result max_sheep]
        by simp
    qed
  qed
  show ?thesis
    using plain_fixed
      adjust_offer_symmetric_irrelevant
        [OF pn pd result_nonnegative sheep_nonnegative, of cap sym_cap]
    unfolding options_eq
    by simp
qed

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

lemma unchanged_maker_cover_implies_adjust_stable:
  assumes post_wf: "party_state_wf maker_at_post"
    and cross_wf: "party_state_wf maker_at_cross"
    and post:
      "post_offer price_n price_d amount maker_at_post options =
        Cxx_Ok (Post_Created posted maker_after)"
    and unchanged: "maker_at_cross = maker_after"
    and cover:
      "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    and release:
      "release_offer_liabilities price_n price_d posted maker_at_cross =
        Cxx_Ok released"
  shows "adjust_stable price_n price_d posted released options"
text \<open>
  Proof sketch: a successful post supplies positive prices and a positive
  adjusted amount.  The fixed-point result above shows that this amount
  remains unchanged when adjusted against the original capacities.  Posting
  acquires the offer's liabilities; because the maker state at crossing is
  exactly the returned post state, releasing those liabilities reverses the
  checked additions and restores the original state.  The crossing-time
  adjustment is consequently the same fixed-point calculation.
\<close>
proof -
  note post' = post[unfolded post_offer_def preflight_offer_def Let_def]
  have valid:
      "\<not> (sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> sint amount \<le> 0)"
    using post'
    by (cases "sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> sint amount \<le> 0")
       simp_all
  have pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    using valid by auto
  obtain buying where buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    using post'
    by (cases "offer_buying_liabilities price_n price_d amount")
       (simp_all split: if_splits)
  obtain selling where selling:
      "offer_selling_liabilities price_n price_d amount = Cxx_Ok selling"
    using post' buying
    by (cases "offer_selling_liabilities price_n price_d amount")
       (simp_all split: if_splits)
  obtain adjusted where adjusted:
      "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) options =
         Cxx_Ok adjusted"
    using post' buying selling
    by (cases "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) options")
       (simp_all split: if_splits)
  obtain acquired where acquire:
      "acquire_offer_liabilities price_n price_d adjusted maker_at_post =
         Cxx_Ok acquired"
    using post' buying selling adjusted
    by (cases
         "acquire_offer_liabilities price_n price_d adjusted maker_at_post")
       (simp_all split: if_splits)
  have adjusted_posted: "adjusted = posted"
    and acquired_after: "acquired = maker_after"
    and adjusted_positive: "0 < sint adjusted"
    using post' buying selling adjusted acquire
    by (simp_all split: if_splits)
  have adjusted_as_posted:
      "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) options =
         Cxx_Ok posted"
    using adjusted adjusted_posted by simp
  have posted_positive: "0 < sint posted"
    using adjusted_positive adjusted_posted by simp
  have sell_capacity_nonnegative:
      "0 \<le> sint (can_sell_at_most maker_at_post)"
    using can_sell_at_most_nonnegative [OF post_wf] .
  have buy_capacity_nonnegative:
      "0 \<le> sint (can_buy_at_most maker_at_post)"
    using can_buy_at_most_nonnegative [OF post_wf] .
  have requested_cap_nonnegative:
      "0 \<le> sint
        (signed_min64 amount (can_sell_at_most maker_at_post))"
    using amount_positive sell_capacity_nonnegative
    by (simp add: signed_min64_def)
  have fixed_and_bounded:
      "adjust_offer_with_options price_n price_d posted
         (can_buy_at_most maker_at_post) options =
         Cxx_Ok posted \<and>
       sint posted \<le> sint
         (signed_min64 amount (can_sell_at_most maker_at_post))"
    using adjust_offer_positive_idempotent
      [OF pn pd requested_cap_nonnegative buy_capacity_nonnegative
        adjusted_as_posted posted_positive] .
  have posted_le_sell_capacity:
      "sint posted \<le> sint (can_sell_at_most maker_at_post)"
    using fixed_and_bounded
    by (simp add: signed_min64_def split: if_splits)
  have posted_min_capacity:
      "signed_min64 posted (can_sell_at_most maker_at_post) = posted"
    using posted_le_sell_capacity
    by (simp add: signed_min64_def)
  have acquire_posted:
      "acquire_offer_liabilities price_n price_d posted maker_at_post =
         Cxx_Ok maker_after"
    using acquire adjusted_posted acquired_after by simp
  note acquire' =
    acquire_posted[unfolded acquire_offer_liabilities_def]
  obtain posted_buying where posted_buying:
      "offer_buying_liabilities price_n price_d posted =
         Cxx_Ok posted_buying"
    using acquire'
    by (cases "offer_buying_liabilities price_n price_d posted") simp_all
  obtain new_buying where add_buying:
      "add_liability_checked
         (sint (buy_limit maker_at_post) - sint (buy_balance maker_at_post))
         (buy_liabilities maker_at_post) (sint posted_buying) =
         Cxx_Ok new_buying"
    using acquire' posted_buying
    by (cases "add_liability_checked
         (sint (buy_limit maker_at_post) - sint (buy_balance maker_at_post))
         (buy_liabilities maker_at_post) (sint posted_buying)")
       simp_all
  obtain posted_selling where posted_selling:
      "offer_selling_liabilities price_n price_d posted =
         Cxx_Ok posted_selling"
    using acquire' posted_buying add_buying
    by (cases "offer_selling_liabilities price_n price_d posted") simp_all
  obtain new_selling where add_selling:
      "add_liability_checked (sint (sell_balance maker_at_post))
         (sell_liabilities maker_at_post) (sint posted_selling) =
         Cxx_Ok new_selling"
    using acquire' posted_buying add_buying posted_selling
    by (cases "add_liability_checked (sint (sell_balance maker_at_post))
         (sell_liabilities maker_at_post) (sint posted_selling)")
       simp_all
  have maker_after_eq:
      "maker_after =
         maker_at_post\<lparr>buy_liabilities := new_buying,
                       sell_liabilities := new_selling\<rparr>"
    using acquire' posted_buying add_buying posted_selling add_selling
    by simp
  have add_buying_condition:
      "\<not> (sint (buy_liabilities maker_at_post) + sint posted_buying < 0 \<or>
          sint (buy_limit maker_at_post) - sint (buy_balance maker_at_post) <
            sint (buy_liabilities maker_at_post) + sint posted_buying)"
    using add_buying
    by (auto simp: add_liability_checked_def split: if_splits)
  have new_buying_eq:
      "new_buying = word_of_int
         (sint (buy_liabilities maker_at_post) + sint posted_buying)"
    using add_buying add_buying_condition
    by (simp add: add_liability_checked_def)
  have add_selling_condition:
      "\<not> (sint (sell_liabilities maker_at_post) + sint posted_selling < 0 \<or>
          sint (sell_balance maker_at_post) <
            sint (sell_liabilities maker_at_post) + sint posted_selling)"
    using add_selling
    by (auto simp: add_liability_checked_def split: if_splits)
  have new_selling_eq:
      "new_selling = word_of_int
         (sint (sell_liabilities maker_at_post) + sint posted_selling)"
    using add_selling add_selling_condition
    by (simp add: add_liability_checked_def)
  have sell_liabilities_nonnegative:
      "0 \<le> sint (sell_liabilities maker_at_post)"
    and sell_liabilities_bounded:
      "sint (sell_liabilities maker_at_post) \<le>
         sint (sell_balance maker_at_post)"
    and buy_balance_nonnegative:
      "0 \<le> sint (buy_balance maker_at_post)"
    and buy_liabilities_nonnegative:
      "0 \<le> sint (buy_liabilities maker_at_post)"
    and buy_liabilities_bounded:
      "sint (buy_liabilities maker_at_post) \<le>
         sint (buy_limit maker_at_post) - sint (buy_balance maker_at_post)"
    using post_wf
    by (simp_all add: party_state_wf_def)
  have buying_sum_nonnegative:
      "0 \<le> sint (buy_liabilities maker_at_post) + sint posted_buying"
    and buying_sum_bounded:
      "sint (buy_liabilities maker_at_post) + sint posted_buying \<le>
         sint (buy_limit maker_at_post) - sint (buy_balance maker_at_post)"
    using add_buying_condition by simp_all
  have selling_sum_nonnegative:
      "0 \<le> sint (sell_liabilities maker_at_post) + sint posted_selling"
    and selling_sum_bounded:
      "sint (sell_liabilities maker_at_post) + sint posted_selling \<le>
         sint (sell_balance maker_at_post)"
    using add_selling_condition by simp_all
  have buying_sum_max:
      "sint (buy_liabilities maker_at_post) + sint posted_buying \<le>
         int64_max_int"
    using buying_sum_bounded buy_balance_nonnegative
      sint64_upper_bound[of "buy_limit maker_at_post"]
    by linarith
  have selling_sum_max:
      "sint (sell_liabilities maker_at_post) + sint posted_selling \<le>
         int64_max_int"
    using selling_sum_bounded
      sint64_upper_bound[of "sell_balance maker_at_post"]
    by linarith
  have new_buying_sint:
      "sint new_buying =
         sint (buy_liabilities maker_at_post) + sint posted_buying"
    unfolding new_buying_eq
    using sint_word_of_int_nonnegative_int64
      [OF buying_sum_nonnegative buying_sum_max] .
  have new_selling_sint:
      "sint new_selling =
         sint (sell_liabilities maker_at_post) + sint posted_selling"
    unfolding new_selling_eq
    using sint_word_of_int_nonnegative_int64
      [OF selling_sum_nonnegative selling_sum_max] .
  have release_after:
      "release_offer_liabilities price_n price_d posted maker_after =
         Cxx_Ok released"
    using release unchanged by simp
  have released_original: "released = maker_at_post"
    using release_after posted_buying posted_selling maker_after_eq
      new_buying_sint new_selling_sint buy_liabilities_nonnegative
      buy_liabilities_bounded sell_liabilities_nonnegative
      sell_liabilities_bounded
    unfolding release_offer_liabilities_def add_liability_checked_def
    by simp
  show ?thesis
    unfolding adjust_stable_def
    using fixed_and_bounded released_original posted_min_capacity
    by simp
qed

subsubsection \<open>Takeability after maker-state changes\<close>

text \<open>
  The third intended property is the changed-state liveness claim
  @{term "posted_offers_remain_takeable \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"}.
  This subsection contains its
  supporting arithmetic and lifecycle lemmas and closes with the universal
  theorem.  The proof first recovers the positive unlimited adjustment
  represented by the posted offer and identifies its selling and buying
  liabilities.  Liability coverage then exposes enough capacity after release
  for the exact-cap adjustment and for all guarded balance movements.  An
  unlimited well-formed taker witnesses a successful positive crossing.
\<close>
lemma post_created_positive_facts:
  assumes post:
    "post_offer price_n price_d amount maker options =
      Cxx_Ok (Post_Created posted maker_after)"
  shows "0 < sint price_n" "0 < sint price_d" "0 < sint amount"
    "0 < sint posted"
text \<open>
  Proof sketch: a created outcome bypasses the malformed branch, so both price
  components are positive.  It also bypasses the no-offer branch reached when
  the adjusted amount is non-positive, so the amount written to the book is
  strictly positive.
\<close>
proof -
  note post' = post[unfolded post_offer_def preflight_offer_def Let_def]
  have valid:
      "\<not> (sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> sint amount \<le> 0)"
    using post'
    by (cases "sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> sint amount \<le> 0")
       simp_all
  then show "0 < sint price_n" "0 < sint price_d" "0 < sint amount"
    by auto
  obtain buying where buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    using post'
    by (cases "offer_buying_liabilities price_n price_d amount")
       (simp_all split: if_splits)
  obtain selling where selling:
      "offer_selling_liabilities price_n price_d amount = Cxx_Ok selling"
    using post' buying
    by (cases "offer_selling_liabilities price_n price_d amount")
       (simp_all split: if_splits)
  obtain adjusted where adjusted:
      "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker))
         (can_buy_at_most maker) options = Cxx_Ok adjusted"
    using post' buying selling
    by (cases "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker))
         (can_buy_at_most maker) options")
       (simp_all split: if_splits)
  obtain acquired where acquired:
      "acquire_offer_liabilities price_n price_d adjusted maker =
        Cxx_Ok acquired"
    using post' buying selling adjusted
    by (cases "acquire_offer_liabilities price_n price_d adjusted maker")
       (simp_all split: if_splits)
  show "0 < sint posted"
    using post' buying selling adjusted acquired
    by (simp split: if_splits)
qed

lemma offer_liabilities_result:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_nonnegative: "0 \<le> sint amount"
  obtains result where
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
      int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"
    "offer_selling_liabilities price_n price_d amount =
       Cxx_Ok (num_wheat_received result)"
    "offer_buying_liabilities price_n price_d amount =
       Cxx_Ok (num_sheep_send result)"
    "0 \<le> sint (num_wheat_received result)"
    "sint (num_wheat_received result) \<le> sint amount"
    "0 \<le> sint (num_sheep_send result)"
text \<open>
  Proof sketch: with positive prices and a non-negative offer amount, the
  unlimited liability exchange satisfies the arithmetic precondition and has
  its canonical successful result.  The generic pre-threshold result contract
  makes both liability amounts non-negative and bounds the selling liability
  by the offered amount.
\<close>
proof -
  have pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  let ?amounts =
    "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
       int64_max Exchange_Normal"
  let ?result =
    "make_exchange_result (word_of_int (fst ?amounts))
       (word_of_int (snd ?amounts))
       (exchange_wheat_value_int price_n price_d amount int64_max >
        exchange_sheep_value_int price_n price_d int64_max int64_max)"
  have exchange:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
        int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok ?result"
    using exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, of Exchange_Normal]
    by simp
  note bounds =
    exchange_v10_without_price_error_thresholds_result_contract
      [OF pre exchange]
  show ?thesis
    using exchange bounds
    by (intro that[of ?result])
       (simp_all add: offer_selling_liabilities_def
          offer_buying_liabilities_def)
qed

lemma covered_offer_release:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_nonnegative: "0 \<le> sint amount"
    and wf: "party_state_wf maker"
    and cover:
      "maker_covers_offer_liabilities price_n price_d amount maker"
  obtains selling buying released where
    "offer_selling_liabilities price_n price_d amount = Cxx_Ok selling"
    "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    "release_offer_liabilities price_n price_d amount maker = Cxx_Ok released"
    "party_state_wf released"
    "sint selling \<le> sint (can_sell_at_most released)"
    "sint buying \<le> sint (can_buy_at_most released)"
text \<open>
  Proof sketch: the liability exchange supplies non-negative selling and buying
  reservations.  Coverage says each is contained in the maker's corresponding
  booked total, while well-formedness bounds those totals by the balance and
  trustline headroom.  Subtracting the reservations therefore passes both
  checked updates, preserves well-formedness, and exposes at least the released
  reservation on each capacity side.
\<close>
proof -
  obtain result where exchange:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
        int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"
    and selling:
      "offer_selling_liabilities price_n price_d amount =
         Cxx_Ok (num_wheat_received result)"
    and buying:
      "offer_buying_liabilities price_n price_d amount =
         Cxx_Ok (num_sheep_send result)"
    and selling_nonnegative:
      "0 \<le> sint (num_wheat_received result)"
    and selling_le_amount:
      "sint (num_wheat_received result) \<le> sint amount"
    and buying_nonnegative:
      "0 \<le> sint (num_sheep_send result)"
    using offer_liabilities_result [OF pn pd amount_nonnegative] by blast
  let ?selling = "num_wheat_received result"
  let ?buying = "num_sheep_send result"
  have sell_cover: "sint ?selling \<le> sint (sell_liabilities maker)"
    and buy_cover: "sint ?buying \<le> sint (buy_liabilities maker)"
    using cover selling buying
    by (simp_all add: maker_covers_offer_liabilities_def)
  have sell_liabilities_nonnegative:
      "0 \<le> sint (sell_liabilities maker)"
    and sell_liabilities_bounded:
      "sint (sell_liabilities maker) \<le> sint (sell_balance maker)"
    and buy_balance_nonnegative: "0 \<le> sint (buy_balance maker)"
    and buy_liabilities_nonnegative:
      "0 \<le> sint (buy_liabilities maker)"
    and buy_liabilities_bounded:
      "sint (buy_balance maker) + sint (buy_liabilities maker) \<le>
        sint (buy_limit maker)"
    using wf by (simp_all add: party_state_wf_def)
  let ?new_selling_int =
    "sint (sell_liabilities maker) - sint ?selling"
  let ?new_buying_int =
    "sint (buy_liabilities maker) - sint ?buying"
  have new_selling_nonnegative: "0 \<le> ?new_selling_int"
    and new_selling_bounded:
      "?new_selling_int \<le> sint (sell_balance maker)"
    and new_buying_nonnegative: "0 \<le> ?new_buying_int"
    and new_buying_bounded:
      "sint (buy_balance maker) + ?new_buying_int \<le>
        sint (buy_limit maker)"
    using sell_cover buy_cover selling_nonnegative buying_nonnegative
      sell_liabilities_bounded buy_liabilities_bounded
    by linarith+
  have new_selling_max: "?new_selling_int \<le> int64_max_int"
    using new_selling_bounded sint64_upper_bound[of "sell_balance maker"]
    by linarith
  have new_buying_max: "?new_buying_int \<le> int64_max_int"
    using new_buying_bounded buy_balance_nonnegative
      sint64_upper_bound[of "buy_limit maker"]
    by linarith
  let ?new_selling = "word_of_int ?new_selling_int :: int64"
  let ?new_buying = "word_of_int ?new_buying_int :: int64"
  have new_selling_sint: "sint ?new_selling = ?new_selling_int"
    using sint_word_of_int_nonnegative_int64
      [OF new_selling_nonnegative new_selling_max] .
  have new_buying_sint: "sint ?new_buying = ?new_buying_int"
    using sint_word_of_int_nonnegative_int64
      [OF new_buying_nonnegative new_buying_max] .
  let ?released =
    "maker\<lparr>buy_liabilities := ?new_buying,
             sell_liabilities := ?new_selling\<rparr>"
  have release:
      "release_offer_liabilities price_n price_d amount maker =
        Cxx_Ok ?released"
    using selling buying new_selling_nonnegative new_selling_bounded
      new_buying_nonnegative new_buying_bounded
    by (simp add: release_offer_liabilities_def add_liability_checked_def)
  have released_wf: "party_state_wf ?released"
    using new_selling_sint new_buying_sint new_selling_nonnegative
      new_selling_bounded buy_balance_nonnegative new_buying_nonnegative
      new_buying_bounded
    by (simp add: party_state_wf_def)
  have sell_available_nonnegative:
      "0 \<le> sint (sell_balance maker) - ?new_selling_int"
    using new_selling_bounded by simp
  have sell_available_max:
      "sint (sell_balance maker) - ?new_selling_int \<le>
        int64_max_int"
    using new_selling_nonnegative sint64_upper_bound[of "sell_balance maker"]
    by linarith
  have released_sell_capacity:
      "sint (can_sell_at_most ?released) =
        sint (sell_balance maker) - ?new_selling_int"
    unfolding can_sell_at_most_def Let_def
    using new_selling_sint sell_available_nonnegative sell_available_max
      sint_word_of_int_nonnegative_int64
        [OF sell_available_nonnegative sell_available_max]
    by simp
  have buy_available_nonnegative:
      "0 \<le> sint (buy_limit maker) - sint (buy_balance maker) -
        ?new_buying_int"
    using new_buying_bounded by linarith
  have buy_available_max:
      "sint (buy_limit maker) - sint (buy_balance maker) -
        ?new_buying_int \<le> int64_max_int"
    using buy_balance_nonnegative new_buying_nonnegative
      sint64_upper_bound[of "buy_limit maker"]
    by linarith
  have released_buy_capacity:
      "sint (can_buy_at_most ?released) =
        sint (buy_limit maker) - sint (buy_balance maker) - ?new_buying_int"
    unfolding can_buy_at_most_def Let_def
    using new_buying_sint buy_available_nonnegative buy_available_max
      sint_word_of_int_nonnegative_int64
        [OF buy_available_nonnegative buy_available_max]
    by simp
  have selling_capacity:
      "sint ?selling \<le> sint (can_sell_at_most ?released)"
    using released_sell_capacity sell_liabilities_bounded by linarith
  have buying_capacity:
      "sint ?buying \<le> sint (can_buy_at_most ?released)"
    using released_buy_capacity buy_liabilities_bounded by linarith
  show ?thesis
    using that[of ?selling ?buying ?released] selling buying release
      released_wf selling_capacity buying_capacity
    by blast
qed

lemma exchange_normal_positive_wheat_has_positive_sheep:
  assumes exchange:
    "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
       max_sheep_send max_sheep_receive Exchange_Normal options =
       Cxx_Ok result"
    and wheat_positive: "0 < sint (num_wheat_received result)"
  shows "0 < sint (num_sheep_send result)"
text \<open>
  Proof sketch: the full exchange ends in the common price-threshold function.
  In normal mode every branch whose input pair is not strictly positive returns
  the explicit two-zero record.  A successful result with positive wheat must
  therefore be the unchanged positive input record, whose sheep field is also
  strictly positive.  This argument is independent of the receive-cap flag.
\<close>
proof -
  obtain before where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         Exchange_Normal options = Cxx_Ok before"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before) (num_sheep_send before)
         (result_wheat_stays before) Exchange_Normal = Cxx_Ok result"
    using exchange
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         Exchange_Normal options")
       (simp_all add: exchange_v10_with_options_def)
  show ?thesis
    using thresholds wheat_positive apply_price_error_thresholds_characterization
    by (auto simp add: apply_price_error_thresholds_spec_def
        make_exchange_result_def Let_def split: if_splits)
qed

lemma exchange_without_thresholds_bounds_any_cap:
  assumes result:
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d
       max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
       rounding options = Cxx_Ok exchange_result"
  shows "0 \<le> sint (num_wheat_received exchange_result)"
    "sint (num_wheat_received exchange_result) \<le>
       min (sint max_wheat_receive) (sint max_wheat_send)"
    "0 \<le> sint (num_sheep_send exchange_result)"
    "sint (num_sheep_send exchange_result) \<le>
       min (sint max_sheep_receive) (sint max_sheep_send)"
text \<open>
  Proof sketch: independently of the receive-cap calculation, the
  pre-threshold exchange passes its amount pair through one common checked
  constructor.  A successful constructor call is exactly the branch in which
  both signed amounts are non-negative and no larger than either party's cap.
\<close>
proof -
  note result' =
    result[unfolded exchange_v10_without_as_checked_amounts]
  obtain wheat_value where wheat_value:
      "calculate_offer_value price_n price_d max_wheat_send
         max_sheep_receive = Cxx_Ok wheat_value"
    using result'
    by (cases "calculate_offer_value price_n price_d max_wheat_send
         max_sheep_receive") simp_all
  obtain sheep_value where sheep_value:
      "calculate_offer_value price_d price_n max_sheep_send
         max_wheat_receive = Cxx_Ok sheep_value"
    using result' wheat_value
    by (cases "calculate_offer_value price_d price_n max_sheep_send
         max_wheat_receive") simp_all
  obtain amounts where amounts:
      "exchange_v10_amounts price_n price_d wheat_value sheep_value
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         (wheat_value > sheep_value) rounding options =
       Cxx_Ok amounts"
    using result' wheat_value sheep_value
    by (cases "exchange_v10_amounts price_n price_d wheat_value sheep_value
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         (wheat_value > sheep_value) rounding options") simp_all
  have checked:
      "check_exchange_v10_result max_wheat_send max_wheat_receive
         max_sheep_send max_sheep_receive (wheat_value > sheep_value)
         amounts = Cxx_Ok exchange_result"
    using result' wheat_value sheep_value amounts by simp
  show "0 \<le> sint (num_wheat_received exchange_result)"
    and "sint (num_wheat_received exchange_result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> sint (num_sheep_send exchange_result)"
    and "sint (num_sheep_send exchange_result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    using checked
    by (auto simp add: check_exchange_v10_result_def Let_def
        make_exchange_result_def split: if_splits)
qed

lemma exchange_normal_positive_result_bounds_any_cap:
  assumes exchange:
    "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
       max_sheep_send max_sheep_receive Exchange_Normal options =
       Cxx_Ok result"
    and wheat_positive: "0 < sint (num_wheat_received result)"
  shows "sint (num_wheat_received result) \<le>
       min (sint max_wheat_receive) (sint max_wheat_send)"
    "sint (num_sheep_send result) \<le>
       min (sint max_sheep_receive) (sint max_sheep_send)"
text \<open>
  Proof sketch: decompose the full exchange into its checked pre-threshold
  result and the common threshold call.  Positive final wheat excludes the
  threshold function's zero record, so the final record is the original one
  and inherits both checked cap bounds.
\<close>
proof -
  obtain before where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         Exchange_Normal options = Cxx_Ok before"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before) (num_sheep_send before)
         (result_wheat_stays before) Exchange_Normal = Cxx_Ok result"
    using exchange
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         Exchange_Normal options")
       (simp_all add: exchange_v10_with_options_def)
  have result_before: "result = before"
    using thresholds wheat_positive apply_price_error_thresholds_characterization
    by (auto simp add: apply_price_error_thresholds_spec_def
        make_exchange_result_def Let_def split: if_splits)
  note bounds = exchange_without_thresholds_bounds_any_cap [OF before]
  show "sint (num_wheat_received result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "sint (num_sheep_send result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    using bounds result_before by simp_all
qed

lemma exchange_against_unlimited_counterparty_does_not_leave_wheat:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_nonnegative: "0 \<le> sint max_wheat_send"
    and sheep_nonnegative: "0 \<le> sint max_sheep_receive"
    and exchange:
      "exchange_v10_with_options price_n price_d max_wheat_send int64_max int64_max
         max_sheep_receive rounding options = Cxx_Ok result"
  shows "\<not> result_wheat_stays result"
text \<open>
  Proof sketch: both maker-side caps are bounded by the signed maximum, so
  the maker's wheat value is no larger than the value offered by a
  counterparty with both caps at that maximum.  The pre-threshold exchange
  records this comparison, and the price-threshold step preserves its
  wheat-stays flag.
\<close>
proof -
  obtain before where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send int64_max int64_max max_sheep_receive rounding
         options = Cxx_Ok before"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before) (num_sheep_send before)
         (result_wheat_stays before) rounding = Cxx_Ok result"
    using exchange
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send int64_max int64_max max_sheep_receive rounding
         options")
       (simp_all add: exchange_v10_with_options_def)
  note before' = before[unfolded exchange_v10_without_as_checked_amounts]
  obtain wheat_value where wheat_value:
      "calculate_offer_value price_n price_d max_wheat_send
         max_sheep_receive = Cxx_Ok wheat_value"
    using before'
    by (cases "calculate_offer_value price_n price_d max_wheat_send
         max_sheep_receive") simp_all
  obtain sheep_value where sheep_value:
      "calculate_offer_value price_d price_n int64_max int64_max =
         Cxx_Ok sheep_value"
    using before' wheat_value
    by (cases "calculate_offer_value price_d price_n int64_max int64_max")
       simp_all
  obtain amounts where amounts:
      "exchange_v10_amounts price_n price_d wheat_value sheep_value
         max_wheat_send int64_max int64_max max_sheep_receive
         (wheat_value > sheep_value) rounding options =
       Cxx_Ok amounts"
    using before' wheat_value sheep_value
    by (cases "exchange_v10_amounts price_n price_d wheat_value sheep_value
         max_wheat_send int64_max int64_max max_sheep_receive
         (wheat_value > sheep_value) rounding options") simp_all
  have checked:
      "check_exchange_v10_result max_wheat_send int64_max int64_max
         max_sheep_receive (wheat_value > sheep_value) amounts =
       Cxx_Ok before"
    using before' wheat_value sheep_value amounts by simp
  have wheat_pre:
      "calculate_offer_value_pre price_n price_d max_wheat_send
         max_sheep_receive"
    using pn pd wheat_nonnegative sheep_nonnegative
    by (simp add: calculate_offer_value_pre_def)
  have sheep_pre:
      "calculate_offer_value_pre price_d price_n int64_max int64_max"
    using pn pd by (simp add: calculate_offer_value_pre_def int64_max_def)
  have wheat_uint:
      "uint wheat_value =
       min (sint max_wheat_send * sint price_n)
         (sint max_sheep_receive * sint price_d)"
    using wheat_value
      calculate_offer_value_integer_characterization[OF wheat_pre]
    by (metis cxx_result.inject)
  have sheep_uint:
      "uint sheep_value =
       min (sint int64_max * sint price_d)
         (sint int64_max * sint price_n)"
    using sheep_value
      calculate_offer_value_integer_characterization[OF sheep_pre]
    by (metis cxx_result.inject)
  have wheat_product_bounded:
      "sint max_wheat_send * sint price_n \<le>
       sint int64_max * sint price_n"
    using sint64_upper_bound[of max_wheat_send] less_imp_le[OF pn]
    by (simp add: int64_max_def mult_right_mono)
  have sheep_product_bounded:
      "sint max_sheep_receive * sint price_d \<le>
       sint int64_max * sint price_d"
    using sint64_upper_bound[of max_sheep_receive] less_imp_le[OF pd]
    by (simp add: int64_max_def mult_right_mono)
  have no_stays: "\<not> wheat_value > sheep_value"
    using wheat_uint sheep_uint wheat_product_bounded sheep_product_bounded
    by (simp add: word_less_def min_def split: if_splits)
  have before_stays:
      "result_wheat_stays before = (wheat_value > sheep_value)"
    using checked
    by (auto simp add: check_exchange_v10_result_def Let_def
        make_exchange_result_def split: if_splits)
  have result_stays:
      "result_wheat_stays result = result_wheat_stays before"
    using apply_price_error_thresholds_preserves_wheat_stays[OF thresholds] .
  show ?thesis
    using no_stays before_stays result_stays by simp
qed

lemma party_receive_within_capacity:
  assumes wf: "party_state_wf party"
    and delta_positive: "0 < sint delta"
    and within: "sint delta \<le> sint (can_buy_at_most party)"
  obtains after where
    "party_receive_buy_asset party delta = Cxx_Ok after"
    "party_state_wf after"
    "can_sell_at_most after = can_sell_at_most party"
text \<open>
  Proof sketch: well-formedness makes the raw unused trustline headroom a
  non-negative signed value represented exactly by @{const can_buy_at_most}.
  The assumed bound therefore passes the guarded balance update.  Adding the
  delta stays below the limit, preserves well-formedness, and does not touch
  the selling fields or their capacity.
\<close>
proof -
  have sell_liabilities_nonnegative:
      "0 \<le> sint (sell_liabilities party)"
    and sell_liabilities_bounded:
      "sint (sell_liabilities party) \<le> sint (sell_balance party)"
    and buy_balance_nonnegative: "0 \<le> sint (buy_balance party)"
    and buy_liabilities_nonnegative:
      "0 \<le> sint (buy_liabilities party)"
    and buy_total_bounded:
      "sint (buy_balance party) + sint (buy_liabilities party) \<le>
       sint (buy_limit party)"
    using wf by (simp_all add: party_state_wf_def)
  let ?available =
    "sint (buy_limit party) - sint (buy_balance party) -
      sint (buy_liabilities party)"
  have available_nonnegative: "0 \<le> ?available"
    using buy_total_bounded by linarith
  have available_max: "?available \<le> int64_max_int"
    using buy_balance_nonnegative buy_liabilities_nonnegative
      sint64_upper_bound[of "buy_limit party"]
    by linarith
  have capacity: "sint (can_buy_at_most party) = ?available"
    unfolding can_buy_at_most_def Let_def
    using available_nonnegative available_max
      sint_word_of_int_nonnegative_int64
        [OF available_nonnegative available_max]
    by simp
  have delta_fits: "sint delta \<le> ?available"
    using within capacity by simp
  let ?new_balance_int = "sint (buy_balance party) + sint delta"
  have new_balance_nonnegative: "0 \<le> ?new_balance_int"
    using buy_balance_nonnegative delta_positive by linarith
  have new_total_bounded:
      "?new_balance_int + sint (buy_liabilities party) \<le>
       sint (buy_limit party)"
    using delta_fits by linarith
  have new_balance_max: "?new_balance_int \<le> int64_max_int"
    using new_total_bounded buy_liabilities_nonnegative
      sint64_upper_bound[of "buy_limit party"]
    by linarith
  let ?new_balance = "word_of_int ?new_balance_int :: int64"
  have new_balance_sint: "sint ?new_balance = ?new_balance_int"
    using sint_word_of_int_nonnegative_int64
      [OF new_balance_nonnegative new_balance_max] .
  let ?after = "party\<lparr>buy_balance := ?new_balance\<rparr>"
  have receive: "party_receive_buy_asset party delta = Cxx_Ok ?after"
    using delta_positive delta_fits
    by (simp add: party_receive_buy_asset_def)
  have after_wf: "party_state_wf ?after"
    using sell_liabilities_nonnegative sell_liabilities_bounded
      buy_liabilities_nonnegative new_balance_nonnegative new_total_bounded
      new_balance_sint
    by (simp add: party_state_wf_def)
  have sell_capacity:
      "can_sell_at_most ?after = can_sell_at_most party"
    by (simp add: can_sell_at_most_def)
  show ?thesis
    using that[of ?after] receive after_wf sell_capacity by blast
qed

lemma party_spend_within_capacity:
  assumes wf: "party_state_wf party"
    and delta_positive: "0 < sint delta"
    and within: "sint delta \<le> sint (can_sell_at_most party)"
  obtains after where
    "party_spend_sell_asset party delta = Cxx_Ok after"
    "party_state_wf after"
text \<open>
  Proof sketch: well-formedness makes the uncommitted selling balance a
  non-negative signed value represented exactly by @{const can_sell_at_most}.
  Spending within it leaves at least the booked selling liabilities, so the
  guarded subtraction succeeds and the updated party remains well formed.
\<close>
proof -
  have sell_liabilities_nonnegative:
      "0 \<le> sint (sell_liabilities party)"
    and sell_liabilities_bounded:
      "sint (sell_liabilities party) \<le> sint (sell_balance party)"
    and buy_balance_nonnegative: "0 \<le> sint (buy_balance party)"
    and buy_liabilities_nonnegative:
      "0 \<le> sint (buy_liabilities party)"
    and buy_total_bounded:
      "sint (buy_balance party) + sint (buy_liabilities party) \<le>
       sint (buy_limit party)"
    using wf by (simp_all add: party_state_wf_def)
  let ?available =
    "sint (sell_balance party) - sint (sell_liabilities party)"
  have available_nonnegative: "0 \<le> ?available"
    using sell_liabilities_bounded by linarith
  have available_max: "?available \<le> int64_max_int"
    using sell_liabilities_nonnegative sint64_upper_bound[of "sell_balance party"]
    by linarith
  have capacity: "sint (can_sell_at_most party) = ?available"
    unfolding can_sell_at_most_def Let_def
    using available_nonnegative available_max
      sint_word_of_int_nonnegative_int64
        [OF available_nonnegative available_max]
    by simp
  have delta_fits: "sint delta \<le> ?available"
    using within capacity by simp
  let ?new_balance_int = "sint (sell_balance party) - sint delta"
  have liabilities_fit:
      "sint (sell_liabilities party) \<le> ?new_balance_int"
    using delta_fits by linarith
  have new_balance_nonnegative: "0 \<le> ?new_balance_int"
    using sell_liabilities_nonnegative liabilities_fit by linarith
  have new_balance_max: "?new_balance_int \<le> int64_max_int"
    using delta_positive sint64_upper_bound[of "sell_balance party"]
    by linarith
  let ?new_balance = "word_of_int ?new_balance_int :: int64"
  have new_balance_sint: "sint ?new_balance = ?new_balance_int"
    using sint_word_of_int_nonnegative_int64
      [OF new_balance_nonnegative new_balance_max] .
  let ?after = "party\<lparr>sell_balance := ?new_balance\<rparr>"
  have spend: "party_spend_sell_asset party delta = Cxx_Ok ?after"
    using delta_positive delta_fits
    by (simp add: party_spend_sell_asset_def)
  have after_wf: "party_state_wf ?after"
    using sell_liabilities_nonnegative liabilities_fit buy_balance_nonnegative
      buy_liabilities_nonnegative buy_total_bounded new_balance_sint
    by (simp add: party_state_wf_def)
  show ?thesis
    using that[of ?after] spend after_wf by blast
qed

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

lemma exact_cap_replays_unlimited_positive_adjustment:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and receive_nonnegative: "0 \<le> sint max_sheep_receive"
    and unlimited:
      "adjust_offer_with_options price_n price_d amount int64_max \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok amount"
    and buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    and buying_fits: "sint buying \<le> sint max_sheep_receive"
  shows "adjust_offer_with_options price_n price_d amount max_sheep_receive \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok amount"
text \<open>
  Proof sketch: the unlimited successful adjustment applies the normal price
  threshold to the offer-liability amount pair and, because its wheat result
  is positive, preserves that pair.  Thus @{term buying} is exactly the sheep
  amount paired with @{term amount}.  If wheat is the more valuable side, the
  exact receive cap adds the denominator-minus-one slack that makes this floor
  payment sufficient for all of @{term amount}; otherwise the exact flag is
  inert and the ceiling conversion already replays the same pair.  The common
  threshold call then returns the original positive result.
\<close>
proof -
  have full_pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  let ?full_amounts =
    "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
       int64_max Exchange_Normal"
  note full_characterization =
    exchange_v10_normal_characterization [OF full_pre]
  have amount_word:
      "amount = (word_of_int (fst ?full_amounts) :: int64)"
    using unlimited full_characterization amount_positive
    by (auto simp add: adjust_offer_with_options_def make_exchange_result_def Let_def
        split: if_splits)
  have full_condition:
      "0 < fst ?full_amounts \<and> 0 < snd ?full_amounts \<and>
       price_error_bound_spec price_n price_d
         (word_of_int (fst ?full_amounts))
         (word_of_int (snd ?full_amounts)) False"
    using unlimited full_characterization amount_positive
    by (auto simp add: adjust_offer_with_options_def make_exchange_result_def Let_def
        split: if_splits)
  note amount_words =
    exchange_v10_amounts_integer_characterization
      [OF full_pre, of Exchange_Normal]
  have amount_sint: "sint amount = fst ?full_amounts"
    using amount_word amount_words(2) by simp
  have full_before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
         int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok
         (make_exchange_result amount
           (word_of_int (snd ?full_amounts))
           (exchange_wheat_value_int price_n price_d amount int64_max >
            exchange_sheep_value_int price_n price_d int64_max int64_max))"
    using exchange_v10_without_price_error_thresholds_integer_characterization
      [OF full_pre, of Exchange_Normal] amount_word
    by simp
  have buying_word:
      "buying = (word_of_int (snd ?full_amounts) :: int64)"
    using buying full_before
    by (simp add: offer_buying_liabilities_def make_exchange_result_def)
  have buying_sint: "sint buying = snd ?full_amounts"
    using buying_word amount_words(3) by simp
  have buying_positive: "0 < sint buying"
    using full_condition buying_sint by simp
  have amount_le_max: "sint amount \<le> sint int64_max"
    using sint64_upper_bound[of amount]
    by (simp add: int64_max_def)
  have wheat_product_bounded:
      "sint amount * sint price_n \<le>
       sint int64_max * sint price_n"
    using amount_le_max less_imp_le[OF pn]
    by (simp add: mult_right_mono)
  have full_stays_false:
      "\<not> exchange_wheat_value_int price_n price_d amount int64_max >
       exchange_sheep_value_int price_n price_d int64_max int64_max"
    using wheat_product_bounded
    by (simp add: exchange_wheat_value_int_def
        exchange_sheep_value_int_def min_def split: if_splits)
  have full_exchange:
      "exchange_v10_with_options price_n price_d amount int64_max int64_max int64_max
         Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (make_exchange_result amount buying False)"
    using full_characterization full_condition amount_word buying_word
      full_stays_false
    by (simp add: Let_def)
  have thresholds:
      "apply_price_error_thresholds price_n price_d amount buying False
         Exchange_Normal =
       Cxx_Ok (make_exchange_result amount buying False)"
    using full_exchange full_before full_stays_false buying_word
    by (simp add: exchange_v10_with_options_def make_exchange_result_def)
  show ?thesis
  proof (cases "sint price_n > sint price_d")
    case wheat_more: True
    have full_formula:
        "?full_amounts =
          (exchange_wheat_value_int price_n price_d amount int64_max
             div sint price_n,
           (exchange_wheat_value_int price_n price_d amount int64_max
             div sint price_n) * sint price_n div sint price_d)"
      using wheat_more full_stays_false
      by (simp add: exchange_v10_amounts_int_def Let_def)
    have amount_quotient:
        "exchange_wheat_value_int price_n price_d amount int64_max
           div sint price_n = sint amount"
      using amount_sint full_formula by simp
    have product_le_wheat_value:
        "sint amount * sint price_n \<le>
         exchange_wheat_value_int price_n price_d amount int64_max"
      using int_div_mult_le [OF pn, of
        "exchange_wheat_value_int price_n price_d amount int64_max"]
        amount_quotient
      by simp
    have wheat_value_le_product:
        "exchange_wheat_value_int price_n price_d amount int64_max \<le>
         sint amount * sint price_n"
      by (simp add: exchange_wheat_value_int_def)
    have full_wheat_value:
        "exchange_wheat_value_int price_n price_d amount int64_max =
         sint amount * sint price_n"
      using product_le_wheat_value wheat_value_le_product by simp
    have product_global_bound:
        "sint amount * sint price_n \<le>
         sint int64_max * sint price_d"
      using full_wheat_value
      by (simp add: exchange_wheat_value_int_def min_def split: if_splits)
    have buying_formula:
        "sint buying = sint amount * sint price_n div sint price_d"
      using buying_sint full_formula full_wheat_value by simp
    have buying_as_quotient:
        "buying = word_of_int
          (sint amount * sint price_n div sint price_d)"
      using buying_formula
      by (metis scast_eq scast_id)
    let ?product = "sint amount * sint price_n"
    let ?units = "?product div sint price_d"
    let ?product_word = "word_of_int ?product :: uint128"
    let ?receive_word =
      "word_of_int (sint max_sheep_receive * sint price_d) :: uint128"
    let ?slack =
      "ucast (scast (price_d - 1) :: int64) :: uint128"
    let ?global_word =
      "word_of_int (sint int64_max * sint price_d) :: uint128"
    have product_nonnegative: "0 \<le> ?product"
      using amount_positive pn by simp
    have product_uint: "uint ?product_word = ?product"
      using big_multiply_uint_value
        [of amount "scast price_n :: int64"]
        less_imp_le[OF amount_positive] less_imp_le[OF pn]
      by simp
    have receive_uint:
        "uint ?receive_word =
         sint max_sheep_receive * sint price_d"
      using big_multiply_uint_value
        [of max_sheep_receive "scast price_d :: int64"]
        receive_nonnegative less_imp_le[OF pd]
      by simp
    have global_uint:
        "uint ?global_word = sint int64_max * sint price_d"
      using big_multiply_uint_value
        [of int64_max "scast price_d :: int64"]
        less_imp_le[OF pd]
      by (simp add: int64_max_def)
    have slack_sint:
        "sint (scast (price_d - 1) :: int64) = sint price_d - 1"
      using positive_price_denominator_minus_one_cast [OF pd] .
    have slack_nonnegative:
        "0 \<le> sint (scast (price_d - 1) :: int64)"
      using slack_sint pd by simp
    have slack_uint64:
        "uint (scast (price_d - 1) :: int64) = sint price_d - 1"
      using uint_eq_sint_nonnegative_int64 [OF slack_nonnegative] slack_sint
      by simp
    have slack_uint: "uint ?slack = sint price_d - 1"
      using slack_uint64
      by (simp add: uint_up_ucast is_up)
    have remainder_less: "?product mod sint price_d < sint price_d"
      using pd by simp
    have decomposition:
        "?product mod sint price_d + ?units * sint price_d = ?product"
      by (rule mod_div_mult_eq)
    have product_le_floor_slack:
        "?product \<le> ?units * sint price_d + sint price_d - 1"
      using remainder_less decomposition by linarith
    have floor_slack_le_cap:
        "?units * sint price_d + sint price_d - 1 \<le>
         sint max_sheep_receive * sint price_d + sint price_d - 1"
    proof -
      have units_fit: "?units \<le> sint max_sheep_receive"
        using buying_fits buying_formula by simp
      have "?units * sint price_d \<le>
          sint max_sheep_receive * sint price_d"
        using mult_right_mono [OF units_fit less_imp_le[OF pd]] .
      then show ?thesis by simp
    qed
    have product_le_receive_slack:
        "?product \<le>
         sint max_sheep_receive * sint price_d + sint price_d - 1"
      using product_le_floor_slack floor_slack_le_cap by linarith
    have receive_product_bound:
        "sint max_sheep_receive * sint price_d < (2 :: int) ^ 126"
    proof -
      have receive_lt: "sint max_sheep_receive < (2 :: int) ^ 63"
        using sint_lt[of max_sheep_receive] by simp
      have denominator_lt:
          "sint (scast price_d :: int64) < (2 :: int) ^ 63"
        using sint_lt[of "scast price_d :: int64"] by simp
      have "sint max_sheep_receive * sint price_d <
          (2 :: int) ^ 63 * 2 ^ 63"
        using receive_lt denominator_lt receive_nonnegative
          less_imp_le[OF pd]
        by (intro mult_strict_mono) simp_all
      then show ?thesis by simp
    qed
    have slack_bound: "uint ?slack < (2 :: int) ^ 64"
      using uint_lt2p [of "scast (price_d - 1) :: int64"]
      by (simp add: uint_up_ucast is_up)
    have receive_no_wrap:
        "uint ?receive_word + uint ?slack < (2 :: int) ^ 128"
      using receive_uint receive_product_bound slack_bound by simp
    have product_le_relaxed_word:
        "?product_word \<le> ?receive_word + ?slack"
      using product_uint receive_uint slack_uint receive_no_wrap
        product_le_receive_slack
      by (simp add: word_le_def uint_word_ariths take_bit_eq_mod)
    have product_le_global_word: "?product_word \<le> ?global_word"
      using product_uint global_uint product_global_bound
      by (simp add: word_le_def)
    have exact_value:
        "calculate_offer_value_with_exact_receive_cap price_n price_d amount
           max_sheep_receive = Cxx_Ok ?product_word"
      using exact_value_word_characterization
        [OF pn pd less_imp_le[OF amount_positive] receive_nonnegative]
        product_le_relaxed_word product_le_global_word
      by (simp add: min_def)
    have wheat_pre:
        "calculate_offer_value_pre price_n price_d amount max_sheep_receive"
      using pn pd amount_positive receive_nonnegative
      by (simp add: calculate_offer_value_pre_def)
    let ?wheat_word =
      "min ?product_word ?receive_word"
    have wheat_value:
        "calculate_offer_value price_n price_d amount max_sheep_receive =
         Cxx_Ok ?wheat_word"
      using calculate_offer_value_success [OF wheat_pre] .
    have sheep_pre:
        "calculate_offer_value_pre price_d price_n int64_max int64_max"
      using pn pd
      by (simp add: calculate_offer_value_pre_def int64_max_def)
    let ?sheep_word =
      "min
        (word_of_int (sint int64_max * sint price_d) :: uint128)
        (word_of_int (sint int64_max * sint price_n) :: uint128)"
    have sheep_value:
        "calculate_offer_value price_d price_n int64_max int64_max =
         Cxx_Ok ?sheep_word"
      using calculate_offer_value_success [OF sheep_pre] .
    have reduced_pre:
        "exchange_v10_pre price_n price_d amount int64_max int64_max
          max_sheep_receive"
      using pn pd amount_positive receive_nonnegative
      by (simp add: exchange_v10_pre_def int64_max_def)
    have reduced_stays_false:
        "\<not> exchange_wheat_value_int price_n price_d amount
            max_sheep_receive >
          exchange_sheep_value_int price_n price_d int64_max int64_max"
    proof -
      have global_sheep_value:
          "exchange_sheep_value_int price_n price_d int64_max int64_max =
           sint int64_max * sint price_d"
        using wheat_more
        by (simp add: exchange_sheep_value_int_def int64_max_def min_def
            mult_left_mono)
      have reduced_wheat_le:
          "exchange_wheat_value_int price_n price_d amount
             max_sheep_receive \<le> ?product"
        by (simp add: exchange_wheat_value_int_def)
      show ?thesis
        using reduced_wheat_le product_global_bound global_sheep_value
        by simp
    qed
    have wheat_uint:
        "uint ?wheat_word =
         exchange_wheat_value_int price_n price_d amount max_sheep_receive"
      using exchange_wheat_value_word [OF reduced_pre] .
    have sheep_uint:
        "uint ?sheep_word =
         exchange_sheep_value_int price_n price_d int64_max int64_max"
      using exchange_sheep_value_word [OF reduced_pre] .
    have no_stays_word: "(?wheat_word > ?sheep_word) = False"
      using wheat_uint sheep_uint reduced_stays_false
      by (simp add: word_less_def)
    have exact_stays_condition:
        "(?sheep_word < ?product_word \<and>
          ?sheep_word < ?receive_word) = False"
      using no_stays_word
      by (simp add: min_def split: if_splits)
    have divide_wheat:
        "big_divide_or_throw128 ?product_word (scast price_n)
           Cxx_Round_Down = Cxx_Ok amount"
      unfolding big_divide_or_throw128_success_iff
      using pn product_uint amount_positive sint64_upper_bound[of amount]
      by simp
    have divide_sheep:
        "big_divide_or_throw amount (scast price_n) (scast price_d)
           Cxx_Round_Down = Cxx_Ok buying"
      unfolding big_divide_or_throw_success_iff
      using pn pd amount_positive buying_formula buying_as_quotient
        sint64_upper_bound[of buying]
      by simp
    have exact_amounts:
        "exchange_v10_amounts price_n price_d ?wheat_word ?sheep_word amount
           int64_max int64_max max_sheep_receive False Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (amount, buying)"
      using wheat_more exact_value divide_wheat divide_sheep
      by (simp add: exchange_v10_amounts_def)
    have exact_amounts_actual:
      "exchange_v10_amounts price_n price_d ?wheat_word ?sheep_word amount
           int64_max int64_max max_sheep_receive (?wheat_word > ?sheep_word)
           Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok (amount, buying)"
      apply (subst no_stays_word)
      apply (rule exact_amounts)
      done
    have exact_before:
        "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
           int64_max int64_max max_sheep_receive Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (make_exchange_result amount buying False)"
      unfolding exchange_v10_without_as_checked_amounts
      apply (simp only: wheat_value cxx_bind.simps)
      apply (simp only: sheep_value cxx_bind.simps)
      apply (simp only: Let_def exact_amounts_actual cxx_bind.simps)
      unfolding check_exchange_v10_result_def
      using no_stays_word amount_positive buying_positive buying_fits
        receive_nonnegative sint64_upper_bound[of amount]
        sint64_upper_bound[of buying]
      by (simp add: Let_def make_exchange_result_def int64_max_def)
    show ?thesis
      using exact_before thresholds
      by (simp add: adjust_offer_with_options_def exchange_v10_with_options_def make_exchange_result_def)
  next
    case not_wheat_more: False
    have price_order: "sint price_n \<le> sint price_d"
      using not_wheat_more by simp
    have full_wheat_value:
        "exchange_wheat_value_int price_n price_d amount int64_max =
         sint amount * sint price_n"
    proof -
      have amount_product_le:
          "sint amount * sint price_n \<le>
           sint int64_max * sint price_n"
        using amount_le_max less_imp_le[OF pn]
        by (simp add: mult_right_mono)
      have price_product_le:
          "sint int64_max * sint price_n \<le>
           sint int64_max * sint price_d"
        using price_order
        by (simp add: int64_max_def mult_left_mono)
      show ?thesis
        using amount_product_le price_product_le
        by (simp add: exchange_wheat_value_int_def min_def)
    qed
    have full_formula:
        "?full_amounts =
          (((sint amount * sint price_n div sint price_d) * sint price_d +
              sint price_n - 1) div sint price_n,
           sint amount * sint price_n div sint price_d)"
      using not_wheat_more full_stays_false full_wheat_value
      by (simp add: exchange_v10_amounts_int_def Let_def)
    let ?reduced_amounts =
      "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         max_sheep_receive Exchange_Normal"
    have reduced_pre:
        "exchange_v10_pre price_n price_d amount int64_max int64_max
          max_sheep_receive"
      using pn pd amount_positive receive_nonnegative
      by (simp add: exchange_v10_pre_def int64_max_def)
    let ?product = "sint amount * sint price_n"
    let ?units = "?product div sint price_d"
    have units: "?units = sint buying"
      using buying_sint full_formula by simp
    have units_nonnegative: "0 \<le> ?units"
      using amount_positive pn pd
      by (simp add: pos_imp_zdiv_nonneg_iff)
    have units_multiple_le_product:
        "?units * sint price_d \<le> ?product"
      using int_div_mult_le [OF pd] .
    have units_multiple_le_cap:
        "?units * sint price_d \<le>
         sint max_sheep_receive * sint price_d"
      using buying_fits units less_imp_le[OF pd]
      by (simp add: mult_right_mono)
    have reduced_units:
        "min ?product (sint max_sheep_receive * sint price_d)
           div sint price_d = ?units"
    proof -
      have lower:
          "?units \<le>
           min ?product (sint max_sheep_receive * sint price_d)
             div sint price_d"
      proof -
        have "(?units * sint price_d) div sint price_d \<le>
            min ?product (sint max_sheep_receive * sint price_d)
              div sint price_d"
          using zdiv_mono1
            [OF min.bounded_iff[THEN iffD2,
                OF conjI[OF units_multiple_le_product
                  units_multiple_le_cap]] pd] .
        then show ?thesis using pd by simp
      qed
      have upper:
          "min ?product (sint max_sheep_receive * sint price_d)
             div sint price_d \<le> ?units"
        using zdiv_mono1 [OF min.cobounded1 pd] .
      show ?thesis using lower upper by simp
    qed
    have reduced_stays_false:
        "\<not> exchange_wheat_value_int price_n price_d amount
            max_sheep_receive >
          exchange_sheep_value_int price_n price_d int64_max int64_max"
    proof -
      have global_sheep_value:
          "exchange_sheep_value_int price_n price_d int64_max int64_max =
           sint int64_max * sint price_n"
        using price_order
        by (simp add: exchange_sheep_value_int_def int64_max_def min_def
            mult_left_mono)
      have reduced_wheat_le:
          "exchange_wheat_value_int price_n price_d amount
             max_sheep_receive \<le> sint amount * sint price_n"
        by (simp add: exchange_wheat_value_int_def)
      show ?thesis
        using reduced_wheat_le wheat_product_bounded global_sheep_value
        by simp
    qed
    have reduced_wheat_units:
        "exchange_wheat_value_int price_n price_d amount max_sheep_receive
           div sint price_d = ?units"
      using reduced_units
      by (simp add: exchange_wheat_value_int_def)
    have reduced_explicit:
        "?reduced_amounts =
          ((?units * sint price_d + sint price_n - 1) div sint price_n,
           ?units)"
      using not_wheat_more reduced_stays_false reduced_wheat_units
      by (simp add: exchange_v10_amounts_int_def Let_def)
    have reduced_formula:
        "?reduced_amounts = ?full_amounts"
      using reduced_explicit full_formula by simp
    note reduced_characterization =
      exchange_v10_normal_characterization [OF reduced_pre]
    have reduced_false:
        "adjust_offer_with_options price_n price_d amount max_sheep_receive \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok amount"
      using reduced_characterization reduced_formula full_condition amount_word
        reduced_stays_false
      by (simp add: adjust_offer_with_options_def make_exchange_result_def Let_def)
    show ?thesis
      using reduced_false
        adjust_offer_exact_irrelevant_if_not_wheat_more
          [OF not_wheat_more, of amount max_sheep_receive]
      by simp
  qed
qed

lemma positive_adjustment_replays_unlimited:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_nonnegative: "0 \<le> sint max_wheat"
    and sheep_nonnegative: "0 \<le> sint max_sheep"
    and adjusted:
      "adjust_offer_with_options price_n price_d max_wheat max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
        Cxx_Ok result"
    and result_positive: "0 < sint result"
  shows "adjust_offer_with_options price_n price_d result int64_max \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok result"
text \<open>
  Proof sketch: first use positive idempotence to replay the adjusted amount
  against its original receive cap.  When wheat is not more valuable, the
  exact flag is inert; the ceiling formula uniquely determines the same sheep
  units even after raising the receive cap to the signed maximum.  When wheat
  is more valuable, the successful exact calculation proves that the full
  result-price product fits the global cap; the unlimited plain calculation
  therefore repeats the same two divisions and the same successful threshold
  call.
\<close>
proof -
  have stable_and_bounded:
      "adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result \<and>
       sint result \<le> sint max_wheat"
    using adjust_offer_positive_idempotent
      [OF pn pd wheat_nonnegative sheep_nonnegative adjusted result_positive] .
  have stable:
      "adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"
    using stable_and_bounded by simp
  show ?thesis
  proof (cases "sint price_n > sint price_d")
    case wheat_more: True
    let ?product_word =
      "word_of_int (sint result * sint price_n) :: uint128"
    let ?trade =
      "min ?product_word
        (min
          ((word_of_int (sint max_sheep * sint price_d) :: uint128) +
            ucast (scast (price_d - 1) :: int64))
          (word_of_int (sint int64_max * sint price_d) :: uint128))"
    have trade:
        "calculate_offer_value_with_exact_receive_cap price_n price_d result
           max_sheep = Cxx_Ok ?trade"
      using exact_value_word_characterization
        [OF pn pd less_imp_le[OF result_positive] sheep_nonnegative] .
    have wheat_pre:
        "calculate_offer_value_pre price_n price_d result max_sheep"
      using pn pd result_positive sheep_nonnegative
      by (simp add: calculate_offer_value_pre_def)
    have sheep_pre:
        "calculate_offer_value_pre price_d price_n int64_max int64_max"
      using pn pd
      by (simp add: calculate_offer_value_pre_def int64_max_def)
    obtain wheat_value where wheat_value:
        "calculate_offer_value price_n price_d result max_sheep =
          Cxx_Ok wheat_value"
      and wheat_value_uint:
        "uint wheat_value =
          min (sint result * sint price_n)
            (sint max_sheep * sint price_d)"
      using calculate_offer_value_integer_characterization [OF wheat_pre] .
    obtain sheep_value where sheep_value:
        "calculate_offer_value price_d price_n int64_max int64_max =
          Cxx_Ok sheep_value"
      and sheep_value_uint:
        "uint sheep_value =
          min (sint int64_max * sint price_d)
            (sint int64_max * sint price_n)"
      using calculate_offer_value_integer_characterization [OF sheep_pre] .
    have result_product_bounded:
        "sint result * sint price_n \<le>
         sint int64_max * sint price_n"
      using sint64_upper_bound[of result] less_imp_le[OF pn]
      by (simp add: int64_max_def mult_right_mono)
    have sheep_product_bounded:
        "sint max_sheep * sint price_d \<le>
         sint int64_max * sint price_d"
      using sint64_upper_bound[of max_sheep] less_imp_le[OF pd]
      by (simp add: int64_max_def mult_right_mono)
    have no_stays: "\<not> wheat_value > sheep_value"
      using wheat_value_uint sheep_value_uint result_product_bounded
        sheep_product_bounded
      by (simp add: word_less_def min_def split: if_splits)
    obtain wheat_receive where first_divide:
        "big_divide_or_throw128 ?trade (scast price_n) Cxx_Round_Down =
          Cxx_Ok wheat_receive"
      using stable wheat_value sheep_value no_stays trade wheat_more
      by (cases "big_divide_or_throw128 ?trade (scast price_n)
           Cxx_Round_Down")
         (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def
            exchange_v10_without_price_error_thresholds_with_options_def
            exchange_v10_amounts_def Let_def)
    obtain sheep_send where second_divide:
        "big_divide_or_throw wheat_receive (scast price_n) (scast price_d)
           Cxx_Round_Down = Cxx_Ok sheep_send"
      using stable wheat_value sheep_value no_stays trade wheat_more
        first_divide
      by (cases "big_divide_or_throw wheat_receive (scast price_n)
           (scast price_d) Cxx_Round_Down")
         (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def
            exchange_v10_without_price_error_thresholds_with_options_def
            exchange_v10_amounts_def Let_def)
    obtain final where threshold:
        "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
           False Exchange_Normal = Cxx_Ok final"
      using stable wheat_value sheep_value no_stays trade wheat_more
        first_divide second_divide
      by (cases "apply_price_error_thresholds price_n price_d wheat_receive
           sheep_send False Exchange_Normal")
         (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def
            exchange_v10_without_price_error_thresholds_with_options_def
            exchange_v10_amounts_def make_exchange_result_def Let_def
            split: if_splits)
    have final_choice:
        "final = make_exchange_result wheat_receive sheep_send False \<or>
         final = make_exchange_result 0 0 False"
      using apply_price_error_thresholds_normal_result [OF threshold] .
    have result_final: "result = num_wheat_received final"
      using stable wheat_value sheep_value no_stays trade wheat_more
        first_divide second_divide threshold
      by (simp add: adjust_offer_with_options_def exchange_v10_with_options_def
          exchange_v10_without_price_error_thresholds_with_options_def
          exchange_v10_amounts_def make_exchange_result_def Let_def
          split: if_splits)
    have result_wheat: "result = wheat_receive"
      using result_final final_choice result_positive
      by (auto simp add: make_exchange_result_def)
    have wheat_receive_check:
        "\<not> min (sint int64_max) (sint result) < sint wheat_receive"
      and sheep_send_nonnegative: "0 \<le> sint sheep_send"
      and sheep_send_check:
        "\<not> min (sint max_sheep) (sint int64_max) < sint sheep_send"
      using stable wheat_value sheep_value no_stays trade wheat_more
        first_divide second_divide threshold
      by (simp_all add: adjust_offer_with_options_def exchange_v10_with_options_def
          exchange_v10_without_price_error_thresholds_with_options_def
          exchange_v10_amounts_def make_exchange_result_def Let_def
          split: if_splits)
    have sheep_send_bounded: "sint sheep_send \<le> sint max_sheep"
      using sheep_send_check by simp
    have result_div:
        "result = word_of_int (uint ?trade div sint price_n)"
      using first_divide result_wheat
      unfolding big_divide_or_throw128_success_iff
      by simp
    have quotient_bounded:
        "uint ?trade div sint price_n \<le> int64_max_int"
      using first_divide
      unfolding big_divide_or_throw128_success_iff
      by simp
    have quotient_nonnegative:
        "0 \<le> uint ?trade div sint price_n"
      using pn by (simp add: pos_imp_zdiv_nonneg_iff)
    have result_sint:
        "sint result = uint ?trade div sint price_n"
    proof -
      have quotient_sint:
          "sint (word_of_int (uint ?trade div sint price_n) :: int64) =
           uint ?trade div sint price_n"
        using sint_word_of_int_nonnegative_int64
          [OF quotient_nonnegative quotient_bounded] .
      have cast_result:
          "sint result =
           sint (word_of_int (uint ?trade div sint price_n) :: int64)"
        by (rule arg_cong[OF result_div])
      show ?thesis
        using cast_result quotient_sint by (rule trans)
    qed
    have product_le_trade:
        "sint result * sint price_n \<le> uint ?trade"
    proof -
      have quotient_product:
          "(uint ?trade div sint price_n) * sint price_n \<le> uint ?trade"
        using int_div_mult_le [OF pn, of "uint ?trade"] .
      have product_eq:
          "sint result * sint price_n =
           (uint ?trade div sint price_n) * sint price_n"
        using result_sint
        by (rule arg_cong[where f="\<lambda>x. x * sint price_n"])
      show ?thesis
        using product_eq quotient_product by linarith
    qed
    have product_uint:
        "uint ?product_word = sint result * sint price_n"
      using big_multiply_uint_value
        [of result "scast price_n :: int64"]
        less_imp_le[OF result_positive] less_imp_le[OF pn]
      by simp
    have trade_le_product: "uint ?trade \<le> sint result * sint price_n"
    proof -
      have "?trade \<le> ?product_word"
        by simp
      then show ?thesis
        using product_uint by (simp add: word_le_def)
    qed
    have trade_uint: "uint ?trade = sint result * sint price_n"
      using product_le_trade trade_le_product by simp
    have trade_word: "?trade = ?product_word"
    proof (rule word_uint_eqI)
      show "uint ?trade = uint ?product_word"
        using trade_uint product_uint by linarith
    qed
    have product_le_global_word:
        "?product_word \<le>
         (word_of_int (sint int64_max * sint price_d) :: uint128)"
    proof -
      have product_le_trade: "?product_word \<le> ?trade"
        using trade_word by (simp only: trade_word order_refl)
      have trade_le_global:
          "?trade \<le>
           (word_of_int (sint int64_max * sint price_d) :: uint128)"
        by (meson min.cobounded2 order_trans)
      show ?thesis
        using product_le_trade trade_le_global by (rule order_trans)
    qed
    have full_wheat_value:
        "calculate_offer_value price_n price_d result int64_max =
          Cxx_Ok ?product_word"
    proof -
      have full_pre:
          "calculate_offer_value_pre price_n price_d result int64_max"
        using pn pd result_positive
        by (simp add: calculate_offer_value_pre_def int64_max_def)
      show ?thesis
        using calculate_offer_value_success [OF full_pre]
          product_le_global_word
        by (simp add: min_def)
    qed
    let ?global_word =
      "word_of_int (sint int64_max * sint price_d) :: uint128"
    have global_uint:
        "uint ?global_word = sint int64_max * sint price_d"
      using big_multiply_uint_value
        [of int64_max "scast price_d :: int64"]
        less_imp_le[OF pd]
      by (simp add: int64_max_def)
    have sheep_is_global: "sheep_value = ?global_word"
    proof (rule word_uint_eqI)
      show "uint sheep_value = uint ?global_word"
        using sheep_value_uint global_uint wheat_more
        by (simp add: int64_max_def min_def mult_left_mono)
    qed
    have full_no_stays: "\<not> ?product_word > sheep_value"
      using product_le_global_word sheep_is_global by simp
    have full_amounts:
        "exchange_v10_amounts price_n price_d ?product_word sheep_value result
           int64_max int64_max int64_max False Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (result, sheep_send)"
      using wheat_more first_divide second_divide trade_word result_wheat
      by (simp add: exchange_v10_amounts_def)
    have full_before:
        "exchange_v10_without_price_error_thresholds_with_options price_n price_d result
           int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (make_exchange_result result sheep_send False)"
      unfolding exchange_v10_without_as_checked_amounts
      apply (simp only: full_wheat_value cxx_bind.simps)
      apply (simp only: sheep_value cxx_bind.simps)
      apply (simp only: Let_def full_no_stays full_amounts cxx_bind.simps)
      unfolding check_exchange_v10_result_def
      using result_positive sheep_send_nonnegative sint64_upper_bound[of result]
        sint64_upper_bound[of sheep_send]
      by (simp add: Let_def make_exchange_result_def int64_max_def)
    have final_original:
        "final = make_exchange_result wheat_receive sheep_send False"
      using final_choice result_final result_positive
      by (auto simp add: make_exchange_result_def)
    have full_exchange:
        "exchange_v10_with_options price_n price_d result int64_max int64_max int64_max
           Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (make_exchange_result result sheep_send False)"
      using full_before threshold result_wheat final_original
      by (simp add: exchange_v10_with_options_def make_exchange_result_def)
    show ?thesis
      using full_exchange
      by (simp add: adjust_offer_with_options_def make_exchange_result_def)
  next
    case not_wheat_more: False
    have stable_false:
        "adjust_offer_with_options price_n price_d result max_sheep \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok result"
      using stable adjust_offer_exact_irrelevant_if_not_wheat_more
        [OF not_wheat_more, of result max_sheep]
      by simp
    have old_pre:
        "exchange_v10_pre price_n price_d result int64_max int64_max
          max_sheep"
      using pn pd result_positive sheep_nonnegative
      by (simp add: exchange_v10_pre_def int64_max_def)
    let ?old_amounts =
      "exchange_v10_amounts_int price_n price_d result int64_max int64_max
         max_sheep Exchange_Normal"
    note old_characterization =
      exchange_v10_normal_characterization [OF old_pre]
    have result_word:
        "result = (word_of_int (fst ?old_amounts) :: int64)"
      using stable_false old_characterization result_positive
      by (auto simp add: adjust_offer_with_options_def make_exchange_result_def Let_def
          split: if_splits)
    have old_condition:
        "0 < fst ?old_amounts \<and> 0 < snd ?old_amounts \<and>
         price_error_bound_spec price_n price_d
           (word_of_int (fst ?old_amounts))
           (word_of_int (snd ?old_amounts)) False"
      using stable_false old_characterization result_positive
      by (auto simp add: adjust_offer_with_options_def make_exchange_result_def Let_def
          split: if_splits)
    note old_words =
      exchange_v10_amounts_integer_characterization
        [OF old_pre, of Exchange_Normal]
    have result_sint: "sint result = fst ?old_amounts"
      using result_word old_words(2) by simp
    have result_le_max: "sint result \<le> sint int64_max"
      using sint64_upper_bound[of result]
      by (simp add: int64_max_def)
    have result_product_bounded:
        "sint result * sint price_n \<le>
         sint int64_max * sint price_n"
      using result_le_max less_imp_le[OF pn]
      by (simp add: mult_right_mono)
    have old_stays_false:
        "\<not> exchange_wheat_value_int price_n price_d result max_sheep >
          exchange_sheep_value_int price_n price_d int64_max int64_max"
    proof -
      have price_order: "sint price_n \<le> sint price_d"
        using not_wheat_more by simp
      have global_sheep_value:
          "exchange_sheep_value_int price_n price_d int64_max int64_max =
           sint int64_max * sint price_n"
        using price_order
        by (simp add: exchange_sheep_value_int_def int64_max_def min_def
            mult_left_mono)
      have old_wheat_le:
          "exchange_wheat_value_int price_n price_d result max_sheep \<le>
           sint result * sint price_n"
        by (simp add: exchange_wheat_value_int_def)
      show ?thesis
        using old_wheat_le result_product_bounded global_sheep_value by simp
    qed
    let ?old_wheat =
      "exchange_wheat_value_int price_n price_d result max_sheep"
    let ?old_units = "?old_wheat div sint price_d"
    have old_formula:
        "?old_amounts =
          ((?old_units * sint price_d + sint price_n - 1) div sint price_n,
           ?old_units)"
      using not_wheat_more old_stays_false
      by (simp add: exchange_v10_amounts_int_def Let_def)
    have result_formula:
        "sint result =
         (?old_units * sint price_d + sint price_n - 1) div sint price_n"
      using result_sint old_formula by simp
    have units_nonnegative: "0 \<le> ?old_units"
      using exchange_wheat_value_int_bounds [OF old_pre] pd
      by (simp add: pos_imp_zdiv_nonneg_iff)
    have units_product_lower:
        "?old_units * sint price_d \<le> sint result * sint price_n"
      unfolding result_formula
      using int_le_ceiling_div_mult
        [OF pn, of "?old_units * sint price_d"] .
    have units_product_upper:
        "sint result * sint price_n \<le>
         ?old_units * sint price_d + sint price_n - 1"
      unfolding result_formula
      using int_div_mult_le
        [OF pn, of "?old_units * sint price_d + sint price_n - 1"] .
    have full_units_lower:
        "?old_units \<le>
         (sint result * sint price_n) div sint price_d"
    proof -
      have "(?old_units * sint price_d) div sint price_d \<le>
          (sint result * sint price_n) div sint price_d"
        using zdiv_mono1 [OF units_product_lower pd] .
      then show ?thesis using pd by simp
    qed
    have full_units_upper:
        "(sint result * sint price_n) div sint price_d \<le> ?old_units"
    proof (rule ccontr)
      assume not_bounded:
          "\<not> (sint result * sint price_n) div sint price_d \<le>
            ?old_units"
      have next_unit:
          "?old_units + 1 \<le>
           (sint result * sint price_n) div sint price_d"
        using zless_imp_add1_zle not_bounded by simp
      have next_multiple:
          "?old_units * sint price_d + sint price_d \<le>
           ((sint result * sint price_n) div sint price_d) * sint price_d"
        using mult_right_mono [OF next_unit less_imp_le[OF pd]]
        by (simp add: algebra_simps)
      have divided_lower:
          "((sint result * sint price_n) div sint price_d) * sint price_d \<le>
           sint result * sint price_n"
        using int_div_mult_le [OF pd] .
      show False
        using next_multiple divided_lower units_product_upper not_wheat_more
        by linarith
    qed
    have full_units:
        "(sint result * sint price_n) div sint price_d = ?old_units"
      using full_units_lower full_units_upper by simp
    have full_wheat_value:
        "exchange_wheat_value_int price_n price_d result int64_max =
         sint result * sint price_n"
    proof -
      have price_order: "sint price_n \<le> sint price_d"
        using not_wheat_more by simp
      have first:
          "sint result * sint price_n \<le>
           sint int64_max * sint price_n"
        using result_product_bounded .
      have second:
          "sint int64_max * sint price_n \<le>
           sint int64_max * sint price_d"
        using price_order
        by (simp add: int64_max_def mult_left_mono)
      show ?thesis
        using first second
        by (simp add: exchange_wheat_value_int_def min_def)
    qed
    have full_stays_false:
        "\<not> exchange_wheat_value_int price_n price_d result int64_max >
          exchange_sheep_value_int price_n price_d int64_max int64_max"
      using result_product_bounded
      by (simp add: exchange_wheat_value_int_def
          exchange_sheep_value_int_def min_def split: if_splits)
    let ?full_amounts =
      "exchange_v10_amounts_int price_n price_d result int64_max int64_max
         int64_max Exchange_Normal"
    have full_formula:
        "?full_amounts = ?old_amounts"
      using not_wheat_more full_stays_false full_wheat_value full_units
        old_formula
      by (simp add: exchange_v10_amounts_int_def Let_def)
    have full_pre:
        "exchange_v10_pre price_n price_d result int64_max int64_max int64_max"
      using pn pd result_positive
      by (simp add: exchange_v10_pre_def int64_max_def)
    note full_characterization =
      exchange_v10_normal_characterization [OF full_pre]
    show ?thesis
      using full_characterization full_formula old_condition result_word
        full_stays_false
      by (simp add: adjust_offer_with_options_def make_exchange_result_def Let_def)
  qed
qed

lemma unlimited_positive_adjustment_identifies_liabilities:
  assumes amount_positive: "0 < sint amount"
    and unlimited:
      "adjust_offer_with_options price_n price_d amount int64_max \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok amount"
    and selling:
      "offer_selling_liabilities price_n price_d amount = Cxx_Ok selling"
    and buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
  shows "selling = amount" "0 < sint buying"
text \<open>
  Proof sketch: the unlimited adjustment and both liability helpers share the
  same pre-threshold exchange call.  Positive final wheat excludes normal
  mode's explicit two-zero threshold result, so the threshold preserves the
  pre-threshold record.  Its wheat field is therefore the adjusted amount and
  its sheep field is strictly positive, exactly identifying both liabilities.
\<close>
proof -
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d amount int64_max int64_max int64_max
         Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok exchanged"
    and wheat: "num_wheat_received exchanged = amount"
    using unlimited
    by (cases "exchange_v10_with_options price_n price_d amount int64_max int64_max
         int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>")
       (simp_all add: adjust_offer_with_options_def)
  have sheep_positive: "0 < sint (num_sheep_send exchanged)"
    using exchange_normal_positive_wheat_has_positive_sheep
      [OF exchange] amount_positive wheat
    by simp
  obtain before where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
         int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok before"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before) (num_sheep_send before)
         (result_wheat_stays before) Exchange_Normal = Cxx_Ok exchanged"
    using exchange
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         amount int64_max int64_max int64_max Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>")
       (simp_all add: exchange_v10_with_options_def)
  have exchanged_before: "exchanged = before"
    using thresholds amount_positive wheat
      apply_price_error_thresholds_characterization
    by (auto simp add: apply_price_error_thresholds_spec_def
        make_exchange_result_def Let_def split: if_splits)
  show "selling = amount"
    using selling before wheat exchanged_before
    by (simp add: offer_selling_liabilities_def)
  show "0 < sint buying"
    using buying before sheep_positive exchanged_before
    by (simp add: offer_buying_liabilities_def)
qed


lemma adjust_offer_congruent_sint_receive_cap:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_nonnegative: "0 \<le> sint amount"
    and first_nonnegative: "0 \<le> sint first_cap"
    and second_nonnegative: "0 \<le> sint second_cap"
    and cap_sint: "sint first_cap = sint second_cap"
  shows "adjust_offer_with_options price_n price_d amount first_cap
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    adjust_offer_with_options price_n price_d amount second_cap
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: the exchange reads receive caps only through their signed
  integer values.  Equal signed caps therefore give equal clipped wheat values,
  integer amount pairs, stays flags, and normal-mode adjustment results.
\<close>
proof -
  have first_pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max first_cap"
    using pn pd amount_nonnegative first_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  have second_pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max second_cap"
    using pn pd amount_nonnegative second_nonnegative
    by (simp add: exchange_v10_pre_def int64_max_def)
  have wheat_equal:
      "exchange_wheat_value_int price_n price_d amount first_cap =
       exchange_wheat_value_int price_n price_d amount second_cap"
    using cap_sint by (simp add: exchange_wheat_value_int_def)
  have amounts_equal:
      "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         first_cap Exchange_Normal =
       exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         second_cap Exchange_Normal"
    using wheat_equal
    by (simp add: exchange_v10_amounts_int_def Let_def)
  note first_characterization =
    exchange_v10_normal_characterization [OF first_pre]
  note second_characterization =
    exchange_v10_normal_characterization [OF second_pre]
  show ?thesis
    unfolding adjust_offer_with_options_def
    using first_characterization second_characterization wheat_equal
      amounts_equal
    by simp
qed

lemma unlimited_adjustment_explicit_filter_conditions:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and unlimited:
      "adjust_offer_with_options price_n price_d amount int64_max
        \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok amount"
  shows
    "sint amount * sint price_n \<le>
       int64_max_int * sint price_d \<and>
     (let buying =
        (sint amount * sint price_n) div sint price_d
      in let wheat =
        (if sint price_n > sint price_d
         then (buying * sint price_d) div sint price_n
         else (buying * sint price_d + sint price_n - 1) div sint price_n)
      in (sint price_n > sint price_d \<or> wheat = sint amount) \<and>
         0 < buying \<and>
         abs (100 * sint price_n * sint amount -
           100 * sint price_d * buying) \<le>
             sint price_n * sint amount)"
text \<open>
  Proof sketch: invert the positive unlimited adjustment through the normal
  exchange characterization.  Its wheat field equals the input amount, which
  forces the price product below the signed receive cap and identifies the
  integer amount pair with the full offer and its floor-rounded buying amount.
  Positivity and the successful threshold branch then give the remaining
  explicit arithmetic conjuncts.
\<close>
proof -
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d amount int64_max int64_max int64_max
         Exchange_Normal
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok exchanged"
    and wheat_result: "num_wheat_received exchanged = amount"
    using unlimited
    by (cases "exchange_v10_with_options price_n price_d amount int64_max int64_max
         int64_max Exchange_Normal
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>")
       (simp_all add: adjust_offer_with_options_def)
  have pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  let ?amounts =
    "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
       int64_max Exchange_Normal"
  note characterization =
    exchange_v10_normal_characterization [OF pre]
  have amounts_positive:
      "0 < fst ?amounts \<and> 0 < snd ?amounts"
    and price_ok:
      "price_error_bound_spec price_n price_d
         (word_of_int (fst ?amounts)) (word_of_int (snd ?amounts)) False"
    and wheat_word:
      "(word_of_int (fst ?amounts) :: int64) = amount"
    using characterization exchange wheat_result amount_positive
    by (auto simp add: make_exchange_result_def Let_def split: if_splits)
  have fst_amounts: "fst ?amounts = sint amount"
  proof -
    have sint_fst:
        "sint (word_of_int (fst ?amounts) :: int64) = fst ?amounts"
      using exchange_v10_amounts_integer_characterization(2)
        [OF pre, where rounding = Exchange_Normal] .
    show ?thesis
      using sint_fst wheat_word by simp
  qed
  have no_stays: "\<not> result_wheat_stays exchanged"
    using exchange_against_unlimited_counterparty_does_not_leave_wheat
      [OF pn pd less_imp_le [OF amount_positive] _ exchange]
    by (simp add: int64_max_def)
  have stays_false:
      "\<not> exchange_wheat_value_int price_n price_d amount int64_max >
         exchange_sheep_value_int price_n price_d int64_max int64_max"
    using characterization exchange no_stays
    by (auto simp add: make_exchange_result_def Let_def split: if_splits)
  have amount_max: "sint amount \<le> int64_max_int"
    using sint64_upper_bound [of amount] by simp
  have price_cases:
      "sint price_n \<le> sint price_d \<or> sint price_d < sint price_n"
    using linorder_class.le_less_linear
      [of "sint price_n" "sint price_d"] .
  have unsaturated:
      "sint amount * sint price_n \<le>
       int64_max_int * sint price_d"
    using price_cases
  proof
    assume not_more: "sint price_n \<le> sint price_d"
    have first:
        "sint amount * sint price_n \<le>
         int64_max_int * sint price_n"
      using mult_right_mono [OF amount_max less_imp_le [OF pn]] .
    have second:
        "int64_max_int * sint price_n \<le>
         int64_max_int * sint price_d"
      using mult_left_mono
        [OF not_more, of int64_max_int] by simp
    show ?thesis
      using first second by linarith
  next
    assume wheat_more: "sint price_d < sint price_n"
    have fst_formula:
        "fst ?amounts =
         (min (sint amount * sint price_n)
           (int64_max_int * sint price_d)) div sint price_n"
      using stays_false wheat_more
      by (simp add: exchange_v10_amounts_int_def
          exchange_wheat_value_int_def exchange_sheep_value_int_def
          int64_max_def Let_def min_def split: if_splits)
    have floor_multiple:
        "((min (sint amount * sint price_n)
            (int64_max_int * sint price_d)) div sint price_n) *
           sint price_n \<le>
         min (sint amount * sint price_n)
           (int64_max_int * sint price_d)"
      using int_div_mult_le [OF pn, of
        "min (sint amount * sint price_n)
          (int64_max_int * sint price_d)"] .
    show ?thesis
      using floor_multiple fst_formula fst_amounts by simp
  qed
  let ?buying =
    "(sint amount * sint price_n) div sint price_d"
  let ?minimum_wheat =
    "if sint price_n > sint price_d
     then (?buying * sint price_d) div sint price_n
     else (?buying * sint price_d + sint price_n - 1) div sint price_n"
  have wheat_value:
      "exchange_wheat_value_int price_n price_d amount int64_max =
       sint amount * sint price_n"
    using unsaturated
    by (simp add: exchange_wheat_value_int_def int64_max_def min_def)
  have amounts_formula:
      "?amounts =
       (if sint price_n > sint price_d
        then (sint amount, ?buying)
        else (?minimum_wheat, ?buying))"
    unfolding exchange_v10_amounts_int_def
    apply (simp only: Let_def stays_false if_False)
    using wheat_value pn pd
    by (cases "sint price_n > sint price_d") simp_all
  have full_wheat:
      "sint price_n > sint price_d \<or> ?minimum_wheat = sint amount"
    using fst_amounts amounts_formula
    by (cases "sint price_n > sint price_d") simp_all
  have buying_positive: "0 < ?buying"
    using amounts_positive amounts_formula
    by (cases "sint price_n > sint price_d") simp_all
  have buying_word:
      "sint (word_of_int ?buying :: int64) = ?buying"
    using exchange_v10_amounts_integer_characterization(3)
      [OF pre, where rounding = Exchange_Normal] amounts_formula
    by (cases "sint price_n > sint price_d") simp_all
  have price_ok_full:
      "price_error_bound_spec price_n price_d amount
         (word_of_int ?buying) False"
    using price_ok amounts_formula wheat_word
    by (cases "sint price_n > sint price_d") simp_all
  have full_threshold:
      "abs (100 * sint price_n * sint amount -
        100 * sint price_d * ?buying) \<le>
          sint price_n * sint amount"
    using price_ok_full buying_word
    unfolding price_error_bound_spec_def Let_def
    by simp
  show ?thesis
    using unsaturated full_wheat buying_positive full_threshold
    by (simp add: Let_def)
qed

lemma minimum_adjustment_explicit_filter_conditions:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and unsaturated:
      "sint amount * sint price_n \<le>
       int64_max_int * sint price_d"
    and minimum:
      "adjust_offer_with_options price_n price_d amount
        (word_of_int
          ((sint amount * sint price_n) div sint price_d))
        \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok adjusted"
    and adjusted_positive: "0 < sint adjusted"
  shows
    "(let buying =
       (sint amount * sint price_n) div sint price_d
     in let wheat =
       (if sint price_n > sint price_d
        then (buying * sint price_d) div sint price_n
        else (buying * sint price_d + sint price_n - 1) div sint price_n)
     in let sheep =
       (if sint price_n > sint price_d
        then (wheat * sint price_n) div sint price_d
        else buying)
     in 0 < wheat \<and>
        0 < sheep \<and>
        abs (100 * sint price_n * wheat -
          100 * sint price_d * sheep) \<le> sint price_n * wheat)"
text \<open>
  Proof sketch: the cap is the explicit floor-rounded buying liability.  Its
  signed representation is in range, and Euclidean division makes the clipped
  wheat value exactly the floor times the denominator.  The normal exchange
  therefore computes exactly the filter's \<open>wheat\<close> and \<open>sheep\<close> pair.  Inverting
  the positive successful adjustment gives positivity of both components and
  its successful one-percent threshold check.
\<close>
proof -
  let ?n = "sint price_n"
  let ?d = "sint price_d"
  let ?a = "sint amount"
  let ?b = "(?a * ?n) div ?d"
  let ?w =
    "if ?n > ?d
     then (?b * ?d) div ?n
     else (?b * ?d + ?n - 1) div ?n"
  let ?s =
    "if ?n > ?d
     then (?w * ?n) div ?d
     else ?b"
  let ?cap = "(word_of_int ?b :: int64)"
  have product_nonnegative: "0 \<le> ?a * ?n"
    using amount_positive pn by simp
  have buying_nonnegative: "0 \<le> ?b"
    using product_nonnegative pd
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have buying_max: "?b \<le> int64_max_int"
  proof -
    have "(?a * ?n) div ?d \<le>
        (int64_max_int * ?d) div ?d"
      using zdiv_mono1 [OF unsaturated pd] .
    then show ?thesis using pd by simp
  qed
  have cap_sint: "sint ?cap = ?b"
    using sint_word_of_int_nonnegative_int64
      [OF buying_nonnegative buying_max] .
  have floor_multiple: "?b * ?d \<le> ?a * ?n"
    using int_div_mult_le [OF pd, of "?a * ?n"] .
  have pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max ?cap"
    using pn pd amount_positive buying_nonnegative cap_sint
    by (simp add: exchange_v10_pre_def int64_max_def)
  have amount_max: "?a \<le> int64_max_int"
    using sint64_upper_bound [of amount] by simp
  have wheat_value:
      "exchange_wheat_value_int price_n price_d amount ?cap = ?b * ?d"
    using cap_sint floor_multiple
    by (simp add: exchange_wheat_value_int_def min_def)
  have stays_false:
      "\<not> exchange_wheat_value_int price_n price_d amount ?cap >
         exchange_sheep_value_int price_n price_d int64_max int64_max"
  proof (cases "?n > ?d")
    case True
    then show ?thesis
      using unsaturated floor_multiple cap_sint
      by (simp add: exchange_wheat_value_int_def
          exchange_sheep_value_int_def int64_max_def min_def
          mult_left_mono mult_right_mono split: if_splits)
  next
    case False
    have "?a * ?n \<le> int64_max_int * ?n"
      using amount_max less_imp_le [OF pn]
      by (simp add: mult_right_mono)
    then show ?thesis
      using False floor_multiple cap_sint
      by (simp add: exchange_wheat_value_int_def
          exchange_sheep_value_int_def int64_max_def min_def
          mult_left_mono mult_right_mono split: if_splits)
  qed
  have amounts:
      "exchange_v10_amounts_int price_n price_d amount int64_max
         int64_max ?cap Exchange_Normal = (?w, ?s)"
    unfolding exchange_v10_amounts_int_def
    apply (simp only: Let_def stays_false if_False)
    using wheat_value pd
    by (cases "?n > ?d") simp_all
  obtain exchanged where exchange:
      "exchange_v10_with_options price_n price_d amount int64_max int64_max ?cap
         Exchange_Normal
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok exchanged"
    and wheat_result: "num_wheat_received exchanged = adjusted"
    using minimum
    by (cases "exchange_v10_with_options price_n price_d amount int64_max int64_max
         ?cap Exchange_Normal
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>")
       (simp_all add: adjust_offer_with_options_def)
  note characterization =
    exchange_v10_normal_characterization [OF pre]
  have amounts_positive:
      "0 < fst
        (exchange_v10_amounts_int price_n price_d amount int64_max
          int64_max ?cap Exchange_Normal) \<and>
       0 < snd
        (exchange_v10_amounts_int price_n price_d amount int64_max
          int64_max ?cap Exchange_Normal)"
    and price_ok:
      "price_error_bound_spec price_n price_d
        (word_of_int
          (fst (exchange_v10_amounts_int price_n price_d amount int64_max
            int64_max ?cap Exchange_Normal)))
        (word_of_int
          (snd (exchange_v10_amounts_int price_n price_d amount int64_max
            int64_max ?cap Exchange_Normal))) False"
    using characterization exchange wheat_result adjusted_positive
    by (auto simp add: make_exchange_result_def Let_def split: if_splits)
  have wheat_positive: "0 < ?w"
    and sheep_positive: "0 < ?s"
    using amounts_positive amounts by simp_all
  have wheat_word:
      "sint (word_of_int ?w :: int64) = ?w"
    using exchange_v10_amounts_integer_characterization(2)
      [OF pre, where rounding = Exchange_Normal] amounts
    by simp
  have sheep_word:
      "sint (word_of_int ?s :: int64) = ?s"
    using exchange_v10_amounts_integer_characterization(3)
      [OF pre, where rounding = Exchange_Normal] amounts
    by simp
  have threshold:
      "abs (100 * ?n * ?w - 100 * ?d * ?s) \<le> ?n * ?w"
    using price_ok amounts wheat_word sheep_word
    unfolding price_error_bound_spec_def Let_def
    by simp
  show ?thesis
    using wheat_positive sheep_positive threshold
    by (simp add: Let_def)
qed

lemma unlimited_adjustment_identifies_buying_liability:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    and unlimited:
      "adjust_offer_with_options price_n price_d amount int64_max
        \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok amount"
  shows "offer_buying_liabilities price_n price_d amount =
    Cxx_Ok
      (word_of_int
        ((sint amount * sint price_n) div sint price_d))"
text \<open>
  Proof sketch: the explicit unlimited conditions identify the pre-threshold
  normal amount pair as the full offered wheat amount and the floor-rounded
  buying amount.  The liability helper selects the sheep field of exactly that
  pre-threshold exchange.
\<close>
proof -
  note explicit =
    unlimited_adjustment_explicit_filter_conditions
      [OF pn pd amount_positive unlimited]
  have unsaturated:
      "sint amount * sint price_n \<le>
       int64_max_int * sint price_d"
    using explicit by blast
  let ?b = "(sint amount * sint price_n) div sint price_d"
  let ?w =
    "if sint price_n > sint price_d
     then (?b * sint price_d) div sint price_n
     else (?b * sint price_d + sint price_n - 1) div sint price_n"
  have full_wheat:
      "sint price_n > sint price_d \<or> ?w = sint amount"
    using explicit by (simp add: Let_def)
  have pre:
      "exchange_v10_pre price_n price_d amount int64_max int64_max int64_max"
    using pn pd amount_positive
    by (simp add: exchange_v10_pre_def int64_max_def)
  have wheat_value:
      "exchange_wheat_value_int price_n price_d amount int64_max =
       sint amount * sint price_n"
    using unsaturated
    by (simp add: exchange_wheat_value_int_def int64_max_def min_def)
  have amount_max: "sint amount \<le> int64_max_int"
    using sint64_upper_bound [of amount] by simp
  have stays_false:
      "\<not> exchange_wheat_value_int price_n price_d amount int64_max >
         exchange_sheep_value_int price_n price_d int64_max int64_max"
  proof (cases "sint price_n > sint price_d")
    case True
    then show ?thesis
      using unsaturated
      by (simp add: exchange_wheat_value_int_def
          exchange_sheep_value_int_def int64_max_def min_def
          mult_left_mono mult_right_mono split: if_splits)
  next
    case False
    have "sint amount * sint price_n \<le>
        int64_max_int * sint price_n"
      using amount_max less_imp_le [OF pn]
      by (simp add: mult_right_mono)
    then show ?thesis
      using False
      by (simp add: exchange_wheat_value_int_def
          exchange_sheep_value_int_def int64_max_def min_def
          mult_left_mono mult_right_mono split: if_splits)
  qed
  have amounts:
      "exchange_v10_amounts_int price_n price_d amount int64_max int64_max
         int64_max Exchange_Normal = (sint amount, ?b)"
    unfolding exchange_v10_amounts_int_def
    apply (simp only: Let_def stays_false if_False)
    using wheat_value pn full_wheat
    by (cases "sint price_n > sint price_d") simp_all
  note exact =
    exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, where rounding = Exchange_Normal]
  have before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d amount
         int64_max int64_max int64_max Exchange_Normal
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok
         (make_exchange_result amount (word_of_int ?b) False)"
    using exact amounts stays_false
    by simp
  show ?thesis
    using before
    by (simp add: offer_buying_liabilities_def make_exchange_result_def)
qed

lemma acquired_offer_is_covered:
  assumes wf: "party_state_wf maker"
    and acquire:
      "acquire_offer_liabilities price_n price_d amount maker =
        Cxx_Ok maker_after"
  shows "maker_covers_offer_liabilities price_n price_d amount maker_after"
text \<open>
  Proof sketch: successful acquisition adds the offer's two nonnegative
  liabilities to the maker's existing nonnegative totals under checked caps.
  Decoding the checked sums therefore shows that each new total covers the
  corresponding offer liability.
\<close>
proof -
  obtain buying where buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    using acquire
    by (cases "offer_buying_liabilities price_n price_d amount")
       (auto simp add: acquire_offer_liabilities_def)
  obtain new_buying where new_buying:
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
    using acquire buying new_buying
    by (cases "offer_selling_liabilities price_n price_d amount")
       (auto simp add: acquire_offer_liabilities_def)
  obtain new_selling where new_selling:
      "add_liability_checked (sint (sell_balance maker))
         (sell_liabilities maker) (sint selling) = Cxx_Ok new_selling"
    using acquire buying new_buying selling
    by (cases "add_liability_checked (sint (sell_balance maker))
         (sell_liabilities maker) (sint selling)")
       (auto simp add: acquire_offer_liabilities_def)
  have maker_after:
      "maker_after =
       maker\<lparr>buy_liabilities := new_buying,
         sell_liabilities := new_selling\<rparr>"
    using acquire buying new_buying selling new_selling
    by (simp add: acquire_offer_liabilities_def)
  have old_buy_nonnegative: "0 \<le> sint (buy_liabilities maker)"
    using wf by (simp add: party_state_wf_def)
  have buy_balance_nonnegative: "0 \<le> sint (buy_balance maker)"
    using wf by (simp add: party_state_wf_def)
  have buy_sum_nonnegative:
      "0 \<le> sint (buy_liabilities maker) + sint buying"
    and buy_sum_cap:
      "sint (buy_liabilities maker) + sint buying \<le>
       sint (buy_limit maker) - sint (buy_balance maker)"
    and new_buying_word:
      "new_buying =
       word_of_int (sint (buy_liabilities maker) + sint buying)"
    using new_buying
    by (auto simp add: add_liability_checked_def Let_def split: if_splits)
  have buy_sum_max:
      "sint (buy_liabilities maker) + sint buying \<le> int64_max_int"
    using buy_sum_cap buy_balance_nonnegative
      sint64_upper_bound [of "buy_limit maker"]
    by linarith
  have new_buying_sint:
      "sint new_buying =
       sint (buy_liabilities maker) + sint buying"
    unfolding new_buying_word
    using sint_word_of_int_nonnegative_int64
      [OF buy_sum_nonnegative buy_sum_max] .
  have buying_covered: "sint buying \<le> sint new_buying"
    using old_buy_nonnegative new_buying_sint by linarith
  have old_sell_nonnegative: "0 \<le> sint (sell_liabilities maker)"
    using wf by (simp add: party_state_wf_def)
  have sell_sum_nonnegative:
      "0 \<le> sint (sell_liabilities maker) + sint selling"
    and sell_sum_cap:
      "sint (sell_liabilities maker) + sint selling \<le>
       sint (sell_balance maker)"
    and new_selling_word:
      "new_selling =
       word_of_int (sint (sell_liabilities maker) + sint selling)"
    using new_selling
    by (auto simp add: add_liability_checked_def Let_def split: if_splits)
  have sell_sum_max:
      "sint (sell_liabilities maker) + sint selling \<le> int64_max_int"
    using sell_sum_cap sint64_upper_bound [of "sell_balance maker"]
    by linarith
  have new_selling_sint:
      "sint new_selling =
       sint (sell_liabilities maker) + sint selling"
    unfolding new_selling_word
    using sint_word_of_int_nonnegative_int64
      [OF sell_sum_nonnegative sell_sum_max] .
  have selling_covered: "sint selling \<le> sint new_selling"
    using old_sell_nonnegative new_selling_sint by linarith
  show ?thesis
    using selling buying selling_covered buying_covered maker_after
    by (simp add: maker_covers_offer_liabilities_def)
qed

lemma post_created_acquires_posted_liabilities:
  assumes post:
    "post_offer price_n price_d amount maker options =
      Cxx_Ok (Post_Created posted maker_after)"
  shows "acquire_offer_liabilities price_n price_d posted maker =
    Cxx_Ok maker_after"
text \<open>
  Proof sketch: invert the successful-created branch of @{const post_offer}.
  Its adjusted amount is exactly \<open>posted\<close>, and the party state paired with that
  amount is exactly the result of acquiring its liabilities.
\<close>
proof -
  have valid:
      "\<not> (sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or> sint amount \<le> 0)"
    using post
    by (auto simp add: post_offer_def split: if_splits)
  obtain preflight where preflight:
      "preflight_offer price_n price_d amount maker = Cxx_Ok preflight"
    using post valid
    by (cases "preflight_offer price_n price_d amount maker")
       (auto simp add: post_offer_def)
  obtain max_sheep_send max_wheat_receive where preflight_ready:
      "preflight = Preflight_Ready max_sheep_send max_wheat_receive"
    using post valid preflight
    by (cases preflight)
       (auto simp add: post_offer_def)
  obtain adjusted where adjustment:
      "adjust_offer_with_options price_n price_d max_sheep_send max_wheat_receive options =
       Cxx_Ok adjusted"
    using post valid preflight preflight_ready
    by (cases "adjust_offer_with_options price_n price_d max_sheep_send
         max_wheat_receive options")
       (auto simp add: post_offer_def)
  have adjusted_positive: "0 < sint adjusted"
    using post valid preflight preflight_ready adjustment
    by (auto simp add: post_offer_def split: if_splits)
  obtain acquired where acquire:
      "acquire_offer_liabilities price_n price_d adjusted maker =
       Cxx_Ok acquired"
    using post valid preflight preflight_ready adjustment adjusted_positive
    by (cases "acquire_offer_liabilities price_n price_d adjusted maker")
       (auto simp add: post_offer_def)
  have result:
      "Post_Created adjusted acquired =
       Post_Created posted maker_after"
    using post valid preflight preflight_ready adjustment adjusted_positive
      acquire
    by (simp add: post_offer_def)
  then have adjusted_posted: "adjusted = posted"
    and acquired_after: "acquired = maker_after"
    by simp_all
  show ?thesis
    using acquire adjusted_posted acquired_after by simp
qed

theorem posted_offers_remain_takeable_exact:
  "posted_offers_remain_takeable \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: a successful post supplies positive prices and a positive
  adjusted amount.  Liability coverage lets crossing release the posted
  liabilities and leaves enough selling capacity for the entire offer and
  enough exact receive capacity for its rounded payment, so the preventative
  adjustment returns the posted amount unchanged.  Choose a taker with
  maximum selling balance and buying limit.  Its crossing exchange is the
  same positive adjustment calculation; the exchange bounds make every
  guarded balance movement succeed, and consuming the full posted amount
  leaves no liability to reacquire.
\<close>
proof -
  show ?thesis
    unfolding posted_offers_remain_takeable_def
  proof (intro allI impI)
    fix price_n price_d amount maker_at_post posted maker_after
      maker_at_cross
    assume lifecycle_premises:
      "party_state_wf maker_at_post \<and>
       party_state_wf maker_at_cross \<and>
       post_offer price_n price_d amount maker_at_post \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (Post_Created posted maker_after) \<and>
       maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
    then obtain post_wf cross_wf post cover where
      post_wf: "party_state_wf maker_at_post"
      and cross_wf: "party_state_wf maker_at_cross"
      and post:
        "post_offer price_n price_d amount maker_at_post \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok (Post_Created posted maker_after)"
      and cover:
        "maker_covers_offer_liabilities price_n price_d posted
          maker_at_cross"
      by blast
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
    obtain adjusted where adjusted:
        "adjust_offer_with_options price_n price_d
           (signed_min64 amount (can_sell_at_most maker_at_post))
           (can_buy_at_most maker_at_post) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok adjusted"
      using post' requested_buying requested_selling
      by (cases "adjust_offer_with_options price_n price_d
           (signed_min64 amount (can_sell_at_most maker_at_post))
           (can_buy_at_most maker_at_post) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>")
         (simp_all split: if_splits)
    obtain acquired where acquired:
        "acquire_offer_liabilities price_n price_d adjusted maker_at_post =
          Cxx_Ok acquired"
      using post' requested_buying requested_selling adjusted
      by (cases "acquire_offer_liabilities price_n price_d adjusted
           maker_at_post")
         (simp_all split: if_splits)
    have adjusted_posted: "adjusted = posted"
      using post' requested_buying requested_selling adjusted acquired
      by (simp split: if_splits)
    have posting_adjustment:
        "adjust_offer_with_options price_n price_d
           (signed_min64 amount (can_sell_at_most maker_at_post))
           (can_buy_at_most maker_at_post) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
      using adjusted adjusted_posted by simp

    have post_sell_nonnegative:
        "0 \<le> sint (can_sell_at_most maker_at_post)"
      using can_sell_at_most_nonnegative [OF post_wf] .
    have post_buy_nonnegative:
        "0 \<le> sint (can_buy_at_most maker_at_post)"
      using can_buy_at_most_nonnegative [OF post_wf] .
    have posting_send_nonnegative:
        "0 \<le> sint
          (signed_min64 amount (can_sell_at_most maker_at_post))"
      using amount_positive post_sell_nonnegative
      by (auto simp add: signed_min64_def split: if_splits)
    have unlimited_adjustment:
        "adjust_offer_with_options price_n price_d posted int64_max \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok posted"
      using positive_adjustment_replays_unlimited
        [OF pn pd posting_send_nonnegative post_buy_nonnegative
          posting_adjustment posted_positive] .

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
        [OF pn pd less_imp_le[OF posted_positive] cross_wf cover]
      by blast
    have selling_posted: "selling = posted"
      and buying_positive: "0 < sint buying"
      using unlimited_positive_adjustment_identifies_liabilities
        [OF posted_positive unlimited_adjustment selling buying]
      by simp_all
    have posted_fits:
        "sint posted \<le> sint (can_sell_at_most released)"
      using selling_fits selling_posted by simp
    have released_buy_nonnegative:
        "0 \<le> sint (can_buy_at_most released)"
      using can_buy_at_most_nonnegative [OF released_wf] .
    have maker_send:
        "signed_min64 posted (can_sell_at_most released) = posted"
      using posted_fits by (simp add: signed_min64_def)
    have preventative_adjustment:
        "adjust_offer_with_options price_n price_d posted (can_buy_at_most released) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok posted"
      using exact_cap_replays_unlimited_positive_adjustment
        [OF pn pd posted_positive released_buy_nonnegative
          unlimited_adjustment buying buying_fits] .

    let ?taker =
      "\<lparr>sell_balance = int64_max, sell_liabilities = 0,
        buy_limit = int64_max, buy_balance = 0, buy_liabilities = 0\<rparr>"
    have taker_wf: "party_state_wf ?taker" by eval
    have taker_buy: "can_buy_at_most ?taker = int64_max" by eval
    have taker_sell: "can_sell_at_most ?taker = int64_max" by eval
    have taker_buy_positive: "0 < sint (can_buy_at_most ?taker)"
      using taker_buy by (simp add: int64_max_def)
    have taker_send:
        "signed_min64 int64_max (can_sell_at_most ?taker) = int64_max"
      using taker_sell by (simp add: signed_min64_def)
    have taker_send_positive:
        "0 < sint
          (signed_min64 int64_max (can_sell_at_most ?taker))"
      using taker_send by (simp add: int64_max_def)

    obtain exchanged where exchange:
        "exchange_v10_with_options price_n price_d posted int64_max int64_max
           (can_buy_at_most released) Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok exchanged"
      and wheat: "num_wheat_received exchanged = posted"
      using preventative_adjustment
      by (cases "exchange_v10_with_options price_n price_d posted int64_max int64_max
           (can_buy_at_most released) Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>")
         (simp_all add: adjust_offer_with_options_def)
    have wheat_positive:
        "0 < sint (num_wheat_received exchanged)"
      using posted_positive wheat by simp
    have sheep_positive:
        "0 < sint (num_sheep_send exchanged)"
      using exchange_normal_positive_wheat_has_positive_sheep
        [OF exchange wheat_positive] .
    note exchange_bounds =
      exchange_normal_positive_result_bounds_any_cap
        [OF exchange wheat_positive]
    have sheep_fits_maker:
        "sint (num_sheep_send exchanged) \<le>
          sint (can_buy_at_most released)"
      using exchange_bounds(2) by simp
    have wheat_fits_maker:
        "sint (num_wheat_received exchanged) \<le>
          sint (can_sell_at_most released)"
      using wheat posted_fits by simp
    have wheat_fits_taker:
        "sint (num_wheat_received exchanged) \<le>
          sint (can_buy_at_most ?taker)"
      using sint64_upper_bound[of "num_wheat_received exchanged"] taker_buy
      by (simp add: int64_max_def)
    have sheep_fits_taker:
        "sint (num_sheep_send exchanged) \<le>
          sint (can_sell_at_most ?taker)"
      using sint64_upper_bound[of "num_sheep_send exchanged"] taker_sell
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
    have wheat_fits_maker_credited:
        "sint (num_wheat_received exchanged) \<le>
          sint (can_sell_at_most maker_credited)"
      using wheat_fits_maker maker_sell_unchanged by simp
    obtain maker_moved where maker_spend:
        "party_spend_sell_asset maker_credited
           (num_wheat_received exchanged) = Cxx_Ok maker_moved"
      and maker_moved_wf: "party_state_wf maker_moved"
      using party_spend_within_capacity
        [OF maker_credited_wf wheat_positive wheat_fits_maker_credited]
      by blast
    obtain taker_credited where taker_receive:
        "party_receive_buy_asset ?taker (num_wheat_received exchanged) =
          Cxx_Ok taker_credited"
      and taker_credited_wf: "party_state_wf taker_credited"
      and taker_sell_unchanged:
        "can_sell_at_most taker_credited = can_sell_at_most ?taker"
      using party_receive_within_capacity
        [OF taker_wf wheat_positive wheat_fits_taker]
      by blast
    have sheep_fits_taker_credited:
        "sint (num_sheep_send exchanged) \<le>
          sint (can_sell_at_most taker_credited)"
      using sheep_fits_taker taker_sell_unchanged by simp
    obtain taker_after where taker_spend:
        "party_spend_sell_asset taker_credited (num_sheep_send exchanged) =
          Cxx_Ok taker_after"
      and taker_after_wf: "party_state_wf taker_after"
      using party_spend_within_capacity
        [OF taker_credited_wf sheep_positive sheep_fits_taker_credited]
      by blast
    have no_stays: "\<not> result_wheat_stays exchanged"
      using exchange_against_unlimited_counterparty_does_not_leave_wheat
        [OF pn pd less_imp_le[OF posted_positive]
          released_buy_nonnegative exchange] .

    let ?crossed =
      "make_cross_result (num_wheat_received exchanged)
         (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
         maker_moved taker_after"
    have crossed:
        "cross_offer_v10 price_n price_d posted maker_at_cross ?taker
           int64_max Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok ?crossed"
      using taker_buy taker_sell taker_send release maker_send
        preventative_adjustment exchange maker_receive maker_spend
        taker_receive taker_spend no_stays
      by (simp add: cross_offer_v10_def Let_def int64_max_def)
    show
      "\<exists>taker taker_amount crossed.
        party_state_wf taker \<and>
        0 < sint (can_buy_at_most taker) \<and>
        0 < sint
          (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
        cross_offer_v10 price_n price_d posted maker_at_cross taker
          taker_amount Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok crossed \<and>
        0 < sint (cross_wheat_received crossed) \<and>
        0 < sint (cross_sheep_send crossed)"
      using taker_wf taker_buy_positive taker_send_positive crossed
        wheat_positive sheep_positive
      by (intro exI[of _ ?taker] exI[of _ int64_max] exI[of _ ?crossed])
         (simp add: make_cross_result_def)
  qed
qed

subsubsection \<open>Coverage implies adjustment stability with the exact receive cap\<close>

text \<open>
  The proof factors the adjustment prefix already used by the exact-cap
  takeability theorem.  The symmetric maximality repair above does
  not affect this result: @{const adjust_offer_with_options} crosses against an unlimited
  counteroffer, so the wheat offer never stays and the repaired wheat-stays
  branch is unreachable.
\<close>

lemma post_created_replays_unlimited:
  assumes post_wf: "party_state_wf maker_at_post"
    and post:
      "post_offer price_n price_d amount maker_at_post \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
        Cxx_Ok (Post_Created posted maker_after)"
  shows "adjust_offer_with_options price_n price_d posted int64_max \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok posted"
  text \<open>
    Proof sketch: unfold the successful post to recover the exact positive
    adjustment result that produced the posted amount.  Party well-formedness
    makes both posting capacities non-negative.  The general replay lemma then
    shows that the positive result is unchanged when both capacities are made
    unlimited; at unlimited receive capacity the exact flag is inert.
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
  obtain adjusted where adjusted:
      "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok adjusted"
    using post' requested_buying requested_selling
    by (cases "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>")
       (simp_all split: if_splits)
  obtain acquired where acquired:
      "acquire_offer_liabilities price_n price_d adjusted maker_at_post =
        Cxx_Ok acquired"
    using post' requested_buying requested_selling adjusted
    by (cases "acquire_offer_liabilities price_n price_d adjusted
         maker_at_post")
       (simp_all split: if_splits)
  have adjusted_posted: "adjusted = posted"
    using post' requested_buying requested_selling adjusted acquired
    by (simp split: if_splits)
  have posting_adjustment:
      "adjust_offer_with_options price_n price_d
         (signed_min64 amount (can_sell_at_most maker_at_post))
         (can_buy_at_most maker_at_post) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
    using adjusted adjusted_posted by simp
  have post_sell_nonnegative:
      "0 \<le> sint (can_sell_at_most maker_at_post)"
    using can_sell_at_most_nonnegative [OF post_wf] .
  have post_buy_nonnegative:
      "0 \<le> sint (can_buy_at_most maker_at_post)"
    using can_buy_at_most_nonnegative [OF post_wf] .
  have posting_send_nonnegative:
      "0 \<le> sint
        (signed_min64 amount (can_sell_at_most maker_at_post))"
    using amount_positive post_sell_nonnegative
    by (auto simp add: signed_min64_def split: if_splits)
  show ?thesis
    using positive_adjustment_replays_unlimited
      [OF pn pd posting_send_nonnegative post_buy_nonnegative
        posting_adjustment posted_positive] .
qed

theorem cover_implies_adjust_stable_exact:
  "cover_implies_adjust_stable \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
  text \<open>
    Proof sketch: a successful post can be replayed as an unlimited adjustment
    returning the posted amount.  Liability coverage and release expose enough
    selling capacity for that amount and enough buying capacity for its booked
    rounded payment.  The exact receive cap turns those two capacity bounds
    back into the same adjustment result, so the crossing-time preventative
    adjustment is the identity.
  \<close>
proof -
  show ?thesis
    unfolding cover_implies_adjust_stable_def
  proof (intro allI impI)
    fix price_n price_d amount maker_at_post posted maker_after
      maker_at_cross released
    assume lifecycle_premises:
      "party_state_wf maker_at_post \<and>
       party_state_wf maker_at_cross \<and>
       post_offer price_n price_d amount maker_at_post \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (Post_Created posted maker_after) \<and>
       maker_covers_offer_liabilities price_n price_d posted
         maker_at_cross \<and>
       release_offer_liabilities price_n price_d posted maker_at_cross =
         Cxx_Ok released"
    have post_wf: "party_state_wf maker_at_post"
      using lifecycle_premises by blast
    have cross_wf: "party_state_wf maker_at_cross"
      using lifecycle_premises by blast
    have post:
        "post_offer price_n price_d amount maker_at_post \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok (Post_Created posted maker_after)"
      using lifecycle_premises by blast
    have cover:
        "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
      using lifecycle_premises by blast
    have release:
        "release_offer_liabilities price_n price_d posted maker_at_cross =
          Cxx_Ok released"
      using lifecycle_premises by blast
    note positive = post_created_positive_facts [OF post]
    have pn: "0 < sint price_n" and pd: "0 < sint price_d"
      and posted_positive: "0 < sint posted"
      using positive by simp_all
    have unlimited_adjustment:
        "adjust_offer_with_options price_n price_d posted int64_max \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok posted"
      using post_created_replays_unlimited [OF post_wf post] .
    obtain selling buying released' where selling:
        "offer_selling_liabilities price_n price_d posted = Cxx_Ok selling"
      and buying:
        "offer_buying_liabilities price_n price_d posted = Cxx_Ok buying"
      and release':
        "release_offer_liabilities price_n price_d posted maker_at_cross =
          Cxx_Ok released'"
      and released_wf': "party_state_wf released'"
      and selling_fits':
        "sint selling \<le> sint (can_sell_at_most released')"
      and buying_fits':
        "sint buying \<le> sint (can_buy_at_most released')"
      using covered_offer_release
        [OF pn pd less_imp_le[OF posted_positive] cross_wf cover]
      by blast
    have released_eq: "released' = released"
      using release release' by simp
    have released_wf: "party_state_wf released"
      using released_wf' released_eq by simp
    have selling_fits:
        "sint selling \<le> sint (can_sell_at_most released)"
      using selling_fits' released_eq by simp
    have buying_fits:
        "sint buying \<le> sint (can_buy_at_most released)"
      using buying_fits' released_eq by simp
    have selling_posted: "selling = posted"
      using unlimited_positive_adjustment_identifies_liabilities
        [OF posted_positive unlimited_adjustment selling buying]
      by simp
    have posted_fits:
        "sint posted \<le> sint (can_sell_at_most released)"
      using selling_fits selling_posted by simp
    have released_buy_nonnegative:
        "0 \<le> sint (can_buy_at_most released)"
      using can_buy_at_most_nonnegative [OF released_wf] .
    have maker_send:
        "signed_min64 posted (can_sell_at_most released) = posted"
      using posted_fits by (simp add: signed_min64_def)
    have preventative_adjustment:
        "adjust_offer_with_options price_n price_d posted (can_buy_at_most released) \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok posted"
      using exact_cap_replays_unlimited_positive_adjustment
        [OF pn pd posted_positive released_buy_nonnegative
          unlimited_adjustment buying buying_fits] .
    show "adjust_stable price_n price_d posted released \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
      using maker_send preventative_adjustment
      by (simp add: adjust_stable_def)
  qed
qed

subsubsection \<open>Maximality of positive normal crossings with both repairs\<close>

text \<open>
  This subsection proves the intended property
  @{const positive_normal_crosses_are_maximal} for the options record with
  both receive-cap repairs enabled.  The development mirrors the plain-cap
  integer characterization: the two corrected normal branches are
  characterized exactly at the word level, the resulting integer amount pair
  is bounded by all four caps, the characterization is lifted through
  @{const exchange_v10_with_options}, and finally every returned positive pair is shown to
  be a @{const normal_favored_candidate} that dominates all candidates.
\<close>



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
    using pn by (simp add: sint_scast_int32_int64)
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by (simp add: sint_scast_int32_int64)
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
    using trade_uint trade_le_send by (simp add: sint_scast_int32_int64)
  note first = big_divide_or_throw128_down_bounded
    [OF pd_wide word_pd_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 trade_word (scast price_d) Cxx_Round_Down =
        Cxx_Ok (word_of_int sheep_send)"
    using first(1) trade_uint
    by (simp add: sheep_send_def sint_scast_int32_int64)
  have first_sint: "sint (word_of_int sheep_send :: int64) = sheep_send"
    using first(2) trade_uint
    by (simp add: sheep_send_def sint_scast_int32_int64)
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
    by (simp add: wheat_receive_def sint_scast_int32_int64)
  have second_result:
      "big_divide_or_throw (word_of_int sheep_send) (scast price_d)
        (scast price_n) Cxx_Round_Down = Cxx_Ok (word_of_int wheat_receive)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pd_wide] pn_wide
          rounded_bound]
      first_sint
    by (simp add: wheat_receive_def sint_scast_int32_int64)
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
    by (simp add: wheat_receive_def sint_scast_int32_int64)
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
    using pn by (simp add: sint_scast_int32_int64)
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by (simp add: sint_scast_int32_int64)
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
    using trade_uint trade_le_send by (simp add: sint_scast_int32_int64)
  note first = big_divide_or_throw128_down_bounded
    [OF pn_wide word_pn_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 trade_word (scast price_n) Cxx_Round_Down =
        Cxx_Ok (word_of_int wheat_receive)"
    using first(1) trade_uint
    by (simp add: wheat_receive_def sint_scast_int32_int64)
  have first_sint:
      "sint (word_of_int wheat_receive :: int64) = wheat_receive"
    using first(2) trade_uint
    by (simp add: wheat_receive_def sint_scast_int32_int64)
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
    by (simp add: sheep_send_def sint_scast_int32_int64)
  have second_result:
      "big_divide_or_throw (word_of_int wheat_receive) (scast price_n)
        (scast price_d) Cxx_Round_Down = Cxx_Ok (word_of_int sheep_send)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pn_wide] pd_wide
          rounded_bound]
      first_sint
    by (simp add: sheep_send_def sint_scast_int32_int64)
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
    by (simp add: sheep_send_def sint_scast_int32_int64)
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
      from bounds wheat_stays False show ?thesis
        by (simp only: exchange_v10_amounts_int_repaired_def Let_def
            if_True if_False fst_conv snd_conv)
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
      from bounds sheep_stays True show ?thesis
        by (simp only: exchange_v10_amounts_int_repaired_def Let_def
            if_True if_False fst_conv snd_conv)
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
      from branch word_stays wheat_stays False show ?thesis
        by (simp only: amounts_def exchange_v10_amounts_int_repaired_def
            Let_def if_True if_False fst_conv snd_conv)
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
      from branch word_stays sheep_stays True show ?thesis
        by (simp only: amounts_def exchange_v10_amounts_int_repaired_def
            Let_def if_True if_False fst_conv snd_conv)
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

subsection \<open>An options-parametric exact-integer abstraction\<close>

text \<open>
  @{const exchange_v10_amounts_int} hard-codes the legacy branch formulas and
  @{const exchange_v10_amounts_int_repaired} the repaired ones in normal mode
  only.  Neither covers a strict-mode call at the repaired record, which is
  what the path-payment routes issue from protocol 29 on.  This subsection
  closes the gap with one abstraction carrying both the rounding mode and the
  options record, so that the whole five-branch calculation has a single exact
  integer image and each existing abstraction is one of its instances.

  Only two branches are option-sensitive, and they are the two the repair
  changes: the round-down sheep-send branch taken when the wheat offer stays
  and sheep is at least as valuable (@{const symmetric_exact_receive_cap}), and
  the round-down wheat-receive branch taken when the wheat offer does not stay
  and wheat is more valuable (@{const exact_receive_cap}).  Both replace a
  plain offer value by the protocol-29 helper
  @{const calculate_offer_amount_from_value}, whose exact image is defined
  first.
\<close>

definition calculate_offer_amount_from_value_int ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int"
  where
    "calculate_offer_amount_from_value_int price_n price_d max_send
        max_receive =
      min (sint max_send * sint price_n)
        (min (sint max_receive * sint price_d + sint price_d - 1)
             (sint int64_max * sint price_d))
      div sint price_n"

text \<open>
  @{const calculate_offer_amount_from_value_int} is the exact-integer image of
  @{const calculate_offer_amount_from_value}: the send-side product, the
  receive-side product relaxed by one divisor unit, the @{const int64_max}
  saturation ceiling, and the single round-down division that the protocol-29
  helper performs in place of the caller's second rounding.
\<close>

lemma calculate_offer_amount_from_value_int_correspondence:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
  shows "calculate_offer_amount_from_value price_n price_d max_send
      max_receive =
    Cxx_Ok
      (word_of_int
        (calculate_offer_amount_from_value_int price_n price_d max_send
          max_receive))"
    and "sint
      (word_of_int
        (calculate_offer_amount_from_value_int price_n price_d max_send
          max_receive) :: int64) =
    calculate_offer_amount_from_value_int price_n price_d max_send max_receive"
text \<open>
  Proof sketch: the relaxed offer value is the exact nested minimum of the
  three products.  That minimum is at most the send-side product, so the
  round-down division by the numerator has a signed-64 quotient and the
  checked helper returns exactly the integer formula and its faithful signed
  interpretation.
\<close>
proof -
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by simp
  obtain trade_word :: uint128 where trade_result:
      "calculate_offer_value_with_exact_receive_cap price_n price_d max_send
         max_receive = Cxx_Ok trade_word"
    and trade_uint:
      "uint trade_word =
        min (sint max_send * sint price_n)
          (min (sint max_receive * sint price_d + sint price_d - 1)
               (sint int64_max * sint price_d))"
    using exact_receive_cap_value_int
      [OF pn pd send_nonnegative receive_nonnegative] .
  have word_pn_bound:
      "uint trade_word \<le> sint max_send * sint (scast price_n :: int64)"
    using trade_uint by simp
  note first = big_divide_or_throw128_down_bounded
    [OF pn_wide word_pn_bound sint64_upper_bound]
  show "calculate_offer_amount_from_value price_n price_d max_send
      max_receive =
    Cxx_Ok
      (word_of_int
        (calculate_offer_amount_from_value_int price_n price_d max_send
          max_receive))"
    using trade_result first(1) trade_uint
    by (simp add: calculate_offer_amount_from_value_int_def)
  show "sint
      (word_of_int
        (calculate_offer_amount_from_value_int price_n price_d max_send
          max_receive) :: int64) =
    calculate_offer_amount_from_value_int price_n price_d max_send max_receive"
    using first(2) trade_uint
    by (simp add: calculate_offer_amount_from_value_int_def)
qed

definition exchange_v10_amounts_int_with_options ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow> int \<times> int"
  where
    "exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding options =
      (let wheat_value =
          exchange_wheat_value_int price_n price_d max_wheat_send
            max_sheep_receive;
         sheep_value =
          exchange_sheep_value_int price_n price_d max_sheep_send
            max_wheat_receive;
         wheat_stays = wheat_value > sheep_value
       in if wheat_stays then
            if rounding = Exchange_Strict_Send then
              (sheep_value div sint price_n,
               min (sint max_sheep_send) (sint max_sheep_receive))
            else if sint price_n > sint price_d \<or>
                rounding = Exchange_Strict_Receive
            then
              let wheat_receive = sheep_value div sint price_n
              in (wheat_receive,
                  (wheat_receive * sint price_n + sint price_d - 1)
                    div sint price_d)
            else
              let sheep_send =
                (if symmetric_exact_receive_cap options
                 then calculate_offer_amount_from_value_int price_d price_n
                   max_sheep_send max_wheat_receive
                 else sheep_value div sint price_d)
              in ((sheep_send * sint price_d) div sint price_n, sheep_send)
          else if sint price_n > sint price_d then
            let wheat_receive =
              (if exact_receive_cap options
               then calculate_offer_amount_from_value_int price_n price_d
                 max_wheat_send max_sheep_receive
               else wheat_value div sint price_n)
            in (wheat_receive,
                (wheat_receive * sint price_n) div sint price_d)
          else
            let sheep_send = wheat_value div sint price_d
            in ((sheep_send * sint price_d + sint price_n - 1)
                  div sint price_n,
                sheep_send))"

text \<open>
  @{const exchange_v10_amounts_int_with_options} is
  @{const exchange_v10_amounts_int} with the two option-sensitive branches
  switched on the corresponding flag.  Every other branch is copied verbatim,
  which is what makes the two collapse equations below hold by unfolding
  alone.
\<close>

lemma exchange_v10_amounts_int_with_options_legacy [simp]:
  "exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
     max_wheat_receive max_sheep_send max_sheep_receive rounding
     legacy_exchange_options =
   exchange_v10_amounts_int price_n price_d max_wheat_send max_wheat_receive
     max_sheep_send max_sheep_receive rounding"
  \<comment> \<open>At the legacy record the new abstraction is the established one, so no
    existing result changes meaning.\<close>
  by (simp add: exchange_v10_amounts_int_with_options_def
      exchange_v10_amounts_int_def legacy_exchange_options_def Let_def)

lemma exchange_v10_amounts_int_with_options_repaired_normal [simp]:
  "exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
     max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal
     repaired_exchange_options =
   exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
     max_wheat_receive max_sheep_send max_sheep_receive"
  \<comment> \<open>At the repaired record in normal mode it is the established repaired
    abstraction.\<close>
  by (simp add: exchange_v10_amounts_int_with_options_def
      exchange_v10_amounts_int_repaired_def repaired_exchange_options_def
      calculate_offer_amount_from_value_int_def Let_def)

lemma exchange_v10_amounts_int_with_options_bounds:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "0 \<le> fst (exchange_v10_amounts_int_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options)"
    and "fst (exchange_v10_amounts_int_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> snd (exchange_v10_amounts_int_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options)"
    and "snd (exchange_v10_amounts_int_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
text \<open>
  Proof sketch: split on the offer-value comparison, the rounding mode, the
  price order, and the relevant flag.  The five plain branches reuse the
  established plain-cap bound lemmas; the two corrected branches reuse the
  repaired ones, whose trade expressions are exactly the exact-image helper
  unfolded.
\<close>
proof -
  let ?A = "exchange_v10_amounts_int_with_options price_n price_d
    max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
    rounding options"
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
    proof (cases "rounding = Exchange_Strict_Send")
      case strict_send: True
      note bounds = exchange_amounts_strict_send_bounds
        [OF pn S0 Swr wheat_stays Wws ss sr]
      from bounds wheat_stays strict_send show ?thesis
        by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
    next
      case not_strict_send: False
      show ?thesis
      proof (cases "sint price_n > sint price_d \<or>
          rounding = Exchange_Strict_Receive")
        case up: True
        note bounds = exchange_amounts_wheat_stays_up_bounds
          [OF pn pd S0 Swr Sss wheat_stays Wws Wsr]
        from bounds wheat_stays not_strict_send up show ?thesis
          by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
      next
        case down: False
        then have price_order: "sint price_n \<le> sint price_d" by simp
        show ?thesis
        proof (cases "symmetric_exact_receive_cap options")
          case symmetric: True
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
            unfolding exchange_v10_amounts_int_with_options_def
              calculate_offer_amount_from_value_int_def
            apply (simp only: Let_def wheat_stays if_True not_strict_send
                down if_False symmetric prod.sel)
            using bounds
            by blast
        next
          case plain: False
          note bounds = exchange_amounts_wheat_stays_down_bounds
            [OF pn pd S0 Swr Sss wheat_stays Wws Wsr]
          from bounds wheat_stays not_strict_send down plain show ?thesis
            by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
        qed
      qed
    qed
  next
    case sheep_stays: False
    then have WS: "?W \<le> ?S" by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case wheat_more: True
      show ?thesis
      proof (cases "exact_receive_cap options")
        case exact: True
        have stays_raw:
            "min (sint max_wheat_send * sint price_n)
               (sint max_sheep_receive * sint price_d) \<le>
             min (sint max_sheep_send * sint price_d)
               (sint max_wheat_receive * sint price_n)"
          using WS
          by (simp add: exchange_wheat_value_int_def
              exchange_sheep_value_int_def)
        note bounds = repaired_sheep_stays_wheat_more_bounds
          [OF pn pd wheat_more imax_nonnegative ws sr stays_raw]
        show ?thesis
          unfolding exchange_v10_amounts_int_with_options_def
            calculate_offer_amount_from_value_int_def
          apply (simp only: Let_def sheep_stays if_False wheat_more if_True
              exact prod.sel)
          using bounds
          by blast
      next
        case plain: False
        note bounds = exchange_amounts_sheep_stays_wheat_more_bounds
          [OF pn pd W0 Wws Wsr WS Swr Sss]
        from bounds sheep_stays wheat_more plain show ?thesis
          by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
      qed
    next
      case False
      note bounds = exchange_amounts_sheep_stays_sheep_more_bounds
        [OF pn pd W0 Wws Wsr WS Swr Sss]
      from bounds sheep_stays False show ?thesis
        by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
    qed
  qed
  from result show "0 \<le> fst ?A" by simp
  from result show
      "fst ?A \<le> min (sint max_wheat_receive) (sint max_wheat_send)" by simp
  from result show "0 \<le> snd ?A" by simp
  from result show
      "snd ?A \<le> min (sint max_sheep_receive) (sint max_sheep_send)" by simp
qed

lemma exchange_v10_amounts_sheep_stays_wheat_more_plain:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and wheat_value:
      "uint wheat_word =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive"
    and wheat_more: "sint price_n > sint price_d"
    and plain_cap: "\<not> exact_receive_cap options"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding options =
    (let wheat_receive =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive div sint price_n;
       sheep_send = wheat_receive * sint price_n div sint price_d
     in Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send))"
  \<comment> \<open>The plain-cap form of the non-staying wheat-more branch, generic in the
    options record rather than pinned to the legacy one.\<close>
text \<open>
  Proof sketch: with the exact receive cap disabled this branch consults no
  other field of the options record, so the call agrees with the legacy call
  by unfolding, and the established legacy branch equation applies.
\<close>
proof -
  have same:
      "exchange_v10_amounts price_n price_d wheat_word sheep_word
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         False rounding options =
       exchange_v10_amounts price_n price_d wheat_word sheep_word
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         False rounding
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
    using wheat_more plain_cap
    by (simp add: exchange_v10_amounts_def)
  show ?thesis
    using same
      exchange_v10_amounts_sheep_stays_wheat_more
        [OF pre wheat_value wheat_more]
    by simp
qed

theorem exchange_v10_amounts_with_options_integer_characterization:
  fixes wheat_word sheep_word :: uint128 and amounts :: "int \<times> int"
    and rounding :: exchange_rounding and options :: exchange_options
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
      exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding options"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      (wheat_word > sheep_word) rounding options =
    Cxx_Ok
      (word_of_int (fst amounts), word_of_int (snd amounts))"
    and "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    and "sint (word_of_int (snd amounts) :: int64) = snd amounts"
text \<open>
  Proof sketch: identify both 128-bit values with their exact integers, then
  split exactly as the abstraction does.  Each of the seven cases is one
  branch equation --- five plain, two repaired --- and the bounds theorem
  above makes both re-encoded result words faithful signed-64 values.
\<close>
proof -
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
  have W_value: "uint wheat_word = ?W"
    using exchange_wheat_value_word [OF pre]
    unfolding wheat_word_def .
  have S_value: "uint sheep_word = ?S"
    using exchange_sheep_value_word [OF pre]
    unfolding sheep_word_def .
  have stays: "(wheat_word > sheep_word) = (?W > ?S)"
    by (simp only: word_less_def W_value S_value)
  show amount_result:
      "exchange_v10_amounts price_n price_d wheat_word sheep_word
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        (wheat_word > sheep_word) rounding options =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
  proof (cases "?W > ?S")
    case wheat_stays: True
    have word_stays: "wheat_word > sheep_word"
      using stays wheat_stays by simp
    show ?thesis
    proof (cases "rounding = Exchange_Strict_Send")
      case strict_send: True
      note branch = exchange_v10_amounts_wheat_stays_strict_send
        [OF pre S_value]
      from branch word_stays wheat_stays strict_send show ?thesis
        by (simp add: amounts_def
            exchange_v10_amounts_int_with_options_def Let_def)
    next
      case not_strict_send: False
      show ?thesis
      proof (cases "sint price_n > sint price_d \<or>
          rounding = Exchange_Strict_Receive")
        case up: True
        note branch = exchange_v10_amounts_wheat_stays_up
          [OF pre S_value not_strict_send up]
        from branch word_stays wheat_stays not_strict_send up show ?thesis
          by (simp add: amounts_def
              exchange_v10_amounts_int_with_options_def Let_def)
      next
        case down: False
        show ?thesis
        proof (cases "symmetric_exact_receive_cap options")
          case symmetric: True
          have price_order: "\<not> sint price_n > sint price_d"
            using down by simp
          have normal: "rounding = Exchange_Normal"
            using not_strict_send down by (cases rounding) simp_all
          note branch = exchange_v10_amounts_wheat_stays_down_repaired
            [OF pn pd price_order wr ss symmetric]
          show ?thesis
            unfolding amounts_def
              exchange_v10_amounts_int_with_options_def
              calculate_offer_amount_from_value_int_def
            apply (simp only: Let_def word_stays wheat_stays if_True
                not_strict_send down if_False symmetric prod.sel)
            using branch(1) [folded normal]
            by blast
        next
          case plain: False
          note branch = exchange_v10_amounts_wheat_stays_down
            [OF pre S_value not_strict_send down plain]
          from branch word_stays wheat_stays not_strict_send down plain
          show ?thesis
            by (simp add: amounts_def
                exchange_v10_amounts_int_with_options_def Let_def)
        qed
      qed
    qed
  next
    case sheep_stays: False
    have word_stays: "\<not> wheat_word > sheep_word"
      using stays sheep_stays by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case wheat_more: True
      show ?thesis
      proof (cases "exact_receive_cap options")
        case exact: True
        note branch = exchange_v10_amounts_sheep_stays_wheat_more_repaired
          [OF pn pd wheat_more ws sr exact]
        show ?thesis
          unfolding amounts_def
            exchange_v10_amounts_int_with_options_def
            calculate_offer_amount_from_value_int_def
          apply (simp only: Let_def word_stays sheep_stays if_False
              wheat_more if_True exact prod.sel)
          using branch(1)
          by blast
      next
        case plain: False
        note branch = exchange_v10_amounts_sheep_stays_wheat_more_plain
          [OF pre W_value wheat_more plain]
        from branch word_stays sheep_stays wheat_more plain show ?thesis
          by (simp add: amounts_def
              exchange_v10_amounts_int_with_options_def Let_def)
      qed
    next
      case sheep_more: False
      note branch = exchange_v10_amounts_sheep_stays_sheep_more
        [OF pre W_value sheep_more]
      from branch word_stays sheep_stays sheep_more show ?thesis
        by (simp add: amounts_def
            exchange_v10_amounts_int_with_options_def Let_def)
    qed
  qed
  note bounds = exchange_v10_amounts_int_with_options_bounds [OF pre]
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


theorem exchange_v10_without_thresholds_options_integer_characterization:
  fixes amounts :: "int \<times> int"
    and rounding :: exchange_rounding and options :: exchange_options
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding options"
  shows "exchange_v10_without_price_error_thresholds_with_options price_n
      price_d max_wheat_send max_wheat_receive max_sheep_send
      max_sheep_receive rounding options =
    Cxx_Ok
      (make_exchange_result
        (word_of_int (fst amounts)) (word_of_int (snd amounts))
        (exchange_wheat_value_int price_n price_d max_wheat_send
           max_sheep_receive >
         exchange_sheep_value_int price_n price_d max_sheep_send
           max_wheat_receive))"
text \<open>
  Proof sketch: both offer-value calls succeed with their exact 128-bit minima
  under @{const exchange_v10_pre}.  Substitute the options-parametric amount
  characterization, then use its signed interpretations and four bounds to
  prove that neither final runtime check is reachable.
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
    exchange_v10_amounts_with_options_integer_characterization
      [OF pre, of rounding options]
  have amount_call:
      "exchange_v10_amounts price_n price_d ?WW ?SW max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive (?WW > ?SW)
        rounding options =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
    using amount_result(1)
    unfolding amounts_def by simp
  have amount_call_integer:
      "exchange_v10_amounts price_n price_d ?WW ?SW max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive (?W > ?S)
        rounding options =
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
  note bounds =
    exchange_v10_amounts_int_with_options_bounds [OF pre, of rounding options]
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

theorem exchange_v10_options_integer_characterization:
  fixes amounts :: "int \<times> int"
    and rounding :: exchange_rounding and options :: exchange_options
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding options"
  shows "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding options =
    apply_price_error_thresholds price_n price_d
      (word_of_int (fst amounts)) (word_of_int (snd amounts))
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      rounding"
  \<comment> \<open>The whole kernel, in every rounding mode and at every exact-cap
    configuration, is the exact-integer calculation followed by the threshold
    pass.\<close>
text \<open>
  Proof sketch: the options-parametric pre-threshold characterization replaces
  the first call by its exact amount record; simplifying the record selectors
  leaves the threshold call shown here.
\<close>
  using exchange_v10_without_thresholds_options_integer_characterization
    [OF pre, of rounding options]
  unfolding exchange_v10_with_options_def amounts_def make_exchange_result_def
  by simp

text \<open>
  @{thm [source] exchange_v10_options_integer_characterization} generalizes
  both @{thm [source] exchange_v10_integer_characterization} and
  @{thm [source] exchange_v10_repaired_integer_characterization}: the first is
  its instance at @{const legacy_exchange_options}, the second its instance at
  @{const repaired_exchange_options} in normal mode, and the two collapse
  equations above make each instance syntactically the established one.  What
  is new is the repaired record in the two strict modes, which is what the
  path-payment routes issue from protocol 29 on.
\<close>

subsection \<open>Strict-send positivity at the repaired record\<close>

text \<open>
  With the options-parametric abstraction available, the legacy strict-send
  positivity \<^emph>\<open>iff\<close> can be redone at the repaired record.  It does not survive
  verbatim.  In the branch where the wheat offer does not stay and wheat is
  the more valuable asset, the repaired calculation divides the relaxed exact
  trade value rather than the plain wheat value, so the exact positivity
  threshold moves: the legacy condition
  @{term "sint price_n \<le> exchange_wheat_value_int price_n price_d
    max_wheat_send max_sheep_receive"} becomes the same comparison against
  @{term "calculate_offer_amount_from_value_int"}'s numerator.  The two other
  strict-send branches are option-free and their conditions are unchanged.
\<close>

definition exact_trade_value_int ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int"
  where
    "exact_trade_value_int price_n price_d max_send max_receive =
      min (sint max_send * sint price_n)
        (min (sint max_receive * sint price_d + sint price_d - 1)
             (sint int64_max * sint price_d))"

lemma calculate_offer_amount_from_value_int_as_trade:
  "calculate_offer_amount_from_value_int price_n price_d max_send
     max_receive =
   exact_trade_value_int price_n price_d max_send max_receive
     div sint price_n"
  \<comment> \<open>Naming the numerator of the protocol-29 helper.\<close>
  by (simp add: calculate_offer_amount_from_value_int_def
      exact_trade_value_int_def)

lemma exact_trade_value_int_nonnegative:
  assumes pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and send_nonnegative: "0 \<le> sint max_send"
    and receive_nonnegative: "0 \<le> sint max_receive"
  shows "0 \<le> exact_trade_value_int price_n price_d max_send max_receive"
  \<comment> \<open>All three components of the relaxed trade value are non-negative.\<close>
text \<open>
  Proof sketch: each of the three products is a product of two non-negative
  factors, and the relaxation addend is non-negative because the denominator
  is positive.
\<close>
proof -
  have "0 \<le> sint max_send * sint price_n"
    using send_nonnegative less_imp_le [OF pn] by simp
  moreover have "0 \<le> sint max_receive * sint price_d + sint price_d - 1"
  proof -
    have "0 \<le> sint max_receive * sint price_d"
      using receive_nonnegative less_imp_le [OF pd] by simp
    then show ?thesis using pd by linarith
  qed
  moreover have "0 \<le> sint int64_max * sint price_d"
    using less_imp_le [OF pd] by (simp add: int64_max_def)
  ultimately show ?thesis
    by (simp add: exact_trade_value_int_def)
qed

theorem exchange_v10_strict_send_sheep_positive_iff_with_options:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "(0 < snd
      (exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive
        Exchange_Strict_Send options)) =
    (let wheat_value =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive;
       sheep_value =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive
     in if wheat_value > sheep_value
        then 0 < sint max_sheep_send \<and> 0 < sint max_sheep_receive
        else if sint price_n > sint price_d
        then if exact_receive_cap options
             then sint price_n \<le>
               exact_trade_value_int price_n price_d max_wheat_send
                 max_sheep_receive
             else sint price_n \<le> wheat_value
        else sint price_d \<le> wheat_value)"
  \<comment> \<open>The exact strict-send positivity threshold, at every exact-cap
    configuration.  Only the non-staying wheat-more branch differs from the
    legacy statement, and it differs by replacing the plain wheat value with
    the relaxed exact trade value.\<close>
text \<open>
  Proof sketch: in the wheat-stays branch the sheep amount is the signed
  minimum of the two sheep maxima, exactly as before.  Otherwise the selected
  floor formula is a nested quotient of a non-negative numerator, positive
  exactly at one numerator unit when wheat is more valuable, and an ordinary
  positive division otherwise.  The exact-cap flag changes only which
  non-negative numerator is divided.
\<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  let ?T = "exact_trade_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and ws: "0 \<le> sint max_wheat_send"
    and ss: "0 \<le> sint max_sheep_send"
    and sr: "0 \<le> sint max_sheep_receive"
    by (simp_all add: exchange_v10_pre_def)
  have W0: "0 \<le> ?W"
    using exchange_wheat_value_int_bounds [OF pre] by simp
  have T0: "0 \<le> ?T"
    using exact_trade_value_int_nonnegative [OF pn pd ws sr] .
  show ?thesis
  proof (cases "?W > ?S")
    case True
    with ss sr show ?thesis
      by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
  next
    case sheep_stays: False
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case wheat_more: True
      show ?thesis
      proof (cases "exact_receive_cap options")
        case exact: True
        note positive = int_nested_floor_product_positive_iff
          [OF T0 wheat_more pd]
        from positive sheep_stays wheat_more exact show ?thesis
          by (simp add: exchange_v10_amounts_int_with_options_def
              calculate_offer_amount_from_value_int_def
              exact_trade_value_int_def Let_def)
      next
        case plain: False
        note positive = int_nested_floor_product_positive_iff
          [OF W0 wheat_more pd]
        from positive sheep_stays wheat_more plain show ?thesis
          by (simp add: exchange_v10_amounts_int_with_options_def Let_def)
      qed
    next
      case False
      with pd sheep_stays show ?thesis
        by (simp add: exchange_v10_amounts_int_with_options_def Let_def
            pos_imp_zdiv_pos_iff)
    qed
  qed
qed

corollary exchange_v10_strict_send_sheep_positive_iff_repaired:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "(0 < snd
      (exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive
        Exchange_Strict_Send repaired_exchange_options)) =
    (let wheat_value =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive;
       sheep_value =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive
     in if wheat_value > sheep_value
        then 0 < sint max_sheep_send \<and> 0 < sint max_sheep_receive
        else if sint price_n > sint price_d
        then sint price_n \<le>
          exact_trade_value_int price_n price_d max_wheat_send
            max_sheep_receive
        else sint price_d \<le> wheat_value)"
  \<comment> \<open>The protocol-29 strict-send positivity threshold.\<close>
  using exchange_v10_strict_send_sheep_positive_iff_with_options
    [OF pre, of repaired_exchange_options]
  by (simp add: repaired_exchange_options_def)

lemma exchange_wheat_value_int_le_exact_trade_value_int:
  assumes pd: "0 < sint price_d"
  shows "exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive \<le>
    exact_trade_value_int price_n price_d max_wheat_send max_sheep_receive"
  \<comment> \<open>The relaxed exact trade value is never below the plain wheat value.\<close>
text \<open>
  Proof sketch: the receive component is relaxed upwards by one divisor unit,
  and the saturation ceiling cannot bind below it, because the sheep-receive
  cap is a signed 64-bit amount and so at most @{const int64_max}.  Both
  minima take the same send component, so the relaxed minimum dominates.
\<close>
proof -
  let ?A = "sint max_wheat_send * sint price_n"
  let ?B = "sint max_sheep_receive * sint price_d"
  have imax: "sint (int64_max :: int64) = int64_max_int"
    by (simp add: int64_max_def)
  have receive_le_cap: "?B \<le> sint (int64_max :: int64) * sint price_d"
    using mult_right_mono
      [OF sint64_upper_bound [of max_sheep_receive] less_imp_le [OF pd]]
      imax
    by simp
  have le_A: "min ?A ?B \<le> ?A" by simp
  have le_B: "min ?A ?B \<le> ?B" by simp
  have le_relaxed: "min ?A ?B \<le> ?B + sint price_d - 1"
    using le_B pd by linarith
  have le_cap: "min ?A ?B \<le> sint (int64_max :: int64) * sint price_d"
    using le_B receive_le_cap by linarith
  have le_inner:
      "min ?A ?B \<le>
       min (?B + sint price_d - 1) (sint (int64_max :: int64) * sint price_d)"
    using le_relaxed le_cap by simp
  show ?thesis
    unfolding exchange_wheat_value_int_def exact_trade_value_int_def
    using le_A le_inner by simp
qed

corollary legacy_strict_send_positivity_implies_repaired:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and legacy_positive:
      "0 < snd
        (exchange_v10_amounts_int price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive
          Exchange_Strict_Send)"
  shows "0 < snd
    (exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Send repaired_exchange_options)"
  \<comment> \<open>Protocol 29 makes more strict-send trades positive, never fewer: every
    positive legacy strict-send sheep amount is still positive at the repaired
    record.\<close>
text \<open>
  Proof sketch: the two thresholds differ only in the non-staying wheat-more
  branch, where the legacy one compares the price numerator against the plain
  wheat value and the repaired one against the relaxed exact trade value.  The
  preceding lemma orders those two numerators, so the legacy condition implies
  the repaired one; the other two branch conditions are identical.
\<close>
proof -
  from pre have pd: "0 < sint price_d"
    by (simp add: exchange_v10_pre_def)
  note legacy = exchange_v10_strict_send_sheep_positive_iff [OF pre]
  note repaired =
    exchange_v10_strict_send_sheep_positive_iff_repaired [OF pre]
  note ordering = exchange_wheat_value_int_le_exact_trade_value_int
    [OF pd, of price_n max_wheat_send max_sheep_receive]
  show ?thesis
    using legacy legacy_positive repaired ordering
    by (simp add: Let_def split: if_splits)
qed

text \<open>
  Comparing @{thm [source] exchange_v10_strict_send_sheep_positive_iff_repaired}
  with @{thm [source] exchange_v10_strict_send_sheep_positive_iff} makes the
  divergence explicit and localizes it: the two outer conditions are word for
  word the legacy ones, and only the non-staying wheat-more condition changes,
  from @{term "sint price_n \<le> exchange_wheat_value_int price_n price_d
    max_wheat_send max_sheep_receive"} to the same comparison against
  @{const exact_trade_value_int}.
  @{thm [source] exchange_wheat_value_int_le_exact_trade_value_int} orders
  those two numerators, so the repaired condition is the weaker one and
  @{thm [source] legacy_strict_send_positivity_implies_repaired} follows:
  protocol 29 makes more strict-send trades positive and never fewer, which is
  the intended direction of the repair.
\<close>

subsection \<open>Counterexample-first probes for the repaired strict modes\<close>

text \<open>
  The results above quantify over inputs whose branches could in principle be
  unreachable, so each is pinned down by an evaluation.  The first two probes
  show that the repaired strict-send threshold really does differ from the
  legacy one, the third that the difference is visible at the protocol-facing
  interface, and the last two that the strict-mode contracts are not vacuous
  at protocol 29 --- including on the branch the exact receive cap changes.
\<close>

lemma repaired_strict_send_amounts_differ_probe:
  "exchange_v10_amounts_int 3 2 1 1 1 1 Exchange_Strict_Send = (0, 0)"
  "exchange_v10_amounts_int_with_options 3 2 1 1 1 1 Exchange_Strict_Send
     repaired_exchange_options = (1, 1)"
  \<comment> \<open>At price three halves with unit caps the legacy strict-send calculation
    yields no trade and the repaired one yields a unit trade, so the two
    positivity thresholds are genuinely different predicates.\<close>
text \<open>
  Proof sketch: evaluate both exact-integer calculations at the witness.
\<close>
  by (eval, eval)

lemma repaired_strict_send_relaxes_threshold_probe:
  "exact_trade_value_int 3 2 1 1 = 3"
  "exchange_wheat_value_int 3 2 1 1 = 2"
  \<comment> \<open>The same witness seen through the two numerators the thresholds compare
    against the price numerator: the relaxed exact trade value reaches it and
    the plain wheat value does not.\<close>
text \<open>
  Proof sketch: evaluate both integer values at the witness.
\<close>
  by (eval, eval)

lemma repaired_strict_send_threshold_rejection_probe:
  "exchange_v10_without_price_error_thresholds_with_options 3 2 3 3 4 4
     Exchange_Strict_Send legacy_exchange_options =
   Cxx_Ok (make_exchange_result 2 3 False)"
  "exchange_v10_without_price_error_thresholds_with_options 3 2 3 3 4 4
     Exchange_Strict_Send repaired_exchange_options =
   Cxx_Ok (make_exchange_result 3 4 False)"
  "exchange_v10 28 3 2 3 3 4 4 Exchange_Strict_Send =
   Cxx_Ok (make_exchange_result 2 3 False)"
  "exchange_v10 29 3 2 3 3 4 4 Exchange_Strict_Send = Cxx_Err Cxx_Runtime_Error"
  \<comment> \<open>A strict-send call that succeeds at protocol 28 and raises a modeled
    runtime error at protocol 29.\<close>
text \<open>
  Proof sketch: evaluate the pre-threshold calculation at both records and the
  protocol-facing call at both versions.
\<close>
  by (eval, eval, eval, eval)

text \<open>
  \<^bold>\<open>What the last probe means.\<close>  It is not a failure of any theorem above ---
  every strict-mode contract is conditional on a \<^emph>\<open>successful\<close> exchange --- and
  it is not a live protocol-29 regression either.  On this input the exact
  receive cap enlarges the pre-threshold pair from @{term "(2::int)"} wheat for
  @{term "(3::int)"} sheep to @{term "(3::int)"} for @{term "(4::int)"}.  Three
  wheat at price three halves is worth four and a half sheep, so the enlarged
  pair underpays by half a sheep unit, and the tight one-sided price-error
  bound that strict modes apply rejects it.  The legacy pair was exact and
  passed.

  What the probe actually shows is that the standing precondition of the
  exchange --- that the resting wheat offer has been adjusted \<^emph>\<open>at the version
  the exchange is running at\<close> --- became load-bearing at protocol 29 in a way
  it was not at protocol 28.  The witness violates it: the same offer state is
  adjusted to @{term "(2::int)"} before the boundary and to @{term "(0::int)"}
  from it, so at protocol 29 the offer is deleted rather than rested and the
  rejected call is one no crossing can issue.
\<close>

lemma repaired_strict_send_rejection_needs_unadjusted_offer:
  "adjust_offer 28 3 2 3 4 = Cxx_Ok 2"
  "adjust_offer 29 3 2 3 4 = Cxx_Ok 0"
  \<comment> \<open>The rejected witness is not a protocol-29 adjustment fixed point: at
    that version the offer is adjusted away entirely.\<close>
text \<open>
  Proof sketch: evaluate the protocol-facing adjustment at both versions.
\<close>
  by (eval, eval)

definition p29_adjusted_strict_case ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> bool"
  where
    "p29_adjusted_strict_case price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive \<longleftrightarrow>
      (if adjust_offer 29 price_n price_d max_wheat_send max_sheep_receive =
          Cxx_Ok max_wheat_send
       then list_all
         (\<lambda>rounding.
            case exchange_v10 29 price_n price_d max_wheat_send
                max_wheat_receive max_sheep_send max_sheep_receive rounding of
              Cxx_Ok _ \<Rightarrow> True
            | Cxx_Err _ \<Rightarrow> False)
         [Exchange_Strict_Send, Exchange_Strict_Receive]
       else True)"

text \<open>
  @{const p29_adjusted_strict_case} restricts attention to the calls a crossing
  can actually issue.  @{const cross_offer_v10} adjusts the resting offer at
  the crossing version and only then exchanges, and its send cap is the
  adjusted amount, so the pair it hands to the exchange is always a fixed point
  of @{term "adjust_offer 29"} at the receive cap in force.  The predicate
  passes vacuously on every other pair and, on those, requires both strict
  modes to return successfully.
\<close>

lemma bounded_p29_adjusted_strict_search:
  "list_all (\<lambda>price_n.
     list_all (\<lambda>price_d.
       list_all (\<lambda>max_wheat_send.
         list_all (\<lambda>max_wheat_receive.
           list_all (\<lambda>max_sheep_send.
             list_all (\<lambda>max_sheep_receive.
               p29_adjusted_strict_case price_n price_d max_wheat_send
                 max_wheat_receive max_sheep_send max_sheep_receive)
               ([1, 2, 3, 4, 5] :: int64 list))
             ([1, 2, 3, 4, 5] :: int64 list))
           ([1, 2, 3, 4, 5] :: int64 list))
         ([1, 2, 3, 4, 5] :: int64 list))
       ([1, 2, 3, 4, 5] :: int32 list))
     ([1, 2, 3, 4, 5] :: int32 list)"
  \<comment> \<open>No adjusted protocol-29 offer reaches the rejection in either strict
    mode, across the whole small grid.\<close>
text \<open>
  Proof sketch: execute the fifteen-thousand-six-hundred-and-twenty-five-case
  grid.  One hundred and fifty of its price and cap combinations are
  protocol-29 adjustment fixed points; on each, both strict-mode exchanges
  succeed.
\<close>
  by eval

lemma p29_adjusted_strict_case_not_vacuous:
  "adjust_offer 29 2 1 1 2 = Cxx_Ok 1"
  "exchange_v10 29 2 1 1 1 2 2 Exchange_Strict_Send =
   Cxx_Ok (make_exchange_result 1 2 False)"
  \<comment> \<open>The search is not vacuous where it matters: this offer is a protocol-29
    adjustment fixed point, its cross has a positive numerator and a
    non-staying wheat offer --- so it is decided by the very branch the exact
    receive cap changes --- and it succeeds.\<close>
text \<open>
  Proof sketch: evaluate the adjustment and the strict-send exchange.
\<close>
  by (eval, eval)

text \<open>
  So the enlarged pair is unreachable through the adjustment discipline that
  @{const cross_offer_v10} maintains, which is what the C++ comment at the
  corresponding throw site asserts without proof.  The bounded search above is
  evidence for that claim, not a proof of it; a proof would have to show that a
  protocol-29 adjustment fixed point always satisfies the tight bound in both
  strict modes, which is a genuine open item rather than a restatement.  What
  remains genuinely unmodelled is only whether some \<^emph>\<open>other\<close> caller reaches
  @{const exchange_v10} without the adjustment step.
\<close>

lemma repaired_strict_mode_positive_success_probes:
  "exchange_v10 29 1 1 1 1 1 1 Exchange_Strict_Send =
   Cxx_Ok (make_exchange_result 1 1 False)"
  "exchange_v10 29 1 1 1 1 1 1 Exchange_Strict_Receive =
   Cxx_Ok (make_exchange_result 1 1 False)"
  \<comment> \<open>Both strict modes have positive protocol-29 successes, so the
    strict-send positivity theorem and the positive case of the
    strict-receive contract are not vacuous.\<close>
text \<open>
  Proof sketch: evaluate the protocol-facing call at version 29 in both
  strict modes.
\<close>
  by (eval, eval)

lemma repaired_strict_send_exact_branch_success_probe:
  "exchange_v10 29 2 1 1 1 2 2 Exchange_Strict_Send =
   Cxx_Ok (make_exchange_result 1 2 False)"
  "exchange_v10 28 3 2 1 1 1 1 Exchange_Strict_Receive =
   Cxx_Ok (make_exchange_result 0 0 False)"
  \<comment> \<open>The first call has a positive numerator and a non-staying wheat offer,
    so it is decided by the branch the exact receive cap changes, and it
    succeeds.  The second is a strict-receive success returning the zero
    record, so both sides of the simultaneous-zero contract are witnessed.\<close>
text \<open>
  Proof sketch: evaluate the two protocol-facing calls.
\<close>
  by (eval, eval)

lemma exchange_v10_amounts_int_repaired_candidate:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "normal_favored_candidate price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      (fst (exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive))
      (snd (exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive))"
  text \<open>
    Proof sketch: the repaired bounds supply non-negativity and the four cap
    clauses.  In each of the four branches the pair satisfies its canonical
    favored rounding equation by construction.  The primary scaled amount is
    bounded by the saturation ceiling: the two corrected branches divide a
    value already clamped by the @{const int64_max} product, and the two
    plain branches divide an offer value bounded by a signed-64 cap times the
    ceiling's price component.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive"
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  note bounds = exchange_v10_amounts_int_repaired_bounds [OF pre]
  have caps_wheat:
      "fst ?A \<le> min (sint max_wheat_send) (sint max_wheat_receive)"
    using bounds(2) by (simp add: min.commute)
  have caps_sheep:
      "snd ?A \<le> min (sint max_sheep_send) (sint max_sheep_receive)"
    using bounds(4) by (simp add: min.commute)
  have canonical_and_saturated:
      "canonical_favored_rounding price_n price_d (?W > ?S)
        (fst ?A) (snd ?A) \<and>
       (if sint price_n > sint price_d
        then fst ?A * sint price_n \<le> sint int64_max * sint price_d
        else snd ?A * sint price_d \<le> sint int64_max * sint price_n)"
  proof (cases "?W > ?S")
    case wheat_stays: True
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      have formula:
          "?A = (?S div sint price_n,
             (?S div sint price_n * sint price_n + sint price_d - 1)
               div sint price_d)"
        using wheat_stays True
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have canonical:
          "canonical_favored_rounding price_n price_d (?W > ?S)
            (fst ?A) (snd ?A)"
        using formula wheat_stays True
        by (simp add: canonical_favored_rounding_def)
      have product_le_S: "fst ?A * sint price_n \<le> ?S"
        using formula int_div_mult_le [OF pn] by simp
      have S_le_cap: "?S \<le> sint max_sheep_send * sint price_d"
        using exchange_sheep_value_int_bounds [OF pre] by simp
      have cap_le_saturation:
          "sint max_sheep_send * sint price_d \<le>
            sint int64_max * sint price_d"
        using sint64_upper_bound [of max_sheep_send] less_imp_le [OF pd]
        by (simp add: int64_max_def mult_right_mono)
      have saturated:
          "fst ?A * sint price_n \<le> sint int64_max * sint price_d"
        using product_le_S S_le_cap cap_le_saturation by linarith
      show ?thesis using canonical saturated True by simp
    next
      case False
      let ?trade =
        "min (sint max_sheep_send * sint price_d)
          (min (sint max_wheat_receive * sint price_n + sint price_n - 1)
            (sint int64_max * sint price_n))"
      have formula:
          "?A = (?trade div sint price_d * sint price_d div sint price_n,
             ?trade div sint price_d)"
        using wheat_stays False
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have canonical:
          "canonical_favored_rounding price_n price_d (?W > ?S)
            (fst ?A) (snd ?A)"
        using formula wheat_stays False
        by (simp add: canonical_favored_rounding_def)
      have snd_eq: "snd ?A = ?trade div sint price_d"
        using formula by simp
      have product_le_trade: "snd ?A * sint price_d \<le> ?trade"
        unfolding snd_eq using int_div_mult_le [OF pd] .
      have trade_le_saturation: "?trade \<le> sint int64_max * sint price_n"
        by (meson min.cobounded2 order_trans)
      have saturated:
          "snd ?A * sint price_d \<le> sint int64_max * sint price_n"
        using product_le_trade trade_le_saturation by linarith
      show ?thesis using canonical saturated False by simp
    qed
  next
    case sheep_stays: False
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      let ?trade =
        "min (sint max_wheat_send * sint price_n)
          (min (sint max_sheep_receive * sint price_d + sint price_d - 1)
            (sint int64_max * sint price_d))"
      have formula:
          "?A = (?trade div sint price_n,
             ?trade div sint price_n * sint price_n div sint price_d)"
        using sheep_stays True
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have canonical:
          "canonical_favored_rounding price_n price_d (?W > ?S)
            (fst ?A) (snd ?A)"
        using formula sheep_stays True
        by (simp add: canonical_favored_rounding_def)
      have fst_eq: "fst ?A = ?trade div sint price_n"
        using formula by simp
      have product_le_trade: "fst ?A * sint price_n \<le> ?trade"
        unfolding fst_eq using int_div_mult_le [OF pn] .
      have trade_le_saturation: "?trade \<le> sint int64_max * sint price_d"
        by (meson min.cobounded2 order_trans)
      have saturated:
          "fst ?A * sint price_n \<le> sint int64_max * sint price_d"
        using product_le_trade trade_le_saturation by linarith
      show ?thesis using canonical saturated True by simp
    next
      case False
      have formula:
          "?A = ((?W div sint price_d * sint price_d + sint price_n - 1)
               div sint price_n,
             ?W div sint price_d)"
        using sheep_stays False
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have canonical:
          "canonical_favored_rounding price_n price_d (?W > ?S)
            (fst ?A) (snd ?A)"
        using formula sheep_stays False
        by (simp add: canonical_favored_rounding_def)
      have product_le_W: "snd ?A * sint price_d \<le> ?W"
        using formula int_div_mult_le [OF pd] by simp
      have W_le_cap: "?W \<le> sint max_wheat_send * sint price_n"
        using exchange_wheat_value_int_bounds [OF pre] by simp
      have cap_le_saturation:
          "sint max_wheat_send * sint price_n \<le>
            sint int64_max * sint price_n"
        using sint64_upper_bound [of max_wheat_send] less_imp_le [OF pn]
        by (simp add: int64_max_def mult_right_mono)
      have saturated:
          "snd ?A * sint price_d \<le> sint int64_max * sint price_n"
        using product_le_W W_le_cap cap_le_saturation by linarith
      show ?thesis using canonical saturated False by simp
    qed
  qed
  show ?thesis
    unfolding normal_favored_candidate_def
    using bounds(1) bounds(3) caps_wheat caps_sheep canonical_and_saturated
    by simp
qed

lemma exchange_v10_amounts_int_repaired_maximal:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and candidate: "normal_favored_candidate price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      wheat_receive sheep_send"
  shows "if sint price_n > sint price_d
      then wheat_receive \<le>
        fst (exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive)
      else sheep_send \<le>
        snd (exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive)"
  text \<open>
    Proof sketch: split on the price order and the staying offer.  In each
    branch the candidate's canonical rounding equation converts its cap on
    the derived amount into a bound on the primary scaled amount; together
    with the candidate's own caps and saturation clause, the primary scaled
    amount is at most the value divided by the implementation, so division
    monotonicity bounds the candidate's primary amount by the returned one.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive"
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have wr_le_mws: "wheat_receive \<le> sint max_wheat_send"
    and wr_le_mwr: "wheat_receive \<le> sint max_wheat_receive"
    and ss_le_mss: "sheep_send \<le> sint max_sheep_send"
    and ss_le_msr: "sheep_send \<le> sint max_sheep_receive"
    using candidate by (simp_all add: normal_favored_candidate_def)
  have canonical:
      "canonical_favored_rounding price_n price_d (?W > ?S)
        wheat_receive sheep_send"
    using candidate by (simp add: normal_favored_candidate_def)
  have saturated:
      "if sint price_n > sint price_d
       then wheat_receive * sint price_n \<le> sint int64_max * sint price_d
       else sheep_send * sint price_d \<le> sint int64_max * sint price_n"
    using candidate by (simp add: normal_favored_candidate_def)
  show ?thesis
  proof (cases "sint price_n > sint price_d")
    case wheat_more: True
    have candidate_rounding:
        "sheep_send =
          (if ?W > ?S
           then (wheat_receive * sint price_n + sint price_d - 1)
             div sint price_d
           else wheat_receive * sint price_n div sint price_d)"
      using canonical wheat_more
      by (simp add: canonical_favored_rounding_def)
    have saturated_wheat:
        "wheat_receive * sint price_n \<le> sint int64_max * sint price_d"
      using saturated wheat_more by simp
    have goal_wheat: "wheat_receive \<le> fst ?A"
    proof (cases "?W > ?S")
      case wheat_stays: True
      have formula: "fst ?A = ?S div sint price_n"
        using wheat_stays wheat_more
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have ceiling_eq:
          "sheep_send =
            (wheat_receive * sint price_n + sint price_d - 1)
              div sint price_d"
        using candidate_rounding wheat_stays by simp
      have product_le_ceiling:
          "wheat_receive * sint price_n \<le> sheep_send * sint price_d"
        unfolding ceiling_eq using int_le_ceiling_div_mult [OF pd] .
      have sheep_multiple_le:
          "sheep_send * sint price_d \<le>
            sint max_sheep_send * sint price_d"
        using ss_le_mss less_imp_le [OF pd] by (simp add: mult_right_mono)
      have product_le_mss:
          "wheat_receive * sint price_n \<le>
            sint max_sheep_send * sint price_d"
        using product_le_ceiling sheep_multiple_le by linarith
      have product_le_mwr:
          "wheat_receive * sint price_n \<le>
            sint max_wheat_receive * sint price_n"
        using wr_le_mwr less_imp_le [OF pn] by (simp add: mult_right_mono)
      have product_le_S: "wheat_receive * sint price_n \<le> ?S"
        using product_le_mss product_le_mwr
        by (simp add: exchange_sheep_value_int_def)
      show ?thesis
        unfolding formula
        using int_le_div_from_product [OF pn product_le_S] .
    next
      case sheep_stays: False
      let ?trade =
        "min (sint max_wheat_send * sint price_n)
          (min (sint max_sheep_receive * sint price_d + sint price_d - 1)
            (sint int64_max * sint price_d))"
      have formula: "fst ?A = ?trade div sint price_n"
        using sheep_stays wheat_more
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have floor_eq:
          "sheep_send = wheat_receive * sint price_n div sint price_d"
        using candidate_rounding sheep_stays by simp
      have quotient_le_msr:
          "wheat_receive * sint price_n div sint price_d \<le>
            sint max_sheep_receive"
        using floor_eq ss_le_msr by simp
      have product_le_msr:
          "wheat_receive * sint price_n \<le>
            sint max_sheep_receive * sint price_d + sint price_d - 1"
        using int_div_le_imp_below_next_multiple [OF pd quotient_le_msr] .
      have product_le_mws:
          "wheat_receive * sint price_n \<le>
            sint max_wheat_send * sint price_n"
        using wr_le_mws less_imp_le [OF pn] by (simp add: mult_right_mono)
      have product_le_trade: "wheat_receive * sint price_n \<le> ?trade"
        using product_le_mws product_le_msr saturated_wheat
        by (simp add: min.bounded_iff)
      show ?thesis
        unfolding formula
        using int_le_div_from_product [OF pn product_le_trade] .
    qed
    show ?thesis using wheat_more goal_wheat by simp
  next
    case sheep_more: False
    have candidate_rounding:
        "wheat_receive =
          (if ?W > ?S
           then sheep_send * sint price_d div sint price_n
           else (sheep_send * sint price_d + sint price_n - 1)
             div sint price_n)"
      using canonical sheep_more
      by (simp add: canonical_favored_rounding_def)
    have saturated_sheep:
        "sheep_send * sint price_d \<le> sint int64_max * sint price_n"
      using saturated sheep_more by simp
    have goal_sheep: "sheep_send \<le> snd ?A"
    proof (cases "?W > ?S")
      case wheat_stays: True
      let ?trade =
        "min (sint max_sheep_send * sint price_d)
          (min (sint max_wheat_receive * sint price_n + sint price_n - 1)
            (sint int64_max * sint price_n))"
      have formula: "snd ?A = ?trade div sint price_d"
        using wheat_stays sheep_more
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have floor_eq:
          "wheat_receive = sheep_send * sint price_d div sint price_n"
        using candidate_rounding wheat_stays by simp
      have quotient_le_mwr:
          "sheep_send * sint price_d div sint price_n \<le>
            sint max_wheat_receive"
        using floor_eq wr_le_mwr by simp
      have product_le_mwr:
          "sheep_send * sint price_d \<le>
            sint max_wheat_receive * sint price_n + sint price_n - 1"
        using int_div_le_imp_below_next_multiple [OF pn quotient_le_mwr] .
      have product_le_mss:
          "sheep_send * sint price_d \<le>
            sint max_sheep_send * sint price_d"
        using ss_le_mss less_imp_le [OF pd] by (simp add: mult_right_mono)
      have product_le_trade: "sheep_send * sint price_d \<le> ?trade"
        using product_le_mss product_le_mwr saturated_sheep
        by (simp add: min.bounded_iff)
      show ?thesis
        unfolding formula
        using int_le_div_from_product [OF pd product_le_trade] .
    next
      case sheep_stays: False
      have formula: "snd ?A = ?W div sint price_d"
        using sheep_stays sheep_more
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
      have ceiling_eq:
          "wheat_receive =
            (sheep_send * sint price_d + sint price_n - 1)
              div sint price_n"
        using candidate_rounding sheep_stays by simp
      have product_le_ceiling:
          "sheep_send * sint price_d \<le> wheat_receive * sint price_n"
        unfolding ceiling_eq using int_le_ceiling_div_mult [OF pn] .
      have wheat_multiple_le:
          "wheat_receive * sint price_n \<le>
            sint max_wheat_send * sint price_n"
        using wr_le_mws less_imp_le [OF pn] by (simp add: mult_right_mono)
      have product_le_mws:
          "sheep_send * sint price_d \<le>
            sint max_wheat_send * sint price_n"
        using product_le_ceiling wheat_multiple_le by linarith
      have product_le_msr:
          "sheep_send * sint price_d \<le>
            sint max_sheep_receive * sint price_d"
        using ss_le_msr less_imp_le [OF pd] by (simp add: mult_right_mono)
      have product_le_W: "sheep_send * sint price_d \<le> ?W"
        using product_le_mws product_le_msr
        by (simp add: exchange_wheat_value_int_def)
      show ?thesis
        unfolding formula
        using int_le_div_from_product [OF pd product_le_W] .
    qed
    show ?thesis using sheep_more goal_sheep by simp
  qed
qed

lemma exchange_v10_repaired_positive_normal_maximal:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
      Cxx_Ok result"
    and positive:
      "0 < sint (num_wheat_received result)"
      "0 < sint (num_sheep_send result)"
  shows "maximal_normal_favored_result price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive result"
  text \<open>
    Proof sketch: the repaired integer characterization identifies the
    exchange with a threshold call on the repaired amount pair.  Positivity
    rules out the threshold's explicit zero record, so the returned fields
    are exactly the repaired amounts and the exact stay flag.  The candidate
    lemma makes that pair a favored candidate and the dominance lemma bounds
    every competing candidate's primary amount.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive"
  let ?WR = "word_of_int (fst ?A) :: int64"
  let ?SS = "word_of_int (snd ?A) :: int64"
  let ?stays = "exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive Exchange_Normal
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
       apply_price_error_thresholds price_n price_d ?WR ?SS ?stays
         Exchange_Normal"
    using exchange_v10_repaired_integer_characterization [OF pre] by simp
  have applied:
      "apply_price_error_thresholds price_n price_d ?WR ?SS ?stays
        Exchange_Normal = Cxx_Ok result"
    using result exact by simp
  note choices = apply_price_error_thresholds_result_choices [OF applied]
  have result_record: "result = make_exchange_result ?WR ?SS ?stays"
    using choices positive by (auto simp add: make_exchange_result_def)
  note words =
    exchange_v10_amounts_repaired_integer_characterization [OF pre]
  have wheat_field: "sint (num_wheat_received result) = fst ?A"
    using result_record words(2) by (simp add: make_exchange_result_def)
  have sheep_field: "sint (num_sheep_send result) = snd ?A"
    using result_record words(3) by (simp add: make_exchange_result_def)
  have stays_field: "result_wheat_stays result = ?stays"
    using result_record by (simp add: make_exchange_result_def)
  have candidate_part:
      "normal_favored_candidate price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive
        (result_wheat_stays result)
        (sint (num_wheat_received result)) (sint (num_sheep_send result))"
    using exchange_v10_amounts_int_repaired_candidate [OF pre]
      wheat_field sheep_field stays_field
    by simp
  have dominance_part:
      "\<And>wheat_receive sheep_send.
        normal_favored_candidate price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive
          (result_wheat_stays result) wheat_receive sheep_send \<Longrightarrow>
        (if sint price_n > sint price_d
         then wheat_receive \<le> sint (num_wheat_received result)
         else sheep_send \<le> sint (num_sheep_send result))"
  proof -
    fix wheat_receive sheep_send
    assume assumed:
        "normal_favored_candidate price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive
          (result_wheat_stays result) wheat_receive sheep_send"
    have cand:
        "normal_favored_candidate price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive
          ?stays wheat_receive sheep_send"
      using assumed stays_field by simp
    show "if sint price_n > sint price_d
        then wheat_receive \<le> sint (num_wheat_received result)
        else sheep_send \<le> sint (num_sheep_send result)"
      using exchange_v10_amounts_int_repaired_maximal [OF pre cand]
        wheat_field sheep_field
      by simp
  qed
  show ?thesis
    unfolding maximal_normal_favored_result_def
    using candidate_part dominance_part by blast
qed



theorem positive_normal_crosses_are_maximal_repaired:
  "positive_normal_crosses_are_maximal
    \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"
  text \<open>
    Proof sketch: unfold the intended property and apply the pointwise
    maximality result to every successful positive normal exchange with both
    receive-cap repairs enabled.
  \<close>
  unfolding positive_normal_crosses_are_maximal_def
  using exchange_v10_repaired_positive_normal_maximal by blast

subsubsection \<open>The reservation anomaly, replayed end to end\<close>

text \<open>
  The definitions are executable, so the walkthrough in Section 5 of
  \<open>formal/docs/offer-lifecycle.md\<close> can be replayed.  Alice holds one TOKEN and a
  USD trustline with limit two and balance zero; she posts an offer selling
  one TOKEN at the price of 101 USD units per 100 TOKEN units.  The offer is
  created at its full amount and reserves one TOKEN of selling liabilities
  and one USD of buying liabilities.  All three lemmas of this subsection
  are proved by evaluating both sides.
\<close>

lemma alice_posts_her_offer:
  "post_offer 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr> \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
   Cxx_Ok (Post_Created 1
     \<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>)"
  by eval

text \<open>
  If nothing disturbs Alice's account, Bob---holding two USD, ample TOKEN
  headroom, and willing to sell up to two USD---crosses her offer at its
  full amount: one TOKEN moves against one USD and the offer leaves the book
  fully consumed.  The maker state at the crossing step is exactly the state
  in which posting left it.
\<close>

lemma bob_takes_the_offer:
  "post_then_cross 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>
     \<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>
     \<lparr>sell_balance = 2, sell_liabilities = 0,
      buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>
     2 Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
   Cxx_Ok
     (Post_Created 1
        \<lparr>sell_balance = 1, sell_liabilities = 1,
         buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>,
      Some
        \<lparr>cross_wheat_received = 1,
         cross_sheep_send = 1,
         cross_wheat_stays = False,
         cross_offer_amount = 0,
         cross_maker =
           \<lparr>sell_balance = 0, sell_liabilities = 0,
            buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr>,
         cross_taker =
           \<lparr>sell_balance = 1, sell_liabilities = 0,
            buy_limit = 1000, buy_balance = 1, buy_liabilities = 0\<rparr>\<rparr>)"
  by eval

text \<open>
  But if Carol first pays Alice one USD---a payment Alice cannot refuse and
  that touches no offer, visible below as the maker's buying balance rising
  from zero to one under an unchanged limit---Alice's headroom drops to
  exactly her reservation.  The same crossing now erases the offer for a
  zero fill: the preventative adjustment clips the offer to nothing, because
  its own reservation, fed back in as a limit, makes the offer look smaller
  than itself.  This is property P9 of the survey document, violated at the
  lifecycle level.
\<close>

lemma carol_griefs_alice:
  "post_then_cross 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>
     \<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>
     \<lparr>sell_balance = 2, sell_liabilities = 0,
      buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>
     2 Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
   Cxx_Ok
     (Post_Created 1
        \<lparr>sell_balance = 1, sell_liabilities = 1,
         buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>,
      Some
        \<lparr>cross_wheat_received = 0,
         cross_sheep_send = 0,
         cross_wheat_stays = False,
         cross_offer_amount = 0,
         cross_maker =
           \<lparr>sell_balance = 1, sell_liabilities = 0,
            buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr>,
         cross_taker =
           \<lparr>sell_balance = 2, sell_liabilities = 0,
            buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>\<rparr>)"
  by eval

text \<open>
  Carol's payment does more than deprive Bob of one fill: it leaves a dead
  offer.  The lemma below quantifies over every taker satisfying the
  positivity contract of \<open>crossOfferV10\<close> and shows each of them receives
  nothing, pays nothing, and erases the offer from the book.  Together with
  @{thm [source] bob_takes_the_offer} this separates the failure cleanly:
  the same posted offer was takeable before the payment, and only the
  interference killed it.  Proof sketch: releasing the offer's liabilities
  restores the state Carol left behind, where the preventative adjustment
  is a closed computation returning zero, because the reservation fed back
  in as a limit values the offer at @{term "(100::int)"} sheep units, one
  short of a lot of wheat at this price.  A zero wheat cap then forces a
  zero wheat value, whose unsigned comparison against any taker's sheep
  value keeps the trade on the fully-consumed branch, where both divisions
  return zero and the thresholds pass the empty trade through.  Every step
  around the symbolic taker is a ground evaluation, and the taker's own
  balance moves are the identity on a zero amount.
\<close>

lemma no_taker_can_take_the_griefed_offer:
  assumes "0 < sint (can_buy_at_most taker)"
    and "0 < sint (signed_min64 taker_amount (can_sell_at_most taker))"
  shows "cross_offer_v10 101 100 1
      \<lparr>sell_balance = 1, sell_liabilities = 1,
       buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>
      taker taker_amount Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok
      \<lparr>cross_wheat_received = 0, cross_sheep_send = 0,
       cross_wheat_stays = False, cross_offer_amount = 0,
       cross_maker =
         \<lparr>sell_balance = 1, sell_liabilities = 0,
          buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr>,
       cross_taker = taker\<rparr>"
proof -
  let ?released = "\<lparr>sell_balance = 1, sell_liabilities = 0,
    buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr>"
  let ?mwr = "can_buy_at_most taker"
  let ?mss = "signed_min64 taker_amount (can_sell_at_most taker)"
  have release: "release_offer_liabilities 101 100 1
      \<lparr>sell_balance = 1, sell_liabilities = 1,
       buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr> =
      Cxx_Ok ?released"
    by eval
  have mwr_pos: "0 < sint ?mwr" and mss_pos: "0 < sint ?mss"
    using assms by simp_all
  have pre: "calculate_offer_value_pre 100 101 ?mss ?mwr"
    using mwr_pos mss_pos by (simp add: calculate_offer_value_pre_def)
  obtain sv where sheep_ok:
      "calculate_offer_value 100 101 ?mss ?mwr = Cxx_Ok sv"
    using calculate_offer_value_success [OF pre] by blast
  have wheat_ok: "calculate_offer_value 101 100 0 1 = Cxx_Ok 0"
    by eval
  have no_stays: "((0::uint128) > sv) = False"
    by (simp add: word_less_def)
  have div128: "big_divide_or_throw128 0 (101::int64) Cxx_Round_Down =
      Cxx_Ok 0"
    by eval
  have div64: "big_divide_or_throw 0 (101::int64) (100::int64)
      Cxx_Round_Down = Cxx_Ok 0"
    by eval
  have amounts: "exchange_v10_amounts 101 100 0 sv 0 ?mwr ?mss 1 False
      Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok (0, 0)"
    by (simp add: exchange_v10_amounts_def div128 div64)
  have thresholds: "apply_price_error_thresholds 101 100 0 0 False
      Exchange_Normal = Cxx_Ok (make_exchange_result 0 0 False)"
    by eval
  have exchange: "exchange_v10_with_options 101 100 0 ?mwr ?mss 1 Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok (make_exchange_result 0 0 False)"
    using mwr_pos mss_pos
    by (simp add: exchange_v10_with_options_def
        exchange_v10_without_price_error_thresholds_with_options_def wheat_ok sheep_ok
        no_stays amounts thresholds make_exchange_result_def)
  have released_sell: "can_sell_at_most ?released = 1" by eval
  have released_buy: "can_buy_at_most ?released = 1" by eval
  have min_one: "signed_min64 1 (1::int64) = 1" by eval
  have min_zero: "signed_min64 0 (1::int64) = 0" by eval
  have adjust_flat: "adjust_offer_with_options 101 100 1 1 \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok 0" by eval
  have maker_receive: "party_receive_buy_asset ?released 0 = Cxx_Ok ?released"
    by eval
  have maker_spend: "party_spend_sell_asset ?released 0 = Cxx_Ok ?released"
    by eval
  have taker_receive: "party_receive_buy_asset taker 0 = Cxx_Ok taker"
    by (simp add: party_receive_buy_asset_def)
  have taker_spend: "party_spend_sell_asset taker 0 = Cxx_Ok taker"
    by (simp add: party_spend_sell_asset_def)
  show ?thesis
    using mwr_pos mss_pos
    by (simp add: cross_offer_v10_def Let_def release released_sell
        released_buy min_one min_zero adjust_flat exchange maker_receive
        maker_spend taker_receive taker_spend make_exchange_result_def
        make_cross_result_def)
qed

text \<open>
  The stability vocabulary of @{const adjust_stable} separates the two
  halves of the anomaly.  Posting writes only adjust-stable amounts: the
  amount admitted by Alice's post (@{thm [source] alice_posts_her_offer})
  is stable at the state it was validated against.  The universal form of
  this certificate---every successful post leaves an adjust-stable amount,
  which is what makes a maker-unchanged crossing replay the posted
  trade---is @{thm [source] unchanged_maker_cover_implies_adjust_stable}.  Ledger
  interference, by contrast, preserves the specification's covering
  premise but not stability: after Carol's payment the maker still covers
  the offer's booked liabilities, yet the amount is no longer stable at
  the released state that the crossing adjustment actually sees.  This is
  @{thm [source] no_taker_can_take_the_griefed_offer} in vocabulary form,
  and the repair goal is the missing implication from covering to
  stability: under either candidate fix the preventative adjustment must
  become the identity at every admissible crossing state.  Both lemmas
  are proved by evaluation.
\<close>

lemma posting_certifies_adjust_stability:
  "adjust_stable 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr> \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
  by eval

lemma covering_does_not_imply_adjust_stability:
  "maker_covers_offer_liabilities 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr> \<and>
   release_offer_liabilities 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr> =
     Cxx_Ok \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr> \<and>
   \<not> adjust_stable 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr> \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
  by eval

subsubsection \<open>A sheep-limit adjustment can make an offer untakeable\<close>

lemma no_taker_can_take_the_limit_adjusted_offer:
  assumes "0 < sint (can_buy_at_most taker)"
    and "0 < sint (signed_min64 taker_amount (can_sell_at_most taker))"
  shows "cross_offer_v10 101 100 1
      \<lparr>sell_balance = 1, sell_liabilities = 1,
       buy_limit = 1, buy_balance = 0, buy_liabilities = 1\<rparr>
      taker taker_amount Exchange_Normal
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok
      \<lparr>cross_wheat_received = 0, cross_sheep_send = 0,
       cross_wheat_stays = False, cross_offer_amount = 0,
       cross_maker =
         \<lparr>sell_balance = 1, sell_liabilities = 0,
          buy_limit = 1, buy_balance = 0, buy_liabilities = 0\<rparr>,
       cross_taker = taker\<rparr>"
text \<open>
  Proof sketch: releasing the posted offer's liabilities leaves the maker with
  one unit of wheat and one unit of sheep headroom.  With both receive-cap
  flags disabled, the preventative adjustment of a one-unit offer at price
  @{term "(101::int) / 100"} evaluates to zero.  The remaining exchange
  calculation therefore transfers zero on both sides for every taker satisfying
  the crossing function's positive-capacity precondition.  All state updates by
  zero are identities.
\<close>
proof -
  let ?released = "\<lparr>sell_balance = 1, sell_liabilities = 0,
    buy_limit = 1, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?mwr = "can_buy_at_most taker"
  let ?mss = "signed_min64 taker_amount (can_sell_at_most taker)"
  have release: "release_offer_liabilities 101 100 1
      \<lparr>sell_balance = 1, sell_liabilities = 1,
       buy_limit = 1, buy_balance = 0, buy_liabilities = 1\<rparr> =
      Cxx_Ok ?released"
    by eval
  have mwr_pos: "0 < sint ?mwr" and mss_pos: "0 < sint ?mss"
    using assms by simp_all
  have pre: "calculate_offer_value_pre 100 101 ?mss ?mwr"
    using mwr_pos mss_pos by (simp add: calculate_offer_value_pre_def)
  obtain sv where sheep_ok:
      "calculate_offer_value 100 101 ?mss ?mwr = Cxx_Ok sv"
    using calculate_offer_value_success [OF pre] by blast
  have wheat_ok: "calculate_offer_value 101 100 0 1 = Cxx_Ok 0"
    by eval
  have no_stays: "((0::uint128) > sv) = False"
    by (simp add: word_less_def)
  have div128: "big_divide_or_throw128 0 (101::int64) Cxx_Round_Down =
      Cxx_Ok 0"
    by eval
  have div64: "big_divide_or_throw 0 (101::int64) (100::int64)
      Cxx_Round_Down = Cxx_Ok 0"
    by eval
  have amounts: "exchange_v10_amounts 101 100 0 sv 0 ?mwr ?mss 1 False
      Exchange_Normal
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok (0, 0)"
    by (simp add: exchange_v10_amounts_def div128 div64)
  have thresholds: "apply_price_error_thresholds 101 100 0 0 False
      Exchange_Normal = Cxx_Ok (make_exchange_result 0 0 False)"
    by eval
  have exchange: "exchange_v10_with_options 101 100 0 ?mwr ?mss 1 Exchange_Normal
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok (make_exchange_result 0 0 False)"
    using mwr_pos mss_pos
    by (simp add: exchange_v10_with_options_def
        exchange_v10_without_price_error_thresholds_with_options_def wheat_ok sheep_ok
        no_stays amounts thresholds make_exchange_result_def)
  have released_sell: "can_sell_at_most ?released = 1" by eval
  have released_buy: "can_buy_at_most ?released = 1" by eval
  have min_one: "signed_min64 1 (1::int64) = 1" by eval
  have min_zero: "signed_min64 0 (1::int64) = 0" by eval
  have adjust_flat: "adjust_offer_with_options 101 100 1 1
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok 0"
    by eval
  have maker_receive: "party_receive_buy_asset ?released 0 =
      Cxx_Ok ?released"
    by eval
  have maker_spend: "party_spend_sell_asset ?released 0 =
      Cxx_Ok ?released"
    by eval
  have taker_receive: "party_receive_buy_asset taker 0 = Cxx_Ok taker"
    by (simp add: party_receive_buy_asset_def)
  have taker_spend: "party_spend_sell_asset taker 0 = Cxx_Ok taker"
    by (simp add: party_spend_sell_asset_def)
  show ?thesis
    using mwr_pos mss_pos
    by (simp add: cross_offer_v10_def Let_def release released_sell
        released_buy min_one min_zero adjust_flat exchange maker_receive
        maker_spend taker_receive taker_spend make_exchange_result_def
        make_cross_result_def)
qed

theorem limit_adjustment_stable_counterexample:
  "\<not> limit_adjustment_stable
    \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: Alice posts one unit of wheat at price
  @{term "(101::int) / 100"} while her sheep limit is two.  Posting books one
  unit of buying liability.  Lowering only @{const buy_limit} to one is still
  well formed because the new limit exactly covers that liability.  If
  @{const limit_adjustment_stable} held, some positive-capacity taker would
  then complete a positive cross.  The preceding lemma shows that every such
  cross instead returns zero wheat and zero sheep, a contradiction.
\<close>
proof
  assume stable: "limit_adjustment_stable
    \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
  let ?alice_at_post =
    "\<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?alice_after =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>"
  let ?alice_at_cross =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 1, buy_balance = 0, buy_liabilities = 1\<rparr>"
  have premises_hold:
    "party_state_wf ?alice_at_post \<and>
     post_offer 101 100 1 ?alice_at_post
       \<lparr>exact_receive_cap = False,
        symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (Post_Created 1 ?alice_after) \<and>
     party_state_wf ?alice_at_cross"
    by eval
  have promised:
    "\<exists>taker taker_amount crossed.
       party_state_wf taker \<and>
       0 < sint (can_buy_at_most taker) \<and>
       0 < sint
         (signed_min64 taker_amount (can_sell_at_most taker)) \<and>
       cross_offer_v10 101 100 1 ?alice_at_cross taker
         taker_amount Exchange_Normal
         \<lparr>exact_receive_cap = False,
          symmetric_exact_receive_cap = False\<rparr> =
           Cxx_Ok crossed \<and>
       0 < sint (cross_wheat_received crossed) \<and>
       0 < sint (cross_sheep_send crossed)"
    using stable[unfolded limit_adjustment_stable_def,
        THEN spec[where x = "(101::int32)"],
        THEN spec[where x = "(100::int32)"],
        THEN spec[where x = "(1::int64)"],
        THEN spec[where x = ?alice_at_post],
        THEN spec[where x = "(1::int64)"],
        THEN spec[where x = ?alice_after],
        THEN spec[where x = "(1::int64)"]] premises_hold
    by simp
  then obtain taker taker_amount crossed where
      mwr_pos: "0 < sint (can_buy_at_most taker)"
    and mss_pos:
      "0 < sint (signed_min64 taker_amount (can_sell_at_most taker))"
    and crossed:
      "cross_offer_v10 101 100 1 ?alice_at_cross taker taker_amount
        Exchange_Normal
        \<lparr>exact_receive_cap = False,
         symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok crossed"
    and wheat_positive: "0 < sint (cross_wheat_received crossed)"
    by blast
  have dead:
    "cross_offer_v10 101 100 1 ?alice_at_cross taker taker_amount
      Exchange_Normal
      \<lparr>exact_receive_cap = False,
       symmetric_exact_receive_cap = False\<rparr> =
     Cxx_Ok
       \<lparr>cross_wheat_received = 0, cross_sheep_send = 0,
        cross_wheat_stays = False, cross_offer_amount = 0,
        cross_maker =
          \<lparr>sell_balance = 1, sell_liabilities = 0,
           buy_limit = 1, buy_balance = 0, buy_liabilities = 0\<rparr>,
        cross_taker = taker\<rparr>"
    using no_taker_can_take_the_limit_adjusted_offer
      [OF mwr_pos mss_pos] .
  have ok_eq:
    "Cxx_Ok crossed =
     Cxx_Ok
       \<lparr>cross_wheat_received = 0, cross_sheep_send = 0,
        cross_wheat_stays = False, cross_offer_amount = 0,
        cross_maker =
          \<lparr>sell_balance = 1, sell_liabilities = 0,
           buy_limit = 1, buy_balance = 0, buy_liabilities = 0\<rparr>,
        cross_taker = taker\<rparr>"
    using crossed[symmetric] dead by (rule trans)
  have crossed_eq:
    "crossed =
       \<lparr>cross_wheat_received = 0, cross_sheep_send = 0,
        cross_wheat_stays = False, cross_offer_amount = 0,
        cross_maker =
          \<lparr>sell_balance = 1, sell_liabilities = 0,
           buy_limit = 1, buy_balance = 0, buy_liabilities = 0\<rparr>,
        cross_taker = taker\<rparr>"
    using ok_eq by simp
  have "cross_wheat_received crossed = 0"
    using crossed_eq by simp
  with wheat_positive show False
    by simp
qed

subsection \<open>Continuous specification and fixed-width refinement\<close>

text \<open>
  This subsection presents the refinement story in one place.  It first gives
  a continuous normal-exchange model over the reals, then identifies that model
  with the unbounded-integer quantities used to reason about the executable
  arithmetic.  Finally it proves that the fixed-width implementation with both
  receive-cap repairs returns the canonical whole-unit approximation for every
  successful positive normal exchange.
\<close>

subsubsection \<open>Continuous normal exchange\<close>

definition ideal_exchange_price ::
    "int32 \<Rightarrow> int32 \<Rightarrow> real"
  where
    "ideal_exchange_price price_n price_d =
      of_int (sint price_n) / of_int (sint price_d)"

definition ideal_wheat_offer_capacity ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> real"
  where
    "ideal_wheat_offer_capacity price_n price_d max_wheat_send
        max_sheep_receive =
      min (of_int (sint max_wheat_send))
        (of_int (sint max_sheep_receive) /
          ideal_exchange_price price_n price_d)"

definition ideal_sheep_offer_capacity ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> real"
  where
    "ideal_sheep_offer_capacity price_n price_d max_sheep_send
        max_wheat_receive =
      min (of_int (sint max_wheat_receive))
        (of_int (sint max_sheep_send) /
          ideal_exchange_price price_n price_d)"

definition ideal_normal_wheat_receive ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> real"
  where
    "ideal_normal_wheat_receive price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive =
      min
        (ideal_wheat_offer_capacity price_n price_d max_wheat_send
          max_sheep_receive)
        (ideal_sheep_offer_capacity price_n price_d max_sheep_send
          max_wheat_receive)"

definition ideal_normal_sheep_send ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> real"
  where
    "ideal_normal_sheep_send price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive =
      ideal_normal_wheat_receive price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive *
      ideal_exchange_price price_n price_d"

definition ideal_normal_wheat_stays ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> bool"
  where
    "ideal_normal_wheat_stays price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive \<longleftrightarrow>
      ideal_wheat_offer_capacity price_n price_d max_wheat_send
        max_sheep_receive >
      ideal_sheep_offer_capacity price_n price_d max_sheep_send
        max_wheat_receive"

text \<open>
  @{const ideal_exchange_price} embeds the ledger price as an exact real
  quotient.  The two capacity definitions measure, in wheat units, how much
  each offer could exchange at that price: each is the smaller of its wheat
  cap and its sheep cap divided by the price.  The ideal normal exchange takes
  the smaller capacity, transfers that much wheat and its exact-price amount of
  sheep, and keeps precisely the offer with the larger capacity.

  These definitions intentionally contain neither integer rounding nor
  fixed-width bounds.  They describe the continuous economic transaction;
  the discrete specification below states how an executable result projects
  that transaction onto whole ledger units.
\<close>

subsubsection \<open>Refinement relation\<close>

definition normal_result_refines_ideal ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_result_v10 \<Rightarrow> bool"
  where
    "normal_result_refines_ideal price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive result \<longleftrightarrow>
      result_wheat_stays result =
        ideal_normal_wheat_stays price_n price_d max_wheat_send
          max_wheat_receive max_sheep_send max_sheep_receive \<and>
      (if sint price_n > sint price_d
       then abs
         (of_int (sint (num_wheat_received result)) -
          ideal_normal_wheat_receive price_n price_d max_wheat_send
            max_wheat_receive max_sheep_send max_sheep_receive) < 1
       else abs
         (of_int (sint (num_sheep_send result)) -
          ideal_normal_sheep_send price_n price_d max_wheat_send
            max_wheat_receive max_sheep_send max_sheep_receive) < 1) \<and>
      favored_seller_ok price_n price_d
        (num_wheat_received result) (num_sheep_send result)
        (result_wheat_stays result) \<and>
      maximal_normal_favored_result price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive result"

text \<open>
  @{const normal_result_refines_ideal} connects the continuous and discrete
  layers.  Its first clause requires the real capacity comparison to choose
  the surviving offer.  Its second places the primary whole-unit amount less
  than one unit from the corresponding continuous amount.  Its third requires
  the effective-price inequality to favor the offer that stays.  The final
  clause requires the pair to be the maximal cap-respecting canonical round of
  the exact price, including the signed-result saturation ceiling.  The relation
  is stated only for the normal-mode policy; threshold zeroing is excluded
  later by requiring a positive returned trade.
\<close>

subsubsection \<open>Real and integer bridge\<close>

lemma real_min_divide_by_positive:
  fixes a b c :: real
  assumes denominator_positive: "0 < c"
  shows "min a (b / c) = min (a * c) b / c"
  text \<open>
    Proof sketch: multiplying both candidates by the same positive denominator
    preserves their order, so taking the minimum commutes with division by it.
  \<close>
  using denominator_positive
  by (auto simp add: min_def pos_le_divide_eq pos_divide_le_eq)

lemma ideal_wheat_offer_capacity_integer:
  assumes numerator_positive: "0 < sint price_n"
  shows "ideal_wheat_offer_capacity price_n price_d max_wheat_send
      max_sheep_receive =
    of_int (exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive) / of_int (sint price_n)"
  text \<open>
    Proof sketch: express the receive cap in wheat units by dividing it by the
    exact real price.  Clearing the positive numerator scales both alternatives
    to the common integer value used by the executable model.
  \<close>
proof -
  have numerator_real: "0 < (of_int (sint price_n) :: real)"
    using numerator_positive by (rule of_int_pos)
  show ?thesis
    unfolding ideal_wheat_offer_capacity_def ideal_exchange_price_def
      exchange_wheat_value_int_def
    apply (simp only: divide_divide_eq_right of_int_min of_int_mult)
    using real_min_divide_by_positive [OF numerator_real,
      of "of_int (sint max_wheat_send)"
         "of_int (sint max_sheep_receive) * of_int (sint price_d)"]
    by simp
qed

lemma ideal_sheep_offer_capacity_integer:
  assumes numerator_positive: "0 < sint price_n"
  shows "ideal_sheep_offer_capacity price_n price_d max_sheep_send
      max_wheat_receive =
    of_int (exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive) / of_int (sint price_n)"
  text \<open>
    Proof sketch: express the sheep offer's send cap in wheat units and clear
    the same positive price numerator.  The resulting minimum is the exact
    common-unit sheep value, up to commutativity of @{const min}.
  \<close>
proof -
  have numerator_real: "0 < (of_int (sint price_n) :: real)"
    using numerator_positive by (rule of_int_pos)
  show ?thesis
    unfolding ideal_sheep_offer_capacity_def ideal_exchange_price_def
      exchange_sheep_value_int_def
    apply (simp only: divide_divide_eq_right of_int_min of_int_mult)
    using real_min_divide_by_positive [OF numerator_real,
      of "of_int (sint max_wheat_receive)"
         "of_int (sint max_sheep_send) * of_int (sint price_d)"]
    by (simp add: min.commute)
qed

lemma ideal_normal_wheat_stays_integer:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "ideal_normal_wheat_stays price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive =
    (exchange_wheat_value_int price_n price_d max_wheat_send
       max_sheep_receive >
     exchange_sheep_value_int price_n price_d max_sheep_send
       max_wheat_receive)"
  text \<open>
    Proof sketch: both real capacities are their exact common-unit integer
    values divided by the same positive price numerator.  Cancelling that
    denominator leaves precisely the executable model's stay comparison.
  \<close>
proof -
  have numerator_positive: "0 < sint price_n"
    using pre by (simp add: exchange_v10_pre_def)
  have numerator_real: "0 < (of_int (sint price_n) :: real)"
    using numerator_positive by (rule of_int_pos)
  show ?thesis
    unfolding ideal_normal_wheat_stays_def
    apply (simp only:
      ideal_wheat_offer_capacity_integer [OF numerator_positive]
      ideal_sheep_offer_capacity_integer [OF numerator_positive])
    using numerator_real
    by (simp add: divide_less_cancel)
qed

lemma ideal_normal_wheat_receive_integer:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "ideal_normal_wheat_receive price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive =
    of_int
      (min
        (exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive)
        (exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive)) /
      of_int (sint price_n)"
  text \<open>
    Proof sketch: the ideal wheat transfer is the smaller offer capacity.
    Replace both capacities by their common-unit integer forms and commute a
    shared positive division with @{const min}.
  \<close>
proof -
  have numerator_positive: "0 < sint price_n"
    using pre by (simp add: exchange_v10_pre_def)
  have numerator_real: "0 < (of_int (sint price_n) :: real)"
    using numerator_positive by (rule of_int_pos)
  show ?thesis
    unfolding ideal_normal_wheat_receive_def
    apply (simp only:
      ideal_wheat_offer_capacity_integer [OF numerator_positive]
      ideal_sheep_offer_capacity_integer [OF numerator_positive]
      of_int_min)
    using numerator_real
    by (simp add: min_divide_distrib_right)
qed

lemma ideal_normal_sheep_send_integer:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "ideal_normal_sheep_send price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive =
    of_int
      (min
        (exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive)
        (exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive)) /
      of_int (sint price_d)"
  text \<open>
    Proof sketch: the ideal sheep transfer is the ideal wheat transfer times
    the exact real price.  Substitute the common trade value and cancel the
    positive price numerator.
  \<close>
proof -
  have numerator_positive: "0 < sint price_n"
    using pre by (simp add: exchange_v10_pre_def)
  have numerator_nonzero: "(of_int (sint price_n) :: real) \<noteq> 0"
    using numerator_positive by (intro notI) simp
  show ?thesis
    unfolding ideal_normal_sheep_send_def ideal_exchange_price_def
    apply (simp only: ideal_normal_wheat_receive_integer [OF pre])
    using numerator_nonzero
    by simp
qed

lemma real_rounded_division_with_slack:
  fixes base adjusted divisor :: int
  assumes divisor_positive: "0 < divisor"
      and base_le_adjusted: "base \<le> adjusted"
      and adjusted_le: "adjusted \<le> base + divisor - 1"
  shows "abs (of_int (adjusted div divisor) -
      of_int base / of_int divisor :: real) < 1"
  text \<open>
    Proof sketch: the adjusted numerator is less than one denominator above the
    ideal numerator.  The defining lower and upper bounds of integer division
    therefore put its quotient less than one real unit on either side of the
    exact quotient.
  \<close>
proof -
  let ?q = "adjusted div divisor"
  have quotient_lower: "?q * divisor \<le> adjusted"
    using int_div_mult_le [OF divisor_positive] .
  have remainder_less: "adjusted mod divisor < divisor"
    using divisor_positive by simp
  have decomposition:
      "adjusted mod divisor + ?q * divisor = adjusted"
    by (rule mod_div_mult_eq)
  have quotient_upper: "adjusted < (?q + 1) * divisor"
  proof -
    have "adjusted = adjusted mod divisor + ?q * divisor"
      using decomposition by simp
    also have "... < divisor + ?q * divisor"
      using remainder_less by linarith
    also have "... = (?q + 1) * divisor"
      by (simp add: algebra_simps)
    finally show ?thesis .
  qed
  have lower_int: "(?q - 1) * divisor < base"
  proof -
    have "(?q - 1) * divisor = ?q * divisor - divisor"
      by (simp add: algebra_simps)
    also have "... \<le> adjusted - divisor"
      using quotient_lower by linarith
    also have "... \<le> base - 1"
      using adjusted_le by linarith
    also have "... < base" by simp
    finally show ?thesis .
  qed
  have upper_int: "base < (?q + 1) * divisor"
    using base_le_adjusted quotient_upper by linarith
  have divisor_real: "0 < (of_int divisor :: real)"
    using divisor_positive by (rule of_int_pos)
  have lower_cast:
      "(of_int ((?q - 1) * divisor) :: real) < of_int base"
    using lower_int by (simp only: of_int_less_iff)
  have upper_cast:
      "(of_int base :: real) < of_int ((?q + 1) * divisor)"
    using upper_int by (simp only: of_int_less_iff)
  have lower_real:
      "(of_int (?q - 1) :: real) <
        of_int base / of_int divisor"
    using lower_cast divisor_real
    by (simp add: pos_less_divide_eq)
  have upper_real:
      "of_int base / of_int divisor <
        (of_int (?q + 1) :: real)"
    using upper_cast divisor_real
    by (simp add: pos_divide_less_eq)
  show ?thesis
    using lower_real upper_real
    by (simp add: abs_less_iff)
qed

subsubsection \<open>Primary-unit proximity\<close>

lemma exchange_v10_amounts_int_repaired_within_ideal:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "if sint price_n > sint price_d
    then abs
      (of_int
        (fst (exchange_v10_amounts_int_repaired price_n price_d
          max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive)) -
       ideal_normal_wheat_receive price_n price_d max_wheat_send
         max_wheat_receive max_sheep_send max_sheep_receive) < 1
    else abs
      (of_int
        (snd (exchange_v10_amounts_int_repaired price_n price_d
          max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive)) -
       ideal_normal_sheep_send price_n price_d max_wheat_send
         max_wheat_receive max_sheep_send max_sheep_receive) < 1"
  text \<open>
    Proof sketch: split on the more valuable asset and the offer that stays.
    The two unchanged branches floor the exact common trade value.  Each
    repaired branch can raise that value by less than the primary divisor, and
    never lowers it; the generic slack lemma therefore bounds the primary
    whole-unit result within one unit of the continuous ideal.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive"
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    using pre by (simp_all add: exchange_v10_pre_def)
  show ?thesis
  proof (cases "sint price_n > sint price_d")
    case wheat_more: True
    show ?thesis
    proof (cases "?W > ?S")
      case wheat_stays: True
      have close:
          "abs (of_int (?S div sint price_n) -
            of_int ?S / of_int (sint price_n) :: real) < 1"
        using real_rounded_division_with_slack
          [where base = ?S and adjusted = ?S
             and divisor = "sint price_n"] pn
        by simp
      show ?thesis
        using close ideal_normal_wheat_receive_integer [OF pre]
          wheat_more wheat_stays
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
    next
      case sheep_stays: False
      let ?send = "sint max_wheat_send * sint price_n"
      let ?receive = "sint max_sheep_receive * sint price_d"
      let ?saturation = "sint int64_max * sint price_d"
      let ?trade =
        "min ?send
          (min (?receive + sint price_d - 1) ?saturation)"
      have W_send: "?W \<le> ?send" and W_receive: "?W \<le> ?receive"
        using exchange_wheat_value_int_bounds [OF pre] by auto
      have receive_saturation: "?receive \<le> ?saturation"
        using sint64_upper_bound [of max_sheep_receive]
          less_imp_le [OF pd]
        by (simp add: int64_max_def mult_right_mono)
      have W_saturation: "?W \<le> ?saturation"
        using W_receive receive_saturation by linarith
      have base_le_trade: "?W \<le> ?trade"
        using W_send W_receive W_saturation pd
        by simp
      have trade_le_base: "?trade \<le> ?W + sint price_n - 1"
      proof (cases "?send \<le> ?receive")
        case True
        have W_eq: "?W = ?send"
          using True by (simp add: exchange_wheat_value_int_def)
        have "?trade \<le> ?send" by simp
        with W_eq pn show ?thesis by linarith
      next
        case False
        have W_eq: "?W = ?receive"
          using False by (simp add: exchange_wheat_value_int_def)
        have "?trade \<le> ?receive + sint price_d - 1" by simp
        with W_eq wheat_more show ?thesis by linarith
      qed
      have close:
          "abs (of_int (?trade div sint price_n) -
            of_int ?W / of_int (sint price_n) :: real) < 1"
        using real_rounded_division_with_slack
          [OF pn base_le_trade trade_le_base] .
      show ?thesis
        using close ideal_normal_wheat_receive_integer [OF pre]
          wheat_more sheep_stays
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
    qed
  next
    case sheep_more: False
    show ?thesis
    proof (cases "?W > ?S")
      case wheat_stays: True
      let ?send = "sint max_sheep_send * sint price_d"
      let ?receive = "sint max_wheat_receive * sint price_n"
      let ?saturation = "sint int64_max * sint price_n"
      let ?trade =
        "min ?send
          (min (?receive + sint price_n - 1) ?saturation)"
      have S_send: "?S \<le> ?send" and S_receive: "?S \<le> ?receive"
        using exchange_sheep_value_int_bounds [OF pre] by auto
      have receive_saturation: "?receive \<le> ?saturation"
        using sint64_upper_bound [of max_wheat_receive]
          less_imp_le [OF pn]
        by (simp add: int64_max_def mult_right_mono)
      have S_saturation: "?S \<le> ?saturation"
        using S_receive receive_saturation by linarith
      have base_le_trade: "?S \<le> ?trade"
        using S_send S_receive S_saturation pn
        by simp
      have trade_le_base: "?trade \<le> ?S + sint price_d - 1"
      proof (cases "?send \<le> ?receive")
        case True
        have S_eq: "?S = ?send"
          using True by (simp add: exchange_sheep_value_int_def)
        have "?trade \<le> ?send" by simp
        with S_eq pd show ?thesis by linarith
      next
        case False
        have S_eq: "?S = ?receive"
          using False by (simp add: exchange_sheep_value_int_def)
        have "?trade \<le> ?receive + sint price_n - 1" by simp
        with S_eq sheep_more show ?thesis by linarith
      qed
      have close:
          "abs (of_int (?trade div sint price_d) -
            of_int ?S / of_int (sint price_d) :: real) < 1"
        using real_rounded_division_with_slack
          [OF pd base_le_trade trade_le_base] .
      show ?thesis
        using close ideal_normal_sheep_send_integer [OF pre]
          sheep_more wheat_stays
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
    next
      case sheep_stays: False
      have close:
          "abs (of_int (?W div sint price_d) -
            of_int ?W / of_int (sint price_d) :: real) < 1"
        using real_rounded_division_with_slack
          [where base = ?W and adjusted = ?W
             and divisor = "sint price_d"] pd
        by simp
      show ?thesis
        using close ideal_normal_sheep_send_integer [OF pre]
          sheep_more sheep_stays
        by (simp add: exchange_v10_amounts_int_repaired_def Let_def)
    qed
  qed
qed

subsubsection \<open>End-to-end refinement\<close>

theorem exchange_v10_repaired_positive_normal_refines_ideal:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
      Cxx_Ok exchange_result"
    and wheat_positive:
      "0 < sint (num_wheat_received exchange_result)"
    and sheep_positive:
      "0 < sint (num_sheep_send exchange_result)"
  shows "normal_result_refines_ideal price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive exchange_result"
  text \<open>
    Proof sketch: the repaired integer characterization exposes the exact
    pre-threshold amount record.  Positivity excludes the threshold's zero
    alternative, fixing the returned stay flag to the integer offer-value
    comparison, which is the real ideal capacity comparison.  The amount
    characterization and continuous proximity lemma establish the strict
    one-primary-unit error bound.  The positive-success theorem makes the
    staying offer's favorable effective-price inequality explicit, and the
    repaired maximality theorem supplies the final canonical lattice round.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive"
  let ?WR = "word_of_int (fst ?A) :: int64"
  let ?SS = "word_of_int (snd ?A) :: int64"
  let ?stays = "exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive Exchange_Normal
        \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
       apply_price_error_thresholds price_n price_d ?WR ?SS ?stays
         Exchange_Normal"
    using exchange_v10_repaired_integer_characterization [OF pre] by simp
  have applied:
      "apply_price_error_thresholds price_n price_d ?WR ?SS ?stays
        Exchange_Normal = Cxx_Ok exchange_result"
    using result exact by simp
  note choices = apply_price_error_thresholds_result_choices [OF applied]
  have result_record:
      "exchange_result = make_exchange_result ?WR ?SS ?stays"
    using choices wheat_positive sheep_positive
    by (auto simp add: make_exchange_result_def)
  have stays_field: "result_wheat_stays exchange_result = ?stays"
    using result_record by (simp add: make_exchange_result_def)
  have ideal_stays:
      "ideal_normal_wheat_stays price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive = ?stays"
    using ideal_normal_wheat_stays_integer [OF pre] .
  note words =
    exchange_v10_amounts_repaired_integer_characterization [OF pre]
  have wheat_field:
      "sint (num_wheat_received exchange_result) = fst ?A"
    using result_record words(2) by (simp add: make_exchange_result_def)
  have sheep_field:
      "sint (num_sheep_send exchange_result) = snd ?A"
    using result_record words(3) by (simp add: make_exchange_result_def)
  have close:
      "if sint price_n > sint price_d
       then abs
         (of_int (sint (num_wheat_received exchange_result)) -
          ideal_normal_wheat_receive price_n price_d max_wheat_send
            max_wheat_receive max_sheep_send max_sheep_receive) < 1
       else abs
         (of_int (sint (num_sheep_send exchange_result)) -
          ideal_normal_sheep_send price_n price_d max_wheat_send
            max_wheat_receive max_sheep_send max_sheep_receive) < 1"
    using exchange_v10_amounts_int_repaired_within_ideal [OF pre]
      wheat_field sheep_field
    by simp
  have favored:
      "favored_seller_ok price_n price_d
        (num_wheat_received exchange_result) (num_sheep_send exchange_result)
        (result_wheat_stays exchange_result)"
    using successful_exchange_favors_offer_that_stays [OF result]
      wheat_positive sheep_positive
    by simp
  have maximal:
      "maximal_normal_favored_result price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive exchange_result"
    using exchange_v10_repaired_positive_normal_maximal
      [OF pre result wheat_positive sheep_positive] .
  show ?thesis
    unfolding normal_result_refines_ideal_def
    using stays_field ideal_stays close favored maximal by simp
qed

subsection \<open>An unconstrained-maker benchmark, kept for reference\<close>

text \<open>
  The following definitions formalize one possible notion of maker
  non-interference.  They are retained as diagnostic material, not asserted as
  intended lifecycle properties: it is not yet clear that the
  unconstrained-maker result is the behavior the protocol should require.

  The benchmark function below computes the fill from the posted amount and
  the taker's limits alone by replacing the maker's receive limit with
  @{const int64_max}.  This removes maker-state dependence from the exchange
  arithmetic, including from the decision about which offer stays.
\<close>

definition exchange_unconstrained_maker ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow> int64 \<Rightarrow>
      exchange_rounding \<Rightarrow> exchange_options \<Rightarrow> exchange_result_v10 cxx_result"
  where
    "exchange_unconstrained_maker price_n price_d amount taker taker_amount
        rounding options =
      exchange_v10_with_options price_n price_d amount (can_buy_at_most taker)
        (signed_min64 taker_amount (can_sell_at_most taker)) int64_max
        rounding options"

definition maker_non_interference_at ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> party_state \<Rightarrow> party_state \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow> bool"
  where
    "maker_non_interference_at price_n price_d amount maker taker
        taker_amount rounding options \<longleftrightarrow>
      (case (cross_offer_v10 price_n price_d amount maker taker taker_amount
               rounding options,
             exchange_unconstrained_maker price_n price_d amount taker
               taker_amount rounding options) of
         (Cxx_Ok crossed, Cxx_Ok unconstrained) \<Rightarrow>
           cross_wheat_received crossed = num_wheat_received unconstrained \<and>
           cross_sheep_send crossed = num_sheep_send unconstrained \<and>
           cross_wheat_stays crossed = result_wheat_stays unconstrained
       | _ \<Rightarrow> False)"

definition posted_offers_trade_as_written :: "exchange_options \<Rightarrow> bool"
  where
    "posted_offers_trade_as_written options \<longleftrightarrow>
      (\<forall>price_n price_d amount maker_at_post posted maker_after
         maker_at_cross taker taker_amount.
        party_state_wf maker_at_post \<and>
        party_state_wf maker_at_cross \<and>
        party_state_wf taker \<and>
        post_offer price_n price_d amount maker_at_post options =
          Cxx_Ok (Post_Created posted maker_after) \<and>
        maker_covers_offer_liabilities price_n price_d posted
          maker_at_cross \<and>
        0 < sint (can_buy_at_most taker) \<and>
        0 < sint (signed_min64 taker_amount (can_sell_at_most taker)) \<longrightarrow>
        maker_non_interference_at price_n price_d posted maker_at_cross
          taker taker_amount Exchange_Normal options)"

text \<open>
  @{const maker_non_interference_at} compares a real crossing with that
  unconstrained-maker benchmark: both calls must succeed and agree on the
  amount the maker sells, the amount the taker sends, and which side remains.
  @{const posted_offers_trade_as_written} lifts the comparison to every
  successful post, every well-formed crossing state that still covers the
  offer's reservation, and every admissible normal-mode taker.

  These predicates capture a useful, strong comparison, but choosing the
  unconstrained-maker fill as normative would additionally require maker-side
  headroom and the resulting \<open>wheatStays\<close> decision to be observationally
  irrelevant.  The counterexamples below record that the shipped behavior and
  the current exact-receive-cap candidate do not satisfy this comparison; they
  do not by themselves establish that the implementation should be changed to
  satisfy it.
\<close>

subsubsection \<open>The shipped protocol differs from the benchmark\<close>

text \<open>
  The griefing replay refutes
  @{term "posted_offers_trade_as_written \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"}, the benchmark comparison
  for the shipped protocol.  Instantiate it with the walkthrough numbers: Alice
  posts one TOKEN at 101/100, her state at the crossing step is the one
  Carol's payment produces, and Bob is the taker.  Every premise holds by
  evaluation, while the crossing fills nothing and the unconstrained-maker
  exchange fills one TOKEN against one USD.  Proof sketch: evaluate the
  premises and the pointwise benchmark comparison at that instance, then
  specialize the universal comparison.
\<close>

lemma posted_offers_do_not_trade_as_written:
  "\<not> posted_offers_trade_as_written \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
proof
  assume asm: "posted_offers_trade_as_written \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
  let ?alice_at_post =
    "\<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?alice_after =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>"
  let ?alice_at_cross =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>"
  let ?bob =
    "\<lparr>sell_balance = 2, sell_liabilities = 0,
      buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>"
  have premises_hold:
    "party_state_wf ?alice_at_post \<and>
     party_state_wf ?alice_at_cross \<and>
     party_state_wf ?bob \<and>
     post_offer 101 100 1 ?alice_at_post \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (Post_Created 1 ?alice_after) \<and>
     maker_covers_offer_liabilities 101 100 1 ?alice_at_cross \<and>
     0 < sint (can_buy_at_most ?bob) \<and>
     0 < sint (signed_min64 2 (can_sell_at_most ?bob))"
    by eval
  have violated:
    "\<not> maker_non_interference_at 101 100 1 ?alice_at_cross ?bob 2
       Exchange_Normal \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
    by eval
  show False
    using asm[unfolded posted_offers_trade_as_written_def, rule_format,
        OF premises_hold] violated
    by simp
qed

subsubsection \<open>The exact receive cap repairs the walkthrough, not the
  benchmark comparison\<close>

text \<open>
  With the flag on, the walkthrough griefing disappears: the preventative
  adjustment values Alice's one-USD headroom as enough for her last unit of
  wheat, so the same crossing that filled nothing under the plain cap now
  fills her offer completely.  The lemma repeats
  @{thm [source] carol_griefs_alice} with the exact receive cap and is
  proved by evaluating both sides.
\<close>

lemma exact_receive_cap_repairs_the_walkthrough:
  "post_then_cross 101 100 1
     \<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>
     \<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>
     \<lparr>sell_balance = 2, sell_liabilities = 0,
      buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>
     2 Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
   Cxx_Ok
     (Post_Created 1
        \<lparr>sell_balance = 1, sell_liabilities = 1,
         buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>,
      Some
        \<lparr>cross_wheat_received = 1,
         cross_sheep_send = 1,
         cross_wheat_stays = False,
         cross_offer_amount = 0,
         cross_maker =
           \<lparr>sell_balance = 0, sell_liabilities = 0,
            buy_limit = 2, buy_balance = 2, buy_liabilities = 0\<rparr>,
         cross_taker =
           \<lparr>sell_balance = 1, sell_liabilities = 0,
            buy_limit = 1000, buy_balance = 1, buy_liabilities = 0\<rparr>\<rparr>)"
  by eval

text \<open>
  The benchmark comparison nevertheless stays false, because the fix deliberately
  leaves the \<open>wheatStays\<close> comparison in
  \<open>exchangeV10WithoutPriceErrorThresholds\<close> on the plain truncating
  values.  A maker whose sheep headroom equals its
  booked buying liability presents a wheat value up to
  @{term "sint price_d - 1"} below the one an unconstrained maker would
  present, and a taker whose sheep value lands in that gap flips the
  comparison: against the constrained maker the resting offer is the
  smaller side and is taken completely, while against the unconstrained
  benchmark it is the larger side and the fill is zero.  The witness below
  reuses the walkthrough state after Carol's payment; the taker is Bob
  willing to sell only one USD, whose sheep value 100 lands in the gap
  between Alice's constrained wheat value 100 and her unconstrained wheat
  value 101.  The crossing then fills one TOKEN against one USD while the
  benchmark fills nothing, so the maker is not griefed---the offer fills
  more, not less---but the fill still depends on maker state that the
  ledger invariants admit.  Both exchange outcomes were confirmed against
  the stellar-core C++.  Proof sketch: as in
  @{thm [source] posted_offers_do_not_trade_as_written}, every premise
  holds by evaluation.  Evaluate the real crossing and the unconstrained
  benchmark separately: their wheat amounts are one and zero, their sheep
  amounts are one and zero, and their stay flags are false and true.  The
  proof then exposes these three unequal selector values before unfolding
  the conjunction required by @{const maker_non_interference_at}.
\<close>

lemma exact_receive_cap_does_not_restore_trade_as_written:
  "\<not> posted_offers_trade_as_written \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
proof
  assume asm: "posted_offers_trade_as_written \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
  let ?alice_at_post =
    "\<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?alice_after =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>"
  let ?alice_at_cross =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>"
  let ?bob =
    "\<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?crossed =
    "make_cross_result 1 1 False 0
      \<lparr>sell_balance = 0, sell_liabilities = 0,
       buy_limit = 2, buy_balance = 2, buy_liabilities = 0\<rparr>
      \<lparr>sell_balance = 0, sell_liabilities = 0,
       buy_limit = 1000, buy_balance = 1, buy_liabilities = 0\<rparr>"
  let ?unconstrained = "make_exchange_result 0 0 True"
  have premises_hold:
    "party_state_wf ?alice_at_post \<and>
     party_state_wf ?alice_at_cross \<and>
     party_state_wf ?bob \<and>
     post_offer 101 100 1 ?alice_at_post \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (Post_Created 1 ?alice_after) \<and>
     maker_covers_offer_liabilities 101 100 1 ?alice_at_cross \<and>
     0 < sint (can_buy_at_most ?bob) \<and>
     0 < sint (signed_min64 1 (can_sell_at_most ?bob))"
    by eval
  have real_cross:
    "cross_offer_v10 101 100 1 ?alice_at_cross ?bob 1
       Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok ?crossed"
    by eval
  have benchmark:
    "exchange_unconstrained_maker 101 100 1 ?bob 1 Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok ?unconstrained"
    by eval
  have selector_values:
    "cross_wheat_received ?crossed = 1 \<and>
     num_wheat_received ?unconstrained = 0 \<and>
     cross_sheep_send ?crossed = 1 \<and>
     num_sheep_send ?unconstrained = 0 \<and>
     cross_wheat_stays ?crossed = False \<and>
     result_wheat_stays ?unconstrained = True"
    by (simp add: make_cross_result_def make_exchange_result_def)
  have comparison_fails:
    "\<not> (cross_wheat_received ?crossed =
          num_wheat_received ?unconstrained \<and>
        cross_sheep_send ?crossed =
          num_sheep_send ?unconstrained \<and>
        cross_wheat_stays ?crossed =
          result_wheat_stays ?unconstrained)"
    using selector_values by simp
  have violated:
    "\<not> maker_non_interference_at 101 100 1 ?alice_at_cross ?bob 1
       Exchange_Normal \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
    unfolding maker_non_interference_at_def
    using real_cross benchmark comparison_fails
    by simp
  show False
    using asm[unfolded posted_offers_trade_as_written_def, rule_format,
        OF premises_hold] violated
    by simp
qed

subsection \<open>Proofs and counterexamples: fully taken posted offers\<close>

text \<open>
  This subsection proves the exact-amount property stated with the intended
  lifecycle predicates above.  It is placed after the benchmark material so
  the proof can reuse all established posting, coverage, adjustment, and
  exchange contracts.  The key arithmetic observation holds uniformly for
  every option record: once the resting wheat offer is known not to stay, two
  calls under the same options no longer differ because of the taker's caps or
  the rounding mode.
  The exact receive cap is needed one layer higher, to make liability coverage
  preserve the posted offer's positive adjustment after the maker state
  changes.  The symmetric receive cap is irrelevant to both adjustments and
  to the non-staying branch, so the strongest theorem quantifies its value and
  a final corollary supplies the requested both-enabled record.
\<close>

lemma check_exchange_v10_result_success_record:
  assumes result:
    "check_exchange_v10_result max_wheat_send max_wheat_receive
       max_sheep_send max_sheep_receive wheat_stays amounts = Cxx_Ok outcome"
  shows "outcome = make_exchange_result (fst amounts) (snd amounts) wheat_stays"
text \<open>
  Proof sketch: unfold the final bounds checker.  Every successful branch
  returns exactly the record made from the checked pair and the supplied stay
  flag.
\<close>
  using result
  by (auto simp add: check_exchange_v10_result_def Let_def
      split: if_splits)

lemma exchange_v10_amounts_nonstaying_independent:
  "exchange_v10_amounts price_n price_d wheat_value sheep_value1
      max_wheat_send max_wheat_receive1 max_sheep_send1 max_sheep_receive
      False rounding1 options =
   exchange_v10_amounts price_n price_d wheat_value sheep_value2
      max_wheat_send max_wheat_receive2 max_sheep_send2 max_sheep_receive
      False rounding2 options"
text \<open>
  Proof sketch: unfold the amount calculation at a false wheat-stays flag.
  Both remaining price branches use only the wheat value and maker-side caps;
  the sheep value, taker-side caps, rounding mode, and symmetric option are
  unreachable or unused.
\<close>
  by (simp add: exchange_v10_amounts_def)

lemma exchange_without_nonstaying_amounts_independent:
  assumes first:
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d
       max_wheat_send max_wheat_receive1 max_sheep_send1 max_sheep_receive
       rounding1 options = Cxx_Ok result1"
    and second:
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d
       max_wheat_send max_wheat_receive2 max_sheep_send2 max_sheep_receive
       rounding2 options = Cxx_Ok result2"
    and first_nonstaying: "\<not> result_wheat_stays result1"
    and second_nonstaying: "\<not> result_wheat_stays result2"
  shows "num_wheat_received result1 = num_wheat_received result2 \<and>
         num_sheep_send result1 = num_sheep_send result2"
text \<open>
  Proof sketch: invert the two successful pre-threshold exchanges through
  their common wheat-value calculation and final checked constructors.  Their
  false stay flags put both calls in the independent amount branch above, so
  the amount pairs and hence both result fields agree.
\<close>
proof -
  note first' = first[unfolded exchange_v10_without_as_checked_amounts]
  obtain wheat_value where wheat_value:
      "calculate_offer_value price_n price_d max_wheat_send
         max_sheep_receive = Cxx_Ok wheat_value"
    using first'
    by (cases "calculate_offer_value price_n price_d max_wheat_send
         max_sheep_receive") simp_all
  obtain sheep_value1 where sheep_value1:
      "calculate_offer_value price_d price_n max_sheep_send1
         max_wheat_receive1 = Cxx_Ok sheep_value1"
    using first' wheat_value
    by (cases "calculate_offer_value price_d price_n max_sheep_send1
         max_wheat_receive1") simp_all
  obtain amounts1 where amounts1:
      "exchange_v10_amounts price_n price_d wheat_value sheep_value1
         max_wheat_send max_wheat_receive1 max_sheep_send1 max_sheep_receive
         (wheat_value > sheep_value1) rounding1 options = Cxx_Ok amounts1"
    using first' wheat_value sheep_value1
    by (cases "exchange_v10_amounts price_n price_d wheat_value sheep_value1
         max_wheat_send max_wheat_receive1 max_sheep_send1 max_sheep_receive
         (wheat_value > sheep_value1) rounding1 options") simp_all
  have checked1:
      "check_exchange_v10_result max_wheat_send max_wheat_receive1
         max_sheep_send1 max_sheep_receive (wheat_value > sheep_value1)
         amounts1 = Cxx_Ok result1"
    using first' wheat_value sheep_value1 amounts1 by simp
  have record1:
      "result1 = make_exchange_result (fst amounts1) (snd amounts1)
         (wheat_value > sheep_value1)"
    using check_exchange_v10_result_success_record [OF checked1] .
  have stays1: "\<not> wheat_value > sheep_value1"
    using first_nonstaying record1
    by (simp add: make_exchange_result_def)

  note second' = second[unfolded exchange_v10_without_as_checked_amounts]
  obtain sheep_value2 where sheep_value2:
      "calculate_offer_value price_d price_n max_sheep_send2
         max_wheat_receive2 = Cxx_Ok sheep_value2"
    using second' wheat_value
    by (cases "calculate_offer_value price_d price_n max_sheep_send2
         max_wheat_receive2") simp_all
  obtain amounts2 where amounts2:
      "exchange_v10_amounts price_n price_d wheat_value sheep_value2
         max_wheat_send max_wheat_receive2 max_sheep_send2 max_sheep_receive
         (wheat_value > sheep_value2) rounding2 options = Cxx_Ok amounts2"
    using second' wheat_value sheep_value2
    by (cases "exchange_v10_amounts price_n price_d wheat_value sheep_value2
         max_wheat_send max_wheat_receive2 max_sheep_send2 max_sheep_receive
         (wheat_value > sheep_value2) rounding2 options") simp_all
  have checked2:
      "check_exchange_v10_result max_wheat_send max_wheat_receive2
         max_sheep_send2 max_sheep_receive (wheat_value > sheep_value2)
         amounts2 = Cxx_Ok result2"
    using second' wheat_value sheep_value2 amounts2 by simp
  have record2:
      "result2 = make_exchange_result (fst amounts2) (snd amounts2)
         (wheat_value > sheep_value2)"
    using check_exchange_v10_result_success_record [OF checked2] .
  have stays2: "\<not> wheat_value > sheep_value2"
    using second_nonstaying record2
    by (simp add: make_exchange_result_def)
  have amounts_equal: "amounts1 = amounts2"
    using amounts1 amounts2 stays1 stays2
      exchange_v10_amounts_nonstaying_independent
        [of price_n price_d wheat_value sheep_value1 max_wheat_send
          max_wheat_receive1 max_sheep_send1 max_sheep_receive rounding1
          options sheep_value2 max_wheat_receive2 max_sheep_send2 rounding2]
    by simp
  show ?thesis
    using record1 record2 amounts_equal
    by (simp add: make_exchange_result_def)
qed

lemma exchange_v10_nonstaying_matches_positive_adjustment:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_positive: "0 < sint max_wheat_send"
    and sheep_nonnegative: "0 \<le> sint max_sheep_receive"
    and adjustment:
      "adjust_offer_with_options price_n price_d max_wheat_send max_sheep_receive options =
       Cxx_Ok max_wheat_send"
    and exchange:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
         max_sheep_send max_sheep_receive rounding options = Cxx_Ok result"
    and nonstaying: "\<not> result_wheat_stays result"
  shows "num_wheat_received result = max_wheat_send"
text \<open>
  Proof sketch: @{const adjust_offer_with_options} is the same exchange against an unlimited
  counterparty in normal mode.  A positive fixed adjustment therefore supplies
  a successful non-staying reference exchange that returns the full wheat cap.
  Any other successful non-staying exchange with the same maker caps has the
  same pre-threshold pair.  Normal mode makes the threshold calls identical;
  either path mode must preserve that positive pair on success.  Thus arbitrary
  taker caps and arbitrary rounding return the reference wheat amount.
\<close>
proof -
  obtain reference where reference:
      "exchange_v10_with_options price_n price_d max_wheat_send int64_max int64_max
         max_sheep_receive Exchange_Normal options = Cxx_Ok reference"
    and reference_wheat:
      "num_wheat_received reference = max_wheat_send"
    using adjustment
    by (cases "exchange_v10_with_options price_n price_d max_wheat_send int64_max
         int64_max max_sheep_receive Exchange_Normal options")
       (simp_all add: adjust_offer_with_options_def)
  have reference_nonstaying: "\<not> result_wheat_stays reference"
    using exchange_against_unlimited_counterparty_does_not_leave_wheat
      [OF pn pd less_imp_le[OF wheat_positive] sheep_nonnegative reference] .
  obtain before_reference where before_reference:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send int64_max int64_max max_sheep_receive
         Exchange_Normal options = Cxx_Ok before_reference"
    and reference_threshold:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before_reference)
         (num_sheep_send before_reference)
         (result_wheat_stays before_reference) Exchange_Normal =
       Cxx_Ok reference"
    using reference
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send int64_max int64_max max_sheep_receive
         Exchange_Normal options")
       (simp_all add: exchange_v10_with_options_def)
  have before_reference_nonstaying:
      "\<not> result_wheat_stays before_reference"
    using reference_nonstaying
      apply_price_error_thresholds_preserves_wheat_stays
        [OF reference_threshold]
    by simp
  have reference_is_before: "reference = before_reference"
    using apply_price_error_thresholds_normal_result [OF reference_threshold]
      reference_wheat wheat_positive
    by (auto simp add: make_exchange_result_def)
  have before_reference_wheat:
      "num_wheat_received before_reference = max_wheat_send"
    using reference_wheat reference_is_before by simp
  have reference_sheep_positive:
      "0 < sint (num_sheep_send reference)"
    using exchange_normal_positive_wheat_has_positive_sheep
      [OF reference] reference_wheat wheat_positive
    by simp
  have before_reference_sheep_positive:
      "0 < sint (num_sheep_send before_reference)"
    using reference_sheep_positive reference_is_before by simp

  obtain before where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         rounding options = Cxx_Ok before"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before) (num_sheep_send before)
         (result_wheat_stays before) rounding = Cxx_Ok result"
    using exchange
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         rounding options")
       (simp_all add: exchange_v10_with_options_def)
  have before_nonstaying: "\<not> result_wheat_stays before"
    using nonstaying apply_price_error_thresholds_preserves_wheat_stays
      [OF thresholds]
    by simp
  have before_amounts:
      "num_wheat_received before_reference = num_wheat_received before \<and>
       num_sheep_send before_reference = num_sheep_send before"
    using exchange_without_nonstaying_amounts_independent
      [OF before_reference before before_reference_nonstaying
        before_nonstaying] .
  have before_wheat: "num_wheat_received before = max_wheat_send"
    using before_amounts before_reference_wheat by simp
  have before_sheep_positive: "0 < sint (num_sheep_send before)"
    using before_amounts before_reference_sheep_positive by simp
  show ?thesis
  proof (cases "rounding = Exchange_Normal")
    case True
    have "result = reference"
      using thresholds reference_threshold before_amounts
        before_nonstaying before_reference_nonstaying True
      by simp
    then show ?thesis using reference_wheat by simp
  next
    case False
    have result_record:
        "result = make_exchange_result (num_wheat_received before)
          (num_sheep_send before) (result_wheat_stays before)"
      using apply_price_error_thresholds_positive_path_result
        [OF _ False thresholds] before_wheat wheat_positive
        before_sheep_positive
      by simp
    show ?thesis
      using result_record before_wheat
      by (simp add: make_exchange_result_def)
  qed
qed

lemma post_offer_symmetric_irrelevant_if_created:
  assumes maker_wf: "party_state_wf maker"
    and post:
      "post_offer price_n price_d amount maker
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr> =
       Cxx_Ok (Post_Created posted maker_after)"
  shows
    "post_offer price_n price_d amount maker
       \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr> =
     Cxx_Ok (Post_Created posted maker_after)"
text \<open>
  Proof sketch: invert the created result to expose the ready pre-flight caps,
  the positive adjustment, and liability acquisition.  Well-formedness makes
  both adjustment caps non-negative, so @{thm [source]
  adjust_offer_symmetric_irrelevant} replaces the symmetric option by false
  without changing the adjusted amount or the acquired maker state.
\<close>
proof -
  note positive = post_created_positive_facts [OF post]
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and amount_positive: "0 < sint amount"
    using positive by simp_all
  have valid:
      "\<not> (sint price_n \<le> 0 \<or> sint price_d \<le> 0 \<or>
        sint amount \<le> 0)"
    using pn pd amount_positive by simp
  obtain preflight where preflight:
      "preflight_offer price_n price_d amount maker = Cxx_Ok preflight"
    using post valid
    by (cases "preflight_offer price_n price_d amount maker")
       (auto simp add: post_offer_def)
  obtain max_sheep_send max_wheat_receive where preflight_ready:
      "preflight = Preflight_Ready max_sheep_send max_wheat_receive"
    using post valid preflight
    by (cases preflight) (auto simp add: post_offer_def)
  obtain adjusted where adjustment:
      "adjust_offer_with_options price_n price_d max_sheep_send max_wheat_receive
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr> =
       Cxx_Ok adjusted"
    using post valid preflight preflight_ready
    by (cases "adjust_offer_with_options price_n price_d max_sheep_send max_wheat_receive
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = sym_cap\<rparr>")
       (auto simp add: post_offer_def)
  have adjusted_positive: "0 < sint adjusted"
    using post valid preflight preflight_ready adjustment
    by (auto simp add: post_offer_def split: if_splits)
  obtain acquired where acquire:
      "acquire_offer_liabilities price_n price_d adjusted maker =
       Cxx_Ok acquired"
    using post valid preflight preflight_ready adjustment adjusted_positive
    by (cases "acquire_offer_liabilities price_n price_d adjusted maker")
       (auto simp add: post_offer_def)
  have created:
      "Post_Created adjusted acquired = Post_Created posted maker_after"
    using post valid preflight preflight_ready adjustment adjusted_positive
      acquire
    by (simp add: post_offer_def)
  have adjusted_posted: "adjusted = posted"
    and acquired_after: "acquired = maker_after"
    using created by simp_all
  have preflight_ready_call:
      "preflight_offer price_n price_d amount maker =
       Cxx_Ok (Preflight_Ready max_sheep_send max_wheat_receive)"
    using preflight preflight_ready by simp
  obtain buying where buying:
      "offer_buying_liabilities price_n price_d amount = Cxx_Ok buying"
    using preflight_ready_call
    by (cases "offer_buying_liabilities price_n price_d amount")
       (simp_all add: preflight_offer_def)
  obtain selling where selling:
      "offer_selling_liabilities price_n price_d amount = Cxx_Ok selling"
    using preflight_ready_call buying
    by (cases "offer_selling_liabilities price_n price_d amount")
       (simp_all add: preflight_offer_def split: if_splits)
  have ready_values:
      "max_sheep_send =
         signed_min64 amount (can_sell_at_most maker) \<and>
       max_wheat_receive = can_buy_at_most maker"
    using preflight_ready_call buying selling
    by (auto simp add: preflight_offer_def Let_def split: if_splits)
  have sell_nonnegative: "0 \<le> sint (can_sell_at_most maker)"
    using can_sell_at_most_nonnegative [OF maker_wf] .
  have buy_nonnegative: "0 \<le> sint (can_buy_at_most maker)"
    using can_buy_at_most_nonnegative [OF maker_wf] .
  have max_sheep_nonnegative: "0 \<le> sint max_sheep_send"
    using ready_values amount_positive sell_nonnegative
    by (auto simp add: signed_min64_def split: if_splits)
  have max_wheat_nonnegative: "0 \<le> sint max_wheat_receive"
    using ready_values buy_nonnegative by simp
  have adjustment_plain:
      "adjust_offer_with_options price_n price_d max_sheep_send max_wheat_receive
         \<lparr>exact_receive_cap = cap, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok adjusted"
    using adjustment
      adjust_offer_symmetric_irrelevant
        [OF pn pd max_sheep_nonnegative max_wheat_nonnegative,
          of cap sym_cap]
    by simp
  show ?thesis
    using valid preflight preflight_ready adjustment_plain adjusted_positive
      acquire adjusted_posted acquired_after
    by (simp add: post_offer_def)
qed

lemma cover_implies_adjust_stable_exact_any_symmetric:
  fixes sym_cap :: bool
  shows "cover_implies_adjust_stable
     \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr>"
text \<open>
  Proof sketch: normalize a successful post to a false symmetric option and
  apply @{thm [source] cover_implies_adjust_stable_exact}.  Covered liability
  release yields a well-formed released state and non-negative adjustment caps;
  symmetric irrelevance then transports the stable result back to the original
  arbitrary symmetric option.
\<close>
proof -
  show ?thesis
    unfolding cover_implies_adjust_stable_def
  proof (intro allI impI)
    fix price_n price_d amount maker_at_post posted maker_after
      maker_at_cross released
    assume lifecycle_premises:
      "party_state_wf maker_at_post \<and>
       party_state_wf maker_at_cross \<and>
       post_offer price_n price_d amount maker_at_post
         \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
           Cxx_Ok (Post_Created posted maker_after) \<and>
       maker_covers_offer_liabilities price_n price_d posted maker_at_cross \<and>
       release_offer_liabilities price_n price_d posted maker_at_cross =
         Cxx_Ok released"
    have post_wf: "party_state_wf maker_at_post"
      using lifecycle_premises by blast
    have cross_wf: "party_state_wf maker_at_cross"
      using lifecycle_premises by blast
    have post:
        "post_offer price_n price_d amount maker_at_post
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok (Post_Created posted maker_after)"
      using lifecycle_premises by blast
    have cover:
        "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
      using lifecycle_premises by blast
    have release:
        "release_offer_liabilities price_n price_d posted maker_at_cross =
         Cxx_Ok released"
      using lifecycle_premises by blast
    have post_plain:
        "post_offer price_n price_d amount maker_at_post
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr> =
         Cxx_Ok (Post_Created posted maker_after)"
      using post_offer_symmetric_irrelevant_if_created [OF post_wf post] .
    have stable_plain:
        "adjust_stable price_n price_d posted released
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
      using cover_implies_adjust_stable_exact
        [unfolded cover_implies_adjust_stable_def]
        post_wf cross_wf post_plain cover release
      by blast
    note positive = post_created_positive_facts [OF post]
    have pn: "0 < sint price_n" and pd: "0 < sint price_d"
      and posted_positive: "0 < sint posted"
      using positive by simp_all
    obtain selling buying released' where selling:
        "offer_selling_liabilities price_n price_d posted = Cxx_Ok selling"
      and buying:
        "offer_buying_liabilities price_n price_d posted = Cxx_Ok buying"
      and release':
        "release_offer_liabilities price_n price_d posted maker_at_cross =
         Cxx_Ok released'"
      and released_wf': "party_state_wf released'"
      using covered_offer_release
        [OF pn pd less_imp_le[OF posted_positive] cross_wf cover]
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
    have send_nonnegative:
        "0 \<le> sint
          (signed_min64 posted (can_sell_at_most released))"
      using posted_positive sell_nonnegative
      by (auto simp add: signed_min64_def split: if_splits)
    have adjustment_equal:
        "adjust_offer_with_options price_n price_d
           (signed_min64 posted (can_sell_at_most released))
           (can_buy_at_most released)
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         adjust_offer_with_options price_n price_d
           (signed_min64 posted (can_sell_at_most released))
           (can_buy_at_most released)
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
      using adjust_offer_symmetric_irrelevant
        [OF pn pd send_nonnegative buy_nonnegative, of True sym_cap] .
    show
      "adjust_stable price_n price_d posted released
         \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr>"
      using stable_plain adjustment_equal
      by (simp add: adjust_stable_def)
  qed
qed

theorem cover_implies_adjust_stable_repaired:
  "cover_implies_adjust_stable
     \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"
text \<open>
  Proof sketch: instantiate the symmetric-option-independent exact-cap result
  at true, the record requested for both repairs enabled.
\<close>
  using cover_implies_adjust_stable_exact_any_symmetric [of True] .

lemma successful_nonstaying_cross_fields:
  assumes cross:
    "cross_offer_v10 price_n price_d offer_amount maker taker taker_amount
       rounding options = Cxx_Ok crossed"
    and nonstaying: "\<not> cross_wheat_stays crossed"
  obtains released adjusted exchanged where
    "release_offer_liabilities price_n price_d offer_amount maker =
       Cxx_Ok released"
    "adjust_offer_with_options price_n price_d
       (signed_min64 offer_amount (can_sell_at_most released))
       (can_buy_at_most released) options = Cxx_Ok adjusted"
    "exchange_v10_with_options price_n price_d
       (signed_min64 adjusted (can_sell_at_most released))
       (can_buy_at_most taker)
       (signed_min64 taker_amount (can_sell_at_most taker))
       (can_buy_at_most released) rounding options = Cxx_Ok exchanged"
    "cross_wheat_received crossed = num_wheat_received exchanged"
    "\<not> result_wheat_stays exchanged"
    "cross_offer_amount crossed = 0"
text \<open>
  Proof sketch: invert the successful crossing through liability release,
  preventative adjustment, exchange, and the four balance moves.  A true inner
  stay flag always constructs a result whose exposed crossing flag is true,
  including the dust-erasure branch, contradicting the premise.  The remaining
  branch copies the inner wheat amount, preserves the false flag, and writes a
  zero remaining offer amount.
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
  have fields:
      "cross_wheat_received crossed = num_wheat_received exchanged \<and>
       \<not> result_wheat_stays exchanged \<and>
       cross_offer_amount crossed = 0"
  proof (cases "result_wheat_stays exchanged")
    case stays: True
    obtain adjusted_after where adjusted_after:
        "adjust_offer_with_options price_n price_d
           (signed_min64 (adjusted - num_wheat_received exchanged)
             (can_sell_at_most maker_moved))
           (can_buy_at_most maker_moved) options = Cxx_Ok adjusted_after"
      using cross' taker_limits release adjustment exchange maker_receive
        maker_spend taker_receive taker_spend stays
      by (cases "adjust_offer_with_options price_n price_d
           (signed_min64 (adjusted - num_wheat_received exchanged)
             (can_sell_at_most maker_moved))
           (can_buy_at_most maker_moved) options") simp_all
    show ?thesis
    proof (cases "adjusted_after = 0")
      case True
      have crossed_eq:
          "crossed = make_cross_result (num_wheat_received exchanged)
            (num_sheep_send exchanged) (result_wheat_stays exchanged) 0
            maker_moved taker_after"
        using cross' taker_limits release adjustment exchange maker_receive
          maker_spend taker_receive taker_spend stays adjusted_after
          True
        by simp
      have "cross_wheat_stays crossed"
        using crossed_eq stays
        by (simp add: make_cross_result_def)
      then show ?thesis using nonstaying by simp
    next
      case False
      obtain maker_final where acquire:
          "acquire_offer_liabilities price_n price_d adjusted_after
             maker_moved = Cxx_Ok maker_final"
        using cross' taker_limits release adjustment exchange maker_receive
          maker_spend taker_receive taker_spend stays adjusted_after False
        by (cases "acquire_offer_liabilities price_n price_d adjusted_after
             maker_moved") simp_all
      have crossed_eq:
          "crossed = make_cross_result (num_wheat_received exchanged)
            (num_sheep_send exchanged) (result_wheat_stays exchanged)
            adjusted_after maker_final taker_after"
        using cross' taker_limits release adjustment exchange maker_receive
          maker_spend taker_receive taker_spend stays adjusted_after False
          acquire
        by simp
      have "cross_wheat_stays crossed"
        using crossed_eq stays
        by (simp add: make_cross_result_def)
      then show ?thesis using nonstaying by simp
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
      using crossed_eq stays
      by (simp add: make_cross_result_def)
  qed
  show thesis
    using that [OF release adjustment exchange] fields by blast
qed

theorem fully_taken_posted_offer_exchanges_posted_amount_exact:
  fixes sym_cap :: bool
  shows "fully_taken_posted_offer_exchanges_posted_amount
     \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr>"
text \<open>
  Proof sketch: invert the successful non-staying cross, which also exposes
  that its branch sets the remaining offer amount to zero.  The both-state
  lifecycle premises and the exact cap make the preventative adjustment return
  the positive posted amount.  Positive adjustment idempotence proves that the
  maker's send cap also equals that amount.  The flag-independent exchange
  lemma then shows that the arbitrary taker's successful non-staying exchange
  returns the whole posted amount for every rounding mode.  The symmetric flag
  remains universally quantified because neither adjustment nor this exchange
  branch consults it.
\<close>
proof -
  show ?thesis
    unfolding fully_taken_posted_offer_exchanges_posted_amount_def
  proof (intro allI impI)
    fix price_n price_d amount maker_at_post posted maker_after
      maker_at_cross taker taker_amount rounding crossed
    assume lifecycle_premises:
      "party_state_wf maker_at_post \<and>
       party_state_wf maker_at_cross \<and>
       post_offer price_n price_d amount maker_at_post
         \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
           Cxx_Ok (Post_Created posted maker_after) \<and>
       maker_covers_offer_liabilities price_n price_d posted maker_at_cross \<and>
       cross_offer_v10 price_n price_d posted maker_at_cross taker
         taker_amount rounding
         \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
           Cxx_Ok crossed \<and>
       \<not> cross_wheat_stays crossed"
    have post_wf: "party_state_wf maker_at_post"
      using lifecycle_premises by blast
    have cross_wf: "party_state_wf maker_at_cross"
      using lifecycle_premises by blast
    have post:
        "post_offer price_n price_d amount maker_at_post
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok (Post_Created posted maker_after)"
      using lifecycle_premises by blast
    have cover:
        "maker_covers_offer_liabilities price_n price_d posted maker_at_cross"
      using lifecycle_premises by blast
    have cross:
        "cross_offer_v10 price_n price_d posted maker_at_cross taker
           taker_amount rounding
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok crossed"
      using lifecycle_premises by blast
    have nonstaying: "\<not> cross_wheat_stays crossed"
      using lifecycle_premises by blast
    obtain released adjusted exchanged where release:
        "release_offer_liabilities price_n price_d posted maker_at_cross =
         Cxx_Ok released"
      and adjustment:
        "adjust_offer_with_options price_n price_d
           (signed_min64 posted (can_sell_at_most released))
           (can_buy_at_most released)
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok adjusted"
      and exchange:
        "exchange_v10_with_options price_n price_d
           (signed_min64 adjusted (can_sell_at_most released))
           (can_buy_at_most taker)
           (signed_min64 taker_amount (can_sell_at_most taker))
           (can_buy_at_most released) rounding
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok exchanged"
      and crossed_wheat:
        "cross_wheat_received crossed = num_wheat_received exchanged"
      and exchanged_nonstaying: "\<not> result_wheat_stays exchanged"
      and erased: "cross_offer_amount crossed = 0"
      using successful_nonstaying_cross_fields [OF cross nonstaying]
      by blast
    have stable:
        "adjust_stable price_n price_d posted released
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr>"
      using cover_implies_adjust_stable_exact_any_symmetric
        [of sym_cap, unfolded cover_implies_adjust_stable_def]
        post_wf cross_wf post cover release
      by blast
    note positive = post_created_positive_facts [OF post]
    have pn: "0 < sint price_n" and pd: "0 < sint price_d"
      and posted_positive: "0 < sint posted"
      using positive by simp_all
    obtain selling buying released' where selling:
        "offer_selling_liabilities price_n price_d posted = Cxx_Ok selling"
      and buying:
        "offer_buying_liabilities price_n price_d posted = Cxx_Ok buying"
      and release':
        "release_offer_liabilities price_n price_d posted maker_at_cross =
         Cxx_Ok released'"
      and released_wf': "party_state_wf released'"
      using covered_offer_release
        [OF pn pd less_imp_le[OF posted_positive] cross_wf cover]
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
           (can_buy_at_most released)
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok posted"
      using stable by (simp add: adjust_stable_def)
    have stable_fixed:
        "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
           Cxx_Ok posted \<and>
         sint posted \<le> sint ?maker_send"
      using adjust_offer_positive_idempotent
        [OF pn pd maker_send_nonnegative buy_nonnegative stable_adjustment
          posted_positive] .
    have maker_send_eq: "?maker_send = posted"
      using stable_fixed
      by (auto simp add: signed_min64_def split: if_splits)
    have direct_adjustment:
        "adjust_offer_with_options price_n price_d posted (can_buy_at_most released)
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok posted"
      using stable_fixed by blast
    have adjusted_eq: "adjusted = posted"
      using adjustment stable_adjustment by simp
    have exchange_posted:
        "exchange_v10_with_options price_n price_d posted (can_buy_at_most taker)
           (signed_min64 taker_amount (can_sell_at_most taker))
           (can_buy_at_most released) rounding
           \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = sym_cap\<rparr> =
         Cxx_Ok exchanged"
      using exchange adjusted_eq maker_send_eq by simp
    have full_wheat: "num_wheat_received exchanged = posted"
      using exchange_v10_nonstaying_matches_positive_adjustment
        [OF pn pd posted_positive buy_nonnegative direct_adjustment
          exchange_posted exchanged_nonstaying] .
    show "cross_wheat_received crossed = posted"
      using crossed_wheat full_wheat by simp
  qed
qed

theorem fully_taken_posted_offer_exchanges_posted_amount_repaired:
  "fully_taken_posted_offer_exchanges_posted_amount
     \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"
text \<open>
  Proof sketch: instantiate the exact-cap theorem at a true symmetric cap,
  retaining the user-requested both-enabled packaging.
\<close>
  using fully_taken_posted_offer_exchanges_posted_amount_exact [of True] .

theorem fully_taken_posted_offer_exchanges_posted_amount_legacy_false:
  "\<not> fully_taken_posted_offer_exchanges_posted_amount
     \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
text \<open>
  Proof sketch: instantiate the existing Alice-and-Carol reservation anomaly.
  Alice's well-formed post creates one unit, Carol's intervening payment leaves
  a well-formed maker state that still covers both liabilities, and the later
  successful cross reports a false stay flag and erases the offer while
  exchanging zero wheat.  This contradicts the claimed equality with the
  posted one unit.
\<close>
proof
  assume claimed:
    "fully_taken_posted_offer_exchanges_posted_amount
       \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr>"
  let ?maker_at_post =
    "\<lparr>sell_balance = 1, sell_liabilities = 0,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?maker_after =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 0, buy_liabilities = 1\<rparr>"
  let ?maker_at_cross =
    "\<lparr>sell_balance = 1, sell_liabilities = 1,
      buy_limit = 2, buy_balance = 1, buy_liabilities = 1\<rparr>"
  let ?taker =
    "\<lparr>sell_balance = 2, sell_liabilities = 0,
      buy_limit = 1000, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?crossed =
    "\<lparr>cross_wheat_received = 0, cross_sheep_send = 0,
      cross_wheat_stays = False, cross_offer_amount = 0,
      cross_maker =
        \<lparr>sell_balance = 1, sell_liabilities = 0,
          buy_limit = 2, buy_balance = 1, buy_liabilities = 0\<rparr>,
      cross_taker = ?taker\<rparr>"
  have witness_facts:
      "party_state_wf ?maker_at_post \<and>
       party_state_wf ?maker_at_cross \<and>
       post_offer 101 100 1 ?maker_at_post
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
           Cxx_Ok (Post_Created 1 ?maker_after) \<and>
       maker_covers_offer_liabilities 101 100 1 ?maker_at_cross \<and>
       cross_offer_v10 101 100 1 ?maker_at_cross ?taker 2 Exchange_Normal
         \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
           Cxx_Ok ?crossed \<and>
       \<not> cross_wheat_stays ?crossed"
    by eval
  have "cross_wheat_received ?crossed = 1"
    using claimed
      [unfolded fully_taken_posted_offer_exchanges_posted_amount_def,
        rule_format, where price_n = 101 and price_d = 100 and amount = 1
          and maker_at_post = ?maker_at_post and posted = 1
          and maker_after = ?maker_after and maker_at_cross = ?maker_at_cross
          and taker = ?taker and taker_amount = 2
          and rounding = Exchange_Normal and crossed = ?crossed]
      witness_facts
    by blast
  then show False by simp
qed

lemma fully_taken_incoming_offer_positive_partial_witness:
  "party_state_wf
      \<lparr>sell_balance = 4, sell_liabilities = 0,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr> \<and>
    party_state_wf
      \<lparr>sell_balance = 4, sell_liabilities = 4,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 6\<rparr> \<and>
    post_offer 3 2 4
      \<lparr>sell_balance = 4, sell_liabilities = 0,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr>
      \<lparr>exact_receive_cap = True,
        symmetric_exact_receive_cap = True\<rparr> =
      Cxx_Ok
        (Post_Created 4
          \<lparr>sell_balance = 4, sell_liabilities = 4,
            buy_limit = 10, buy_balance = 0, buy_liabilities = 6\<rparr>) \<and>
    maker_covers_offer_liabilities 3 2 4
      \<lparr>sell_balance = 4, sell_liabilities = 4,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 6\<rparr> \<and>
    party_state_wf
      \<lparr>sell_balance = 4, sell_liabilities = 0,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr> \<and>
    preflight_offer 2 3 4
      \<lparr>sell_balance = 4, sell_liabilities = 0,
        buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr> =
      Cxx_Ok (Preflight_Ready 4 10) \<and>
    (case cross_offer_v10 3 2 4
        \<lparr>sell_balance = 4, sell_liabilities = 4,
          buy_limit = 10, buy_balance = 0, buy_liabilities = 6\<rparr>
        \<lparr>sell_balance = 4, sell_liabilities = 0,
          buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr>
        4 Exchange_Normal
        \<lparr>exact_receive_cap = True,
          symmetric_exact_receive_cap = True\<rparr> of
       Cxx_Ok crossed \<Rightarrow>
         cross_wheat_received crossed = 2 \<and>
         cross_sheep_send crossed = 3 \<and>
         cross_offer_amount crossed = 2 \<and>
         cross_wheat_stays crossed
     | Cxx_Err _ \<Rightarrow> False)"
text \<open>
  Proof sketch: executable evaluation confirms the full resting lifecycle:
  the initial and later maker states are well formed, posting creates the
  actual four-wheat offer and acquires its four selling and six buying
  liabilities, and the later state covers them.  Reciprocal
  \<open>ManageSellOffer\<close> pre-flight accepts the raw four-sheep request without
  clipping and with ten units of wheat receive headroom, so the request is
  send-amount limited rather than receive-headroom limited.  At price three
  halves, three sheep buy two whole wheat at the exact price while the fourth
  sheep cannot buy another whole wheat.  Normal price-error filtering keeps
  this positive result and its true wheat-stays flag.  Two wheat remain on the
  resting offer, while the accepted transfer is two wheat for only three of
  the four incoming sheep.
\<close>
  by eval

theorem fully_taken_incoming_offer_exchanges_incoming_amount_repaired_false:
  "\<not> fully_taken_incoming_offer_exchanges_incoming_amount
     \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr>"
text \<open>
  Proof sketch: specialize the universal property to the executable witness
  above.  Its well-formed maker posts four wheat, the well-formed crossing state
  still covers that actual offer's liabilities, its well-formed taker's
  positive request passes reciprocal pre-flight with the request itself as the
  send cap, and successful crossing reports that wheat stays.  The property
  would therefore equate the observed three-sheep transfer with the incoming
  amount four, a contradiction.  Hence enabling both exact receive caps does
  not make the wheat-stays flag an exact full-send certificate after integer
  exchange rounding, even when the accepted exchange is positive and exactly
  priced.
\<close>
proof
  assume claimed:
    "fully_taken_incoming_offer_exchanges_incoming_amount
       \<lparr>exact_receive_cap = True,
         symmetric_exact_receive_cap = True\<rparr>"
  let ?maker_at_post =
    "\<lparr>sell_balance = 4, sell_liabilities = 0,
      buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?maker_at_cross =
    "\<lparr>sell_balance = 4, sell_liabilities = 4,
      buy_limit = 10, buy_balance = 0, buy_liabilities = 6\<rparr>"
  let ?taker =
    "\<lparr>sell_balance = 4, sell_liabilities = 0,
      buy_limit = 10, buy_balance = 0, buy_liabilities = 0\<rparr>"
  let ?options =
    "\<lparr>exact_receive_cap = True,
      symmetric_exact_receive_cap = True\<rparr>"
  have maker_at_post_wf: "party_state_wf ?maker_at_post"
    and maker_at_cross_wf: "party_state_wf ?maker_at_cross"
    and post:
      "post_offer 3 2 4 ?maker_at_post ?options =
       Cxx_Ok (Post_Created 4 ?maker_at_cross)"
    and cover:
      "maker_covers_offer_liabilities 3 2 4 ?maker_at_cross"
    and taker_wf: "party_state_wf ?taker"
    and preflight:
      "preflight_offer 2 3 4 ?taker =
       Cxx_Ok (Preflight_Ready 4 10)"
    and crossing_case:
      "case cross_offer_v10 3 2 4 ?maker_at_cross ?taker 4 Exchange_Normal
          ?options of
         Cxx_Ok crossed \<Rightarrow>
           cross_wheat_received crossed = 2 \<and>
           cross_sheep_send crossed = 3 \<and>
           cross_offer_amount crossed = 2 \<and>
           cross_wheat_stays crossed
       | Cxx_Err _ \<Rightarrow> False"
    using fully_taken_incoming_offer_positive_partial_witness
    by simp_all
  obtain crossed where cross:
      "cross_offer_v10 3 2 4 ?maker_at_cross ?taker 4 Exchange_Normal
         ?options =
       Cxx_Ok crossed"
    and sheep_partial: "cross_sheep_send crossed = 3"
    and stays: "cross_wheat_stays crossed"
    using crossing_case
    by (cases "cross_offer_v10 3 2 4 ?maker_at_cross ?taker 4 Exchange_Normal
         ?options") auto
  have full_send: "cross_sheep_send crossed = 4"
    using claimed
      [unfolded fully_taken_incoming_offer_exchanges_incoming_amount_def,
        rule_format, where price_n = 3 and price_d = 2
          and resting_request = 4 and maker_at_post = ?maker_at_post
          and posted = 4 and maker_after = ?maker_at_cross
          and maker_at_cross = ?maker_at_cross and taker = ?taker
          and incoming_amount = 4 and incoming_receive_cap = 10
          and rounding = Exchange_Normal and crossed = crossed]
      maker_at_post_wf maker_at_cross_wf post cover taker_wf preflight cross
      stays
    by simp
  show False
    using full_send sheep_partial by simp
qed


lemma exchange_v10_bounds_any_cap:
  assumes exchange:
    "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
       max_sheep_send max_sheep_receive rounding options = Cxx_Ok result"
  shows
    "0 \<le> sint (num_wheat_received result)"
    "sint (num_wheat_received result) \<le>
       min (sint max_wheat_receive) (sint max_wheat_send)"
    "0 \<le> sint (num_sheep_send result)"
    "sint (num_sheep_send result) \<le>
       min (sint max_sheep_receive) (sint max_sheep_send)"
text \<open>
  Proof sketch: decompose the full exchange into its checked pre-threshold
  result and the common threshold call.  The checked result satisfies all four
  cap bounds.  Every successful threshold branch returns either that original
  amount pair or the explicit zero pair, in all three rounding modes, so the
  same inequalities hold without assuming a positive normal result.
\<close>
proof -
  obtain before where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         rounding options = Cxx_Ok before"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before) (num_sheep_send before)
         (result_wheat_stays before) rounding = Cxx_Ok result"
    using exchange
    by (cases "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         rounding options")
       (simp_all add: exchange_v10_with_options_def)
  note bounds = exchange_without_thresholds_bounds_any_cap [OF before]
  have choices:
      "(num_wheat_received result = num_wheat_received before \<and>
        num_sheep_send result = num_sheep_send before) \<or>
       (num_wheat_received result = 0 \<and> num_sheep_send result = 0)"
    using thresholds apply_price_error_thresholds_characterization
    by (cases rounding)
       (auto simp add: apply_price_error_thresholds_spec_def
          make_exchange_result_def Let_def split: if_splits)
  show "0 \<le> sint (num_wheat_received result)"
    using bounds(1) choices by auto
  show "sint (num_wheat_received result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    using bounds(2) bounds(1) choices by auto
  show "0 \<le> sint (num_sheep_send result)"
    using bounds(3) choices by auto
  show "sint (num_sheep_send result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    using bounds(4) bounds(3) choices by auto
qed

section \<open>Strict-mode contracts across the exact-cap boundary\<close>

text \<open>
  Every strict-mode result of the arithmetic theory
  is pinned to @{const legacy_exchange_options}, because it is derived from
  @{const exchange_v10_amounts_int}, the exact-integer abstraction that
  hard-codes the legacy branch formulas.  Both strict modes can nevertheless
  reach a repaired branch: strict send and strict receive both bypass the
  symmetric wheat-stays branch, but neither bypasses the
  @{const exact_receive_cap} branch taken when the wheat offer does not stay
  and wheat is the more valuable asset.  So nothing about path payments was
  proved on the protocol-29 side of the boundary.

  This section closes that gap without an options-parametric integer
  abstraction, by observing where the strict-mode guarantees actually come
  from.  @{const apply_price_error_thresholds} does not inspect the options,
  and @{thm [source] exchange_without_thresholds_bounds_any_cap} already
  proves the four cap bounds for every options record, because the
  pre-threshold exchange passes its amount pair through one common checked
  constructor whatever the branch computed.  The strict-mode contracts are
  consequences of exactly those two facts, so they hold at every options
  record --- the two real protocols and the two diagnostic mutants alike ---
  and need neither @{const exchange_v10_pre} nor any branch formula.
\<close>

lemma exchange_v10_decompose_any_options:
  assumes result:
    "exchange_v10_with_options price_n price_d max_wheat_send
       max_wheat_receive max_sheep_send max_sheep_receive rounding options =
     Cxx_Ok exchange_result"
  obtains before_thresholds where
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d
       max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
       rounding options = Cxx_Ok before_thresholds"
    and "apply_price_error_thresholds price_n price_d
       (num_wheat_received before_thresholds)
       (num_sheep_send before_thresholds)
       (result_wheat_stays before_thresholds) rounding =
     Cxx_Ok exchange_result"
text \<open>
  Proof sketch: the full exchange is one monadic bind of the pre-threshold
  calculation into the threshold pass, so a successful outcome forces both
  calls to have succeeded, with the second applied to the fields of the
  first.
\<close>
proof -
  obtain before_thresholds where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         rounding options = Cxx_Ok before_thresholds"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before_thresholds)
         (num_sheep_send before_thresholds)
         (result_wheat_stays before_thresholds) rounding =
       Cxx_Ok exchange_result"
    using result
    by (cases "exchange_v10_without_price_error_thresholds_with_options
         price_n price_d max_wheat_send max_wheat_receive max_sheep_send
         max_sheep_receive rounding options")
       (simp_all add: exchange_v10_with_options_def)
  show ?thesis
    by (rule that [OF before thresholds])
qed

subsection \<open>Strict send\<close>

theorem exchange_v10_strict_send_sheep_positive_any_options:
  assumes result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Send options = Cxx_Ok exchange_result"
  shows "0 < sint (num_sheep_send exchange_result)"
  \<comment> \<open>A successful strict-send exchange always sends a strictly positive
    amount of sheep, at every exact-cap configuration.\<close>
text \<open>
  Proof sketch: decompose the exchange into its pre-threshold result and the
  threshold pass.  Strict-send success returns the pre-threshold record
  unchanged and proves its sheep word nonzero, and the common checked
  constructor already made that word a non-negative signed amount, so nonzero
  strengthens to strictly positive.  Neither step looks at the options.
\<close>
proof -
  obtain before_thresholds where before:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         Exchange_Strict_Send options = Cxx_Ok before_thresholds"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before_thresholds)
         (num_sheep_send before_thresholds)
         (result_wheat_stays before_thresholds) Exchange_Strict_Send =
       Cxx_Ok exchange_result"
    using result by (rule exchange_v10_decompose_any_options)
  note strict = apply_price_error_thresholds_strict_send_success [OF thresholds]
  have nonnegative: "0 \<le> sint (num_sheep_send before_thresholds)"
    using exchange_without_thresholds_bounds_any_cap [OF before] by simp
  have "sint (num_sheep_send before_thresholds) \<noteq> 0"
    using strict(2) word_zero_iff_sint_zero by auto
  then have "0 < sint (num_sheep_send before_thresholds)"
    using nonnegative by linarith
  then show ?thesis
    using strict(1) by (simp add: make_exchange_result_def)
qed

corollary exchange_v10_strict_send_sheep_positive_repaired:
  assumes result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Send repaired_exchange_options = Cxx_Ok exchange_result"
  shows "0 < sint (num_sheep_send exchange_result)"
  \<comment> \<open>The protocol-29 instance of strict-send positivity.\<close>
  using exchange_v10_strict_send_sheep_positive_any_options [OF result] .

text \<open>
  @{thm [source] exchange_v10_strict_send_sheep_positive_any_options} is a
  strict generalization of @{thm [source] exchange_v10_strict_send_sheep_positive}:
  it drops both the options record and the @{const exchange_v10_pre}
  hypothesis.  The legacy theorem needed the precondition only to route the
  argument through the exact-integer abstraction, which is what tied it to one
  configuration; the shorter route above needs neither.

  The corresponding \<^emph>\<open>iff\<close> results,
  @{thm [source] exchange_v10_strict_send_sheep_positive_iff} and
  @{thm [source] exchange_v10_without_strict_send_sheep_positive_iff}, do not
  generalize this way.  They compute the exact positivity threshold from the
  branch formulas, and the repaired non-staying branch replaces the plain
  wheat value by the relaxed exact-cap value, so the right-hand side changes.
  Deciding the repaired threshold requires the options-parametric integer
  abstraction and is not attempted here; what is proved instead is the
  positivity direction, which is the direction the lifecycle results consume.
\<close>

subsection \<open>Strict receive, and simultaneous zero in general\<close>

theorem apply_price_error_thresholds_zero_iff:
  assumes not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and result:
      "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding = Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
    (num_sheep_send exchange_result = 0)"
  \<comment> \<open>Outside strict-send mode the threshold pass never returns a half-zero
    trade, whatever amount pair it was given.\<close>
text \<open>
  Proof sketch: read the total decision tree.  The unchanged record is
  returned only under the guard that both incoming amounts are strictly
  positive, so both its words are nonzero; every other successful branch
  outside strict-send mode is the explicit zero record.  Strict send is
  excluded because it is the one branch that returns the unchanged record
  without that guard.
\<close>
  using result apply_price_error_thresholds_characterization not_strict_send
  by (auto simp add: apply_price_error_thresholds_spec_def
      make_exchange_result_def Let_def word_zero_iff_sint_zero
      split: if_splits)

theorem exchange_v10_zero_iff_any_options:
  assumes not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding options =
      Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
    (num_sheep_send exchange_result = 0)"
  \<comment> \<open>Outside strict-send mode a successful exchange transfers either both
    assets or neither, at every exact-cap configuration.\<close>
text \<open>
  Proof sketch: decompose the exchange and apply the threshold pass's own
  simultaneous-zero property to whatever amount pair the branch block
  produced.
\<close>
proof -
  obtain before_thresholds where
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d
       max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
       rounding options = Cxx_Ok before_thresholds"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before_thresholds)
         (num_sheep_send before_thresholds)
         (result_wheat_stays before_thresholds) rounding =
       Cxx_Ok exchange_result"
    using result by (rule exchange_v10_decompose_any_options)
  show ?thesis
    using apply_price_error_thresholds_zero_iff [OF not_strict_send thresholds] .
qed

text \<open>
  @{thm [source] exchange_v10_zero_iff_any_options} subsumes
  @{thm [source] exchange_v10_zero_iff}, dropping both the options record and
  @{const exchange_v10_pre}.  It is the load-bearing half of the strict-receive
  contract: the amount-block branch formulas do not enter, so the repaired
  branches are covered for free.
\<close>

theorem exchange_v10_positive_trade_contract_any_options:
  assumes result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding options =
      Cxx_Ok exchange_result"
    and positive:
      "0 < sint (num_wheat_received exchange_result) \<and>
       0 < sint (num_sheep_send exchange_result)"
  shows "favored_seller_ok price_n price_d
      (num_wheat_received exchange_result)
      (num_sheep_send exchange_result)
      (result_wheat_stays exchange_result)"
    and "if rounding = Exchange_Normal
      then price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) False
      else price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True"
  \<comment> \<open>A positive trade favours whichever offer stays and meets its rounding
    mode's price-error bound, at every exact-cap configuration.\<close>
text \<open>
  Proof sketch: decompose the exchange.  A positive returned trade cannot be
  the explicit zero record, so the threshold choice theorem identifies it with
  the pre-threshold record, whose amounts are therefore positive too.  The
  threshold caller's favoured-seller and price-bound contracts then apply and
  their fields are the returned ones.
\<close>
proof -
  obtain before_thresholds where
    before: "exchange_v10_without_price_error_thresholds_with_options price_n
       price_d max_wheat_send max_wheat_receive max_sheep_send
       max_sheep_receive rounding options = Cxx_Ok before_thresholds"
    and thresholds:
      "apply_price_error_thresholds price_n price_d
         (num_wheat_received before_thresholds)
         (num_sheep_send before_thresholds)
         (result_wheat_stays before_thresholds) rounding =
       Cxx_Ok exchange_result"
    using result by (rule exchange_v10_decompose_any_options)
  note choices = apply_price_error_thresholds_result_choices [OF thresholds]
  have result_record:
      "exchange_result =
       make_exchange_result (num_wheat_received before_thresholds)
         (num_sheep_send before_thresholds)
         (result_wheat_stays before_thresholds)"
    using choices positive by (auto simp add: make_exchange_result_def)
  have input_positive:
      "0 < sint (num_wheat_received before_thresholds) \<and>
       0 < sint (num_sheep_send before_thresholds)"
    using positive result_record by (simp add: make_exchange_result_def)
  show "favored_seller_ok price_n price_d
      (num_wheat_received exchange_result)
      (num_sheep_send exchange_result)
      (result_wheat_stays exchange_result)"
    using apply_price_error_thresholds_positive_success_favored
      [OF input_positive thresholds]
    unfolding result_record make_exchange_result_def by simp
  show "if rounding = Exchange_Normal
      then price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) False
      else price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True"
    using apply_price_error_thresholds_positive_trade_bound
      [OF input_positive thresholds positive] result_record
    by (cases rounding) (simp_all add: make_exchange_result_def)
qed

theorem exchange_v10_strict_receive_contract_any_options:
  assumes result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Receive options = Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
      (num_sheep_send exchange_result = 0)"
    and "0 \<le> sint (num_wheat_received exchange_result)"
    and "sint (num_wheat_received exchange_result) \<le>
       min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> sint (num_sheep_send exchange_result)"
    and "sint (num_sheep_send exchange_result) \<le>
       min (sint max_sheep_receive) (sint max_sheep_send)"
    and "0 < sint (num_wheat_received exchange_result) \<Longrightarrow>
       favored_seller_ok price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result)
         (result_wheat_stays exchange_result) \<and>
       price_error_bound_spec price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result) True"
  \<comment> \<open>The strict-receive contract: a successful strict-receive exchange
    transfers both assets or neither, respects all four caps, and, when it
    transfers anything, favours whichever offer stays and meets the tight
    one-sided price-error bound.\<close>
text \<open>
  Proof sketch: the first claim is the general simultaneous-zero theorem, the
  four cap claims are the option-free bounds of a successful exchange, and the
  last is the positive-trade contract, whose non-normal branch is the tight
  bound.  A positive wheat amount forces a positive sheep amount through the
  first claim and the non-negativity of the sheep amount.
\<close>
proof -
  show zero_iff: "(num_wheat_received exchange_result = 0) =
      (num_sheep_send exchange_result = 0)"
    using exchange_v10_zero_iff_any_options [OF _ result] by simp
  note bounds = exchange_v10_bounds_any_cap [OF result]
  show "0 \<le> sint (num_wheat_received exchange_result)"
    using bounds(1) .
  show "sint (num_wheat_received exchange_result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    using bounds(2) .
  show "0 \<le> sint (num_sheep_send exchange_result)"
    using bounds(3) .
  show "sint (num_sheep_send exchange_result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    using bounds(4) .
  show "0 < sint (num_wheat_received exchange_result) \<Longrightarrow>
     favored_seller_ok price_n price_d
       (num_wheat_received exchange_result)
       (num_sheep_send exchange_result)
       (result_wheat_stays exchange_result) \<and>
     price_error_bound_spec price_n price_d
       (num_wheat_received exchange_result)
       (num_sheep_send exchange_result) True"
  proof -
    assume wheat_positive:
      "0 < sint (num_wheat_received exchange_result)"
    have wheat_nonzero: "num_wheat_received exchange_result \<noteq> 0"
      using wheat_positive word_zero_iff_sint_zero by auto
    have sheep_nonzero: "num_sheep_send exchange_result \<noteq> 0"
      using wheat_nonzero zero_iff by simp
    have sheep_positive: "0 < sint (num_sheep_send exchange_result)"
      using sheep_nonzero bounds(3) word_zero_iff_sint_zero by auto
    note contract = exchange_v10_positive_trade_contract_any_options
      [OF result conjI [OF wheat_positive sheep_positive]]
    show "favored_seller_ok price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result)
         (result_wheat_stays exchange_result) \<and>
       price_error_bound_spec price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result) True"
      using contract(1) contract(2) by simp
  qed
qed

corollary exchange_v10_strict_receive_contract_repaired:
  assumes result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Receive repaired_exchange_options =
      Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
      (num_sheep_send exchange_result = 0)"
    and "0 < sint (num_wheat_received exchange_result) \<Longrightarrow>
       price_error_bound_spec price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result) True"
  \<comment> \<open>The protocol-29 instance of the strict-receive contract.\<close>
proof -
  note contract =
    exchange_v10_strict_receive_contract_any_options [OF result]
  show "(num_wheat_received exchange_result = 0) =
      (num_sheep_send exchange_result = 0)"
    using contract(1) .
  show "0 < sint (num_wheat_received exchange_result) \<Longrightarrow>
      price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True"
    using contract(6) by simp
qed

section \<open>Protocol-29 property catalogue\<close>

text \<open>
  The results above are stated for an @{typ exchange_options} record, so each
  covers both real protocols and the two diagnostic mutants at once.  This
  section packages the ones that matter at the protocol boundary
  itself, phrased through @{const exchange_options_at_version} so that the
  hypothesis is a ledger version rather than a choice of flags.  Each is a
  short specialization: no property is re-proved here.
\<close>

corollary positive_normal_crosses_are_maximal_p29:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   positive_normal_crosses_are_maximal
     (exchange_options_at_version ledger_version)"
  \<comment> \<open>From protocol 29 on, a positive normal cross transfers as much wheat as
    any admissible trade could.\<close>
  by (simp add: repaired_exchange_options_def
      positive_normal_crosses_are_maximal_repaired)

corollary cover_implies_adjust_stable_p29:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   cover_implies_adjust_stable (exchange_options_at_version ledger_version)"
  \<comment> \<open>From protocol 29 on, an offer whose liabilities its maker still covers
    is not reduced by adjustment.\<close>
  by (simp add: repaired_exchange_options_def
      cover_implies_adjust_stable_repaired)

corollary fully_taken_posted_offer_exchanges_posted_amount_p29:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   fully_taken_posted_offer_exchanges_posted_amount
     (exchange_options_at_version ledger_version)"
  \<comment> \<open>From protocol 29 on, a resting offer that does not stay transfers its
    actual stored amount.\<close>
  by (simp add: repaired_exchange_options_def
      fully_taken_posted_offer_exchanges_posted_amount_repaired)

corollary fully_taken_posted_offer_exchanges_posted_amount_p28_false:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   \<not> fully_taken_posted_offer_exchanges_posted_amount
     (exchange_options_at_version ledger_version)"
  \<comment> \<open>The same property is false at protocol 28, so this is a behavioral
    repair and not merely a restatement.\<close>
  by (simp add: legacy_exchange_options_def
      fully_taken_posted_offer_exchanges_posted_amount_legacy_false)

text \<open>
  The pair above is the sharpest statement of what protocol 29 changes in the
  lifecycle: at protocol 28 a fully taken resting offer need not transfer its
  stored amount, and from protocol 29 it always does.
\<close>

corollary exchange_v10_p29_positive_normal_refines_ideal:
  assumes version:
      "protocol_version_starts_from ledger_version protocol_version_v29"
    and pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result: "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal =
      Cxx_Ok exchange_result"
    and wheat_positive: "0 < sint (num_wheat_received exchange_result)"
    and sheep_positive: "0 < sint (num_sheep_send exchange_result)"
  shows "normal_result_refines_ideal price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive exchange_result"
  \<comment> \<open>A positive normal protocol-29 exchange refines the ideal
    specification.\<close>
  text \<open>
    Proof sketch: the protocol mapping turns the public call at a version from
    29 on into the repaired kernel, and the existing repaired refinement
    theorem applies to that call unchanged.
  \<close>
proof -
  have kernel: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal
      \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = True\<rparr> =
      Cxx_Ok exchange_result"
    using result version
    by (simp add: exchange_v10_repaired repaired_exchange_options_def)
  show ?thesis
    using exchange_v10_repaired_positive_normal_refines_ideal
      [OF pre kernel wheat_positive sheep_positive] .
qed

corollary rounding_favors_offer_that_stays_p29:
  "rounding_favors_offer_that_stays (exchange_options_at_version ledger_version)"
  \<comment> \<open>Rounding favours whichever offer stays, at every ledger version.  The
    protocol boundary does not enter: the guarantee comes from the threshold
    pass, which never inspects the exact-cap options.\<close>
  unfolding rounding_favors_offer_that_stays_def
  using successful_exchange_favors_offer_that_stays by blast

corollary adjust_offer_positive_idempotent_p29:
  assumes pn: "0 < sint price_n"
    and pd: "0 < sint price_d"
    and wheat_nonnegative: "0 \<le> sint max_wheat"
    and sheep_nonnegative: "0 \<le> sint max_sheep"
    and adjusted:
      "adjust_offer ledger_version price_n price_d max_wheat max_sheep =
        Cxx_Ok result"
    and result_positive: "0 < sint result"
  shows
    "adjust_offer ledger_version price_n price_d result max_sheep =
       Cxx_Ok result \<and>
     sint result \<le> sint max_wheat"
  \<comment> \<open>Re-adjusting a positive adjustment result changes nothing, at every
    ledger version.\<close>
  text \<open>
    Proof sketch: the underlying idempotence result already quantifies over
    the options record, so the protocol-facing call is an instance of it at
    the record the version selects.
  \<close>
  using adjust_offer_positive_idempotent
    [OF pn pd wheat_nonnegative sheep_nonnegative
      adjusted [unfolded adjust_offer_def] result_positive]
  by (simp add: adjust_offer_def)

corollary exchange_v10_p29_integer_characterization:
  fixes amounts :: "int \<times> int"
  assumes version:
      "protocol_version_starts_from ledger_version protocol_version_v29"
    and pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int_repaired price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal =
    apply_price_error_thresholds price_n price_d
      (word_of_int (fst amounts)) (word_of_int (snd amounts))
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      Exchange_Normal"
  \<comment> \<open>The protocol-29 public call is exactly the repaired exact-integer
    calculation followed by the threshold pass.\<close>
  text \<open>
    Proof sketch: the version hypothesis reduces the public call to the
    repaired kernel, where the established integer characterization applies
    unchanged.
  \<close>
  using exchange_v10_repaired_integer_characterization [OF pre] version
  by (simp add: exchange_v10_repaired repaired_exchange_options_def
      amounts_def)

text \<open>
  @{thm [source] exchange_v10_p29_integer_characterization} carries three of
  the protocol-29 obligations at once.  It is the totality and determinism
  statement for the protocol-29 public function, since the right-hand side is
  a branch-free calculation over exact integers that is defined for every
  input satisfying @{const exchange_v10_pre}.  It is the C++ error
  characterization, because @{const apply_price_error_thresholds} is where the
  modeled failures are produced.  And the retained-offer flag it passes is the
  comparison of the two \<^emph>\<open>plain\<close> offer values, so the \<open>wheatStays\<close> decision is
  visibly unchanged by the repair.
\<close>

subsection \<open>The exact-integer image at the protocol interface\<close>

corollary exchange_v10_p29_options_integer_characterization:
  fixes amounts :: "int \<times> int"
    and rounding :: exchange_rounding and ledger_version :: uint32
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding
      (exchange_options_at_version ledger_version)"
  shows "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding =
    apply_price_error_thresholds price_n price_d
      (word_of_int (fst amounts)) (word_of_int (snd amounts))
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      rounding"
  \<comment> \<open>The protocol-facing public call, at every ledger version and in all
    three rounding modes, is the exact-integer calculation for that version
    followed by the threshold pass.\<close>
  text \<open>
    Proof sketch: the public call is the kernel at the options record the
    version selects, where the options-parametric integer characterization
    applies unchanged.
  \<close>
  using exchange_v10_options_integer_characterization [OF pre]
  by (simp add: exchange_v10_def amounts_def)

text \<open>
  @{thm [source] exchange_v10_p29_options_integer_characterization} is the
  version of @{thm [source] exchange_v10_p29_integer_characterization} that
  drops both restrictions of the latter: it holds in the two strict rounding
  modes as well as normal mode, and before the boundary as well as from
  protocol 29 on.  The normal-mode protocol-29 instance is the earlier
  theorem, because the collapse equation
  @{thm [source] exchange_v10_amounts_int_with_options_repaired_normal}
  identifies the two abstractions there.
\<close>

corollary exchange_v10_p29_strict_send_sheep_positive_iff:
  assumes version:
      "protocol_version_starts_from ledger_version protocol_version_v29"
    and pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "(0 < snd
      (exchange_v10_amounts_int_with_options price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive
        Exchange_Strict_Send
        (exchange_options_at_version ledger_version))) =
    (let wheat_value =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive;
       sheep_value =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive
     in if wheat_value > sheep_value
        then 0 < sint max_sheep_send \<and> 0 < sint max_sheep_receive
        else if sint price_n > sint price_d
        then sint price_n \<le>
          exact_trade_value_int price_n price_d max_wheat_send
            max_sheep_receive
        else sint price_d \<le> wheat_value)"
  \<comment> \<open>The protocol-29 strict-send positivity threshold, stated through the
    protocol mapping.\<close>
  text \<open>
    Proof sketch: the version hypothesis reduces the mapped options to the
    repaired record, where the established threshold applies.
  \<close>
  using exchange_v10_strict_send_sheep_positive_iff_repaired [OF pre] version
  by (simp add: exchange_options_at_version_def)

subsection \<open>Strict-mode contracts through the protocol mapping\<close>

text \<open>
  The strict-mode results of the preceding section hold at every options
  record, so their protocol-facing forms need no version hypothesis at all.
  That is the point worth recording: path payments were the part of the
  interface with no protocol-29 statement, and what the boundary changes for
  them is nothing.
\<close>

corollary exchange_v10_strict_send_sheep_positive_p29:
  assumes result: "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Send = Cxx_Ok exchange_result"
  shows "0 < sint (num_sheep_send exchange_result)"
  \<comment> \<open>A successful strict-send exchange sends a positive amount of sheep, at
    every ledger version and in particular from protocol 29 on.\<close>
  using exchange_v10_strict_send_sheep_positive_any_options
    [OF result [unfolded exchange_v10_def]] .

corollary exchange_v10_zero_iff_p29:
  assumes not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and result: "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding =
      Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
    (num_sheep_send exchange_result = 0)"
  \<comment> \<open>Outside strict-send mode a successful exchange transfers both assets or
    neither, at every ledger version.\<close>
  using exchange_v10_zero_iff_any_options
    [OF not_strict_send result [unfolded exchange_v10_def]] .

corollary exchange_v10_strict_receive_contract_p29:
  assumes result: "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Receive = Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
      (num_sheep_send exchange_result = 0)"
    and "0 \<le> sint (num_wheat_received exchange_result)"
    and "sint (num_wheat_received exchange_result) \<le>
       min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> sint (num_sheep_send exchange_result)"
    and "sint (num_sheep_send exchange_result) \<le>
       min (sint max_sheep_receive) (sint max_sheep_send)"
    and "0 < sint (num_wheat_received exchange_result) \<Longrightarrow>
       favored_seller_ok price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result)
         (result_wheat_stays exchange_result) \<and>
       price_error_bound_spec price_n price_d
         (num_wheat_received exchange_result)
         (num_sheep_send exchange_result) True"
  \<comment> \<open>The strict-receive contract at the protocol-facing interface, at every
    ledger version.\<close>
  using exchange_v10_strict_receive_contract_any_options
    [OF result [unfolded exchange_v10_def]]
  by blast+

corollary exchange_v10_positive_trade_contract_p29:
  assumes result: "exchange_v10 ledger_version price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding =
      Cxx_Ok exchange_result"
    and positive:
      "0 < sint (num_wheat_received exchange_result) \<and>
       0 < sint (num_sheep_send exchange_result)"
  shows "favored_seller_ok price_n price_d
      (num_wheat_received exchange_result)
      (num_sheep_send exchange_result)
      (result_wheat_stays exchange_result)"
    and "if rounding = Exchange_Normal
      then price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) False
      else price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True"
  \<comment> \<open>The positive-trade contract at the protocol-facing interface, in all
    three rounding modes and at every ledger version.\<close>
  using exchange_v10_positive_trade_contract_any_options
    [OF result [unfolded exchange_v10_def] positive]
  by blast+

subsection \<open>Properties protocol 29 does not promise\<close>

corollary fully_taken_incoming_offer_exchanges_incoming_amount_p29_false:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   \<not> fully_taken_incoming_offer_exchanges_incoming_amount
     (exchange_options_at_version ledger_version)"
  \<comment> \<open>Consuming the incoming offer still does not certify that its entire raw
    requested amount was exchanged.\<close>
  by (simp add: repaired_exchange_options_def
      fully_taken_incoming_offer_exchanges_incoming_amount_repaired_false)

text \<open>
  This negative result is retained deliberately.  The repair is about the
  resting offer's stored amount, not about the incoming request: a positive
  cross that leaves the resting offer in the book can still transfer less
  wheat than the taker asked for, and no definition should be weakened to make
  the incoming-side claim true.  Stating it against
  @{const exchange_options_at_version} keeps the distinction visible to
  reviewers between what protocol 29 repairs and what it does not.
\<close>

end
