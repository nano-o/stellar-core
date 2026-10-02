section \<open>Abstract offer-exchange model\<close>

theory Offer_Exchange_Specification
  imports
    Main
    HOL.Rat
    "HOL-Library.Monad_Syntax"
begin

text \<open>
In this theory we formalize the offer exchange process with the goal of maximum simplicity, as
opposed to following the C++ implementation. Ideally, we will later modify the C++ implementation
to follow this specification.
\<close>

subsection "Isabelle/HOL Setup"

text \<open>In this section we do a little technical setup that can be ignored if you mostly
care about the semantics of the offer exchange and not Isabelle/HOL technicalities.\<close>

text \<open>
  Longer ordered validation chains use the guarded conditional notation below.
  The first true guard determines the result, and the final otherwise clause is
  the fallback.  This is input syntax only: Isabelle immediately translates it
  to ordinary nested conditionals.
\<close>

nonterminal cond_cases

syntax
  "_cond" :: "cond_cases \<Rightarrow> 'a"
    ("(cond {//(2 _)//})" [12] 62)
  "_cond_when" :: "[bool, 'a, cond_cases] \<Rightarrow> cond_cases"
    ("(when _ \<Rightarrow>/ _/ | _)" [0, 13, 12] 12)
  "_cond_otherwise" :: "'a \<Rightarrow> cond_cases"
    ("(otherwise \<Rightarrow>/ _)" [13] 12)

translations
  "_cond (_cond_when condition result rest)"
    \<rightharpoonup> "CONST If condition result (_cond rest)"
  "_cond (_cond_otherwise result)"
    \<rightharpoonup> "result"

text \<open>
  This theory enables Isabelle's standard coercion from @{typ int} (unbounded integer) to @{typ rat}
  (unbounded-precision rational). An integer-valued ledger amount or price component used in a
  rational expression is therefore promoted automatically. This keeps exact prices written as
  ordinary quotients instead of obscuring the formulas with explicit conversion functions.
\<close>

declare [[coercion_enabled]]
declare [[coercion "of_int :: int \<Rightarrow> rat"]]

subsection "Price"

datatype ledger_price =
  Ledger_Price (price_n: int) (price_d: int)

definition rat_price :: "ledger_price \<Rightarrow> rat"
  where
    "rat_price price = price_n price / price_d price"

declare [[coercion rat_price]] \<comment> \<open>We implicitly coerce @{typ ledger_price} to rational.\<close>

definition ledger_price_well_formed :: "ledger_price \<Rightarrow> bool"
  where
    "ledger_price_well_formed price \<longleftrightarrow> 0 < price_n price \<and> 0 < price_d price"


text \<open>
  @{typ ledger_price} is the price representation stored in the ledger. Its coercion through @{const
  rat_price} gives the corresponding exact rational value whenever a rational expression requires
  it.
\<close>

subsection "Offers"

record offer_attributes =
  is_passive :: bool

record sell_wheat_offer = offer_attributes +
  wheat_amount :: int
  sheep_per_wheat :: ledger_price

record sell_sheep_offer = offer_attributes +
  sheep_amount :: int
  wheat_per_sheep :: ledger_price

definition sell_wheat_offer_well_formed :: "sell_wheat_offer \<Rightarrow> bool"
  where
    "sell_wheat_offer_well_formed offer \<longleftrightarrow>
      0 < wheat_amount offer
      \<and> ledger_price_well_formed (sheep_per_wheat offer)"

definition sell_sheep_offer_well_formed :: "sell_sheep_offer \<Rightarrow> bool"
  where
    "sell_sheep_offer_well_formed offer \<longleftrightarrow>
      0 < sheep_amount offer
      \<and> ledger_price_well_formed (wheat_per_sheep offer)"

text \<open>
  The maker sells wheat and buys sheep, while the taker sells sheep and buys
  wheat.  Both roles therefore have balances for both assets, while their
  selling liabilities, buying liabilities, and trustline limits follow their
  respective directions.
\<close>

subsection "The ledger"

definition int64_max :: int
  where
    "int64_max = 2 ^ 63 - 1"

text \<open>
We implicitely assume that all non-computed integer values are @{const int64_max} at most.
\<close>

record balances =
  wheat_balance :: int
  sheep_balance :: int

record maker_state = balances +
  wheat_selling_liabilities :: int
  sheep_limit :: int
  sheep_buying_liabilities :: int

record taker_state = balances +
  sheep_selling_liabilities :: int
  wheat_limit :: int
  wheat_buying_liabilities :: int

record ledger =
  maker_state :: maker_state
  taker_state :: taker_state

definition maker_state_well_formed :: "maker_state \<Rightarrow> bool"
  where
    "maker_state_well_formed maker \<longleftrightarrow>
      0 \<le> wheat_selling_liabilities maker
      \<and> wheat_selling_liabilities maker \<le> wheat_balance maker
      \<and> 0 \<le> sheep_balance maker
      \<and> 0 \<le> sheep_buying_liabilities maker
      \<and> sheep_balance maker + sheep_buying_liabilities maker \<le> sheep_limit maker"

definition maker_available_wheat :: "maker_state \<Rightarrow> int"
  where
    "maker_available_wheat maker =
      wheat_balance maker - wheat_selling_liabilities maker"

definition maker_sheep_headroom :: "maker_state \<Rightarrow> int"
  where
    "maker_sheep_headroom maker =
      sheep_limit maker - sheep_balance maker -
      sheep_buying_liabilities maker"

subsection "Maximum unrestricted exchange"

record exchanged_amounts =
  wheat_to_taker :: int
  sheep_to_maker :: int

definition max_unrestricted_exchange where
  "max_unrestricted_exchange offer = do {
     let p = sheep_per_wheat offer;
     let feasible = {wheat . \<exists> sheep .
           wheat = \<lceil>sheep/p\<rceil> \<and> wheat \<le> wheat_amount offer
           \<and> sheep = \<lfloor>wheat*p\<rfloor>
           \<and> 0 < wheat \<and> wheat \<le> int64_max
           \<and> 0 < sheep \<and> sheep \<le> int64_max
           \<and> wheat*p \<le> int64_max \<comment> \<open>NOTE: seems weird\<close>
         };
     let max_wheat = Max feasible;

     if feasible = {} then \<lparr>wheat_to_taker = 0, sheep_to_maker = 0\<rparr>
     else \<lparr>wheat_to_taker = max_wheat, sheep_to_maker = \<lfloor>max_wheat*p\<rfloor>\<rparr>}"

text \<open>
@{const max_unrestricted_exchange} corresponds to the maximum trade possible, measured in wheat,
assuming an unrestricted counterparty.
\<close>

subsection "Valid offers"

text \<open>TODO: is this enforced upstream of @{verbatim OfferExchance.cpp}?\<close>

definition valid_offer where
  "valid_offer offer ledger \<longleftrightarrow> do {
     let max_exch = max_unrestricted_exchange offer;
     let maker_state = maker_state ledger;                   

     if (max_exch = \<lparr>wheat_to_taker = 0, sheep_to_maker = 0\<rparr>)
     then
       False
     else 
       wheat_balance maker_state \<ge>
         wheat_to_taker max_exch + wheat_selling_liabilities maker_state
       \<and> sheep_limit maker_state \<ge>
           sheep_balance maker_state + sheep_to_maker max_exch
             + sheep_buying_liabilities maker_state}"

text \<open>
  An offer is valid when its maximum unrestricted exchange is nonzero and the
  maker can reserve the corresponding selling and buying liabilities.
\<close>

subsection "Trades"

text \<open>TODO: do we need this record? Why not not just use @{typ exchanged_amounts}?\<close>

record trade = exchanged_amounts +
  resting_offer_stays :: bool

text \<open>
  A @{typ trade} records a positive whole-unit transfer and whether the
  resting offer has greater capped capacity (meaning it is not fully consumed and stays on the book).
\<close>

definition effective_sheep_per_wheat :: "'a exchanged_amounts_scheme \<Rightarrow> rat"
  where
    "effective_sheep_per_wheat exchange =
      sheep_to_maker exchange / wheat_to_taker exchange"

text \<open>
  For a trade with a positive wheat amount,
  @{const effective_sheep_per_wheat} is the realized number of sheep sent per
  wheat received.
\<close>

definition price_error_within_bound ::
    "ledger_price \<Rightarrow> 'a exchanged_amounts_scheme \<Rightarrow> bool"
  where
    "price_error_within_bound price exchange \<longleftrightarrow>
      abs (effective_sheep_per_wheat exchange - price) \<le> (price :: rat) / 100"

text \<open>
  For a positive whole-unit trade, @{const price_error_within_bound} compares
  its effective sheep-per-wheat price with the posted ledger price.  It accepts
  the trade when their absolute difference is at most one percent of the posted
  price.  A trade that fails this test is rejected.
\<close>

subsection "Posting an offer"

definition reserve_sell_wheat_offer_liabilities ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> maker_state"
  where
    "reserve_sell_wheat_offer_liabilities offer maker = do {
       let amounts = max_unrestricted_exchange offer;
       maker\<lparr>
         wheat_selling_liabilities :=
           wheat_selling_liabilities maker + wheat_to_taker amounts,
         sheep_buying_liabilities :=
           sheep_buying_liabilities maker + sheep_to_maker amounts\<rparr> }"

datatype post_outcome =
    Malformed
  | Line_Full
  | Underfunded
  | No_Offer
  | Created sell_wheat_offer maker_state

definition post_sell_wheat_offer ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> post_outcome"
  where
    "post_sell_wheat_offer offer maker = do {
       let amounts = max_unrestricted_exchange offer;
       cond {
         when \<not> ledger_price_well_formed (sheep_per_wheat offer) \<or> wheat_amount offer < 0 \<Rightarrow>
           Malformed
       | when maker_sheep_headroom maker \<le> 0 \<or>
              maker_sheep_headroom maker < sheep_to_maker amounts \<Rightarrow>
           Line_Full
       | when maker_available_wheat maker < wheat_to_taker amounts \<Rightarrow>
           Underfunded
       | when wheat_amount offer = 0 \<or> wheat_to_taker amounts = 0 \<Rightarrow>
           No_Offer
       | when \<not> price_error_within_bound
                    (sheep_per_wheat offer) amounts \<Rightarrow>
           No_Offer
       | otherwise \<Rightarrow> do {
           let posted = offer\<lparr>wheat_amount := wheat_to_taker amounts\<rparr>;
           Created posted (reserve_sell_wheat_offer_liabilities posted maker)}} }"

text \<open>
  The line-full branch also rejects nonpositive sheep headroom, matching the
  immediate C++ check @{verbatim "maxWheatReceive == 0"} after capacities are
  clamped.  The maximum unrestricted exchange is the full execution selected against an unrestricted
  active taker, for which the resting offer does not stay.  Applying the
  price-error threshold before reserving liabilities ensures that every
  @{const Created} offer admits that execution.  Failure is @{const No_Offer}
  because the offer is syntactically well formed but has no acceptable full
  unrestricted execution at whole-unit precision.
\<close>

subsection \<open>Crossing a posted sell-wheat offer\<close>


definition taker_state_well_formed :: "taker_state \<Rightarrow> bool"
  where
    "taker_state_well_formed taker \<longleftrightarrow>
      0 \<le> sheep_selling_liabilities taker
      \<and> sheep_selling_liabilities taker \<le> sheep_balance taker
      \<and> 0 \<le> wheat_balance taker
      \<and> 0 \<le> wheat_buying_liabilities taker
      \<and> wheat_balance taker + wheat_buying_liabilities taker \<le> wheat_limit taker"

definition taker_available_sheep :: "taker_state \<Rightarrow> int"
  where
    "taker_available_sheep taker =
      sheep_balance taker - sheep_selling_liabilities taker"

definition taker_wheat_headroom :: "taker_state \<Rightarrow> int"
  where
    "taker_wheat_headroom taker =
      wheat_limit taker - wheat_balance taker - wheat_buying_liabilities taker"

definition offers_cross ::
    "sell_wheat_offer \<Rightarrow> sell_sheep_offer \<Rightarrow> bool"
  where
    "offers_cross resting incoming \<longleftrightarrow> do {
       let sheep_per_wheat_resting = (sheep_per_wheat resting :: rat);
       let sheep_per_wheat_incoming_limit = 1 / (wheat_per_sheep incoming :: rat);
       if is_passive incoming
       then sheep_per_wheat_resting < sheep_per_wheat_incoming_limit
       else sheep_per_wheat_resting \<le> sheep_per_wheat_incoming_limit
     }"

definition release_sell_wheat_offer_liabilities ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> maker_state"
  where
    "release_sell_wheat_offer_liabilities offer maker =
      (let amounts = max_unrestricted_exchange offer
       in maker\<lparr>
          wheat_selling_liabilities :=
            wheat_selling_liabilities maker - wheat_to_taker amounts,
          sheep_buying_liabilities :=
            sheep_buying_liabilities maker - sheep_to_maker amounts\<rparr>)"

record exchange_caps =
  maker_wheat_send_cap :: int
  taker_wheat_receive_cap :: int
  taker_sheep_send_cap :: int
  maker_sheep_receive_cap :: int

text \<open>
  @{typ exchange_caps} groups both parties' upper bounds on the two transferred
  assets.
\<close>

definition exchange_caps ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> sell_sheep_offer \<Rightarrow> taker_state \<Rightarrow> exchange_caps"
  where
    "exchange_caps resting maker incoming taker =
      (let amounts = max_unrestricted_exchange resting
       in let released_maker =
            release_sell_wheat_offer_liabilities resting maker
       in \<lparr>maker_wheat_send_cap =
              min (wheat_to_taker amounts)
                  (maker_available_wheat released_maker), \<comment> \<open>TODO: Isn't this guaranteed to be the first arg since we just released the liabilities?\<close>
           taker_wheat_receive_cap = taker_wheat_headroom taker,
           taker_sheep_send_cap =
              min (sheep_amount incoming) (taker_available_sheep taker),
           maker_sheep_receive_cap =
              min (sheep_to_maker amounts) \<comment> \<open>NOTE: C++ just uses just the headroom...\<close>
                  (maker_sheep_headroom released_maker)\<rparr>)"

text \<open>
  @{const exchange_caps} combines the resting offer's released
  reservation with the incoming offer's amount and the parties' current
  ledger capacities.  By construction, it caps the resting side by its
  reservation even after releasing that reservation.  Consequently, unrelated
  capacity acquired later cannot cause the crossing to consume more than the
  resting offer had reserved.  The incoming offer's own price is deliberately
  absent: it decides whether the offers cross, while a selected crossing
  executes at the resting price.
\<close>

definition resting_capacity_in_wheat ::
    "ledger_price \<Rightarrow> exchange_caps \<Rightarrow> rat"
  where
    "resting_capacity_in_wheat price caps =
      min (maker_wheat_send_cap caps)
          (maker_sheep_receive_cap caps / price)"

definition incoming_capacity_in_wheat ::
    "ledger_price \<Rightarrow> exchange_caps \<Rightarrow> rat"
  where
    "incoming_capacity_in_wheat price caps =
      min (taker_wheat_receive_cap caps)
          (taker_sheep_send_cap caps / price)"

text \<open>
  @{const resting_capacity_in_wheat} and
  @{const incoming_capacity_in_wheat} express both sides' exact capacities in
  the common unit of wheat at the resting price.  They are rational quantities
  so the comparison happens before whole-unit rounding.
\<close>

definition resting_offer_has_greater_capacity ::
    "ledger_price \<Rightarrow> exchange_caps \<Rightarrow> bool"
  where
    "resting_offer_has_greater_capacity price caps \<longleftrightarrow>
      resting_capacity_in_wheat price caps > incoming_capacity_in_wheat price caps"

definition resting_offer_stays_at_crossing ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> sell_sheep_offer \<Rightarrow> taker_state \<Rightarrow> bool"
    \<comment> \<open>TODO: does this actually implies it will stay after adjustment?\<close>
  where
    "resting_offer_stays_at_crossing resting maker incoming taker \<longleftrightarrow>
      (let caps = exchange_caps resting maker incoming taker
       in resting_offer_has_greater_capacity (sheep_per_wheat resting) caps)"

text \<open>
  @{const resting_offer_has_greater_capacity} uses a strict comparison: the
  resting offer stays only when its exact wheat capacity is greater.  Equal
  capacities therefore do not leave a remainder of the resting offer.
  @{const resting_offer_stays_at_crossing} instantiates that comparison with
  the live caps and the resting execution price.
\<close>

text \<open>
  The pre-threshold selector below mirrors the liability calculation: it
  describes every positive whole-unit crossing allowed by the four live caps
  and the appropriate rounding direction, then chooses the greatest feasible
  wheat transfer.  An empty feasible set denotes the absence of a trade.
\<close>

definition trade_before_error_threshold ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> sell_sheep_offer \<Rightarrow> taker_state \<Rightarrow> trade option"
    \<comment> \<open>TODO: shouldn't we just use the posted amount for maker capacity? It's suposed to 
be an invariant that liabilities are covered.\<close>
  where
    "trade_before_error_threshold resting maker incoming taker =
      (let price = sheep_per_wheat resting
       in let caps =
            exchange_caps resting maker incoming taker
       in let stays =
            resting_offer_has_greater_capacity price caps
       in let feasible = {wheat. \<exists> sheep.
            0 < wheat
            \<and> wheat \<le> maker_wheat_send_cap caps
            \<and> wheat \<le> taker_wheat_receive_cap caps
            \<and> wheat \<le> int64_max
            \<and> 0 < sheep
            \<and> sheep \<le> taker_sheep_send_cap caps
            \<and> sheep \<le> maker_sheep_receive_cap caps
            \<and> sheep \<le> int64_max
            \<and> wheat * price \<le> int64_max
            \<and> sheep / price \<le> int64_max
            \<and> (if stays
               then sheep = \<lceil>wheat * price\<rceil>
                    \<and> wheat = \<lfloor>sheep / price\<rfloor>
               else sheep = \<lfloor>wheat * price\<rfloor>
                    \<and> wheat = \<lceil>sheep / price\<rceil>)}
       in if feasible = {} then None
          else
            (let wheat = Max feasible
             in let sheep =
                  (if stays then \<lceil>wheat * price\<rceil>
                   else \<lfloor>wheat * price\<rfloor>)
             in Some
                  \<lparr>wheat_to_taker = wheat,
                   sheep_to_maker = sheep,
                   resting_offer_stays = stays\<rparr>))"

text \<open>
  @{const trade_before_error_threshold} selects amounts
  before applying the price-error filter.  When the resting offer stays, the
  rounding favors its seller; otherwise the opposite rounding favors the
  incoming seller.  The mutually rounded equations rule out transfers made
  artificially favorable by more than whole-unit indivisibility requires.
\<close>

definition trade ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> sell_sheep_offer \<Rightarrow> taker_state \<Rightarrow> trade option"
  where
    "trade resting maker incoming taker =
      (case trade_before_error_threshold
               resting maker incoming taker of
         None \<Rightarrow> None
       | Some selected \<Rightarrow>
           if price_error_within_bound
                (sheep_per_wheat resting) selected
           then Some selected else None)"

text \<open>
  @{const trade} applies the one-percent price-error bound
  to the maximal pre-threshold trade.  Rejection produces no trade.
\<close>

definition cross_sell_wheat_offer ::
    "sell_wheat_offer \<Rightarrow> maker_state \<Rightarrow> sell_sheep_offer \<Rightarrow> taker_state \<Rightarrow> trade option"
  where
    "cross_sell_wheat_offer resting maker incoming taker =
      (if offers_cross resting incoming
       then trade resting maker incoming taker
       else None)"

text \<open>
  @{const cross_sell_wheat_offer} first checks price compatibility and then
  delegates to the declarative selector.  Well-formed offers and party states,
  together with coverage of the resting offer's reservation, are domain
  assumptions for later crossing theorems rather than additional result
  variants of this pure selection function.
\<close>

definition unrestricted_sell_sheep_offer ::
    "sell_wheat_offer \<Rightarrow> sell_sheep_offer"
  where
    "unrestricted_sell_sheep_offer resting =
      \<lparr>is_passive = False,
       sheep_amount = int64_max,
       wheat_per_sheep =
         Ledger_Price
           (price_d (sheep_per_wheat resting))
           (price_n (sheep_per_wheat resting))\<rparr>"

definition unrestricted_taker_state :: taker_state
  where
    "unrestricted_taker_state =
      \<lparr>wheat_balance = 0,
       sheep_balance = int64_max,
       sheep_selling_liabilities = 0,
       wheat_limit = int64_max,
       wheat_buying_liabilities = 0\<rparr>"

text \<open>
  @{const unrestricted_sell_sheep_offer} is an active incoming offer at the
  reciprocal resting price with the largest ledger amount.  Together with
  @{const unrestricted_taker_state}, which has maximal sheep balance and wheat
  headroom and no liabilities, it provides the canonical counterparty used to
  state that a successfully posted offer is executable.
\<close>

text \<open>
  Refinement note: @{const exchange_caps} caps the maker's sheep-receive
  capacity by both its live headroom and the buying liability reserved for the
  resting offer.  In contrast, C++ @{verbatim "crossOfferV10"} releases that
  liability and passes the full live headroom returned by
  @{verbatim "canBuyAtMost"} to @{verbatim "exchangeV10"}.  Extra headroom can
  therefore change which offer stays and select a different rounding branch;
  for small amounts, an exchange admitted by this specification can become a
  zero exchange in C++.  This mismatch remains when both exact-cap protocol
  choices are enabled because they do not change the initial stays comparison.
\<close>

subsection "Properties"

text \<open>
  A resting offer successfully produced by @{const post_sell_wheat_offer}
  carries a full-fill pair given by @{const max_unrestricted_exchange}.  The
  property below says that any price-compatible incoming offer whose net send
  and receive capacities cover that pair consumes the resting offer completely.
  The crossing-time maker state is otherwise arbitrary: well-formedness and
  coverage of the resting offer's two booked liabilities are the only maker
  requirements.  In particular, unrelated extra maker balance or headroom must
  not change the transferred amounts or which offer stays.
\<close>

(*
theorem sufficiently_large_incoming_offer_fully_takes_covered_posted_offer:
  fixes requested resting :: sell_wheat_offer
    and maker_at_post posted_maker maker_at_cross :: maker_state
    and incoming :: sell_sheep_offer
    and taker :: taker_state
    and full_fill :: exchanged_amounts
  defines "full_fill \<equiv> max_unrestricted_exchange resting"
  assumes maker_at_post_wf: "maker_state_well_formed maker_at_post"
    and posted:
      "post_sell_wheat_offer requested maker_at_post =
        Created resting posted_maker"
    and maker_at_cross_wf: "maker_state_well_formed maker_at_cross"
    and selling_liability_covered:
      "wheat_to_taker full_fill \<le>
        wheat_selling_liabilities maker_at_cross"
    and buying_liability_covered:
      "sheep_to_maker full_fill \<le>
        sheep_buying_liabilities maker_at_cross"
    and incoming_wf: "sell_sheep_offer_well_formed incoming"
    and taker_wf: "taker_state_well_formed taker"
    and price_compatible: "offers_cross resting incoming"
    and incoming_wheat_capacity:
      "wheat_to_taker full_fill \<le> taker_wheat_headroom taker"
    and incoming_sheep_capacity:
      "sheep_to_maker full_fill \<le>
        min (sheep_amount incoming) (taker_available_sheep taker)"
  shows
    "cross_sell_wheat_offer resting maker_at_cross incoming taker =
      Some
        \<lparr>wheat_to_taker = wheat_to_taker full_fill,
         sheep_to_maker = sheep_to_maker full_fill,
         resting_offer_stays = False\<rparr>"
  sorry
*)

lemma max_unrestricted_exchange_all_zero_or_none:
  assumes "sell_wheat_offer_well_formed offer"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  shows "wheat_to_taker amounts = 0 \<longleftrightarrow> sheep_to_maker amounts = 0"

text \<open>Proof sketch. The feasible wheat amounts form a finite set because they lie in an
integer interval. If the set is empty, the definition assigns zero to both amounts.
Otherwise its maximum belongs to the set; feasibility says that the maximum wheat amount
and its corresponding rounded sheep amount are both positive. Hence neither amount is
zero.\<close>

proof -
  let ?p = "sheep_per_wheat offer"
  let ?feasible = "{wheat. \<exists> sheep.
        wheat = \<lceil>sheep / ?p\<rceil> \<and> wheat \<le> wheat_amount offer
        \<and> sheep = \<lfloor>wheat * ?p\<rfloor>
        \<and> 0 < wheat \<and> wheat \<le> int64_max
        \<and> 0 < sheep \<and> sheep \<le> int64_max
        \<and> wheat * ?p \<le> int64_max}"
  have finite_feasible: "finite ?feasible"
  proof (rule finite_subset[where B = "{1..wheat_amount offer}"])
    show "?feasible \<subseteq> {1..wheat_amount offer}"
      by auto
    show "finite {1..wheat_amount offer}"
      by simp
  qed
  show ?thesis
  proof (cases "?feasible = {}")
    case True
    have amounts_eq: "amounts =
        \<lparr>wheat_to_taker = 0, sheep_to_maker = 0\<rparr>"
      unfolding amounts_def max_unrestricted_exchange_def Let_def
      by (subst if_P[OF True]) (rule refl)
    then show ?thesis
      by simp
  next
    case False
    have max_in: "Max ?feasible \<in> ?feasible"
      using finite_feasible False by (rule Max_in)
    then have max_positive: "0 < Max ?feasible"
      and sheep_positive: "0 < \<lfloor>Max ?feasible * ?p\<rfloor>"
      by auto
    have max_nonzero: "Max ?feasible \<noteq> 0"
      using max_positive by linarith
    have sheep_nonzero: "\<lfloor>Max ?feasible * ?p\<rfloor> \<noteq> 0"
      using sheep_positive by linarith
    have amounts_eq: "amounts =
        \<lparr>wheat_to_taker = Max ?feasible,
          sheep_to_maker = \<lfloor>Max ?feasible * ?p\<rfloor>\<rparr>"
      unfolding amounts_def max_unrestricted_exchange_def Let_def
      by (subst if_not_P[OF False]) (rule refl)
    show ?thesis
      using amounts_eq max_nonzero sheep_nonzero by simp
  qed
qed

text \<open>
  Proof sketch.  Reaching the @{const Created} branch means that every earlier
  posting guard was false.  The negated guards give price and amount validity,
  a nonzero unrestricted amount, acceptance of that exchange by the price-error
  threshold, and sufficient maker capacity.  Injectivity of @{const Created}
  identifies the returned state with the state produced by reservation.
\<close>

lemma created_sell_wheat_offer_facts:
  assumes posted:
    "post_sell_wheat_offer offer maker = Created offer posted_maker"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  defines "unrestricted_trade \<equiv>
    \<lparr>wheat_to_taker = wheat_to_taker amounts,
     sheep_to_maker = sheep_to_maker amounts,
     resting_offer_stays = False\<rparr>"
  shows "ledger_price_well_formed (sheep_per_wheat offer)
       \<and> 0 < wheat_amount offer
       \<and> wheat_to_taker amounts \<noteq> 0
       \<and> price_error_within_bound
           (sheep_per_wheat offer) unrestricted_trade
       \<and> sheep_to_maker amounts
           \<le> maker_sheep_headroom maker
       \<and> wheat_to_taker amounts
           \<le> maker_available_wheat maker
       \<and> posted_maker =
           reserve_sell_wheat_offer_liabilities offer maker"
  using posted
  unfolding post_sell_wheat_offer_def amounts_def unrestricted_trade_def
  apply (simp only: Let_def)
  by (auto simp: price_error_within_bound_def effective_sheep_per_wheat_def
           split: if_splits)

text \<open>
  Proof sketch.  A nonzero wheat amount rules out the empty feasible set,
  because the empty branch assigns zero.  The set is finite since all its wheat
  amounts lie in a finite integer interval.  Its maximum therefore belongs to
  the set, and expanding the nonempty branch transfers every feasibility
  condition to the two stored amounts.
\<close>

lemma nonzero_max_unrestricted_exchange_is_feasible:
  assumes nonzero:
    "wheat_to_taker
       (max_unrestricted_exchange offer) \<noteq> 0"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  shows
    "wheat_to_taker amounts =
       \<lceil>sheep_to_maker amounts /
          sheep_per_wheat offer\<rceil>
     \<and> wheat_to_taker amounts \<le> wheat_amount offer
     \<and> sheep_to_maker amounts =
         \<lfloor>wheat_to_taker amounts *
            sheep_per_wheat offer\<rfloor>
     \<and> 0 < wheat_to_taker amounts
     \<and> wheat_to_taker amounts \<le> int64_max
     \<and> sheep_to_maker amounts /
          sheep_per_wheat offer \<le> int64_max
     \<and> 0 < sheep_to_maker amounts
     \<and> sheep_to_maker amounts \<le> int64_max
     \<and> wheat_to_taker amounts *
          sheep_per_wheat offer \<le> int64_max"
proof -
  let ?price = "sheep_per_wheat offer"
  let ?feasible = "{wheat. \<exists> sheep.
       wheat = \<lceil>sheep / ?price\<rceil>
       \<and> wheat \<le> wheat_amount offer
       \<and> sheep = \<lfloor>wheat * ?price\<rfloor>
       \<and> 0 < wheat
       \<and> wheat \<le> int64_max
       \<and> 0 < sheep
       \<and> sheep \<le> int64_max
       \<and> wheat * ?price \<le> int64_max}"
  have finite_feasible: "finite ?feasible"
  proof (rule finite_subset[where B = "{1..wheat_amount offer}"])
    show "?feasible \<subseteq> {1..wheat_amount offer}"
      by auto
    show "finite {1..wheat_amount offer}"
      by simp
  qed
  have feasible_nonempty: "?feasible \<noteq> {}"
  proof
    assume empty: "?feasible = {}"
    have "wheat_to_taker
            (max_unrestricted_exchange offer) = 0"
      unfolding max_unrestricted_exchange_def Let_def
      apply (subst if_P[OF empty])
      by simp
    with nonzero show False
      by contradiction
  qed
  have max_mem: "Max ?feasible \<in> ?feasible"
    using finite_feasible feasible_nonempty by (rule Max_in)
  have amounts_eq:
    "amounts =
      \<lparr>wheat_to_taker = Max ?feasible,
       sheep_to_maker = \<lfloor>Max ?feasible * ?price\<rfloor>\<rparr>"
    unfolding amounts_def max_unrestricted_exchange_def Let_def
    by (subst if_not_P[OF feasible_nonempty]) (rule refl)
  text \<open>
    The feasible set no longer records that the sheep value divided by the
    price fits, but that bound follows from the wheat bound: the quotient is
    at most its ceiling, which is the wheat amount.
  \<close>
  have sheep_bound: "sheep_to_maker amounts / ?price \<le> int64_max"
  proof -
    obtain sheep where
      w: "Max ?feasible = \<lceil>sheep / ?price\<rceil>" and
      s: "sheep = \<lfloor>Max ?feasible * ?price\<rfloor>" and
      bound: "Max ?feasible \<le> int64_max"
      using max_mem by blast
    have sheep_is: "sheep_to_maker amounts = sheep"
      using amounts_eq s by simp
    have "sheep / ?price \<le> \<lceil>sheep / ?price\<rceil>"
      by (rule le_of_int_ceiling)
    also have "... = Max ?feasible" using w by simp
    also have "... \<le> int64_max" using bound by simp
    finally show ?thesis using sheep_is by simp
  qed
  show ?thesis
    using max_mem amounts_eq sheep_bound
    by auto
qed

text \<open>
  Proof sketch.  Reserving and then releasing this offer cancels exactly the
  two liability additions.  The successful posting guards say the original
  maker capacities cover the liabilities, so both maker-side minima select the
  liabilities.  The canonical taker contributes @{const int64_max} on both of
  its sides.
\<close>

lemma unrestricted_caps_after_created:
  assumes posted:
    "post_sell_wheat_offer offer maker = Created offer posted_maker"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  shows
    "exchange_caps
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
     unrestricted_taker_state =
     \<lparr>maker_wheat_send_cap =
         wheat_to_taker amounts,
      taker_wheat_receive_cap = int64_max,
      taker_sheep_send_cap = int64_max,
      maker_sheep_receive_cap =
         sheep_to_maker amounts\<rparr>"
proof -
  have facts:
    "sheep_to_maker amounts \<le> maker_sheep_headroom maker
     \<and> wheat_to_taker amounts \<le> maker_available_wheat maker
     \<and> posted_maker =
         reserve_sell_wheat_offer_liabilities offer maker"
    using created_sell_wheat_offer_facts[OF posted]
    unfolding amounts_def
    by simp
  show ?thesis
    using facts
    unfolding exchange_caps_def
      unrestricted_sell_sheep_offer_def unrestricted_taker_state_def
      reserve_sell_wheat_offer_liabilities_def
      release_sell_wheat_offer_liabilities_def
      taker_wheat_headroom_def taker_available_sheep_def
      amounts_def
    by (simp add: Let_def maker_available_wheat_def maker_sheep_headroom_def
        min_absorb1)
qed

text \<open>
  Proof sketch.  The canonical incoming offer is active and stores the
  reciprocal ledger price.  Taking its reciprocal recovers the resting price,
  so the non-strict active-offer crossing test holds with equality.
\<close>

lemma unrestricted_offer_crosses:
  "offers_cross offer (unrestricted_sell_sheep_offer offer)"
  unfolding offers_cross_def unrestricted_sell_sheep_offer_def
    rat_price_def
  by simp

text \<open>
  Proof sketch.  The two resting caps are the unrestricted exchange amounts,
  bounds both by @{const int64_max}.  Positivity of the posted price preserves
  the sheep-cap inequality when converting it to wheat.  Monotonicity of
  @{const min} therefore makes resting capacity no greater than canonical
  incoming capacity, so the strict stays comparison is false.
\<close>

lemma unrestricted_resting_offer_does_not_stay_after_created:
  assumes posted:
    "post_sell_wheat_offer offer maker = Created offer posted_maker"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  shows
    "\<not> resting_offer_has_greater_capacity
         (sheep_per_wheat offer)
         (exchange_caps
            offer posted_maker
            (unrestricted_sell_sheep_offer offer)
            unrestricted_taker_state)"
proof -
  let ?wheat = "wheat_to_taker amounts"
  let ?sheep = "sheep_to_maker amounts"
  let ?price = "(sheep_per_wheat offer :: rat)"
  have created:
    "ledger_price_well_formed (sheep_per_wheat offer)
     \<and> ?wheat \<noteq> 0"
    using created_sell_wheat_offer_facts[OF posted]
    unfolding amounts_def
    by simp
  have nonzero:
    "wheat_to_taker
       (max_unrestricted_exchange offer) \<noteq> 0"
    using created
    unfolding amounts_def
    by simp
  note feasible =
    nonzero_max_unrestricted_exchange_is_feasible[OF nonzero]
  have feasible_local:
    "?wheat =
       \<lceil>?sheep / sheep_per_wheat offer\<rceil>
     \<and> ?wheat \<le> wheat_amount offer
     \<and> ?sheep =
         \<lfloor>?wheat * sheep_per_wheat offer\<rfloor>
     \<and> 0 < ?wheat
     \<and> ?wheat \<le> int64_max
     \<and> ?sheep / sheep_per_wheat offer \<le> int64_max
     \<and> 0 < ?sheep
     \<and> ?sheep \<le> int64_max
     \<and> ?wheat * sheep_per_wheat offer \<le> int64_max"
    unfolding amounts_def
    by (rule feasible)
  have wheat_le_int: "?wheat \<le> int64_max"
    using feasible_local by blast
  have sheep_le_int: "?sheep \<le> int64_max"
    using feasible_local by blast
  have wheat_le: "(?wheat :: rat) \<le> int64_max"
    using wheat_le_int by simp
  have sheep_le: "(?sheep :: rat) \<le> int64_max"
    using sheep_le_int by simp
  have price_well_formed:
    "ledger_price_well_formed (sheep_per_wheat offer)"
    using created by blast
  then have numerator_positive:
      "0 < price_n (sheep_per_wheat offer)"
    and denominator_positive:
      "0 < price_d (sheep_per_wheat offer)"
    unfolding ledger_price_well_formed_def
    by blast+
  have price_positive: "0 < ?price"
    using numerator_positive denominator_positive
    unfolding rat_price_def
    by simp
  have price_nonnegative: "0 \<le> ?price"
    using price_positive by linarith
  have sheep_capacity_le:
    "(?sheep :: rat) / ?price \<le> int64_max / ?price"
    by (rule Fields.linordered_field_class.divide_right_mono[
          OF sheep_le price_nonnegative])
  have capacity_le:
    "min (?wheat :: rat) (?sheep / ?price) \<le>
       min (int64_max :: rat) (int64_max / ?price)"
    by (rule min.mono[OF wheat_le sheep_capacity_le])
  have not_greater:
    "\<not> min (?wheat :: rat) (?sheep / ?price) >
       min (int64_max :: rat) (int64_max / ?price)"
    using capacity_le
    by linarith
  have not_greater_concrete:
    "\<not> min
         (wheat_to_taker
            (max_unrestricted_exchange offer) :: rat)
         (sheep_to_maker
            (max_unrestricted_exchange offer) /
          sheep_per_wheat offer) >
       min (int64_max :: rat)
         (int64_max / sheep_per_wheat offer)"
    using not_greater
    unfolding amounts_def
    by assumption
  have caps:
    "exchange_caps
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
     unrestricted_taker_state =
     \<lparr>maker_wheat_send_cap =
         wheat_to_taker
           (max_unrestricted_exchange offer),
      taker_wheat_receive_cap = int64_max,
      taker_sheep_send_cap = int64_max,
      maker_sheep_receive_cap =
         sheep_to_maker
           (max_unrestricted_exchange offer)\<rparr>"
    by (rule unrestricted_caps_after_created[OF posted])
  show ?thesis
    unfolding resting_offer_has_greater_capacity_def
      resting_capacity_in_wheat_def incoming_capacity_in_wheat_def
    by (simp only: caps exchange_caps.select_convs
        not_greater_concrete; simp)
qed

text \<open>
  Proof sketch.  The unrestricted exchange is feasible for the pre-threshold selector
  under the canonical caps and the non-stays rounding direction.  Conversely,
  every selector-feasible wheat amount is bounded by the unrestricted wheat
  amount.  Hence that amount is exactly the maximum.  Its rounded sheep amount
  is the unrestricted sheep amount, so the selected record is that exchange.
\<close>

lemma unrestricted_prethreshold_exchange_after_created:
  assumes posted:
    "post_sell_wheat_offer offer maker = Created offer posted_maker"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  defines "unrestricted_trade \<equiv>
    \<lparr>wheat_to_taker = wheat_to_taker amounts,
     sheep_to_maker = sheep_to_maker amounts,
     resting_offer_stays = False\<rparr>"
  shows
    "trade_before_error_threshold
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
       unrestricted_taker_state =
     Some unrestricted_trade"
proof -
  let ?wheat = "wheat_to_taker amounts"
  let ?sheep = "sheep_to_maker amounts"
  let ?price = "sheep_per_wheat offer"
  let ?caps =
    "exchange_caps
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
       unrestricted_taker_state"
  let ?stays =
    "resting_offer_has_greater_capacity ?price ?caps"
  let ?feasible = "{wheat. \<exists> sheep.
       0 < wheat
       \<and> wheat \<le> maker_wheat_send_cap ?caps
       \<and> wheat \<le> taker_wheat_receive_cap ?caps
       \<and> wheat \<le> int64_max
       \<and> 0 < sheep
       \<and> sheep \<le> taker_sheep_send_cap ?caps
       \<and> sheep \<le> maker_sheep_receive_cap ?caps
       \<and> sheep \<le> int64_max
       \<and> wheat * ?price \<le> int64_max
       \<and> sheep / ?price \<le> int64_max
       \<and> (if ?stays
          then sheep = \<lceil>wheat * ?price\<rceil>
               \<and> wheat = \<lfloor>sheep / ?price\<rfloor>
          else sheep = \<lfloor>wheat * ?price\<rfloor>
               \<and> wheat = \<lceil>sheep / ?price\<rceil>)}"
  have nonzero:
    "wheat_to_taker
       (max_unrestricted_exchange offer) \<noteq> 0"
    using created_sell_wheat_offer_facts[OF posted]
    by simp
  have amounts_feasible:
    "?wheat =
       \<lceil>?sheep / ?price\<rceil>
     \<and> ?wheat \<le> wheat_amount offer
     \<and> ?sheep = \<lfloor>?wheat * ?price\<rfloor>
     \<and> 0 < ?wheat
     \<and> ?wheat \<le> int64_max
     \<and> ?sheep / ?price \<le> int64_max
     \<and> 0 < ?sheep
     \<and> ?sheep \<le> int64_max
     \<and> ?wheat * ?price \<le> int64_max"
    unfolding amounts_def
    by (rule nonzero_max_unrestricted_exchange_is_feasible[OF nonzero])
  have caps:
    "?caps =
     \<lparr>maker_wheat_send_cap = ?wheat,
      taker_wheat_receive_cap = int64_max,
      taker_sheep_send_cap = int64_max,
      maker_sheep_receive_cap = ?sheep\<rparr>"
    using unrestricted_caps_after_created[OF posted]
    unfolding amounts_def
    by assumption
  have stays_false: "\<not> ?stays"
    using unrestricted_resting_offer_does_not_stay_after_created[OF posted]
    by assumption
  have cap_values:
    "maker_wheat_send_cap ?caps = ?wheat
     \<and> taker_wheat_receive_cap ?caps = int64_max
     \<and> taker_sheep_send_cap ?caps = int64_max
     \<and> maker_sheep_receive_cap ?caps = ?sheep"
    using caps by simp
  have maker_wheat_cap:
    "maker_wheat_send_cap ?caps = ?wheat"
    using cap_values by blast
  have taker_wheat_cap:
    "taker_wheat_receive_cap ?caps = int64_max"
    using cap_values by blast
  have taker_sheep_cap:
    "taker_sheep_send_cap ?caps = int64_max"
    using cap_values by blast
  have maker_sheep_cap:
    "maker_sheep_receive_cap ?caps = ?sheep"
    using cap_values by blast
  have chosen_mem: "?wheat \<in> ?feasible"
    apply (simp only: Set.mem_Collect_eq)
    apply (rule exI[where x = ?sheep])
    apply (simp only: maker_wheat_cap taker_wheat_cap
        taker_sheep_cap maker_sheep_cap stays_false if_False)
    using amounts_feasible
    by blast
  have finite_feasible: "finite ?feasible"
  proof (rule finite_subset[where B = "{1..?wheat}"])
    show "?feasible \<subseteq> {1..?wheat}"
    proof
      fix wheat
      assume member: "wheat \<in> ?feasible"
      then have "0 < wheat
        \<and> wheat \<le> maker_wheat_send_cap ?caps"
        by blast
      with maker_wheat_cap show "wheat \<in> {1..?wheat}"
        by simp
    qed
    show "finite {1..?wheat}"
      by simp
  qed
  have feasible_nonempty: "?feasible \<noteq> {}"
    using chosen_mem by blast
  have all_le: "\<forall>wheat \<in> ?feasible. wheat \<le> ?wheat"
  proof (intro ballI)
    fix wheat
    assume "wheat \<in> ?feasible"
    then have
      "wheat \<le> maker_wheat_send_cap ?caps"
      by blast
    with maker_wheat_cap show "wheat \<le> ?wheat"
      by simp
  qed
  have max_le: "Max ?feasible \<le> ?wheat"
    using Lattices_Big.linorder_class.Max_le_iff[
      OF finite_feasible feasible_nonempty] all_le
    by blast
  have wheat_le_max: "?wheat \<le> Max ?feasible"
    using finite_feasible chosen_mem
    by (rule Max_ge)
  have max_eq: "Max ?feasible = ?wheat"
    using max_le wheat_le_max by linarith
  have sheep_eq:
    "?sheep = \<lfloor>?wheat * ?price\<rfloor>"
    using amounts_feasible by blast
  have rounded_sheep:
    "\<lfloor>?wheat * ?price\<rfloor> = ?sheep"
    by (rule sym[OF sheep_eq])
  show ?thesis
    unfolding trade_before_error_threshold_def
      unrestricted_trade_def
    apply (simp only: Let_def feasible_nonempty if_False max_eq)
    by (simp only: stays_false if_False rounded_sheep)
qed

text \<open>
  Proof sketch.  The previous lemma identifies the pre-threshold selection.
  The additional posting guard records exactly that this unrestricted exchange
  satisfies the price-error bound, so the thresholded selector preserves it.
\<close>

lemma unrestricted_selected_exchange_after_created:
  assumes posted:
    "post_sell_wheat_offer offer maker = Created offer posted_maker"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  defines "unrestricted_trade \<equiv>
    \<lparr>wheat_to_taker = wheat_to_taker amounts,
     sheep_to_maker = sheep_to_maker amounts,
     resting_offer_stays = False\<rparr>"
  shows
    "trade
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
       unrestricted_taker_state =
     Some unrestricted_trade"
proof -
  have before:
    "trade_before_error_threshold
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
       unrestricted_taker_state =
     Some unrestricted_trade"
    using unrestricted_prethreshold_exchange_after_created[OF posted]
    unfolding amounts_def unrestricted_trade_def
    by assumption
  have within:
    "price_error_within_bound
       (sheep_per_wheat offer) unrestricted_trade"
    using created_sell_wheat_offer_facts[OF posted]
    unfolding amounts_def unrestricted_trade_def
    by simp
  show ?thesis
    unfolding trade_def
    using before within
    by simp
qed

text \<open>
  Proof sketch.  The canonical incoming offer crosses at equality because it
  is active and reciprocal.  The thresholded selector returns the unrestricted
  exchange by the preceding lemma, so unfolding the outer crossing check yields
  that same successful trade.
\<close>

theorem successfully_posted_offer_has_unrestricted_taker:
  assumes posted:
    "post_sell_wheat_offer offer maker = Created offer posted_maker"
  defines "amounts \<equiv> max_unrestricted_exchange offer"
  shows
    "cross_sell_wheat_offer
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
       unrestricted_taker_state =
     Some
       \<lparr>wheat_to_taker =
          wheat_to_taker amounts,
        sheep_to_maker =
          sheep_to_maker amounts,
        resting_offer_stays = False\<rparr>"
proof -
  let ?trade =
    "\<lparr>wheat_to_taker = wheat_to_taker amounts,
      sheep_to_maker = sheep_to_maker amounts,
      resting_offer_stays = False\<rparr>"
  have crosses:
    "offers_cross offer (unrestricted_sell_sheep_offer offer)"
    by (rule unrestricted_offer_crosses)
  have selected:
    "trade
       offer posted_maker
       (unrestricted_sell_sheep_offer offer)
       unrestricted_taker_state =
     Some ?trade"
    using unrestricted_selected_exchange_after_created[OF posted]
    unfolding amounts_def
    by assumption
  show ?thesis
    unfolding cross_sell_wheat_offer_def
    using crosses selected
    by simp
qed

end
